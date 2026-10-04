//! Applying a plan: run each action's command (elevated where needed),
//! verify the update is no longer pending, and append every outcome to an
//! audit log. One apply at a time per user (a lock file enforces it).

use crate::exec::{CommandRunner, Elevation, elevate, is_elevated};
use crate::managers::{self, Context};
use crate::model::{AvailableUpdate, ManagerId, OsFamily, OsInfo, Scan, SystemReport};
use crate::plan::{Excluded, PlannedAction, Selection, UpdatePlan, build_plan, selected_keys};
use crate::policy::Policy;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ApplyOptions {
    /// Show what would run; change nothing.
    pub dry_run: bool,
    pub elevation: Elevation,
    /// Re-query each manager afterwards to confirm the updates landed.
    pub verify: bool,
    pub audit_log: Option<PathBuf>,
    /// Directory for the lock file.
    pub lock_dir: Option<PathBuf>,
    /// Stop after the first failed action instead of continuing.
    pub stop_on_failure: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        ApplyOptions {
            dry_run: true,
            elevation: Elevation::default_for(false),
            verify: true,
            audit_log: crate::paths::audit_log(),
            lock_dir: crate::paths::data_dir(),
            stop_on_failure: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ActionStatus {
    /// Dry run: the command was shown, not run.
    DryRun,
    /// Installed, and the manager no longer lists the update.
    Verified,
    /// The command succeeded; verification was off or inconclusive.
    Installed,
    /// Installed; finishes after a restart.
    NeedsRestart,
    Failed,
    /// Not attempted (missing privileges, or stopped after a failure).
    Skipped,
}

impl ActionStatus {
    pub fn is_success(self) -> bool {
        matches!(
            self,
            ActionStatus::Verified | ActionStatus::Installed | ActionStatus::NeedsRestart | ActionStatus::DryRun
        )
    }
    pub fn label(self) -> &'static str {
        match self {
            ActionStatus::DryRun => "dry run",
            ActionStatus::Verified => "verified",
            ActionStatus::Installed => "installed",
            ActionStatus::NeedsRestart => "restart needed",
            ActionStatus::Failed => "failed",
            ActionStatus::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionResult {
    pub key: String,
    pub title: String,
    pub command: String,
    pub status: ActionStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub message: String,
    pub output_tail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplyReport {
    pub started_at: String,
    pub finished_at: String,
    pub dry_run: bool,
    pub results: Vec<ActionResult>,
    /// Problems that did not stop the run, such as an audit log that could
    /// not be written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ApplyReport {
    pub fn count(&self, s: ActionStatus) -> usize {
        self.results.iter().filter(|r| r.status == s).count()
    }
    pub fn all_succeeded(&self) -> bool {
        self.results.iter().all(|r| r.status.is_success())
    }
    pub fn restart_required(&self) -> bool {
        self.results.iter().any(|r| r.status == ActionStatus::NeedsRestart)
    }
}

pub enum ApplyEvent<'a> {
    Started {
        index: usize,
        total: usize,
        action: &'a PlannedAction,
        command: &'a str,
    },
    Finished {
        index: usize,
        total: usize,
        result: &'a ActionResult,
    },
    Verifying(ManagerId),
    /// Something the person should know that does not stop the run (also
    /// kept in [`ApplyReport::warnings`]).
    Warning(&'a str),
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("another patchscope apply is running (lock file {0}); wait for it to finish")]
    Locked(String),
    #[error("lock file {path}: {source}")]
    Lock {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "audit log {path}: {source}; nothing was installed, because every install must be recorded (if an earlier run with sudo left the file or its folder owned by root, give it back to your user)"
    )]
    Audit {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Holds the operating system's lock on `apply.lock` for as long as the
/// apply runs. The OS releases it when the file is closed, which also
/// happens when patchscope is killed without unwinding (Ctrl-C at a sudo
/// prompt), so a leftover file never blocks. The file itself stays: removing
/// it would let a later run lock a new file while an older one still holds
/// the old one.
struct LockGuard {
    _file: Option<std::fs::File>,
}

fn take_lock(dir: Option<&Path>) -> Result<LockGuard, ApplyError> {
    let Some(dir) = dir else {
        return Ok(LockGuard { _file: None });
    };
    std::fs::create_dir_all(dir).map_err(|source| ApplyError::Lock {
        path: dir.display().to_string(),
        source,
    })?;
    let path = dir.join("apply.lock");
    let lock_err = |source| ApplyError::Lock {
        path: path.display().to_string(),
        source,
    };
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(lock_err)?;
    match f.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(ApplyError::Locked(path.display().to_string())),
        Err(std::fs::TryLockError::Error(e)) => return Err(lock_err(e)),
    }
    // For a person looking at the file; the lock is what counts.
    let _ = f.set_len(0);
    let _ = writeln!(f, "pid={} started={}", std::process::id(), util::now_rfc3339());
    Ok(LockGuard { _file: Some(f) })
}

/// Open the audit log for appending; owner-only on Unix, including a file
/// that already existed with wider permissions.
fn open_audit_log(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.permissions().mode() & 0o777 != 0o600 {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(f)
}

/// The open audit log. The first write that fails becomes a warning and
/// nothing more is written.
struct AuditLog {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl AuditLog {
    fn record(&mut self, dry_run: bool, r: &ActionResult) -> Option<String> {
        let f = self.file.as_mut()?;
        let line = serde_json::json!({
            "ts": util::now_rfc3339(),
            "dry_run": dry_run,
            "key": r.key,
            "command": r.command,
            "status": r.status,
            "exit_code": r.exit_code,
            "duration_ms": r.duration_ms,
            "message": r.message,
        });
        // One write per line, so concurrent appends cannot interleave.
        match f.write_all(format!("{line}\n").as_bytes()) {
            Ok(()) => None,
            Err(e) => {
                self.file = None;
                Some(format!(
                    "audit log {}: could not write: {e}; this and later actions are not recorded there",
                    self.path.display()
                ))
            }
        }
    }
}

/// Where warnings go: shown as they happen, and kept for the report.
struct Warnings<'a> {
    list: Vec<String>,
    on_event: &'a dyn Fn(ApplyEvent),
}

impl Warnings<'_> {
    fn add(&mut self, w: String) {
        (self.on_event)(ApplyEvent::Warning(&w));
        self.list.push(w);
    }

    fn audit(&mut self, log: &mut Option<AuditLog>, dry_run: bool, r: &ActionResult) {
        if let Some(w) = log.as_mut().and_then(|l| l.record(dry_run, r)) {
            self.add(w);
        }
    }
}

pub fn apply_plan(
    plan: &UpdatePlan,
    os: &OsInfo,
    runner: &dyn CommandRunner,
    opts: &ApplyOptions,
    on_event: &dyn Fn(ApplyEvent),
) -> Result<ApplyReport, ApplyError> {
    let _lock = if opts.dry_run {
        LockGuard { _file: None }
    } else {
        take_lock(opts.lock_dir.as_deref())?
    };
    let mut warnings = Warnings {
        list: Vec::new(),
        on_event,
    };
    // An install that cannot be recorded does not start; a dry run says so.
    let mut audit_log = match opts.audit_log.as_deref() {
        None => None,
        Some(p) => match open_audit_log(p) {
            Ok(f) => Some(AuditLog {
                path: p.to_path_buf(),
                file: Some(f),
            }),
            Err(source) if !opts.dry_run => {
                return Err(ApplyError::Audit {
                    path: p.display().to_string(),
                    source,
                });
            }
            Err(e) => {
                warnings.add(format!("audit log {}: {e}; this dry run is not recorded", p.display()));
                None
            }
        },
    };
    let started_at = util::now_rfc3339();
    let total = plan.actions.len();

    // Can privileged actions run at all?
    let elevated_now = !opts.dry_run && plan.needs_elevation() && is_elevated(runner);
    let elevation = if elevated_now { Elevation::None } else { opts.elevation };
    let cannot_elevate =
        !opts.dry_run && !elevated_now && (elevation == Elevation::None || OsFamily::current() == OsFamily::Windows);
    let ctx = Context::new(os.clone());

    let mut results: Vec<ActionResult> = Vec::with_capacity(total);
    let mut stop = false;
    for (index, action) in plan.actions.iter().enumerate() {
        let mgr = managers::get(action.manager);
        let base = mgr.install_command(&action.updates[0]);
        let (spec, refused) = match elevate(&base, elevation) {
            Ok(s) => (s, None),
            Err(e) => (base, Some(e.to_string())),
        };
        let command = spec.display();
        on_event(ApplyEvent::Started {
            index,
            total,
            action,
            command: &command,
        });
        let mut r = ActionResult {
            key: action.key.clone(),
            title: action.title.clone(),
            command: command.clone(),
            status: ActionStatus::DryRun,
            exit_code: None,
            duration_ms: 0,
            message: String::new(),
            output_tail: String::new(),
        };
        if opts.dry_run {
            r.message = match &refused {
                Some(e) => format!("not run (dry run); {e}"),
                None => "not run (dry run)".into(),
            };
        } else if stop {
            r.status = ActionStatus::Skipped;
            r.message = "not run: an earlier action failed or is still running".into();
        } else if action.needs_elevation && cannot_elevate {
            r.status = ActionStatus::Skipped;
            r.message = if OsFamily::current() == OsFamily::Windows {
                "needs Administrator rights: run patchscope from an elevated terminal (Run as administrator)".into()
            } else {
                "needs root: re-run with sudo, or allow an elevation method".into()
            };
        } else if let Some(e) = refused {
            r.status = ActionStatus::Failed;
            r.message = e;
        } else {
            let t = Instant::now();
            match runner.run(&spec) {
                Ok(out) => {
                    r.exit_code = out.status;
                    r.output_tail = out.tail(2000);
                    if out.success() {
                        r.status = if action.restart_required {
                            ActionStatus::NeedsRestart
                        } else {
                            ActionStatus::Installed
                        };
                        r.message = "command succeeded".into();
                    } else {
                        r.status = ActionStatus::Failed;
                        r.message = if out.timed_out && action.needs_elevation {
                            // An unprivileged process cannot be sure the root
                            // command stopped; it may still hold the package
                            // database lock, so nothing else runs.
                            stop = true;
                            format!(
                                "timed out after {} minutes; the administrator command may still be running, so the remaining updates were not started",
                                spec.timeout.as_secs() / 60
                            )
                        } else if out.timed_out {
                            format!("timed out after {} minutes", spec.timeout.as_secs() / 60)
                        } else {
                            format!(
                                "exited with {}",
                                out.status.map_or("a signal".into(), |c| c.to_string())
                            )
                        };
                    }
                }
                Err(e) => {
                    r.status = ActionStatus::Failed;
                    r.message = e.to_string();
                }
            }
            r.duration_ms = t.elapsed().as_millis() as u64;
            if r.status == ActionStatus::Failed && opts.stop_on_failure {
                stop = true;
            }
        }
        warnings.audit(&mut audit_log, opts.dry_run, &r);
        on_event(ApplyEvent::Finished {
            index,
            total,
            result: &r,
        });
        results.push(r);
    }

    if opts.verify && !opts.dry_run {
        verify(
            plan,
            &mut results,
            runner,
            &ctx,
            on_event,
            &mut audit_log,
            &mut warnings,
        );
    }

    Ok(ApplyReport {
        started_at,
        finished_at: util::now_rfc3339(),
        dry_run: opts.dry_run,
        results,
        warnings: warnings.list,
    })
}

/// Re-query each manager that installed something and check the update is
/// gone from its list.
fn verify(
    plan: &UpdatePlan,
    results: &mut [ActionResult],
    runner: &dyn CommandRunner,
    ctx: &Context,
    on_event: &dyn Fn(ApplyEvent),
    audit_log: &mut Option<AuditLog>,
    warnings: &mut Warnings,
) {
    let touched: BTreeSet<ManagerId> = plan
        .actions
        .iter()
        .zip(results.iter())
        .filter(|(_, r)| matches!(r.status, ActionStatus::Installed | ActionStatus::NeedsRestart))
        .map(|(a, _)| a.manager)
        .collect();
    let mut pending: HashMap<ManagerId, Option<Vec<String>>> = HashMap::new();
    for m in touched {
        on_event(ApplyEvent::Verifying(m));
        let list = managers::get(m)
            .updates(runner, ctx)
            .ok()
            .map(|ups| ups.into_iter().map(|u| u.key()).collect());
        pending.insert(m, list);
    }
    for (a, r) in plan.actions.iter().zip(results.iter_mut()) {
        if !matches!(r.status, ActionStatus::Installed | ActionStatus::NeedsRestart) {
            continue;
        }
        match pending.get(&a.manager) {
            Some(Some(still)) => {
                let left: Vec<&str> = a
                    .updates
                    .iter()
                    .filter(|u| still.contains(&u.key()))
                    .map(|u| u.name.as_str())
                    .collect();
                if left.is_empty() {
                    if r.status == ActionStatus::Installed {
                        r.status = ActionStatus::Verified;
                    }
                    r.message = format!("{}; no longer listed by {}", r.message, a.manager.display_name());
                } else if r.status == ActionStatus::NeedsRestart {
                    r.message = format!("{}; still listed until the restart", r.message);
                } else {
                    r.status = ActionStatus::Failed;
                    r.message = format!(
                        "command succeeded but {} still lists: {}",
                        a.manager.display_name(),
                        left.join(", ")
                    );
                }
            }
            _ => {
                r.message = format!(
                    "{}; could not re-query {} to verify",
                    r.message,
                    a.manager.display_name()
                )
            }
        }
        warnings.audit(audit_log, false, r);
    }
}

/// Refresh package metadata (`apt-get update`, `brew update`, …) for every
/// available manager that has such a step.
pub fn refresh_metadata(
    report: &SystemReport,
    runner: &dyn CommandRunner,
    elevation: Elevation,
    progress: &dyn Fn(&str),
) -> Vec<(ManagerId, Result<(), String>)> {
    let elevation = if is_elevated(runner) {
        Elevation::None
    } else {
        elevation
    };
    let mut out = Vec::new();
    for inv in report.managers.iter().filter(|m| m.available) {
        let Some(spec) = managers::get(inv.id).refresh_command() else {
            continue;
        };
        progress(&format!("Refreshing {}…", inv.id.display_name()));
        let spec = match elevate(&spec, elevation) {
            Ok(s) => s,
            Err(e) => {
                out.push((inv.id, Err(e.to_string())));
                continue;
            }
        };
        let res = match runner.run(&spec) {
            Ok(o) if o.success() => Ok(()),
            Ok(o) => Err(o.tail(300)),
            Err(e) => Err(e.to_string()),
        };
        out.push((inv.id, res));
    }
    out
}

/// Plan from a saved scan (`apply --from`) without trusting the file beyond
/// the person's selection. The file contributes which updates (their keys)
/// and the research; everything that decides whether and how an update is
/// installed comes from this machine, now:
///
/// - a scan of another OS install (name, version, kernel or build) is
///   refused: scan again;
/// - each manager with a selected update is asked again, and only updates
///   it still offers are planned, with its current kind, restart flag,
///   version and notes (a crafted id, such as a Homebrew tap formula, is
///   not offered, so it is refused);
/// - whole-system managers (pacman) keep every update they offer now, so the
///   plan sees everything `pacman -Syu` would install.
///
/// Returns the report the plan was built from (this machine's OS) and the plan.
pub fn plan_from_saved(
    scan: &Scan,
    live_os: &OsInfo,
    runner: &dyn CommandRunner,
    policy: &Policy,
    selection: &Selection,
    progress: &dyn Fn(&str),
) -> Result<(SystemReport, UpdatePlan), String> {
    let saved = &scan.report.os;
    if (saved.family, &saved.name, &saved.version, &saved.kernel, &saved.build)
        != (
            live_os.family,
            &live_os.name,
            &live_os.version,
            &live_os.kernel,
            &live_os.build,
        )
    {
        let describe = |os: &OsInfo| {
            format!(
                "{} (kernel {}{})",
                os.name,
                os.kernel,
                os.build.as_ref().map(|b| format!(", build {b}")).unwrap_or_default()
            )
        };
        return Err(format!(
            "the scan was taken on {}, but this machine runs {}; its updates may not apply here, so scan again",
            describe(saved),
            describe(live_os)
        ));
    }
    let selected = selected_keys(&scan.report, &scan.analysis, selection);
    let ctx = Context::new(live_os.clone());
    let mut report = scan.report.clone();
    report.os = live_os.clone();
    let mut refused: Vec<Excluded> = Vec::new();
    let mut asked: BTreeSet<ManagerId> = BTreeSet::new();
    for inv in &mut report.managers {
        // The plan reports disabled managers itself.
        if policy.managers.disabled.contains(&inv.id) {
            continue;
        }
        let wanted: Vec<&AvailableUpdate> = inv.updates.iter().filter(|u| selected.contains(&u.key())).collect();
        // A manager listed twice in the file is asked (and planned) once.
        if wanted.is_empty() || !asked.insert(inv.id) {
            inv.updates.clear();
            continue;
        }
        progress(&format!("Checking {} again…", inv.id.display_name()));
        let mgr = managers::get(inv.id);
        let refuse = |u: &AvailableUpdate, reason: String| Excluded {
            key: u.key(),
            title: format!(
                "{} {} → {}",
                u.name,
                u.installed_version.as_deref().unwrap_or("installed"),
                u.available_version
            ),
            reason,
        };
        let live = match mgr.updates(runner, &ctx) {
            Ok(l) => l,
            Err(e) => {
                refused.extend(
                    wanted
                        .iter()
                        .map(|u| refuse(u, format!("could not ask {} again: {e}", inv.id.display_name()))),
                );
                inv.updates.clear();
                continue;
            }
        };
        refused.extend(
            wanted
                .iter()
                .filter(|u| !live.iter().any(|l| l.key() == u.key()))
                .map(|u| refuse(u, format!("no longer offered by {}", inv.id.display_name()))),
        );
        let saved_keys: Vec<String> = inv.updates.iter().map(|u| u.key()).collect();
        inv.updates = live
            .into_iter()
            .filter(|l| mgr.upgrade_all_only() || saved_keys.contains(&l.key()))
            .collect();
    }
    let mut plan = build_plan(&report, &scan.analysis, policy, selection);
    plan.excluded.extend(refused);
    Ok((report, plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_refuses_a_second_apply_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let first = take_lock(Some(dir.path())).unwrap();
        let err = take_lock(Some(dir.path())).err().expect("second apply refused");
        assert!(err.to_string().contains("another patchscope apply"), "{err}");
        drop(first);
        // Other tests spawn processes on other threads; a child forked in
        // that instant shares the descriptor until it execs (where
        // close-on-exec drops it), so allow the release a moment.
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while take_lock(Some(dir.path())).is_err() {
            assert!(Instant::now() < deadline, "free again once the first apply ends");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn a_leftover_lock_file_with_no_holder_does_not_block() {
        // What a run killed without unwinding (Ctrl-C at a sudo prompt) leaves.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("apply.lock"), "pid=1 started=2026-10-04T00:00:00Z\n").unwrap();
        take_lock(Some(dir.path())).expect("an unheld lock file is not a running apply");
    }

    #[test]
    fn a_long_apply_keeps_its_lock() {
        let dir = tempfile::tempdir().unwrap();
        let _first = take_lock(Some(dir.path())).unwrap();
        // Seven hours in: an age heuristic would call this lock stale.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 3600);
        std::fs::File::options()
            .write(true)
            .open(dir.path().join("apply.lock"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(
            take_lock(Some(dir.path())).is_err(),
            "a running apply's lock must not be taken over, however old"
        );
    }
}
