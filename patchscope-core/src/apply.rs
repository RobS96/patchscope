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
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error(
        "another patchscope apply is running (lock file {0}); wait for it to finish, or delete the file if it is stale"
    )]
    Locked(String),
    #[error("lock file {path}: {source}")]
    Lock {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Removes the lock file when the apply ends, however it ends.
struct LockGuard(Option<PathBuf>);

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

const STALE_LOCK_SECS: u64 = 6 * 3600;

fn take_lock(dir: Option<&Path>) -> Result<LockGuard, ApplyError> {
    let Some(dir) = dir else { return Ok(LockGuard(None)) };
    std::fs::create_dir_all(dir).map_err(|source| ApplyError::Lock {
        path: dir.display().to_string(),
        source,
    })?;
    let path = dir.join("apply.lock");
    for attempt in 0..2 {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                let _ = writeln!(f, "pid={} started={}", std::process::id(), util::now_rfc3339());
                return Ok(LockGuard(Some(path)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > STALE_LOCK_SECS);
                if stale {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                return Err(ApplyError::Locked(path.display().to_string()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ApplyError::Locked(path.display().to_string()));
            }
            Err(source) => {
                return Err(ApplyError::Lock {
                    path: path.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(ApplyError::Locked(path.display().to_string()))
}

fn audit(path: Option<&Path>, dry_run: bool, r: &ActionResult) {
    let Some(path) = path else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(path) {
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
        let _ = writeln!(f, "{line}");
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
        LockGuard(None)
    } else {
        take_lock(opts.lock_dir.as_deref())?
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
        let spec = elevate(&mgr.install_command(&action.updates[0]), elevation);
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
            r.message = "not run (dry run)".into();
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
        audit(opts.audit_log.as_deref(), opts.dry_run, &r);
        on_event(ApplyEvent::Finished {
            index,
            total,
            result: &r,
        });
        results.push(r);
    }

    if opts.verify && !opts.dry_run {
        verify(plan, &mut results, runner, &ctx, on_event, opts);
    }

    Ok(ApplyReport {
        started_at,
        finished_at: util::now_rfc3339(),
        dry_run: opts.dry_run,
        results,
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
    opts: &ApplyOptions,
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
        audit(opts.audit_log.as_deref(), false, r);
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
        let spec = elevate(&spec, elevation);
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
