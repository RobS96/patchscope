//! Planning: decide which available updates to install, in what order, and
//! say why each one was included or left out.

use crate::analysis::findings_by_update;
use crate::managers;
use crate::model::{Analysis, AvailableUpdate, ManagerId, Severity, SystemReport, UpdateKind};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};

/// Which updates the person asked for.
#[derive(Debug, Clone, PartialEq)]
pub enum Selection {
    /// Everything the policy allows.
    All,
    /// Updates whose strongest finding is at least this severe.
    AtLeast(Severity),
    /// Exactly these update keys (`manager:id`).
    Keys(Vec<String>),
}

impl Selection {
    /// Whether the update `key`, whose strongest finding is `severity`, is
    /// asked for.
    pub fn includes(&self, key: &str, severity: Severity) -> bool {
        match self {
            Selection::All => true,
            Selection::AtLeast(s) => severity >= *s,
            Selection::Keys(keys) => keys.iter().any(|k| k == key),
        }
    }
}

/// The keys of the updates in `report` that `selection` asks for.
pub fn selected_keys(report: &SystemReport, analysis: &Analysis, selection: &Selection) -> Vec<String> {
    let by_update = findings_by_update(analysis);
    report
        .all_updates()
        .map(|u| u.key())
        .filter(|k| selection.includes(k, strongest(by_update.get(k).map(Vec::as_slice))))
        .collect()
}

fn strongest(findings: Option<&[&crate::model::Finding]>) -> Severity {
    findings
        .unwrap_or_default()
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Low)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlannedAction {
    /// `manager:id` of the update, or `manager:*` for a whole-system upgrade.
    pub key: String,
    pub manager: ManagerId,
    pub title: String,
    pub severity: Severity,
    pub finding_ids: Vec<String>,
    /// The updates this action installs (several for whole-system upgrades).
    pub updates: Vec<AvailableUpdate>,
    /// The exact command, for review before anything runs.
    pub command: String,
    pub needs_elevation: bool,
    pub restart_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Excluded {
    pub key: String,
    pub title: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdatePlan {
    pub generated_at: String,
    pub actions: Vec<PlannedAction>,
    pub excluded: Vec<Excluded>,
}

impl UpdatePlan {
    pub fn needs_elevation(&self) -> bool {
        self.actions.iter().any(|a| a.needs_elevation)
    }
    pub fn restart_required(&self) -> bool {
        self.actions.iter().any(|a| a.restart_required)
    }
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Install order: language/user-level managers first (quick, low risk),
/// system packages next, OS updates (which may want a restart) last.
fn stage(m: ManagerId) -> u8 {
    match m {
        ManagerId::NpmGlobal | ManagerId::Rustup => 0,
        ManagerId::Homebrew
        | ManagerId::Mas
        | ManagerId::Winget
        | ManagerId::Chocolatey
        | ManagerId::Flatpak
        | ManagerId::Snap => 1,
        ManagerId::Apt | ManagerId::Dnf | ManagerId::Pacman => 2,
        ManagerId::Softwareupdate | ManagerId::WindowsUpdate => 3,
    }
}

pub fn build_plan(report: &SystemReport, analysis: &Analysis, policy: &Policy, selection: &Selection) -> UpdatePlan {
    let by_update = findings_by_update(analysis);
    let mut actions: Vec<PlannedAction> = Vec::new();
    let mut excluded: Vec<Excluded> = Vec::new();
    // Whole-system managers (pacman) collect into one action each.
    let mut whole_system: Vec<(ManagerId, Vec<AvailableUpdate>, Severity, Vec<String>)> = Vec::new();

    for u in report.all_updates() {
        let key = u.key();
        let findings = by_update.get(&key).cloned().unwrap_or_default();
        let severity = strongest(Some(&findings));
        let security = u.security || findings.iter().any(|f| !f.advisories.is_empty());
        let title = format!(
            "{} {} → {}",
            u.name,
            u.installed_version.as_deref().unwrap_or("installed"),
            u.available_version
        );
        let exclude = |reason: String| Excluded {
            key: key.clone(),
            title: title.clone(),
            reason,
        };

        if !selection.includes(&key, severity) {
            continue;
        }
        if policy.managers.disabled.contains(&u.manager) {
            excluded.push(exclude(format!(
                "{} is disabled in the policy",
                u.manager.display_name()
            )));
            continue;
        }
        if let Some(p) = policy.protection_for(u) {
            excluded.push(exclude(format!("protected by policy pattern `{p}`")));
            continue;
        }
        if u.kind == UpdateKind::OsUpgrade && !policy.apply.allow_os_upgrades {
            excluded.push(exclude(
                "major OS upgrade; set `allow_os_upgrades = true` to plan it".into(),
            ));
            continue;
        }
        if u.restart_required && !policy.apply.allow_restart_required {
            excluded.push(exclude(
                "needs a restart; set `allow_restart_required = true` to plan it".into(),
            ));
            continue;
        }
        if policy.apply.security_only && !security && severity < Severity::High {
            excluded.push(exclude("not security-related (`security_only = true`)".into()));
            continue;
        }
        if severity < policy.apply.min_severity {
            excluded.push(exclude(format!(
                "below the policy's minimum severity ({})",
                policy.apply.min_severity
            )));
            continue;
        }
        // Identifiers reach package-manager command lines as arguments, and
        // can come from a saved (or crafted) scan file.
        if !managers::valid_identifier(u.manager, &u.id) {
            excluded.push(exclude(format!(
                "`{}` is not a valid {} identifier",
                u.id.escape_debug(),
                u.manager.display_name()
            )));
            continue;
        }
        if !managers::valid_version(u.manager, &u.available_version) {
            excluded.push(exclude(format!(
                "`{}` is not a plain version",
                u.available_version.escape_debug()
            )));
            continue;
        }
        // Apple silicon Macs need the volume owner's password for macOS
        // updates, which softwareupdate can only take on a terminal.
        if u.manager == ManagerId::Softwareupdate
            && matches!(u.kind, UpdateKind::OsUpdate | UpdateKind::OsUpgrade)
            && matches!(report.os.arch.as_str(), "arm64" | "aarch64")
        {
            excluded.push(exclude(
                "on Apple silicon, install macOS updates from System Settings → General → Software Update (they need the owner's password)".into(),
            ));
            continue;
        }
        if u.notes.as_deref().is_some_and(|n| n.contains("truncated")) {
            excluded.push(exclude(
                "the package id was truncated by the package manager; update it there directly".into(),
            ));
            continue;
        }
        let mgr = managers::get(u.manager);
        if mgr.upgrade_all_only() {
            let finding_ids = findings.iter().map(|f| f.id.clone()).collect::<Vec<_>>();
            match whole_system.iter_mut().find(|w| w.0 == u.manager) {
                Some(w) => {
                    w.1.push(u.clone());
                    w.2 = w.2.max(severity);
                    w.3.extend(finding_ids);
                }
                None => whole_system.push((u.manager, vec![u.clone()], severity, finding_ids)),
            }
            continue;
        }
        let cmd = mgr.install_command(u);
        actions.push(PlannedAction {
            key,
            manager: u.manager,
            title,
            severity,
            finding_ids: findings.iter().map(|f| f.id.clone()).collect(),
            updates: vec![u.clone()],
            command: cmd.display(),
            needs_elevation: cmd.needs_elevation,
            restart_required: u.restart_required,
        });
    }

    for (m, ups, severity, finding_ids) in whole_system {
        let title = format!("Full system upgrade (all {} pending packages)", ups.len());
        // The upgrade installs every pending package, so it is planned only
        // if every one of them was selected and allowed.
        let blocked: Vec<&str> = report
            .manager(m)
            .map(|inv| inv.updates.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|p| !ups.iter().any(|u| u.key() == p.key()))
            .map(|p| p.name.as_str())
            .collect();
        if !blocked.is_empty() {
            excluded.push(Excluded {
                key: format!("{m}:*"),
                title,
                reason: format!(
                    "{} can only upgrade every package at once, and these were left out or not selected: {}",
                    m.display_name(),
                    blocked.join(", ")
                ),
            });
            continue;
        }
        let mgr = managers::get(m);
        let cmd = mgr.install_command(&ups[0]);
        actions.push(PlannedAction {
            key: format!("{m}:*"),
            manager: m,
            title,
            severity,
            finding_ids,
            restart_required: ups.iter().any(|u| u.restart_required),
            updates: ups,
            command: cmd.display(),
            needs_elevation: cmd.needs_elevation,
        });
    }

    // The cap keeps the most severe actions, wherever they fall in the order.
    if actions.len() > policy.apply.max_actions {
        actions.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.key.cmp(&b.key)));
        for a in actions.split_off(policy.apply.max_actions) {
            excluded.push(Excluded {
                key: a.key,
                title: a.title,
                reason: format!("over the policy's max_actions ({})", policy.apply.max_actions),
            });
        }
    }
    actions.sort_by(|a, b| {
        stage(a.manager)
            .cmp(&stage(b.manager))
            .then(b.severity.cmp(&a.severity))
            .then(a.key.cmp(&b.key))
    });
    UpdatePlan {
        generated_at: crate::util::now_rfc3339(),
        actions,
        excluded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn update(manager: ManagerId, id: &str, to: &str) -> AvailableUpdate {
        AvailableUpdate {
            manager,
            id: id.into(),
            name: id.into(),
            installed_version: Some("1.0".into()),
            available_version: to.into(),
            kind: UpdateKind::Package,
            security: false,
            restart_required: false,
            notes: None,
        }
    }

    fn report(updates: Vec<AvailableUpdate>) -> SystemReport {
        let mut managers: Vec<ManagerInventory> = Vec::new();
        for u in updates {
            match managers.iter_mut().find(|m| m.id == u.manager) {
                Some(m) => m.updates.push(u),
                None => managers.push(ManagerInventory {
                    id: u.manager,
                    available: true,
                    version: None,
                    installed: Vec::new(),
                    updates: vec![u],
                    error: None,
                }),
            }
        }
        SystemReport {
            schema_version: SCHEMA_VERSION,
            tool_version: "test".into(),
            generated_at: "2026-10-04T00:00:00Z".into(),
            host: HostInfo::default(),
            os: OsInfo {
                family: OsFamily::Linux,
                name: "test".into(),
                version: "1".into(),
                build: None,
                kernel: "k".into(),
                arch: "x86_64".into(),
                distro_id: None,
                distro_version_id: None,
                edition: None,
            },
            hardware: HardwareInfo::default(),
            runtimes: Vec::new(),
            managers,
            warnings: Vec::new(),
        }
    }

    fn analysis() -> Analysis {
        Analysis {
            schema_version: SCHEMA_VERSION,
            generated_at: String::new(),
            offline: true,
            sources: Vec::new(),
            summary: Summary::default(),
            findings: Vec::new(),
        }
    }

    #[test]
    fn npm_versions_must_be_versions() {
        // npm reads `name@<spec>`: a URL, alias, git or file spec there
        // installs something else entirely.
        for spec in [
            "https://evil.example/x.tgz",
            "npm:evil@1.0.0",
            "github:u/r",
            "file:/tmp/x",
            "git+ssh://git@x/y.git",
            "latest",
            "1.2.8 evil",
        ] {
            let r = report(vec![update(ManagerId::NpmGlobal, "minimist", spec)]);
            let plan = build_plan(&r, &analysis(), &Policy::default(), &Selection::All);
            assert!(plan.actions.is_empty(), "{spec}: {:?}", plan.actions);
            assert!(
                plan.excluded[0].reason.contains("not a plain version"),
                "{spec}: {:?}",
                plan.excluded
            );
        }
        for v in ["1.2.8", "2.0.0-beta.1", "1.0.0+build.5"] {
            let r = report(vec![update(ManagerId::NpmGlobal, "minimist", v)]);
            let plan = build_plan(&r, &analysis(), &Policy::default(), &Selection::All);
            assert_eq!(plan.actions.len(), 1, "{v}");
            assert!(plan.actions[0].command.ends_with(&format!("minimist@{v}")));
        }
    }

    #[test]
    fn pacman_whole_system_upgrade_needs_every_pending_package() {
        let ups = || {
            vec![
                update(ManagerId::Pacman, "linux", "6.17"),
                update(ManagerId::Pacman, "firefox", "143.0-1"),
            ]
        };
        // Everything allowed: one action, titled for what it really does.
        let plan = build_plan(&report(ups()), &analysis(), &Policy::default(), &Selection::All);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].key, "pacman:*");
        assert_eq!(plan.actions[0].title, "Full system upgrade (all 2 pending packages)");

        // A protected package would be upgraded by `pacman -Syu` anyway.
        let mut policy = Policy::default();
        policy.apply.protected = vec!["pacman:linux".into()];
        let plan = build_plan(&report(ups()), &analysis(), &policy, &Selection::All);
        assert!(plan.actions.is_empty(), "{:?}", plan.actions);
        let e = plan.excluded.iter().find(|e| e.key == "pacman:*").expect("explained");
        assert!(
            e.reason.contains("linux") && e.reason.contains("at once"),
            "{}",
            e.reason
        );

        // So would one the person did not select.
        let plan = build_plan(
            &report(ups()),
            &analysis(),
            &Policy::default(),
            &Selection::Keys(vec!["pacman:firefox".into()]),
        );
        assert!(plan.actions.is_empty(), "{:?}", plan.actions);
        let e = plan.excluded.iter().find(|e| e.key == "pacman:*").expect("explained");
        assert!(e.reason.contains("linux"), "{}", e.reason);
    }
}
