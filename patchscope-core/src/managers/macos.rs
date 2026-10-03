//! macOS: Homebrew, `softwareupdate` (OS and Apple security updates) and
//! the Mac App Store via `mas`.

use super::{Context, ListResult, Manager, mins, run_list};
use crate::exec::{CommandRunner, CommandSpec};
use crate::model::{AvailableUpdate, ManagerId, OsFamily, Package, UpdateKind};
use serde::Deserialize;

fn brew(args: &[&str]) -> CommandSpec {
    CommandSpec::new("brew", args)
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_ENV_HINTS", "1")
        .env("HOMEBREW_NO_INSTALL_CLEANUP", "1")
        .timeout(mins(5))
}

pub struct Homebrew;

#[derive(Deserialize)]
struct BrewOutdated {
    #[serde(default)]
    formulae: Vec<BrewOutdatedItem>,
    #[serde(default)]
    casks: Vec<BrewOutdatedItem>,
}

#[derive(Deserialize)]
struct BrewOutdatedItem {
    name: String,
    #[serde(default)]
    installed_versions: Vec<String>,
    current_version: String,
    #[serde(default)]
    pinned: bool,
}

/// `brew list --versions` lines: `name v1 [v2 …]`.
fn parse_brew_versions(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let version = it.last()?;
            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

impl Manager for Homebrew {
    fn id(&self) -> ManagerId {
        ManagerId::Homebrew
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        matches!(os, OsFamily::Macos | OsFamily::Linux)
    }
    fn program(&self) -> &'static str {
        "brew"
    }

    fn version(&self, runner: &dyn CommandRunner) -> Option<String> {
        let out = runner.run(&brew(&["--version"])).ok()?;
        out.stdout.lines().next().map(|l| l.trim().to_string())
    }

    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let mut out = Vec::new();
        for (flag, _) in [("--formula", false), ("--cask", true)] {
            let text = run_list(runner, brew(&["list", flag, "--versions"]), &[])?;
            out.extend(parse_brew_versions(&text).into_iter().map(|(name, version)| Package {
                manager: ManagerId::Homebrew,
                name,
                version,
                source_name: None,
                source_version: None,
                ecosystem: None,
            }));
        }
        Ok(out)
    }

    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        let text = run_list(runner, brew(&["outdated", "--json=v2"]), &[])?;
        let parsed: BrewOutdated = serde_json::from_str(&text).map_err(|e| format!("brew outdated JSON: {e}"))?;
        let mut out = Vec::new();
        for (items, cask) in [(parsed.formulae, false), (parsed.casks, true)] {
            for i in items {
                out.push(AvailableUpdate {
                    manager: ManagerId::Homebrew,
                    id: if cask {
                        format!("cask:{}", i.name)
                    } else {
                        i.name.clone()
                    },
                    name: i.name,
                    installed_version: i.installed_versions.last().cloned(),
                    available_version: i.current_version,
                    kind: if cask {
                        UpdateKind::Application
                    } else {
                        UpdateKind::Package
                    },
                    security: false,
                    restart_required: false,
                    notes: i
                        .pinned
                        .then(|| "pinned in Homebrew; `brew upgrade` will skip it".to_string()),
                });
            }
        }
        Ok(out)
    }

    fn refresh_command(&self) -> Option<CommandSpec> {
        Some(CommandSpec::new("brew", &["update"]).timeout(mins(10)))
    }

    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        match u.id.strip_prefix("cask:") {
            Some(token) => brew(&["upgrade", "--cask", token]),
            None => brew(&["upgrade", "--formula", &u.id]),
        }
        .timeout(mins(60))
    }
}

pub struct Softwareupdate;

/// Parse `softwareupdate --list`. Items look like:
///
/// ```text
/// * Label: macOS Tahoe 26.7.2-25H210
///     Title: macOS Tahoe 26.7.2, Version: 26.7.2, Size: 7654321KiB, Recommended: YES, Action: restart,
/// ```
pub(crate) fn parse_softwareupdate(text: &str, os_major: Option<u32>) -> Vec<AvailableUpdate> {
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(l) = t.strip_prefix("* Label:") {
            label = Some(l.trim().to_string());
            continue;
        }
        let Some(lab) = label.take() else { continue };
        let field = |key: &str| -> Option<String> {
            t.split(", ")
                .find_map(|kv| kv.trim().strip_prefix(&format!("{key}: ")))
                .map(|v| v.trim().trim_end_matches(',').to_string())
        };
        let title = field("Title").unwrap_or_else(|| lab.clone());
        let version = field("Version").unwrap_or_default();
        let restart = field("Action").is_some_and(|a| a.eq_ignore_ascii_case("restart"));
        let lower = title.to_ascii_lowercase();
        let is_os = lower.starts_with("macos");
        let major = version.split('.').next().and_then(|m| m.parse::<u32>().ok());
        let kind = if is_os && major.is_some() && os_major.is_some() && major > os_major {
            UpdateKind::OsUpgrade
        } else if is_os {
            UpdateKind::OsUpdate
        } else if lower.contains("firmware") || lower.contains("bridgeos") {
            UpdateKind::Firmware
        } else {
            UpdateKind::Application
        };
        // Apple ships security content in every OS point release and labels
        // standalone security items as such; it does not flag them otherwise.
        let security = matches!(kind, UpdateKind::OsUpdate)
            || lower.contains("security")
            || lower.contains("xprotect")
            || lower.contains("rapid security response");
        out.push(AvailableUpdate {
            manager: ManagerId::Softwareupdate,
            id: lab,
            name: title,
            installed_version: None,
            available_version: version,
            kind,
            security,
            restart_required: restart,
            notes: None,
        });
    }
    out
}

impl Manager for Softwareupdate {
    fn id(&self) -> ManagerId {
        ManagerId::Softwareupdate
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Macos
    }
    fn program(&self) -> &'static str {
        "softwareupdate"
    }
    fn version(&self, _runner: &dyn CommandRunner) -> Option<String> {
        None
    }
    fn installed(&self, _runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        Ok(Vec::new())
    }
    fn updates(&self, runner: &dyn CommandRunner, ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // Contacts Apple's catalogue; slow on a cold cache.
        let text = run_list(
            runner,
            CommandSpec::new("softwareupdate", &["--list"]).timeout(mins(5)),
            &[],
        )?;
        let os_major = ctx.os.version.split('.').next().and_then(|m| m.parse().ok());
        let mut ups = parse_softwareupdate(&text, os_major);
        for u in &mut ups {
            if matches!(u.kind, UpdateKind::OsUpdate | UpdateKind::OsUpgrade) {
                u.installed_version = Some(ctx.os.version.clone());
            }
        }
        Ok(ups)
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        let mut spec = CommandSpec::new("softwareupdate", &["--install", &u.id]);
        if u.kind == UpdateKind::OsUpgrade {
            spec = spec.arg("--agree-to-license");
        }
        // No --restart: patchscope reports that a restart is needed and
        // leaves the moment to the person at the machine.
        spec.timeout(mins(120)).elevated()
    }
}

pub struct Mas;

/// `mas list` (`497799835  Xcode  (26.5)`) and `mas outdated`
/// (`497799835 Xcode (26.4 -> 26.5)`): id, name, version(s) in parentheses.
pub(crate) fn parse_mas_line(line: &str) -> Option<(String, String, String, Option<String>)> {
    let line = line.trim();
    let (id, rest) = line.split_once(char::is_whitespace)?;
    if !id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let open = rest.rfind('(')?;
    let name = rest[..open].trim().to_string();
    let inner = rest[open + 1..].trim_end().trim_end_matches(')');
    let (from, to) = match inner.split_once("->") {
        Some((a, b)) => (a.trim().to_string(), Some(b.trim().to_string())),
        None => (inner.trim().to_string(), None),
    };
    Some((id.to_string(), name, from, to))
}

impl Manager for Mas {
    fn id(&self) -> ManagerId {
        ManagerId::Mas
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Macos
    }
    fn program(&self) -> &'static str {
        "mas"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(runner, CommandSpec::new("mas", &["list"]).timeout(mins(1)), &[])?;
        Ok(text
            .lines()
            .filter_map(parse_mas_line)
            .map(|(_, name, version, _)| Package {
                manager: ManagerId::Mas,
                name,
                version,
                source_name: None,
                source_version: None,
                ecosystem: None,
            })
            .collect())
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        let text = run_list(runner, CommandSpec::new("mas", &["outdated"]).timeout(mins(2)), &[])?;
        Ok(text
            .lines()
            .filter_map(parse_mas_line)
            .map(|(id, name, from, to)| AvailableUpdate {
                manager: ManagerId::Mas,
                id,
                name,
                installed_version: Some(from),
                available_version: to.unwrap_or_default(),
                kind: UpdateKind::Application,
                security: false,
                restart_required: false,
                notes: None,
            })
            .collect())
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        CommandSpec::new("mas", &["upgrade", &u.id]).timeout(mins(60))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{inventory, test_ctx};
    use super::*;
    use crate::exec::{CommandOutput, FakeRunner};

    const BREW_OUTDATED: &str = include_str!("../../tests/fixtures/brew-outdated.json");

    #[test]
    fn homebrew_inventory_from_recorded_output() {
        let r = FakeRunner::new()
            .respond("brew --version", CommandOutput::ok("Homebrew 4.6.12\n"))
            .respond(
                "brew list --formula --versions",
                CommandOutput::ok("git 2.51.0\nopenssl@3 3.5.1 3.5.2\n"),
            )
            .respond("brew list --cask --versions", CommandOutput::ok("firefox 142.0\n"))
            .respond("brew outdated --json=v2", CommandOutput::ok(BREW_OUTDATED));
        let inv = inventory(&Homebrew, &r, &test_ctx(OsFamily::Macos, None));
        assert!(inv.error.is_none(), "{:?}", inv.error);
        assert_eq!(inv.installed.len(), 3);
        assert_eq!(inv.installed[1].version, "3.5.2", "the newest installed keg wins");
        assert_eq!(inv.updates.len(), 3);
        let git = &inv.updates[0];
        assert_eq!(
            (
                git.id.as_str(),
                git.installed_version.as_deref(),
                git.available_version.as_str()
            ),
            ("git", Some("2.51.0"), "2.51.1")
        );
        let pinned = inv.updates.iter().find(|u| u.name == "node").unwrap();
        assert!(pinned.notes.as_deref().unwrap().contains("pinned"));
        let cask = inv.updates.iter().find(|u| u.kind == UpdateKind::Application).unwrap();
        assert_eq!(cask.id, "cask:firefox");
        assert_eq!(Homebrew.install_command(cask).args, ["upgrade", "--cask", "firefox"]);
        assert_eq!(Homebrew.install_command(git).args, ["upgrade", "--formula", "git"]);
        assert!(
            !Homebrew.install_command(git).needs_elevation,
            "Homebrew refuses to run as root"
        );
    }

    #[test]
    fn softwareupdate_list_parses_os_and_other_items() {
        let text = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n\
* Label: macOS Tahoe 26.7.2-25H210\n\tTitle: macOS Tahoe 26.7.2, Version: 26.7.2, Size: 7654321KiB, Recommended: YES, Action: restart, \n\
* Label: macOS Golden Gate 27.0.1-26A120\n\tTitle: macOS Golden Gate 27.0.1, Version: 27.0.1, Size: 15000000KiB, Recommended: YES, Action: restart, \n\
* Label: Command Line Tools for Xcode 26.5-26.5\n\tTitle: Command Line Tools for Xcode 26.5, Version: 26.5, Size: 912345KiB, Recommended: YES, \n";
        let u = parse_softwareupdate(text, Some(26));
        assert_eq!(u.len(), 3);
        assert_eq!(u[0].id, "macOS Tahoe 26.7.2-25H210");
        assert_eq!(u[0].kind, UpdateKind::OsUpdate);
        assert!(u[0].security && u[0].restart_required);
        assert_eq!(u[1].kind, UpdateKind::OsUpgrade);
        assert_eq!(u[2].kind, UpdateKind::Application);
        assert!(!u[2].restart_required);
        assert_eq!(u[2].available_version, "26.5");

        let cmd = Softwareupdate.install_command(&u[0]);
        assert_eq!(cmd.args, ["--install", "macOS Tahoe 26.7.2-25H210"]);
        assert!(cmd.needs_elevation);
        assert!(
            Softwareupdate
                .install_command(&u[1])
                .args
                .contains(&"--agree-to-license".to_string())
        );
    }

    #[test]
    fn softwareupdate_nothing_available() {
        assert!(parse_softwareupdate("Software Update Tool\n\nFinding available software\n", Some(26)).is_empty());
    }

    #[test]
    fn mas_lines() {
        assert_eq!(
            parse_mas_line("497799835  Xcode            (26.5)"),
            Some(("497799835".into(), "Xcode".into(), "26.5".into(), None))
        );
        assert_eq!(
            parse_mas_line("409183694 Keynote (14.3 -> 14.4)"),
            Some(("409183694".into(), "Keynote".into(), "14.3".into(), Some("14.4".into())))
        );
        assert_eq!(
            parse_mas_line("1295203466 Microsoft Remote Desktop (Classic) (10.9.10 -> 10.9.11)")
                .unwrap()
                .1,
            "Microsoft Remote Desktop (Classic)"
        );
        assert_eq!(parse_mas_line("Warning: something"), None);
    }
}
