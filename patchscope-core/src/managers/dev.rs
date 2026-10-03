//! Developer toolchains present on every OS: global npm packages and Rust
//! toolchains managed by rustup.

use super::{Context, ListResult, Manager, mins, run_list};
use crate::exec::{CommandRunner, CommandSpec};
use crate::model::{AvailableUpdate, ManagerId, OsFamily, Package, UpdateKind};
use serde::Deserialize;
use std::collections::BTreeMap;

// -------------------------------------------------------------- npm global

pub struct NpmGlobal;

#[derive(Deserialize)]
struct NpmLs {
    #[serde(default)]
    dependencies: BTreeMap<String, NpmLsDep>,
}

#[derive(Deserialize)]
struct NpmLsDep {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct NpmOutdated {
    #[serde(default)]
    current: Option<String>,
    #[serde(default)]
    latest: Option<String>,
}

pub(crate) fn parse_npm_ls(text: &str) -> Result<Vec<Package>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let ls: NpmLs = serde_json::from_str(text).map_err(|e| format!("npm ls JSON: {e}"))?;
    Ok(ls
        .dependencies
        .into_iter()
        .filter_map(|(name, d)| {
            Some(Package {
                manager: ManagerId::NpmGlobal,
                name,
                version: d.version?,
                source_name: None,
                source_version: None,
                ecosystem: Some("npm".into()),
            })
        })
        .collect())
}

pub(crate) fn parse_npm_outdated(text: &str) -> Result<Vec<AvailableUpdate>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let map: BTreeMap<String, NpmOutdated> =
        serde_json::from_str(text).map_err(|e| format!("npm outdated JSON: {e}"))?;
    Ok(map
        .into_iter()
        .filter_map(|(name, o)| {
            let latest = o.latest?;
            (o.current.as_deref() != Some(latest.as_str())).then(|| AvailableUpdate {
                manager: ManagerId::NpmGlobal,
                id: name.clone(),
                name,
                installed_version: o.current,
                available_version: latest,
                kind: UpdateKind::Package,
                security: false,
                restart_required: false,
                notes: None,
            })
        })
        .collect())
}

/// npm package names: optional `@scope/`, then URL-safe characters. Checked
/// before a name is used in an install command.
pub(crate) fn valid_npm_name(s: &str) -> bool {
    let body = match s.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, name)) if !scope.is_empty() && !name.is_empty() => format!("{scope}{name}"),
            _ => return false,
        },
        None => s.to_string(),
    };
    !body.is_empty() && !s.starts_with('-') && body.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
}

impl Manager for NpmGlobal {
    fn id(&self) -> ManagerId {
        ManagerId::NpmGlobal
    }
    fn supported_on(&self, _os: OsFamily) -> bool {
        true
    }
    fn program(&self) -> &'static str {
        "npm"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(
            runner,
            CommandSpec::new("npm", &["ls", "--global", "--depth=0", "--json"]).timeout(mins(2)),
            &[1],
        )?;
        parse_npm_ls(&text)
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // npm outdated exits 1 when anything is outdated.
        let text = run_list(
            runner,
            CommandSpec::new("npm", &["outdated", "--global", "--json"]).timeout(mins(5)),
            &[1],
        )?;
        parse_npm_outdated(&text)
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        let target = if valid_npm_name(&u.id) {
            format!("{}@{}", u.id, u.available_version)
        } else {
            "invalid-package-name".into()
        };
        CommandSpec::new("npm", &["install", "--global", "--no-fund", "--no-audit", &target]).timeout(mins(30))
    }
}

// ------------------------------------------------------------------ rustup

pub struct Rustup;

/// `rustup check` lines:
/// `stable-x86_64-apple-darwin - Update available : 1.98.0 (…) -> 1.99.0 (…)`
/// `rustup - Up to date : 1.28.2`
pub(crate) fn parse_rustup_check(text: &str) -> Vec<AvailableUpdate> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(" - ")?;
            let (status, versions) = rest.split_once(" : ")?;
            if !status.trim().eq_ignore_ascii_case("Update available") {
                return None;
            }
            let (from, to) = versions.split_once("->")?;
            let first = |s: &str| s.split_whitespace().next().unwrap_or_default().to_string();
            let name = name.trim().to_string();
            Some(AvailableUpdate {
                manager: ManagerId::Rustup,
                id: name.clone(),
                name,
                installed_version: Some(first(from)),
                available_version: first(to),
                kind: UpdateKind::Toolchain,
                security: false,
                restart_required: false,
                notes: None,
            })
        })
        .collect()
}

/// `rustup toolchain list`: one toolchain per line, the default marked `(default)`.
pub(crate) fn parse_rustup_toolchains(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let name = l.split_whitespace().next()?;
            (!name.is_empty() && !name.starts_with("no")).then(|| Package {
                manager: ManagerId::Rustup,
                name: name.to_string(),
                version: if l.contains("(default)") {
                    "default".into()
                } else {
                    "installed".into()
                },
                source_name: None,
                source_version: None,
                ecosystem: None,
            })
        })
        .collect()
}

fn valid_toolchain(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

impl Manager for Rustup {
    fn id(&self) -> ManagerId {
        ManagerId::Rustup
    }
    fn supported_on(&self, _os: OsFamily) -> bool {
        true
    }
    fn program(&self) -> &'static str {
        "rustup"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(runner, CommandSpec::new("rustup", &["toolchain", "list"]), &[])?;
        Ok(parse_rustup_toolchains(&text))
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // `rustup check` exits 100 when updates are available (rustup ≥ 1.28).
        let text = run_list(runner, CommandSpec::new("rustup", &["check"]).timeout(mins(3)), &[100])?;
        Ok(parse_rustup_check(&text))
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        if u.id == "rustup" {
            CommandSpec::new("rustup", &["self", "update"]).timeout(mins(10))
        } else {
            let tc = if valid_toolchain(&u.id) {
                u.id.as_str()
            } else {
                "invalid-toolchain"
            };
            CommandSpec::new("rustup", &["update", "--no-self-update", tc]).timeout(mins(30))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{inventory, test_ctx};
    use super::*;
    use crate::exec::{CommandOutput, FakeRunner};

    #[test]
    fn npm_inventory_with_outdated_exit_code() {
        let ls = r#"{"name":"lib","dependencies":{"npm":{"version":"11.6.0","overridden":false},"minimist":{"version":"1.2.0","overridden":false},"@scope/tool":{"version":"2.0.0"}}}"#;
        let outdated = r#"{"minimist":{"current":"1.2.0","wanted":"1.2.8","latest":"1.2.8","dependent":"global","location":"/usr/local/lib/node_modules/minimist"}}"#;
        let r = FakeRunner::new()
            .respond("npm --version", CommandOutput::ok("11.6.0\n"))
            .respond("npm ls --global --depth=0 --json", CommandOutput::ok(ls))
            .respond(
                "npm outdated --global --json",
                CommandOutput::with_status(1, outdated, ""),
            );
        let inv = inventory(&NpmGlobal, &r, &test_ctx(OsFamily::Windows, None));
        assert!(inv.error.is_none(), "{:?}", inv.error);
        assert_eq!(inv.installed.len(), 3);
        assert!(inv.installed.iter().all(|p| p.ecosystem.as_deref() == Some("npm")));
        assert_eq!(inv.updates.len(), 1);
        assert_eq!(inv.updates[0].available_version, "1.2.8");
        assert_eq!(
            NpmGlobal.install_command(&inv.updates[0]).args,
            ["install", "--global", "--no-fund", "--no-audit", "minimist@1.2.8"]
        );
    }

    #[test]
    fn npm_names_are_validated() {
        assert!(valid_npm_name("left-pad"));
        assert!(valid_npm_name("@scope/pkg.name"));
        assert!(!valid_npm_name("--registry=http://evil"));
        assert!(!valid_npm_name("a b"));
        assert!(!valid_npm_name("@/x"));
        assert!(!valid_npm_name("git+https://x"));
    }

    #[test]
    fn rustup_check_lines() {
        let text = "stable-x86_64-apple-darwin - Update available : 1.98.0 (aaaaaaaa 2026-08-14) -> 1.99.0 (b940084d7 2026-09-28)\n\
                    nightly-x86_64-apple-darwin - Up to date : 1.100.0-nightly (c 2026-10-02)\n\
                    rustup - Update available : 1.28.2 -> 1.29.0\n";
        let u = parse_rustup_check(text);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].installed_version.as_deref(), Some("1.98.0"));
        assert_eq!(u[0].available_version, "1.99.0");
        assert_eq!(
            Rustup.install_command(&u[0]).args,
            ["update", "--no-self-update", "stable-x86_64-apple-darwin"]
        );
        assert_eq!(Rustup.install_command(&u[1]).args, ["self", "update"]);
        let tc = parse_rustup_toolchains("stable-x86_64-apple-darwin (default)\n1.88-x86_64-apple-darwin\n");
        assert_eq!(tc.len(), 2);
        assert_eq!(tc[0].version, "default");
    }
}
