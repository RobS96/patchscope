//! Linux: APT (Debian/Ubuntu), DNF (Fedora/RHEL/Rocky/Alma), pacman (Arch),
//! Flatpak and Snap.

use super::{Context, ListResult, Manager, mins, run_list};
use crate::exec::{CommandRunner, CommandSpec};
use crate::model::{AvailableUpdate, ManagerId, OsFamily, Package, UpdateKind};
use std::collections::HashSet;

// Elevated commands name their program by absolute path: `sudo` without a
// `secure_path`, `pkexec` and `env` would otherwise look a bare name up on
// the caller's PATH, which can hold user-writable directories. These are
// the paths every mainstream distribution installs the tools at (on
// merged-/usr systems /bin and /sbin are links into /usr/bin).
const APT_GET: &str = "/usr/bin/apt-get";
const DNF: &str = "/usr/bin/dnf";
const PACMAN: &str = "/usr/bin/pacman";
const SNAP: &str = "/usr/bin/snap";

fn c_locale(spec: CommandSpec) -> CommandSpec {
    spec.env("LC_ALL", "C")
}

// -------------------------------------------------------------------- APT

pub struct Apt;

/// `dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n'`
pub(crate) fn parse_dpkg_query(text: &str, ecosystem: Option<&str>) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 5 || !f[4].starts_with("ii") {
                return None;
            }
            Some(Package {
                manager: ManagerId::Apt,
                name: f[0].to_string(),
                version: f[1].to_string(),
                source_name: Some(f[2].to_string()).filter(|s| !s.is_empty()),
                source_version: Some(f[3].to_string()).filter(|s| !s.is_empty()),
                ecosystem: ecosystem.map(str::to_string),
            })
        })
        .collect()
}

/// `apt list --upgradable`:
/// `curl/noble-updates,noble-security 8.5.0-2ubuntu10.6 amd64 [upgradable from: 8.5.0-2ubuntu10.5]`
///
/// With multiarch, a foreign-architecture copy is its own line with the same
/// name (`libc6/… i386`); given dpkg's native architecture, those get the
/// `name:arch` id apt-get takes, so the two do not share one key.
pub(crate) fn parse_apt_upgradable(text: &str, native_arch: Option<&str>) -> Vec<AvailableUpdate> {
    text.lines()
        .filter_map(|l| {
            let (name_suites, rest) = l.split_once(' ')?;
            let (name, suites) = name_suites.split_once('/')?;
            let mut it = rest.split_whitespace();
            let version = it.next()?;
            let arch = it.next().unwrap_or_default();
            let id = match native_arch {
                Some(native) if !arch.is_empty() && arch != native && arch != "all" => format!("{name}:{arch}"),
                _ => name.to_string(),
            };
            let from = l
                .split("upgradable from: ")
                .nth(1)
                .map(|s| s.trim_end_matches(']').trim().to_string());
            Some(AvailableUpdate {
                manager: ManagerId::Apt,
                id,
                name: name.to_string(),
                installed_version: from,
                available_version: version.to_string(),
                kind: UpdateKind::Package,
                security: suites.split(',').any(|s| s.contains("-security") || s == "security"),
                restart_required: is_reboot_package(name),
                notes: None,
            })
        })
        .collect()
}

/// A Debian package name (lowercase letters, digits, `+`, `-`, `.`; at
/// least two characters, starting with a letter or digit), optionally
/// `:arch`. apt-get reads more than names: a trailing `-` means "remove",
/// `~` and `?` start search patterns, `=`/`/` pick versions and releases.
pub(crate) fn valid_debian_package(id: &str) -> bool {
    let (name, arch) = match id.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (id, None),
    };
    let lower = |s: &str, extra: &str| {
        s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
    };
    name.len() >= 2
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !name.ends_with('-')
        && lower(name, "+-.")
        && arch.is_none_or(|a| !a.is_empty() && !a.starts_with('-') && !a.ends_with('-') && lower(a, "-"))
}

/// Packages whose update only takes full effect after a reboot.
fn is_reboot_package(name: &str) -> bool {
    name.starts_with("linux-image")
        || name.starts_with("kernel")
        || name == "linux"
        || name.starts_with("linux-lts")
        || name == "systemd"
        || name.starts_with("glibc")
        || name == "libc6"
        || name.starts_with("dbus")
}

impl Manager for Apt {
    fn id(&self) -> ManagerId {
        ManagerId::Apt
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Linux
    }
    fn program(&self) -> &'static str {
        "apt-get"
    }
    fn version(&self, runner: &dyn CommandRunner) -> Option<String> {
        let out = runner.run(&CommandSpec::new("apt-get", &["--version"])).ok()?;
        out.stdout.lines().next().map(|l| l.trim().to_string())
    }
    fn installed(&self, runner: &dyn CommandRunner, ctx: &Context) -> ListResult<Vec<Package>> {
        let fmt = "${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n";
        let text = run_list(
            runner,
            c_locale(CommandSpec::new("dpkg-query", &["-W", "-f", fmt])),
            &[],
        )?;
        Ok(parse_dpkg_query(&text, ctx.osv_distro_ecosystem().as_deref()))
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // Best effort: without it, foreign-architecture lines keep the bare name.
        let native = run_list(
            runner,
            c_locale(CommandSpec::new("dpkg", &["--print-architecture"])).timeout(mins(1)),
            &[],
        )
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|a| {
            !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
        let text = run_list(
            runner,
            c_locale(CommandSpec::new("apt", &["list", "--upgradable"])),
            &[],
        )?;
        Ok(parse_apt_upgradable(&text, native.as_deref()))
    }
    fn refresh_command(&self) -> Option<CommandSpec> {
        Some(
            c_locale(CommandSpec::new(APT_GET, &["update"]))
                .timeout(mins(10))
                .elevated(),
        )
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        // --only-upgrade: never installs a package that is not there already.
        // Phased updates are included: the person chose this update.
        c_locale(CommandSpec::new(
            APT_GET,
            &[
                "install",
                "--only-upgrade",
                // Abort rather than remove anything to satisfy an upgrade.
                "--no-remove",
                "-y",
                "-o",
                "APT::Get::Always-Include-Phased-Updates=true",
                // Keep locally edited config files instead of stopping at
                // dpkg's prompt (stdin is not a terminal).
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                &u.id,
            ],
        ))
        .env("DEBIAN_FRONTEND", "noninteractive")
        .timeout(mins(60))
        .elevated()
    }
}

// -------------------------------------------------------------------- DNF

pub struct Dnf;

/// Strip `-VERSION-RELEASE.ARCH` from an RPM NEVRA, leaving the name.
pub(crate) fn rpm_name_from_nevra(nevra: &str) -> Option<&str> {
    let no_arch = nevra.rsplit_once('.').map_or(nevra, |(a, _)| a);
    let (rest, _release) = no_arch.rsplit_once('-')?;
    let (name, _version) = rest.rsplit_once('-')?;
    Some(name)
}

/// `rpm -qa --qf '%{NAME}\t[EPOCH:]%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n'`. The
/// epoch is kept: OSV's Rocky and Alma ranges carry it, and without it a
/// `1:` package compares as older than every fix.
pub(crate) fn parse_rpm_qa(text: &str, ecosystem: Option<&str>) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 2 || f[0].is_empty() || f[0] == "gpg-pubkey" {
                return None;
            }
            let source = f
                .get(2)
                .and_then(|s| s.strip_suffix(".src.rpm"))
                .and_then(rpm_name_from_nevra_src);
            Some(Package {
                manager: ManagerId::Dnf,
                name: f[0].to_string(),
                version: f[1].to_string(),
                source_name: source.map(str::to_string),
                source_version: source.map(|_| f[1].to_string()),
                ecosystem: ecosystem.map(str::to_string),
            })
        })
        .collect()
}

/// `openssl-3.0.7-27.el9` (source RPM without `.src.rpm`) → `openssl`.
fn rpm_name_from_nevra_src(s: &str) -> Option<&str> {
    let (rest, _release) = s.rsplit_once('-')?;
    let (name, _version) = rest.rsplit_once('-')?;
    Some(name)
}

/// `dnf repoquery --upgrades --qf '%{name}\t%{evr}\t%{reponame}\n'`. dnf4
/// adds its own newline after each entry, dnf5 does not, so blank lines are
/// skipped. When several upgrades of one package are listed, the last
/// (newest) wins.
pub(crate) fn parse_dnf_upgrades(text: &str, security: &HashSet<String>) -> Vec<AvailableUpdate> {
    let mut by_name: Vec<AvailableUpdate> = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 2 || f[0].trim().is_empty() {
            continue;
        }
        let name = f[0].trim();
        let evr = f[1].trim();
        // The epoch "0:" is noise for people reading the report.
        let evr = evr.strip_prefix("0:").unwrap_or(evr);
        let u = AvailableUpdate {
            manager: ManagerId::Dnf,
            id: name.to_string(),
            name: name.to_string(),
            installed_version: None,
            available_version: evr.to_string(),
            kind: UpdateKind::Package,
            security: security.contains(name),
            restart_required: is_reboot_package(name),
            notes: f.get(2).map(|r| format!("repository: {}", r.trim())),
        };
        match by_name.iter_mut().find(|x| x.id == u.id) {
            Some(existing) => *existing = u,
            None => by_name.push(u),
        }
    }
    by_name
}

/// Package names with a pending security advisory, from dnf4
/// `updateinfo list --security` or dnf5 `advisory list --security`. Both
/// print one row per (advisory, package) with the NEVRA as a column.
pub(crate) fn parse_dnf_security(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for l in text.lines() {
        for tok in l.split_whitespace() {
            if tok.matches('-').count() >= 2
                && tok.contains('.')
                && !tok.starts_with("FEDORA-")
                && !tok.starts_with("RHSA-")
                && !tok.starts_with("RLSA-")
                && !tok.starts_with("ALSA-")
                && let Some(name) = rpm_name_from_nevra(tok)
            {
                out.insert(name.to_string());
            }
        }
    }
    out
}

impl Manager for Dnf {
    fn id(&self) -> ManagerId {
        ManagerId::Dnf
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Linux
    }
    fn program(&self) -> &'static str {
        "dnf"
    }
    fn installed(&self, runner: &dyn CommandRunner, ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(
            runner,
            c_locale(CommandSpec::new(
                "rpm",
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n",
                ],
            )),
            &[],
        )?;
        Ok(parse_rpm_qa(&text, ctx.osv_distro_ecosystem().as_deref()))
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // Security advisories are a best-effort extra: some mirrors carry none.
        let sec = run_list(
            runner,
            c_locale(CommandSpec::new(
                "dnf",
                &["-q", "updateinfo", "list", "--security", "--updates"],
            ))
            .timeout(mins(10)),
            &[],
        )
        .map(|t| parse_dnf_security(&t))
        .unwrap_or_default();
        let text = run_list(
            runner,
            c_locale(CommandSpec::new(
                "dnf",
                &[
                    "-q",
                    "repoquery",
                    "--upgrades",
                    "--latest-limit=1",
                    "--qf",
                    "%{name}\t%{evr}\t%{reponame}\n",
                ],
            ))
            .timeout(mins(10)),
            &[],
        )?;
        Ok(parse_dnf_upgrades(&text, &sec))
    }
    fn refresh_command(&self) -> Option<CommandSpec> {
        Some(
            c_locale(CommandSpec::new(DNF, &["-q", "makecache"]))
                .timeout(mins(10))
                .elevated(),
        )
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        c_locale(CommandSpec::new(DNF, &["upgrade", "-y", &u.id]))
            .timeout(mins(60))
            .elevated()
    }
}

// ----------------------------------------------------------------- pacman

pub struct Pacman;

/// `pacman -Q` lines: `name version`.
pub(crate) fn parse_pacman_q(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let (n, v) = l.trim().split_once(' ')?;
            Some(Package {
                manager: ManagerId::Pacman,
                name: n.to_string(),
                version: v.trim().to_string(),
                source_name: None,
                source_version: None,
                ecosystem: None,
            })
        })
        .collect()
}

/// `checkupdates` / `pacman -Qu` lines: `name 1.0-1 -> 1.1-1`.
pub(crate) fn parse_pacman_qu(text: &str) -> Vec<AvailableUpdate> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || f[2] != "->" {
                return None;
            }
            Some(AvailableUpdate {
                manager: ManagerId::Pacman,
                id: f[0].to_string(),
                name: f[0].to_string(),
                installed_version: Some(f[1].to_string()),
                available_version: f[3].to_string(),
                kind: UpdateKind::Package,
                security: false,
                restart_required: is_reboot_package(f[0]),
                notes: Some("Arch Linux updates the whole system at once (no partial upgrades)".into()),
            })
        })
        .collect()
}

impl Manager for Pacman {
    fn id(&self) -> ManagerId {
        ManagerId::Pacman
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Linux
    }
    fn program(&self) -> &'static str {
        "pacman"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        Ok(parse_pacman_q(&run_list(
            runner,
            c_locale(CommandSpec::new("pacman", &["-Q"])),
            &[],
        )?))
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // checkupdates (pacman-contrib) syncs a private copy of the database,
        // so it sees new versions without root. Exit 2 means "none".
        let checked = runner.which("checkupdates").and_then(|_| {
            run_list(
                runner,
                c_locale(CommandSpec::new("checkupdates", &[])).timeout(mins(10)),
                &[2],
            )
            .ok()
        });
        let text = match checked {
            Some(t) => t,
            // No checkupdates, or it failed (it needs fakeroot): pacman -Qu
            // against the local database. It exits 1 when nothing is out of date.
            None => run_list(runner, c_locale(CommandSpec::new("pacman", &["-Qu"])), &[1])?,
        };
        Ok(parse_pacman_qu(&text))
    }
    fn install_command(&self, _u: &AvailableUpdate) -> CommandSpec {
        c_locale(CommandSpec::new(PACMAN, &["-Syu", "--noconfirm"]))
            .timeout(mins(90))
            .elevated()
    }
    fn upgrade_all_only(&self) -> bool {
        true
    }
}

// ----------------------------------------------------------------- Flatpak

pub struct Flatpak;

fn parse_tab_rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(|s| s.trim().to_string()).collect())
        .collect()
}

impl Manager for Flatpak {
    fn id(&self) -> ManagerId {
        ManagerId::Flatpak
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Linux
    }
    fn program(&self) -> &'static str {
        "flatpak"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(
            runner,
            CommandSpec::new("flatpak", &["list", "--app", "--columns=application,version"]),
            &[],
        )?;
        Ok(parse_tab_rows(&text)
            .into_iter()
            .map(|r| Package {
                manager: ManagerId::Flatpak,
                name: r[0].clone(),
                version: r.get(1).cloned().unwrap_or_default(),
                source_name: None,
                source_version: None,
                ecosystem: None,
            })
            .collect())
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        let text = run_list(
            runner,
            CommandSpec::new(
                "flatpak",
                &["remote-ls", "--updates", "--app", "--columns=application,version"],
            )
            .timeout(mins(5)),
            &[],
        )?;
        Ok(parse_tab_rows(&text)
            .into_iter()
            .map(|r| AvailableUpdate {
                manager: ManagerId::Flatpak,
                id: r[0].clone(),
                name: r[0].clone(),
                installed_version: None,
                available_version: r
                    .get(1)
                    .cloned()
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| "newer build".into()),
                kind: UpdateKind::Application,
                security: false,
                restart_required: false,
                notes: None,
            })
            .collect())
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        CommandSpec::new("flatpak", &["update", "-y", "--noninteractive", &u.id]).timeout(mins(60))
    }
}

// -------------------------------------------------------------------- Snap

pub struct Snap;

/// `snap list` / `snap refresh --list`: whitespace table with a header row.
pub(crate) fn parse_snap_table(text: &str) -> Vec<(String, String)> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    match lines.next() {
        Some(h) if h.starts_with("Name") => {}
        _ => return Vec::new(),
    }
    lines
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

impl Manager for Snap {
    fn id(&self) -> ManagerId {
        ManagerId::Snap
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Linux
    }
    fn program(&self) -> &'static str {
        "snap"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(runner, CommandSpec::new("snap", &["list"]), &[])?;
        Ok(parse_snap_table(&text)
            .into_iter()
            .map(|(name, version)| Package {
                manager: ManagerId::Snap,
                name,
                version,
                source_name: None,
                source_version: None,
                ecosystem: None,
            })
            .collect())
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        let text = run_list(
            runner,
            CommandSpec::new("snap", &["refresh", "--list"]).timeout(mins(5)),
            &[],
        )?;
        Ok(parse_snap_table(&text)
            .into_iter()
            .map(|(name, version)| AvailableUpdate {
                manager: ManagerId::Snap,
                id: name.clone(),
                name,
                installed_version: None,
                available_version: version,
                kind: UpdateKind::Application,
                security: false,
                restart_required: false,
                notes: None,
            })
            .collect())
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        CommandSpec::new(SNAP, &["refresh", &u.id]).timeout(mins(60)).elevated()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{inventory, test_ctx};
    use super::*;
    use crate::exec::{CommandOutput, FakeRunner};

    #[test]
    fn apt_inventory_and_security_pocket() {
        let dpkg = "curl\t8.5.0-2ubuntu10.5\tcurl\t8.5.0-2ubuntu10.5\tii \n\
                    libssl3t64\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4\tii \n\
                    oldpkg\t1.0\t\t\trc \n";
        let upg = "Listing...\n\
                   curl/noble-updates,noble-security 8.5.0-2ubuntu10.6 amd64 [upgradable from: 8.5.0-2ubuntu10.5]\n\
                   tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]\n\
                   linux-image-generic/noble-security 6.8.0-80.80 amd64 [upgradable from: 6.8.0-79.79]\n";
        let fmt = "${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n";
        let r = FakeRunner::new()
            .respond("apt-get --version", CommandOutput::ok("apt 2.7.14 (amd64)\n"))
            .respond(&format!("dpkg-query -W -f {fmt}"), CommandOutput::ok(dpkg))
            .respond("apt list --upgradable", CommandOutput::ok(upg));
        let inv = inventory(&Apt, &r, &test_ctx(OsFamily::Linux, Some(("ubuntu", "24.04"))));
        assert!(inv.error.is_none(), "{:?}", inv.error);
        assert_eq!(
            inv.installed.len(),
            2,
            "removed-but-configured packages are not installed"
        );
        assert_eq!(inv.installed[1].source_name.as_deref(), Some("openssl"));
        assert_eq!(inv.installed[1].ecosystem.as_deref(), Some("Ubuntu:24.04:LTS"));
        assert_eq!(inv.updates.len(), 3);
        assert!(inv.updates[0].security);
        assert!(!inv.updates[1].security);
        assert!(inv.updates[2].restart_required);
        assert_eq!(inv.updates[0].installed_version.as_deref(), Some("8.5.0-2ubuntu10.5"));

        let cmd = Apt.install_command(&inv.updates[0]);
        assert_eq!(
            cmd.args,
            [
                "install",
                "--only-upgrade",
                "--no-remove",
                "-y",
                "-o",
                "APT::Get::Always-Include-Phased-Updates=true",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "curl"
            ]
        );
        assert!(cmd.needs_elevation);
        assert_eq!(cmd.program, "/usr/bin/apt-get", "elevated: never looked up on PATH");
        assert!(cmd.env.contains(&("DEBIAN_FRONTEND".into(), "noninteractive".into())));
    }

    #[test]
    fn apt_install_never_removes() {
        // `apt-get install name-` removes `name`; --no-remove makes apt-get
        // abort instead of removing anything, whatever the argument.
        let u = AvailableUpdate {
            manager: ManagerId::Apt,
            id: "curl".into(),
            name: "curl".into(),
            installed_version: None,
            available_version: "8.5.0-2ubuntu10.6".into(),
            kind: UpdateKind::Package,
            security: false,
            restart_required: false,
            notes: None,
        };
        assert!(Apt.install_command(&u).args.iter().any(|a| a == "--no-remove"));
    }

    #[test]
    fn apt_foreign_architectures_get_their_own_key() {
        let upg = "Listing...\n\
                   libc6/noble-updates 2.39-0ubuntu8.6 amd64 [upgradable from: 2.39-0ubuntu8.5]\n\
                   libc6/noble-updates 2.39-0ubuntu8.6 i386 [upgradable from: 2.39-0ubuntu8.5]\n\
                   tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]\n";
        let r = FakeRunner::new()
            .respond("dpkg --print-architecture", CommandOutput::ok("amd64\n"))
            .respond("apt list --upgradable", CommandOutput::ok(upg));
        let u = Apt
            .updates(&r, &test_ctx(OsFamily::Linux, Some(("ubuntu", "24.04"))))
            .unwrap();
        let keys: Vec<String> = u.iter().map(|u| u.key()).collect();
        assert_eq!(keys, ["apt:libc6", "apt:libc6:i386", "apt:tzdata"]);
        assert_eq!(u[1].name, "libc6");
        assert!(u[1].restart_required);
        assert_eq!(Apt.install_command(&u[1]).args.last().unwrap(), "libc6:i386");
        // Without dpkg's answer nothing is qualified (the old behaviour).
        let r = FakeRunner::new().respond("apt list --upgradable", CommandOutput::ok(upg));
        let u = Apt.updates(&r, &test_ctx(OsFamily::Linux, None)).unwrap();
        assert_eq!(u[1].id, "libc6");
    }

    #[test]
    fn dnf_upgrades_security_and_dedup() {
        let sec = "FEDORA-2025-1a2b3c4d5e Important/Sec.  curl-8.11.1-4.fc42.x86_64\n\
                   FEDORA-2025-9f8e7d6c5b Moderate/Sec.   openssl-libs-1:3.2.4-1.fc42.x86_64\n";
        let set = parse_dnf_security(sec);
        assert!(set.contains("curl"), "{set:?}");
        assert!(set.contains("openssl-libs"), "{set:?}");
        let up = "curl\t8.11.1-4.fc42\tupdates\n\n\
                  openssl-libs\t1:3.2.4-1.fc42\tupdates\n\
                  vim-enhanced\t2:9.1.1000-1.fc42\tupdates\n\
                  vim-enhanced\t2:9.1.1100-1.fc42\tupdates\n";
        let u = parse_dnf_upgrades(up, &set);
        assert_eq!(u.len(), 3);
        assert!(u[0].security && u[1].security && !u[2].security);
        assert_eq!(u[2].available_version, "2:9.1.1100-1.fc42");
        assert_eq!(Dnf.install_command(&u[0]).args, ["upgrade", "-y", "curl"]);
    }

    #[test]
    fn rpm_names() {
        assert_eq!(rpm_name_from_nevra("curl-8.11.1-4.fc42.x86_64"), Some("curl"));
        assert_eq!(
            rpm_name_from_nevra("python3-libs-3.13.1-2.fc42.x86_64"),
            Some("python3-libs")
        );
        let pk = parse_rpm_qa(
            "openssl-libs\t3.0.7-27.el9\topenssl-3.0.7-27.el9.src.rpm\ngpg-pubkey\tx-y\t(none)\n",
            Some("Rocky Linux:9"),
        );
        assert_eq!(pk.len(), 1);
        assert_eq!(pk[0].source_name.as_deref(), Some("openssl"));
    }

    #[test]
    fn pacman_is_whole_system() {
        let u = parse_pacman_qu("linux 6.16.1.arch1-1 -> 6.16.2.arch1-1\nfirefox 142.0-1 -> 143.0-1\n");
        assert_eq!(u.len(), 2);
        assert!(u[0].restart_required);
        assert!(Pacman.upgrade_all_only());
        assert_eq!(Pacman.install_command(&u[1]).args, ["-Syu", "--noconfirm"]);
        assert_eq!(parse_pacman_q("bash 5.3.3-1\n")[0].version, "5.3.3-1");
    }

    #[test]
    fn pacman_uses_checkupdates_and_accepts_its_none_code() {
        let r = FakeRunner::new()
            .respond("pacman --version", CommandOutput::ok("Pacman v7.0.0\n"))
            .respond("pacman -Q", CommandOutput::ok("bash 5.3.3-1\n"))
            .respond("checkupdates", CommandOutput::with_status(2, "", ""));
        let inv = inventory(&Pacman, &r, &test_ctx(OsFamily::Linux, Some(("arch", "rolling"))));
        assert!(inv.error.is_none(), "{:?}", inv.error);
        assert!(inv.updates.is_empty());
    }

    #[test]
    fn pacman_falls_back_when_checkupdates_fails() {
        let r = FakeRunner::new()
            .respond("pacman --version", CommandOutput::ok("Pacman v7.0.0\n"))
            .respond("pacman -Q", CommandOutput::ok("bash 5.3.3-1\n"))
            .respond(
                "checkupdates",
                CommandOutput::with_status(1, "", "==> ERROR: Cannot find the fakeroot binary."),
            )
            .respond("pacman -Qu", CommandOutput::ok("bash 5.3.3-1 -> 5.3.3-2\n"));
        let inv = inventory(&Pacman, &r, &test_ctx(OsFamily::Linux, Some(("arch", "rolling"))));
        assert!(inv.error.is_none(), "{:?}", inv.error);
        assert_eq!(inv.updates.len(), 1);
    }

    #[test]
    fn rpm_query_keeps_the_epoch() {
        let r = FakeRunner::new().respond(
            "rpm -qa --qf %{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n",
            CommandOutput::ok("openssl\t1:3.5.1-3.el9_7\topenssl-3.5.1-3.el9_7.src.rpm\n"),
        );
        let p = Dnf
            .installed(&r, &test_ctx(OsFamily::Linux, Some(("almalinux", "9.6"))))
            .unwrap();
        assert_eq!(p[0].version, "1:3.5.1-3.el9_7");
        assert_eq!(p[0].source_version.as_deref(), Some("1:3.5.1-3.el9_7"));
        assert_eq!(p[0].ecosystem.as_deref(), Some("AlmaLinux:9"));
    }

    #[test]
    fn snap_and_flatpak_tables() {
        let s = "Name     Version   Rev    Size   Publisher   Notes\nfirefox  143.0-1   6789   250MB  mozilla✓    -\n";
        assert_eq!(parse_snap_table(s), [("firefox".to_string(), "143.0-1".to_string())]);
        assert!(parse_snap_table("All snaps up to date.\n").is_empty());
        let rows = parse_tab_rows("org.mozilla.firefox\t143.0\norg.gimp.GIMP\t\n");
        assert_eq!(rows[1][0], "org.gimp.GIMP");
    }
}
