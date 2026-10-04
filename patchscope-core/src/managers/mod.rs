//! Package-manager adapters. Each one knows how to list what is installed,
//! list what can be updated, and build the command that installs one update.
//! Listing is read-only and unprivileged; only the install commands change
//! anything, and those run only from [`crate::apply`].

mod dev;
mod linux;
mod macos;
mod windows;

pub use dev::{NpmGlobal, Rustup};
pub use linux::{Apt, Dnf, Flatpak, Pacman, Snap};
pub use macos::{Homebrew, Mas, Softwareupdate};
pub use windows::{Chocolatey, WindowsUpdate, Winget};

use crate::exec::{CommandRunner, CommandSpec};
use crate::model::{AvailableUpdate, ManagerId, ManagerInventory, OsFamily, OsInfo, Package};
use std::time::Duration;

/// What an adapter may need to know about the OS (OSV ecosystem names
/// depend on the distribution release, OS update kinds on the version).
#[derive(Debug, Clone)]
pub struct Context {
    pub os: OsInfo,
}

impl Context {
    pub fn new(os: OsInfo) -> Self {
        Context { os }
    }

    /// The OSV ecosystem that indexes this distribution's native packages.
    pub fn osv_distro_ecosystem(&self) -> Option<String> {
        let id = self.os.distro_id.as_deref()?;
        let ver = self.os.distro_version_id.as_deref()?;
        let major = ver.split('.').next().unwrap_or(ver);
        match id {
            "debian" => Some(format!("Debian:{major}")),
            "ubuntu" => {
                // OSV names LTS releases "Ubuntu:24.04:LTS" and interim ones "Ubuntu:25.10".
                let lts = ver.ends_with(".04") && major.parse::<u32>().is_ok_and(|y| y % 2 == 0);
                Some(if lts {
                    format!("Ubuntu:{ver}:LTS")
                } else {
                    format!("Ubuntu:{ver}")
                })
            }
            "rocky" => Some(format!("Rocky Linux:{major}")),
            "almalinux" => Some(format!("AlmaLinux:{major}")),
            _ => None,
        }
    }
}

pub type ListResult<T> = Result<T, String>;

pub trait Manager: Send + Sync {
    fn id(&self) -> ManagerId;
    fn supported_on(&self, os: OsFamily) -> bool;
    /// The executable whose presence means this manager is installed.
    fn program(&self) -> &'static str;

    fn version(&self, runner: &dyn CommandRunner) -> Option<String> {
        let out = runner
            .run(&CommandSpec::new(self.program(), &["--version"]).timeout(Duration::from_secs(30)))
            .ok()?;
        out.success()
            .then(|| {
                out.stdout
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| l.trim().to_string())
            })
            .flatten()
    }

    fn installed(&self, runner: &dyn CommandRunner, ctx: &Context) -> ListResult<Vec<Package>>;
    fn updates(&self, runner: &dyn CommandRunner, ctx: &Context) -> ListResult<Vec<AvailableUpdate>>;

    /// Refresh the manager's package metadata (`apt-get update`). `None`
    /// when listing updates already contacts the source.
    fn refresh_command(&self) -> Option<CommandSpec> {
        None
    }

    /// The command that installs `update`.
    fn install_command(&self, update: &AvailableUpdate) -> CommandSpec;

    /// Some managers cannot update one package on its own (Arch Linux does
    /// not support partial upgrades); they update everything at once.
    fn upgrade_all_only(&self) -> bool {
        false
    }
}

/// Every adapter patchscope ships, in the order reports list them.
pub fn all() -> Vec<Box<dyn Manager>> {
    ManagerId::ALL.into_iter().map(get).collect()
}

pub fn get(id: ManagerId) -> Box<dyn Manager> {
    match id {
        ManagerId::Softwareupdate => Box::new(Softwareupdate),
        ManagerId::WindowsUpdate => Box::new(WindowsUpdate),
        ManagerId::Apt => Box::new(Apt),
        ManagerId::Dnf => Box::new(Dnf),
        ManagerId::Pacman => Box::new(Pacman),
        ManagerId::Homebrew => Box::new(Homebrew),
        ManagerId::Mas => Box::new(Mas),
        ManagerId::Winget => Box::new(Winget),
        ManagerId::Chocolatey => Box::new(Chocolatey),
        ManagerId::Flatpak => Box::new(Flatpak),
        ManagerId::Snap => Box::new(Snap),
        ManagerId::NpmGlobal => Box::new(NpmGlobal),
        ManagerId::Rustup => Box::new(Rustup),
    }
}

/// Query one manager. Never fails: a manager that is missing is reported as
/// unavailable, and one that errors carries the error.
pub fn inventory(m: &dyn Manager, runner: &dyn CommandRunner, ctx: &Context) -> ManagerInventory {
    let mut inv = ManagerInventory {
        id: m.id(),
        available: false,
        version: None,
        installed: Vec::new(),
        updates: Vec::new(),
        error: None,
    };
    if !m.supported_on(ctx.os.family) || runner.which(m.program()).is_none() {
        return inv;
    }
    inv.available = true;
    inv.version = m.version(runner);
    let mut errors = Vec::new();
    match m.installed(runner, ctx) {
        Ok(p) => inv.installed = p,
        Err(e) => errors.push(format!("listing installed: {e}")),
    }
    match m.updates(runner, ctx) {
        Ok(u) => inv.updates = u,
        Err(e) => errors.push(format!("listing updates: {e}")),
    }
    // Fill in installed versions an update listing left out.
    for u in &mut inv.updates {
        if u.installed_version.is_none() {
            u.installed_version = inv
                .installed
                .iter()
                .find(|p| p.name == u.id || p.name == u.name)
                .map(|p| p.version.clone());
        }
    }
    if !errors.is_empty() {
        inv.error = Some(errors.join("; "));
    }
    inv
}

// ------------------------------------------------------------ shared helpers

/// Run a listing command; `ok_codes` are the exit statuses that mean success
/// (dnf and npm use non-zero codes to say "updates exist").
pub(crate) fn run_list(runner: &dyn CommandRunner, spec: CommandSpec, ok_codes: &[i32]) -> ListResult<String> {
    let out = runner.run(&spec).map_err(|e| e.to_string())?;
    if out.timed_out {
        return Err(format!(
            "`{}` timed out after {}s",
            spec.display(),
            spec.timeout.as_secs()
        ));
    }
    match out.status {
        Some(c) if c == 0 || ok_codes.contains(&c) => Ok(out.stdout),
        _ => Err(format!(
            "`{}` exited with {}: {}",
            spec.display(),
            out.status.map_or("a signal".to_string(), |c| c.to_string()),
            out.tail(400)
        )),
    }
}

/// Parse a fixed-width table (winget): column positions come from the
/// header, measured in characters.
pub(crate) fn parse_fixed_width_table(text: &str, header_starts_with: &str) -> Vec<Vec<String>> {
    // Progress spinners write `\r`-separated frames before the table.
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.rsplit('\r').next().unwrap_or(l).to_string())
        .collect();
    let Some(hi) = lines
        .iter()
        .position(|l| l.trim_start().starts_with(header_starts_with))
    else {
        return Vec::new();
    };
    let header: Vec<char> = lines[hi].trim_start().chars().collect();
    let indent = lines[hi].chars().count() - header.len();
    let mut starts = vec![0usize];
    for i in 1..header.len() {
        if header[i - 1] == ' ' && header[i] != ' ' {
            starts.push(i);
        }
    }
    let mut rows = Vec::new();
    for line in lines.iter().skip(hi + 1) {
        let chars: Vec<char> = line.chars().skip(indent).collect();
        if chars.iter().all(|c| *c == '-' || c.is_whitespace()) {
            if chars.contains(&'-') {
                continue; // the rule under the header
            }
            break; // a blank line ends the table
        }
        // A footer such as "3 upgrades available." ends the table.
        let text: String = chars.iter().collect();
        let text = text.trim();
        if text.starts_with(|c: char| c.is_ascii_digit())
            && text.ends_with('.')
            && (text.contains(" available") || text.contains(" upgrade") || text.contains(" package"))
        {
            break;
        }
        let mut row = Vec::new();
        for (ci, &s) in starts.iter().enumerate() {
            let e = starts.get(ci + 1).copied().unwrap_or(chars.len()).min(chars.len());
            let cell: String = if s < chars.len() {
                chars[s..e].iter().collect()
            } else {
                String::new()
            };
            row.push(cell.trim().to_string());
        }
        // Any other line that fills only the first column is not a row.
        if row.iter().skip(1).all(String::is_empty) {
            break;
        }
        rows.push(row);
    }
    rows
}

/// Whether `id` is safe to hand to `manager`'s install command. Package
/// managers accept more than package names (`dnf upgrade https://…/x.rpm`,
/// `apt-get install ./x.deb`), so an id from a saved or crafted scan must
/// look like what that manager lists, not merely "not an option".
pub fn valid_identifier(manager: ManagerId, id: &str) -> bool {
    if id.is_empty() || id.starts_with('-') || id.chars().any(char::is_control) {
        return false;
    }
    let name = |extra: &str| {
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-@:~".contains(c) || extra.contains(c))
    };
    // Only these characters, besides ASCII letters and digits.
    let only = |allowed: &str| id.chars().all(|c| c.is_ascii_alphanumeric() || allowed.contains(c));
    match manager {
        ManagerId::Apt => linux::valid_debian_package(id),
        // `@name` is a group or module and `name:stream` a module stream.
        ManagerId::Dnf => only("._+-"),
        // pacman's install command takes no name (`-Syu`).
        ManagerId::Pacman => only("@._+-"),
        ManagerId::Snap => only("-_") && !id.chars().any(|c| c.is_ascii_uppercase()),
        ManagerId::Flatpak => only("._-"),
        // `choco upgrade all` upgrades every package.
        ManagerId::Chocolatey => only("._-") && !id.eq_ignore_ascii_case("all"),
        // Only ever reaches winget as `--id ID --exact`.
        ManagerId::Winget => name(""),
        // Tap formulae are `user/tap/name`; never a path or URL. A saved
        // scan's tap names are not trusted: `apply --from` keeps only
        // updates that `brew outdated` lists now.
        ManagerId::Homebrew => name("/") && !id.starts_with('/') && !id.contains("..") && !id.contains("//"),
        ManagerId::Mas => id.chars().all(|c| c.is_ascii_digit()),
        ManagerId::WindowsUpdate => windows::is_guid(id),
        ManagerId::NpmGlobal => dev::valid_npm_name(id),
        ManagerId::Rustup => dev::valid_toolchain(id),
        // Software Update labels are free text ("macOS Tahoe 26.7.2-25H210")
        // and only ever reach softwareupdate as one --install argument.
        ManagerId::Softwareupdate => true,
    }
}

/// Whether `version` is safe on `manager`'s install command. Only npm puts
/// the version there (`npm install --global name@version`).
pub fn valid_version(manager: ManagerId, version: &str) -> bool {
    match manager {
        ManagerId::NpmGlobal => dev::valid_npm_version(version),
        _ => true,
    }
}

/// For the fuzz targets: parsers that sit below an adapter's listing.
pub(crate) fn parse_softwareupdate_for_fuzzing(text: &str) -> Vec<AvailableUpdate> {
    macos::parse_softwareupdate(text, Some(26))
}

pub(crate) fn parse_mas_line_for_fuzzing(line: &str) -> Option<(String, String, String, Option<String>)> {
    macos::parse_mas_line(line)
}

pub(crate) fn mins(m: u64) -> Duration {
    Duration::from_secs(m * 60)
}

#[cfg(test)]
pub(crate) fn test_ctx(family: OsFamily, distro: Option<(&str, &str)>) -> Context {
    Context::new(OsInfo {
        family,
        name: "test".into(),
        version: "1".into(),
        build: None,
        kernel: "k".into(),
        arch: "x86_64".into(),
        distro_id: distro.map(|d| d.0.to_string()),
        distro_version_id: distro.map(|d| d.1.to_string()),
        edition: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{CommandOutput, FakeRunner};
    use crate::model::UpdateKind;

    #[test]
    fn identifiers_are_checked_per_manager() {
        use ManagerId::*;
        assert!(valid_identifier(Apt, "libc6:amd64"));
        assert!(!valid_identifier(Apt, "./evil.deb"));
        assert!(!valid_identifier(Apt, "curl=7.0"));
        assert!(!valid_identifier(Dnf, "https://example.com/x.rpm"));
        assert!(!valid_identifier(Dnf, "/tmp/x.rpm"));
        assert!(valid_identifier(Homebrew, "openssl@3"));
        assert!(valid_identifier(Homebrew, "cask:firefox"));
        assert!(valid_identifier(Homebrew, "user/tap/tool"));
        assert!(!valid_identifier(Homebrew, "/tmp/evil.rb"));
        assert!(!valid_identifier(Homebrew, "https://x/y.rb"));
        assert!(valid_identifier(Winget, "Microsoft.VCRedist.2015+.x64"));
        assert!(!valid_identifier(Winget, "x y"));
        assert!(valid_identifier(Mas, "497799835"));
        assert!(!valid_identifier(Mas, "4977x"));
        assert!(!valid_identifier(WindowsUpdate, "KB5065426"));
        assert!(!valid_identifier(NpmGlobal, "git+https://x"));
        assert!(valid_identifier(Softwareupdate, "macOS Tahoe 26.7.2-25H210"));
        assert!(!valid_identifier(Softwareupdate, "--all"));
        assert!(!valid_identifier(Snap, "a\nb"));
    }

    #[test]
    fn identifiers_follow_each_managers_grammar() {
        use ManagerId::*;
        // apt-get reads a trailing `-` as "remove" and `~`/`?` as patterns.
        for bad in [
            "openssh-server-",
            "~i",
            "~nfoo",
            "?installed",
            "foo~bar",
            "a@b",
            "Curl",
            "libc6:",
            "x",
        ] {
            assert!(!valid_identifier(Apt, bad), "apt {bad}");
        }
        for ok in [
            "curl",
            "g++",
            "libstdc++6",
            "libc6:i386",
            "linux-image-6.8.0-80-generic",
            "tzdata",
        ] {
            assert!(valid_identifier(Apt, ok), "apt {ok}");
        }
        // dnf: `@name` is a group or module, `name:stream` a module stream.
        for bad in ["@core", "@development-tools", "nodejs:18", "a~b"] {
            assert!(!valid_identifier(Dnf, bad), "dnf {bad}");
        }
        for ok in ["curl", "gcc-c++", "openssl-libs", "python3.12", "NetworkManager"] {
            assert!(valid_identifier(Dnf, ok), "dnf {ok}");
        }
        // `choco upgrade all` upgrades every package.
        for bad in ["all", "ALL", "All", "a@b", "a:b", "a+b"] {
            assert!(!valid_identifier(Chocolatey, bad), "choco {bad}");
        }
        for ok in [
            "git",
            "nodejs.install",
            "vcredist140",
            "notepadplusplus.install",
            "7zip",
        ] {
            assert!(valid_identifier(Chocolatey, ok), "choco {ok}");
        }
        for ok in ["firefox", "core22", "gnome-42-2204", "snapd", "firefox_beta"] {
            assert!(valid_identifier(Snap, ok), "snap {ok}");
        }
        for bad in ["x.snap", "a@b", "a:b"] {
            assert!(!valid_identifier(Snap, bad), "snap {bad}");
        }
        for ok in [
            "org.mozilla.firefox",
            "org.gimp.GIMP",
            "com.github.tchx84.Flatseal",
            "io.github.a_b.C-d",
        ] {
            assert!(valid_identifier(Flatpak, ok), "flatpak {ok}");
        }
        for bad in ["a@b", "a:b", "a~b"] {
            assert!(!valid_identifier(Flatpak, bad), "flatpak {bad}");
        }
        for ok in [
            "linux",
            "gtk3",
            "libxml2",
            "python-pip",
            "lib32-glibc",
            "gcc-libs",
            "dbus-broker",
        ] {
            assert!(valid_identifier(Pacman, ok), "pacman {ok}");
        }
        assert!(valid_identifier(Pacman, "libsigc++"));
        assert!(!valid_identifier(Pacman, "a:b"));
        for ok in [
            "rustup",
            "stable-x86_64-apple-darwin",
            "nightly-2026-10-01",
            "1.88-x86_64-apple-darwin",
        ] {
            assert!(valid_identifier(Rustup, ok), "rustup {ok}");
        }
        for bad in ["a@b", "a:b", "a+b"] {
            assert!(!valid_identifier(Rustup, bad), "rustup {bad}");
        }
    }

    #[test]
    fn elevated_commands_name_their_program_by_absolute_path() {
        // sudo (macOS has no secure_path), pkexec and `env` look a bare name
        // up on the caller's PATH, where a user-writable directory such as
        // /usr/local/bin can come first: that would run user code as root.
        // Windows has no wrapper (the whole process is elevated).
        let mut checked = 0;
        for m in all() {
            if !(m.supported_on(OsFamily::Macos) || m.supported_on(OsFamily::Linux)) {
                continue;
            }
            let mut specs: Vec<CommandSpec> = m.refresh_command().into_iter().collect();
            for kind in [UpdateKind::Package, UpdateKind::OsUpdate, UpdateKind::OsUpgrade] {
                specs.push(m.install_command(&AvailableUpdate {
                    manager: m.id(),
                    id: "pkg".into(),
                    name: "pkg".into(),
                    installed_version: Some("1".into()),
                    available_version: "2".into(),
                    kind,
                    security: false,
                    restart_required: false,
                    notes: None,
                }));
            }
            for s in specs.iter().filter(|s| s.needs_elevation) {
                assert!(
                    s.program.starts_with('/'),
                    "{}: elevated command `{}` must name its program by absolute path",
                    m.id(),
                    s.display()
                );
                checked += 1;
            }
        }
        assert!(checked >= 8, "only {checked} elevated commands found");
    }

    #[test]
    fn distro_ecosystems() {
        let e = |d, v| test_ctx(OsFamily::Linux, Some((d, v))).osv_distro_ecosystem();
        assert_eq!(e("debian", "12").as_deref(), Some("Debian:12"));
        assert_eq!(e("ubuntu", "24.04").as_deref(), Some("Ubuntu:24.04:LTS"));
        assert_eq!(e("ubuntu", "25.10").as_deref(), Some("Ubuntu:25.10"));
        assert_eq!(e("ubuntu", "23.04").as_deref(), Some("Ubuntu:23.04"));
        assert_eq!(e("rocky", "9.4").as_deref(), Some("Rocky Linux:9"));
        assert_eq!(e("arch", "rolling"), None);
    }

    #[test]
    fn fixed_width_table_handles_spinner_rule_and_footer() {
        let text = "\r-\r\\\r|\rName               Id                  Version  Available Source\n\
                    ------------------------------------------------------------------\n\
                    Git                Git.Git             2.44.0   2.45.1    winget\n\
                    Mozilla Firefox (… Mozilla.Firefox     124.0    125.0.1   winget\n\
                    2 upgrades available.\n";
        let rows = parse_fixed_width_table(text, "Name");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ["Git", "Git.Git", "2.44.0", "2.45.1", "winget"]);
        assert_eq!(rows[1][0], "Mozilla Firefox (…");
        assert_eq!(rows[1][1], "Mozilla.Firefox");
    }

    #[test]
    fn missing_manager_is_unavailable_not_an_error() {
        let r = FakeRunner::new();
        let inv = inventory(&Homebrew, &r, &test_ctx(OsFamily::Macos, None));
        assert!(!inv.available);
        assert!(inv.error.is_none());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn unsupported_os_is_skipped_even_if_program_exists() {
        let r = FakeRunner::new().with_program("winget");
        let inv = inventory(&Winget, &r, &test_ctx(OsFamily::Linux, None));
        assert!(!inv.available);
    }

    #[test]
    fn listing_failure_is_carried_not_fatal() {
        let r = FakeRunner::new()
            .respond("brew --version", CommandOutput::ok("Homebrew 4.6.0\n"))
            .respond(
                "brew list --formula --versions",
                CommandOutput::with_status(1, "", "Error: boom"),
            )
            .respond("brew list --cask --versions", CommandOutput::ok(""))
            .respond(
                "brew outdated --json=v2",
                CommandOutput::ok("{\"formulae\":[],\"casks\":[]}"),
            );
        let inv = inventory(&Homebrew, &r, &test_ctx(OsFamily::Macos, None));
        assert!(inv.available);
        assert_eq!(inv.version.as_deref(), Some("Homebrew 4.6.0"));
        assert!(inv.error.as_deref().unwrap().contains("boom"), "{:?}", inv.error);
    }
}
