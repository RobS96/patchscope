//! Windows: winget, Chocolatey and Windows Update (the Windows Update Agent
//! COM API, driven through PowerShell).

use super::{Context, ListResult, Manager, mins, parse_fixed_width_table, run_list};
use crate::exec::{CommandRunner, CommandSpec, windows_dir, windows_powershell_program};
use crate::model::{AvailableUpdate, ManagerId, OsFamily, Package, UpdateKind};
use serde::Deserialize;

// ------------------------------------------------------------------ winget

pub struct Winget;

/// APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE (0x8A15002B) as the i32
/// exit status Windows reports.
const WINGET_NO_APPLICABLE_UPDATE: i32 = 0x8A15_002Bu32 as i32;

const WINGET_COMMON: [&str; 2] = ["--accept-source-agreements", "--disable-interactivity"];

/// winget stays a bare name: it is a per-user App Execution Alias (in
/// `%LOCALAPPDATA%\Microsoft\WindowsApps`) with no fixed system path, and
/// its installs never need patchscope to be elevated (each installer asks
/// UAC itself), unlike Chocolatey and Windows Update below.
fn winget(args: &[&str]) -> CommandSpec {
    let mut a: Vec<&str> = args.to_vec();
    a.extend(WINGET_COMMON);
    CommandSpec::new("winget", &a).timeout(mins(5))
}

/// winget truncates long cells with "…"; a truncated Id cannot be installed.
fn truncated(s: &str) -> bool {
    s.ends_with('…')
}

pub(crate) fn parse_winget_list(text: &str) -> Vec<Package> {
    parse_fixed_width_table(text, "Name")
        .into_iter()
        .filter(|r| r.len() >= 3 && !r[1].is_empty())
        .map(|r| Package {
            manager: ManagerId::Winget,
            name: r[1].clone(),
            version: r[2].clone(),
            source_name: Some(r[0].clone()),
            source_version: None,
            ecosystem: None,
        })
        .collect()
}

pub(crate) fn parse_winget_upgrade(text: &str) -> Vec<AvailableUpdate> {
    parse_fixed_width_table(text, "Name")
        .into_iter()
        .filter(|r| r.len() >= 4 && !r[1].is_empty() && !r[3].is_empty())
        .map(|r| AvailableUpdate {
            manager: ManagerId::Winget,
            id: r[1].clone(),
            name: r[0].clone(),
            installed_version: Some(r[2].clone()),
            available_version: r[3].clone(),
            kind: UpdateKind::Application,
            security: false,
            restart_required: false,
            notes: truncated(&r[1]).then(|| "winget truncated this package id; update it from winget directly".into()),
        })
        .collect()
}

impl Manager for Winget {
    fn id(&self) -> ManagerId {
        ManagerId::Winget
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Windows
    }
    fn program(&self) -> &'static str {
        "winget"
    }
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        Ok(parse_winget_list(&run_list(runner, winget(&["list"]), &[])?))
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        // winget exits 0x8A15002B (UPDATE_NOT_APPLICABLE) when there is
        // nothing to upgrade. Any other failure (a source that could not be
        // searched, an unaccepted agreement, no network) is an error, not
        // an empty list.
        let text = run_list(runner, winget(&["upgrade"]), &[WINGET_NO_APPLICABLE_UPDATE])?;
        Ok(parse_winget_upgrade(&text))
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        winget(&[
            "upgrade",
            "--id",
            &u.id,
            "--exact",
            "--silent",
            "--accept-package-agreements",
        ])
        .timeout(mins(60))
    }
}

// -------------------------------------------------------------- Chocolatey

pub struct Chocolatey;

/// `choco.exe` for a given `%ProgramData%`, where the Chocolatey installer
/// puts it: `%ProgramData%\chocolatey\bin\choco.exe`. Its commands run as
/// Administrator (patchscope runs elevated as a whole), so it is named by
/// absolute path, not looked up on PATH. `ChocolateyInstall` is not used:
/// it is an ordinary environment variable that a user-level setting can
/// point at a folder the user can write, and an absolute path there is no
/// safer. A Chocolatey installed elsewhere is still found on PATH but its
/// commands fail with "not found", naming this path.
pub(crate) fn choco_program_for(program_data: Option<&str>) -> String {
    format!(
        r"{}\chocolatey\bin\choco.exe",
        windows_dir(program_data, r"C:\ProgramData")
    )
}

fn choco(args: &[&str]) -> CommandSpec {
    CommandSpec::new(&choco_program_for(std::env::var("ProgramData").ok().as_deref()), args)
}

/// `choco list -r` → `name|version`; `choco outdated -r` →
/// `name|current|available|pinned`.
pub(crate) fn parse_choco_pipes(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| l.contains('|'))
        .map(|l| l.trim().split('|').map(str::to_string).collect())
        .collect()
}

impl Manager for Chocolatey {
    fn id(&self) -> ManagerId {
        ManagerId::Chocolatey
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Windows
    }
    /// For the availability probe only; commands use [`choco_program_for`].
    fn program(&self) -> &'static str {
        "choco"
    }
    fn version(&self, runner: &dyn CommandRunner) -> Option<String> {
        let out = runner
            .run(&choco(&["--version"]).timeout(std::time::Duration::from_secs(30)))
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
    fn installed(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        let text = run_list(runner, choco(&["list", "-r"]).timeout(mins(5)), &[])?;
        Ok(parse_choco_pipes(&text)
            .into_iter()
            .map(|r| Package {
                manager: ManagerId::Chocolatey,
                name: r[0].clone(),
                version: r.get(1).cloned().unwrap_or_default(),
                source_name: None,
                source_version: None,
                ecosystem: None,
            })
            .collect())
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        let text = run_list(runner, choco(&["outdated", "-r"]).timeout(mins(10)), &[2])?;
        Ok(parse_choco_pipes(&text)
            .into_iter()
            .filter(|r| r.len() >= 3)
            .map(|r| AvailableUpdate {
                manager: ManagerId::Chocolatey,
                id: r[0].clone(),
                name: r[0].clone(),
                installed_version: Some(r[1].clone()),
                available_version: r[2].clone(),
                kind: UpdateKind::Application,
                security: false,
                restart_required: false,
                notes: r
                    .get(3)
                    .filter(|p| p.eq_ignore_ascii_case("true"))
                    .map(|_| "pinned in Chocolatey".into()),
            })
            .collect())
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        choco(&["upgrade", &u.id, "-y", "--no-progress"])
            .timeout(mins(60))
            .elevated()
    }
}

// ---------------------------------------------------------- Windows Update

pub struct WindowsUpdate;

/// Windows PowerShell by absolute path: its install commands run as
/// Administrator.
fn powershell(script: &str) -> CommandSpec {
    CommandSpec::new(
        &windows_powershell_program(),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
}

const WU_SEARCH: &str = r#"$ErrorActionPreference = 'Stop'
$session = New-Object -ComObject Microsoft.Update.Session
$result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
@($result.Updates | ForEach-Object {
  [pscustomobject]@{
    id = $_.Identity.UpdateID
    title = $_.Title
    kb = ($_.KBArticleIDs -join ',')
    severity = $_.MsrcSeverity
    categories = (@($_.Categories | ForEach-Object { $_.Name }) -join ';')
    reboot = [int]$_.InstallationBehavior.RebootBehavior
  }
}) | ConvertTo-Json -Compress -Depth 3"#;

#[derive(Deserialize)]
struct WuItem {
    id: String,
    title: String,
    #[serde(default)]
    kb: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    categories: Option<String>,
    #[serde(default)]
    reboot: i64,
}

/// `ConvertTo-Json` prints a bare object for one result, an array for
/// several and nothing at all for none.
pub(crate) fn parse_wu_json(text: &str) -> Result<Vec<AvailableUpdate>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<WuItem> = if t.starts_with('[') {
        serde_json::from_str(t).map_err(|e| e.to_string())?
    } else {
        vec![serde_json::from_str(t).map_err(|e| e.to_string())?]
    };
    Ok(items
        .into_iter()
        .map(|i| {
            let cats = i.categories.unwrap_or_default();
            let sev = i.severity.filter(|s| !s.is_empty());
            let lower = i.title.to_ascii_lowercase();
            let kind = if lower.contains("feature update") || lower.contains("upgrade to windows") {
                UpdateKind::OsUpgrade
            } else if lower.contains("firmware") || cats.contains("Driver") {
                UpdateKind::Firmware
            } else if cats.contains("Definition") || lower.contains("security intelligence") {
                UpdateKind::Package
            } else {
                UpdateKind::OsUpdate
            };
            let security = sev.is_some()
                || cats.contains("Security")
                || cats.contains("Definition")
                || lower.contains("cumulative update");
            AvailableUpdate {
                manager: ManagerId::WindowsUpdate,
                name: i.title.clone(),
                available_version: i
                    .kb
                    .filter(|k| !k.is_empty())
                    .map(|k| format!("KB{}", k.replace(',', ", KB")))
                    .unwrap_or_else(|| "latest".into()),
                id: i.id,
                installed_version: None,
                kind,
                security,
                // RebootBehavior: 0 never, 1 always, 2 can request.
                restart_required: i.reboot != 0,
                notes: sev.map(|s| format!("Microsoft severity: {s}")),
            }
        })
        .collect())
}

/// Windows UpdateIDs are GUIDs; anything else is refused before it gets
/// near a PowerShell script.
pub(crate) fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

impl Manager for WindowsUpdate {
    fn id(&self) -> ManagerId {
        ManagerId::WindowsUpdate
    }
    fn supported_on(&self, os: OsFamily) -> bool {
        os == OsFamily::Windows
    }
    /// For the availability probe only; commands use
    /// [`windows_powershell_program`].
    fn program(&self) -> &'static str {
        "powershell"
    }
    fn version(&self, _runner: &dyn CommandRunner) -> Option<String> {
        None
    }
    fn installed(&self, _runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<Package>> {
        Ok(Vec::new())
    }
    fn updates(&self, runner: &dyn CommandRunner, _ctx: &Context) -> ListResult<Vec<AvailableUpdate>> {
        let text = run_list(runner, powershell(WU_SEARCH).timeout(mins(15)), &[])?;
        parse_wu_json(&text)
    }
    fn install_command(&self, u: &AvailableUpdate) -> CommandSpec {
        // Validated here and again by the plan; a non-GUID id produces a
        // script that refuses to run.
        let id = if is_guid(&u.id) {
            u.id.as_str()
        } else {
            "invalid-update-id"
        };
        let script = format!(
            r#"$ErrorActionPreference = 'Stop'
if ('{id}' -notmatch '^[0-9a-fA-F-]{{36}}$') {{ throw 'invalid update id' }}
$session = New-Object -ComObject Microsoft.Update.Session
$found = $session.CreateUpdateSearcher().Search("UpdateID='{id}'").Updates
if ($found.Count -eq 0) {{ Write-Output 'NotFound: already installed or withdrawn'; exit 0 }}
$coll = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $found) {{ if (-not $u.EulaAccepted) {{ $u.AcceptEula() }}; [void]$coll.Add($u) }}
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll; $res = $inst.Install()
Write-Output ("ResultCode={{0}} RebootRequired={{1}}" -f $res.ResultCode, $res.RebootRequired)
if ($res.ResultCode -ne 2 -and $res.ResultCode -ne 3) {{ exit 1 }}"#
        );
        powershell(&script).timeout(mins(120)).elevated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINGET_UPGRADE: &str = include_str!("../../tests/fixtures/winget-upgrade.txt");

    #[test]
    fn winget_upgrade_table() {
        let u = parse_winget_upgrade(WINGET_UPGRADE);
        assert_eq!(u.len(), 3, "{u:#?}");
        assert_eq!(u[0].id, "Git.Git");
        assert_eq!(u[0].installed_version.as_deref(), Some("2.50.1"));
        assert_eq!(u[0].available_version, "2.51.0");
        assert_eq!(u[1].name, "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14…");
        assert!(u[2].notes.as_deref().unwrap().contains("truncated"));
        let cmd = Winget.install_command(&u[0]);
        assert_eq!(&cmd.args[..4], ["upgrade", "--id", "Git.Git", "--exact"]);
        assert!(!cmd.needs_elevation, "winget elevates per installer through UAC");
    }

    #[test]
    fn winget_upgrade_failures_are_errors() {
        use crate::exec::{CommandOutput, FakeRunner};
        let ctx = crate::managers::test_ctx(OsFamily::Windows, None);
        let cmd = "winget upgrade --accept-source-agreements --disable-interactivity";
        // 0x8A15002B (APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE) as an i32.
        assert_eq!(WINGET_NO_APPLICABLE_UPDATE, -1_978_335_189);
        assert_eq!(0x1_0000_0000i64 - 0x8A15_002Bi64, 1_978_335_189);
        let none = FakeRunner::new().respond(
            cmd,
            CommandOutput::with_status(
                -1_978_335_189,
                "No installed package found matching input criteria.\n",
                "",
            ),
        );
        assert!(Winget.updates(&none, &ctx).unwrap().is_empty());
        let table = FakeRunner::new().respond(cmd, CommandOutput::ok(WINGET_UPGRADE));
        assert_eq!(Winget.updates(&table, &ctx).unwrap().len(), 3);
        // A source or network failure is not "nothing to update".
        let failed = FakeRunner::new().respond(
            cmd,
            CommandOutput::with_status(
                -1_978_335_217, // 0x8A15000F: data required by the source is missing
                "Failed when searching source: winget\nAn unexpected error occurred while executing the command:\n",
                "",
            ),
        );
        let err = Winget.updates(&failed, &ctx).unwrap_err();
        assert!(err.contains("Failed when searching source"), "{err}");
        let other = FakeRunner::new().respond(cmd, CommandOutput::with_status(1, "", "boom"));
        assert!(Winget.updates(&other, &ctx).is_err());
    }

    #[test]
    fn winget_list_table() {
        let text = "Name            Id              Version   Available Source\n\
                    ---------------------------------------------------------\n\
                    7-Zip 24.09     7zip.7zip       24.09               winget\n\
                    Git             Git.Git         2.50.1    2.51.0    winget\n";
        let p = parse_winget_list(text);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].name.as_str(), p[0].version.as_str()), ("7zip.7zip", "24.09"));
    }

    #[test]
    fn choco_is_named_by_absolute_path() {
        assert_eq!(
            choco_program_for(Some(r"D:\ProgramData")),
            r"D:\ProgramData\chocolatey\bin\choco.exe"
        );
        for bad in [None, Some(""), Some("ProgramData"), Some(r"\\server\share")] {
            assert_eq!(
                choco_program_for(bad),
                r"C:\ProgramData\chocolatey\bin\choco.exe",
                "{bad:?}"
            );
        }
        let u = AvailableUpdate {
            manager: ManagerId::Chocolatey,
            id: "git".into(),
            name: "git".into(),
            installed_version: Some("1".into()),
            available_version: "2".into(),
            kind: UpdateKind::Application,
            security: false,
            restart_required: false,
            notes: None,
        };
        let cmd = Chocolatey.install_command(&u);
        assert!(cmd.program.ends_with(r"\chocolatey\bin\choco.exe"), "{}", cmd.program);
        assert_eq!(cmd.args, ["upgrade", "git", "-y", "--no-progress"]);
        assert!(cmd.needs_elevation);
        // The availability probe still looks for the bare name.
        assert_eq!(Chocolatey.program(), "choco");
        assert_eq!(WindowsUpdate.program(), "powershell");
    }

    #[test]
    fn choco_rows() {
        let r = parse_choco_pipes("Chocolatey v2.5.1\ngit|2.50.1|2.51.0|false\nnodejs|22.1.0|22.9.0|true\n");
        assert_eq!(r.len(), 2);
        assert_eq!(r[1][3], "true");
    }

    #[test]
    fn windows_update_json_single_and_array() {
        let one = r#"{"id":"0f7e7b3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b","title":"2025-09 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5065426)","kb":"5065426","severity":"Critical","categories":"Security Updates;Windows 11","reboot":1}"#;
        let u = parse_wu_json(one).unwrap();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].available_version, "KB5065426");
        assert_eq!(u[0].kind, UpdateKind::OsUpdate);
        assert!(u[0].security && u[0].restart_required);

        let many = format!(
            r#"[{one},{{"id":"11111111-2222-3333-4444-555555555555","title":"Feature update to Windows 11, version 25H2","kb":"","severity":"","categories":"Upgrades","reboot":1}}]"#
        );
        let u = parse_wu_json(&many).unwrap();
        assert_eq!(u.len(), 2);
        assert_eq!(u[1].kind, UpdateKind::OsUpgrade);
        assert!(parse_wu_json("  \r\n").unwrap().is_empty());
    }

    #[test]
    fn windows_update_install_refuses_non_guid_ids() {
        assert!(is_guid("0f7e7b3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"));
        assert!(!is_guid("x'; Remove-Item C:\\ -Recurse; '"));
        let evil = AvailableUpdate {
            manager: ManagerId::WindowsUpdate,
            id: "'; Remove-Item C:\\ -Recurse; '".into(),
            name: "evil".into(),
            installed_version: None,
            available_version: "1".into(),
            kind: UpdateKind::OsUpdate,
            security: true,
            restart_required: false,
            notes: None,
        };
        let script = WindowsUpdate.install_command(&evil).args.last().unwrap().clone();
        assert!(!script.contains("Remove-Item"));
        assert!(script.contains("invalid-update-id"));
    }
}
