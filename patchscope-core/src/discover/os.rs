//! Operating-system identification.

use crate::exec::{CommandRunner, CommandSpec};
use crate::model::{OsFamily, OsInfo};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

pub fn detect(runner: &dyn CommandRunner, warnings: &mut Vec<String>) -> OsInfo {
    let family = OsFamily::current();
    let kernel = sysinfo::System::kernel_version().unwrap_or_default();
    let arch = sysinfo::System::cpu_arch();
    let mut info = OsInfo {
        family,
        name: sysinfo::System::long_os_version().unwrap_or_else(|| family.to_string()),
        version: sysinfo::System::os_version().unwrap_or_default(),
        build: None,
        kernel,
        arch,
        distro_id: None,
        distro_version_id: None,
        edition: None,
    };
    match family {
        OsFamily::Macos => macos(runner, &mut info, warnings),
        OsFamily::Linux => match std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        {
            Ok(text) => apply_os_release(&text, &mut info),
            Err(e) => warnings.push(format!("os-release unreadable: {e}")),
        },
        OsFamily::Windows => windows(runner, &mut info, warnings),
        OsFamily::Other => {}
    }
    info
}

/// Apple's marketing names, by major version.
pub fn macos_codename(major: u32) -> Option<&'static str> {
    Some(match major {
        11 => "Big Sur",
        12 => "Monterey",
        13 => "Ventura",
        14 => "Sonoma",
        15 => "Sequoia",
        26 => "Tahoe",
        27 => "Golden Gate",
        _ => return None,
    })
}

fn macos(runner: &dyn CommandRunner, info: &mut OsInfo, warnings: &mut Vec<String>) {
    let q = |flag: &str| {
        runner
            .run(&CommandSpec::new("sw_vers", &[flag]).timeout(Duration::from_secs(15)))
            .ok()
            .filter(|o| o.success())
            .map(|o| o.stdout.trim().to_string())
    };
    match q("-productVersion") {
        Some(v) => {
            let major = v.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
            info.name = match macos_codename(major) {
                Some(c) => format!("macOS {v} ({c})"),
                None => format!("macOS {v}"),
            };
            info.version = v;
        }
        None => warnings.push("sw_vers failed; macOS version taken from sysinfo".into()),
    }
    info.build = q("-buildVersion");
}

/// Fill distribution fields from `/etc/os-release` text.
pub fn apply_os_release(text: &str, info: &mut OsInfo) {
    let kv: HashMap<&str, String> = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches('"').trim_matches('\'').to_string()))
        .collect();
    if let Some(n) = kv.get("PRETTY_NAME") {
        info.name = n.clone();
    }
    info.distro_id = kv.get("ID").cloned();
    info.distro_version_id = kv.get("VERSION_ID").cloned();
    if let Some(v) = kv.get("VERSION_ID") {
        info.version = v.clone();
    }
    info.edition = kv.get("VARIANT").or_else(|| kv.get("VERSION_CODENAME")).cloned();
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WinCurrentVersion {
    product_name: Option<String>,
    display_version: Option<String>,
    current_build: Option<String>,
    #[serde(rename = "UBR")]
    ubr: Option<u64>,
    #[serde(rename = "EditionID")]
    edition_id: Option<String>,
    installation_type: Option<String>,
}

const WIN_VERSION_PS: &str = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | \
Select-Object ProductName,DisplayVersion,CurrentBuild,UBR,EditionID,InstallationType | ConvertTo-Json -Compress";

fn windows(runner: &dyn CommandRunner, info: &mut OsInfo, warnings: &mut Vec<String>) {
    let out = runner.run(
        &CommandSpec::new(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", WIN_VERSION_PS],
        )
        .timeout(Duration::from_secs(60)),
    );
    match out {
        Ok(o) if o.success() => {
            if let Err(e) = apply_windows_registry(&o.stdout, info) {
                warnings.push(format!("Windows version JSON: {e}"));
            }
        }
        Ok(o) => warnings.push(format!("Windows version query failed: {}", o.tail(200))),
        Err(e) => warnings.push(format!("Windows version query failed: {e}")),
    }
}

pub fn apply_windows_registry(json: &str, info: &mut OsInfo) -> Result<(), String> {
    let v: WinCurrentVersion = serde_json::from_str(json.trim()).map_err(|e| e.to_string())?;
    let build: u64 = v.current_build.as_deref().and_then(|b| b.parse().ok()).unwrap_or(0);
    let mut product = v.product_name.unwrap_or_else(|| "Windows".into());
    // The registry still says "Windows 10" on Windows 11 (build 22000+).
    if build >= 22000 && product.contains("Windows 10") {
        product = product.replace("Windows 10", "Windows 11");
    }
    let display = v.display_version.unwrap_or_default();
    info.name = if display.is_empty() {
        product
    } else {
        format!("{product} {display}")
    };
    info.version = format!("10.0.{build}");
    info.build = Some(match v.ubr {
        Some(u) => format!("{build}.{u}"),
        None => build.to_string(),
    });
    info.edition = v.edition_id;
    if v.installation_type.as_deref() == Some("Server") {
        info.distro_id = Some("windows-server".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank() -> OsInfo {
        OsInfo {
            family: OsFamily::Linux,
            name: String::new(),
            version: String::new(),
            build: None,
            kernel: String::new(),
            arch: String::new(),
            distro_id: None,
            distro_version_id: None,
            edition: None,
        }
    }

    #[test]
    fn os_release() {
        let mut i = blank();
        apply_os_release(
            "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n",
            &mut i,
        );
        assert_eq!(i.name, "Ubuntu 24.04.3 LTS");
        assert_eq!(i.distro_id.as_deref(), Some("ubuntu"));
        assert_eq!(i.version, "24.04");
        assert_eq!(i.edition.as_deref(), Some("noble"));
    }

    #[test]
    fn windows_registry_names_windows_11_correctly() {
        let mut i = blank();
        apply_windows_registry(
            r#"{"ProductName":"Windows 10 Pro","DisplayVersion":"24H2","CurrentBuild":"26100","UBR":4946,"EditionID":"Professional","InstallationType":"Client"}"#,
            &mut i,
        )
        .unwrap();
        assert_eq!(i.name, "Windows 11 Pro 24H2");
        assert_eq!(i.version, "10.0.26100");
        assert_eq!(i.build.as_deref(), Some("26100.4946"));
        assert_eq!(i.edition.as_deref(), Some("Professional"));
        assert_eq!(i.distro_id, None);

        let mut s = blank();
        apply_windows_registry(
            r#"{"ProductName":"Windows Server 2022 Datacenter","DisplayVersion":"21H2","CurrentBuild":"20348","UBR":3091,"EditionID":"ServerDatacenter","InstallationType":"Server"}"#,
            &mut s,
        )
        .unwrap();
        assert_eq!(s.distro_id.as_deref(), Some("windows-server"));
    }

    #[test]
    fn codenames() {
        assert_eq!(macos_codename(26), Some("Tahoe"));
        assert_eq!(macos_codename(99), None);
    }
}
