//! The data patchscope produces: what a machine has ([`SystemReport`]), what
//! the research found about it ([`Analysis`]), and what it proposes to do
//! ([`crate::plan::UpdatePlan`]). Every type here is serialisable, so a
//! report taken on one machine can be reviewed on another.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Bumped whenever a field is removed or changes meaning.
pub const SCHEMA_VERSION: u32 = 1;

/// Everything discovery learned about one machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemReport {
    pub schema_version: u32,
    pub tool_version: String,
    /// RFC 3339, UTC.
    pub generated_at: String,
    pub host: HostInfo,
    pub os: OsInfo,
    pub hardware: HardwareInfo,
    pub runtimes: Vec<Runtime>,
    pub managers: Vec<ManagerInventory>,
    /// Non-fatal problems met while discovering (a tool that timed out, a
    /// file that could not be read). Discovery never stops for one.
    pub warnings: Vec<String>,
}

impl SystemReport {
    pub fn manager(&self, id: ManagerId) -> Option<&ManagerInventory> {
        self.managers.iter().find(|m| m.id == id)
    }

    /// Every update every available manager offers.
    pub fn all_updates(&self) -> impl Iterator<Item = &AvailableUpdate> {
        self.managers.iter().flat_map(|m| m.updates.iter())
    }

    pub fn installed_count(&self) -> usize {
        self.managers.iter().map(|m| m.installed.len()).sum()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    /// `None` unless identifiers were requested (`--include-identifiers`).
    pub hostname: Option<String>,
    pub uptime_secs: u64,
    pub is_elevated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Macos,
    Windows,
    Linux,
    Other,
}

impl OsFamily {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "macos" => OsFamily::Macos,
            "windows" => OsFamily::Windows,
            "linux" => OsFamily::Linux,
            _ => OsFamily::Other,
        }
    }
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OsFamily::Macos => "macOS",
            OsFamily::Windows => "Windows",
            OsFamily::Linux => "Linux",
            OsFamily::Other => "Other",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsInfo {
    pub family: OsFamily,
    /// Human name, e.g. "macOS 26.7.1 (Tahoe)", "Ubuntu 24.04.3 LTS".
    pub name: String,
    /// Marketing version, e.g. "26.7.1", "24.04", "10.0.26100".
    pub version: String,
    /// Build identifier: macOS build ("25H123"), Windows build+UBR ("26100.4946").
    pub build: Option<String>,
    pub kernel: String,
    pub arch: String,
    /// Linux `/etc/os-release` ID (`ubuntu`, `debian`, `fedora`, …).
    pub distro_id: Option<String>,
    /// Linux `/etc/os-release` VERSION_ID.
    pub distro_version_id: Option<String>,
    /// Windows edition ("Professional", "Enterprise", …) or Linux variant.
    pub edition: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HardwareInfo {
    pub vendor: Option<String>,
    pub model: Option<String>,
    /// `None` unless identifiers were requested.
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub gpus: Vec<String>,
    pub battery: Option<BatteryInfo>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub temperatures: Vec<Temperature>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CpuInfo {
    pub brand: String,
    pub vendor: String,
    pub arch: String,
    pub physical_cores: Option<usize>,
    pub logical_cores: usize,
    pub frequency_mhz: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub kind: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub removable: bool,
}

impl DiskInfo {
    pub fn free_fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            1.0
        } else {
            self.available_bytes as f64 / self.total_bytes as f64
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BatteryInfo {
    pub cycle_count: Option<u32>,
    pub condition: Option<String>,
    pub max_capacity_percent: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    /// `None` unless identifiers were requested.
    pub mac_address: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Temperature {
    pub label: String,
    pub celsius: f32,
}

/// A language runtime found on `PATH`, checked against its support lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Runtime {
    /// endoflife.date product id: `python`, `nodejs`, `go`, `ruby`, `php`.
    pub product: String,
    pub display_name: String,
    pub version: String,
    pub path_command: String,
}

/// The package/update sources patchscope understands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ManagerId {
    /// macOS system and security updates (`softwareupdate`).
    Softwareupdate,
    /// Windows Update (via the Windows Update Agent COM API).
    WindowsUpdate,
    Apt,
    Dnf,
    Pacman,
    Homebrew,
    Mas,
    Winget,
    Chocolatey,
    Flatpak,
    Snap,
    NpmGlobal,
    Rustup,
}

impl ManagerId {
    pub const ALL: [ManagerId; 13] = [
        ManagerId::Softwareupdate,
        ManagerId::WindowsUpdate,
        ManagerId::Apt,
        ManagerId::Dnf,
        ManagerId::Pacman,
        ManagerId::Homebrew,
        ManagerId::Mas,
        ManagerId::Winget,
        ManagerId::Chocolatey,
        ManagerId::Flatpak,
        ManagerId::Snap,
        ManagerId::NpmGlobal,
        ManagerId::Rustup,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ManagerId::Softwareupdate => "softwareupdate",
            ManagerId::WindowsUpdate => "windows-update",
            ManagerId::Apt => "apt",
            ManagerId::Dnf => "dnf",
            ManagerId::Pacman => "pacman",
            ManagerId::Homebrew => "homebrew",
            ManagerId::Mas => "mas",
            ManagerId::Winget => "winget",
            ManagerId::Chocolatey => "chocolatey",
            ManagerId::Flatpak => "flatpak",
            ManagerId::Snap => "snap",
            ManagerId::NpmGlobal => "npm-global",
            ManagerId::Rustup => "rustup",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            ManagerId::Softwareupdate => "macOS Software Update",
            ManagerId::WindowsUpdate => "Windows Update",
            ManagerId::Apt => "APT",
            ManagerId::Dnf => "DNF",
            ManagerId::Pacman => "pacman",
            ManagerId::Homebrew => "Homebrew",
            ManagerId::Mas => "Mac App Store",
            ManagerId::Winget => "winget",
            ManagerId::Chocolatey => "Chocolatey",
            ManagerId::Flatpak => "Flatpak",
            ManagerId::Snap => "Snap",
            ManagerId::NpmGlobal => "npm (global)",
            ManagerId::Rustup => "rustup",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str().eq_ignore_ascii_case(s))
    }
}

impl fmt::Display for ManagerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One package manager's view of the machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagerInventory {
    pub id: ManagerId,
    pub available: bool,
    pub version: Option<String>,
    pub installed: Vec<Package>,
    pub updates: Vec<AvailableUpdate>,
    /// Set when the manager is present but could not be queried.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Package {
    pub manager: ManagerId,
    pub name: String,
    pub version: String,
    /// Source package (Debian/Ubuntu); OSV indexes these, not binary names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    /// OSV ecosystem string when the package can be matched against OSV.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateKind {
    Package,
    Application,
    /// A patch or minor OS release within the installed major version.
    OsUpdate,
    /// A new major OS version. Never applied unless the policy allows it.
    OsUpgrade,
    Firmware,
    Toolchain,
}

/// An update a package manager says is available right now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AvailableUpdate {
    pub manager: ManagerId,
    /// Identifier the manager's install command takes (package name,
    /// winget id, softwareupdate label, App Store id, Windows UpdateID).
    pub id: String,
    pub name: String,
    pub installed_version: Option<String>,
    pub available_version: String,
    pub kind: UpdateKind,
    /// The vendor marks this update as security-relevant.
    pub security: bool,
    pub restart_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl AvailableUpdate {
    pub fn key(&self) -> String {
        format!("{}:{}", self.manager, self.id)
    }
}

// ---------------------------------------------------------------- analysis

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const DESCENDING: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_cvss(score: f64) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// A published advisory affects the installed version.
    Vulnerability,
    /// The OS or a runtime is past (or near) the end of vendor support.
    EndOfLife,
    /// The vendor flags a pending update as security-relevant.
    SecurityUpdate,
    /// An operating-system update (point release, cumulative update, firmware).
    OsUpdate,
    /// A newer version exists; no advisory is known against this one.
    Outdated,
    /// A hardware condition that affects updating or reliability.
    Hardware,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Vulnerability => "Vulnerability",
            Category::EndOfLife => "End of life",
            Category::SecurityUpdate => "Security update",
            Category::OsUpdate => "OS update",
            Category::Outdated => "Outdated",
            Category::Hardware => "Hardware",
        }
    }
}

/// A published vulnerability, enriched with exploitation evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    /// Severity word the database published, when there is no CVSS vector.
    pub database_severity: Option<String>,
    /// Listed in CISA's Known Exploited Vulnerabilities catalogue.
    pub kev: bool,
    pub kev_due_date: Option<String>,
    pub kev_ransomware: bool,
    /// FIRST EPSS probability of exploitation in the next 30 days (0–1).
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub fixed_versions: Vec<String>,
    pub url: String,
}

impl Advisory {
    /// The CVE identifiers among the id and aliases.
    pub fn cves(&self) -> Vec<String> {
        let mut out = Vec::new();
        for s in std::iter::once(&self.id).chain(self.aliases.iter()) {
            if let Some(cve) = extract_cve(s)
                && !out.contains(&cve)
            {
                out.push(cve);
            }
        }
        out
    }
}

/// `CVE-2024-1234` from `CVE-2024-1234`, `DEBIAN-CVE-2024-1234` or
/// `UBUNTU-CVE-2024-1234`.
pub fn extract_cve(s: &str) -> Option<String> {
    let at = s.find("CVE-")?;
    let rest = &s[at..];
    let end = rest
        .char_indices()
        .skip(4)
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '-'))
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    let cve = &rest[..end];
    let mut parts = cve.split('-');
    let (_, year, num) = (parts.next()?, parts.next()?, parts.next()?);
    (year.len() == 4 && num.len() >= 4 && parts.next().is_none()).then(|| cve.to_string())
}

/// Something the user should know or act on, with the evidence for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Stable across runs for the same subject: `vuln:apt:openssl`.
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub manager: Option<ManagerId>,
    pub subject: String,
    pub installed_version: Option<String>,
    /// Why this severity: the evidence, in plain language.
    pub rationale: String,
    pub advisories: Vec<Advisory>,
    /// The update that resolves this finding, when one is available.
    pub remediation: Option<Remediation>,
    /// 0–100; orders findings within and across severities.
    pub risk_score: f64,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Remediation {
    /// `AvailableUpdate::key()` of each update that addresses this (a
    /// Debian source package can ship several binary packages).
    pub update_keys: Vec<String>,
    pub to_version: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceStatus {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub updates_available: usize,
    pub security_updates: usize,
    pub packages_scanned: usize,
    pub advisories: usize,
    pub kev_advisories: usize,
}

impl Summary {
    pub fn count(&self, s: Severity) -> usize {
        match s {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }
}

/// Research results for one [`SystemReport`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Analysis {
    pub schema_version: u32,
    pub generated_at: String,
    pub offline: bool,
    pub sources: Vec<SourceStatus>,
    pub summary: Summary,
    /// Highest risk first.
    pub findings: Vec<Finding>,
}

/// A discovery report and its analysis, saved together so a scan taken on
/// one machine (or earlier) can be planned, reviewed or applied later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scan {
    pub report: SystemReport,
    pub analysis: Analysis,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cves_from_prefixed_ids() {
        assert_eq!(extract_cve("CVE-2024-1234").as_deref(), Some("CVE-2024-1234"));
        assert_eq!(extract_cve("DEBIAN-CVE-2023-5363").as_deref(), Some("CVE-2023-5363"));
        assert_eq!(extract_cve("UBUNTU-CVE-2024-13176").as_deref(), Some("CVE-2024-13176"));
        assert_eq!(extract_cve("GHSA-vh95-rmgr-6w4m"), None);
        assert_eq!(extract_cve("CVE-24-1"), None);
    }

    #[test]
    fn severity_orders_and_maps_from_cvss() {
        assert!(Severity::Critical > Severity::High);
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.0), Severity::High);
        assert_eq!(Severity::from_cvss(5.3), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn manager_ids_round_trip() {
        for m in ManagerId::ALL {
            assert_eq!(ManagerId::parse(m.as_str()), Some(m));
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(json, format!("\"{}\"", m.as_str()));
        }
    }
}
