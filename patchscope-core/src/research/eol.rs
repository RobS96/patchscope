//! endoflife.date: support lifecycles of operating systems and runtimes.
//! <https://endoflife.date/docs/api/v1/>

use super::http::HttpClient;
use crate::model::{OsFamily, OsInfo, Runtime};
use crate::util::{compare_versions, parse_date};
use serde::Deserialize;
use std::cmp::Ordering;

pub const API: &str = "https://endoflife.date/api/v1/products";

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub name: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub is_eol: bool,
    #[serde(default)]
    pub eol_from: Option<String>,
    #[serde(default)]
    pub is_maintained: Option<bool>,
    #[serde(default)]
    pub latest: Option<Latest>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Latest {
    pub name: String,
    #[serde(default)]
    pub link: Option<String>,
}

#[derive(Deserialize)]
struct Envelope {
    result: ProductBody,
}

#[derive(Deserialize)]
struct ProductBody {
    releases: Vec<Release>,
    #[serde(default)]
    links: Option<Links>,
}

#[derive(Deserialize)]
struct Links {
    html: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Product {
    pub id: String,
    /// Newest release first, as the API returns them.
    pub releases: Vec<Release>,
    pub page: String,
}

pub fn fetch(http: &dyn HttpClient, product: &str) -> Result<Product, String> {
    let body = http.get(&format!("{API}/{product}/"))?;
    parse(product, &body)
}

pub fn parse(product: &str, body: &[u8]) -> Result<Product, String> {
    let e: Envelope = serde_json::from_slice(body).map_err(|e| format!("endoflife.date {product}: {e}"))?;
    Ok(Product {
        id: product.to_string(),
        releases: e.result.releases,
        page: e
            .result
            .links
            .and_then(|l| l.html)
            .unwrap_or_else(|| format!("https://endoflife.date/{product}")),
    })
}

/// Where an installed version stands in its product's lifecycle.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub product: String,
    pub cycle: String,
    pub label: String,
    pub is_eol: bool,
    pub eol_date: Option<String>,
    /// Days until end of support (negative once past).
    pub days_left: Option<i64>,
    pub latest_in_cycle: Option<String>,
    /// The installed version is older than the cycle's latest release.
    pub behind_latest: bool,
    /// The newest cycle, when it is not the installed one.
    pub newer_cycle: Option<String>,
    pub page: String,
}

pub fn status(product: &Product, cycle: &Release, installed_version: &str, today: i64) -> Status {
    let eol_days = cycle.eol_from.as_deref().and_then(parse_date);
    let latest = cycle.latest.as_ref().map(|l| l.name.clone());
    let behind = latest
        .as_deref()
        .is_some_and(|l| compare_versions(installed_version, l) == Ordering::Less);
    let newest = product
        .releases
        .first()
        .map(|r| r.name.clone())
        .filter(|n| *n != cycle.name);
    Status {
        product: product.id.clone(),
        cycle: cycle.name.clone(),
        label: cycle
            .label
            .clone()
            .unwrap_or_else(|| format!("{} {}", product.id, cycle.name)),
        is_eol: cycle.is_eol || eol_days.is_some_and(|d| d <= today),
        eol_date: cycle.eol_from.clone(),
        days_left: eol_days.map(|d| d - today),
        latest_in_cycle: latest,
        behind_latest: behind,
        newer_cycle: newest,
        page: product.page.clone(),
    }
}

/// The endoflife.date product for this OS and a function that picks the
/// installed cycle from that product's releases.
pub fn os_product(os: &OsInfo) -> Option<&'static str> {
    match os.family {
        OsFamily::Macos => Some("macos"),
        OsFamily::Windows if os.distro_id.as_deref() == Some("windows-server") => Some("windows-server"),
        OsFamily::Windows => Some("windows"),
        OsFamily::Linux => match os.distro_id.as_deref()? {
            "ubuntu" => Some("ubuntu"),
            "debian" => Some("debian"),
            "fedora" => Some("fedora"),
            "rhel" => Some("rhel"),
            "rocky" => Some("rocky-linux"),
            "almalinux" => Some("almalinux"),
            "centos" => Some("centos"),
            "alpine" => Some("alpine-linux"),
            "opensuse-leap" => Some("opensuse"),
            "sles" => Some("sles"),
            "linuxmint" => Some("linuxmint"),
            "pop" => Some("pop-os"),
            "amzn" => Some("amazon-linux"),
            "ol" => Some("oracle-linux"),
            _ => None,
        },
        OsFamily::Other => None,
    }
}

/// Choose the release (cycle) the installed OS belongs to.
pub fn os_cycle<'a>(os: &OsInfo, product: &'a Product) -> Option<&'a Release> {
    let rel = &product.releases;
    match os.family {
        OsFamily::Macos => {
            let mut parts = os.version.split('.');
            let major = parts.next()?;
            // macOS 10.x cycles are named "10.15"; 11+ by major version.
            let cycle = if major == "10" {
                format!("10.{}", parts.next()?)
            } else {
                major.to_string()
            };
            rel.iter().find(|r| r.name == cycle)
        }
        OsFamily::Windows => {
            let build = os.version.rsplit('.').next()?;
            let want = format!("10.0.{build}");
            let ed = os.edition.as_deref().unwrap_or("").to_ascii_lowercase();
            let enterprise = ed.contains("enterprise") || ed.contains("education");
            // LTSC editions report EditionID "EnterpriseS"/"EnterpriseSN".
            let ltsc = ed.contains("ltsc")
                || ed.contains("ltsb")
                || ed.ends_with("enterprises")
                || ed.ends_with("enterprisesn");
            let candidates: Vec<&Release> = rel
                .iter()
                .filter(|r| r.latest.as_ref().is_some_and(|l| l.name == want))
                .collect();
            if product.id == "windows-server" {
                return candidates.first().copied();
            }
            candidates
                .iter()
                .find(|r| {
                    let n = r.name.as_str();
                    let is_lts = n.contains("lts");
                    !n.contains("iot")
                        && is_lts == ltsc
                        && (n.ends_with(if enterprise { "-e" } else { "-w" })
                            || ltsc
                            || !(n.ends_with("-e") || n.ends_with("-w")))
                })
                .or_else(|| candidates.first())
                .copied()
        }
        _ => {
            let v = os.distro_version_id.as_deref()?;
            // Exact (24.04, 3.20), then major (12, 9).
            rel.iter()
                .find(|r| r.name == v)
                .or_else(|| rel.iter().find(|r| Some(r.name.as_str()) == v.split('.').next()))
                .or_else(|| {
                    let mm: String = v.split('.').take(2).collect::<Vec<_>>().join(".");
                    rel.iter().find(|r| r.name == mm)
                })
        }
    }
}

/// The cycle a runtime version belongs to: Node.js by major, the others by
/// major.minor.
pub fn runtime_cycle<'a>(rt: &Runtime, product: &'a Product) -> Option<&'a Release> {
    let mut parts = rt.version.split('.');
    let major = parts.next()?;
    let minor = parts.next();
    let mm = minor.map(|m| format!("{major}.{m}"));
    product
        .releases
        .iter()
        .find(|r| Some(&r.name) == mm.as_ref())
        .or_else(|| product.releases.iter().find(|r| r.name == major))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::days_from_civil;

    const MACOS: &str = include_str!("../../tests/fixtures/eol-macos.json");
    const WINDOWS: &str = include_str!("../../tests/fixtures/eol-windows.json");

    fn os(family: OsFamily, version: &str, edition: Option<&str>, distro: Option<(&str, &str)>) -> OsInfo {
        OsInfo {
            family,
            name: String::new(),
            version: version.into(),
            build: None,
            kernel: String::new(),
            arch: String::new(),
            distro_id: distro.map(|d| d.0.into()),
            distro_version_id: distro.map(|d| d.1.into()),
            edition: edition.map(str::to_string),
        }
    }

    #[test]
    fn macos_cycle_and_status() {
        let p = parse("macos", MACOS.as_bytes()).unwrap();
        let o = os(OsFamily::Macos, "26.7.1", None, None);
        let r = os_cycle(&o, &p).unwrap();
        assert_eq!(r.name, "26");
        let s = status(&p, r, "26.7.1", days_from_civil(2026, 10, 3));
        assert!(!s.is_eol);
        assert_eq!(s.latest_in_cycle.as_deref(), Some("26.7.2"));
        assert!(s.behind_latest);
        assert_eq!(s.newer_cycle.as_deref(), Some("27"));

        let old = os(OsFamily::Macos, "13.7.8", None, None);
        let r = os_cycle(&old, &p).unwrap();
        let s = status(&p, r, "13.7.8", days_from_civil(2026, 10, 3));
        assert!(s.is_eol, "{s:?}");
    }

    #[test]
    fn windows_cycle_by_build_and_edition() {
        let p = parse("windows", WINDOWS.as_bytes()).unwrap();
        let pro = os(OsFamily::Windows, "10.0.26100", Some("Professional"), None);
        assert_eq!(os_cycle(&pro, &p).unwrap().name, "11-24h2-w");
        let ent = os(OsFamily::Windows, "10.0.26100", Some("Enterprise"), None);
        assert_eq!(os_cycle(&ent, &p).unwrap().name, "11-24h2-e");
        let ltsc = os(OsFamily::Windows, "10.0.26100", Some("EnterpriseS"), None);
        assert_eq!(os_cycle(&ltsc, &p).unwrap().name, "11-24h2-e-lts");
        let w = os_cycle(&pro, &p).unwrap();
        let s = status(&p, w, "10.0.26100", days_from_civil(2026, 10, 14));
        assert!(s.is_eol, "Home/Pro 24H2 support ends 2026-10-13");
        let s = status(&p, w, "10.0.26100", days_from_civil(2026, 10, 3));
        assert_eq!(s.days_left, Some(10));
    }

    #[test]
    fn linux_and_runtime_cycles() {
        let body = br#"{"result":{"releases":[{"name":"12","isEol":false,"eolFrom":"2026-06-10","latest":{"name":"12.12"}},{"name":"11","isEol":true,"eolFrom":"2024-08-14"}]}}"#;
        let p = parse("debian", body).unwrap();
        let o = os(OsFamily::Linux, "12", None, Some(("debian", "12")));
        let s = status(&p, os_cycle(&o, &p).unwrap(), "12", days_from_civil(2026, 10, 3));
        assert!(s.is_eol, "eolFrom in the past counts even if isEol lags");

        let py = br#"{"result":{"releases":[{"name":"3.14","isEol":false,"latest":{"name":"3.14.0"}},{"name":"3.9","isEol":true,"eolFrom":"2025-10-31","latest":{"name":"3.9.24"}}]}}"#;
        let p = parse("python", py).unwrap();
        let rt = Runtime {
            product: "python".into(),
            display_name: "Python".into(),
            version: "3.9.6".into(),
            path_command: "/usr/bin/python3".into(),
        };
        assert_eq!(runtime_cycle(&rt, &p).unwrap().name, "3.9");
        let node = br#"{"result":{"releases":[{"name":"24","latest":{"name":"24.9.0"}},{"name":"22","latest":{"name":"22.20.0"}}]}}"#;
        let p = parse("nodejs", node).unwrap();
        let rt = Runtime {
            product: "nodejs".into(),
            display_name: "Node.js".into(),
            version: "22.9.0".into(),
            path_command: "node".into(),
        };
        assert_eq!(runtime_cycle(&rt, &p).unwrap().name, "22");
        assert_eq!(
            os_product(&os(OsFamily::Linux, "", None, Some(("rocky", "9.4")))),
            Some("rocky-linux")
        );
    }
}
