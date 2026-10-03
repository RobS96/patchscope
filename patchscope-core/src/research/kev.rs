//! CISA Known Exploited Vulnerabilities: CVEs with evidence of exploitation
//! in the wild. <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

use super::http::HttpClient;
use serde::Deserialize;
use std::collections::HashMap;

pub const URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, PartialEq)]
pub struct KevEntry {
    pub due_date: Option<String>,
    pub ransomware: bool,
    pub name: String,
}

#[derive(Deserialize)]
struct Catalog {
    #[serde(rename = "catalogVersion", default)]
    version: String,
    vulnerabilities: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    #[serde(rename = "cveID")]
    cve: String,
    #[serde(rename = "dueDate", default)]
    due: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    ransomware: Option<String>,
    #[serde(rename = "vulnerabilityName", default)]
    name: String,
}

pub struct Kev {
    pub version: String,
    pub entries: HashMap<String, KevEntry>,
}

pub fn parse(body: &[u8]) -> Result<Kev, String> {
    let c: Catalog = serde_json::from_slice(body).map_err(|e| format!("KEV catalogue: {e}"))?;
    Ok(Kev {
        version: c.version,
        entries: c
            .vulnerabilities
            .into_iter()
            .map(|i| {
                (
                    i.cve.to_ascii_uppercase(),
                    KevEntry {
                        due_date: i.due,
                        ransomware: i.ransomware.is_some_and(|r| r.eq_ignore_ascii_case("known")),
                        name: i.name,
                    },
                )
            })
            .collect(),
    })
}

pub fn fetch(http: &dyn HttpClient) -> Result<Kev, String> {
    parse(&http.get(URL)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_catalogue() {
        let body = br#"{"title":"CISA Catalog","catalogVersion":"2026.10.02","count":2,"vulnerabilities":[
            {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Apache Log4j2 RCE","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known"},
            {"cveID":"CVE-2024-3094","vendorProject":"XZ","product":"XZ Utils","vulnerabilityName":"XZ Utils Embedded Malicious Code","dueDate":"2024-04-19","knownRansomwareCampaignUse":"Unknown"}]}"#;
        let k = parse(body).unwrap();
        assert_eq!(k.version, "2026.10.02");
        assert!(k.entries["CVE-2021-44228"].ransomware);
        assert!(!k.entries["CVE-2024-3094"].ransomware);
        assert_eq!(k.entries["CVE-2024-3094"].due_date.as_deref(), Some("2024-04-19"));
    }
}
