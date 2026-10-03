//! OSV.dev: which published vulnerabilities affect an installed version.
//! <https://google.github.io/osv.dev/api/>

use super::http::HttpClient;
use crate::model::Advisory;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const API: &str = "https://api.osv.dev/v1";
/// OSV accepts at most 1000 queries per batch.
const BATCH: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Query {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Serialize)]
struct BatchBody<'a> {
    queries: Vec<BatchQuery<'a>>,
}

#[derive(Serialize)]
struct BatchQuery<'a> {
    package: BatchPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct BatchPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVuln>,
}

#[derive(Deserialize)]
struct BatchVuln {
    id: String,
}

/// Vulnerability ids affecting each query, in query order.
pub fn query_batch(http: &dyn HttpClient, queries: &[Query]) -> Result<Vec<Vec<String>>, String> {
    let mut out = Vec::with_capacity(queries.len());
    for chunk in queries.chunks(BATCH) {
        let body = BatchBody {
            queries: chunk
                .iter()
                .map(|q| BatchQuery {
                    package: BatchPackage {
                        name: &q.name,
                        ecosystem: &q.ecosystem,
                    },
                    version: &q.version,
                })
                .collect(),
        };
        let body = serde_json::to_string(&body).map_err(|e| e.to_string())?;
        let resp = http.post_json(&format!("{API}/querybatch"), &body)?;
        let parsed: BatchResponse = serde_json::from_slice(&resp).map_err(|e| format!("OSV querybatch: {e}"))?;
        if parsed.results.len() != chunk.len() {
            return Err(format!(
                "OSV returned {} results for {} queries",
                parsed.results.len(),
                chunk.len()
            ));
        }
        out.extend(
            parsed
                .results
                .into_iter()
                .map(|r| r.vulns.into_iter().map(|v| v.id).collect()),
        );
    }
    Ok(out)
}

/// Fetch one record and turn it into an [`Advisory`] for `package` in
/// `ecosystem` (fixed versions are those of the matching `affected` entry).
pub fn fetch_advisory(http: &dyn HttpClient, id: &str, ecosystem: &str, package: &str) -> Result<Advisory, String> {
    let body = http.get(&format!("{API}/vulns/{id}"))?;
    let v: Value = serde_json::from_slice(&body).map_err(|e| format!("OSV {id}: {e}"))?;
    Ok(advisory_from_osv(&v, ecosystem, package))
}

/// An advisory known only by id (detail fetch skipped or failed).
pub fn bare_advisory(id: &str) -> Advisory {
    Advisory {
        id: id.to_string(),
        aliases: Vec::new(),
        summary: None,
        cvss_score: None,
        cvss_vector: None,
        database_severity: None,
        kev: false,
        kev_due_date: None,
        kev_ransomware: false,
        epss: None,
        epss_percentile: None,
        fixed_versions: Vec::new(),
        url: format!("https://osv.dev/vulnerability/{id}"),
    }
}

pub fn advisory_from_osv(v: &Value, ecosystem: &str, package: &str) -> Advisory {
    let id = v.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
    let mut a = bare_advisory(&id);
    a.aliases = v
        .get("aliases")
        .and_then(Value::as_array)
        .map(|xs| xs.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // Debian/Ubuntu records carry the CVE as an upstream reference.
    if let Some(up) = v.get("upstream").and_then(Value::as_array) {
        for u in up.iter().filter_map(Value::as_str) {
            if !a.aliases.iter().any(|x| x == u) {
                a.aliases.push(u.to_string());
            }
        }
    }
    a.summary = v
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| v.get("details").and_then(Value::as_str))
        .map(|s| first_sentence(s, 240));

    // Best available score: CVSS v3, then v4, then v2.
    let mut vectors: Vec<(u8, String)> = Vec::new();
    for sev in v.get("severity").and_then(Value::as_array).into_iter().flatten() {
        let ty = sev.get("type").and_then(Value::as_str).unwrap_or_default();
        let score = sev.get("score").and_then(Value::as_str).unwrap_or_default();
        match ty {
            "CVSS_V3" => vectors.push((0, score.into())),
            "CVSS_V4" => vectors.push((1, score.into())),
            "CVSS_V2" => vectors.push((2, score.into())),
            // Ubuntu publishes its priority ("low", "medium", …) here.
            _ if !score.is_empty() && !score.contains('/') => a.database_severity = Some(score.to_lowercase()),
            _ => {}
        }
    }
    vectors.sort();
    for (_, vec) in vectors {
        if let Ok(c) = vec.parse::<cvss::Cvss>() {
            a.cvss_score = Some((c.score() * 10.0).round() / 10.0);
            a.cvss_vector = Some(vec);
            break;
        }
    }
    if a.database_severity.is_none() {
        a.database_severity = v
            .pointer("/database_specific/severity")
            .and_then(Value::as_str)
            .map(str::to_lowercase);
    }
    // Ubuntu also puts a per-package priority under ecosystem_specific.
    for aff in v.get("affected").and_then(Value::as_array).into_iter().flatten() {
        let eco = aff
            .pointer("/package/ecosystem")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = aff.pointer("/package/name").and_then(Value::as_str).unwrap_or_default();
        if !(name == package && (eco == ecosystem || ecosystem.starts_with(eco) || eco.starts_with(ecosystem))) {
            continue;
        }
        if a.database_severity.is_none()
            && let Some(p) = aff
                .pointer("/ecosystem_specific/urgency")
                .or_else(|| aff.pointer("/ecosystem_specific/severity"))
                .and_then(Value::as_str)
        {
            a.database_severity = Some(p.to_lowercase());
        }
        for r in aff.get("ranges").and_then(Value::as_array).into_iter().flatten() {
            for ev in r.get("events").and_then(Value::as_array).into_iter().flatten() {
                if let Some(f) = ev.get("fixed").and_then(Value::as_str)
                    && !a.fixed_versions.iter().any(|x| x == f)
                {
                    a.fixed_versions.push(f.to_string());
                }
            }
        }
    }
    a
}

fn first_sentence(s: &str, max: usize) -> String {
    let s = s.trim().replace('\n', " ");
    let end = s.find(". ").map(|i| i + 1).unwrap_or(s.len()).min(max);
    let mut end = end.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].trim().to_string();
    if end < s.len() && !out.ends_with('.') {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::research::http::FakeHttp;

    const GHSA: &str = include_str!("../../tests/fixtures/osv-GHSA-vh95-rmgr-6w4m.json");
    const UBUNTU: &str = include_str!("../../tests/fixtures/osv-UBUNTU-CVE-2024-13176.json");

    #[test]
    fn ghsa_record_scores_cvss_and_fixed_version() {
        let v: Value = serde_json::from_str(GHSA).unwrap();
        let a = advisory_from_osv(&v, "npm", "minimist");
        assert_eq!(a.id, "GHSA-vh95-rmgr-6w4m");
        assert_eq!(a.cves(), ["CVE-2020-7598"]);
        assert_eq!(a.cvss_score, Some(5.6));
        assert_eq!(a.database_severity.as_deref(), Some("moderate"));
        assert_eq!(a.fixed_versions, ["0.2.1", "1.2.3"]);
        assert_eq!(a.summary.as_deref(), Some("Prototype Pollution in minimist"));
    }

    #[test]
    fn ubuntu_record_uses_priority_and_upstream_cve() {
        let v: Value = serde_json::from_str(UBUNTU).unwrap();
        let a = advisory_from_osv(&v, "Ubuntu:24.04:LTS", "openssl");
        assert_eq!(a.cves(), ["CVE-2024-13176"]);
        assert_eq!(a.database_severity.as_deref(), Some("low"));
        assert_eq!(a.fixed_versions, ["3.0.13-0ubuntu3.5"]);
        assert!(a.summary.unwrap().len() <= 241);
    }

    #[test]
    fn batch_keeps_query_order() {
        let http = FakeHttp::new().post_route(
            "https://api.osv.dev/v1/querybatch",
            r#"{"results":[{"vulns":[{"id":"GHSA-1","modified":"x"}]},{}]}"#,
        );
        let q = |n: &str| Query {
            ecosystem: "npm".into(),
            name: n.into(),
            version: "1.0.0".into(),
        };
        let r = query_batch(&http, &[q("a"), q("b")]).unwrap();
        assert_eq!(r, vec![vec!["GHSA-1".to_string()], vec![]]);
        let sent = http.requests.lock().unwrap()[0].clone();
        assert!(
            sent.contains(r#"{"package":{"name":"a","ecosystem":"npm"},"version":"1.0.0"}"#),
            "{sent}"
        );
    }

    #[test]
    fn batch_rejects_mismatched_result_count() {
        let http = FakeHttp::new().post_route("https://api.osv.dev/v1/querybatch", r#"{"results":[]}"#);
        let q = Query {
            ecosystem: "npm".into(),
            name: "a".into(),
            version: "1".into(),
        };
        assert!(query_batch(&http, &[q]).is_err());
    }

    #[test]
    fn sentences() {
        assert_eq!(first_sentence("One. Two.", 100), "One.");
        assert_eq!(first_sentence("abcdef", 3), "abc…");
    }
}
