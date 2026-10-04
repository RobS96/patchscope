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
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
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
    /// Set when this query has more results (too many for one page, or the
    /// query ran long): ask again with it as `page_token`.
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct BatchVuln {
    id: String,
}

/// Most follow-up pages fetched per scan before giving up on the rest.
const MAX_PAGES: usize = 20;

/// The result of [`query_batch`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BatchOutcome {
    /// Vulnerability ids affecting each query, in query order.
    pub ids: Vec<Vec<String>>,
    /// Queries whose later result pages could not be fetched, so their
    /// lists may be incomplete; empty when every page was read.
    pub incomplete: Vec<String>,
}

/// One query's ids on one page, and the token for its next page.
type Page = (Vec<String>, Option<String>);

/// One `querybatch` call: each query with its page token (None: page one).
fn post_batch(http: &dyn HttpClient, queries: &[(&Query, Option<&str>)]) -> Result<Vec<Page>, String> {
    let body = BatchBody {
        queries: queries
            .iter()
            .map(|(q, token)| BatchQuery {
                package: BatchPackage {
                    name: &q.name,
                    ecosystem: &q.ecosystem,
                },
                version: &q.version,
                page_token: *token,
            })
            .collect(),
    };
    let body = serde_json::to_string(&body).map_err(|e| e.to_string())?;
    let resp = http.post_json(&format!("{API}/querybatch"), &body)?;
    let parsed: BatchResponse = serde_json::from_slice(&resp).map_err(|e| format!("OSV querybatch: {e}"))?;
    if parsed.results.len() != queries.len() {
        return Err(format!(
            "OSV returned {} results for {} queries",
            parsed.results.len(),
            queries.len()
        ));
    }
    Ok(parsed
        .results
        .into_iter()
        .map(|r| {
            (
                r.vulns.into_iter().map(|v| v.id).collect(),
                r.next_page_token.filter(|t| !t.is_empty()),
            )
        })
        .collect())
}

/// Vulnerability ids affecting each query, following `next_page_token`
/// until every query is complete (at most [`MAX_PAGES`] follow-up rounds).
/// A failed first page is an error; a failed later page keeps what was read
/// and names the query in [`BatchOutcome::incomplete`].
pub fn query_batch(http: &dyn HttpClient, queries: &[Query]) -> Result<BatchOutcome, String> {
    let mut out = BatchOutcome {
        ids: Vec::with_capacity(queries.len()),
        incomplete: Vec::new(),
    };
    for chunk in queries.chunks(BATCH) {
        let base = out.ids.len();
        let first: Vec<(&Query, Option<&str>)> = chunk.iter().map(|q| (q, None)).collect();
        // (index into `out.ids`, token) of the queries with more pages.
        let mut pending: Vec<(usize, String)> = Vec::new();
        for (i, (ids, token)) in post_batch(http, &first)?.into_iter().enumerate() {
            out.ids.push(ids);
            if let Some(t) = token {
                pending.push((base + i, t));
            }
        }
        let mut round = 0;
        while !pending.is_empty() {
            let label = |i: usize| format!("{} {}", queries[i].name, queries[i].version);
            if round == MAX_PAGES {
                out.incomplete.extend(
                    pending
                        .iter()
                        .map(|(i, _)| format!("{}: more than {MAX_PAGES} result pages", label(*i))),
                );
                break;
            }
            round += 1;
            let next: Vec<(&Query, Option<&str>)> =
                pending.iter().map(|(i, t)| (&queries[*i], Some(t.as_str()))).collect();
            match post_batch(http, &next) {
                Ok(results) => {
                    let mut still = Vec::new();
                    for ((i, _), (ids, token)) in pending.iter().zip(results) {
                        for id in ids {
                            if !out.ids[*i].contains(&id) {
                                out.ids[*i].push(id);
                            }
                        }
                        if let Some(t) = token {
                            still.push((*i, t));
                        }
                    }
                    pending = still;
                }
                Err(e) => {
                    out.incomplete.extend(
                        pending
                            .iter()
                            .map(|(i, _)| format!("{}: next page failed: {e}", label(*i))),
                    );
                    break;
                }
            }
        }
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
        assert_eq!(r.ids, vec![vec!["GHSA-1".to_string()], vec![]]);
        assert!(r.incomplete.is_empty());
        let sent = http.requests.lock().unwrap()[0].clone();
        assert!(
            sent.contains(r#"{"package":{"name":"a","ecosystem":"npm"},"version":"1.0.0"}"#),
            "{sent}"
        );
    }

    #[test]
    fn batch_follows_next_page_token() {
        let url = "https://api.osv.dev/v1/querybatch";
        let http = FakeHttp::new()
            .post_route_when(
                url,
                r#""page_token":"p2""#,
                r#"{"results":[{"vulns":[{"id":"DEBIAN-CVE-2024-0003"}]}]}"#,
            )
            .post_route(
                url,
                r#"{"results":[{"vulns":[{"id":"DEBIAN-CVE-2024-0001"},{"id":"DEBIAN-CVE-2024-0002"}],"next_page_token":"p2"},{"vulns":[{"id":"GHSA-x"}]}]}"#,
            );
        let q = |n: &str| Query {
            ecosystem: "Debian:12".into(),
            name: n.into(),
            version: "1".into(),
        };
        let r = query_batch(&http, &[q("linux"), q("zlib")]).unwrap();
        assert!(r.incomplete.is_empty(), "{:?}", r.incomplete);
        let r = r.ids;
        assert_eq!(
            r[0],
            ["DEBIAN-CVE-2024-0001", "DEBIAN-CVE-2024-0002", "DEBIAN-CVE-2024-0003"],
            "the second page is fetched"
        );
        assert_eq!(r[1], ["GHSA-x"]);
        let sent = http.requests.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(
            sent[1].contains(r#""page_token":"p2""#)
                && sent[1].contains(r#""name":"linux""#)
                && !sent[1].contains("zlib"),
            "only the paged query is re-issued, with its token: {}",
            sent[1]
        );
    }

    #[test]
    fn batch_reports_pages_it_could_not_read() {
        let url = "https://api.osv.dev/v1/querybatch";
        let q = Query {
            ecosystem: "Debian:12".into(),
            name: "linux".into(),
            version: "6.1.0".into(),
        };
        // A later page fails: keep the first page, say the list is partial.
        let http = FakeHttp::new()
            .post_fail_when(url, "page_token", "http status: 503")
            .post_route(
                url,
                r#"{"results":[{"vulns":[{"id":"DEBIAN-CVE-2024-0001"}],"next_page_token":"p2"}]}"#,
            );
        let r = query_batch(&http, std::slice::from_ref(&q)).unwrap();
        assert_eq!(r.ids[0], ["DEBIAN-CVE-2024-0001"]);
        assert_eq!(r.incomplete.len(), 1);
        assert!(
            r.incomplete[0].contains("linux 6.1.0") && r.incomplete[0].contains("503"),
            "{:?}",
            r.incomplete
        );

        // A token that never runs out stops at the page cap.
        let http = FakeHttp::new().post_route(
            url,
            r#"{"results":[{"vulns":[{"id":"DEBIAN-CVE-2024-0001"}],"next_page_token":"again"}]}"#,
        );
        let r = query_batch(&http, &[q]).unwrap();
        assert_eq!(http.request_count(), 1 + MAX_PAGES);
        assert_eq!(r.ids[0], ["DEBIAN-CVE-2024-0001"], "duplicates are dropped");
        assert!(
            r.incomplete[0].contains("more than 20 result pages"),
            "{:?}",
            r.incomplete
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
