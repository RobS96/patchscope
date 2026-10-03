//! FIRST EPSS: the probability a CVE is exploited in the next 30 days.
//! <https://www.first.org/epss/api>

use super::http::HttpClient;
use serde::Deserialize;
use std::collections::HashMap;

pub const API: &str = "https://api.first.org/data/v1/epss";
/// CVEs per request; keeps the URL well under common length limits.
const CHUNK: usize = 100;

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    data: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    cve: String,
    epss: String,
    percentile: String,
}

/// (probability, percentile) per CVE. CVEs EPSS does not score are absent.
pub fn fetch(http: &dyn HttpClient, cves: &[String]) -> Result<HashMap<String, (f64, f64)>, String> {
    let mut out = HashMap::new();
    for chunk in cves.chunks(CHUNK) {
        let url = format!("{API}?cve={}", chunk.join(","));
        out.extend(parse(&http.get(&url)?)?);
    }
    Ok(out)
}

pub fn parse(body: &[u8]) -> Result<HashMap<String, (f64, f64)>, String> {
    let r: Response = serde_json::from_slice(body).map_err(|e| format!("EPSS: {e}"))?;
    Ok(r.data
        .into_iter()
        .filter_map(|row| Some((row.cve, (row.epss.parse().ok()?, row.percentile.parse().ok()?))))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::research::http::FakeHttp;

    #[test]
    fn parses_and_chunks() {
        let body = r#"{"status":"OK","data":[{"cve":"CVE-2021-44906","epss":"0.045810000","percentile":"0.913500000","date":"2026-10-02"}]}"#;
        let http = FakeHttp::new().route(API, body);
        let cves: Vec<String> = (0..150).map(|i| format!("CVE-2021-{:05}", 40000 + i)).collect();
        let m = fetch(&http, &cves).unwrap();
        assert_eq!(http.request_count(), 2);
        assert_eq!(m["CVE-2021-44906"], (0.04581, 0.9135));
    }
}
