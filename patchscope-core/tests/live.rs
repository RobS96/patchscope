//! Against the real research services. Ignored by default (they need the
//! network); run with `cargo test -p patchscope-core --test live -- --ignored`.
//! The weekly end-to-end workflow runs them, so a change in an upstream API
//! is caught even when nothing in this repository changed.

use patchscope_core::research::http::UreqClient;
use patchscope_core::research::{eol, epss, kev, osv};

#[test]
#[ignore = "network"]
fn osv_finds_known_vulnerabilities() {
    let http = UreqClient::new();
    let q = |eco: &str, name: &str, version: &str| osv::Query {
        ecosystem: eco.into(),
        name: name.into(),
        version: version.into(),
    };
    let ids = osv::query_batch(
        &http,
        &[
            q("npm", "minimist", "1.2.0"),
            q("npm", "minimist", "1.2.8"),
            q("Debian:12", "openssl", "3.0.11-1~deb12u1"),
        ],
    )
    .unwrap()
    .ids;
    assert!(ids[0].iter().any(|i| i == "GHSA-vh95-rmgr-6w4m"), "{:?}", ids[0]);
    assert!(ids[1].is_empty(), "minimist 1.2.8 is fixed: {:?}", ids[1]);
    assert!(!ids[2].is_empty(), "an old Debian openssl has advisories");
    let a = osv::fetch_advisory(&http, "GHSA-vh95-rmgr-6w4m", "npm", "minimist").unwrap();
    assert_eq!(a.cves(), ["CVE-2020-7598"]);
    assert!(a.cvss_score.is_some());
}

#[test]
#[ignore = "network"]
fn kev_catalogue_parses() {
    let k = kev::fetch(&UreqClient::new()).unwrap();
    assert!(k.entries.len() > 1000, "{} entries", k.entries.len());
    assert!(k.entries.contains_key("CVE-2021-44228"), "Log4Shell is in KEV");
}

#[test]
#[ignore = "network"]
fn epss_scores_a_known_cve() {
    let m = epss::fetch(&UreqClient::new(), &["CVE-2021-44228".into()]).unwrap();
    let (p, pct) = m["CVE-2021-44228"];
    assert!(p > 0.5 && pct > 0.9, "Log4Shell: {p} / {pct}");
}

#[test]
#[ignore = "network"]
fn endoflife_products_parse() {
    let http = UreqClient::new();
    for product in [
        "macos",
        "windows",
        "windows-server",
        "ubuntu",
        "debian",
        "fedora",
        "rocky-linux",
        "almalinux",
        "python",
        "nodejs",
        "go",
        "ruby",
        "php",
        "eclipse-temurin",
        "amazon-corretto",
        "azul-zulu",
        "oracle-jdk",
        "microsoft-build-of-openjdk",
        "redhat-build-of-openjdk",
    ] {
        let p = eol::fetch(&http, product).unwrap_or_else(|e| panic!("{product}: {e}"));
        assert!(!p.releases.is_empty(), "{product} has releases");
    }
}
