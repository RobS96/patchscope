//! Entry points for the cargo-fuzz targets in `fuzz/`, kept here so a plain
//! `cargo test` runs them too. Not a stable API.
//!
//! Every parser in patchscope reads text it does not control: package
//! manager output, vendor tools, and JSON from public services. These
//! functions feed arbitrary bytes through them. A panic is a bug; so is a
//! broken safety invariant, which they assert:
//!
//! - nothing planned carries an identifier its manager would not list, or
//!   a version that is not a plain version where it reaches a command;
//! - an HTML report never contains a raw `<script`;
//! - text shown to a person (terminal, reports) carries no control or
//!   hidden/bidi character other than tab and newline.

use crate::analysis::{AnalyzeOptions, analyze};
use crate::discover::{hardware, os};
use crate::exec::{CommandOutput, FakeRunner};
use crate::managers::{self, Context};
use crate::model::*;
use crate::plan::{Selection, build_plan};
use crate::policy::Policy;
use crate::research::http::FakeHttp;
use crate::research::{eol, epss, kev, osv};
use crate::{report, util};

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

fn os_for(selector: u8) -> OsInfo {
    let (family, distro, version) = match selector % 6 {
        0 => (OsFamily::Macos, None, "26.7.1"),
        1 => (OsFamily::Windows, None, "10.0.26100"),
        2 => (OsFamily::Linux, Some(("ubuntu", "24.04")), "24.04"),
        3 => (OsFamily::Linux, Some(("debian", "13")), "13"),
        4 => (OsFamily::Linux, Some(("almalinux", "9.6")), "9.6"),
        _ => (OsFamily::Linux, Some(("arch", "rolling")), "rolling"),
    };
    OsInfo {
        family,
        name: "fuzz".into(),
        version: version.into(),
        build: None,
        kernel: "k".into(),
        arch: if selector & 0x80 != 0 {
            "arm64".into()
        } else {
            "x86_64".into()
        },
        distro_id: distro.map(|d| d.0.to_string()),
        distro_version_id: distro.map(|d| d.1.to_string()),
        edition: None,
    }
}

/// The exit statuses that matter to the adapters: success, "updates exist"
/// (1 for npm/dnf/pacman, 2 for checkupdates/choco, 100 for rustup), failure.
fn status_for(selector: u8) -> i32 {
    [0, 1, 2, 100, 127][(selector as usize) % 5]
}

/// Every adapter, with every command answering `data`.
pub fn manager_output(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    let ctx = Context::new(os_for(sel));
    let runner = FakeRunner::new().answer_everything(CommandOutput::with_status(status_for(sel >> 3), &text(rest), ""));
    for m in managers::all() {
        let inv = managers::inventory(m.as_ref(), &runner, &ctx);
        for u in &inv.updates {
            // Building the command must never panic, whatever the id.
            let _ = m.install_command(u).display();
        }
    }
    // The line and table parsers directly, on the raw text.
    let t = text(rest);
    let _ = managers::parse_softwareupdate_for_fuzzing(&t);
    for line in t.lines() {
        let _ = managers::parse_mas_line_for_fuzzing(line);
    }
}

/// Research and discovery parsers on arbitrary JSON and text.
pub fn research_data(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    let t = text(rest);
    match sel % 8 {
        0 => {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(rest) {
                let a = osv::advisory_from_osv(&v, "npm", "minimist");
                let _ = (
                    crate::analysis::advisory_severity(&a),
                    crate::analysis::advisory_risk(&a),
                    a.cves(),
                );
            }
        }
        1 => {
            let _ = kev::parse(rest);
        }
        2 => {
            let _ = epss::parse(rest);
        }
        3 => {
            if let Ok(p) = eol::parse("fuzz", rest) {
                for r in &p.releases {
                    let _ = eol::status(&p, r, "1.2.3", util::today_days());
                }
                let _ = eol::os_cycle(&os_for(sel >> 3), &p);
                let rt = Runtime {
                    product: "python".into(),
                    display_name: "Python".into(),
                    version: "3.12.1".into(),
                    path_command: "python3".into(),
                };
                let _ = eol::runtime_cycle(&rt, &p);
            }
        }
        4 => {
            let mut info = os_for(2);
            os::apply_os_release(&t, &mut info);
            let _ = os::apply_windows_registry(&t, &mut info);
        }
        5 => {
            let mut hw = HardwareInfo::default();
            let _ = hardware::apply_system_profiler(&t, &mut hw);
            let _ = hardware::apply_windows_cim(&t, &mut hw);
            let _ = hardware::parse_lspci_gpus(&t);
        }
        6 => {
            let _ = extract_cve(&t);
        }
        _ => {
            let _ = serde_json::from_str::<Scan>(&t);
        }
    }
}

/// Arbitrary tool output and arbitrary research responses, through
/// analysis, planning and both report formats, checking the invariants.
pub fn pipeline(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    // 0xFF never occurs in UTF-8, so it separates the parts.
    let mut parts = rest.split(|b| *b == 0xFF).map(text);
    let tool = parts.next().unwrap_or_default();
    let batch = parts.next().unwrap_or_default();
    let vuln = parts.next().unwrap_or_default();
    let kev_body = parts.next().unwrap_or_default();
    let epss_body = parts.next().unwrap_or_default();
    let eol_body = parts.next().unwrap_or_default();

    let os = os_for(sel);
    let ctx = Context::new(os.clone());
    let runner = FakeRunner::new().answer_everything(CommandOutput::with_status(status_for(sel >> 3), &tool, ""));
    let report = SystemReport {
        schema_version: SCHEMA_VERSION,
        tool_version: "fuzz".into(),
        generated_at: "2026-01-01T00:00:00Z".into(),
        host: HostInfo::default(),
        os,
        hardware: HardwareInfo::default(),
        runtimes: Vec::new(),
        managers: managers::all()
            .iter()
            .map(|m| managers::inventory(m.as_ref(), &runner, &ctx))
            .collect(),
        warnings: Vec::new(),
    };
    let http = FakeHttp::new()
        .post_route("https://api.osv.dev/v1/querybatch", &batch)
        .route("https://api.osv.dev/v1/vulns/", &vuln)
        .route("https://www.cisa.gov/", &kev_body)
        .route("https://api.first.org/", &epss_body)
        .route("https://endoflife.date/", &eol_body);
    let opts = AnalyzeOptions {
        cache_dir: None,
        max_advisory_details: 20,
        today: Some(util::days_from_civil(2026, 10, 3)),
        ..Default::default()
    };
    let analysis = analyze(&report, &http, &opts, &|_| {});
    let plan = build_plan(&report, &analysis, &Policy::default(), &Selection::All);

    for a in &plan.actions {
        for u in &a.updates {
            assert!(
                managers::valid_identifier(u.manager, &u.id),
                "planned an invalid {} identifier: {:?}",
                u.manager,
                u.id
            );
            assert!(
                managers::valid_version(u.manager, &u.available_version),
                "planned an invalid {} version: {:?}",
                u.manager,
                u.available_version
            );
        }
    }
    let html = report::html(&report, Some(&analysis), Some(&plan));
    assert!(!html.contains("<script"), "unescaped script in the HTML report");
    let md = report::markdown(&report, Some(&analysis), Some(&plan));
    for (name, out) in [("HTML", &html), ("Markdown", &md)] {
        assert!(
            out.chars()
                .all(|c| c == '\n' || c == '\t' || !util::is_hidden_or_control(c)),
            "control or hidden character in the {name} report"
        );
    }
}

/// Policy files and the small text utilities.
pub fn policy_and_text(data: &[u8]) {
    let t = text(data);
    if let Ok(p) = Policy::from_toml(&t) {
        let u = AvailableUpdate {
            manager: ManagerId::Homebrew,
            id: "git".into(),
            name: "git".into(),
            installed_version: None,
            available_version: "2".into(),
            kind: UpdateKind::Package,
            security: false,
            restart_required: false,
            notes: None,
        };
        let _ = p.protection_for(&u);
        let _ = Policy::from_toml(&p.to_toml()).expect("a policy's own TOML parses back");
    }
    let (a, b) = t.split_once('\0').unwrap_or((&t, ""));
    let _ = util::compare_versions(a, b);
    let _ = util::glob_match(a, b);
    let _ = util::first_version(&t);
    let _ = util::parse_date(&t);
    assert!(
        util::display_safe(&t)
            .chars()
            .all(|c| c == '\t' || !util::is_hidden_or_control(c))
    );
    assert!(
        util::display_safe_multiline(&t)
            .chars()
            .all(|c| c == '\t' || c == '\n' || !util::is_hidden_or_control(c))
    );
    for m in ManagerId::ALL {
        let _ = managers::valid_identifier(m, a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic stand-in for the fuzzer on stable: hostile and random
    /// inputs through every entry point.
    #[test]
    fn entry_points_survive_hostile_and_random_input() {
        let mut seeds: Vec<Vec<u8>> = [
            "",
            "\0",
            "Name Id\n----\n\u{2026}\u{2026}\u{2026}",
            "* Label:\n\tTitle: , Version: , Action: restart,",
            "{\"formulae\":[{\"name\":\"--force\",\"current_version\":\"1\"}],\"casks\":[]}",
            "{\"dependencies\":{\"../x\":{\"version\":\"1\"}}}",
            "{\"minimist\":{\"current\":\"1\",\"latest\":\"2\"}}",
            "curl/noble-security 1 amd64 [upgradable from: 0]\n./evil.deb/x 2 all",
            "a|b|c|true\n|||\n",
            "{\"id\":\"<script>alert(1)</script>\",\"aliases\":[\"CVE-9999-0001\"],\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"CVSS:3.1/AV:N\"}]}",
            "{\"result\":{\"releases\":[{\"name\":\"26\",\"eolFrom\":\"2026-13-45\",\"latest\":{\"name\":\"\"}}]}}",
            "[apply]\nprotected=[\"*\"]\nmax_actions=0",
            "CVE-2024-",
            "\u{feff}\r\n\r\n",
            "Name Id Version Available\n----\nEvil\u{1b}[1A\u{1b}[2K\u{202e}`x`[a](b) Evil.App 1 2\n",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
        // xorshift: reproducible pseudo-random bytes.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for len in [1, 7, 64, 300, 2000] {
            for _ in 0..20 {
                let v: Vec<u8> = (0..len)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        (x & 0xFF) as u8
                    })
                    .collect();
                seeds.push(v);
            }
        }
        for s in &seeds {
            for sel in [0u8, 1, 2, 3, 4, 5, 6, 7, 0x83, 0xF5] {
                let mut d = vec![sel];
                d.extend_from_slice(s);
                manager_output(&d);
                research_data(&d);
                policy_and_text(&d);
            }
        }
        // The pipeline is slower (it analyses): fewer, structured inputs.
        let vuln = include_str!("../tests/fixtures/osv-GHSA-vh95-rmgr-6w4m.json");
        for s in seeds.iter().take(30) {
            let mut d = vec![2u8];
            d.extend_from_slice(s);
            d.push(0xFF);
            d.extend_from_slice(br#"{"results":[{"vulns":[{"id":"GHSA-vh95-rmgr-6w4m"}]}]}"#);
            d.push(0xFF);
            d.extend_from_slice(vuln.as_bytes());
            pipeline(&d);
        }
    }
}
