//! Exit codes of `scan` and `plan`, on saved scans (`--from`): no discovery,
//! no network, no package manager is run.

use patchscope_core::model::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn saved_scan(dir: &Path, sources: Vec<SourceStatus>, findings: Vec<Finding>) -> PathBuf {
    let scan = Scan {
        report: SystemReport {
            schema_version: SCHEMA_VERSION,
            tool_version: "test".into(),
            generated_at: "2026-10-04T00:00:00Z".into(),
            host: HostInfo::default(),
            os: OsInfo {
                family: OsFamily::Linux,
                name: "Debian GNU/Linux 13".into(),
                version: "13".into(),
                build: None,
                kernel: "6.12".into(),
                arch: "x86_64".into(),
                distro_id: Some("debian".into()),
                distro_version_id: Some("13".into()),
                edition: None,
            },
            hardware: HardwareInfo::default(),
            runtimes: Vec::new(),
            managers: Vec::new(),
            warnings: Vec::new(),
        },
        analysis: Analysis {
            schema_version: SCHEMA_VERSION,
            generated_at: "2026-10-04T00:00:00Z".into(),
            offline: false,
            sources,
            summary: Summary::default(),
            findings,
        },
    };
    let path = dir.join("scan.json");
    std::fs::write(&path, serde_json::to_string(&scan).unwrap()).unwrap();
    path
}

fn src(name: &str, ok: bool) -> SourceStatus {
    SourceStatus {
        name: name.into(),
        ok,
        detail: if ok {
            "checked".into()
        } else {
            "network unreachable".into()
        },
    }
}

fn high_finding() -> Finding {
    Finding {
        id: "update:apt:openssl".into(),
        severity: Severity::High,
        category: Category::SecurityUpdate,
        title: "openssl 3.5.1-1 → 3.5.1-2".into(),
        manager: Some(ManagerId::Apt),
        subject: "openssl".into(),
        installed_version: Some("3.5.1-1".into()),
        rationale: "security".into(),
        advisories: Vec::new(),
        remediation: None,
        risk_score: 70.0,
        references: Vec::new(),
    }
}

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let policy = dir.join("policy.toml");
    std::fs::write(&policy, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_patchscope"))
        .arg("--quiet")
        .arg("--policy")
        .arg(&policy)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn failed_research_is_not_a_clean_scan() {
    let dir = tempfile::tempdir().unwrap();
    let scan = saved_scan(
        dir.path(),
        vec![src("OSV.dev", false), src("CISA KEV", true)],
        Vec::new(),
    );
    let from = scan.to_str().unwrap();

    let (code, out) = run(dir.path(), &["scan", "--from", from, "--fail-on", "high"]);
    assert_eq!(code, 4, "OSV.dev could not be queried: {out}");
    assert!(out.contains("Research incomplete"), "{out}");
    let (code, out) = run(dir.path(), &["scan", "--from", from, "--allow-partial"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(dir.path(), &["plan", "--from", from]);
    assert_eq!(code, 4, "{out}");
    let (code, out) = run(dir.path(), &["plan", "--from", from, "--allow-partial"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn complete_research_keeps_the_old_codes() {
    let dir = tempfile::tempdir().unwrap();
    let clean = saved_scan(dir.path(), vec![src("OSV.dev", true)], Vec::new());
    let (code, out) = run(dir.path(), &["scan", "--from", clean.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("Research incomplete"), "{out}");

    let found = saved_scan(dir.path(), vec![src("OSV.dev", true)], vec![high_finding()]);
    let (code, _) = run(dir.path(), &["scan", "--from", found.to_str().unwrap()]);
    assert_eq!(code, 2);
    let (code, _) = run(
        dir.path(),
        &["scan", "--from", found.to_str().unwrap(), "--fail-on", "critical"],
    );
    assert_eq!(code, 0);
    let (code, _) = run(dir.path(), &["plan", "--from", found.to_str().unwrap()]);
    assert_eq!(code, 0);
}

#[test]
fn incomplete_research_takes_precedence_over_findings() {
    let dir = tempfile::tempdir().unwrap();
    let scan = saved_scan(dir.path(), vec![src("OSV.dev", false)], vec![high_finding()]);
    let from = scan.to_str().unwrap();
    let (code, _) = run(dir.path(), &["scan", "--from", from]);
    assert_eq!(code, 4);
    let (code, _) = run(dir.path(), &["scan", "--from", from, "--allow-partial"]);
    assert_eq!(code, 2, "with --allow-partial the findings decide");
}
