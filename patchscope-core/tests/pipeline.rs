//! End to end on recorded data: inventory → research → findings → plan →
//! apply → verify, with no network and no real package manager.

use patchscope_core::analysis::{AnalyzeOptions, analyze};
use patchscope_core::apply::{ActionStatus, ApplyEvent, ApplyOptions, apply_plan, plan_from_saved};
use patchscope_core::exec::{CommandOutput, Elevation, FakeRunner};
use patchscope_core::managers::{self, Context};
use patchscope_core::model::*;
use patchscope_core::plan::{Selection, build_plan};
use patchscope_core::policy::Policy;
use patchscope_core::report;
use patchscope_core::research::http::FakeHttp;
use patchscope_core::util::days_from_civil;
use std::time::Duration;

const OSV_MINIMIST: &str = include_str!("fixtures/osv-GHSA-vh95-rmgr-6w4m.json");
const EOL_MACOS: &str = include_str!("fixtures/eol-macos.json");

fn os_macos(version: &str) -> OsInfo {
    OsInfo {
        family: OsFamily::Macos,
        name: format!("macOS {version}"),
        version: version.into(),
        build: Some("25H1".into()),
        kernel: "25.6.0".into(),
        arch: "x86_64".into(),
        distro_id: None,
        distro_version_id: None,
        edition: None,
    }
}

/// npm with one vulnerable global package; mas offering an Xcode update
/// (protected); Homebrew with a plain outdated formula; softwareupdate with
/// a macOS point release.
fn recorded_runner() -> FakeRunner {
    FakeRunner::new()
        .respond("npm --version", CommandOutput::ok("11.6.0\n"))
        .respond(
            "npm ls --global --depth=0 --json",
            CommandOutput::ok(r#"{"dependencies":{"minimist":{"version":"1.2.0"},"npm":{"version":"11.6.0"}}}"#),
        )
        .respond(
            "npm outdated --global --json",
            CommandOutput::with_status(1, r#"{"minimist":{"current":"1.2.0","wanted":"1.2.8","latest":"1.2.8"}}"#, ""),
        )
        // After the install, npm reports nothing outdated.
        .respond("npm outdated --global --json", CommandOutput::ok("{}"))
        .respond("npm install --global --no-fund --no-audit minimist@1.2.8", CommandOutput::ok("changed 1 package\n"))
        .respond("mas --version", CommandOutput::ok("2.2.2\n"))
        .respond("mas list", CommandOutput::ok("497799835  Xcode  (26.4)\n"))
        .respond("mas outdated", CommandOutput::ok("497799835 Xcode (26.4 -> 26.6)\n"))
        .respond("brew --version", CommandOutput::ok("Homebrew 4.6.12\n"))
        .respond("brew list --formula --versions", CommandOutput::ok("jq 1.8.0\n"))
        .respond("brew list --cask --versions", CommandOutput::ok(""))
        .respond(
            "brew outdated --json=v2",
            CommandOutput::ok(r#"{"formulae":[{"name":"jq","installed_versions":["1.8.0"],"current_version":"1.8.1","pinned":false}],"casks":[]}"#),
        )
        .respond("brew upgrade --formula jq", CommandOutput::with_status(1, "", "Error: jq: download failed"))
        .respond(
            "softwareupdate --list",
            CommandOutput::ok("Software Update found the following new or updated software:\n* Label: macOS Tahoe 26.7.2-25H210\n\tTitle: macOS Tahoe 26.7.2, Version: 26.7.2, Size: 7654321KiB, Recommended: YES, Action: restart, \n"),
        )
        .respond("id -u", CommandOutput::ok("501\n"))
}

fn inventory(runner: &FakeRunner, os: &OsInfo) -> SystemReport {
    let ctx = Context::new(os.clone());
    let managers = [
        ManagerId::Softwareupdate,
        ManagerId::Homebrew,
        ManagerId::Mas,
        ManagerId::NpmGlobal,
    ]
    .into_iter()
    .map(|id| managers::inventory(managers::get(id).as_ref(), runner, &ctx))
    .collect();
    SystemReport {
        schema_version: SCHEMA_VERSION,
        tool_version: "test".into(),
        generated_at: "2026-10-03T00:00:00Z".into(),
        host: HostInfo::default(),
        os: os.clone(),
        hardware: HardwareInfo {
            disks: vec![DiskInfo {
                name: "Macintosh HD".into(),
                mount_point: "/System/Volumes/Data".into(),
                file_system: "apfs".into(),
                kind: "SSD".into(),
                total_bytes: 1_000_000_000_000,
                available_bytes: 8_000_000_000,
                removable: false,
            }],
            ..Default::default()
        },
        runtimes: Vec::new(),
        managers,
        warnings: Vec::new(),
    }
}

fn research_http(kev_cve: Option<&str>) -> FakeHttp {
    let kev = match kev_cve {
        Some(c) => format!(
            r#"{{"catalogVersion":"2026.10.02","vulnerabilities":[{{"cveID":"{c}","vulnerabilityName":"test","dueDate":"2026-10-20","knownRansomwareCampaignUse":"Known"}}]}}"#
        ),
        None => r#"{"catalogVersion":"2026.10.02","vulnerabilities":[]}"#.into(),
    };
    FakeHttp::new()
        .post_route(
            "https://api.osv.dev/v1/querybatch",
            r#"{"results":[{"vulns":[{"id":"GHSA-vh95-rmgr-6w4m"}]},{}]}"#,
        )
        .route("https://api.osv.dev/v1/vulns/GHSA-vh95-rmgr-6w4m", OSV_MINIMIST)
        .route("https://www.cisa.gov/", &kev)
        .route(
            "https://api.first.org/data/v1/epss",
            r#"{"data":[{"cve":"CVE-2020-7598","epss":"0.019310000","percentile":"0.793090000"}]}"#,
        )
        .route("https://endoflife.date/api/v1/products/macos/", EOL_MACOS)
}

fn opts() -> AnalyzeOptions {
    AnalyzeOptions {
        cache_dir: None,
        today: Some(days_from_civil(2026, 10, 3)),
        ..Default::default()
    }
}

#[test]
fn research_ranks_and_explains_findings() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    assert_eq!(report.all_updates().count(), 4);

    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    assert!(a.sources.iter().all(|s| s.ok), "{:#?}", a.sources);

    let vuln = a
        .findings
        .iter()
        .find(|f| f.category == Category::Vulnerability)
        .expect("minimist finding");
    assert_eq!(vuln.subject, "minimist");
    assert_eq!(vuln.severity, Severity::Medium, "CVSS 5.6, not in KEV, EPSS < 10%");
    assert_eq!(vuln.advisories[0].epss, Some(0.01931));
    assert_eq!(vuln.remediation.as_ref().unwrap().update_keys, ["npm-global:minimist"]);
    assert!(vuln.rationale.contains("CVE-2020-7598"), "{}", vuln.rationale);

    // The npm update is explained by the advisory, not listed twice.
    assert_eq!(a.findings.iter().filter(|f| f.subject == "minimist").count(), 1);

    let os = a
        .findings
        .iter()
        .find(|f| f.id == "update:softwareupdate:macOS Tahoe 26.7.2-25H210")
        .unwrap();
    assert_eq!(os.severity, Severity::High);
    assert!(
        a.findings
            .iter()
            .any(|f| f.id == "os:newer" && f.severity == Severity::Info)
    );
    assert!(
        !a.findings.iter().any(|f| f.id == "os:behind"),
        "Software Update already offers the point release"
    );
    let disk = a
        .findings
        .iter()
        .find(|f| f.id == "hardware:disk")
        .expect("8 GB free is below the 20 GB threshold");
    assert_eq!(disk.severity, Severity::Medium);
    let jq = a.findings.iter().find(|f| f.subject == "jq").unwrap();
    assert_eq!((jq.severity, jq.category), (Severity::Low, Category::Outdated));

    // Highest severity first.
    assert!(a.findings.windows(2).all(|w| w[0].severity >= w[1].severity));
    assert_eq!(a.summary.updates_available, 4);
    assert_eq!(a.summary.kev_advisories, 0);
}

#[test]
fn kev_listing_makes_a_vulnerability_critical() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(Some("CVE-2020-7598")), &opts(), &|_| {});
    let vuln = a
        .findings
        .iter()
        .find(|f| f.category == Category::Vulnerability)
        .unwrap();
    assert_eq!(vuln.severity, Severity::Critical);
    assert!(vuln.advisories[0].kev && vuln.advisories[0].kev_ransomware);
    assert!(vuln.rationale.contains("Known Exploited"), "{}", vuln.rationale);
    assert_eq!(a.findings[0].id, vuln.id, "the exploited vulnerability ranks first");
    assert_eq!(a.summary.kev_advisories, 1);
}

#[test]
fn unsupported_os_is_critical() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("13.7.8"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let eol = a
        .findings
        .iter()
        .find(|f| f.id == "os:eol")
        .expect("macOS 13 is past end of support");
    assert_eq!(eol.severity, Severity::Critical);
}

#[test]
fn research_degrades_when_sources_are_down() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let http = FakeHttp::new().fail("https://", "network unreachable");
    let a = analyze(&report, &http, &opts(), &|_| {});
    let osv = a.sources.iter().find(|s| s.name == "OSV.dev").unwrap();
    assert!(!osv.ok);
    // Package-manager evidence still produces findings.
    assert!(
        a.findings
            .iter()
            .any(|f| f.subject == "minimist" && f.category == Category::Outdated)
    );
    assert!(a.findings.iter().any(|f| f.id.starts_with("update:softwareupdate:")));
}

#[test]
fn offline_mode_makes_no_requests() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let http = research_http(None);
    let dir = tempfile::tempdir().unwrap();
    let o = AnalyzeOptions {
        offline: true,
        cache_dir: Some(dir.path().into()),
        ..opts()
    };
    let _ = analyze(&report, &http, &o, &|_| {});
    assert_eq!(http.request_count(), 0);
}

#[test]
fn cached_research_is_reused() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let dir = tempfile::tempdir().unwrap();
    let o = AnalyzeOptions {
        cache_dir: Some(dir.path().into()),
        cache_ttl: Duration::from_secs(3600),
        ..opts()
    };
    let http = research_http(None);
    let first = analyze(&report, &http, &o, &|_| {});
    let n = http.request_count();
    let second = analyze(&report, &http, &o, &|_| {});
    assert_eq!(http.request_count(), n, "everything came from the cache");
    assert_eq!(first.findings, second.findings);
}

#[test]
fn plan_respects_policy() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});

    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let keys: Vec<&str> = plan.actions.iter().map(|x| x.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "npm-global:minimist",
            "homebrew:jq",
            "softwareupdate:macOS Tahoe 26.7.2-25H210"
        ],
        "user-level first, OS update last"
    );
    let xcode = plan
        .excluded
        .iter()
        .find(|e| e.key == "mas:497799835")
        .expect("Xcode is protected by default");
    assert!(xcode.reason.contains("protected"));
    assert!(plan.needs_elevation(), "softwareupdate --install needs root");
    assert!(plan.restart_required());

    let mut sec = Policy::default();
    sec.apply.security_only = true;
    let plan = build_plan(&report, &a, &sec, &Selection::All);
    let keys: Vec<&str> = plan.actions.iter().map(|x| x.key.as_str()).collect();
    assert_eq!(
        keys,
        ["npm-global:minimist", "softwareupdate:macOS Tahoe 26.7.2-25H210"]
    );
    assert!(
        plan.excluded
            .iter()
            .any(|e| e.key == "homebrew:jq" && e.reason.contains("security"))
    );

    let plan = build_plan(&report, &a, &Policy::default(), &Selection::AtLeast(Severity::High));
    assert_eq!(plan.actions.len(), 1);

    let plan = build_plan(
        &report,
        &a,
        &Policy::default(),
        &Selection::Keys(vec!["homebrew:jq".into()]),
    );
    assert_eq!(plan.actions.len(), 1);
    assert_eq!(
        plan.actions[0].command,
        "HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 brew upgrade --formula jq"
    );

    let md = report::markdown(&report, Some(&a), Some(&plan));
    assert!(md.contains("## Update plan") && md.contains("minimist"));
    let html = report::html(&report, Some(&a), Some(&plan));
    assert!(html.contains("Content-Security-Policy") && !html.contains("<script"));
}

#[test]
fn option_like_identifiers_are_refused() {
    let runner = recorded_runner();
    let mut report = inventory(&runner, &os_macos("26.7.1"));
    let brew = report
        .managers
        .iter_mut()
        .find(|m| m.id == ManagerId::Homebrew)
        .unwrap();
    brew.updates[0].id = "--force".into();
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    assert!(plan.actions.iter().all(|x| !x.command.contains("--force")));
    assert!(
        plan.excluded
            .iter()
            .any(|e| e.key == "homebrew:--force" && e.reason.contains("not a valid"))
    );
}

#[test]
fn dry_run_changes_nothing() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let before = runner.calls().len();
    let dir = tempfile::tempdir().unwrap();
    let r = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: true,
            audit_log: Some(dir.path().join("audit.jsonl")),
            lock_dir: Some(dir.path().into()),
            ..Default::default()
        },
        &|_| {},
    )
    .unwrap();
    assert_eq!(runner.calls().len(), before, "a dry run runs no commands");
    assert!(r.results.iter().all(|x| x.status == ActionStatus::DryRun));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
}

/// An audit log path that cannot be opened: its parent is a file.
fn unopenable_audit_log(dir: &std::path::Path) -> std::path::PathBuf {
    std::fs::write(dir.join("not-a-directory"), "").unwrap();
    dir.join("not-a-directory").join("audit.jsonl")
}

#[test]
fn apply_refuses_to_start_without_its_audit_log() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let before = runner.calls().len();
    let dir = tempfile::tempdir().unwrap();
    let err = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: false,
            elevation: Elevation::None,
            verify: true,
            audit_log: Some(unopenable_audit_log(dir.path())),
            lock_dir: Some(dir.path().into()),
            stop_on_failure: false,
        },
        &|_| {},
    )
    .expect_err("an apply that cannot be audited must not start");
    assert!(err.to_string().contains("audit log"), "{err}");
    assert_eq!(runner.calls().len(), before, "nothing ran");
}

#[test]
fn a_dry_run_reports_an_audit_log_it_cannot_write() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let dir = tempfile::tempdir().unwrap();
    let warned = std::sync::Mutex::new(Vec::new());
    let r = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: true,
            audit_log: Some(unopenable_audit_log(dir.path())),
            lock_dir: Some(dir.path().into()),
            ..Default::default()
        },
        &|e| {
            if let ApplyEvent::Warning(w) = e {
                warned.lock().unwrap().push(w.to_string());
            }
        },
    )
    .unwrap();
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    assert!(r.warnings[0].contains("audit log"), "{}", r.warnings[0]);
    assert_eq!(*warned.lock().unwrap(), r.warnings, "shown as it happens too");
}

#[cfg(unix)]
#[test]
fn an_existing_audit_log_is_made_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.jsonl");
    std::fs::write(&audit, "").unwrap();
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
    apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: true,
            audit_log: Some(audit.clone()),
            lock_dir: Some(dir.path().into()),
            ..Default::default()
        },
        &|_| {},
    )
    .unwrap();
    assert_eq!(std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn apply_installs_verifies_and_audits() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let events = std::sync::Mutex::new(Vec::new());
    let r = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: false,
            elevation: Elevation::None,
            verify: true,
            audit_log: Some(audit.clone()),
            lock_dir: Some(dir.path().into()),
            stop_on_failure: false,
        },
        &|e| {
            if let ApplyEvent::Finished { result, .. } = e {
                events.lock().unwrap().push(result.key.clone());
            }
        },
    )
    .unwrap();

    let st: Vec<(&str, ActionStatus)> = r.results.iter().map(|x| (x.key.as_str(), x.status)).collect();
    assert_eq!(
        st,
        [
            ("npm-global:minimist", ActionStatus::Verified),
            ("homebrew:jq", ActionStatus::Failed),
            ("softwareupdate:macOS Tahoe 26.7.2-25H210", ActionStatus::Skipped),
        ]
    );
    assert!(r.results[1].output_tail.contains("download failed"));
    let m = &r.results[2].message;
    assert!(
        m.contains("root") || m.contains("Administrator"),
        "no elevation method and not elevated: {m}"
    );
    assert_eq!(events.lock().unwrap().len(), 3);
    assert!(!r.all_succeeded());
    let lock = std::fs::File::options()
        .write(true)
        .open(dir.path().join("apply.lock"))
        .unwrap();
    assert!(lock.try_lock().is_ok(), "the lock is released");

    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.lines().count() >= 3);
    assert!(log.contains("\"status\":\"verified\""), "{log}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn elevated_actions_use_the_chosen_method() {
    let runner = recorded_runner().respond(
        "/usr/bin/sudo -n -- /usr/sbin/softwareupdate --install macOS Tahoe 26.7.2-25H210",
        CommandOutput::ok("Installing…\nDone. Please restart.\n"),
    );
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(
        &report,
        &a,
        &Policy::default(),
        &Selection::Keys(vec!["softwareupdate:macOS Tahoe 26.7.2-25H210".into()]),
    );
    let dir = tempfile::tempdir().unwrap();
    let r = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: false,
            elevation: Elevation::SudoNonInteractive,
            verify: false,
            audit_log: None,
            lock_dir: Some(dir.path().into()),
            stop_on_failure: false,
        },
        &|_| {},
    )
    .unwrap();
    if cfg!(windows) {
        // Windows never wraps with sudo: it needs an elevated process.
        assert_eq!(r.results[0].status, ActionStatus::Skipped);
    } else {
        assert_eq!(r.results[0].status, ActionStatus::NeedsRestart);
        assert!(r.restart_required());
        assert!(
            runner
                .call_lines()
                .iter()
                .any(|l| l.starts_with("/usr/bin/sudo -n -- /usr/sbin/softwareupdate --install"))
        );
    }
}

#[test]
fn a_second_apply_is_refused_while_one_runs() {
    let dir = tempfile::tempdir().unwrap();
    // Another patchscope holds the operating system's lock on the file.
    let held = std::fs::File::create(dir.path().join("apply.lock")).unwrap();
    held.try_lock().unwrap();
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    let err = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: false,
            lock_dir: Some(dir.path().into()),
            audit_log: None,
            ..Default::default()
        },
        &|_| {},
    )
    .unwrap_err();
    assert!(err.to_string().contains("another patchscope apply"));
}

#[test]
fn reports_round_trip_as_json() {
    let runner = recorded_runner();
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let back: SystemReport = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    assert_eq!(back, report);
    let back: Analysis = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
    assert_eq!(back, a);
}

#[test]
fn apple_silicon_os_updates_go_to_system_settings() {
    let runner = recorded_runner();
    let mut os = os_macos("26.7.1");
    os.arch = "arm64".into();
    let report = inventory(&runner, &os);
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let plan = build_plan(&report, &a, &Policy::default(), &Selection::All);
    assert!(plan.actions.iter().all(|x| x.manager != ManagerId::Softwareupdate));
    let e = plan
        .excluded
        .iter()
        .find(|e| e.key.starts_with("softwareupdate:"))
        .unwrap();
    assert!(e.reason.contains("System Settings"), "{}", e.reason);
}

#[test]
fn an_elevated_timeout_stops_the_run() {
    let timed_out = CommandOutput {
        status: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: true,
    };
    let runner = recorded_runner().respond(
        "/usr/bin/sudo -n -- /usr/sbin/softwareupdate --install macOS Tahoe 26.7.2-25H210",
        timed_out,
    );
    let report = inventory(&runner, &os_macos("26.7.1"));
    let a = analyze(&report, &research_http(None), &opts(), &|_| {});
    let mut plan = build_plan(
        &report,
        &a,
        &Policy::default(),
        &Selection::Keys(vec![
            "softwareupdate:macOS Tahoe 26.7.2-25H210".into(),
            "npm-global:minimist".into(),
        ]),
    );
    // Put the privileged action first so something follows it.
    plan.actions.reverse();
    let dir = tempfile::tempdir().unwrap();
    let r = apply_plan(
        &plan,
        &report.os,
        &runner,
        &ApplyOptions {
            dry_run: false,
            elevation: Elevation::SudoNonInteractive,
            verify: false,
            audit_log: None,
            lock_dir: Some(dir.path().into()),
            stop_on_failure: false,
        },
        &|_| {},
    )
    .unwrap();
    if cfg!(windows) {
        return; // no sudo on Windows: the privileged action is skipped instead
    }
    assert_eq!(r.results[0].status, ActionStatus::Failed);
    assert!(
        r.results[0].message.contains("may still be running"),
        "{}",
        r.results[0].message
    );
    assert_eq!(r.results[1].status, ActionStatus::Skipped);
    assert!(
        !runner.call_lines().iter().any(|l| l.starts_with("npm install")),
        "nothing ran after it"
    );
}

// ------------------------------------------------- applying a saved scan

/// A scan saved on this machine, as `scan --save` writes it.
fn saved_scan(runner: &FakeRunner, os: &OsInfo) -> Scan {
    let report = inventory(runner, os);
    let analysis = analyze(&report, &research_http(None), &opts(), &|_| {});
    Scan { report, analysis }
}

fn saved_update<'a>(scan: &'a mut Scan, key: &str) -> &'a mut AvailableUpdate {
    scan.report
        .managers
        .iter_mut()
        .flat_map(|m| m.updates.iter_mut())
        .find(|u| u.key() == key)
        .unwrap()
}

#[test]
fn a_saved_scan_cannot_add_updates_the_machine_does_not_offer() {
    let mut scan = saved_scan(&recorded_runner(), &os_macos("26.7.1"));
    // A crafted tap formula: brew would tap attacker/evil and run its Ruby.
    let mut evil = saved_update(&mut scan, "homebrew:jq").clone();
    evil.id = "attacker/evil/git".into();
    evil.name = "git".into();
    scan.report
        .managers
        .iter_mut()
        .find(|m| m.id == ManagerId::Homebrew)
        .unwrap()
        .updates
        .push(evil);

    let live = recorded_runner();
    let (_, plan) = plan_from_saved(
        &scan,
        &os_macos("26.7.1"),
        &live,
        &Policy::default(),
        &Selection::Keys(vec!["homebrew:attacker/evil/git".into(), "homebrew:jq".into()]),
        &|_| {},
    )
    .unwrap();
    let keys: Vec<&str> = plan.actions.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys, ["homebrew:jq"]);
    assert!(plan.actions.iter().all(|a| !a.command.contains("attacker")));
    let e = plan
        .excluded
        .iter()
        .find(|e| e.key == "homebrew:attacker/evil/git")
        .expect("refused with a reason");
    assert!(e.reason.contains("no longer offered by Homebrew"), "{}", e.reason);

    // Listing a manager twice does not plan its updates twice.
    let brew = scan.report.manager(ManagerId::Homebrew).unwrap().clone();
    scan.report.managers.push(brew);
    let (_, plan) = plan_from_saved(
        &scan,
        &os_macos("26.7.1"),
        &recorded_runner(),
        &Policy::default(),
        &Selection::Keys(vec!["homebrew:jq".into()]),
        &|_| {},
    )
    .unwrap();
    assert_eq!(plan.actions.len(), 1, "{:?}", plan.actions);
}

#[test]
fn a_saved_scan_cannot_change_what_an_update_is() {
    let major = "Software Update found the following new or updated software:\n* Label: macOS Golden Gate 27.0-26A100\n\tTitle: macOS Golden Gate 27.0, Version: 27.0, Size: 17654321KiB, Recommended: YES, Action: restart, \n";
    let su = || {
        FakeRunner::new()
            .respond("softwareupdate --list", CommandOutput::ok(major))
            .respond("id -u", CommandOutput::ok("501\n"))
    };
    let key = "softwareupdate:macOS Golden Gate 27.0-26A100";
    let os = os_macos("26.7.1");
    let mut scan = saved_scan(&su(), &os);
    assert_eq!(saved_update(&mut scan, key).kind, UpdateKind::OsUpgrade);
    // Edited to look like a point release that needs no restart.
    saved_update(&mut scan, key).kind = UpdateKind::OsUpdate;
    saved_update(&mut scan, key).restart_required = false;
    let sel = Selection::Keys(vec![key.into()]);

    let (_, plan) = plan_from_saved(&scan, &os, &su(), &Policy::default(), &sel, &|_| {}).unwrap();
    assert!(plan.actions.is_empty(), "{:?}", plan.actions);
    assert!(
        plan.excluded.iter().any(|e| e.reason.contains("major OS upgrade")),
        "{:?}",
        plan.excluded
    );

    let mut policy = Policy::default();
    policy.apply.allow_os_upgrades = true;
    policy.apply.allow_restart_required = false;
    let (_, plan) = plan_from_saved(&scan, &os, &su(), &policy, &sel, &|_| {}).unwrap();
    assert!(plan.actions.is_empty(), "{:?}", plan.actions);
    assert!(
        plan.excluded.iter().any(|e| e.reason.contains("needs a restart")),
        "{:?}",
        plan.excluded
    );

    // The architecture is this machine's, not the file's.
    policy.apply.allow_restart_required = true;
    let mut arm = os.clone();
    arm.arch = "arm64".into();
    let (report, plan) = plan_from_saved(&scan, &arm, &su(), &policy, &sel, &|_| {}).unwrap();
    assert_eq!(report.os.arch, "arm64");
    assert!(plan.actions.is_empty(), "{:?}", plan.actions);
    assert!(
        plan.excluded.iter().any(|e| e.reason.contains("Apple silicon")),
        "{:?}",
        plan.excluded
    );

    // And the version installed is the one the manager offers now.
    let mut scan = saved_scan(&recorded_runner(), &os);
    saved_update(&mut scan, "npm-global:minimist").available_version = "https://evil.example/x.tgz".into();
    let (_, plan) = plan_from_saved(
        &scan,
        &os,
        &recorded_runner(),
        &Policy::default(),
        &Selection::Keys(vec!["npm-global:minimist".into()]),
        &|_| {},
    )
    .unwrap();
    assert_eq!(plan.actions.len(), 1);
    assert!(
        plan.actions[0].command.ends_with("minimist@1.2.8"),
        "{}",
        plan.actions[0].command
    );
}

#[test]
fn a_scan_from_another_machine_is_refused() {
    let scan = saved_scan(&recorded_runner(), &os_macos("26.7.1"));
    for live in [
        os_macos("26.7.2"),
        OsInfo {
            build: Some("25H2".into()),
            ..os_macos("26.7.1")
        },
        OsInfo {
            kernel: "25.7.0".into(),
            ..os_macos("26.7.1")
        },
    ] {
        let err = plan_from_saved(
            &scan,
            &live,
            &recorded_runner(),
            &Policy::default(),
            &Selection::All,
            &|_| {},
        )
        .unwrap_err();
        assert!(err.contains("scan again"), "{err}");
    }
}

#[test]
fn a_saved_pacman_selection_cannot_hide_other_pending_packages() {
    let os = OsInfo {
        family: OsFamily::Linux,
        name: "Arch Linux".into(),
        version: "rolling".into(),
        build: None,
        kernel: "6.16.1-arch1-1".into(),
        arch: "x86_64".into(),
        distro_id: Some("arch".into()),
        distro_version_id: None,
        edition: None,
    };
    let pacman = |pending: &str| {
        FakeRunner::new()
            .respond("pacman --version", CommandOutput::ok("Pacman v7.0.0\n"))
            .respond(
                "pacman -Q",
                CommandOutput::ok("firefox 142.0-1\nlinux 6.16.1.arch1-1\n"),
            )
            .respond("checkupdates", CommandOutput::ok(pending))
    };
    let ctx = Context::new(os.clone());
    let inv = managers::inventory(&managers::Pacman, &pacman("firefox 142.0-1 -> 143.0-1\n"), &ctx);
    let mut report = inventory(&FakeRunner::new(), &os);
    report.managers = vec![inv];
    let analysis = analyze(&report, &research_http(None), &opts(), &|_| {});
    let scan = Scan { report, analysis };

    // Since the scan, the kernel is pending too; -Syu would install it.
    let live = pacman("firefox 142.0-1 -> 143.0-1\nlinux 6.16.1.arch1-1 -> 6.16.2.arch1-1\n");
    let (_, plan) = plan_from_saved(
        &scan,
        &os,
        &live,
        &Policy::default(),
        &Selection::Keys(vec!["pacman:firefox".into()]),
        &|_| {},
    )
    .unwrap();
    assert!(plan.actions.is_empty(), "{:?}", plan.actions);
    let e = plan.excluded.iter().find(|e| e.key == "pacman:*").expect("explained");
    assert!(e.reason.contains("linux"), "{}", e.reason);
}
