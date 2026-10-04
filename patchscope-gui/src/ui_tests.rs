//! The app driven the way a person uses it (clicking through accessibility
//! labels), with a backend that returns recorded results.

use crate::app::{App, Tab};
use crate::backend::{Backend, Progress, ScanSettings};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use patchscope_core::apply::{ActionResult, ActionStatus, ApplyOptions, ApplyReport};
use patchscope_core::model::*;
use patchscope_core::plan::UpdatePlan;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct FakeBackend {
    applied: Mutex<Vec<(Vec<String>, bool)>>,
}

fn update(manager: ManagerId, id: &str, from: &str, to: &str, security: bool) -> AvailableUpdate {
    AvailableUpdate {
        manager,
        id: id.into(),
        name: id.into(),
        installed_version: Some(from.into()),
        available_version: to.into(),
        kind: UpdateKind::Package,
        security,
        restart_required: false,
        notes: None,
    }
}

fn finding(id: &str, sev: Severity, title: &str, key: &str) -> Finding {
    Finding {
        id: id.into(),
        severity: sev,
        category: if sev >= Severity::High {
            Category::Vulnerability
        } else {
            Category::Outdated
        },
        title: title.into(),
        manager: None,
        subject: title.into(),
        installed_version: None,
        rationale: format!("because of {title}"),
        advisories: Vec::new(),
        remediation: Some(Remediation {
            update_keys: vec![key.into()],
            to_version: "x".into(),
            summary: format!("Update {title}"),
        }),
        risk_score: 50.0,
        references: Vec::new(),
    }
}

pub fn recorded_scan() -> Scan {
    let npm = ManagerInventory {
        id: ManagerId::NpmGlobal,
        available: true,
        version: Some("11.6.0".into()),
        installed: vec![Package {
            manager: ManagerId::NpmGlobal,
            name: "minimist".into(),
            version: "1.2.0".into(),
            source_name: None,
            source_version: None,
            ecosystem: Some("npm".into()),
        }],
        updates: vec![
            update(ManagerId::NpmGlobal, "minimist", "1.2.0", "1.2.8", false),
            update(ManagerId::NpmGlobal, "left-pad", "1.0.0", "1.3.0", false),
        ],
        error: None,
    };
    let report = SystemReport {
        schema_version: SCHEMA_VERSION,
        tool_version: "test".into(),
        generated_at: "2026-10-03T12:00:00Z".into(),
        host: HostInfo::default(),
        os: OsInfo {
            family: OsFamily::current(),
            name: "Test OS 1.0".into(),
            version: "1.0".into(),
            build: None,
            kernel: "1".into(),
            arch: "x86_64".into(),
            distro_id: None,
            distro_version_id: None,
            edition: None,
        },
        hardware: HardwareInfo {
            model: Some("Test Machine".into()),
            disks: vec![DiskInfo {
                name: "disk".into(),
                mount_point: "/".into(),
                file_system: "apfs".into(),
                kind: "SSD".into(),
                total_bytes: 500_000_000_000,
                available_bytes: 200_000_000_000,
                removable: false,
            }],
            ..Default::default()
        },
        runtimes: Vec::new(),
        managers: vec![npm],
        warnings: Vec::new(),
    };
    let findings = vec![
        finding(
            "vuln:npm-global:minimist",
            Severity::Critical,
            "minimist: Prototype Pollution",
            "npm-global:minimist",
        ),
        finding(
            "update:npm-global:left-pad",
            Severity::Low,
            "left-pad 1.0.0 → 1.3.0",
            "npm-global:left-pad",
        ),
    ];
    Scan {
        report,
        analysis: Analysis {
            schema_version: SCHEMA_VERSION,
            generated_at: "2026-10-03T12:00:01Z".into(),
            offline: false,
            sources: vec![SourceStatus {
                name: "OSV.dev".into(),
                ok: true,
                detail: "1 package checked".into(),
            }],
            summary: Summary {
                critical: 1,
                low: 1,
                updates_available: 2,
                ..Default::default()
            },
            findings,
        },
    }
}

impl Backend for FakeBackend {
    fn scan(&self, _s: &ScanSettings, progress: Progress) -> Result<Scan, String> {
        progress("Querying npm (global)…");
        Ok(recorded_scan())
    }
    fn apply(
        &self,
        plan: &UpdatePlan,
        _os: &OsInfo,
        opts: &ApplyOptions,
        progress: Progress,
    ) -> Result<ApplyReport, String> {
        self.applied
            .lock()
            .unwrap()
            .push((plan.actions.iter().map(|a| a.key.clone()).collect(), opts.dry_run));
        let results = plan
            .actions
            .iter()
            .map(|a| {
                progress(&format!("installing {}", a.title));
                ActionResult {
                    key: a.key.clone(),
                    title: a.title.clone(),
                    command: a.command.clone(),
                    status: if opts.dry_run {
                        ActionStatus::DryRun
                    } else {
                        ActionStatus::Verified
                    },
                    exit_code: Some(0),
                    duration_ms: 1,
                    message: "ok".into(),
                    output_tail: String::new(),
                }
            })
            .collect();
        Ok(ApplyReport {
            started_at: "s".into(),
            finished_at: "f".into(),
            dry_run: opts.dry_run,
            results,
            warnings: Vec::new(),
        })
    }
}

fn harness(backend: Arc<FakeBackend>, dir: &std::path::Path) -> Harness<'static, App> {
    let policy = dir.join("patchscope.toml");
    let export = dir.to_path_buf();
    Harness::builder()
        .with_size(egui::Vec2::new(1100.0, 800.0))
        .build_eframe(move |_cc| App::new(backend, Some(policy)).with_export_dir(export))
}

use eframe::egui;

/// Step the app until the background work finishes.
fn settle(h: &mut Harness<'static, App>) {
    for _ in 0..500 {
        h.step();
        if h.state().busy.is_none() {
            h.run_steps(3);
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("background work did not finish");
}

#[test]
fn welcome_scan_review_and_install() {
    let dir = tempfile_dir();
    let backend = Arc::new(FakeBackend::default());
    let mut h = harness(Arc::clone(&backend), dir.path());
    h.run_steps(2);

    // Welcome screen, nothing scanned.
    h.get_by_label("Scan this computer");
    assert!(h.state().scan.is_none());

    h.get_by_label("Scan this computer").click();
    h.run_steps(1);
    settle(&mut h);
    assert!(h.state().scan.is_some());
    assert_eq!(h.state().selected.len(), 2, "all allowed updates start ticked");
    h.get_by_label_contains("minimist: Prototype Pollution");

    // Findings tab lists both findings.
    h.get_by_label("Findings  1").click();
    h.run_steps(2);
    assert_eq!(h.state().tab, Tab::Findings);
    h.get_by_label_contains("left-pad 1.0.0");

    // Updates: keep only critical & high, then install.
    h.get_by_label("Updates  2").click();
    h.run_steps(2);
    h.get_by_label("Critical & high only").click();
    h.run_steps(2);
    assert_eq!(h.state().selected.iter().collect::<Vec<_>>(), ["npm-global:minimist"]);
    h.get_by_label("Install selected (1)").click();
    h.run_steps(2);
    assert!(h.state().confirm_open, "installing asks first");
    h.get_by_label("Install now").click();
    h.run_steps(1);
    settle(&mut h);

    let applied = backend.applied.lock().unwrap().clone();
    assert_eq!(applied, vec![(vec!["npm-global:minimist".to_string()], false)]);
    assert_eq!(h.state().tab, Tab::Activity);
    let r = h.state().last_apply.clone().unwrap();
    assert_eq!(r.results[0].status, ActionStatus::Verified);
    h.get_by_label("verified");
}

#[test]
fn cancel_installs_nothing_and_dry_run_is_labelled() {
    let dir = tempfile_dir();
    let backend = Arc::new(FakeBackend::default());
    let mut h = harness(Arc::clone(&backend), dir.path());
    h.run_steps(2);
    h.get_by_label("Scan this computer").click();
    h.run_steps(1);
    settle(&mut h);
    h.get_by_label("Updates  2").click();
    h.run_steps(2);

    h.get_by_label("Install selected (2)").click();
    h.run_steps(2);
    h.get_by_label("Cancel").click();
    h.run_steps(2);
    assert!(!h.state().confirm_open);
    assert!(backend.applied.lock().unwrap().is_empty());

    h.get_by_label("Dry run (show the commands, change nothing)").click();
    h.run_steps(2);
    h.get_by_label("Dry run selected (2)").click();
    h.run_steps(2);
    h.get_by_label("Run dry run").click();
    h.run_steps(1);
    settle(&mut h);
    assert!(
        backend.applied.lock().unwrap()[0].1,
        "the backend was asked for a dry run"
    );
}

#[test]
fn nothing_selected_means_nothing_to_install() {
    let dir = tempfile_dir();
    let mut h = harness(Arc::new(FakeBackend::default()), dir.path());
    h.run_steps(2);
    h.get_by_label("Scan this computer").click();
    h.run_steps(1);
    settle(&mut h);
    h.state_mut().tab = Tab::Updates;
    h.run_steps(2);
    h.get_by_label("Select none").click();
    h.run_steps(2);
    assert!(h.state().selected.is_empty());
    h.get_by_label("Install selected (0)").click();
    h.run_steps(2);
    assert!(!h.state().confirm_open, "the button is disabled with nothing ticked");
}

#[test]
fn policy_is_validated_before_saving() {
    let dir = tempfile_dir();
    let mut h = harness(Arc::new(FakeBackend::default()), dir.path());
    h.run_steps(2);
    let path = dir.path().join("patchscope.toml");

    // A typo is refused and nothing is written.
    h.state_mut().tab = Tab::Settings;
    h.run_steps(2);
    {
        let app = h.state_mut();
        app.scan = Some(recorded_scan());
        set_policy_text(app, "[apply]\nallow_os_upgrade = true\n");
        app.save_policy();
    }
    assert!(!path.exists());

    // A valid policy is written and re-plans: protecting left-pad drops it.
    {
        let app = h.state_mut();
        set_policy_text(app, "[apply]\nprotected = [\"left-pad\"]\n");
        app.save_policy();
    }
    assert!(path.exists());
    let app = h.state();
    let plan = app.plan.as_ref().unwrap();
    assert_eq!(plan.actions.len(), 1);
    assert!(plan.excluded.iter().any(|e| e.key == "npm-global:left-pad"));
}

#[test]
fn a_broken_policy_file_blocks_installing() {
    // The CLI refuses to run with a malformed policy; the app must not fall
    // back to the defaults and offer to install everything instead.
    let dir = tempfile_dir();
    std::fs::write(dir.path().join("patchscope.toml"), "[apply]\nallow_os_upgrade = true\n").unwrap();
    let backend = Arc::new(FakeBackend::default());
    let mut h = harness(Arc::clone(&backend), dir.path());
    h.run_steps(2);
    h.get_by_label("Scan this computer").click();
    h.run_steps(1);
    settle(&mut h);
    assert!(h.state().selected.is_empty(), "nothing is pre-selected");

    h.get_by_label("Updates  0").click();
    h.run_steps(2);
    h.get_by_label_contains("allow_os_upgrade");
    h.get_by_label("Select all").click();
    h.run_steps(2);
    h.get_by_label("Install selected (2)").click();
    h.run_steps(2);
    assert!(!h.state().confirm_open, "Install is disabled");
    // Even if the dialog is reached, Install does nothing.
    h.state_mut().confirm_open = true;
    h.run_steps(2);
    assert!(
        h.query_all_by_label_contains("allow_os_upgrade").count() >= 2,
        "the error is in the dialog too"
    );
    h.get_by_label("Install now").click();
    h.run_steps(2);
    assert!(h.state().busy.is_none() && backend.applied.lock().unwrap().is_empty());
    h.state_mut().confirm_open = false;
    h.run_steps(2);

    // A dry run is still allowed.
    h.get_by_label("Dry run (show the commands, change nothing)").click();
    h.run_steps(2);
    h.get_by_label("Dry run selected (2)").click();
    h.run_steps(2);
    h.get_by_label("Run dry run").click();
    h.run_steps(1);
    settle(&mut h);
    assert_eq!(
        backend.applied.lock().unwrap().clone(),
        vec![(
            vec!["npm-global:minimist".to_string(), "npm-global:left-pad".to_string()],
            true
        )]
    );

    // Saving a valid policy clears the block.
    {
        let app = h.state_mut();
        set_policy_text(app, "[apply]\n");
        app.save_policy();
        app.tab = Tab::Updates;
        app.dry_run = false;
    }
    h.run_steps(2);
    assert_eq!(h.state().selected.len(), 2);
    h.get_by_label("Install selected (2)").click();
    h.run_steps(2);
    assert!(h.state().confirm_open);
}

#[test]
fn every_tab_renders_with_and_without_a_scan() {
    let dir = tempfile_dir();
    let mut h = harness(Arc::new(FakeBackend::default()), dir.path());
    for with_scan in [false, true] {
        if with_scan {
            h.state_mut().scan = Some(recorded_scan());
        }
        for t in [
            "Overview", "Findings", "Updates", "Activity", "Hardware", "Software", "Settings",
        ] {
            let tab = match t {
                "Overview" => Tab::Overview,
                "Findings" => Tab::Findings,
                "Updates" => Tab::Updates,
                "Activity" => Tab::Activity,
                "Hardware" => Tab::Hardware,
                "Software" => Tab::Software,
                _ => Tab::Settings,
            };
            h.state_mut().tab = tab;
            h.run_steps(2);
        }
    }
    h.state_mut().tab = Tab::Hardware;
    h.run_steps(2);
    h.get_by_label("Test Machine");
}

#[test]
fn export_writes_reports() {
    let dir = tempfile_dir();
    let mut h = harness(Arc::new(FakeBackend::default()), dir.path());
    h.run_steps(2);
    h.get_by_label("Scan this computer").click();
    h.run_steps(1);
    settle(&mut h);
    h.get_by_label("Export report").click();
    h.run_steps(2);
    h.get_by_label("HTML page").click();
    h.run_steps(2);
    let html: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".html"))
        .collect();
    assert_eq!(html.len(), 1);
    let body = std::fs::read_to_string(html[0].path()).unwrap();
    assert!(body.contains("minimist: Prototype Pollution"));
}

fn set_policy_text(app: &mut App, text: &str) {
    app.set_policy_text_for_test(text);
}

fn tempfile_dir() -> TempDir {
    TempDir::new()
}

/// A scratch directory removed on drop (keeps the GUI crate free of a
/// tempfile dependency just for tests).
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        // The clock alone can repeat between tests started together (macOS
        // reports microseconds), so a counter keeps each directory apart.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "patchscope-gui-test-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn overview_says_when_research_is_incomplete() {
    let dir = tempfile_dir();
    let mut h = harness(Arc::new(FakeBackend::default()), dir.path());
    h.state_mut().scan = Some(recorded_scan());
    h.run_steps(2);
    assert!(h.query_by_label_contains("Research incomplete").is_none());

    let mut scan = recorded_scan();
    scan.analysis.sources[0].ok = false;
    h.state_mut().scan = Some(scan);
    h.run_steps(2);
    h.get_by_label_contains("Research incomplete: OSV.dev");
}
