//! The patchscope desktop app.

use crate::backend::{Backend, ScanSettings};
use eframe::egui::{self, Color32, RichText};
use patchscope_core::apply::{ActionStatus, ApplyOptions, ApplyReport};
use patchscope_core::exec::Elevation;
use patchscope_core::model::{Finding, OsFamily, Scan, Severity};
use patchscope_core::plan::{Selection, UpdatePlan, build_plan};
use patchscope_core::policy::Policy;
use patchscope_core::util::{display_safe as safe, display_safe_multiline as safe_multiline};
use patchscope_core::{paths, report, util};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Findings,
    Updates,
    Activity,
    Hardware,
    Software,
    Settings,
}

impl Tab {
    const ALL: [Tab; 7] = [
        Tab::Overview,
        Tab::Findings,
        Tab::Updates,
        Tab::Activity,
        Tab::Hardware,
        Tab::Software,
        Tab::Settings,
    ];
    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Findings => "Findings",
            Tab::Updates => "Updates",
            Tab::Activity => "Activity",
            Tab::Hardware => "Hardware",
            Tab::Software => "Software",
            Tab::Settings => "Settings",
        }
    }
}

enum Msg {
    Progress(String),
    Scanned(Box<Result<Scan, String>>),
    Applied(Result<ApplyReport, String>),
}

fn policy_error_text(e: &str) -> String {
    format!(
        "The policy file could not be loaded, so installing is off (dry runs still work). Fix it in Settings and save. {}",
        safe_multiline(e)
    )
}

/// Shown under a command whose display differs from what will run, as the
/// CLI does.
const ESCAPED_NOTE: &str = "(hidden or control characters shown as \\u{..}, backslashes doubled)";

/// A planned command as shown in the app: text from package managers and
/// scan files may hold characters egui draws as nothing (bidi overrides,
/// zero-width characters), so they are shown as escapes and flagged.
fn command_label(ui: &mut egui::Ui, prefix: &str, command: &str, text: impl Fn(String) -> RichText) {
    let shown = safe(command);
    let escaped = shown != command;
    ui.label(text(format!("{prefix}{shown}")));
    if escaped {
        ui.label(
            RichText::new(ESCAPED_NOTE)
                .small()
                .color(severity_color(Severity::High, ui.visuals().dark_mode)),
        );
    }
}

pub fn severity_color(s: Severity, dark: bool) -> Color32 {
    match (s, dark) {
        (Severity::Critical, false) => Color32::from_rgb(185, 28, 28),
        (Severity::Critical, true) => Color32::from_rgb(248, 113, 113),
        (Severity::High, false) => Color32::from_rgb(194, 65, 12),
        (Severity::High, true) => Color32::from_rgb(251, 146, 60),
        (Severity::Medium, false) => Color32::from_rgb(161, 98, 7),
        (Severity::Medium, true) => Color32::from_rgb(250, 204, 21),
        (Severity::Low, false) => Color32::from_rgb(29, 78, 216),
        (Severity::Low, true) => Color32::from_rgb(96, 165, 250),
        (Severity::Info, _) => Color32::GRAY,
    }
}

pub struct App {
    backend: Arc<dyn Backend>,
    pub tab: Tab,
    pub scan: Option<Scan>,
    pub plan: Option<UpdatePlan>,
    /// Keys of the plan actions the person has ticked.
    pub selected: BTreeSet<String>,
    pub policy: Policy,
    policy_path: Option<PathBuf>,
    policy_text: String,
    policy_msg: Option<(bool, String)>,
    /// The policy file did not load. Like the CLI, the app then installs
    /// nothing (dry runs still work) until a valid policy is saved.
    policy_error: Option<String>,
    pub settings: ScanSettings,
    pub elevation: Elevation,
    pub dry_run: bool,
    /// Status while a scan or apply runs.
    pub busy: Option<String>,
    pub log: Vec<String>,
    rx: Option<Receiver<Msg>>,
    pub last_apply: Option<ApplyReport>,
    pub confirm_open: bool,
    pub error: Option<String>,
    notice: Option<String>,
    finding_filter: String,
    min_severity: Severity,
    package_filter: String,
    export_dir: Option<PathBuf>,
}

impl App {
    pub fn new(backend: Arc<dyn Backend>, policy_path: Option<PathBuf>) -> Self {
        let (policy, policy_error) = match &policy_path {
            Some(p) => match Policy::load(p) {
                Ok(pol) => (pol, None),
                Err(e) => (Policy::default(), Some(e.to_string())),
            },
            None => (Policy::default(), None),
        };
        let policy_msg = policy_error
            .as_ref()
            .map(|e| (false, format!("{e}; installing is off until a valid policy is saved")));
        let export_dir =
            directories::UserDirs::new().and_then(|u| u.download_dir().or(u.document_dir()).map(|d| d.to_path_buf()));
        App {
            backend,
            tab: Tab::Overview,
            scan: None,
            plan: None,
            selected: BTreeSet::new(),
            policy_text: policy.to_toml(),
            policy,
            policy_path,
            policy_msg,
            policy_error,
            settings: ScanSettings::default(),
            elevation: Elevation::default_for(true),
            dry_run: false,
            busy: None,
            log: Vec::new(),
            rx: None,
            last_apply: None,
            confirm_open: false,
            error: None,
            notice: None,
            finding_filter: String::new(),
            min_severity: Severity::Info,
            package_filter: String::new(),
            export_dir,
        }
    }

    #[cfg(test)]
    pub fn with_export_dir(mut self, dir: PathBuf) -> Self {
        self.export_dir = Some(dir);
        self
    }

    // ------------------------------------------------------------- actions

    pub fn start_scan(&mut self, ctx: &egui::Context) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some("Starting scan…".into());
        self.error = None;
        self.log.push(format!("— Scan started {}", util::now_rfc3339()));
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        let backend = Arc::clone(&self.backend);
        let settings = self.settings.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let tx_p = std::sync::Mutex::new(tx.clone());
            let ctx_p = ctx.clone();
            let progress = move |m: &str| {
                let _ = tx_p.lock().map(|t| t.send(Msg::Progress(m.to_string())));
                ctx_p.request_repaint();
            };
            let r = backend.scan(&settings, &progress);
            let _ = tx.send(Msg::Scanned(Box::new(r)));
            ctx.request_repaint();
        });
    }

    /// The plan restricted to the ticked actions.
    pub fn selected_plan(&self) -> Option<UpdatePlan> {
        let plan = self.plan.as_ref()?;
        Some(UpdatePlan {
            generated_at: plan.generated_at.clone(),
            actions: plan
                .actions
                .iter()
                .filter(|a| self.selected.contains(&a.key))
                .cloned()
                .collect(),
            excluded: Vec::new(),
        })
    }

    pub fn start_apply(&mut self, ctx: &egui::Context) {
        let (Some(plan), Some(scan)) = (self.selected_plan(), self.scan.as_ref()) else {
            return;
        };
        if plan.is_empty() || self.busy.is_some() || (!self.dry_run && self.policy_error.is_some()) {
            return;
        }
        self.confirm_open = false;
        self.busy = Some(if self.dry_run {
            "Dry run…".into()
        } else {
            "Installing updates…".into()
        });
        self.tab = Tab::Activity;
        self.log.push(format!(
            "— {} {} update(s) {}",
            if self.dry_run { "Dry run of" } else { "Installing" },
            plan.actions.len(),
            util::now_rfc3339()
        ));
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        let backend = Arc::clone(&self.backend);
        let os = scan.report.os.clone();
        let opts = ApplyOptions {
            dry_run: self.dry_run,
            elevation: self.elevation,
            ..Default::default()
        };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let tx_p = std::sync::Mutex::new(tx.clone());
            let ctx_p = ctx.clone();
            let progress = move |m: &str| {
                let _ = tx_p.lock().map(|t| t.send(Msg::Progress(m.to_string())));
                ctx_p.request_repaint();
            };
            let r = backend.apply(&plan, &os, &opts, &progress);
            let _ = tx.send(Msg::Applied(r));
            ctx.request_repaint();
        });
    }

    fn rebuild_plan(&mut self) {
        if let Some(scan) = &self.scan {
            let plan = build_plan(&scan.report, &scan.analysis, &self.policy, &Selection::All);
            self.selected = if self.policy_error.is_some() {
                BTreeSet::new()
            } else {
                plan.actions.iter().map(|a| a.key.clone()).collect()
            };
            self.plan = Some(plan);
        }
    }

    fn fail(&mut self, e: String) {
        self.log.push(format!("Error: {e}"));
        self.error = Some(e);
    }

    /// Drain messages from the worker thread.
    pub fn poll(&mut self) {
        let Some(rx) = self.rx.take() else { return };
        let mut done = false;
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Progress(p) => {
                    self.busy = Some(p.clone());
                    self.log.push(p);
                }
                Msg::Scanned(r) => {
                    match *r {
                        Ok(scan) => {
                            self.log.push(format!(
                                "Scan complete: {} findings, {} updates available",
                                scan.analysis.findings.len(),
                                scan.analysis.summary.updates_available
                            ));
                            self.scan = Some(scan);
                            self.rebuild_plan();
                        }
                        Err(e) => self.fail(e),
                    }
                    done = true;
                }
                Msg::Applied(Err(e)) => {
                    self.fail(e);
                    done = true;
                }
                Msg::Applied(Ok(r)) => {
                    self.log.push(format!(
                        "Finished: {} verified, {} installed, {} need a restart, {} failed, {} skipped",
                        r.count(ActionStatus::Verified),
                        r.count(ActionStatus::Installed),
                        r.count(ActionStatus::NeedsRestart),
                        r.count(ActionStatus::Failed),
                        r.count(ActionStatus::Skipped)
                    ));
                    self.last_apply = Some(r);
                    done = true;
                }
            }
        }
        if done {
            self.busy = None;
        } else {
            self.rx = Some(rx);
        }
    }

    fn export(&mut self, kind: &str) {
        let Some(scan) = &self.scan else { return };
        let Some(dir) = &self.export_dir else {
            self.notice = Some("No Downloads or Documents folder to save into.".into());
            return;
        };
        let stamp = util::now_rfc3339()
            .replace([':', '-'], "")
            .replace('T', "-")
            .trim_end_matches('Z')
            .to_string();
        let (ext, body) = match kind {
            "html" => (
                "html",
                report::html(&scan.report, Some(&scan.analysis), self.plan.as_ref()),
            ),
            "md" => (
                "md",
                report::markdown(&scan.report, Some(&scan.analysis), self.plan.as_ref()),
            ),
            _ => ("json", serde_json::to_string_pretty(scan).unwrap_or_default()),
        };
        let path = dir.join(format!("patchscope-report-{stamp}.{ext}"));
        self.notice = Some(match std::fs::write(&path, body) {
            Ok(()) => format!("Saved {}", path.display()),
            Err(e) => format!("Could not save {}: {e}", path.display()),
        });
    }

    // ------------------------------------------------------------------ UI

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("patchscope").strong());
            ui.label(RichText::new(format!("v{}", patchscope_core::VERSION)).weak());
            ui.separator();
            let scanning = self.busy.is_some();
            let label = if self.scan.is_some() { "Scan again" } else { "Scan now" };
            if ui.add_enabled(!scanning, egui::Button::new(label)).clicked() {
                self.start_scan(ui.ctx());
            }
            if let Some(b) = &self.busy {
                ui.spinner();
                ui.label(safe(b));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_enabled_ui(self.scan.is_some(), |ui| {
                    ui.menu_button("Export report", |ui| {
                        if ui.button("HTML page").clicked() {
                            self.export("html");
                            ui.close();
                        }
                        if ui.button("Markdown").clicked() {
                            self.export("md");
                            ui.close();
                        }
                        if ui.button("JSON (full scan)").clicked() {
                            self.export("json");
                            ui.close();
                        }
                    });
                });
            });
        });
        if let Some(e) = self.error.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(
                    severity_color(Severity::Critical, ui.visuals().dark_mode),
                    format!("⚠ {}", safe_multiline(&e)),
                );
                if ui.small_button("Dismiss").clicked() {
                    self.error = None;
                }
            });
        }
        if let Some(n) = self.notice.clone() {
            ui.horizontal(|ui| {
                ui.label(safe(&n));
                if ui.small_button("OK").clicked() {
                    self.notice = None;
                }
            });
        }
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        for t in Tab::ALL {
            let badge = match (t, &self.scan) {
                (Tab::Findings, Some(s)) => {
                    let n = s.analysis.summary.critical + s.analysis.summary.high;
                    (n > 0).then(|| format!("  {n}"))
                }
                (Tab::Updates, Some(_)) => Some(format!("  {}", self.selected.len())),
                _ => None,
            };
            let text = format!("{}{}", t.label(), badge.unwrap_or_default());
            if ui.selectable_label(self.tab == t, text).clicked() {
                self.tab = t;
            }
        }
    }

    fn sev_chip(ui: &mut egui::Ui, s: Severity) {
        let c = severity_color(s, ui.visuals().dark_mode);
        ui.label(RichText::new(s.as_str().to_uppercase()).color(c).strong().small());
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let Some(scan) = &self.scan else {
            ui.add_space(24.0);
            ui.heading("Welcome to patchscope");
            ui.add_space(8.0);
            ui.label(
                "patchscope looks at this computer's operating system, hardware and installed software, checks them \
against public vulnerability and support-lifecycle data, and tells you what needs updating and why. You choose \
which updates to install; nothing changes until you confirm.",
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Sources: OSV.dev · CISA Known Exploited Vulnerabilities · FIRST EPSS · endoflife.date")
                    .weak(),
            );
            ui.label(
                RichText::new("Serial numbers, hostname and MAC addresses are left out of reports unless you turn them on in Settings.")
                    .weak(),
            );
            ui.add_space(16.0);
            let enabled = self.busy.is_none();
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(RichText::new("Scan this computer").size(18.0)),
                )
                .clicked()
            {
                self.start_scan(ui.ctx());
            }
            return;
        };
        let s = &scan.analysis.summary;
        let dark = ui.visuals().dark_mode;
        ui.heading(safe(&scan.report.os.name));
        ui.label(RichText::new(format!("Scanned {}", safe(&scan.report.generated_at))).weak());
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for sev in Severity::DESCENDING {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_width(96.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(s.count(sev).to_string())
                                .size(26.0)
                                .strong()
                                .color(severity_color(sev, dark)),
                        );
                        ui.label(sev.as_str());
                    });
                });
            }
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_width(140.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(s.updates_available.to_string()).size(26.0).strong());
                    ui.label(format!("updates ({} security)", s.security_updates));
                });
            });
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_width(140.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(s.kev_advisories.to_string()).size(26.0).strong().color(
                        if s.kev_advisories > 0 {
                            severity_color(Severity::Critical, dark)
                        } else {
                            ui.visuals().text_color()
                        },
                    ));
                    ui.label("actively exploited");
                });
            });
        });
        for note in report::research_notes(&scan.analysis) {
            ui.add_space(8.0);
            ui.colored_label(severity_color(Severity::High, dark), format!("⚠ {}", safe(&note)));
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Review updates →").clicked() {
                self.tab = Tab::Updates;
            }
            if ui.button("See all findings →").clicked() {
                self.tab = Tab::Findings;
            }
        });
        ui.add_space(12.0);
        ui.strong("Most important");
        let top: Vec<Finding> = scan.analysis.findings.iter().take(6).cloned().collect();
        if top.is_empty() {
            ui.label("Nothing needs attention. 🎉");
        }
        for f in &top {
            ui.horizontal_wrapped(|ui| {
                Self::sev_chip(ui, f.severity);
                ui.label(safe(&f.title));
            });
        }
        ui.add_space(12.0);
        ui.strong("Research sources");
        for src in &scan.analysis.sources {
            ui.horizontal_wrapped(|ui| {
                ui.label(if src.ok { "✔" } else { "✖" });
                ui.label(RichText::new(safe(&src.name)).strong());
                ui.label(safe(&src.detail));
            });
        }
        if !scan.report.warnings.is_empty() {
            ui.add_space(8.0);
            egui::CollapsingHeader::new(format!("Discovery notes ({})", scan.report.warnings.len()))
                .id_salt("warnings")
                .show(ui, |ui| {
                    for w in &scan.report.warnings {
                        ui.label(safe_multiline(w));
                    }
                });
        }
    }

    fn findings(&mut self, ui: &mut egui::Ui) {
        let Some(scan) = &self.scan else {
            ui.label("Run a scan to see findings.");
            return;
        };
        ui.horizontal(|ui| {
            ui.label("Search");
            ui.add(
                egui::TextEdit::singleline(&mut self.finding_filter)
                    .hint_text("package, CVE, text…")
                    .desired_width(220.0),
            );
            egui::ComboBox::from_label("minimum severity")
                .selected_text(self.min_severity.as_str())
                .show_ui(ui, |ui| {
                    for s in Severity::DESCENDING {
                        ui.selectable_value(&mut self.min_severity, s, s.as_str());
                    }
                });
        });
        ui.separator();
        let q = self.finding_filter.to_lowercase();
        let dark = ui.visuals().dark_mode;
        let mut shown = 0;
        for f in scan
            .analysis
            .findings
            .iter()
            .filter(|f| f.severity >= self.min_severity)
        {
            let hay = format!(
                "{} {} {} {}",
                f.title,
                f.subject,
                f.rationale,
                f.advisories.iter().flat_map(|a| a.cves()).collect::<Vec<_>>().join(" ")
            )
            .to_lowercase();
            if !q.is_empty() && !hay.contains(&q) {
                continue;
            }
            shown += 1;
            let header = RichText::new(format!("{}  {}", f.severity.as_str().to_uppercase(), safe(&f.title)))
                .color(severity_color(f.severity, dark));
            egui::CollapsingHeader::new(header).id_salt(&f.id).show(ui, |ui| {
                ui.label(RichText::new(format!("{} · {}", f.category.label(), safe(&f.subject))).weak());
                ui.label(safe_multiline(&f.rationale));
                if let Some(r) = &f.remediation {
                    ui.label(RichText::new(format!("Fix: {}", safe(&r.summary))).strong());
                }
                if !f.advisories.is_empty() {
                    egui::Grid::new(format!("adv-{}", f.id))
                        .striped(true)
                        .num_columns(4)
                        .show(ui, |ui| {
                            ui.strong("Advisory");
                            ui.strong("Score");
                            ui.strong("Exploitation");
                            ui.strong("Fixed in");
                            ui.end_row();
                            for a in f.advisories.iter().take(50) {
                                ui.vertical(|ui| {
                                    ui.hyperlink_to(safe(&a.id), &a.url);
                                    let cves = a.cves().join(", ");
                                    if !cves.is_empty() && cves != a.id {
                                        ui.label(RichText::new(safe(&cves)).small());
                                    }
                                });
                                ui.label(
                                    a.cvss_score
                                        .map(|c| format!("CVSS {c:.1}"))
                                        .or_else(|| a.database_severity.as_deref().map(safe))
                                        .unwrap_or_else(|| "—".into()),
                                );
                                let mut ex = Vec::new();
                                if a.kev {
                                    ex.push("CISA KEV".to_string());
                                }
                                if let Some(e) = a.epss {
                                    ex.push(format!("EPSS {:.1}%", e * 100.0));
                                }
                                ui.label(if ex.is_empty() { "—".into() } else { ex.join(" · ") });
                                ui.label(safe(&a.fixed_versions.join(", ")));
                                ui.end_row();
                            }
                        });
                    if f.advisories.len() > 50 {
                        ui.label(format!("…and {} more", f.advisories.len() - 50));
                    }
                }
                for r in &f.references {
                    ui.hyperlink_to(safe(r), r);
                }
            });
        }
        if shown == 0 {
            ui.label("No findings match.");
        }
    }

    fn updates(&mut self, ui: &mut egui::Ui) {
        let Some(plan) = self.plan.clone() else {
            ui.label("Run a scan to see available updates.");
            return;
        };
        let dark = ui.visuals().dark_mode;
        if let Some(e) = &self.policy_error {
            ui.colored_label(severity_color(Severity::Critical, dark), policy_error_text(e));
        }
        ui.label("Tick the updates to install. Commands run through the system's own package managers; nothing runs until you confirm.");
        ui.horizontal(|ui| {
            if ui.button("Select all").clicked() {
                self.selected = plan.actions.iter().map(|a| a.key.clone()).collect();
            }
            if ui.button("Critical & high only").clicked() {
                self.selected = plan
                    .actions
                    .iter()
                    .filter(|a| a.severity >= Severity::High)
                    .map(|a| a.key.clone())
                    .collect();
            }
            if ui.button("Select none").clicked() {
                self.selected.clear();
            }
        });
        ui.separator();
        if plan.actions.is_empty() {
            ui.label("Nothing to install: everything the policy allows is up to date.");
        }
        for a in &plan.actions {
            ui.horizontal_wrapped(|ui| {
                let mut on = self.selected.contains(&a.key);
                if ui.checkbox(&mut on, "").on_hover_text(safe(&a.key)).changed() {
                    if on {
                        self.selected.insert(a.key.clone());
                    } else {
                        self.selected.remove(&a.key);
                    }
                }
                ui.label(
                    RichText::new(a.severity.as_str().to_uppercase())
                        .color(severity_color(a.severity, dark))
                        .small()
                        .strong(),
                );
                ui.label(safe(&a.title));
                ui.label(RichText::new(a.manager.display_name()).weak());
                if a.needs_elevation {
                    ui.label(RichText::new("admin").small())
                        .on_hover_text("Asks for administrator rights");
                }
                if a.restart_required {
                    ui.label(RichText::new("restart").small())
                        .on_hover_text("Finishes after a restart");
                }
            });
            command_label(ui, "    $ ", &a.command, |t| {
                RichText::new(t).monospace().small().weak()
            });
        }
        if !plan.excluded.is_empty() {
            ui.add_space(6.0);
            egui::CollapsingHeader::new(format!("Left out by policy ({})", plan.excluded.len()))
                .id_salt("excluded")
                .show(ui, |ui| {
                    for e in &plan.excluded {
                        ui.label(format!("{} — {}", safe(&e.title), safe(&e.reason)));
                    }
                });
        }
        ui.separator();
        let windows_needs_admin = OsFamily::current() == OsFamily::Windows
            && self.scan.as_ref().is_some_and(|s| !s.report.host.is_elevated)
            && plan
                .actions
                .iter()
                .any(|a| self.selected.contains(&a.key) && a.needs_elevation);
        if windows_needs_admin {
            ui.colored_label(
                severity_color(Severity::High, dark),
                "Some selected updates need Administrator rights. Close patchscope and start it with \"Run as administrator\" to install them; the others will install now.",
            );
        }
        ui.checkbox(&mut self.dry_run, "Dry run (show the commands, change nothing)");
        ui.horizontal(|ui| {
            let n = self.selected.len();
            let label = if self.dry_run {
                format!("Dry run selected ({n})")
            } else {
                format!("Install selected ({n})")
            };
            let enabled = n > 0 && self.busy.is_none() && (self.dry_run || self.policy_error.is_none());
            if ui
                .add_enabled(enabled, egui::Button::new(RichText::new(label).strong()))
                .clicked()
            {
                self.confirm_open = true;
            }
        });
    }

    fn confirm_modal(&mut self, ctx: &egui::Context) {
        let Some(plan) = self.selected_plan() else {
            self.confirm_open = false;
            return;
        };
        let mut go = false;
        let mut cancel = false;
        let resp = egui::Modal::new(egui::Id::new("confirm-apply")).show(ctx, |ui| {
            ui.set_max_width(560.0);
            ui.heading(if self.dry_run {
                format!("Dry run {} update(s)?", plan.actions.len())
            } else {
                format!("Install {} update(s)?", plan.actions.len())
            });
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                for a in &plan.actions {
                    ui.label(RichText::new(safe(&a.title)).strong());
                    command_label(ui, "", &a.command, |t| RichText::new(t).monospace().small());
                }
            });
            ui.add_space(6.0);
            if let Some(e) = &self.policy_error {
                ui.colored_label(
                    severity_color(Severity::Critical, ui.visuals().dark_mode),
                    policy_error_text(e),
                );
            }
            if plan.needs_elevation() && !self.dry_run {
                ui.label("Your computer will ask for an administrator password.");
            }
            if plan.restart_required() {
                ui.label("Some updates finish after a restart. patchscope never restarts the computer itself.");
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
                let go_label = if self.dry_run { "Run dry run" } else { "Install now" };
                let allowed = self.dry_run || self.policy_error.is_none();
                if ui
                    .add_enabled(allowed, egui::Button::new(RichText::new(go_label).strong()))
                    .clicked()
                {
                    go = true;
                }
            });
        });
        if cancel || resp.should_close() {
            self.confirm_open = false;
        }
        if go {
            self.start_apply(ctx);
        }
    }

    fn activity(&mut self, ui: &mut egui::Ui) {
        if let Some(r) = &self.last_apply {
            let dark = ui.visuals().dark_mode;
            ui.strong(if r.dry_run { "Last dry run" } else { "Last install" });
            egui::Grid::new("results").striped(true).num_columns(3).show(ui, |ui| {
                ui.strong("Update");
                ui.strong("Result");
                ui.strong("Detail");
                ui.end_row();
                for x in &r.results {
                    ui.label(safe(&x.title));
                    let c = match x.status {
                        ActionStatus::Verified | ActionStatus::Installed => Color32::from_rgb(22, 163, 74),
                        ActionStatus::NeedsRestart => severity_color(Severity::Medium, dark),
                        ActionStatus::Failed => severity_color(Severity::Critical, dark),
                        ActionStatus::Skipped | ActionStatus::DryRun => Color32::GRAY,
                    };
                    ui.colored_label(c, x.status.label());
                    ui.label(safe(&x.message));
                    ui.end_row();
                }
            });
            for w in &r.warnings {
                ui.colored_label(severity_color(Severity::High, dark), safe(w));
            }
            if r.restart_required() {
                ui.label("Restart the computer to finish installing.");
            }
            if !r.dry_run && ui.button("Scan again to confirm").clicked() {
                self.start_scan(ui.ctx());
            }
            if let Some(p) = paths::audit_log() {
                ui.label(
                    RichText::new(format!("Every action is recorded in {}", p.display()))
                        .weak()
                        .small(),
                );
            }
            ui.separator();
        }
        ui.strong("Log");
        if self.log.is_empty() {
            ui.label("Nothing yet.");
        }
        for l in &self.log {
            ui.label(RichText::new(safe_multiline(l)).monospace().small());
        }
    }

    fn hardware(&mut self, ui: &mut egui::Ui) {
        let Some(scan) = &self.scan else {
            ui.label("Run a scan to see hardware details.");
            return;
        };
        let r = &scan.report;
        let hw = &r.hardware;
        egui::Grid::new("hw").striped(true).num_columns(2).show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.strong(k);
                ui.label(safe(&v));
                ui.end_row();
            };
            row("Operating system", r.os.name.clone());
            if let Some(b) = &r.os.build {
                row("Build", b.clone());
            }
            row("Kernel", r.os.kernel.clone());
            row("Architecture", r.os.arch.clone());
            if let Some(v) = &hw.vendor {
                row("Manufacturer", v.clone());
            }
            if let Some(m) = &hw.model {
                row("Model", m.clone());
            }
            if let Some(s) = &hw.serial {
                row("Serial number", s.clone());
            }
            if let Some(f) = &hw.firmware {
                row("Firmware", f.clone());
            }
            row(
                "Processor",
                format!(
                    "{} · {} logical cores{} · {} MHz",
                    hw.cpu.brand,
                    hw.cpu.logical_cores,
                    hw.cpu
                        .physical_cores
                        .map(|p| format!(" ({p} physical)"))
                        .unwrap_or_default(),
                    hw.cpu.frequency_mhz
                ),
            );
            row(
                "Memory",
                format!(
                    "{} ({} available)",
                    util::human_bytes(hw.memory.total_bytes),
                    util::human_bytes(hw.memory.available_bytes)
                ),
            );
            for g in &hw.gpus {
                row("Graphics", g.clone());
            }
            if let Some(b) = &hw.battery {
                row(
                    "Battery",
                    format!(
                        "{} {} {}",
                        b.condition.clone().unwrap_or_default(),
                        b.max_capacity_percent
                            .map(|p| format!("· {p}% of design capacity"))
                            .unwrap_or_default(),
                        b.cycle_count.map(|c| format!("· {c} cycles")).unwrap_or_default()
                    ),
                );
            }
            row("Uptime", format!("{:.1} days", r.host.uptime_secs as f64 / 86_400.0));
            if let Some(h) = &r.host.hostname {
                row("Hostname", h.clone());
            }
        });
        ui.add_space(10.0);
        ui.strong("Storage");
        for d in &hw.disks {
            let used = 1.0 - d.free_fraction() as f32;
            ui.label(safe(&format!("{} ({}, {})", d.mount_point, d.file_system, d.kind)));
            ui.add(egui::ProgressBar::new(used).desired_width(360.0).text(format!(
                "{} free of {}",
                util::human_bytes(d.available_bytes),
                util::human_bytes(d.total_bytes)
            )));
        }
        if !hw.temperatures.is_empty() {
            ui.add_space(10.0);
            egui::CollapsingHeader::new(format!("Temperature sensors ({})", hw.temperatures.len()))
                .id_salt("temps")
                .show(ui, |ui| {
                    for t in &hw.temperatures {
                        ui.label(format!("{}: {:.0} °C", safe(&t.label), t.celsius));
                    }
                });
        }
        if !hw.network_interfaces.is_empty() {
            egui::CollapsingHeader::new(format!("Network interfaces ({})", hw.network_interfaces.len()))
                .id_salt("nics")
                .show(ui, |ui| {
                    for n in &hw.network_interfaces {
                        ui.label(safe(&match &n.mac_address {
                            Some(m) => format!("{} · {m}", n.name),
                            None => n.name.clone(),
                        }));
                    }
                });
        }
        if !r.runtimes.is_empty() {
            ui.add_space(10.0);
            ui.strong("Language runtimes");
            for rt in &r.runtimes {
                ui.label(safe(&format!(
                    "{} {} ({})",
                    rt.display_name, rt.version, rt.path_command
                )));
            }
        }
    }

    fn software(&mut self, ui: &mut egui::Ui) {
        let Some(scan) = &self.scan else {
            ui.label("Run a scan to see installed software.");
            return;
        };
        ui.strong("Package sources");
        egui::Grid::new("mgrs").striped(true).num_columns(4).show(ui, |ui| {
            ui.strong("Source");
            ui.strong("Installed");
            ui.strong("Updates");
            ui.strong("Status");
            ui.end_row();
            for m in scan.report.managers.iter().filter(|m| m.available) {
                ui.label(m.id.display_name());
                ui.label(m.installed.len().to_string());
                ui.label(m.updates.len().to_string());
                ui.label(m.error.as_deref().map_or_else(|| "ok".into(), safe));
                ui.end_row();
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Search installed");
            ui.add(egui::TextEdit::singleline(&mut self.package_filter).desired_width(220.0));
        });
        let q = self.package_filter.to_lowercase();
        let rows: Vec<String> = scan
            .report
            .managers
            .iter()
            .flat_map(|m| m.installed.iter())
            .filter(|p| q.is_empty() || p.name.to_lowercase().contains(&q))
            .map(|p| format!("{:<14} {}  {}", p.manager.as_str(), safe(&p.name), safe(&p.version)))
            .collect();
        ui.label(format!("{} packages", rows.len()));
        let h = ui.text_style_height(&egui::TextStyle::Monospace);
        egui::ScrollArea::vertical()
            .id_salt("pkgs")
            .max_height(420.0)
            .auto_shrink([false, true])
            .show_rows(ui, h, rows.len(), |ui, range| {
                for r in &rows[range] {
                    ui.label(RichText::new(r).monospace());
                }
            });
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.strong("Scanning");
        ui.checkbox(&mut self.settings.offline, "Offline: use only cached research data");
        ui.checkbox(
            &mut self.settings.include_identifiers,
            "Include hostname, serial number and MAC addresses in reports",
        );
        ui.add_space(8.0);
        ui.strong("Installing");
        egui::ComboBox::from_label("How to get administrator rights")
            .selected_text(format!("{:?}", self.elevation))
            .show_ui(ui, |ui| {
                for e in [
                    Elevation::MacosAdminPrompt,
                    Elevation::Pkexec,
                    Elevation::Sudo,
                    Elevation::SudoNonInteractive,
                    Elevation::None,
                ] {
                    ui.selectable_value(&mut self.elevation, e, format!("{e:?}"));
                }
            });
        ui.add_space(8.0);
        ui.strong("Policy");
        ui.label(
            "What patchscope may install. Protected patterns are never touched (Xcode by default); major OS upgrades are \
off unless allowed.",
        );
        if let Some(p) = &self.policy_path {
            ui.label(RichText::new(p.display().to_string()).weak().small());
        }
        ui.add(
            egui::TextEdit::multiline(&mut self.policy_text)
                .code_editor()
                .desired_rows(12)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            if ui.button("Save policy").clicked() {
                self.save_policy();
            }
            if ui.button("Reset to defaults").clicked() {
                self.policy_text = Policy::default().to_toml();
            }
        });
        if let Some((ok, m)) = &self.policy_msg {
            let c = if *ok {
                Color32::from_rgb(22, 163, 74)
            } else {
                severity_color(Severity::Critical, ui.visuals().dark_mode)
            };
            ui.colored_label(c, safe_multiline(m));
        }
    }

    #[cfg(test)]
    pub fn set_policy_text_for_test(&mut self, text: &str) {
        self.policy_text = text.to_string();
    }

    pub fn save_policy(&mut self) {
        match Policy::from_toml(&self.policy_text) {
            Ok(p) => {
                let written = match &self.policy_path {
                    Some(path) => path
                        .parent()
                        .map_or(Ok(()), std::fs::create_dir_all)
                        .and_then(|_| std::fs::write(path, p.to_toml()))
                        .map(|_| format!("Saved to {}", path.display())),
                    None => Ok("Applied for this session".to_string()),
                };
                match written {
                    Ok(m) => {
                        self.policy = p;
                        self.policy_error = None;
                        self.policy_msg = Some((true, m));
                        self.rebuild_plan();
                    }
                    Err(e) => self.policy_msg = Some((false, format!("Could not save: {e}"))),
                }
            }
            Err(e) => self.policy_msg = Some((false, format!("Not saved: {e}"))),
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.poll();
        if self.busy.is_some() {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(4.0);
        });
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(150.0)
            .show(ui, |ui| self.nav(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("main")
                .auto_shrink([false, false])
                .show(ui, |ui| match self.tab {
                    Tab::Overview => self.overview(ui),
                    Tab::Findings => self.findings(ui),
                    Tab::Updates => self.updates(ui),
                    Tab::Activity => self.activity(ui),
                    Tab::Hardware => self.hardware(ui),
                    Tab::Software => self.software(ui),
                    Tab::Settings => self.settings_tab(ui),
                });
        });
        if self.confirm_open {
            let ctx = ui.ctx().clone();
            self.confirm_modal(&ctx);
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}
