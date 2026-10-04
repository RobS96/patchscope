//! `patchscope`: discover a machine's software and hardware, research what
//! needs updating and why, and apply the updates.

use clap::{Args, Parser, Subcommand, ValueEnum};
use patchscope_core::analysis::{AnalyzeOptions, analyze};
use patchscope_core::apply::{ActionStatus, ApplyEvent, ApplyOptions, apply_plan, plan_from_saved, refresh_metadata};
use patchscope_core::discover::{self, DiscoverOptions, discover};
use patchscope_core::exec::{Elevation, SystemRunner};
use patchscope_core::model::{Analysis, ManagerId, Scan, Severity, SystemReport};
use patchscope_core::plan::{Selection, UpdatePlan, build_plan};
use patchscope_core::policy::Policy;
use patchscope_core::research::http::UreqClient;
// Text that came from the machine, a package manager, a research source or
// a saved scan file goes through `safe` before it is printed.
use patchscope_core::util::display_safe as safe;
use patchscope_core::{managers, paths, report, util};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "patchscope",
    version,
    about = "Find out what this machine runs, what is vulnerable or out of support, and fix it.",
    long_about = "patchscope inventories the operating system, hardware and installed software, checks them against \
OSV.dev, CISA's Known Exploited Vulnerabilities catalogue, FIRST EPSS and endoflife.date, ranks what it finds, \
and installs the updates you approve through the system's own package managers.\n\n\
Typical use:\n  patchscope scan                 # what needs attention and why\n  patchscope apply --dry-run      # the exact commands it would run\n  patchscope apply                # review the plan, confirm, install, verify"
)]
struct Cli {
    /// Only print results; no progress messages.
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Policy file (default: the platform config directory's patchscope.toml).
    #[arg(long, global = true, value_name = "FILE")]
    policy: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover and research: list what needs updating and why.
    Scan(ScanArgs),
    /// Inventory only (no network): OS, hardware, runtimes, packages.
    Discover(DiscoverArgs),
    /// Show the update plan the policy allows, without installing anything.
    Plan(PlanArgs),
    /// Install updates: shows the plan, asks for confirmation, verifies.
    Apply(ApplyArgs),
    /// Refresh package-manager metadata (apt-get update, brew update, …).
    Refresh(ElevationArgs),
    /// List the package managers patchscope supports and which are present.
    Managers,
    /// Show or create the policy file.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Print the effective policy.
    Show,
    /// Print where the policy file lives.
    Path,
    /// Write the default policy to the policy file (refuses to overwrite).
    Init,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Markdown,
    Html,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

#[derive(Args, Clone)]
struct DiscoverArgs {
    /// Include hostname, serial number and MAC addresses (off by default).
    #[arg(long)]
    include_identifiers: bool,
    /// Query only these managers (repeatable), e.g. --manager apt.
    #[arg(long = "manager", value_name = "ID", value_parser = parse_manager)]
    managers: Vec<ManagerId>,
    /// Skip these managers (repeatable).
    #[arg(long = "skip-manager", value_name = "ID", value_parser = parse_manager)]
    skip: Vec<ManagerId>,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Write the output to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct ResearchArgs {
    /// Use only cached research data; make no network requests.
    #[arg(long)]
    offline: bool,
    /// Reuse a scan saved with `scan --save` instead of scanning again. With
    /// `apply`, it only picks the updates: each one must still be offered
    /// by its manager on this machine, which decides what it installs.
    #[arg(long, value_name = "FILE")]
    from: Option<PathBuf>,
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    discover: DiscoverArgs,
    #[command(flatten)]
    research: ResearchArgs,
    /// Also save the scan (report + analysis) as JSON for `plan`/`apply --from`.
    #[arg(long, value_name = "FILE")]
    save: Option<PathBuf>,
    /// Exit with status 2 when a finding is at least this severe.
    #[arg(long, value_enum, default_value_t = SeverityArg::High)]
    fail_on: SeverityArg,
    #[command(flatten)]
    partial: PartialArgs,
}

#[derive(Args, Clone)]
struct PartialArgs {
    /// Accept incomplete research: do not exit with status 4 when a research
    /// source (OSV.dev, CISA KEV, FIRST EPSS, endoflife.date) could not be
    /// fully queried.
    #[arg(long)]
    allow_partial: bool,
}

/// Exit status when a research source could not be fully queried, so the
/// absence of findings proves nothing.
const EXIT_RESEARCH_INCOMPLETE: u8 = 4;

fn research_exit(a: &Analysis, p: &PartialArgs) -> Option<ExitCode> {
    (!p.allow_partial && !a.incomplete_sources().is_empty()).then(|| ExitCode::from(EXIT_RESEARCH_INCOMPLETE))
}

#[derive(Args, Clone)]
struct SelectArgs {
    /// Only updates whose findings are at least this severe.
    #[arg(long, value_enum)]
    min_severity: Option<SeverityArg>,
    /// Only these updates (repeatable), by key as shown in the plan: manager:id.
    #[arg(long = "only", value_name = "KEY")]
    only: Vec<String>,
    /// Only updates tied to a security finding (overrides the policy).
    #[arg(long)]
    security_only: bool,
}

#[derive(Args)]
struct PlanArgs {
    #[command(flatten)]
    discover: DiscoverArgs,
    #[command(flatten)]
    research: ResearchArgs,
    #[command(flatten)]
    select: SelectArgs,
    #[command(flatten)]
    partial: PartialArgs,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ElevationArg {
    /// Already root/Administrator, or fail.
    None,
    /// sudo (prompts in the terminal).
    Sudo,
    /// sudo -n (never prompts; for unattended runs).
    SudoNonInteractive,
    /// pkexec (graphical prompt on Linux).
    Pkexec,
    /// macOS administrator dialog.
    MacosPrompt,
}

#[derive(Args, Clone)]
struct ElevationArgs {
    /// How to run commands that need root/Administrator.
    #[arg(long, value_enum)]
    elevation: Option<ElevationArg>,
}

impl ElevationArgs {
    fn get(&self) -> Elevation {
        match self.elevation {
            None => Elevation::default_for(false),
            Some(ElevationArg::None) => Elevation::None,
            Some(ElevationArg::Sudo) => Elevation::Sudo,
            Some(ElevationArg::SudoNonInteractive) => Elevation::SudoNonInteractive,
            Some(ElevationArg::Pkexec) => Elevation::Pkexec,
            Some(ElevationArg::MacosPrompt) => Elevation::MacosAdminPrompt,
        }
    }
}

#[derive(Args)]
struct ApplyArgs {
    #[command(flatten)]
    discover: DiscoverArgs,
    #[command(flatten)]
    research: ResearchArgs,
    #[command(flatten)]
    select: SelectArgs,
    #[command(flatten)]
    elevation: ElevationArgs,
    /// Show the commands that would run; change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Do not ask for confirmation (required when stdin is not a terminal).
    #[arg(short, long)]
    yes: bool,
    /// Skip re-querying managers afterwards.
    #[arg(long)]
    no_verify: bool,
    /// Stop at the first failed update.
    #[arg(long)]
    stop_on_failure: bool,
}

fn parse_manager(s: &str) -> Result<ManagerId, String> {
    ManagerId::parse(s).ok_or_else(|| {
        format!(
            "unknown manager `{s}`; one of: {}",
            ManagerId::ALL.iter().map(|m| m.as_str()).collect::<Vec<_>>().join(", ")
        )
    })
}

// ------------------------------------------------------------- terminal UI

struct Ui {
    quiet: bool,
    color: bool,
}

impl Ui {
    fn new(quiet: bool) -> Self {
        Ui {
            quiet,
            color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }
    fn progress(&self, msg: &str) {
        if !self.quiet {
            eprintln!("  {}", safe(msg));
        }
    }
    fn sev(&self, s: Severity) -> String {
        let label = format!("{:<8}", s.as_str().to_uppercase());
        if !self.color {
            return label;
        }
        let code = match s {
            Severity::Critical => "1;31",
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        format!("\x1b[{code}m{label}\x1b[0m")
    }
    fn bold(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

fn write_out(output: Option<&PathBuf>, text: &str) -> Result<(), String> {
    match output {
        Some(p) => std::fs::write(p, text).map_err(|e| format!("writing {}: {e}", p.display())),
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(text.as_bytes())
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())
        }
    }
}

fn load_policy(cli_path: Option<&PathBuf>) -> Result<Policy, String> {
    match cli_path {
        Some(p) => Policy::load_existing(p),
        None => Policy::load_default(),
    }
    .map_err(|e| e.to_string())
}

fn discover_opts(a: &DiscoverArgs, policy: &Policy) -> DiscoverOptions {
    let mut skip = a.skip.clone();
    skip.extend(policy.managers.disabled.iter().copied());
    DiscoverOptions {
        include_identifiers: a.include_identifiers,
        only_managers: a.managers.clone(),
        skip_managers: skip,
    }
}

fn scan(ui: &Ui, d: &DiscoverArgs, r: &ResearchArgs, policy: &Policy) -> Result<Scan, String> {
    if let Some(path) = &r.from {
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        return serde_json::from_str(&text).map_err(|e| format!("{}: not a patchscope scan: {e}", path.display()));
    }
    let runner = SystemRunner::new();
    let progress = |m: &str| ui.progress(m);
    let report = discover(&runner, &discover_opts(d, policy), &progress);
    let opts = AnalyzeOptions {
        offline: r.offline,
        ..Default::default()
    };
    let analysis = analyze(&report, &UreqClient::new(), &opts, &progress);
    Ok(Scan { report, analysis })
}

fn print_system(ui: &Ui, r: &SystemReport) -> String {
    let hw = &r.hardware;
    let mut o = String::new();
    o += &format!("{}\n", ui.bold("System"));
    o += &format!(
        "  OS         {}{}\n",
        safe(&r.os.name),
        r.os.build
            .as_ref()
            .map(|b| format!(" (build {})", safe(b)))
            .unwrap_or_default()
    );
    o += &format!("  Kernel     {} · {}\n", safe(&r.os.kernel), safe(&r.os.arch));
    if let Some(m) = &hw.model {
        o += &format!("  Model      {}\n", safe(m));
    }
    if let Some(f) = &hw.firmware {
        o += &format!("  Firmware   {}\n", safe(f));
    }
    o += &format!(
        "  CPU        {} ({} logical cores)\n",
        safe(&hw.cpu.brand),
        hw.cpu.logical_cores
    );
    o += &format!(
        "  Memory     {} ({} available)\n",
        util::human_bytes(hw.memory.total_bytes),
        util::human_bytes(hw.memory.available_bytes)
    );
    for d in &hw.disks {
        o += &format!(
            "  Disk       {} — {} free of {}\n",
            safe(&d.mount_point),
            util::human_bytes(d.available_bytes),
            util::human_bytes(d.total_bytes)
        );
    }
    for g in &hw.gpus {
        o += &format!("  GPU        {}\n", safe(g));
    }
    if let Some(b) = &hw.battery {
        o += &format!(
            "  Battery    {} {} {}\n",
            safe(b.condition.as_deref().unwrap_or_default()),
            b.max_capacity_percent
                .map(|p| format!("· {p}% capacity"))
                .unwrap_or_default(),
            b.cycle_count.map(|c| format!("· {c} cycles")).unwrap_or_default()
        );
    }
    for rt in &r.runtimes {
        o += &format!("  {:<10} {}\n", safe(&rt.display_name), safe(&rt.version));
    }
    o += &format!("\n{}\n", ui.bold("Package sources"));
    for m in r.managers.iter().filter(|m| m.available) {
        o += &format!(
            "  {:<22} {:>5} installed {:>4} updates{}\n",
            m.id.display_name(),
            m.installed.len(),
            m.updates.len(),
            m.error.as_ref().map(|e| format!("  ⚠ {}", safe(e))).unwrap_or_default()
        );
    }
    o
}

fn print_notes(a: &Analysis) -> String {
    report::research_notes(a)
        .iter()
        .map(|n| format!("  ⚠ {}\n", safe(n)))
        .collect()
}

fn print_analysis(ui: &Ui, a: &Analysis) -> String {
    let s = &a.summary;
    let mut o = format!(
        "\n{}  {} critical · {} high · {} medium · {} low · {} info\n",
        ui.bold("Findings"),
        s.critical,
        s.high,
        s.medium,
        s.low,
        s.info
    );
    o += &format!(
        "  {} updates available ({} security) · {} advisories matched · {} actively exploited\n\n",
        s.updates_available, s.security_updates, s.advisories, s.kev_advisories
    );
    let notes = print_notes(a);
    if !notes.is_empty() {
        o += &notes;
        o += "\n";
    }
    for f in &a.findings {
        o += &format!("  {} {}\n", ui.sev(f.severity), safe(&f.title));
        if f.severity >= Severity::High {
            o += &format!("           {}\n", safe(&f.rationale));
        }
    }
    o += &format!("\n{}\n", ui.bold("Sources"));
    for src in &a.sources {
        o += &format!(
            "  {} {}: {}\n",
            if src.ok { "✓" } else { "✗" },
            safe(&src.name),
            safe(&src.detail)
        );
    }
    o
}

fn print_plan(ui: &Ui, p: &UpdatePlan) -> String {
    let mut o = format!("\n{}\n", ui.bold("Update plan"));
    if p.actions.is_empty() {
        o += "  Nothing to install.\n";
    }
    for (i, a) in p.actions.iter().enumerate() {
        o += &format!(
            "  {:>2}. {} {}  [{}]\n",
            i + 1,
            ui.sev(a.severity),
            safe(&a.title),
            safe(&a.key)
        );
        let command = safe(&a.command);
        o += &format!(
            "      $ {}{}{}{}\n",
            command,
            if a.needs_elevation { "   (as administrator)" } else { "" },
            if a.restart_required { "   (restart needed)" } else { "" },
            if command != a.command {
                "   (hidden or control characters shown as \\u{..}, backslashes doubled)"
            } else {
                ""
            }
        );
    }
    if !p.excluded.is_empty() {
        o += &format!("\n  Left out ({}):\n", p.excluded.len());
        for e in &p.excluded {
            o += &format!("    - {} — {}\n", safe(&e.title), safe(&e.reason));
        }
    }
    o
}

/// What `apply` prints as each action starts and finishes.
fn print_event(e: &ApplyEvent, dry_run: bool) -> String {
    let mut o = String::new();
    match e {
        ApplyEvent::Started {
            index,
            total,
            action,
            command,
        } => {
            o += &format!("[{}/{}] {}\n", index + 1, total, safe(&action.title));
            if dry_run {
                o += &format!("      would run: {}\n", safe(command));
            }
        }
        ApplyEvent::Finished { result, .. } if !dry_run => {
            o += &format!("      → {} ({})\n", result.status.label(), safe(&result.message));
            if result.status == ActionStatus::Failed && !result.output_tail.is_empty() {
                for l in result.output_tail.lines().take(8) {
                    o += &format!("        | {}\n", safe(l));
                }
            }
        }
        _ => {}
    }
    o
}

fn selection(s: &SelectArgs) -> Selection {
    if !s.only.is_empty() {
        Selection::Keys(s.only.clone())
    } else if let Some(m) = s.min_severity {
        Selection::AtLeast(m.into())
    } else {
        Selection::All
    }
}

fn effective_policy(mut p: Policy, s: &SelectArgs) -> Policy {
    if s.security_only {
        p.apply.security_only = true;
    }
    p
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let ui = Ui::new(cli.quiet);
    match cli.command {
        Command::Discover(d) => {
            let policy = load_policy(cli.policy.as_ref())?;
            let runner = SystemRunner::new();
            let report = discover(&runner, &discover_opts(&d, &policy), &|m| ui.progress(m));
            let text = match d.format {
                Format::Json => serde_json::to_string_pretty(&report).map_err(|e| e.to_string())? + "\n",
                Format::Markdown => report::markdown(&report, None, None),
                Format::Html => report::html(&report, None, None),
                Format::Text => print_system(&ui, &report),
            };
            write_out(d.output.as_ref(), &text)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan(a) => {
            let policy = load_policy(cli.policy.as_ref())?;
            let s = scan(&ui, &a.discover, &a.research, &policy)?;
            if let Some(path) = &a.save {
                let json = serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?;
                std::fs::write(path, json).map_err(|e| format!("writing {}: {e}", path.display()))?;
                ui.progress(&format!("Scan saved to {}", path.display()));
            }
            let text = match a.discover.format {
                Format::Json => serde_json::to_string_pretty(&s).map_err(|e| e.to_string())? + "\n",
                Format::Markdown => report::markdown(&s.report, Some(&s.analysis), None),
                Format::Html => report::html(&s.report, Some(&s.analysis), None),
                Format::Text => print_system(&ui, &s.report) + &print_analysis(&ui, &s.analysis),
            };
            write_out(a.discover.output.as_ref(), &text)?;
            let threshold: Severity = a.fail_on.into();
            // Incomplete research comes first: the findings shown are real,
            // but more may have been missed.
            Ok(research_exit(&s.analysis, &a.partial).unwrap_or(
                if s.analysis.findings.iter().any(|f| f.severity >= threshold) {
                    ExitCode::from(2)
                } else {
                    ExitCode::SUCCESS
                },
            ))
        }
        Command::Plan(a) => {
            let policy = effective_policy(load_policy(cli.policy.as_ref())?, &a.select);
            let s = scan(&ui, &a.discover, &a.research, &policy)?;
            let plan = build_plan(&s.report, &s.analysis, &policy, &selection(&a.select));
            let text = match a.discover.format {
                Format::Json => serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())? + "\n",
                Format::Markdown => report::markdown(&s.report, Some(&s.analysis), Some(&plan)),
                Format::Html => report::html(&s.report, Some(&s.analysis), Some(&plan)),
                Format::Text => print_notes(&s.analysis) + &print_plan(&ui, &plan),
            };
            write_out(a.discover.output.as_ref(), &text)?;
            Ok(research_exit(&s.analysis, &a.partial).unwrap_or(ExitCode::SUCCESS))
        }
        Command::Apply(a) => {
            let policy = effective_policy(load_policy(cli.policy.as_ref())?, &a.select);
            let s = scan(&ui, &a.discover, &a.research, &policy)?;
            let (report, plan) = match &a.research.from {
                // A saved scan picks the updates; this machine, asked again
                // now, decides what they are.
                Some(path) => {
                    ui.progress("Checking the saved scan against this machine…");
                    let runner = SystemRunner::new();
                    let os = discover::os::detect(&runner, &mut Vec::new());
                    plan_from_saved(&s, &os, &runner, &policy, &selection(&a.select), &|m| ui.progress(m))
                        .map_err(|e| format!("{}: {e}", path.display()))?
                }
                None => {
                    let plan = build_plan(&s.report, &s.analysis, &policy, &selection(&a.select));
                    (s.report, plan)
                }
            };
            print!("{}", print_plan(&ui, &plan));
            if plan.is_empty() {
                return Ok(ExitCode::SUCCESS);
            }
            if !a.dry_run && !a.yes {
                if !std::io::stdin().is_terminal() {
                    return Err(
                        "refusing to install without confirmation: stdin is not a terminal (pass --yes)".into(),
                    );
                }
                print!("\nInstall {} update(s)? [y/N] ", plan.actions.len());
                std::io::stdout().flush().ok();
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer).map_err(|e| e.to_string())?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("Nothing installed.");
                    return Ok(ExitCode::SUCCESS);
                }
            }
            let runner = SystemRunner::new();
            let opts = ApplyOptions {
                dry_run: a.dry_run,
                elevation: a.elevation.get(),
                verify: !a.no_verify,
                stop_on_failure: a.stop_on_failure,
                ..Default::default()
            };
            println!();
            let r = apply_plan(&plan, &report.os, &runner, &opts, &|e| match e {
                ApplyEvent::Verifying(m) => ui.progress(&format!("Verifying {}…", m.display_name())),
                // Shown even with --quiet.
                ApplyEvent::Warning(w) => eprintln!("warning: {}", safe(w)),
                e => print!("{}", print_event(&e, a.dry_run)),
            })
            .map_err(|e| e.to_string())?;
            println!(
                "\n{} verified · {} installed · {} restart needed · {} failed · {} skipped{}",
                r.count(ActionStatus::Verified),
                r.count(ActionStatus::Installed),
                r.count(ActionStatus::NeedsRestart),
                r.count(ActionStatus::Failed),
                r.count(ActionStatus::Skipped),
                if r.dry_run { " (dry run: nothing changed)" } else { "" }
            );
            if r.restart_required() {
                println!("Restart the machine to finish installing.");
            }
            if let Some(p) = paths::audit_log() {
                ui.progress(&format!("Audit log: {}", p.display()));
            }
            Ok(if r.all_succeeded() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            })
        }
        Command::Refresh(e) => {
            let policy = load_policy(cli.policy.as_ref())?;
            let runner = SystemRunner::new();
            let opts = DiscoverOptions {
                skip_managers: policy.managers.disabled.clone(),
                ..Default::default()
            };
            let report = discover(&runner, &opts, &|m| ui.progress(m));
            let res = refresh_metadata(&report, &runner, e.get(), &|m| ui.progress(m));
            let mut failed = false;
            for (m, r) in res {
                match r {
                    Ok(()) => println!("✓ {}", m.display_name()),
                    Err(e) => {
                        failed = true;
                        println!("✗ {}: {}", m.display_name(), util::display_safe_multiline(&e));
                    }
                }
            }
            Ok(if failed { ExitCode::from(3) } else { ExitCode::SUCCESS })
        }
        Command::Managers => {
            let runner = SystemRunner::new();
            let os = patchscope_core::model::OsFamily::current();
            use patchscope_core::exec::CommandRunner;
            for m in managers::all() {
                let state = if !m.supported_on(os) {
                    "not for this OS".to_string()
                } else if let Some(p) = runner.which(m.program()) {
                    format!("found ({})", safe(&p.display().to_string()))
                } else {
                    "not installed".to_string()
                };
                println!("  {:<16} {:<22} {state}", m.id().as_str(), m.id().display_name());
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Policy { action } => {
            let path = cli.policy.clone().or_else(paths::policy_file);
            match action {
                PolicyAction::Show => print!(
                    "{}",
                    util::display_safe_multiline(&load_policy(cli.policy.as_ref())?.to_toml())
                ),
                PolicyAction::Path => println!(
                    "{}",
                    path.map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(no config directory)".into())
                ),
                PolicyAction::Init => {
                    let p = path.ok_or("no config directory on this system; pass --policy FILE")?;
                    if p.exists() {
                        return Err(format!("{} already exists", p.display()));
                    }
                    if let Some(dir) = p.parent() {
                        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                    }
                    std::fs::write(&p, Policy::default().to_toml()).map_err(|e| e.to_string())?;
                    println!("Wrote {}", p.display());
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("patchscope: {}", util::display_safe_multiline(&e));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use patchscope_core::apply::ActionResult;
    use patchscope_core::model::{
        BatteryInfo, CpuInfo, DiskInfo, Finding, HardwareInfo, ManagerInventory, OsFamily, OsInfo, Runtime,
        SourceStatus,
    };
    use patchscope_core::plan::{Excluded, PlannedAction};

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn manager_ids_parse() {
        assert_eq!(parse_manager("apt"), Ok(ManagerId::Apt));
        assert!(parse_manager("nope").unwrap_err().contains("homebrew"));
    }

    #[test]
    fn selection_prefers_explicit_keys() {
        let s = SelectArgs {
            min_severity: Some(SeverityArg::High),
            only: vec!["apt:curl".into()],
            security_only: false,
        };
        assert_eq!(selection(&s), Selection::Keys(vec!["apt:curl".into()]));
        let s = SelectArgs {
            min_severity: Some(SeverityArg::High),
            only: vec![],
            security_only: true,
        };
        assert_eq!(selection(&s), Selection::AtLeast(Severity::High));
        assert!(effective_policy(Policy::default(), &s).apply.security_only);
    }

    /// Erase the line above, CSI (C1) erase, carriage return, right-to-left
    /// override, isolate, zero-width space.
    const HOSTILE: &str = "\x1b[1A\x1b[2K\u{9b}2K\r\u{202e}gpj.exe\u{2066}\u{200b}";

    /// Fails if `out` carries any character a terminal would act on or hide.
    fn assert_inert(out: &str) {
        for c in out.chars() {
            assert!(
                !matches!(
                    c,
                    '\x1b' | '\u{9b}' | '\r' | '\u{202e}' | '\u{2066}' | '\u{200b}' | '\x07'
                ),
                "{c:?} reached the terminal: {out:?}"
            );
        }
    }

    fn plain() -> Ui {
        Ui {
            quiet: true,
            color: false,
        }
    }

    fn action(title: &str, command: &str) -> PlannedAction {
        PlannedAction {
            key: format!("softwareupdate:{title}"),
            manager: ManagerId::Softwareupdate,
            title: title.into(),
            severity: Severity::High,
            finding_ids: vec![],
            updates: vec![],
            command: command.into(),
            needs_elevation: true,
            restart_required: false,
        }
    }

    #[test]
    fn plan_shown_before_confirmation_is_inert() {
        let plan = UpdatePlan {
            generated_at: "2026-10-04T00:00:00Z".into(),
            actions: vec![
                action("git 1 → 2", "brew upgrade --formula git"),
                action(
                    &format!("Label{HOSTILE} 1 → 2"),
                    &format!("softwareupdate --install 'Label{HOSTILE}'"),
                ),
            ],
            excluded: vec![Excluded {
                key: format!("apt:{HOSTILE}"),
                title: HOSTILE.into(),
                reason: HOSTILE.into(),
            }],
        };
        let out = print_plan(&plain(), &plan);
        assert_inert(&out);
        // The earlier command is still there, and the hidden characters are visible.
        assert!(out.contains("$ brew upgrade --formula git"), "{out}");
        assert!(out.contains(r"\u{1b}[1A\u{1b}[2K\u{9b}2K\u{d}\u{202e}gpj.exe"), "{out}");
        assert!(out.contains("hidden or control characters"), "{out}");
    }

    #[test]
    fn findings_sources_and_system_are_inert() {
        let finding = |sev| Finding {
            id: "x".into(),
            severity: sev,
            category: patchscope_core::model::Category::Vulnerability,
            title: format!("t{HOSTILE}"),
            manager: None,
            subject: HOSTILE.into(),
            installed_version: None,
            rationale: format!("r{HOSTILE}\nsecond line"),
            advisories: vec![],
            remediation: None,
            risk_score: 0.0,
            references: vec![],
        };
        let analysis = Analysis {
            schema_version: 1,
            generated_at: HOSTILE.into(),
            offline: false,
            sources: vec![SourceStatus {
                name: HOSTILE.into(),
                ok: false,
                detail: HOSTILE.into(),
            }],
            summary: Default::default(),
            findings: vec![finding(Severity::Critical), finding(Severity::Low)],
        };
        let out = print_analysis(&plain(), &analysis);
        assert_inert(&out);
        assert!(!out.contains("\nsecond line"), "a rationale stays on one line: {out}");

        let report = SystemReport {
            schema_version: 1,
            tool_version: HOSTILE.into(),
            generated_at: HOSTILE.into(),
            host: Default::default(),
            os: OsInfo {
                family: OsFamily::Macos,
                name: HOSTILE.into(),
                version: "26".into(),
                build: Some(HOSTILE.into()),
                kernel: HOSTILE.into(),
                arch: HOSTILE.into(),
                distro_id: None,
                distro_version_id: None,
                edition: None,
            },
            hardware: HardwareInfo {
                model: Some(HOSTILE.into()),
                firmware: Some(HOSTILE.into()),
                cpu: CpuInfo {
                    brand: HOSTILE.into(),
                    ..Default::default()
                },
                disks: vec![DiskInfo {
                    mount_point: HOSTILE.into(),
                    ..Default::default()
                }],
                gpus: vec![HOSTILE.into()],
                battery: Some(BatteryInfo {
                    cycle_count: Some(1),
                    condition: Some(HOSTILE.into()),
                    max_capacity_percent: Some(90),
                }),
                ..Default::default()
            },
            runtimes: vec![Runtime {
                product: "python".into(),
                display_name: HOSTILE.into(),
                version: HOSTILE.into(),
                path_command: "python3".into(),
            }],
            managers: vec![ManagerInventory {
                id: ManagerId::Homebrew,
                available: true,
                version: None,
                installed: vec![],
                updates: vec![],
                error: Some(format!("{HOSTILE}\nmore")),
            }],
            warnings: vec![],
        };
        let out = print_system(&plain(), &report);
        assert_inert(&out);
    }

    #[test]
    fn apply_progress_is_inert() {
        let a = action(&format!("t{HOSTILE}"), "x");
        let command = format!("softwareupdate --install 'L{HOSTILE}'");
        let started = ApplyEvent::Started {
            index: 0,
            total: 1,
            action: &a,
            command: &command,
        };
        let out = print_event(&started, true);
        assert_inert(&out);
        assert!(out.contains(r"\u{202e}"), "{out}");
        let result = ActionResult {
            key: a.key.clone(),
            title: a.title.clone(),
            command,
            status: ActionStatus::Failed,
            exit_code: Some(1),
            duration_ms: 1,
            message: format!("m{HOSTILE}"),
            output_tail: format!("one{HOSTILE}\ntwo\x07"),
        };
        let finished = ApplyEvent::Finished {
            index: 0,
            total: 1,
            result: &result,
        };
        let out = print_event(&finished, false);
        assert_inert(&out);
        assert_eq!(out.lines().count(), 3, "{out}");
    }
}
