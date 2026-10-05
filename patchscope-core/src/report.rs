//! Human-readable reports: Markdown (for tickets and pull requests) and a
//! self-contained HTML page (no scripts, no external assets).

use crate::apply::ApplyReport;
use crate::model::*;
use crate::plan::UpdatePlan;
use crate::util::{display_safe, display_safe_multiline, human_bytes};
use std::fmt::Write;

/// One line of untrusted text with its line breaks as spaces and its hidden
/// and control characters shown as escapes.
fn md_line(s: &str) -> String {
    display_safe(&s.replace("\r\n", " ").replace(['\r', '\n'], " "))
}

/// Text for a Markdown paragraph or table cell: every character Markdown
/// could read as a link, image, HTML, emphasis, code or a cell boundary is
/// backslash-escaped.
fn md_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in md_line(s).chars() {
        if "\\`*_[]<>|".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// A code span in a table cell. Backslashes do not escape inside one, so the
/// fence is one backtick longer than the longest run in the text, padded
/// with a space where the text starts or ends with a backtick or space
/// (CommonMark); `|` is escaped because GFM splits cells before code spans.
fn md_code_cell(s: &str) -> String {
    let s = md_line(s).replace('|', "\\|");
    if s.is_empty() {
        return String::new();
    }
    let longest = s.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if s.starts_with(['`', ' ']) || s.ends_with(['`', ' ']) {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{s}{pad}{fence}")
}

pub fn markdown(report: &SystemReport, analysis: Option<&Analysis>, plan: Option<&UpdatePlan>) -> String {
    let mut o = String::new();
    let hw = &report.hardware;
    let _ = writeln!(o, "# patchscope report\n");
    let _ = writeln!(
        o,
        "Generated {} by patchscope {}.\n",
        md_escape(&report.generated_at),
        md_escape(&report.tool_version)
    );
    let _ = writeln!(o, "## System\n");
    let _ = writeln!(o, "| | |\n|---|---|");
    let _ = writeln!(o, "| Operating system | {} |", md_escape(&report.os.name));
    if let Some(b) = &report.os.build {
        let _ = writeln!(o, "| Build | {} |", md_escape(b));
    }
    let _ = writeln!(o, "| Kernel | {} |", md_escape(&report.os.kernel));
    let _ = writeln!(o, "| Architecture | {} |", md_escape(&report.os.arch));
    if let Some(m) = &hw.model {
        let _ = writeln!(o, "| Model | {} |", md_escape(m));
    }
    if let Some(f) = &hw.firmware {
        let _ = writeln!(o, "| Firmware | {} |", md_escape(f));
    }
    let _ = writeln!(
        o,
        "| CPU | {} ({} logical cores) |",
        md_escape(&hw.cpu.brand),
        hw.cpu.logical_cores
    );
    let _ = writeln!(o, "| Memory | {} |", human_bytes(hw.memory.total_bytes));
    for d in &hw.disks {
        let _ = writeln!(
            o,
            "| Disk {} | {} free of {} ({}) |",
            md_escape(&d.mount_point),
            human_bytes(d.available_bytes),
            human_bytes(d.total_bytes),
            md_escape(&d.file_system)
        );
    }
    for g in &hw.gpus {
        let _ = writeln!(o, "| GPU | {} |", md_escape(g));
    }
    if let Some(b) = &hw.battery {
        let _ = writeln!(
            o,
            "| Battery | {} {} {} |",
            md_escape(b.condition.as_deref().unwrap_or_default()),
            b.max_capacity_percent
                .map(|p| format!("{p}% capacity"))
                .unwrap_or_default(),
            b.cycle_count.map(|c| format!("{c} cycles")).unwrap_or_default()
        );
    }
    for r in &report.runtimes {
        let _ = writeln!(o, "| {} | {} |", md_escape(&r.display_name), md_escape(&r.version));
    }

    let _ = writeln!(o, "\n## Package sources\n");
    let _ = writeln!(o, "| Source | Installed | Updates | Status |\n|---|---:|---:|---|");
    for m in report.managers.iter().filter(|m| m.available) {
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} |",
            m.id.display_name(),
            m.installed.len(),
            m.updates.len(),
            md_escape(m.error.as_deref().unwrap_or("ok"))
        );
    }

    if let Some(a) = analysis {
        let s = &a.summary;
        let _ = writeln!(o, "\n## Findings\n");
        let _ = writeln!(
            o,
            "**{} critical, {} high, {} medium, {} low, {} info.** {} updates available ({} security). {} advisories matched, {} actively exploited (CISA KEV).\n",
            s.critical,
            s.high,
            s.medium,
            s.low,
            s.info,
            s.updates_available,
            s.security_updates,
            s.advisories,
            s.kev_advisories
        );
        for n in scan_notes(report, a) {
            let _ = writeln!(o, "> **{}**\n", md_escape(&n));
        }
        let _ = writeln!(o, "| Severity | Finding | Category | Fix |\n|---|---|---|---|");
        for f in &a.findings {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} |",
                f.severity,
                md_escape(&f.title),
                f.category.label(),
                md_escape(f.remediation.as_ref().map(|r| r.summary.as_str()).unwrap_or("—"))
            );
        }
        let notable: Vec<&Finding> = a.findings.iter().filter(|f| f.severity >= Severity::High).collect();
        if !notable.is_empty() {
            let _ = writeln!(o, "\n### Why these matter\n");
            for f in notable {
                let _ = writeln!(
                    o,
                    "- **{}** ({}): {}",
                    md_escape(&f.title),
                    f.severity,
                    md_escape(&f.rationale)
                );
            }
        }
        let _ = writeln!(o, "\n### Sources\n");
        for src in &a.sources {
            let _ = writeln!(
                o,
                "- {} {}: {}",
                if src.ok { "✓" } else { "✗" },
                md_escape(&src.name),
                md_escape(&src.detail)
            );
        }
    }

    if let Some(p) = plan {
        let _ = writeln!(o, "\n## Update plan\n");
        if p.actions.is_empty() {
            let _ = writeln!(o, "Nothing to install.");
        } else {
            let _ = writeln!(o, "| # | Update | Severity | Command |\n|---:|---|---|---|");
            for (i, a) in p.actions.iter().enumerate() {
                let _ = writeln!(
                    o,
                    "| {} | {} | {} | {} |",
                    i + 1,
                    md_escape(&a.title),
                    a.severity,
                    md_code_cell(&a.command)
                );
            }
        }
        if !p.excluded.is_empty() {
            let _ = writeln!(o, "\nLeft out:\n");
            for e in &p.excluded {
                let _ = writeln!(o, "- {}: {}", md_escape(&e.title), md_escape(&e.reason));
            }
        }
    }
    if !report.warnings.is_empty() {
        let _ = writeln!(o, "\n## Discovery warnings\n");
        for w in &report.warnings {
            let _ = writeln!(o, "- {}", md_escape(w));
        }
    }
    o
}

pub fn apply_markdown(r: &ApplyReport) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# patchscope apply {}\n", if r.dry_run { "(dry run)" } else { "" });
    let _ = writeln!(
        o,
        "Started {}, finished {}.\n",
        md_escape(&r.started_at),
        md_escape(&r.finished_at)
    );
    let _ = writeln!(o, "| Update | Status | Detail |\n|---|---|---|");
    for x in &r.results {
        let _ = writeln!(
            o,
            "| {} | {} | {} |",
            md_escape(&x.title),
            x.status.label(),
            md_escape(&x.message)
        );
    }
    for w in &r.warnings {
        let _ = writeln!(o, "\n**Warning:** {}", md_escape(w));
    }
    o
}

/// HTML text, with hidden and control characters (which a browser would
/// apply, e.g. a right-to-left override) shown as escapes.
fn h(s: &str) -> String {
    display_safe_multiline(s)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Only http(s) links are rendered as links.
fn link(url: &str) -> String {
    if url.starts_with("https://") || url.starts_with("http://") {
        format!("<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>", h(url), h(url))
    } else {
        h(url)
    }
}

/// "a", "a and b", "a, b and c".
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The one-line notice that a scan is incomplete: which research sources
/// and which package managers could not be (fully) queried. `None` when
/// both were complete.
pub fn incomplete_notice(report: &SystemReport, a: &Analysis) -> Option<String> {
    let sources = a.incomplete_sources();
    let managers = report.incomplete_managers();
    let names: Vec<&str> = sources
        .iter()
        .map(|s| s.name.as_str())
        .chain(managers.iter().map(|m| m.id.display_name()))
        .collect();
    Some(match (sources.is_empty(), managers.is_empty()) {
        (true, true) => return None,
        (false, true) => format!(
            "Research incomplete: {} could not be fully queried, so findings may be missing or rated too low (see Sources).",
            and_list(&names)
        ),
        (true, false) => format!(
            "Scan incomplete: {} could not be fully queried, so updates and findings may be missing.",
            and_list(&names)
        ),
        (false, false) => format!(
            "Scan incomplete: {} could not be fully queried, so updates and findings may be missing or rated too low (see Sources).",
            and_list(&names)
        ),
    })
}

/// One-line notes that belong above any findings list: a scan that was
/// incomplete (research or package managers), and research served from the
/// offline cache.
pub fn scan_notes(report: &SystemReport, a: &Analysis) -> Vec<String> {
    let mut notes = Vec::new();
    notes.extend(incomplete_notice(report, a));
    if a.offline {
        notes.push("Offline: research data comes from the local cache (see Sources for how old it is).".into());
    }
    notes
}

const CSS: &str = r#"
:root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#6b6b70;--card:#fff;--line:#e4e4e7;
--critical:#b42318;--high:#c4320a;--medium:#a15c07;--low:#2e6bc6;--info:#6b6b70}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececf0;--muted:#a0a0a8;--card:#1d1d21;--line:#2e2e34;
--critical:#ff6b5e;--high:#ff8a4c;--medium:#e3b341;--low:#6ea8fe;--info:#a0a0a8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{margin:0 0 4px;font-size:26px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:26px}.sev-critical b,.pill.critical{color:var(--critical)}.sev-high b,.pill.high{color:var(--high)}
.sev-medium b,.pill.medium{color:var(--medium)}.sev-low b,.pill.low{color:var(--low)}.pill.info{color:var(--info)}
.pill{font-weight:600;text-transform:uppercase;font-size:12px;letter-spacing:.04em}
section{margin-top:28px}.table{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}tr:last-child td{border-bottom:0}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0}
summary{cursor:pointer;font-weight:600}code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
a{color:var(--low)}.note{border-left:4px solid var(--high);background:var(--card);padding:8px 12px;border-radius:6px}"#;

pub fn html(report: &SystemReport, analysis: Option<&Analysis>, plan: Option<&UpdatePlan>) -> String {
    let mut o = String::new();
    let hw = &report.hardware;
    let _ = write!(
        o,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<title>patchscope report</title><style>{CSS}</style></head><body><main>"
    );
    let _ = write!(
        o,
        "<h1>patchscope report</h1><p class=\"muted\">{} · generated {} · patchscope {}</p>",
        h(&report.os.name),
        h(&report.generated_at),
        h(&report.tool_version)
    );
    if let Some(a) = analysis {
        let s = &a.summary;
        let _ = write!(o, "<div class=\"grid\">");
        for sev in Severity::DESCENDING {
            let _ = write!(
                o,
                "<div class=\"tile sev-{0}\"><b>{1}</b>{0}</div>",
                sev.as_str(),
                s.count(sev)
            );
        }
        let _ = write!(
            o,
            "<div class=\"tile\"><b>{}</b>updates ({} security)</div><div class=\"tile\"><b>{}</b>exploited (KEV)</div></div>",
            s.updates_available, s.security_updates, s.kev_advisories
        );
        for n in scan_notes(report, a) {
            let _ = write!(o, "<p class=\"note\"><b>{}</b></p>", h(&n));
        }
    }
    let _ = write!(o, "<section><h2>System</h2><div class=\"table\"><table>");
    let mut row = |k: &str, v: String| {
        let _ = write!(o, "<tr><th>{}</th><td>{}</td></tr>", h(k), h(&v));
    };
    row("Operating system", report.os.name.clone());
    if let Some(b) = &report.os.build {
        row("Build", b.clone());
    }
    row("Kernel", report.os.kernel.clone());
    row("Architecture", report.os.arch.clone());
    if let Some(m) = &hw.model {
        row("Model", m.clone());
    }
    if let Some(f) = &hw.firmware {
        row("Firmware", f.clone());
    }
    row(
        "CPU",
        format!("{} · {} logical cores", hw.cpu.brand, hw.cpu.logical_cores),
    );
    row("Memory", human_bytes(hw.memory.total_bytes));
    for d in &hw.disks {
        row(
            &format!("Disk {}", d.mount_point),
            format!(
                "{} free of {} · {}",
                human_bytes(d.available_bytes),
                human_bytes(d.total_bytes),
                d.file_system
            ),
        );
    }
    for g in &hw.gpus {
        row("GPU", g.clone());
    }
    for r in &report.runtimes {
        row(&r.display_name, r.version.clone());
    }
    let _ = write!(o, "</table></div></section>");

    if let Some(a) = analysis {
        let _ = write!(o, "<section><h2>Findings</h2>");
        for f in &a.findings {
            let _ = write!(
                o,
                "<details><summary><span class=\"pill {0}\">{0}</span> {1} <span class=\"muted\">· {2}</span></summary><p>{3}</p>",
                f.severity.as_str(),
                h(&f.title),
                h(f.category.label()),
                h(&f.rationale)
            );
            if let Some(r) = &f.remediation {
                let _ = write!(o, "<p><b>Fix:</b> {}</p>", h(&r.summary));
            }
            if !f.advisories.is_empty() {
                let _ = write!(
                    o,
                    "<div class=\"table\"><table><tr><th>Advisory</th><th>Score</th><th>Exploitation</th><th>Fixed in</th></tr>"
                );
                for adv in &f.advisories {
                    let score = adv
                        .cvss_score
                        .map(|c| format!("CVSS {c:.1}"))
                        .or_else(|| adv.database_severity.clone())
                        .unwrap_or_else(|| "—".into());
                    let mut ex = Vec::new();
                    if adv.kev {
                        ex.push("CISA KEV".to_string());
                    }
                    if let Some(e) = adv.epss {
                        ex.push(format!("EPSS {:.1}%", e * 100.0));
                    }
                    let _ = write!(
                        o,
                        "<tr><td>{} {}<br><span class=\"muted\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        link(&adv.url),
                        h(&adv.cves().join(", ")),
                        h(adv.summary.as_deref().unwrap_or("")),
                        h(&score),
                        h(&ex.join(", ")),
                        h(&adv.fixed_versions.join(", "))
                    );
                }
                let _ = write!(o, "</table></div>");
            }
            for r in &f.references {
                let _ = write!(o, "<p class=\"muted\">{}</p>", link(r));
            }
            let _ = write!(o, "</details>");
        }
        let _ = write!(o, "<h3>Sources</h3><ul>");
        for s in &a.sources {
            let _ = write!(
                o,
                "<li>{} <b>{}</b>: {}</li>",
                if s.ok { "✓" } else { "✗" },
                h(&s.name),
                h(&s.detail)
            );
        }
        let _ = write!(o, "</ul></section>");
    }
    if let Some(p) = plan {
        let _ = write!(o, "<section><h2>Update plan</h2>");
        if p.actions.is_empty() {
            let _ = write!(o, "<p>Nothing to install.</p>");
        } else {
            let _ = write!(
                o,
                "<div class=\"table\"><table><tr><th>#</th><th>Update</th><th>Severity</th><th>Command</th></tr>"
            );
            for (i, a) in p.actions.iter().enumerate() {
                let _ = write!(
                    o,
                    "<tr><td>{}</td><td>{}</td><td><span class=\"pill {2}\">{2}</span></td><td><code>{3}</code></td></tr>",
                    i + 1,
                    h(&a.title),
                    a.severity.as_str(),
                    h(&a.command)
                );
            }
            let _ = write!(o, "</table></div>");
        }
        if !p.excluded.is_empty() {
            let _ = write!(o, "<h3>Left out</h3><ul>");
            for e in &p.excluded {
                let _ = write!(o, "<li>{}: {}</li>", h(&e.title), h(&e.reason));
            }
            let _ = write!(o, "</ul>");
        }
        let _ = write!(o, "</section>");
    }
    let _ = write!(o, "</main></body></html>");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escapes_and_only_links_http() {
        assert_eq!(h("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
        assert!(link("javascript:alert(1)").starts_with("javascript"));
        assert!(!link("javascript:alert(1)").contains("<a"));
        assert!(link("https://osv.dev/x").contains("href=\"https://osv.dev/x\""));
        assert_eq!(md_escape("a|b\nc"), "a\\|b c");
    }

    /// Link, image beacon, raw HTML, emphasis, a code-span break-out, a
    /// carriage return and a right-to-left override.
    const CRAFTED: &str = "`x` [a](https://e.test/l) ![b](https://e.test/i.png) <img src=x> **y**\r\u{202e}z";

    fn crafted() -> (SystemReport, Analysis, UpdatePlan) {
        let report = SystemReport {
            schema_version: SCHEMA_VERSION,
            tool_version: CRAFTED.into(),
            generated_at: CRAFTED.into(),
            host: HostInfo::default(),
            os: OsInfo {
                family: OsFamily::Macos,
                name: CRAFTED.into(),
                version: "26".into(),
                build: Some(CRAFTED.into()),
                kernel: CRAFTED.into(),
                arch: CRAFTED.into(),
                distro_id: None,
                distro_version_id: None,
                edition: None,
            },
            hardware: HardwareInfo {
                model: Some(CRAFTED.into()),
                gpus: vec![CRAFTED.into()],
                battery: Some(BatteryInfo {
                    cycle_count: None,
                    condition: Some(CRAFTED.into()),
                    max_capacity_percent: None,
                }),
                ..Default::default()
            },
            runtimes: vec![Runtime {
                product: "python".into(),
                display_name: CRAFTED.into(),
                version: CRAFTED.into(),
                path_command: "python3".into(),
            }],
            managers: vec![],
            warnings: vec![CRAFTED.into()],
        };
        let finding = Finding {
            id: "x".into(),
            severity: Severity::High,
            category: Category::Vulnerability,
            title: CRAFTED.into(),
            manager: None,
            subject: CRAFTED.into(),
            installed_version: None,
            rationale: CRAFTED.into(),
            advisories: vec![],
            remediation: None,
            risk_score: 0.0,
            references: vec![],
        };
        let analysis = Analysis {
            schema_version: SCHEMA_VERSION,
            generated_at: CRAFTED.into(),
            offline: false,
            sources: vec![SourceStatus {
                name: CRAFTED.into(),
                ok: true,
                detail: CRAFTED.into(),
            }],
            summary: Summary::default(),
            findings: vec![finding],
        };
        let action = |command: &str| crate::plan::PlannedAction {
            key: "softwareupdate:x".into(),
            manager: ManagerId::Softwareupdate,
            title: CRAFTED.into(),
            severity: Severity::High,
            finding_ids: vec![],
            updates: vec![],
            command: command.into(),
            needs_elevation: true,
            restart_required: false,
        };
        let plan = UpdatePlan {
            generated_at: "2026-10-04T00:00:00Z".into(),
            actions: vec![
                action("softwareupdate --install 'a`b ``c <img src=x>'"),
                action("`starts with a backtick"),
            ],
            excluded: vec![crate::plan::Excluded {
                key: "k".into(),
                title: CRAFTED.into(),
                reason: CRAFTED.into(),
            }],
        };
        (report, analysis, plan)
    }

    /// `needle` occurs in `md` without a backslash escaping its first character.
    fn unescaped(md: &str, needle: &str) -> bool {
        md.match_indices(needle)
            .any(|(i, _)| !md[..i].ends_with('\\') || md[..i].ends_with("\\\\"))
    }

    #[test]
    fn markdown_text_cannot_inject_markup() {
        let (r, a, mut p) = crafted();
        // Commands are code spans, where `<img` is literal; tested below.
        for x in &mut p.actions {
            x.command = "plain".into();
        }
        let md = markdown(&r, Some(&a), Some(&p));
        for needle in ["](", "<img", "**y", "`x`"] {
            assert!(!unescaped(&md, needle), "unescaped {needle:?} in:\n{md}");
        }
        assert!(md.contains(r"\[a\](https://e.test/l)"), "{md}");
        assert!(md.contains(r"!\[b\]"), "{md}");
        assert!(md.contains(r"\<img src=x\>"), "{md}");
        assert!(!md.contains('\r') && !md.contains('\u{202e}'), "{md:?}");
        assert!(md.contains(r"\\u{202e}z"), "the override is shown, escaped: {md}");
        // Every table row is still one line with its own cells.
        for line in md.lines().filter(|l| l.starts_with("| ")) {
            assert!(line.ends_with(" |"), "broken row: {line}");
        }
    }

    #[test]
    fn markdown_commands_stay_inside_their_code_span() {
        let (r, a, p) = crafted();
        let md = markdown(&r, Some(&a), Some(&p));
        // The longest backtick run inside is two, so the fence is three.
        assert!(
            md.contains("| ```softwareupdate --install 'a`b ``c <img src=x>'``` |"),
            "{md}"
        );
        // Content that starts with a backtick is padded with a space.
        assert!(md.contains("| `` `starts with a backtick `` |"), "{md}");
        assert_eq!(md_code_cell("a|b"), r"`a\|b`");
    }

    #[test]
    fn html_cannot_be_reordered_by_bidi_controls() {
        let (r, a, p) = crafted();
        let html = html(&r, Some(&a), Some(&p));
        assert!(!html.contains('\u{202e}') && !html.contains('\r'), "{html:?}");
        assert!(!html.contains("<img"));
    }
}
