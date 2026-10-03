//! Human-readable reports: Markdown (for tickets and pull requests) and a
//! self-contained HTML page (no scripts, no external assets).

use crate::apply::ApplyReport;
use crate::model::*;
use crate::plan::UpdatePlan;
use crate::util::human_bytes;
use std::fmt::Write;

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn markdown(report: &SystemReport, analysis: Option<&Analysis>, plan: Option<&UpdatePlan>) -> String {
    let mut o = String::new();
    let hw = &report.hardware;
    let _ = writeln!(o, "# patchscope report\n");
    let _ = writeln!(
        o,
        "Generated {} by patchscope {}.\n",
        report.generated_at, report.tool_version
    );
    let _ = writeln!(o, "## System\n");
    let _ = writeln!(o, "| | |\n|---|---|");
    let _ = writeln!(o, "| Operating system | {} |", md_escape(&report.os.name));
    if let Some(b) = &report.os.build {
        let _ = writeln!(o, "| Build | {} |", md_escape(b));
    }
    let _ = writeln!(o, "| Kernel | {} |", md_escape(&report.os.kernel));
    let _ = writeln!(o, "| Architecture | {} |", report.os.arch);
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
            b.condition.clone().unwrap_or_default(),
            b.max_capacity_percent
                .map(|p| format!("{p}% capacity"))
                .unwrap_or_default(),
            b.cycle_count.map(|c| format!("{c} cycles")).unwrap_or_default()
        );
    }
    for r in &report.runtimes {
        let _ = writeln!(o, "| {} | {} |", r.display_name, r.version);
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
                src.name,
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
                    "| {} | {} | {} | `{}` |",
                    i + 1,
                    md_escape(&a.title),
                    a.severity,
                    md_escape(&a.command)
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
    let _ = writeln!(o, "Started {}, finished {}.\n", r.started_at, r.finished_at);
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
    o
}

fn h(s: &str) -> String {
    s.replace('&', "&amp;")
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
a{color:var(--low)}"#;

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
}
