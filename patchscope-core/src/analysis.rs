//! Analysis: turn a [`SystemReport`] into ranked [`Finding`]s using
//! vulnerability, exploitation and lifecycle evidence.
//!
//! The rubric (documented in `docs/methodology.md`):
//!
//! | Severity | Evidence |
//! |---|---|
//! | Critical | an advisory in CISA KEV; CVSS ≥ 9.0; the OS is past end of support |
//! | High | CVSS 7.0–8.9; EPSS ≥ 10 %; a vendor-flagged security update; a runtime past end of support; OS support ends within the warning window |
//! | Medium | CVSS 4.0–6.9 or unscored advisory; a pending OS update; low disk space; runtime support ending soon |
//! | Low | a newer version with no known advisory; minor hardware notes |
//! | Info | major OS upgrades available, sources that could not be queried |

use crate::discover::{Progress, runtimes};
use crate::model::*;
use crate::research::http::{CachedHttp, HttpClient};
use crate::research::{eol, epss, kev, osv};
use crate::util;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// Use only cached research data; make no network requests.
    pub offline: bool,
    pub cache_dir: Option<PathBuf>,
    pub cache_ttl: Duration,
    /// Most advisory records fetched in full. The rest are listed by id.
    pub max_advisory_details: usize,
    /// Warn this many days before end of support.
    pub eol_warning_days: i64,
    /// Below this much free space on the system volume, updates may fail.
    pub min_free_disk_bytes: u64,
    /// Override "today" (days since 1970-01-01); for tests.
    pub today: Option<i64>,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        AnalyzeOptions {
            offline: false,
            cache_dir: crate::paths::cache_dir(),
            cache_ttl: Duration::from_secs(12 * 3600),
            max_advisory_details: 400,
            eol_warning_days: 90,
            min_free_disk_bytes: 20_000_000_000,
            today: None,
        }
    }
}

/// Map a database's severity word onto the rubric.
fn word_severity(w: &str) -> Option<Severity> {
    Some(match w.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" | "important" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" | "negligible" | "unimportant" => Severity::Low,
        _ => return None,
    })
}

pub fn advisory_severity(a: &Advisory) -> Severity {
    if a.kev {
        return Severity::Critical;
    }
    let cvss = a.cvss_score.map(Severity::from_cvss);
    let word = a.database_severity.as_deref().and_then(word_severity);
    // Distribution trackers rate the issue in their build and configuration,
    // which is closer to this machine than the upstream CVSS score.
    let distro = a.id.starts_with("UBUNTU-") || a.id.starts_with("DEBIAN-");
    let base = if distro { word.or(cvss) } else { cvss.or(word) }.unwrap_or(Severity::Medium);
    if a.epss.is_some_and(|e| e >= 0.10) && base < Severity::High {
        Severity::High
    } else {
        base
    }
}

pub fn advisory_risk(a: &Advisory) -> f64 {
    let base = a.cvss_score.unwrap_or(match advisory_severity(a) {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
        Severity::Info => 0.0,
    });
    let mut r = base * 7.0;
    if a.kev {
        r += 25.0;
    }
    r += a.epss.unwrap_or(0.0) * 25.0;
    r.clamp(0.0, 100.0)
}

/// One OSV query and the installed packages it stands for.
struct Subject {
    query: osv::Query,
    manager: ManagerId,
    binaries: Vec<String>,
}

pub fn analyze(report: &SystemReport, http: &dyn HttpClient, opts: &AnalyzeOptions, progress: Progress) -> Analysis {
    let http = CachedHttp::new(http, opts.cache_dir.clone(), opts.cache_ttl, opts.offline);
    let today = opts.today.unwrap_or_else(util::today_days);
    let mut sources = Vec::new();
    let mut findings = Vec::new();

    // ---- vulnerabilities (OSV), grouped by what OSV indexes
    let mut subjects: BTreeMap<(ManagerId, osv::Query), Vec<String>> = BTreeMap::new();
    let mut covered_managers: HashSet<ManagerId> = HashSet::new();
    for inv in &report.managers {
        for p in &inv.installed {
            let Some(eco) = &p.ecosystem else { continue };
            covered_managers.insert(inv.id);
            let q = osv::Query {
                ecosystem: eco.clone(),
                name: p.source_name.clone().unwrap_or_else(|| p.name.clone()),
                version: p.source_version.clone().unwrap_or_else(|| p.version.clone()),
            };
            subjects.entry((inv.id, q)).or_default().push(p.name.clone());
        }
    }
    let subjects: Vec<Subject> = subjects
        .into_iter()
        .map(|((manager, query), binaries)| Subject {
            query,
            manager,
            binaries,
        })
        .collect();

    // Offline, each source's detail says how old its cached data is.
    let stamp = |detail: String| match http.take_offline_as_of() {
        Some(t) => format!("{detail}; offline, data as of {}", util::rfc3339(t)),
        None => detail,
    };

    let mut advisories: Vec<Vec<Advisory>> = vec![Vec::new(); subjects.len()];
    if !subjects.is_empty() {
        progress(&format!("Checking {} packages against OSV.dev…", subjects.len()));
        let queries: Vec<osv::Query> = subjects.iter().map(|s| s.query.clone()).collect();
        match osv::query_batch(&http, &queries) {
            Ok(batch) => {
                let total: usize = batch.ids.iter().map(Vec::len).sum();
                progress(&format!("Fetching details for {total} advisories…"));
                let details = fetch_details(&http, &subjects, &batch.ids, opts.max_advisory_details);
                advisories = details.advisories;
                let skipped = total.saturating_sub(opts.max_advisory_details);
                let mut detail = format!(
                    "{} packages checked, {total} advisories matched{}",
                    subjects.len(),
                    if skipped > 0 {
                        format!(
                            " ({skipped} listed by id only, over the limit of {} fetched in full)",
                            opts.max_advisory_details
                        )
                    } else {
                        String::new()
                    }
                );
                // A query whose later pages were lost, or an advisory whose
                // record failed to load (so it has no severity or CVE alias
                // for KEV/EPSS), means this research is incomplete.
                if !batch.incomplete.is_empty() {
                    detail.push_str(&format!("; results incomplete for {}", first_few(&batch.incomplete, 3)));
                }
                if details.failed > 0 {
                    detail.push_str(&format!(
                        "; {} advisory record{} could not be fetched and {} listed by id only, without severity or KEV/EPSS matching ({})",
                        details.failed,
                        if details.failed == 1 { "" } else { "s" },
                        if details.failed == 1 { "is" } else { "are" },
                        details.first_error.unwrap_or_default()
                    ));
                }
                sources.push(SourceStatus {
                    name: "OSV.dev".into(),
                    ok: batch.incomplete.is_empty() && details.failed == 0,
                    detail: stamp(detail),
                });
            }
            Err(e) => sources.push(SourceStatus {
                name: "OSV.dev".into(),
                ok: false,
                detail: stamp(e),
            }),
        }
    }
    let uncovered: Vec<&str> = report
        .managers
        .iter()
        .filter(|m| m.available && !m.installed.is_empty() && !covered_managers.contains(&m.id))
        .map(|m| m.id.display_name())
        .collect();
    if !uncovered.is_empty() {
        sources.push(SourceStatus {
            name: "Coverage".into(),
            ok: true,
            detail: format!(
                "No public vulnerability database indexes {}; those are checked for available updates only",
                uncovered.join(", ")
            ),
        });
    }

    // ---- exploitation evidence (KEV, EPSS)
    let all_cves: Vec<String> = {
        let mut set: Vec<String> = advisories.iter().flatten().flat_map(Advisory::cves).collect();
        set.sort();
        set.dedup();
        set
    };
    if !all_cves.is_empty() {
        progress("Checking CISA Known Exploited Vulnerabilities…");
        match kev::fetch(&http) {
            Ok(k) => {
                let mut hits = 0;
                for a in advisories.iter_mut().flatten() {
                    for c in a.cves() {
                        if let Some(e) = k.entries.get(&c) {
                            a.kev = true;
                            a.kev_due_date = e.due_date.clone();
                            a.kev_ransomware |= e.ransomware;
                            hits += 1;
                        }
                    }
                }
                sources.push(SourceStatus {
                    name: "CISA KEV".into(),
                    ok: true,
                    detail: stamp(format!("catalogue {}: {hits} matches", k.version)),
                });
            }
            Err(e) => sources.push(SourceStatus {
                name: "CISA KEV".into(),
                ok: false,
                detail: stamp(e),
            }),
        }
        progress("Fetching EPSS exploit-probability scores…");
        // Newest first: when there are more CVEs than the limit, the oldest
        // (whose exploitation history is best known) are left out.
        let mut capped = all_cves.clone();
        capped.sort_by_key(|c| std::cmp::Reverse(cve_order(c)));
        let dropped = capped.len().saturating_sub(MAX_EPSS_CVES);
        capped.truncate(MAX_EPSS_CVES);
        match epss::fetch(&http, &capped) {
            Ok(scores) => {
                for a in advisories.iter_mut().flatten() {
                    let best = a.cves().iter().filter_map(|c| scores.get(c)).copied().fold(
                        None,
                        |acc: Option<(f64, f64)>, s| {
                            Some(match acc {
                                Some(x) if x.0 >= s.0 => x,
                                _ => s,
                            })
                        },
                    );
                    if let Some((p, pct)) = best {
                        a.epss = Some(p);
                        a.epss_percentile = Some(pct);
                    }
                }
                sources.push(SourceStatus {
                    name: "FIRST EPSS".into(),
                    ok: true,
                    detail: stamp(format!(
                        "{} of {} CVEs scored{}",
                        scores.len(),
                        capped.len(),
                        if dropped > 0 {
                            format!("; {dropped} not sent (the oldest, over the limit of {MAX_EPSS_CVES})")
                        } else {
                            String::new()
                        }
                    )),
                });
            }
            Err(e) => sources.push(SourceStatus {
                name: "FIRST EPSS".into(),
                ok: false,
                detail: stamp(e),
            }),
        }
    }

    // ---- vulnerability findings
    let mut covered_updates: HashSet<String> = HashSet::new();
    for (s, advs) in subjects.iter().zip(advisories) {
        if advs.is_empty() {
            continue;
        }
        let f = vulnerability_finding(report, s, advs);
        if let Some(r) = &f.remediation {
            covered_updates.extend(r.update_keys.iter().cloned());
        }
        findings.push(f);
    }

    // ---- pending updates not already explained by an advisory
    for u in report.all_updates() {
        if !covered_updates.contains(&u.key()) {
            findings.push(update_finding(u));
        }
    }

    // ---- lifecycle
    progress("Checking support lifecycles (endoflife.date)…");
    let mut eol_ok = Vec::new();
    let mut eol_err = Vec::new();
    if let Some(product) = eol::os_product(&report.os) {
        match eol::fetch(&http, product) {
            Ok(p) => {
                eol_ok.push(product.to_string());
                match eol::os_cycle(&report.os, &p) {
                    Some(cycle) => findings.extend(os_lifecycle_findings(report, &p, cycle, today, opts)),
                    None => eol_err.push(format!("{product}: release {} not listed", report.os.version)),
                }
            }
            Err(e) => eol_err.push(e),
        }
    }
    for rt in &report.runtimes {
        match eol::fetch(&http, &rt.product) {
            Ok(p) => {
                eol_ok.push(rt.product.clone());
                if let Some(cycle) = eol::runtime_cycle(rt, &p) {
                    findings.extend(runtime_lifecycle_finding(
                        rt,
                        &eol::status(&p, cycle, &rt.version, today),
                        opts,
                    ));
                }
            }
            Err(e) => eol_err.push(e),
        }
    }
    if !eol_ok.is_empty() || !eol_err.is_empty() {
        sources.push(SourceStatus {
            name: "endoflife.date".into(),
            ok: eol_err.is_empty(),
            detail: stamp(match (eol_ok.is_empty(), eol_err.is_empty()) {
                (_, true) => format!("checked {}", eol_ok.join(", ")),
                (true, false) => format!("failed: {}", eol_err.join("; ")),
                (false, false) => format!("checked {}; failed: {}", eol_ok.join(", "), eol_err.join("; ")),
            }),
        });
    }

    // ---- hardware conditions that affect updating
    findings.extend(hardware_findings(report, opts));

    // ---- managers that could not be queried
    for m in report.incomplete_managers() {
        findings.push(Finding {
            id: format!("coverage:{}", m.id),
            severity: Severity::Info,
            category: Category::Outdated,
            title: format!("{} could not be fully queried", m.id.display_name()),
            manager: Some(m.id),
            subject: m.id.display_name().into(),
            installed_version: m.version.clone(),
            rationale: format!(
                "Results for this source may be incomplete: {}",
                m.error.as_deref().unwrap_or_default()
            ),
            advisories: Vec::new(),
            remediation: None,
            risk_score: 1.0,
            references: Vec::new(),
        });
    }

    // ---- research sources that could not be (fully) queried
    for src in sources.iter().filter(|s| !s.ok) {
        findings.push(Finding {
            id: format!("research:{}", src.name),
            severity: Severity::Info,
            category: Category::Outdated,
            title: format!("Research incomplete: {}", src.name),
            manager: None,
            subject: src.name.clone(),
            installed_version: None,
            rationale: format!(
                "{} could not be fully queried, so findings that depend on it may be missing or rated too low: {}",
                src.name, src.detail
            ),
            advisories: Vec::new(),
            remediation: None,
            risk_score: 1.0,
            references: Vec::new(),
        });
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.risk_score.total_cmp(&a.risk_score))
            .then(a.subject.cmp(&b.subject))
    });

    let mut summary = Summary {
        updates_available: report.all_updates().count(),
        security_updates: report.all_updates().filter(|u| u.security).count(),
        packages_scanned: report.installed_count(),
        ..Default::default()
    };
    for f in &findings {
        match f.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Info => summary.info += 1,
        }
        summary.advisories += f.advisories.len();
        summary.kev_advisories += f.advisories.iter().filter(|a| a.kev).count();
    }
    progress("Analysis complete.");
    Analysis {
        schema_version: SCHEMA_VERSION,
        generated_at: util::now_rfc3339(),
        offline: opts.offline,
        sources,
        summary,
        findings,
    }
}

/// Most CVEs sent to EPSS per scan.
const MAX_EPSS_CVES: usize = 2000;

/// `CVE-2024-12345` → (2024, 12345), for newest-first ordering.
fn cve_order(cve: &str) -> (u32, u64) {
    let mut parts = cve.trim_start_matches("CVE-").splitn(2, '-');
    let year = parts.next().and_then(|y| y.parse().ok()).unwrap_or(0);
    let num = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
    (year, num)
}

/// The first `n` items, then how many more.
fn first_few(items: &[String], n: usize) -> String {
    let mut s = items.iter().take(n).cloned().collect::<Vec<_>>().join("; ");
    if items.len() > n {
        s.push_str(&format!(" and {} more", items.len() - n));
    }
    s
}

struct Details {
    advisories: Vec<Vec<Advisory>>,
    /// Records that should have been fetched in full but could not be.
    failed: usize,
    first_error: Option<String>,
}

/// Fetch advisory records in parallel (8 at a time), at most `cap` in full.
/// The cap is shared round-robin across packages (every package's first
/// advisory, then every package's second, …), so one package with hundreds
/// of advisories (a kernel) cannot use it all up.
fn fetch_details(http: &dyn HttpClient, subjects: &[Subject], ids: &[Vec<String>], cap: usize) -> Details {
    let mut jobs: Vec<(usize, String)> = Vec::new();
    let longest = ids.iter().map(Vec::len).max().unwrap_or(0);
    for k in 0..longest {
        for (i, list) in ids.iter().enumerate() {
            if let Some(id) = list.get(k) {
                jobs.push((i, id.clone()));
            }
        }
    }
    let results: Mutex<Vec<Vec<Advisory>>> = Mutex::new(vec![Vec::new(); subjects.len()]);
    let failures: Mutex<(usize, Option<String>)> = Mutex::new((0, None));
    let next = Mutex::new(0usize);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                loop {
                    let n = {
                        let mut g = next.lock().expect("lock");
                        let n = *g;
                        *g += 1;
                        n
                    };
                    let Some((i, id)) = jobs.get(n) else { break };
                    let subj = &subjects[*i];
                    let adv = if n < cap {
                        osv::fetch_advisory(http, id, &subj.query.ecosystem, &subj.query.name).unwrap_or_else(|e| {
                            let mut f = failures.lock().expect("lock");
                            f.0 += 1;
                            f.1.get_or_insert(e);
                            osv::bare_advisory(id)
                        })
                    } else {
                        osv::bare_advisory(id)
                    };
                    results.lock().expect("lock")[*i].push(adv);
                }
            });
        }
    });
    let mut out = results.into_inner().expect("lock");
    for list in &mut out {
        list.sort_by(|a, b| advisory_risk(b).total_cmp(&advisory_risk(a)).then(a.id.cmp(&b.id)));
    }
    let (failed, first_error) = failures.into_inner().expect("lock");
    Details {
        advisories: out,
        failed,
        first_error,
    }
}

fn vulnerability_finding(report: &SystemReport, s: &Subject, advs: Vec<Advisory>) -> Finding {
    let severity = advs.iter().map(advisory_severity).max().unwrap_or(Severity::Medium);
    let risk = advs.iter().map(advisory_risk).fold(0.0, f64::max);
    let kev: Vec<&Advisory> = advs.iter().filter(|a| a.kev).collect();
    let top = &advs[0];
    let inv = report.manager(s.manager);
    let updates: Vec<&AvailableUpdate> = inv
        .map(|m| {
            m.updates
                .iter()
                .filter(|u| s.binaries.contains(&u.id) || s.binaries.contains(&u.name) || u.id == s.query.name)
                .collect()
        })
        .unwrap_or_default();

    let mut why = format!(
        "OSV.dev lists {} advisor{} affecting {} {} ({}).",
        advs.len(),
        if advs.len() == 1 { "y" } else { "ies" },
        s.query.name,
        s.query.version,
        s.query.ecosystem
    );
    if s.binaries.len() > 1 || s.binaries.first() != Some(&s.query.name) {
        why.push_str(&format!(" Installed from it: {}.", s.binaries.join(", ")));
    }
    why.push_str(&format!(
        " Highest risk: {}",
        top.cves().first().cloned().unwrap_or_else(|| top.id.clone())
    ));
    if let Some(c) = top.cvss_score {
        why.push_str(&format!(" (CVSS {c:.1})"));
    } else if let Some(w) = &top.database_severity {
        why.push_str(&format!(" (rated {w})"));
    }
    why.push('.');
    if !kev.is_empty() {
        why.push_str(&format!(
            " {} {} in CISA's Known Exploited Vulnerabilities catalogue: attackers are using {} now.",
            kev.len(),
            if kev.len() == 1 { "is" } else { "are" },
            if kev.len() == 1 { "it" } else { "them" }
        ));
        if kev.iter().any(|a| a.kev_ransomware) {
            why.push_str(" At least one is used in ransomware campaigns.");
        }
    }
    if let Some((e, p)) = advs
        .iter()
        .filter_map(|a| Some((a.epss?, a.epss_percentile.unwrap_or(0.0))))
        .max_by(|a, b| a.0.total_cmp(&b.0))
    {
        why.push_str(&format!(
            " Highest EPSS: {:.1}% chance of exploitation in 30 days ({:.0}th percentile).",
            e * 100.0,
            p * 100.0
        ));
    }
    let unfixed = advs
        .iter()
        .filter(|a| a.fixed_versions.is_empty() && a.summary.is_some())
        .count();
    let remediation = if updates.is_empty() {
        why.push_str(&format!(
            " {} offers no update for it yet{}.",
            s.manager.display_name(),
            if unfixed > 0 {
                format!("; {unfixed} of these have no released fix")
            } else {
                String::new()
            }
        ));
        None
    } else {
        let to = updates[0].available_version.clone();
        why.push_str(&format!(" {} has an update to {to}.", s.manager.display_name()));
        Some(Remediation {
            update_keys: updates.iter().map(|u| u.key()).collect(),
            to_version: to.clone(),
            summary: format!(
                "Update {} to {to}",
                updates.iter().map(|u| u.name.as_str()).collect::<Vec<_>>().join(", ")
            ),
        })
    };
    let title = if advs.len() == 1 {
        format!(
            "{}: {}",
            s.query.name,
            top.summary.clone().unwrap_or_else(|| top.id.clone())
        )
    } else {
        format!(
            "{} known vulnerabilities in {} {}",
            advs.len(),
            s.query.name,
            s.query.version
        )
    };
    let mut refs: Vec<String> = advs.iter().take(5).map(|a| a.url.clone()).collect();
    for a in &kev {
        for c in a.cves() {
            refs.push(format!("https://nvd.nist.gov/vuln/detail/{c}"));
        }
    }
    Finding {
        id: format!("vuln:{}:{}", s.manager, s.query.name),
        severity,
        category: Category::Vulnerability,
        title,
        manager: Some(s.manager),
        subject: s.query.name.clone(),
        installed_version: Some(s.query.version.clone()),
        rationale: why,
        advisories: advs,
        remediation,
        risk_score: risk,
        references: refs,
    }
}

fn update_finding(u: &AvailableUpdate) -> Finding {
    let from = u.installed_version.clone().unwrap_or_else(|| "installed".into());
    let (severity, category, risk, why) = match u.kind {
        UpdateKind::OsUpgrade => (
            Severity::Info,
            Category::OsUpdate,
            5.0,
            "A new major OS version. Major upgrades change too much to apply unattended, so patchscope reports them but plans them only when the policy allows (`allow_os_upgrades = true`).".to_string(),
        ),
        UpdateKind::OsUpdate | UpdateKind::Firmware if u.security => (
            Severity::High,
            Category::OsUpdate,
            75.0,
            "An operating-system update with security content. OS point releases and cumulative updates fix vulnerabilities across the whole system, many of them exploitable remotely.".to_string(),
        ),
        UpdateKind::OsUpdate | UpdateKind::Firmware => (
            Severity::Medium,
            Category::OsUpdate,
            45.0,
            "A pending operating-system or firmware update.".to_string(),
        ),
        _ if u.security => (
            Severity::High,
            Category::SecurityUpdate,
            70.0,
            format!("{} marks this update as a security update.", u.manager.display_name()),
        ),
        _ => (
            Severity::Low,
            Category::Outdated,
            15.0,
            "A newer version is available. No published advisory is known against the installed version, but staying current keeps future security fixes small and quick to apply.".to_string(),
        ),
    };
    let mut why = why;
    if u.restart_required {
        why.push_str(" A restart is needed to finish installing it.");
    }
    if let Some(n) = &u.notes {
        why.push_str(&format!(" Note: {n}."));
    }
    Finding {
        id: format!("update:{}", u.key()),
        severity,
        category,
        title: format!("{} {} → {}", u.name, from, u.available_version),
        manager: Some(u.manager),
        subject: u.name.clone(),
        installed_version: u.installed_version.clone(),
        rationale: why,
        advisories: Vec::new(),
        remediation: Some(Remediation {
            update_keys: vec![u.key()],
            to_version: u.available_version.clone(),
            summary: format!("Install {} {}", u.name, u.available_version),
        }),
        risk_score: risk,
        references: Vec::new(),
    }
}

fn os_lifecycle_findings(
    report: &SystemReport,
    product: &eol::Product,
    cycle: &eol::Release,
    today: i64,
    opts: &AnalyzeOptions,
) -> Vec<Finding> {
    let os = &report.os;
    let st = eol::status(product, cycle, &os.version, today);
    let mut out = Vec::new();
    let base = |id: &str, severity, title: String, why: String, risk| Finding {
        id: format!("os:{id}"),
        severity,
        category: Category::EndOfLife,
        title,
        manager: None,
        subject: os.name.clone(),
        installed_version: Some(os.version.clone()),
        rationale: why,
        advisories: Vec::new(),
        remediation: None,
        risk_score: risk,
        references: vec![st.page.clone()],
    };
    if st.is_eol {
        out.push(base(
            "eol",
            Severity::Critical,
            format!("{} is no longer supported", st.label),
            format!(
                "Vendor security support for {} ended{}. New vulnerabilities in it will not be fixed, so every other update on this machine sits on an unpatched base. Upgrade to a supported release{}.",
                st.label,
                st.eol_date.as_deref().map(|d| format!(" on {d}")).unwrap_or_default(),
                st.newer_cycle.as_deref().map(|n| format!(" (newest: {n})")).unwrap_or_default()
            ),
            95.0,
        ));
    } else if let Some(days) = st.days_left.filter(|d| *d <= opts.eol_warning_days) {
        out.push(base(
            "eol-soon",
            Severity::High,
            format!("{} support ends in {days} days", st.label),
            format!(
                "Security updates for {} stop on {}. Plan the upgrade now; afterwards this becomes a critical finding.",
                st.label,
                st.eol_date.clone().unwrap_or_default()
            ),
            70.0,
        ));
    }
    // Point releases: meaningful for macOS, whose version names the patch
    // level. Linux point releases arrive as package updates, and Windows
    // patch levels (UBR) are not in the lifecycle data.
    let os_update_pending = report.all_updates().any(|u| u.kind == UpdateKind::OsUpdate);
    if os.family == OsFamily::Macos && st.behind_latest && !os_update_pending {
        let latest = st.latest_in_cycle.clone().unwrap_or_default();
        let mut f = base(
            "behind",
            Severity::Medium,
            format!("{} → {latest} is available", os.name),
            format!(
                "The newest release of this macOS version is {latest}. Software Update did not offer it to this Mac (it may be deferred by device management or not yet visible); install it from System Settings → General → Software Update."
            ),
            50.0,
        );
        f.category = Category::OsUpdate;
        out.push(f);
    }
    if let Some(newer) = &st.newer_cycle
        && !st.is_eol
    {
        let mut f = base(
            "newer",
            Severity::Info,
            format!("A newer major release is available ({newer})"),
            format!(
                "{} is still supported; {} {newer} is the newest release. Major upgrades are reported, never applied automatically.",
                st.label, product.id
            ),
            3.0,
        );
        f.category = Category::OsUpdate;
        out.push(f);
    }
    out
}

fn runtime_lifecycle_finding(rt: &Runtime, st: &eol::Status, opts: &AnalyzeOptions) -> Option<Finding> {
    let (severity, title, why, risk) = if st.is_eol {
        (
            Severity::High,
            format!("{} {} is past end of life", rt.display_name, st.cycle),
            format!(
                "{} {} stopped receiving security fixes{}. Code run with it inherits every vulnerability found since. Move to a supported release line.",
                rt.display_name,
                st.cycle,
                st.eol_date.as_deref().map(|d| format!(" on {d}")).unwrap_or_default()
            ),
            65.0,
        )
    } else if let Some(days) = st.days_left.filter(|d| *d <= opts.eol_warning_days) {
        (
            Severity::Medium,
            format!("{} {} support ends in {days} days", rt.display_name, st.cycle),
            format!(
                "Plan a move off {} {} before {}.",
                rt.display_name,
                st.cycle,
                st.eol_date.clone().unwrap_or_default()
            ),
            40.0,
        )
    } else if st.behind_latest && !runtimes::is_java_product(&rt.product) {
        // Java vendors number their builds their own way (Zulu 25.36.205,
        // Corretto 25.0.4.10.1), so `java -version` can't be compared with
        // the cycle's latest release.
        (
            Severity::Low,
            format!(
                "{} {} → {} is available",
                rt.display_name,
                rt.version,
                st.latest_in_cycle.clone().unwrap_or_default()
            ),
            "A newer patch release of this supported line exists; patch releases usually carry security fixes."
                .to_string(),
            20.0,
        )
    } else {
        return None;
    };
    Some(Finding {
        id: format!("runtime:{}", rt.product),
        severity,
        category: Category::EndOfLife,
        title,
        manager: None,
        subject: format!("{} ({})", rt.display_name, rt.path_command),
        installed_version: Some(rt.version.clone()),
        rationale: format!(
            "{why} Found at {}; update it with the tool that installed it.",
            rt.path_command
        ),
        advisories: Vec::new(),
        remediation: None,
        risk_score: risk,
        references: vec![st.page.clone()],
    })
}

/// The volume OS updates are written to.
fn system_volume(report: &SystemReport) -> Option<&DiskInfo> {
    let disks = &report.hardware.disks;
    let pick = |m: &str| disks.iter().find(|d| d.mount_point.eq_ignore_ascii_case(m));
    match report.os.family {
        OsFamily::Macos => pick("/").or_else(|| pick("/System/Volumes/Data")),
        OsFamily::Windows => pick("C:\\"),
        _ => pick("/"),
    }
}

fn hardware_findings(report: &SystemReport, opts: &AnalyzeOptions) -> Vec<Finding> {
    let mut out = Vec::new();
    let hw = &report.hardware;
    let mk = |id: &str, severity, title: String, why: String, risk| Finding {
        id: format!("hardware:{id}"),
        severity,
        category: Category::Hardware,
        title,
        manager: None,
        subject: hw.model.clone().unwrap_or_else(|| "this machine".into()),
        installed_version: None,
        rationale: why,
        advisories: Vec::new(),
        remediation: None,
        risk_score: risk,
        references: Vec::new(),
    };
    if let Some(d) = system_volume(report)
        && (d.available_bytes < opts.min_free_disk_bytes || d.free_fraction() < 0.10)
    {
        out.push(mk(
            "disk",
            Severity::Medium,
            format!("Low free space on {} ({} free)", d.mount_point, util::human_bytes(d.available_bytes)),
            format!(
                "OS updates need room to download and stage (macOS and Windows feature updates often need 20 GB or more). With {} of {} free, updates may fail part-way. Free up space before applying them.",
                util::human_bytes(d.available_bytes),
                util::human_bytes(d.total_bytes)
            ),
            45.0,
        ));
    }
    if let Some(b) = &hw.battery {
        let bad_condition = b
            .condition
            .as_deref()
            .is_some_and(|c| !matches!(c.to_ascii_lowercase().as_str(), "good" | "normal" | "unknown"));
        let worn = b.max_capacity_percent.is_some_and(|p| p < 80);
        if bad_condition || worn {
            out.push(mk(
                "battery",
                Severity::Low,
                "Battery service recommended".into(),
                format!(
                    "Battery condition {}, {} of design capacity{}. A long OS update on a weak battery can be interrupted; install large updates on mains power.",
                    b.condition.clone().unwrap_or_else(|| "unknown".into()),
                    b.max_capacity_percent.map(|p| format!("{p}%")).unwrap_or_else(|| "unknown".into()),
                    b.cycle_count.map(|c| format!(", {c} cycles")).unwrap_or_default()
                ),
                12.0,
            ));
        }
    }
    let hot: Vec<&Temperature> = hw.temperatures.iter().filter(|t| t.celsius >= 95.0).collect();
    if !hot.is_empty() {
        out.push(mk(
            "thermal",
            Severity::Low,
            "Components running very hot".into(),
            format!(
                "{} sensor(s) at or above 95 °C (hottest: {} at {:.0} °C). Check cooling before long update runs.",
                hot.len(),
                hot[0].label,
                hot[0].celsius
            ),
            10.0,
        ));
    }
    out
}

/// Findings that reference an update, keyed by update key, for the plan.
pub fn findings_by_update(analysis: &Analysis) -> HashMap<String, Vec<&Finding>> {
    let mut m: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in &analysis.findings {
        if let Some(r) = &f.remediation {
            for k in &r.update_keys {
                m.entry(k.clone()).or_default().push(f);
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::research::http::FakeHttp;

    fn subject(name: &str) -> Subject {
        Subject {
            query: osv::Query {
                ecosystem: "npm".into(),
                name: name.into(),
                version: "1.0.0".into(),
            },
            manager: ManagerId::NpmGlobal,
            binaries: vec![name.into()],
        }
    }

    #[test]
    fn detail_cap_is_shared_across_packages() {
        let http = FakeHttp::new().route(
            "https://api.osv.dev/v1/vulns/",
            r#"{"id":"X","aliases":["CVE-2024-1"]}"#,
        );
        let subjects = [subject("a"), subject("b")];
        let ids: Vec<Vec<String>> = vec![vec!["A1".into(), "A2".into(), "A3".into()], vec!["B1".into()]];
        let _ = fetch_details(&http, &subjects, &ids, 2);
        let sent = http.requests.lock().unwrap().clone();
        assert!(
            sent.iter().any(|r| r.ends_with("/vulns/B1")),
            "b's only advisory is fetched although a sorts first and has more: {sent:?}"
        );
    }

    #[test]
    fn java_lifecycle_findings_skip_patch_level() {
        let today = util::days_from_civil(2026, 10, 7);
        let body = br#"{"result":{"releases":[{"name":"25","eolFrom":"2033-09-30","latest":{"name":"25.36.205"}},{"name":"8","isEol":true,"eolFrom":"2026-03-31","latest":{"name":"8.80.0.17"}}]}}"#;
        let p = eol::parse("azul-zulu", body).unwrap();
        let rt = |version: &str| Runtime {
            product: "azul-zulu".into(),
            display_name: "Java (Azul Zulu)".into(),
            version: version.into(),
            path_command: "/usr/bin/java".into(),
        };
        let opts = AnalyzeOptions::default();
        let old = rt("1.8.0_422");
        let f = runtime_lifecycle_finding(
            &old,
            &eol::status(&p, eol::runtime_cycle(&old, &p).unwrap(), &old.version, today),
            &opts,
        )
        .expect("Java 8 past end of life is reported");
        assert_eq!((f.severity, f.id.as_str()), (Severity::High, "runtime:azul-zulu"));
        assert_eq!(f.title, "Java (Azul Zulu) 8 is past end of life");

        // Zulu's own build number (25.36.205) is not a Java version.
        let cur = rt("25.0.3");
        let st = eol::status(&p, eol::runtime_cycle(&cur, &p).unwrap(), &cur.version, today);
        assert!(st.behind_latest, "the comparison alone would claim an update");
        assert!(runtime_lifecycle_finding(&cur, &st, &opts).is_none());
    }
}
