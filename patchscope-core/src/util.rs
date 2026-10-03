//! Small helpers: civil dates without a date library, version comparison.

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse `YYYY-MM-DD` (anything after the date is ignored).
pub fn parse_date(s: &str) -> Option<i64> {
    let s = s.get(..10)?;
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| days_from_civil(y, m, d))
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn today_days() -> i64 {
    (unix_now() / 86_400) as i64
}

pub fn format_days(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// RFC 3339 timestamp in UTC for a Unix time.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        format_days(days),
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn now_rfc3339() -> String {
    rfc3339(unix_now())
}

/// The first version-looking token in a tool's `--version` output:
/// `Python 3.12.4` → `3.12.4`, `v22.9.0` → `22.9.0`, `go1.23.1` → `1.23.1`.
pub fn first_version(text: &str) -> Option<String> {
    for tok in text.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')') {
        let t = tok.trim_start_matches('v').trim_start_matches("go");
        if t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains('.') {
            let v: String = t
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            return Some(v.trim_end_matches('.').to_string());
        }
    }
    None
}

/// Compare dotted versions numerically where both sides are numbers
/// (`26.10` > `26.9`), falling back to text comparison per component.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let split = |s: &str| -> Vec<String> { s.split(['.', '-', '+', '_']).map(str::to_string).collect() };
    let (pa, pb) = (split(a), split(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).map(String::as_str).unwrap_or("0");
        let y = pb.get(i).map(String::as_str).unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(n), Ok(m)) => n.cmp(&m),
            _ => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Case-insensitive glob with `*` as the only wildcard.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2026, 10, 3), (2099, 12, 31)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(parse_date("2026-10-03"), Some(days_from_civil(2026, 10, 3)));
        assert_eq!(parse_date("2026-13-03"), None);
        assert_eq!(parse_date("soon"), None);
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_791_034_245), "2026-10-03T13:30:45Z");
    }

    #[test]
    fn versions() {
        assert_eq!(first_version("Python 3.12.4").as_deref(), Some("3.12.4"));
        assert_eq!(first_version("v22.9.0\n").as_deref(), Some("22.9.0"));
        assert_eq!(
            first_version("go version go1.23.1 darwin/amd64").as_deref(),
            Some("1.23.1")
        );
        assert_eq!(
            first_version("ruby 3.3.5 (2024-09-03 revision ef084cc8f4) [x86_64-darwin23]").as_deref(),
            Some("3.3.5")
        );
        assert_eq!(
            first_version("PHP 8.3.11 (cli) (built: Aug 27 2024)").as_deref(),
            Some("8.3.11")
        );
        assert_eq!(first_version("nothing here"), None);
        assert_eq!(compare_versions("26.10", "26.9"), Ordering::Greater);
        assert_eq!(compare_versions("26.7.1", "26.7.1"), Ordering::Equal);
        assert_eq!(compare_versions("26.7", "26.7.1"), Ordering::Less);
        assert_eq!(compare_versions("10.0.26100", "10.0.26200"), Ordering::Less);
    }

    #[test]
    fn globs() {
        assert!(glob_match("xcode*", "Xcode"));
        assert!(glob_match("*xcode*", "Command Line Tools for Xcode 26.5"));
        assert!(glob_match("mas:497799835", "MAS:497799835"));
        assert!(!glob_match("xcode", "xcodes"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn bytes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(16_000_000_000), "16.0 GB");
    }
}
