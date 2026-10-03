# Methodology

How patchscope decides what needs updating, how urgently, and why, and
where its knowledge stops.

## 1. Evidence it gathers

### From the machine (discovery)

| Evidence | How |
|---|---|
| OS name, version, build, kernel, architecture | `sw_vers` (macOS), `/etc/os-release` (Linux), the `CurrentVersion` registry key (Windows), plus `sysinfo` |
| Model, firmware, GPUs, battery | `system_profiler` (macOS), `/sys/class/dmi` + `lspci` + `/sys/class/power_supply` (Linux), CIM `Win32_ComputerSystem`/`Win32_BIOS`/`Win32_VideoController` (Windows) |
| CPU, memory, disks, temperatures, network interfaces | `sysinfo` |
| Language runtimes | `python3`/`python`, `node`, `go`, `ruby`, `php` on `PATH` (on a Mac without developer tools the `/usr/bin` stubs are skipped, since running them opens an install dialog) |
| Installed packages and pending updates | each package manager's own listing commands (see [platform support](platform-support.md)) |

### From public sources (research)

| Source | What it answers | Request |
|---|---|---|
| [OSV.dev](https://osv.dev) | Which published advisories affect *this exact version* of a package | `POST /v1/querybatch` (≤1000 packages per call), `GET /v1/vulns/{id}` for details (8 in parallel, at most 400 per scan) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is the CVE being exploited in the wild? Is it used by ransomware? | the catalogue JSON (~2 MB) |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days | `GET /data/v1/epss?cve=…` (100 CVEs per call) |
| [endoflife.date](https://endoflife.date) | Is this OS / runtime release still supported, until when, and what is its latest patch release? | `GET /api/v1/products/{product}/` |

Responses are cached for 12 hours. `--offline` uses only the cache.

**What leaves the machine:** package names, versions and their ecosystem
(to OSV.dev), CVE ids (to FIRST), and product names (to endoflife.date).
Nothing that identifies the machine or its user.

## 2. Matching

- **Debian and Ubuntu** packages are matched by **source package** and
  source version (`dpkg-query ${source:Package}`), which is how both
  security trackers and OSV index them. One finding covers every binary
  package built from that source. Ubuntu LTS releases use the
  `Ubuntu:24.04:LTS` ecosystem, interim releases `Ubuntu:25.10`.
- **Rocky Linux and AlmaLinux** RPMs: `Rocky Linux:9`, `AlmaLinux:9`.
- **npm** global packages: `npm`.
- Everything else is matched on "the package manager offers a newer
  version" only. See [coverage](#4-limits).

An advisory's **fixed versions** are taken from its `affected` entry for
this package and ecosystem. A vulnerable package whose manager has no
update yet is still reported, with "no update offered yet", and as many of
its advisories as have no released fix.

## 3. Severity and risk

### Per advisory

1. Listed in **CISA KEV** → **Critical**.
2. Otherwise the base severity is:
   - for Debian/Ubuntu records, the distribution's own rating (Ubuntu
     *priority*, Debian *urgency*), which reflects how the package is
     built and configured on that distribution, falling back to CVSS;
   - for everything else, the **CVSS** base score (v3, then v4, then v2)
     computed from the vector, falling back to the database's word
     (GHSA *moderate*/*high* …);
   - *Medium* when there is neither.
3. **EPSS ≥ 10 %** raises anything below High to **High**.

CVSS mapping: ≥ 9.0 Critical, 7.0–8.9 High, 4.0–6.9 Medium, > 0 Low.

### Per finding

A finding's severity is that of its worst advisory. Findings with no
advisory:

| Finding | Severity |
|---|---|
| OS release past end of support | Critical |
| OS update with security content (macOS point release, Windows cumulative/security update, firmware flagged security) | High |
| Update the vendor flags as security (`-security` APT pocket, DNF security advisory, MSRC severity) | High |
| Runtime release past end of life | High |
| OS support ends within 90 days | High |
| Other OS / firmware update | Medium |
| macOS point release exists but Software Update did not offer it | Medium |
| Free space on the system volume < 20 GB or < 10 % | Medium |
| Runtime support ends within 90 days | Medium |
| Newer version, no known advisory | Low |
| Runtime behind the latest patch of its line | Low |
| Battery worn (< 80 % capacity or service condition), sensors ≥ 95 °C | Low |
| New major OS release available | Info |
| A package source could not be queried | Info |

### Risk score (ordering)

Within a severity, findings are ordered by a 0–100 risk score:

```
risk = clamp( 7 × CVSS  +  25 × [in KEV]  +  25 × EPSS , 0, 100 )
```

using the highest-scoring advisory, with a CVSS stand-in of 9.5 / 7.5 /
5.0 / 2.5 for unscored Critical / High / Medium / Low advisories. Findings
with no advisory carry fixed scores (EOL OS 95, security OS update 75,
vendor security update 70, …).

## 4. Limits

- **Coverage.** No public database indexes Homebrew formulae and casks,
  winget, Chocolatey, Mac App Store apps, Flatpak, Snap or Arch packages
  by version. For those, patchscope reports *that an update exists*
  (Low unless the vendor flags it) and says in every report which sources
  had no vulnerability coverage. A vulnerable app from one of these
  sources appears as an outdated package, not a vulnerability.
- **OS-level CVEs** on macOS and Windows are not matched individually
  (neither vendor publishes per-build data to OSV). The OS update
  findings stand in for them: every macOS point release and Windows
  cumulative update fixes security issues, hence High.
- **Fedora and RHEL** RPMs are not matched against OSV (their records do
  not map cleanly to installed versions); DNF's own security advisories
  flag security updates instead.
- **Fixed-version comparison** is the database's. patchscope does not
  re-derive whether the *available* update fixes every advisory; the
  fixed versions are listed so you can see.
- **Firmware** beyond what Software Update / Windows Update deliver
  (e.g. `fwupd`, vendor BIOS tools) is reported as inventory only.
- **Hardware findings** are about updating safely (disk space, battery,
  temperatures), not a hardware health check.
- Research is as good as its sources: an advisory published after the
  cache was filled appears on the next scan after 12 hours, or at once
  after the cache directory is cleared.
