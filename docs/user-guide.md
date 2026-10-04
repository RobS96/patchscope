# User guide

- [The desktop app](#the-desktop-app)
- [The command line](#the-command-line)
- [The policy file](#policy)
- [Exit codes](#exit-codes)
- [Automating patchscope](#automating-patchscope)
- [Files patchscope writes](#files-patchscope-writes)
- [Troubleshooting](#troubleshooting)

## The desktop app

Start `patchscope-gui` (see the [README](../README.md#2-run-the-app) for
per-OS notes) and click **Scan this computer**. The tabs on the left:

| Tab | What it shows |
|---|---|
| **Overview** | Counts per severity, updates available (and how many are security updates), actively exploited issues, the six most important findings, and the status of each research source. |
| **Findings** | Every finding, filterable by text (package, CVE id …) and minimum severity. Expand one for the reasoning, the advisories (with CVSS, KEV and EPSS), the fixed versions, references and the fix. |
| **Updates** | The plan: every update the policy allows, ticked. *Select all*, *Critical & high only* and *Select none* adjust the ticks. Each row shows the command that will run and badges for **admin** (asks for an administrator password) and **restart**. Updates left out by policy are listed with the reason. |
| **Activity** | Live progress while installing, then each update's result: *verified* (installed and no longer offered), *installed*, *restart needed*, *failed* (with the tool's own output), *skipped* (with why). |
| **Hardware** | Model, firmware, processor, memory, graphics, battery health, storage with free space, temperature sensors, network interfaces, language runtimes. |
| **Software** | Each package source with installed and update counts, and a searchable list of every installed package. |
| **Settings** | Offline mode, whether to include identifiers in reports, how to obtain administrator rights, and the [policy](#policy) editor. |

**Installing.** On **Updates**, tick what you want and click **Install
selected**. A dialog lists every command; nothing runs until you click
**Install now**. Tick **Dry run** first to see the commands without
running them. When it finishes, **Scan again to confirm** re-checks the
machine.

**Exporting.** *Export report* (top right) saves an HTML page, Markdown
or the full scan as JSON to your Downloads folder. A JSON scan can be
reviewed or applied later with `patchscope plan --from` / `apply --from`.

## The command line

```
patchscope [--quiet] [--policy FILE] <command>
```

### `scan`: inventory and research

```bash
patchscope scan                               # human-readable report
patchscope scan --format html -o report.html  # also: json, markdown
patchscope scan --save scan.json              # keep the scan for plan/apply --from
patchscope scan --manager apt --manager snap  # only these sources
patchscope scan --skip-manager mas            # all but these
patchscope scan --offline                     # cached research only, no network
patchscope scan --include-identifiers         # hostname, serial, MAC addresses
patchscope scan --fail-on critical            # exit 2 only for critical findings
```

### `discover`: inventory only

The same inventory without research (no network). `--format json` gives
the full machine-readable report.

### `plan`: what would be installed

```bash
patchscope plan                             # everything the policy allows
patchscope plan --min-severity high         # only updates tied to high/critical findings
patchscope plan --security-only             # only security-relevant updates
patchscope plan --only apt:openssl --only homebrew:git   # exactly these
patchscope plan --from scan.json --format markdown -o plan.md
```

Update keys are `manager:id`, as shown in square brackets in the plan.

### `apply`: install

```bash
patchscope apply --dry-run                  # show the commands, change nothing
patchscope apply                            # show the plan, ask, install, verify
patchscope apply --min-severity critical --yes
patchscope apply --from scan.json --only npm-global:minimist --yes
```

| Option | Meaning |
|---|---|
| `--yes` | Don't ask. Required when stdin is not a terminal. |
| `--elevation sudo\|sudo-non-interactive\|pkexec\|macos-prompt\|none` | How to run commands that need root. Default: `sudo` in a terminal on macOS/Linux. On Windows run patchscope from an elevated terminal. |
| `--no-verify` | Skip re-querying managers afterwards. |
| `--stop-on-failure` | Stop at the first failed update (default: carry on and report). |

The selection options (`--min-severity`, `--only`, `--security-only`) and
`--from` work as for `plan`, except that `apply --from` uses the saved scan
only to pick the updates: it refuses a scan taken on another machine or OS
version, asks each package manager again, leaves out any update no longer
offered, and installs what the manager offers now. On Arch, the single
`pacman -Syu` action is planned only when every pending pacman update is
selected and allowed by the policy, since it upgrades all of them.

### `refresh`

Refreshes package metadata (`apt-get update`, `dnf makecache`,
`brew update`) so the next scan sees the newest versions. Uses
`--elevation` like `apply`.

### `managers`

Lists every supported package source and whether it is present on this
machine.

### `policy`

`patchscope policy show` prints the effective policy; `policy path` where
the file lives; `policy init` writes the default policy there.

## Policy

The policy decides what patchscope may plan and install. It lives in
`patchscope.toml` in the platform config directory (`patchscope policy
path`), or wherever `--policy` points. Every key is optional:

```toml
[apply]
# Never planned or installed, in addition to the defaults (*xcode*,
# mas:497799835). Patterns match "manager:id", "manager:name", the id or
# the name, case-insensitively; * is a wildcard.
protected = ["homebrew:postgresql@*"]
default_protection = true        # false drops the built-in Xcode protection
allow_os_upgrades = false        # new major OS versions
allow_restart_required = true    # updates that need a restart to finish
security_only = false            # only updates tied to a security finding
min_severity = "info"            # skip updates whose findings are all below this
max_actions = 100                # most severe first when capped

[managers]
disabled = ["mas"]               # never queried or updated
```

Defaults: Xcode and the Command Line Tools for Xcode protected (a new
release can drop support for the Mac it runs on, and Xcode is a very large
download), no major OS upgrades, everything else allowed. Your own
`protected` list adds to the defaults; only `default_protection = false`
removes them. **An unknown key or bad value is an error, and so is a
`--policy` file that does not exist**, so a typo can never silently widen
what gets installed.

Manager ids: `softwareupdate`, `windows-update`, `apt`, `dnf`, `pacman`,
`homebrew`, `mas`, `winget`, `chocolatey`, `flatpak`, `snap`,
`npm-global`, `rustup`.

## Exit codes

| Code | `scan` | `apply` / `refresh` |
|---|---|---|
| 0 | no finding at or above `--fail-on` (default `high`) | every action succeeded (or nothing to do) |
| 1 | error (bad option, unreadable file …) | error, or refused (another apply running, no confirmation) |
| 2 | at least one finding at or above `--fail-on` | — |
| 3 | — | at least one action failed or was skipped |

## Automating patchscope

A weekly report as a scheduled task, with no changes made:

```bash
patchscope --quiet scan --format html -o "$HOME/patchscope-$(date +%F).html"
```

Unattended security patching (Linux, as root, from cron or a systemd
timer):

```bash
patchscope --quiet refresh --elevation none
patchscope --quiet apply --security-only --yes --elevation none
```

Use `--elevation sudo-non-interactive` instead when running as a user with
a passwordless sudo rule. Exit code 3 means something needs a look; the
audit log says what.

## Files patchscope writes

| What | Where |
|---|---|
| Policy | config dir: `~/.config/patchscope/` (Linux), `~/Library/Application Support/io.github.RobS96.patchscope/` (macOS), `%APPDATA%\RobS96\patchscope\config\` (Windows) |
| Research cache (12 h) | the platform cache dir (e.g. `~/.cache/patchscope/`) |
| Audit log `audit.jsonl`, lock `apply.lock` | the platform local data dir |
| Reports | only where you ask (`-o`, *Export report*) |

## Troubleshooting

- **"needs Administrator rights" (Windows):** start the app or terminal
  with *Run as administrator*. winget updates install without it; Windows
  Update and Chocolatey need it.
- **A source shows "could not be fully queried":** the tool timed out or
  failed. Its own error is in the finding and in *Discovery notes*. On a
  Mac, `softwareupdate` can take minutes on a slow network; it is given
  five.
- **"another patchscope apply is running":** another patchscope is
  installing right now; wait for it to finish. The lock is released when
  that run exits, however it exits, so there is nothing to delete.
- **"audit log …: Permission denied":** patchscope does not install
  without recording what it does. This usually means an earlier run under
  `sudo` left `audit.jsonl` (or its folder) owned by root; give it back to
  your user (`sudo chown -R "$USER" <folder>`).
- **Research source ✗ / certificate errors behind a corporate proxy:**
  patchscope trusts the operating system's certificate store, or the PEM
  bundle named by `SSL_CERT_FILE` if that is set. `--offline` uses the
  cache only.
- **An update stays "failed: … still lists":** the command succeeded but
  the manager still offers the update. Often it is held back, pinned, or
  needs a newer dependency. The tool's output is in **Activity** and the
  audit log.
