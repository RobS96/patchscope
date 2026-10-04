# Safety model

patchscope changes software on the machine it runs on, usually with
administrator rights. This page sets out what it will and will not do.

## Read-only until you confirm

| Step | Changes the system? | Privileges |
|---|---|---|
| `discover` / scan | No. Listing commands only (`brew list`, `dpkg-query`, `winget list`, …). | none |
| research | No. HTTPS requests to the four public sources. | none |
| `plan` | No | none |
| `refresh` | Package *metadata* only (`apt-get update` …) | root for APT/DNF |
| `apply --dry-run` | No. Prints each command. | none |
| `apply` | **Yes**, after confirmation: the CLI asks (or needs `--yes`), the app shows a dialog listing every command. | per command |

## What `apply` runs

Exactly the package manager's own update command for each selected update,
shown before it runs:

| Source | Command |
|---|---|
| Homebrew | `brew upgrade --formula NAME` / `brew upgrade --cask NAME` |
| Mac App Store | `mas upgrade ID` |
| macOS Software Update | `softwareupdate --install LABEL` (root; `--agree-to-license` only for an allowed major upgrade; never `--restart`). On Apple silicon, macOS updates are left to System Settings, which can ask for the owner's password. |
| APT | `apt-get install --only-upgrade --no-remove -y -o APT::Get::Always-Include-Phased-Updates=true -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold NAME` (root, `DEBIAN_FRONTEND=noninteractive`; locally edited config files are kept; an upgrade that would remove a package fails instead) |
| DNF | `dnf upgrade -y NAME` (root) |
| pacman | `pacman -Syu --noconfirm` (root; Arch does not support partial upgrades, so it is one whole-system action, planned only when every pending pacman update is selected and allowed by the policy) |
| Flatpak | `flatpak update -y --noninteractive APP` |
| Snap | `snap refresh NAME` (root) |
| winget | `winget upgrade --id ID --exact --silent --accept-package-agreements …` |
| Chocolatey | `choco upgrade NAME -y --no-progress` (Administrator) |
| Windows Update | a PowerShell script that searches for the one UpdateID, downloads and installs it (Administrator) |
| npm (global) | `npm install --global NAME@VERSION` |
| rustup | `rustup update TOOLCHAIN` / `rustup self update` |

`--only-upgrade` and the per-package forms never install software that is
not already there. patchscope never removes packages and never restarts
the machine.

## Injection resistance

- Commands are spawned with an argument vector, never through a shell, so
  a package name is always one argument.
- Every identifier is checked against what its own manager lists before
  it is planned: package-name characters only for APT, DNF, pacman, Snap,
  Flatpak, winget and Chocolatey (so no `./file.deb`, `/tmp/x.rpm`,
  `https://…` or `name=version`), narrowed per manager to what it really
  lists: Debian package names (optionally `:arch`) for APT, so no trailing
  `-` (which asks apt-get to remove the package) and no `~`/`?` patterns;
  no `@group` or `module:stream` for DNF; never `all` for Chocolatey;
  toolchain names for rustup. `user/tap/name` but no paths or URLs for
  Homebrew; digits for the App Store; the npm grammar, and a plain version
  (`1.2.8`, not a URL, `npm:`, `github:` or `file:` spec) after the `@`;
  GUIDs for Windows Update. Anything starting with `-` or containing
  control characters is refused everywhere.
- A saved scan is trusted only for which updates to install.
  `apply --from scan.json` refuses a scan taken on another OS install
  (name, version, kernel or build differ), then asks each manager with a
  selected update again: an update it no longer offers is left out ("no
  longer offered by …"), and what is installed (kind, version, restart,
  notes) and the OS details the policy checks come from this machine, not
  the file. A crafted id (such as a Homebrew tap formula, which brew would
  fetch and evaluate) is therefore never planned unless the manager itself
  lists it.
- Windows UpdateIDs must be GUIDs before they are placed in the
  PowerShell script, which re-checks them itself.
- The macOS administrator prompt quotes each argument for the shell and
  then escapes it for AppleScript (tested with quotes and backslashes).
- HTML reports escape all text, link only `http(s)` URLs, carry a
  `Content-Security-Policy` that forbids scripts, and load nothing external.

## Privileges

patchscope never stores or handles passwords. When a command needs root it
is wrapped with the method you choose. Neither the wrapper nor the program
it runs is looked up on `PATH`: `sudo`, `pkexec` and `osascript` are run by
absolute path, and so is every program that runs as root
(`/usr/sbin/softwareupdate`, `/usr/bin/apt-get`, `/usr/bin/dnf`,
`/usr/bin/pacman`, `/usr/bin/snap`, the paths every mainstream system
installs them at). This matters because macOS's `sudo` has no
`secure_path` and `pkexec` resolves a bare name on the caller's `PATH`,
where a user-writable directory such as Homebrew's `/usr/local/bin` can come
first. A privileged command whose program is not an absolute path is
refused, not run. The methods:

| Method | Where | How |
|---|---|---|
| `sudo` | macOS/Linux terminal (default) | prompts on the terminal |
| `sudo-non-interactive` | unattended | `sudo -n`; fails instead of prompting |
| `pkexec` | Linux desktop (app default) | polkit's graphical prompt |
| `macos-prompt` | macOS app (default) | the system administrator dialog via `osascript` |
| `none` | already root / Administrator | nothing; privileged actions are skipped with a message if not elevated |

Windows has no per-command elevation: run patchscope elevated to install
Windows Update and Chocolatey updates. Unelevated, those are *skipped*
(reported, not failed silently) and winget updates still install. Whether
the process is elevated is read from its token (`whoami /groups`, run from
`System32`: High or System integrity level), so it does not depend on the
Server service that `net session` needs.

## The policy guardrails

See [the policy file](user-guide.md#policy). The defaults protect Xcode and
its Command Line Tools (your own list adds to them) and exclude major OS
upgrades. A policy file with an unknown key or bad
value is rejected, never partially applied: the CLI stops, and the app
shows the error on the Updates tab and in the confirmation dialog, ticks
nothing and turns Install off (dry runs still work) until a valid policy is
saved.

## Verification, audit, locking

- **Verify:** after installing, every manager that installed something
  is queried again. An update still offered becomes **failed** ("command
  succeeded but … still lists"), unless it needs a restart to finish.
- **Audit log:** every action, including dry runs, is appended as one
  JSON line (time, command, status, exit code, duration, message) to
  `audit.jsonl` in the local data directory. On macOS/Linux the file is
  created with mode `0600`, and an existing file is set back to `0600`. If
  the log cannot be opened for appending (for example because an earlier
  run under `sudo` left it owned by root), `apply` refuses to start and
  installs nothing; a dry run carries on with a warning. A write that fails
  during a run is shown as a warning and listed in the result.
- **Lock:** `apply.lock` stops two applies from overlapping. The run holds
  an operating-system lock on the file from start to finish; the system
  releases it when patchscope exits, however it exits (including Ctrl-C at
  a `sudo` prompt or a crash), so a leftover file never blocks a later run
  and a long run is never treated as stale. The file itself stays in place.

## Time limits

Every command has a timeout (listing: 30 s–15 min depending on the tool;
installs: up to 2 h for OS updates). A command that times out gets
SIGTERM (which `sudo` and `pkexec` pass on to the root command, so a
package manager can exit without leaving its database locked), then 20 s
later SIGKILL, for its whole process group on Unix (`taskkill /T` on
Windows), so a hung helper cannot stall patchscope. If an administrator
command times out, patchscope cannot be sure the root process stopped, so
the remaining updates are not started. Every
HTTP request is limited to 90 s and 64 MB.

## Network and TLS

TLS 1.3 (1.2 fallback) via rustls with the aws-lc-rs provider, which
prefers the hybrid post-quantum key exchange X25519MLKEM768. Certificates
are checked against the operating system's trust store, or the PEM bundle
named by `SSL_CERT_FILE`. Only the four research hosts are contacted:
`api.osv.dev`, `www.cisa.gov`, `api.first.org`, `endoflife.date`.

## Supply chain of patchscope itself

`#![forbid(unsafe_code)]` in all crates; `cargo deny` (advisories, licences,
sources) and `cargo vet` gate every change; CodeQL scans Rust and the
workflows; GitHub Actions are pinned to commit SHAs with read-only default
tokens; releases are built by CI from signed tags, carry SLSA build
provenance attestations and per-platform SHA-256 sums, and ship a CycloneDX
SBOM in every archive.
