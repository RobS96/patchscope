# Platform support

Release binaries: Windows x86_64 (10/11, Server 2019+), macOS universal
(Intel and Apple silicon, 11+), Linux x86_64 (glibc 2.35+). Other targets
build from source.

## Package sources

| Source | OS | Lists installed with | Lists updates with | Vulnerability data | Needs admin to update |
|---|---|---|---|---|---|
| Software Update | macOS | — | `softwareupdate --list` | OS updates rated by kind | yes |
| Homebrew | macOS, Linux | `brew list --versions` | `brew outdated --json=v2` | no | no (Homebrew refuses root) |
| Mac App Store | macOS | `mas list` | `mas outdated` | no | no |
| Windows Update | Windows | — | Windows Update Agent COM search | MSRC severity | yes |
| winget | Windows | `winget list` | `winget upgrade` | no | no (installers prompt via UAC) |
| Chocolatey | Windows | `choco list -r` | `choco outdated -r` | no | yes |
| APT | Debian, Ubuntu, derivatives | `dpkg-query` | `apt list --upgradable` | OSV (Debian, Ubuntu) + `-security` pocket | yes |
| DNF | Fedora, RHEL, Rocky, Alma | `rpm -qa` | `dnf repoquery --upgrades` + `dnf updateinfo --security` | OSV (Rocky, Alma) + DNF security advisories | yes |
| pacman | Arch and derivatives | `pacman -Q` | `checkupdates` (pacman-contrib) or `pacman -Qu` | no | yes |
| Flatpak | Linux | `flatpak list --app` | `flatpak remote-ls --updates` | no | no |
| Snap | Linux | `snap list` | `snap refresh --list` | no | yes |
| npm (global) | all | `npm ls --global` | `npm outdated --global` | OSV (npm) | no |
| rustup | all | `rustup toolchain list` | `rustup check` | no | no |

`mas` (Mac App Store CLI) and `pacman-contrib` are optional extras the
user installs; patchscope uses them when present.

## Per-OS notes

### macOS

- OS identity from `sw_vers`; hardware from `system_profiler` (model,
  firmware/Boot ROM, GPUs, battery cycles and capacity).
- Every point release within the installed major version is treated as a
  security update (Apple ships security content in all of them). A major
  release (e.g. 26 → 27) is reported as *Info* and only planned when the
  policy sets `allow_os_upgrades = true`.
- On Apple silicon, installing a macOS update needs the volume owner's
  password, which `softwareupdate` can only take on a terminal. patchscope
  reports those updates (and their severity) but leaves them out of the
  plan with a pointer to System Settings → General → Software Update.
  Other Software Update items (e.g. Safari, XProtect) are planned as usual.
- Disk free space is the APFS container's (`/`).

### Windows

- OS identity from the registry (`ProductName` is corrected to Windows 11
  for builds ≥ 22000, which Microsoft leaves as "Windows 10").
- Lifecycle from endoflife.date by build number and edition: Home/Pro →
  `-w` cycles, Enterprise/Education → `-e`, LTSC (`EnterpriseS`) → `-e-lts`.
- winget tables are parsed by column position. If winget truncates a
  package id (very long ids, `…`), that update is reported but left out of
  the plan, because it cannot be installed reliably by id.
- The Windows Update search can take several minutes.

### Linux

- Distribution from `/etc/os-release`; hardware from DMI (`/sys/class/dmi`,
  serial readable only by root), `lspci` and `/sys/class/power_supply`.
- Run `patchscope refresh` (or your usual `apt-get update`) first; without
  fresh metadata the manager cannot know about new versions.
- Arch Linux: updates are always one whole-system `pacman -Syu`. Install
  `pacman-contrib` (and `fakeroot`) for `checkupdates`, which sees new
  versions without syncing the system database; without it patchscope
  falls back to `pacman -Qu`.
- Ubuntu phased updates are included when you explicitly select an update.

## Tested environments

CI runs the full test suite and the end-to-end lifecycle on GitHub-hosted
`ubuntu-24.04`, `macos-26` and `windows-2025`, and system-update
end-to-end runs in `debian:13`, `ubuntu:24.04`, `fedora:44` and
`archlinux:latest` containers. On hosted Windows VMs (no GPU, OpenGL
1.1) the app's window cannot be created, so the Windows "GUI starts"
check is informational; the UI logic is tested there by `cargo test`. See [testing.md](testing.md).
