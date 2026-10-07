# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-10-07

### Added

- CI reports test coverage (lines, regions, functions; cargo-llvm-cov) on
  every change and weekly, and Dependabot keeps the fuzz targets'
  lockfile current.

### Changed

- `scan` and `plan` also exit with 4 when an installed package manager
  could not be fully queried (its listing failed or timed out), not only
  when a research source failed: such a scan never saw that manager's
  updates. `--allow-partial` accepts it; a manager that is not installed,
  disabled by policy or skipped with `--skip-manager` does not count. The
  notice reads "Scan incomplete: …" and names the managers.

### Security

- The desktop app shows text patchscope did not write with control,
  invisible and bidirectional characters escaped, as the terminal and
  reports already do, including in the install confirmation.
- Windows: Chocolatey and Windows PowerShell are run by absolute path
  (`%ProgramData%\chocolatey\bin\choco.exe`,
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`) instead
  of being found on `PATH` while patchscope runs as Administrator.

## [0.1.1] - 2026-10-04

### Added

- Fuzzing: four cargo-fuzz targets (package-manager output, research and
  discovery parsers, the analyse → plan → report pipeline with its safety
  invariants, policy and text utilities), run on every change and weekly.
- Optional Developer ID signing and notarisation of the macOS binaries in
  the release pipeline, behind an approval-gated environment
  (docs/code-signing.md), switched on with one command:
  `scripts/enable-macos-signing.sh <DeveloperID.p12> <AuthKey.p8>`.
- Each release attaches its build provenance attestation as a Sigstore
  bundle (`patchscope-<version>-provenance.sigstore.json`), for
  `gh attestation verify --bundle`.

### Changed

- The end-to-end tests' deliberately vulnerable npm package is checked
  against a pinned integrity hash before it is planted.
- `scan` and `plan` exit with 4 when a research source could not be
  queried (`--allow-partial` accepts that). Each such source is an Info
  finding, and every output says the research was incomplete.

### Fixed

- APT packages of a foreign architecture get their own key (`name:arch`).
- The run lock is an operating-system file lock: an interrupted apply no
  longer blocks the next one for six hours, and a long apply's lock cannot
  be taken over.
- An apply refuses to start if it cannot write its audit log, an existing
  log is made owner-only, and write failures are reported.
- Windows: elevation is read from the process token (`whoami /groups`)
  instead of `net session`, which fails when the Server service is off.
- OSV.dev results beyond the first page are read.
- Advisory records that could not be fetched mark OSV.dev as incomplete
  instead of becoming Medium-severity stubs; the 400-record limit is shared
  across packages.
- winget errors are reported instead of reading as "no updates".
- Flatpak runtimes are listed and updated, not only apps.
- Offline scans say how old their cached data is, and the EPSS limit says
  how many CVEs it left out (the oldest).

### Security

- `apply --from` re-checks a saved scan against this machine. The scan must
  come from this OS (name, version, kernel, build), and each selected update
  must still be offered by its package manager, which supplies the version,
  kind and restart flag that get planned. A crafted or edited scan could
  previously install a package spec of its choosing through npm, remove a
  package through APT (a trailing `-`), make Homebrew tap an arbitrary
  repository, or slip an update past the policy.
- Package identifiers follow each manager's own grammar (APT, DNF, pacman,
  Snap, Flatpak, Chocolatey, rustup), npm versions must be plain versions,
  and `apt-get` runs with `--no-remove`.
- pacman's full-system upgrade is planned only when every pending pacman
  package is selected and allowed by the policy.
- Elevated commands name their program by absolute path, so sudo, pkexec
  and the macOS administrator prompt no longer find it through `PATH`.
- The desktop app blocks installing while the policy file has an error
  (dry runs still work) instead of falling back to the default policy.
- Text patchscope did not write (package names, advisory text, saved-scan
  fields, tool output) is shown with control, invisible and bidirectional
  characters escaped, in the terminal and in Markdown and HTML reports, so
  it cannot hide or reorder what is shown before confirmation. Markdown
  reports also escape links, images, HTML and code spans.

## [0.1.0] - 2026-10-03

### Added

- Discovery on Windows, macOS and Linux: OS identity and build, model,
  firmware, CPU, memory, disks, GPUs, battery, temperatures, network
  interfaces, language runtimes (Python, Node.js, Go, Ruby, PHP).
- Package-source adapters: macOS Software Update, Homebrew, Mac App Store
  (`mas`), Windows Update, winget, Chocolatey, APT, DNF, pacman, Flatpak,
  Snap, npm (global), rustup. All are queried in parallel, every command
  is time-bounded, and a timed-out tool is killed along with its helpers.
- Research: OSV.dev (Debian, Ubuntu, Rocky, Alma, npm), CISA Known
  Exploited Vulnerabilities, FIRST EPSS, endoflife.date (OS and runtime
  lifecycles), with a 12-hour on-disk cache and an offline mode.
- Ranked findings with a documented severity rubric, a 0–100 risk score
  and a plain-language rationale for each finding.
- Policy file (`patchscope.toml`): protected packages (Xcode and its
  Command Line Tools always, unless explicitly turned off),
  major OS upgrades off by default, security-only mode, minimum severity,
  action cap, disabled managers. Strict parsing.
- Planning and applying: exact commands shown before anything runs,
  confirmation, elevation via sudo / sudo -n / pkexec / the macOS
  administrator prompt, post-install verification, JSONL audit log, run
  lock, restart reporting (never restarts).
- `patchscope` CLI: `scan`, `discover`, `plan`, `apply`, `refresh`,
  `managers`, `policy`; text, JSON, Markdown and HTML output; saved scans
  (`--save` / `--from`); meaningful exit codes.
- Desktop app: overview, findings, update selection with confirmation,
  live activity, hardware, software and settings (including a policy
  editor); HTML/Markdown/JSON export.
- Tests: unit, pipeline, GUI (egui_kittest), live research, and
  end-to-end on Windows, macOS, Ubuntu, Debian, Fedora and Arch.
- CI: fmt, clippy, tests on three OSes, MSRV, cargo-deny, cargo-vet,
  CodeQL, OpenSSF Scorecard, dependency review, SBOMs, packaging smoke
  tests, attested releases from signed tags.

[Unreleased]: https://github.com/RobS96/patchscope/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/RobS96/patchscope/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/RobS96/patchscope/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/RobS96/patchscope/releases/tag/v0.1.0
