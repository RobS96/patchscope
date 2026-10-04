# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

### Fixed

- APT packages of a foreign architecture get their own key (`name:arch`).

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

[Unreleased]: https://github.com/RobS96/patchscope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RobS96/patchscope/releases/tag/v0.1.0
