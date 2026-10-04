# Testing

patchscope installs software with administrator rights, so it is tested at
every level from parsers to real machines.

## Levels

| Level | Where | What it proves | Run it |
|---|---|---|---|
| **Unit** | `patchscope-core/src/**` | Every package-manager parser on recorded output (incl. empty, error, truncated and odd cases); install commands' exact arguments; elevation wrapping and quoting; timeouts kill helper processes; CVSS, KEV, EPSS and lifecycle parsing; policy strictness; date and version maths. | `cargo test -p patchscope-core --lib` |
| **Pipeline** | `patchscope-core/tests/pipeline.rs` | The whole flow with fake commands and recorded API responses: ranking (KEV → Critical, EOL OS → Critical, security OS update → High …), degraded, partial (lost OSV pages, failed advisory records, EPSS limit) and offline research, caching, policy exclusions (Xcode, security-only, severity, explicit keys), option-like ids refused, dry run runs nothing, install → verify → audit (mode 0600), failures and skipped privileged actions, elevation via `sudo -n`, the lock, and a saved scan re-checked against the live managers (crafted ids, kinds, versions, another machine, pacman selections). | `cargo test -p patchscope-core --test pipeline` |
| **CLI** | `patchscope-cli/tests/exit_codes.rs` | `scan` and `plan` exit codes on saved scans (`--from`; no discovery, no network): 0, 2 by `--fail-on`, 4 when research was incomplete, `--allow-partial`. | `cargo test -p patchscope-cli` |
| **GUI** | `patchscope-gui/src/ui_tests.rs` | The real app clicked through its accessibility tree: welcome → scan → findings → narrow selection → confirm → install → verified; cancel installs nothing; dry run; nothing selected disables install; invalid policy refused, valid policy saved and re-planned; every tab renders with and without a scan; HTML export. | `cargo test -p patchscope-gui` |
| **Live research** | `patchscope-core/tests/live.rs` | OSV, KEV, EPSS and endoflife.date still answer in the shape the parsers expect (and the OS trust store works for TLS). | `cargo test -p patchscope-core --test live -- --ignored` |
| **Fuzzing** | `fuzz/` + `patchscope-core/src/fuzzing.rs` | libFuzzer (cargo-fuzz) on four targets: every package-manager adapter fed arbitrary output with every meaningful exit code; the research and discovery parsers on arbitrary JSON/text; arbitrary tool output plus arbitrary API responses through analysis → plan → Markdown/HTML, asserting no invalid identifier is ever planned and no HTML report contains `<script`; the policy and version/date/glob utilities. One minute per target on every change, fifteen weekly; crashing inputs are kept as artifacts. A deterministic stand-in runs the same entry points in `cargo test`. | `cargo +nightly fuzz run --fuzz-dir fuzz pipeline` |
| **End-to-end** | `.github/workflows/e2e.yml` | On Windows, macOS and Ubuntu runners: real inventory; a known-vulnerable npm package found, researched live, dry-run, installed, verified, gone on rescan; reports render; the GUI binary starts and stays up. In Debian 13, Ubuntu 24.04, Fedora 44 and Arch containers: refresh, scan, apply **every** pending system update as root, and the distribution's own manager must then report none left. Runs on every push and weekly. | GitHub Actions |

## Quality gates (every push and pull request)

- `cargo fmt --check`, `cargo clippy -D warnings` on all targets, on all
  three OSes
- the MSRV (Rust 1.95) builds
- `cargo deny check`: advisories, banned sources, licence allow-list
- `cargo vet check`: every dependency audited by a trusted organisation
  or explicitly exempted
- CodeQL default setup, extended query suite (Rust and workflow files),
  OpenSSF Scorecard, dependency review
- release packaging is built and smoke-tested on every run, not just at
  release time

## Why end-to-end runs only in CI

Real installs run only on throwaway CI machines and containers, never on a
developer's workstation. On a workstation, use `patchscope apply --dry-run`
to check what would run.

## Writing tests

- Anything that runs a command must go through `CommandRunner`; test it
  with `FakeRunner::respond("program arg1 arg2", CommandOutput::ok(…))`.
- Anything that fetches must take `&dyn HttpClient`; test it with
  `FakeHttp`. Record real responses into `tests/fixtures/` (trim them to
  what the test needs).
- GUI behaviour: drive `App` through `egui_kittest` by label, with the
  `FakeBackend` in `ui_tests.rs`.
