# Contributing

Thanks for considering a contribution. patchscope is a Cargo workspace,
so the usual Rust workflow applies.

## Project layout

```
patchscope-core/   discovery, package-manager adapters, research, analysis, plan, apply, reports
patchscope-cli/    the `patchscope` command
patchscope-gui/    the desktop app (eframe/egui)
docs/              user guide, methodology, safety model, architecture, testing
```

Anything about operating systems, package managers, research or safety
belongs in `patchscope-core`, so both front ends get it. See
[docs/architecture.md](docs/architecture.md), including how to add a
package manager or a research source.

## Setup

Rust 1.95 or newer. On Linux, the GUI needs windowing headers to build:

```bash
sudo apt-get update && sudo apt-get install -y libx11-dev libxkbcommon-dev libxkbcommon-x11-dev libgl1-mesa-dev pkg-config
```

## Before opening a pull request

Run what CI runs on your code:

```bash
cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace
```

When you change dependencies, also run `cargo deny check` and
`cargo vet check` (CI does). If you touch a research client, run the live
tests: `cargo test -p patchscope-core --test live -- --ignored`.

## Rules for changes that touch the system

- Every command goes through `CommandRunner` with a timeout, as an
  argument vector. Never `sh -c`, never string-built command lines.
- Listing must stay read-only and unprivileged.
- A new install command needs a unit test asserting its exact arguments,
  and a row in [docs/safety.md](docs/safety.md#what-apply-runs).
- Parsers are tested on **real recorded output**, including the "nothing
  to report" and error forms.
- Don't run real installs on your own machine to test; CI's end-to-end
  jobs do that on throwaway runners and containers.

## Commits and pull requests

- One logical change per pull request, with a clear description of what
  and why. Update `CHANGELOG.md` under *Unreleased* for anything
  user-visible.
- Commits to `main` must be signed (GitHub verifies them).
- Be kind: see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Releases

Maintainers bump `version` in the workspace `Cargo.toml` and the two
`patchscope-core` path dependencies, move *Unreleased* to a dated heading
in `CHANGELOG.md`, merge, then push a **signed annotated tag** `vX.Y.Z` on
`main`. CI builds, tests, packages, attests and publishes the release; it
refuses a lightweight, unsigned or off-`main` tag and a version mismatch.
