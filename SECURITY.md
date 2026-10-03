# Security Policy

## Supported versions

patchscope is pre-1.0; only the latest release is supported with security
fixes.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

Please report security issues **privately** through
[GitHub private vulnerability reporting](https://github.com/RobS96/patchscope/security/advisories/new),
not in a public issue. Include what you found, how to reproduce it, and
the version (`patchscope --version`). You should get a first response
within a week. Once a fix is released, the advisory is published with
credit unless you prefer otherwise.

## What is in scope

patchscope runs package-manager commands with administrator rights on the
user's behalf, so these are treated as vulnerabilities:

- anything that makes patchscope run a command, or a command argument, that
  the person did not see and confirm (including via a crafted package name,
  version string, tool output, research API response or policy file);
- a way to make `apply` install, remove or downgrade software outside the
  confirmed plan, or to bypass the policy's protected list;
- privilege handling that leaks or stores credentials, or runs more than
  the confirmed command elevated;
- script or content injection in the HTML reports;
- research requests that send identifying information beyond what
  [docs/methodology.md](docs/methodology.md#1-evidence-it-gathers) lists;
- TLS validation weaknesses in the research client;
- weaknesses in the release pipeline (provenance, checksums, signing).

Out of scope: vulnerabilities in the package managers or OS updaters
patchscope drives, inaccuracies in the public data sources (report those
upstream), and findings that require an attacker who already controls the
user's account or `PATH`.

## How patchscope is hardened

See [docs/safety.md](docs/safety.md). In short: `#![forbid(unsafe_code)]`;
no shell (argument vectors only); identifiers that look like options are
refused, and Windows UpdateIDs must be GUIDs; strict policy parsing;
confirmation before any change; verification and an append-only audit log
(0600); a run lock; timeouts with process-tree kill on every command;
bounded HTTP (90 s, 64 MB); TLS 1.3 via rustls/aws-lc-rs against the OS
trust store; HTML reports with a script-forbidding CSP. Every parser and
the plan/report path are fuzzed on each change. Dependencies are
gated by `cargo deny` and `cargo vet`; CodeQL and OpenSSF Scorecard run on
the repository; Actions are SHA-pinned with read-only default tokens;
releases are built from signed tags with build-provenance attestations.
