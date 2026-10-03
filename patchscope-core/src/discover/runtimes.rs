//! Language runtimes on PATH, so their support lifecycle can be checked.

use crate::exec::{CommandRunner, CommandSpec};
use crate::model::{OsFamily, Runtime};
use crate::util::first_version;
use std::time::Duration;

/// (endoflife.date product, display name, candidate commands, version args)
const RUNTIMES: &[(&str, &str, &[&str], &[&str])] = &[
    ("python", "Python", &["python3", "python"], &["--version"]),
    ("nodejs", "Node.js", &["node"], &["--version"]),
    ("go", "Go", &["go"], &["version"]),
    ("ruby", "Ruby", &["ruby"], &["--version"]),
    ("php", "PHP", &["php"], &["--version"]),
];

pub fn detect(runner: &dyn CommandRunner) -> Vec<Runtime> {
    let mut out = Vec::new();
    for (product, display, commands, args) in RUNTIMES {
        for cmd in *commands {
            let Some(path) = runner.which(cmd) else { continue };
            if macos_stub_would_prompt(runner, &path) {
                continue;
            }
            let Ok(o) = runner.run(&CommandSpec::new(cmd, args).timeout(Duration::from_secs(20))) else {
                continue;
            };
            // Python 2 printed its version on stderr.
            let text = if o.stdout.trim().is_empty() {
                &o.stderr
            } else {
                &o.stdout
            };
            if o.success()
                && let Some(version) = first_version(text)
            {
                out.push(Runtime {
                    product: product.to_string(),
                    display_name: display.to_string(),
                    version,
                    path_command: path.to_string_lossy().into_owned(),
                });
                break;
            }
        }
    }
    out
}

/// On a Mac without the Command Line Tools, `/usr/bin/python3` (and friends)
/// are stubs that open an "install developer tools" dialog when run.
fn macos_stub_would_prompt(runner: &dyn CommandRunner, path: &std::path::Path) -> bool {
    if OsFamily::current() != OsFamily::Macos || !path.starts_with("/usr/bin") {
        return false;
    }
    !runner
        .run(&CommandSpec::new("xcode-select", &["-p"]).timeout(Duration::from_secs(10)))
        .map(|o| o.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{CommandOutput, FakeRunner};

    #[test]
    fn finds_runtimes_and_falls_back_to_python() {
        let r = FakeRunner::new()
            .with_program("python")
            .respond("python --version", CommandOutput::ok("Python 3.11.9\n"))
            .respond("node --version", CommandOutput::ok("v20.18.0\n"))
            .respond("go version", CommandOutput::ok("go version go1.24.2 linux/amd64\n"));
        let rt = detect(&r);
        let names: Vec<_> = rt.iter().map(|r| (r.product.as_str(), r.version.as_str())).collect();
        assert_eq!(names, [("python", "3.11.9"), ("nodejs", "20.18.0"), ("go", "1.24.2")]);
    }
}
