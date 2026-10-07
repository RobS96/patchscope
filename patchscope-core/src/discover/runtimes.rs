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

/// Java builds with a published lifecycle, told apart by the vendor text in
/// `java -version`: (needle, endoflife.date product, vendor name). Other
/// builds (distro packages, Homebrew, jdk.java.net, GraalVM) follow their
/// packager's support and are not reported.
const JAVA_VENDORS: &[(&str, &str, &str)] = &[
    ("Temurin", "eclipse-temurin", "Eclipse Temurin"),
    ("Corretto", "amazon-corretto", "Amazon Corretto"),
    ("Zulu", "azul-zulu", "Azul Zulu"),
    ("Microsoft-", "microsoft-build-of-openjdk", "Microsoft Build of OpenJDK"),
    ("Red_Hat", "redhat-build-of-openjdk", "Red Hat build of OpenJDK"),
    ("Java(TM) SE", "oracle-jdk", "Oracle JDK"),
];

/// The endoflife.date product is one of the Java builds above.
pub fn is_java_product(product: &str) -> bool {
    JAVA_VENDORS.iter().any(|(_, p, _)| *p == product)
}

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
    out.extend(detect_java(runner));
    out
}

fn detect_java(runner: &dyn CommandRunner) -> Option<Runtime> {
    let path = runner.which("java")?;
    if macos_java_stub(runner, &path) {
        return None;
    }
    let o = runner
        .run(&CommandSpec::new("java", &["-version"]).timeout(Duration::from_secs(20)))
        .ok()?;
    if !o.success() {
        return None;
    }
    let text = format!("{}\n{}", o.stderr, o.stdout);
    let (version, product, vendor) = parse_java_version(&text)?;
    Some(Runtime {
        product: product.to_string(),
        display_name: format!("Java ({vendor})"),
        version,
        path_command: path.to_string_lossy().into_owned(),
    })
}

/// The quoted version (`1.8.0_422`, `21.0.4`, `23`) and the vendor's
/// lifecycle product, from `java -version` output.
fn parse_java_version(text: &str) -> Option<(String, &'static str, &'static str)> {
    if text.contains("GraalVM") {
        return None;
    }
    let (_, product, vendor) = JAVA_VENDORS.iter().find(|(needle, _, _)| text.contains(needle))?;
    let rest = &text[text.find(" version \"")? + " version \"".len()..];
    let version = &rest[..rest.find('"')?];
    version
        .starts_with(|c: char| c.is_ascii_digit())
        .then(|| (version.to_string(), *product, *vendor))
}

/// On a Mac with no JDK installed, `/usr/bin/java` is a stub that offers to
/// install one; `/usr/libexec/java_home` fails quietly in that case.
fn macos_java_stub(runner: &dyn CommandRunner, path: &std::path::Path) -> bool {
    if OsFamily::current() != OsFamily::Macos || !path.starts_with("/usr/bin") {
        return false;
    }
    !runner
        .run(&CommandSpec::new("/usr/libexec/java_home", &[]).timeout(Duration::from_secs(10)))
        .map(|o| o.success())
        .unwrap_or(false)
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

    /// `java -version` writes to stderr.
    fn java(stderr: &str) -> Vec<Runtime> {
        detect(&FakeRunner::new().respond("java -version", CommandOutput::with_status(0, "", stderr)))
    }

    #[test]
    fn java_vendor_picks_the_lifecycle_product() {
        let cases = [
            (
                "openjdk version \"21.0.4\" 2024-07-16 LTS\nOpenJDK Runtime Environment Temurin-21.0.4+7 (build 21.0.4+7-LTS)\nOpenJDK 64-Bit Server VM Temurin-21.0.4+7 (build 21.0.4+7-LTS, mixed mode)\n",
                "eclipse-temurin",
                "21.0.4",
            ),
            (
                "openjdk version \"1.8.0_422\"\nOpenJDK Runtime Environment (Temurin)(build 1.8.0_422-b05)\n",
                "eclipse-temurin",
                "1.8.0_422",
            ),
            (
                "openjdk version \"17.0.12\" 2024-07-16 LTS\nOpenJDK Runtime Environment Corretto-17.0.12.7.1 (build 17.0.12+7-LTS)\n",
                "amazon-corretto",
                "17.0.12",
            ),
            (
                "openjdk version \"1.8.0_422\"\nOpenJDK Runtime Environment (Zulu 8.80.0.17-CA-macosx) (build 1.8.0_422-b05)\n",
                "azul-zulu",
                "1.8.0_422",
            ),
            (
                "openjdk version \"21.0.4\" 2024-07-16 LTS\nOpenJDK Runtime Environment Microsoft-9889606 (build 21.0.4+7-LTS)\n",
                "microsoft-build-of-openjdk",
                "21.0.4",
            ),
            (
                "openjdk version \"17.0.12\" 2024-07-16 LTS\nOpenJDK Runtime Environment (Red_Hat-17.0.12.0.7-1) (build 17.0.12+7-LTS)\n",
                "redhat-build-of-openjdk",
                "17.0.12",
            ),
            (
                "Picked up JAVA_TOOL_OPTIONS: -Xmx1g\njava version \"1.8.0_421\"\nJava(TM) SE Runtime Environment (build 1.8.0_421-b09)\nJava HotSpot(TM) 64-Bit Server VM (build 25.421-b09, mixed mode)\n",
                "oracle-jdk",
                "1.8.0_421",
            ),
            (
                "java version \"23\" 2024-09-17\nJava(TM) SE Runtime Environment (build 23+37-2369)\n",
                "oracle-jdk",
                "23",
            ),
        ];
        for (stderr, product, version) in cases {
            let rt = java(stderr);
            assert_eq!(rt.len(), 1, "{stderr}");
            assert_eq!(
                (rt[0].product.as_str(), rt[0].version.as_str()),
                (product, version),
                "{stderr}"
            );
            assert!(rt[0].display_name.starts_with("Java ("), "{}", rt[0].display_name);
            assert!(is_java_product(&rt[0].product));
        }
        assert!(!is_java_product("python"));
    }

    #[test]
    fn java_without_a_published_lifecycle_is_not_reported() {
        // Distro, Homebrew and jdk.java.net builds follow their packager's
        // support, and GraalVM has its own; none can be matched to one
        // endoflife.date schedule, so guessing would report false EOLs.
        for stderr in [
            "openjdk version \"17.0.12\" 2024-07-16\nOpenJDK Runtime Environment (build 17.0.12+7-Ubuntu-1ubuntu222.04)\n",
            "openjdk version \"17.0.12\" 2024-07-16\nOpenJDK Runtime Environment (build 17.0.12+7-Debian-2deb12u1)\n",
            "openjdk version \"23\" 2024-09-17\nOpenJDK Runtime Environment Homebrew (build 23)\n",
            "openjdk version \"23\" 2024-09-17\nOpenJDK Runtime Environment (build 23+37-2369)\n",
            "java version \"21.0.4\" 2024-07-16 LTS\nJava(TM) SE Runtime Environment Oracle GraalVM 21.0.4+8.1 (build 21.0.4+8-LTS-jvmci-23.1-b41)\n",
            "The operation couldn't be completed. Unable to locate a Java Runtime.\n",
        ] {
            assert!(java(stderr).is_empty(), "{stderr}");
        }
    }
}
