//! Running external tools: every command patchscope runs goes through
//! [`CommandRunner`], so discovery, planning and applying can be tested
//! against recorded tool output ([`FakeRunner`]) on any OS, and every real
//! command is time-bounded ([`SystemRunner`]).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

/// A command to run. Arguments are passed as a vector, never through a
/// shell, so package names cannot inject shell syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    /// The command must run as root/Administrator.
    pub needs_elevation: bool,
    /// The command may prompt on the terminal (interactive `sudo`), so it
    /// stays in the terminal's process group.
    pub interactive: bool,
}

impl CommandSpec {
    pub fn new(program: &str, args: &[&str]) -> Self {
        CommandSpec {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            timeout: Duration::from_secs(120),
            needs_elevation: false,
            interactive: false,
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.to_string(), v.to_string()));
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn elevated(mut self) -> Self {
        self.needs_elevation = true;
        self
    }

    /// The command as a person would type it, for display and audit logs.
    pub fn display(&self) -> String {
        let mut parts: Vec<String> = self
            .env
            .iter()
            .map(|(k, v)| format!("{k}={}", shell_quote(v)))
            .collect();
        parts.push(shell_quote(&self.program));
        parts.extend(self.args.iter().map(|a| shell_quote(a)));
        parts.join(" ")
    }

    fn key(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// POSIX single-quote a word if it needs it.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@+,%".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// `None` when killed by a signal or by the timeout.
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CommandOutput {
    pub fn ok(stdout: &str) -> Self {
        CommandOutput {
            status: Some(0),
            stdout: stdout.to_string(),
            ..Default::default()
        }
    }

    pub fn with_status(status: i32, stdout: &str, stderr: &str) -> Self {
        CommandOutput {
            status: Some(status),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            timed_out: false,
        }
    }

    pub fn success(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }

    /// The last `n` bytes of stderr (or stdout when stderr is empty), for
    /// error messages.
    pub fn tail(&self, n: usize) -> String {
        let s = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        let s = s.trim();
        if s.len() <= n {
            return s.to_string();
        }
        let mut start = s.len() - n;
        while !s.is_char_boundary(start) {
            start += 1;
        }
        format!("…{}", &s[start..])
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("{0}: not found on PATH")]
    NotFound(String),
    #[error("{program}: could not start: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ExecError>;
    /// Where `program` would be found, if anywhere.
    fn which(&self, program: &str) -> Option<PathBuf>;
}

/// Most stdout patchscope keeps from one command. `brew info --json` on a
/// large installation is a few MB; this is far above that.
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;

/// Runs real commands, each bounded by its timeout.
#[derive(Debug, Clone)]
pub struct SystemRunner {
    search_path: Vec<PathBuf>,
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemRunner {
    pub fn new() -> Self {
        let mut search_path: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        // A GUI started from Finder, a desktop launcher or the Start menu
        // gets a minimal PATH that misses the usual package-manager homes.
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        let mut extra: Vec<PathBuf> = vec![
            "/opt/homebrew/bin".into(),
            "/usr/local/bin".into(),
            "/usr/bin".into(),
            "/usr/sbin".into(),
            "/bin".into(),
            "/sbin".into(),
            "/snap/bin".into(),
        ];
        if let Some(h) = &home {
            extra.push(h.join(".cargo/bin"));
            extra.push(h.join(".volta/bin"));
            extra.push(h.join(".npm-global/bin"));
        }
        if let Some(la) = std::env::var_os("LOCALAPPDATA") {
            extra.push(PathBuf::from(la).join("Microsoft").join("WindowsApps"));
        }
        if let Some(pd) = std::env::var_os("ProgramData") {
            extra.push(PathBuf::from(pd).join("chocolatey").join("bin"));
        }
        if let Some(sr) = std::env::var_os("SystemRoot") {
            let sr = PathBuf::from(sr);
            extra.push(sr.join("System32"));
            extra.push(sr.join("System32").join("WindowsPowerShell").join("v1.0"));
        }
        for p in extra {
            if !search_path.contains(&p) {
                search_path.push(p);
            }
        }
        SystemRunner { search_path }
    }

    fn candidates(program: &str) -> Vec<String> {
        if cfg!(windows) && Path::new(program).extension().is_none() {
            let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
            exts.split(';')
                .filter(|e| !e.is_empty())
                .map(|e| format!("{program}{}", e.to_ascii_lowercase()))
                .collect()
        } else {
            vec![program.to_string()]
        }
    }
}

impl CommandRunner for SystemRunner {
    fn which(&self, program: &str) -> Option<PathBuf> {
        let p = Path::new(program);
        if p.is_absolute() {
            return p.is_file().then(|| p.to_path_buf());
        }
        for dir in &self.search_path {
            for name in Self::candidates(program) {
                let full = dir.join(&name);
                if full.is_file() {
                    return Some(full);
                }
            }
        }
        None
    }

    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ExecError> {
        let exe = self
            .which(&spec.program)
            .ok_or_else(|| ExecError::NotFound(spec.program.clone()))?;
        let mut cmd = Command::new(&exe);
        cmd.args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        // Its own process group, so a timeout can kill everything the tool
        // started. Not for commands that prompt on the terminal: a process
        // outside the foreground group is stopped when it reads the tty.
        #[cfg(unix)]
        if !spec.interactive {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd.spawn().map_err(|source| ExecError::Spawn {
            program: spec.program.clone(),
            source,
        })?;

        // Drain both pipes on their own threads, so a chatty tool cannot fill
        // a pipe buffer and deadlock against our wait. Data is shared as it
        // arrives: a helper the tool leaves running can hold the pipes open
        // after the tool exits, and what was already written must not be lost.
        let drain = |mut pipe: Box<dyn Read + Send>| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let (tx, rx) = mpsc::channel::<()>();
            let shared = Arc::clone(&buf);
            std::thread::spawn(move || {
                let mut chunk = [0u8; 8192];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut b = shared.lock().expect("pipe buffer");
                            if (b.len() as u64) < MAX_OUTPUT {
                                b.extend_from_slice(&chunk[..n]);
                            }
                        }
                    }
                }
                let _ = tx.send(());
            });
            (buf, rx)
        };
        let (out_buf, out_done) = drain(Box::new(child.stdout.take().expect("stdout is piped")));
        let (err_buf, err_done) = drain(Box::new(child.stderr.take().expect("stderr is piped")));

        let (status, timed_out) = match child.wait_timeout(spec.timeout) {
            Ok(Some(st)) => (st.code(), false),
            Ok(None) | Err(_) => {
                // Ask first: sudo and pkexec pass SIGTERM on to the root
                // command (which an unprivileged SIGKILL cannot reach), and a
                // package manager given the chance exits without leaving its
                // database locked. Then force.
                signal_tree(child.id(), spec.interactive, "-TERM");
                let exited = matches!(child.wait_timeout(TERM_GRACE), Ok(Some(_)));
                if !exited {
                    signal_tree(child.id(), spec.interactive, "-KILL");
                    let _ = child.kill();
                    let _ = child.wait();
                }
                (None, true)
            }
        };
        // One shared grace period for both pipes to reach end-of-file.
        let deadline = Instant::now() + Duration::from_secs(3);
        for done in [&out_done, &err_done] {
            let _ = done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
        let stdout = out_buf.lock().expect("pipe buffer").clone();
        let stderr = err_buf.lock().expect("pipe buffer").clone();
        Ok(CommandOutput {
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            timed_out,
        })
    }
}

/// How long a timed-out command gets to exit after SIGTERM.
const TERM_GRACE: Duration = Duration::from_secs(20);

/// Signal a timed-out command and everything it started (`-TERM`, then
/// `-KILL`). On Windows the tree is terminated at once.
fn signal_tree(pid: u32, interactive: bool, signal: &str) {
    let quiet = |c: &mut Command| {
        let _ = c
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    if cfg!(windows) {
        quiet(Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()]));
    } else if interactive {
        quiet(Command::new("/bin/kill").args([signal, &pid.to_string()]));
    } else {
        // The child leads its own process group (see `run`).
        quiet(Command::new("/bin/kill").args([signal, "--", &format!("-{pid}")]));
    }
}

/// A recorded-output runner for tests: responds to exact command lines and
/// records every command it was asked to run.
#[derive(Debug, Default)]
pub struct FakeRunner {
    programs: Vec<String>,
    responses: HashMap<String, Vec<CommandOutput>>,
    /// Answer for every program and command line not otherwise recorded.
    fallback: Option<CommandOutput>,
    calls: Mutex<Vec<CommandSpec>>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make `which(program)` succeed.
    pub fn with_program(mut self, program: &str) -> Self {
        self.programs.push(program.to_string());
        self
    }

    /// Respond to `command_line` (program and arguments joined by single
    /// spaces). Several responses to one line are returned in order; the
    /// last one repeats.
    pub fn respond(mut self, command_line: &str, output: CommandOutput) -> Self {
        let program = command_line.split(' ').next().unwrap_or_default().to_string();
        if !self.programs.contains(&program) {
            self.programs.push(program);
        }
        self.responses.entry(command_line.to_string()).or_default().push(output);
        self
    }

    /// Every program exists and every unrecorded command gets `output`
    /// (used by the fuzz targets to feed one input to every adapter).
    pub fn answer_everything(mut self, output: CommandOutput) -> Self {
        self.fallback = Some(output);
        self
    }

    pub fn calls(&self) -> Vec<CommandSpec> {
        self.calls.lock().expect("calls lock").clone()
    }

    pub fn call_lines(&self) -> Vec<String> {
        self.calls().iter().map(CommandSpec::key).collect()
    }
}

impl CommandRunner for FakeRunner {
    fn which(&self, program: &str) -> Option<PathBuf> {
        (self.fallback.is_some() || self.programs.iter().any(|p| p == program))
            .then(|| PathBuf::from(format!("/fake/{program}")))
    }

    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ExecError> {
        let key = spec.key();
        let n = {
            let mut calls = self.calls.lock().expect("calls lock");
            calls.push(spec.clone());
            calls.iter().filter(|c| c.key() == key).count()
        };
        match self.responses.get(&key) {
            Some(list) => Ok(list[(n - 1).min(list.len() - 1)].clone()),
            None if self.fallback.is_some() => Ok(self.fallback.clone().unwrap_or_default()),
            None if self.which(&spec.program).is_some() => Ok(CommandOutput::with_status(
                127,
                "",
                &format!("FakeRunner: no response for `{key}`"),
            )),
            None => Err(ExecError::NotFound(spec.program.clone())),
        }
    }
}

/// How to gain root/Administrator for a command that needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Elevation {
    /// Already elevated, or the command does not need it.
    None,
    /// `sudo` (prompts on the terminal).
    Sudo,
    /// `sudo -n` (fails rather than prompting; for unattended runs).
    SudoNonInteractive,
    /// `pkexec` (graphical polkit prompt on Linux desktops).
    Pkexec,
    /// macOS administrator dialog via `osascript`.
    MacosAdminPrompt,
}

impl Elevation {
    /// The sensible default for an interactive terminal or a GUI.
    pub fn default_for(gui: bool) -> Self {
        match (crate::model::OsFamily::current(), gui) {
            (crate::model::OsFamily::Windows, _) => Elevation::None,
            (crate::model::OsFamily::Macos, true) => Elevation::MacosAdminPrompt,
            (crate::model::OsFamily::Linux, true) => Elevation::Pkexec,
            _ => Elevation::Sudo,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElevateError {
    #[error(
        "refusing to run `{0}` with administrator rights: the program must be named by absolute path, not looked up on PATH"
    )]
    RelativeProgram(String),
}

/// Wrap `spec` so it runs elevated. Commands that do not need elevation,
/// and [`Elevation::None`], pass through unchanged.
///
/// A wrapped program must be an absolute path: `sudo` without `secure_path`
/// (the macOS default), `pkexec` and `env` look a bare name up on the
/// caller's PATH, where a user-writable directory would let user-level code
/// run as root.
pub fn elevate(spec: &CommandSpec, how: Elevation) -> Result<CommandSpec, ElevateError> {
    if !spec.needs_elevation || how == Elevation::None {
        return Ok(spec.clone());
    }
    // Every wrapper is a Unix program, so absolute means a leading `/`
    // (`Path::is_absolute` would say no to it on Windows).
    if !spec.program.starts_with('/') {
        return Err(ElevateError::RelativeProgram(spec.program.clone()));
    }
    // Environment variables cross the privilege boundary through
    // `env K=V`, since sudo and pkexec reset the environment.
    let mut inner: Vec<String> = Vec::new();
    if !spec.env.is_empty() {
        inner.push("/usr/bin/env".into());
        inner.extend(spec.env.iter().map(|(k, v)| format!("{k}={v}")));
    }
    inner.push(spec.program.clone());
    inner.extend(spec.args.iter().cloned());

    let wrapped = |program: &str, prefix: &[&str]| CommandSpec {
        program: program.into(),
        args: prefix
            .iter()
            .map(|s| s.to_string())
            .chain(inner.iter().cloned())
            .collect(),
        env: Vec::new(),
        timeout: spec.timeout,
        needs_elevation: false,
        interactive: how == Elevation::Sudo,
    };
    Ok(match how {
        Elevation::None => spec.clone(),
        // Absolute paths: a directory earlier on PATH must not be able to
        // stand in for the program that asks for the password.
        Elevation::Sudo => wrapped("/usr/bin/sudo", &["--"]),
        Elevation::SudoNonInteractive => wrapped("/usr/bin/sudo", &["-n", "--"]),
        Elevation::Pkexec => wrapped("/usr/bin/pkexec", &[]),
        Elevation::MacosAdminPrompt => {
            let shell_line = inner.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
            let applescript_string = shell_line.replace('\\', "\\\\").replace('"', "\\\"");
            CommandSpec {
                program: "/usr/bin/osascript".into(),
                args: vec![
                    "-e".into(),
                    format!("do shell script \"{applescript_string}\" with administrator privileges"),
                ],
                env: Vec::new(),
                timeout: spec.timeout,
                needs_elevation: false,
                interactive: false,
            }
        }
    })
}

/// Whether this process already runs as root/Administrator.
pub fn is_elevated(runner: &dyn CommandRunner) -> bool {
    if cfg!(windows) {
        is_elevated_windows(runner)
    } else {
        runner
            .run(&CommandSpec::new("id", &["-u"]).timeout(Duration::from_secs(10)))
            .map(|o| o.success() && o.stdout.trim() == "0")
            .unwrap_or(false)
    }
}

/// Whether `p` is a Windows path from the root of a drive (`C:\...`).
pub(crate) fn is_windows_drive_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// A Windows directory named by an environment variable (`SystemRoot`,
/// `ProgramData`), or `default` when it is unset or not a path from the
/// root of a drive. Windows has no `sudo`: patchscope runs elevated as a
/// whole, so the programs it starts are named by absolute path rather than
/// looked up on `PATH`, where a user-writable directory can come first.
pub(crate) fn windows_dir(value: Option<&str>, default: &str) -> String {
    match value {
        Some(v) if is_windows_drive_path(v) => v.trim_end_matches(['\\', '/']).to_string(),
        _ => default.to_string(),
    }
}

/// Windows PowerShell for a given `%SystemRoot%`:
/// `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`.
pub(crate) fn windows_powershell_program_for(system_root: Option<&str>) -> String {
    format!(
        r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
        windows_dir(system_root, r"C:\Windows")
    )
}

/// Windows PowerShell by absolute path, so nothing earlier on PATH can
/// stand in for it.
pub(crate) fn windows_powershell_program() -> String {
    windows_powershell_program_for(std::env::var("SystemRoot").ok().as_deref())
}

/// `whoami.exe` by absolute path, so nothing earlier on PATH can answer.
fn whoami_program() -> String {
    let root = windows_dir(std::env::var("SystemRoot").ok().as_deref(), r"C:\Windows");
    format!(r"{root}\System32\whoami.exe")
}

/// Read the process token's integrity level: High (`S-1-16-12288`) or
/// System (`S-1-16-16384`) means elevated. Unlike `net session`, this does
/// not depend on the Server service running, and SIDs are not translated.
fn is_elevated_windows(runner: &dyn CommandRunner) -> bool {
    let spec = CommandSpec::new(&whoami_program(), &["/groups", "/fo", "csv", "/nh"]).timeout(Duration::from_secs(10));
    runner.run(&spec).is_ok_and(|o| {
        o.success()
            && o.stdout
                .split(|c: char| c == ',' || c == '"' || c.is_whitespace())
                .any(|t| t == "S-1-16-12288" || t == "S-1-16-16384")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_only_when_needed() {
        assert_eq!(shell_quote("brew"), "brew");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn elevation_wraps_only_privileged_commands() {
        let plain = CommandSpec::new("brew", &["upgrade", "git"]);
        assert_eq!(elevate(&plain, Elevation::Sudo).unwrap(), plain);

        let apt = CommandSpec::new("/usr/bin/apt-get", &["install", "--only-upgrade", "-y", "curl"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .elevated();
        let s = elevate(&apt, Elevation::Sudo).unwrap();
        assert_eq!(s.program, "/usr/bin/sudo");
        assert_eq!(
            s.args,
            [
                "--",
                "/usr/bin/env",
                "DEBIAN_FRONTEND=noninteractive",
                "/usr/bin/apt-get",
                "install",
                "--only-upgrade",
                "-y",
                "curl"
            ]
        );
        assert!(!s.needs_elevation);
        assert_eq!(
            elevate(&apt, Elevation::SudoNonInteractive).unwrap().args[..2],
            ["-n", "--"]
        );
        assert_eq!(elevate(&apt, Elevation::Pkexec).unwrap().program, "/usr/bin/pkexec");
    }

    #[test]
    fn elevation_refuses_programs_looked_up_on_path() {
        // sudo without secure_path, pkexec and env resolve a bare name on the
        // caller's PATH: a user-writable directory there would run as root.
        let bare = CommandSpec::new("softwareupdate", &["--install", "x"]).elevated();
        for how in [
            Elevation::Sudo,
            Elevation::SudoNonInteractive,
            Elevation::Pkexec,
            Elevation::MacosAdminPrompt,
        ] {
            let e = elevate(&bare, how).unwrap_err();
            assert!(e.to_string().contains("absolute path"), "{e}");
        }
        let rel = CommandSpec::new("bin/apt-get", &["update"]).elevated();
        assert!(elevate(&rel, Elevation::Sudo).is_err());
        // No wrapper, nothing resolved through one: unchanged (Windows).
        assert_eq!(elevate(&bare, Elevation::None).unwrap(), bare);
        // Unprivileged commands are never wrapped, so never refused.
        let plain = CommandSpec::new("brew", &["upgrade", "git"]);
        assert_eq!(elevate(&plain, Elevation::Sudo).unwrap(), plain);
    }

    #[test]
    fn macos_admin_prompt_escapes_for_applescript() {
        let spec = CommandSpec::new("/usr/sbin/softwareupdate", &["--install", "macOS Tahoe 26.7.2-25H200"]).elevated();
        let s = elevate(&spec, Elevation::MacosAdminPrompt).unwrap();
        assert_eq!(s.program, "/usr/bin/osascript");
        assert_eq!(
            s.args[1],
            "do shell script \"/usr/sbin/softwareupdate --install 'macOS Tahoe 26.7.2-25H200'\" with administrator privileges"
        );
        let nasty = CommandSpec::new("/x", &["a\"b\\c"]).elevated();
        let s = elevate(&nasty, Elevation::MacosAdminPrompt).unwrap();
        assert!(s.args[1].contains(r#"'a\"b\\c'"#), "{}", s.args[1]);
    }

    #[test]
    fn windows_programs_are_named_by_absolute_path() {
        assert_eq!(
            windows_powershell_program_for(Some(r"D:\WINDOWS")),
            r"D:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        assert_eq!(
            windows_powershell_program_for(Some(r"C:\Windows\")),
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        // Unset, relative, UNC or empty: the default, never a PATH lookup.
        for bad in [
            None,
            Some(""),
            Some("Windows"),
            Some(r"\\server\share"),
            Some(r"..\x"),
            Some("C:"),
        ] {
            assert_eq!(
                windows_powershell_program_for(bad),
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "{bad:?}"
            );
        }
        assert!(is_windows_drive_path(&windows_powershell_program()));
        assert!(is_windows_drive_path(&whoami_program()));
        assert!(whoami_program().ends_with(r"\System32\whoami.exe"));
    }

    #[test]
    fn windows_elevation_is_read_from_the_token() {
        // `whoami /groups /fo csv /nh`: the integrity level is a group. High
        // (S-1-16-12288) or System (S-1-16-16384) means elevated; this works
        // whether or not the Server service (`net session`) is running.
        let whoami = format!("{} /groups /fo csv /nh", whoami_program());
        let groups = |label: &str, sid: &str| {
            format!(
                "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group, Enabled by default, Enabled group\"\r\n\
                 \"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Mandatory group, Enabled by default, Enabled group, Group owner\"\r\n\
                 \"Mandatory Label\\{label} Mandatory Level\",\"Label\",\"{sid}\",\"\"\r\n"
            )
        };
        let elevated = |out: CommandOutput| {
            // `net session` fails: the Server service is disabled.
            let r = FakeRunner::new()
                .respond("net session", CommandOutput::with_status(2, "", "System error 1726"))
                .respond(&whoami, out);
            is_elevated_windows(&r)
        };
        assert!(elevated(CommandOutput::ok(&groups("High", "S-1-16-12288"))));
        assert!(elevated(CommandOutput::ok(&groups("System", "S-1-16-16384"))));
        // An administrator's unelevated (filtered) token is Medium.
        assert!(!elevated(CommandOutput::ok(&groups("Medium", "S-1-16-8192"))));
        // A SID that merely starts with the High one is not it.
        assert!(!elevated(CommandOutput::ok(&groups("Odd", "S-1-16-122880"))));
        assert!(!elevated(CommandOutput::with_status(
            1,
            &groups("High", "S-1-16-12288"),
            ""
        )));
        assert!(!elevated(CommandOutput::ok("")));
    }

    #[test]
    fn fake_runner_replays_in_order_and_records() {
        let r = FakeRunner::new()
            .respond("tool list", CommandOutput::ok("one"))
            .respond("tool list", CommandOutput::ok("two"));
        let spec = CommandSpec::new("tool", &["list"]);
        assert_eq!(r.run(&spec).unwrap().stdout, "one");
        assert_eq!(r.run(&spec).unwrap().stdout, "two");
        assert_eq!(r.run(&spec).unwrap().stdout, "two");
        assert_eq!(r.call_lines(), ["tool list", "tool list", "tool list"]);
        assert!(r.which("tool").is_some());
        assert!(r.which("other").is_none());
        assert!(matches!(
            r.run(&CommandSpec::new("other", &[])),
            Err(ExecError::NotFound(_))
        ));
        assert_eq!(r.run(&CommandSpec::new("tool", &["x"])).unwrap().status, Some(127));
    }

    #[test]
    fn system_runner_times_out() {
        let r = SystemRunner::new();
        let spec = if cfg!(windows) {
            CommandSpec::new(
                &windows_powershell_program(),
                &["-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
            )
        } else {
            CommandSpec::new("sleep", &["30"])
        }
        .timeout(Duration::from_millis(500));
        let started = std::time::Instant::now();
        let out = r.run(&spec).unwrap();
        assert!(out.timed_out);
        assert!(!out.success());
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_helpers_that_hold_the_pipes() {
        // The shell starts a background sleeper that inherits stdout, then
        // waits; on timeout both must die and run() must return promptly.
        let r = SystemRunner::new();
        let spec = CommandSpec::new("sh", &["-c", "sleep 60 & sleep 60"]).timeout(Duration::from_millis(500));
        let started = std::time::Instant::now();
        let out = r.run(&spec).unwrap();
        assert!(out.timed_out);
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "took {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_left_running_after_exit_does_not_block() {
        let r = SystemRunner::new();
        let spec = CommandSpec::new("sh", &["-c", "echo done; sleep 30 &"]).timeout(Duration::from_secs(60));
        let started = std::time::Instant::now();
        let out = r.run(&spec).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.trim(), "done", "output written before exit is kept");
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn system_runner_reports_missing_programs() {
        let r = SystemRunner::new();
        assert!(matches!(
            r.run(&CommandSpec::new("patchscope-definitely-not-a-program", &[])),
            Err(ExecError::NotFound(_))
        ));
    }

    #[test]
    fn output_tail_respects_char_boundaries() {
        let o = CommandOutput::with_status(1, "", "ééééé");
        let t = o.tail(3);
        assert!(t.starts_with('…'));
    }
}
