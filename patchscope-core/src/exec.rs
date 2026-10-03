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

/// Wrap `spec` so it runs elevated. Commands that do not need elevation,
/// and [`Elevation::None`], pass through unchanged.
pub fn elevate(spec: &CommandSpec, how: Elevation) -> CommandSpec {
    if !spec.needs_elevation {
        return spec.clone();
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
    match how {
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
    }
}

/// Whether this process already runs as root/Administrator.
pub fn is_elevated(runner: &dyn CommandRunner) -> bool {
    if cfg!(windows) {
        // `net session` succeeds only for an elevated Administrator.
        runner
            .run(&CommandSpec::new("net", &["session"]).timeout(Duration::from_secs(10)))
            .map(|o| o.success())
            .unwrap_or(false)
    } else {
        runner
            .run(&CommandSpec::new("id", &["-u"]).timeout(Duration::from_secs(10)))
            .map(|o| o.success() && o.stdout.trim() == "0")
            .unwrap_or(false)
    }
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
        assert_eq!(elevate(&plain, Elevation::Sudo), plain);

        let apt = CommandSpec::new("apt-get", &["install", "--only-upgrade", "-y", "curl"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .elevated();
        let s = elevate(&apt, Elevation::Sudo);
        assert_eq!(s.program, "/usr/bin/sudo");
        assert_eq!(
            s.args,
            [
                "--",
                "/usr/bin/env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "--only-upgrade",
                "-y",
                "curl"
            ]
        );
        assert!(!s.needs_elevation);
        assert_eq!(elevate(&apt, Elevation::SudoNonInteractive).args[..2], ["-n", "--"]);
        assert_eq!(elevate(&apt, Elevation::Pkexec).program, "/usr/bin/pkexec");
    }

    #[test]
    fn macos_admin_prompt_escapes_for_applescript() {
        let spec = CommandSpec::new("softwareupdate", &["--install", "macOS Tahoe 26.7.2-25H200"]).elevated();
        let s = elevate(&spec, Elevation::MacosAdminPrompt);
        assert_eq!(s.program, "/usr/bin/osascript");
        assert_eq!(
            s.args[1],
            "do shell script \"softwareupdate --install 'macOS Tahoe 26.7.2-25H200'\" with administrator privileges"
        );
        let nasty = CommandSpec::new("x", &["a\"b\\c"]).elevated();
        let s = elevate(&nasty, Elevation::MacosAdminPrompt);
        assert!(s.args[1].contains(r#"'a\"b\\c'"#), "{}", s.args[1]);
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
            CommandSpec::new("powershell", &["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
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
