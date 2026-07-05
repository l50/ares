use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use crate::ToolOutput;

/// Default timeout for tool execution (2 minutes).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Map a program name to a prioritized list of candidate executables that
/// satisfy the same role. Used to recover when an image ships a broken or
/// missing symlink for the canonical name (e.g. the Kali pipx install of
/// NetExec creates `/usr/local/bin/NetExec` but the lowercase
/// `/usr/local/bin/netexec` symlink is sometimes broken/self-referential).
///
/// First candidate that resolves on PATH (or is an absolute path that
/// exists) wins. Returns `None` to mean "use the program as-is".
fn resolve_program_alias(program: &str) -> Option<&'static [&'static str]> {
    match program {
        // NetExec a.k.a. nxc a.k.a. legacy crackmapexec.
        "netexec" | "nxc" | "NetExec" => Some(&[
            "netexec",
            "nxc",
            "NetExec",
            "/opt/pipx/venvs/netexec/bin/NetExec",
            "/opt/pipx/venvs/netexec/bin/netexec",
            "crackmapexec",
        ]),
        _ => None,
    }
}

/// Return the first candidate that is resolvable (either an absolute path
/// that exists, or a bare name that `which`-resolves on PATH).
fn first_resolvable<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    use std::path::Path;
    for cand in candidates {
        if cand.contains('/') {
            // Absolute or relative path — check existence directly so we
            // sidestep broken symlinks (readlink returns Ok for those).
            if Path::new(cand).exists() {
                return Some(cand);
            }
            continue;
        }
        // Bare name — walk $PATH and check that each candidate resolves to
        // a file that actually exists. `metadata()` follows symlinks, so a
        // self-referential symlink returns Err and we skip it.
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in path_var.split(':') {
                if dir.is_empty() {
                    continue;
                }
                let full = Path::new(dir).join(cand);
                if std::fs::metadata(&full).is_ok() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Builder for constructing and executing subprocess commands with timeout support.
pub struct CommandBuilder {
    program: String,
    args: Vec<String>,
    env_vars: Vec<(String, String)>,
    timeout: Duration,
    stdin_data: Option<String>,
    cwd: Option<std::path::PathBuf>,
}

impl CommandBuilder {
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
            env_vars: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            stdin_data: None,
            cwd: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Only add the arg if the condition is true.
    pub fn arg_if(self, condition: bool, arg: impl Into<String>) -> Self {
        if condition {
            self.arg(arg)
        } else {
            self
        }
    }

    /// Add a flag and its value as two separate args (e.g., `-p 445`).
    pub fn flag(self, flag: &str, value: impl Into<String>) -> Self {
        self.arg(flag).arg(value)
    }

    /// Add a flag and value only if the value is Some.
    pub fn flag_opt(self, flag: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.flag(flag, v),
            None => self,
        }
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }

    pub fn stdin(mut self, data: impl Into<String>) -> Self {
        self.stdin_data = Some(data.into());
        self
    }

    pub fn current_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Test accessor for the positional/flag arg vector. Used by unit tests
    /// (in this crate and downstream callers) to assert on the constructed
    /// command line without actually spawning the binary — e.g., that
    /// `-k -no-pass` is present when a Kerberos ccache is supplied.
    ///
    /// Exposed (rather than `#[cfg(test)]`-gated) so the ares-cli worker
    /// crate can write the Bug-B contract test that walks the resolver's
    /// `tool_consumes_ticket_path` allowlist.
    #[doc(hidden)]
    pub fn args_for_test(&self) -> &[String] {
        &self.args
    }

    /// Test accessor for the environment-variable list. Used to assert that
    /// tools wire `KRB5CCNAME` into the child process when the caller
    /// supplies a `ticket_path` — Bug B silent-drop guard.
    #[doc(hidden)]
    pub fn env_vars_for_test(&self) -> &[(String, String)] {
        &self.env_vars
    }

    pub async fn execute(self) -> Result<ToolOutput> {
        #[cfg(test)]
        {
            if let Some(output) = mock::take_next() {
                return Ok(output);
            }
        }

        let display_cmd = format!("{} {}", self.program, self.args.join(" "));
        tracing::debug!(cmd = %display_cmd, timeout = ?self.timeout, "executing tool command");

        // Global cap on concurrent subprocess spawns. Held for the full
        // spawn+wait lifetime; released when this function returns.
        let _tool_permit = crate::concurrency::acquire_tool_permit().await;

        // Resolve aliases like `netexec` -> `NetExec` when the canonical
        // name isn't resolvable on PATH (broken symlink, etc.).
        let resolved_program: String = match resolve_program_alias(&self.program) {
            Some(candidates) => match first_resolvable(candidates) {
                Some(found) => found.to_string(),
                None => self.program.clone(),
            },
            None => self.program.clone(),
        };
        if resolved_program != self.program {
            tracing::debug!(
                requested = %self.program,
                resolved = %resolved_program,
                "resolved program alias"
            );
        }

        let mut cmd = Command::new(&resolved_program);
        cmd.args(&self.args);

        if let Some(ref dir) = self.cwd {
            cmd.current_dir(dir);
        }

        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        if self.stdin_data.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // Send SIGKILL when the `Child` is dropped. Required for the
        // timeout-abort path below to actually terminate the OS process
        // (tokio's default is to leave the child running on drop).
        cmd.kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn '{}' — is it installed?", self.program))?;

        if let Some(data) = &self.stdin_data {
            use tokio::io::AsyncWriteExt;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data.as_bytes()).await?;
                drop(stdin);
            }
        }

        // Move the child into a task so we can cancel the wait on timeout.
        // On timeout we must `handle.abort()` — merely dropping a `JoinHandle`
        // detaches the task and the child continues to run. Aborting drops
        // the task's owned `Child`, and the `kill_on_drop(true)` above then
        // sends SIGKILL to the OS process.
        let timeout = self.timeout;
        let handle = tokio::spawn(async move { child.wait_with_output().await });
        let abort = handle.abort_handle();

        let join_result = tokio::time::timeout(timeout, handle).await;

        match join_result {
            Ok(Ok(Ok(output))) => {
                let stdout = sanitize_tool_output(&output.stdout);
                let stderr = sanitize_tool_output(&output.stderr);
                let exit_code = output.status.code();
                let success = output.status.success();

                tracing::debug!(
                    exit_code = ?exit_code,
                    stdout_len = stdout.len(),
                    stderr_len = stderr.len(),
                    "command completed"
                );

                Ok(ToolOutput {
                    stdout,
                    stderr,
                    exit_code,
                    success,
                })
            }
            Ok(Ok(Err(e))) => Err(anyhow::anyhow!("command execution failed: {e}")),
            Ok(Err(e)) => Err(anyhow::anyhow!("task join error: {e}")),
            Err(_) => {
                abort.abort();
                Err(anyhow::anyhow!(
                    "command timed out after {:?}: {}",
                    timeout,
                    display_cmd
                ))
            }
        }
    }
}

/// Convert raw bytes to a clean UTF-8 string safe for JSON serialization.
/// Strips null bytes and C0 control characters (except newline, tab, carriage return)
/// that would cause OpenAI-compatible APIs to reject the payload.
fn sanitize_tool_output(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| {
            // Keep printable chars, newline, tab, carriage return
            // Strip null bytes and other C0 controls that break JSON parsers
            *c >= ' ' || *c == '\n' || *c == '\t' || *c == '\r'
        })
        .collect()
}

/// Convenience: run a simple command with default timeout.
pub async fn run(program: &str, args: &[&str]) -> Result<ToolOutput> {
    CommandBuilder::new(program)
        .args(args.iter().map(|s| s.to_string()))
        .execute()
        .await
}

/// Mock executor for testing tool wrapper functions without spawning subprocesses.
///
/// In test mode, push `ToolOutput` values onto the thread-local queue.
/// Each `CommandBuilder::execute()` call pops the next response (or falls through
/// to real execution if the queue is empty).
#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    thread_local! {
        static RESPONSES: RefCell<VecDeque<ToolOutput>> = const { RefCell::new(VecDeque::new()) };
    }

    /// Push a single mock response onto the queue.
    pub fn push(output: ToolOutput) {
        RESPONSES.with(|r| r.borrow_mut().push_back(output));
    }

    /// Pop the next response, or `None` to fall through to real execution.
    pub(super) fn take_next() -> Option<ToolOutput> {
        RESPONSES.with(|r| r.borrow_mut().pop_front())
    }

    /// Create a default success output.
    pub fn success() -> ToolOutput {
        ToolOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        }
    }

    /// Create a success output with custom stdout.
    pub fn success_with_stdout(stdout: impl Into<String>) -> ToolOutput {
        ToolOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_tool_output ─────────────────────────────────────────────────

    #[test]
    fn sanitize_valid_utf8_passthrough() {
        let input = b"hello world";
        assert_eq!(sanitize_tool_output(input), "hello world");
    }

    #[test]
    fn sanitize_strips_null_bytes() {
        let input = b"hel\x00lo";
        assert_eq!(sanitize_tool_output(input), "hello");
    }

    #[test]
    fn sanitize_strips_c0_control_chars() {
        // \x01 (SOH), \x07 (BEL), \x1b (ESC) are C0 controls that must be stripped
        let input = b"he\x01ll\x07o\x1b";
        assert_eq!(sanitize_tool_output(input), "hello");
    }

    #[test]
    fn sanitize_preserves_newline_tab_cr() {
        let input = b"line1\nline2\ttabbed\r\nwindows";
        assert_eq!(
            sanitize_tool_output(input),
            "line1\nline2\ttabbed\r\nwindows"
        );
    }

    #[test]
    fn sanitize_empty_input() {
        assert_eq!(sanitize_tool_output(b""), "");
    }

    #[test]
    fn sanitize_lossy_utf8() {
        // 0xff is not valid UTF-8; from_utf8_lossy replaces it with U+FFFD.
        // U+FFFD (0xFFFD) is >= ' ', so it should be kept.
        let input = b"ok\xff!";
        let result = sanitize_tool_output(input);
        assert!(result.starts_with("ok"));
        assert!(result.ends_with('!'));
        // Replacement char is present somewhere between them
        assert!(result.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_mixed_control_and_printable() {
        // BEL (\x07) stripped, space and printable kept, newline kept
        let input = b"alert\x07\nsafe text";
        assert_eq!(sanitize_tool_output(input), "alert\nsafe text");
    }

    // ── CommandBuilder builder API ───────────────────────────────────────────

    #[test]
    fn builder_new_does_not_panic() {
        let _b = CommandBuilder::new("echo");
    }

    #[test]
    fn builder_arg_chains() {
        let _b = CommandBuilder::new("echo").arg("hello").arg("world");
    }

    #[test]
    fn builder_args_chains() {
        let _b = CommandBuilder::new("ls").args(["-l", "-a"]);
    }

    #[test]
    fn builder_arg_if_true_adds_arg() {
        // We can't inspect private fields, but we verify it returns Self (compiles & doesn't panic).
        let _b = CommandBuilder::new("cmd").arg_if(true, "--verbose");
    }

    #[test]
    fn builder_arg_if_false_skips_arg() {
        let _b = CommandBuilder::new("cmd").arg_if(false, "--verbose");
    }

    #[test]
    fn builder_flag_chains() {
        let _b = CommandBuilder::new("nmap").flag("-p", "445");
    }

    #[test]
    fn builder_flag_opt_some_chains() {
        let _b = CommandBuilder::new("cmd").flag_opt("-u", Some("admin"));
    }

    #[test]
    fn builder_flag_opt_none_skips() {
        let _b = CommandBuilder::new("cmd").flag_opt("-u", Option::<String>::None);
    }

    #[test]
    fn builder_env_chains() {
        let _b = CommandBuilder::new("cmd").env("MY_VAR", "value");
    }

    #[test]
    fn builder_timeout_secs_chains() {
        let _b = CommandBuilder::new("cmd").timeout_secs(30);
    }

    #[test]
    fn builder_stdin_chains() {
        let _b = CommandBuilder::new("cmd").stdin("input data");
    }

    #[test]
    fn builder_full_chain_does_not_panic() {
        let _b = CommandBuilder::new("netexec")
            .arg("smb")
            .args(["192.168.58.10", "-u", "admin"])
            .flag("-p", "Password1")
            .flag_opt("--domain", Some("contoso.local"))
            .flag_opt("--extra", Option::<String>::None)
            .arg_if(true, "--shares")
            .arg_if(false, "--sam")
            .env("KRB5CCNAME", "/tmp/ticket.ccache")
            .timeout_secs(60)
            .stdin("y\n");
    }

    // ── timeout kills the child process ─────────────────────────────────────
    //
    // Regression guard for the OOM cause where a hung tool's `Child` was
    // detached (via dropping the `JoinHandle`) instead of aborted, leaking
    // the OS process. Verifies end-to-end that timeout → abort → SIGKILL.

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_child_process() {
        use std::time::{Duration, Instant};

        // sh writes its PID to a temp file, then `exec sleep 30` replaces
        // the shell process with sleep — same PID, so the file tells us
        // exactly which OS process to check for aliveness after timeout.
        let pid_file = tempfile::NamedTempFile::new().unwrap();
        let script = format!("echo $$ > {} && exec sleep 30", pid_file.path().display());

        let start = Instant::now();
        let result = CommandBuilder::new("sh")
            .arg("-c")
            .arg(&script)
            .timeout(Duration::from_millis(500))
            .execute()
            .await;
        let elapsed = start.elapsed();

        // Must time out, not wait 30s.
        assert!(result.is_err(), "expected timeout error, got {result:?}");
        assert!(
            elapsed < Duration::from_secs(3),
            "execute() didn't return promptly on timeout: {elapsed:?}"
        );

        // Give the runtime a moment to drop the aborted task and let the
        // OS deliver SIGKILL + reap. 200ms is generous; the abort chain is
        // synchronous up to the kernel signal.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Read the PID sh wrote before exec'ing sleep.
        let pid_str = std::fs::read_to_string(pid_file.path())
            .expect("child never wrote its PID — script didn't run at all");
        let pid: i32 = pid_str
            .trim()
            .parse()
            .expect("PID file contained non-integer");

        // `kill -0 <pid>` returns 0 if the process exists and we can signal
        // it, non-zero (ESRCH) if it's gone. This is the actual assertion
        // the whole fix hinges on.
        let alive = std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .expect("failed to invoke `kill -0`")
            .success();

        assert!(
            !alive,
            "child pid {pid} is still alive after timeout — abort/kill path is broken"
        );
    }
}
