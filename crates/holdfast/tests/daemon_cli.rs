//! Process-level tests: real `holdfast` processes, real sockets, real
//! auto-spawn (spec §7.3, §3.2, §3.4).
//!
//! Everything here runs against `CARGO_BIN_EXE_holdfast`, so it exercises
//! the same binary a user installs. Each test owns a private
//! `HOLDFAST_RUNTIME_DIR`; `TestEnv::drop` stops the daemon and removes it,
//! so a failed run cannot wedge the next one.
//!
//! ## Nothing in this file may block without a deadline
//!
//! Every wait here is bounded, and that is a property of the suite
//! rather than defensive habit. These tests drive processes that can
//! stop answering without dying — a shim whose daemon accepted the
//! connection and never replied, a `holdfast logs` parked in `call_raw`,
//! which has no timeout of its own. A mutation that turns a reply into
//! silence should redden the build rather than hang it, and a hung job
//! looks like an infrastructure problem for as long as it takes someone
//! to read the logs.
//!
//! **The reason this used to give — "the workspace has no
//! `nextest.toml` and no per-test harness timeout" — is no longer
//! true, and it is corrected rather than left**, because a stale reason
//! is how a discipline gets dropped by the next person who checks it.
//! `.config/nextest.toml` landed in #93 with `slow-timeout = { period =
//! "60s", terminate-after = 5 }`. `tests/worker_protocol.rs` has
//! already settled what that changes: *"a hang is now named at 300 s
//! instead of taking the job down anonymously. That changes what a hang
//! costs, not whether one is acceptable."* Two things it does not
//! change at all. It reads only under `cargo nextest run`, and
//! `scripts/ci-flake-hunt.sh` deliberately runs `cargo test` — *"Do not
//! 'modernise' this line"* — a hundred times per `nightly.yml` run, so
//! an unbounded wait there is bounded by nothing short of the job's
//! `timeout-minutes: 180`, which yields no verdict and no artifact. And
//! a harness kill names the test but never the wait.
//!
//! So a wait that expires **panics**. It is never absorbed into an
//! `Ok(_) | Err(_)` that would let a timeout count as a pass.

// Unix-only, like `attach_cli.rs` above it. Everything below drives a real
// daemon over a Unix socket, and §3.3/§3.6 give Windows native neither —
// `holdfast-core`'s `daemon::{attach_server, peer, server, spawn}` are
// `#[cfg(unix)]` from #19 on, so these targets have nothing to link
// against there rather than nothing to say.
//
// **Named per module, and NOT as `daemon`, which is what this comment
// said until PR #87's review.** `daemon::paths` is deliberately ungated —
// the argument is in `src/daemon/mod.rs`, which calls that asymmetry the
// whole shape of the module on Windows — so "the `daemon` module is
// `#[cfg(unix)]`" is false, and false in the direction that makes a real
// gate look vacuous: `ci.yml`'s `windows-native` job runs a filtered
// `--lib` over `daemon::paths::{home_tests, log_append_tests}` and
// asserts a floor on how many rows ran, which is only reachable because
// `paths` compiles on Windows. `tests/wire_shape.rs` had the form right,
// naming `daemon::server` rather than its parent.
#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Barrier;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_holdfast");

/// How long a `holdfast` subcommand may take before it is treated as hung.
///
/// Generous on purpose: `daemon start` can legitimately spend
/// `LOCK_TIMEOUT` (5 s) waiting for a contended `holdfast.lock` and then
/// `SPAWN_TIMEOUT` (2 s) waiting for the daemon to answer, and the whole
/// suite runs in parallel on a machine that may be loaded. This is not a
/// performance assertion — it is the line past which "slow" and
/// "wedged" stop being worth distinguishing.
const CLI_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the shim may take to answer one JSON-RPC request.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// The `aws-access-key-id` rule's own `positive` example from
/// `crates/holdfast-core/data/redaction_default.toml`. A fixture with a
/// documented shape, not a credential — the same choice
/// `scripts/mcp-smoke.sh` makes with its GitHub token.
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// The marker the redactor leaves in its place.
const AWS_MARK: &str = "[REDACTED:aws]";

struct TestEnv {
    dir: PathBuf,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        // `/tmp/holdfast-cli-*`, not the workspace `target/`: a socket under
        // `target/` overruns `sockaddr_un.sun_path`.
        let unique = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = PathBuf::from(format!("/tmp/holdfast-cli-{tag}-{unique}-{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        Self { dir }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env("HOLDFAST_RUNTIME_DIR", &self.dir);
        // §10.1's discovery is `$XDG_CONFIG_HOME/holdfast/config.toml`, and
        // `HOLDFAST_RUNTIME_DIR` deliberately does **not** move it
        // (REQ-CFG-005 is instance selection, not a configuration knob).
        // So a test that did not set this would run the daemon against
        // the *developer's* `~/.config/holdfast/config.toml` — the same
        // class of leak `audit_log()` closes for `~/.holdfast/logs`, and
        // the reason a config assertion here could otherwise mean
        // nothing. Absent by default, which resolves to `Config::default`.
        c.env("XDG_CONFIG_HOME", self.dir.join("xdg-config"));
        c
    }

    /// Write this instance's `config.toml` at the path §10.1 discovers.
    fn write_config(&self, body: &str) {
        // The runtime directory itself must be created `0700` here,
        // because writing the config is what brings it into existence
        // and `ensure_dir` **refuses** a group- or world-writable
        // directory rather than tightening it. A plain `create_dir_all`
        // takes the umask, and on a machine with a `0002` umask the
        // daemon then declines to start for a reason that has nothing to
        // do with the config under test.
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .expect("create runtime dir 0700");
        let dir = self.dir.join("xdg-config").join("holdfast");
        std::fs::create_dir_all(&dir).expect("create config dir");
        std::fs::write(dir.join("config.toml"), body).expect("write config.toml");
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let child = self
            .cmd()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run holdfast");
        match wait_bounded(child, CLI_TIMEOUT) {
            Some(result) => result,
            None => panic!(
                "`holdfast {}` did not exit within {CLI_TIMEOUT:?} and was killed",
                args.join(" ")
            ),
        }
    }

    fn daemon_pid(&self) -> Option<u32> {
        let text = std::fs::read_to_string(self.dir.join("holdfast.pid")).ok()?;
        text.split_whitespace().next()?.parse().ok()
    }

    /// Plant a `holdfast.pid` naming `pid`, in `write_pid_file`'s shape —
    /// `"<pid> <version>\n"` — which is what a daemon that died without
    /// cleaning up leaves behind.
    fn plant_pid_file(&self, pid: u32) {
        std::fs::write(
            self.dir.join("holdfast.pid"),
            format!("{pid} {}\n", env!("CARGO_PKG_VERSION")),
        )
        .expect("write holdfast.pid");
    }

    /// Wait, bounded, for the daemon to remove its own `holdfast.pid`.
    ///
    /// `daemon/stop` is answered before `server::run` reaches its
    /// cleanup, so a test that planted a pid file the instant the command
    /// returned could have it deleted out from under itself — and would
    /// then pass against a `--force` that never read one at all.
    fn await_no_pid_file(&self) {
        let path = self.dir.join("holdfast.pid");
        let deadline = Instant::now() + Duration::from_secs(10);
        while path.exists() {
            assert!(
                Instant::now() < deadline,
                "{} outlived `daemon stop`",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Every `redaction_disabled` entry in this instance's §9.4 audit log.
    ///
    /// Read from `$HOLDFAST_RUNTIME_DIR/logs/audit.log` rather than from
    /// `~/.holdfast/logs`, which is what keeps a test run out of the
    /// developer's real trail — and what makes a count assertion mean
    /// anything at all.
    fn redaction_disabled_entries(&self) -> Vec<Value> {
        let path = self.dir.join("logs").join("audit.log");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("no audit log at {}: {e}", path.display()));
        text.lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["kind"] == "redaction_disabled")
            .collect()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Bounded like everything else, but silent: a wedged daemon here
        // must not turn a passing test into a panic-during-drop, which
        // aborts the process and takes the real verdict with it.
        if let Ok(child) = self
            .cmd()
            .args(["daemon", "stop", "--force"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            let _ = wait_bounded(child, CLI_TIMEOUT);
        }
        // The daemon needs a beat to unlink its socket before the
        // directory can go, and a walk that races it can fail partway.
        std::thread::sleep(Duration::from_millis(150));
        for _ in 0..20 {
            match std::fs::remove_dir_all(&self.dir) {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(_) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }
}

/// Wait for `child`, killing it if it outlives `limit`.
///
/// `None` means it had to be killed, which is a hang; no caller treats
/// that as success. Both pipes are drained on their own threads before
/// the wait, because `holdfast logs` can print a quarter of a megabyte and
/// a child blocked on a full pipe would otherwise never reach the exit
/// this polls for — a deadlock produced by the very code meant to bound
/// one.
fn wait_bounded(mut child: Child, limit: Duration) -> Option<(i32, String, String)> {
    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");
    let out_h = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        buf
    });
    let err_h = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait().expect("wait for holdfast") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = String::from_utf8_lossy(&out_h.join().expect("stdout reader")).into_owned();
    let stderr = String::from_utf8_lossy(&err_h.join().expect("stderr reader")).into_owned();
    status.map(|s| (s.code().unwrap_or(-1), stdout, stderr))
}

fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 performs the existence/permission check only.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn signal(pid: u32, sig: i32) -> bool {
    // SAFETY: `kill` takes no pointers.
    unsafe { libc::kill(pid as i32, sig) == 0 }
}

/// Whether this machine has the `/proc` that `--force`'s pid
/// confirmation reads. Tests that turn on it skip elsewhere, the way
/// `the_running_daemon_holds_no_listening_tcp_socket` does.
fn have_proc() -> bool {
    PathBuf::from("/proc/self/fd").exists()
}

/// What the daemon's fd table says about its sockets: how many it holds
/// at all, and any TCP listeners among them.
///
/// Two implementations because the question has two spellings, not
/// because the platforms disagree about the answer. Linux reads
/// `/proc/<pid>/fd` for socket inodes and intersects them with
/// `/proc/net/tcp{,6}`. macOS has neither file, and `lsof` answers both
/// halves directly.
///
/// **The macOS arm exists because the guard it replaces returned early.**
/// That made "the daemon binds no TCP port" — the property 0.0.10's
/// bridge will be measured against, and the one a reader of this file
/// would assume is checked everywhere — pass on macOS without ever being
/// asked. The count is the witness that the scan saw anything at all, so
/// an empty answer cannot read as a clean result.
#[cfg(target_os = "linux")]
fn daemon_sockets(pid: u32) -> (usize, Vec<String>) {
    let mut inodes = std::collections::HashSet::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read the daemon's fd table")
        .flatten()
    {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let s = target.to_string_lossy().into_owned();
            if let Some(i) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                inodes.insert(i.to_string());
            }
        }
    }
    let mut listening = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Field 3 is the state (`0A` = TCP_LISTEN); field 9 is the inode.
            if f.len() > 9 && f[3] == "0A" && inodes.contains(f[9]) {
                listening.push(line.to_string());
            }
        }
    }
    (inodes.len(), listening)
}

/// The `n` lines of an `lsof -F` report — one path or address per line.
#[cfg(not(target_os = "linux"))]
fn lsof_names(args: &[&str]) -> Vec<String> {
    let Ok(out) = Command::new("lsof").args(args).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix('n').map(str::to_string))
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn daemon_sockets(pid: u32) -> (usize, Vec<String>) {
    let pid = pid.to_string();
    // `-U` alone for the witness: the daemon's own listener is a Unix
    // socket, so a zero here means `lsof` answered nothing rather than
    // that the daemon is clean.
    let held = lsof_names(&["-a", "-p", &pid, "-U", "-F", "n"]);
    let listening = lsof_names(&["-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN", "-F", "n"]);
    (held.len(), listening)
}

/// Pids of the `holdfast daemon run` processes serving `runtime_dir`.
///
/// Asked differently per platform, because the two expose process
/// identity differently:
///
/// * Linux reads the command from `/proc/<pid>/cmdline` and the
///   instance from the `HOLDFAST_RUNTIME_DIR` in `/proc/<pid>/environ`.
/// * macOS has no `/proc`, and no route to another process's
///   environment at all: that goes through `KERN_PROCARGS2`, which
///   stopped handing out the environment portion in Catalina — `ps -E`
///   prints nothing even for a process this very user owns. So the
///   instance is confirmed from the `control.sock` the daemon has
///   **bound**, which is the stronger claim of the two: it says the
///   process is serving this runtime dir, not merely that it was
///   pointed at one when it started.
///
/// Matched on the runtime dir's own directory name rather than its full
/// path, because `/tmp` is a symlink to `/private/tmp` on macOS and
/// `lsof` may report either side of it. `TestEnv::new` builds that name
/// from the pid and a nanosecond count, so it is unique per test.
#[cfg(target_os = "linux")]
fn daemons_for(runtime_dir: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if !String::from_utf8_lossy(&cmdline)
            .replace('\0', " ")
            .contains("daemon run")
        {
            continue;
        }
        let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
            continue;
        };
        if String::from_utf8_lossy(&environ)
            .replace('\0', "\n")
            .contains(&format!("HOLDFAST_RUNTIME_DIR={}", runtime_dir.display()))
        {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(not(target_os = "linux"))]
fn daemons_for(runtime_dir: &Path) -> Vec<u32> {
    let marker = format!(
        "{}/control.sock",
        runtime_dir
            .file_name()
            .expect("the runtime dir has a final component")
            .to_string_lossy()
    );
    // `-ww` because `ps` otherwise clamps the argv column and the `run`
    // being matched on is what would be cut.
    let listing = Command::new("ps")
        .args(["-A", "-ww", "-o", "pid=,args="])
        .output()
        .expect("ps enumerates processes");
    let mut pids = Vec::new();
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        let Some((pid, args)) = line.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if !args.contains("daemon run") {
            continue;
        }
        // `-U` restricts the report to Unix sockets and `-F n` asks for
        // the parsable form: one field per line, `n` carrying the path.
        let Ok(open) = Command::new("lsof")
            .args(["-a", "-p", &pid.to_string(), "-U", "-F", "n"])
            .output()
        else {
            continue;
        };
        if String::from_utf8_lossy(&open.stdout)
            .lines()
            .any(|l| l.strip_prefix('n').is_some_and(|s| s.ends_with(&marker)))
        {
            pids.push(pid);
        }
    }
    pids
}

/// The state letter from `/proc/<pid>/stat` — `T` stopped, `Z` zombie —
/// or `None` when the process is gone.
///
/// Read from after the **last** `)`: field 2 is the executable name in
/// parentheses, and it may itself contain spaces and parentheses.
fn proc_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, after_comm) = stat.rsplit_once(')')?;
    after_comm.split_whitespace().next()?.chars().next()
}

/// Dead, or dead enough.
///
/// Not `!alive(pid)`: a killed process lingers as a zombie until its
/// parent reaps it, and `kill(pid, 0)` answers `0` for a zombie. A test
/// that asked `alive` about a process it had just killed would be
/// waiting on the reaper, not on the kill.
fn ended(pid: u32) -> bool {
    !matches!(proc_state(pid), Some(state) if state != 'Z')
}

/// A `holdfast mcp` process driven over stdio with raw JSON-RPC.
struct Shim {
    child: Child,
    /// Lines of the shim's stdout, delivered by a reader thread.
    ///
    /// A thread and a channel rather than a `BufReader` read inline,
    /// because `read_line` on a live-but-silent child never returns and
    /// this suite may not contain an unbounded wait. `recv_timeout` gives
    /// the same bytes with a deadline, and a closed channel is EOF.
    lines: Receiver<String>,
    next_id: u64,
}

impl Shim {
    fn start(env: &TestEnv) -> Self {
        Self::spawn(env, &["mcp"])
    }

    fn spawn(env: &TestEnv, args: &[&str]) -> Self {
        Self::spawn_cmd(env.cmd(), args)
    }

    /// [`Shim::spawn`] over a command the caller has already adjusted.
    ///
    /// Exists for the one environment variable `TestEnv::cmd` cannot set
    /// for everybody: `$HOME`. See
    /// `the_no_daemon_server_honours_a_configured_session_cap`.
    fn spawn_cmd(mut cmd: Command, args: &[&str]) -> Self {
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn holdfast mcp");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let mut shim = Self {
            child,
            lines,
            next_id: 1,
        };
        shim.initialize();
        shim
    }

    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn read_response(&mut self) -> Value {
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let line = match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the shim did not answer within {RESPONSE_TIMEOUT:?}")
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("the shim closed stdout before responding")
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            // Strict, and this is the only place that can be. The shim's
            // stdout **is** the MCP transport, so anything on it that is
            // not JSON-RPC is a protocol violation, not noise to skip
            // past. Skipping it is how `ensure_daemon`'s inherited
            // stdout put `daemon started (pid N)` in front of every
            // client's first response and no Rust test noticed.
            let value: Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| {
                panic!("the shim wrote a non-JSON-RPC line to stdout, which is the MCP transport: {line:?} ({e})")
            });
            if value.get("id").is_some() {
                return value;
            }
        }
    }

    fn initialize(&mut self) {
        self.send(
            &json!({
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "holdfast-test", "version": "0" }
                }
            })
            .to_string(),
        );
        let init = self.read_response();
        assert!(
            init["result"]["capabilities"]["tools"].is_object(),
            "{init}"
        );
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(
            &json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": name, "arguments": arguments }
            })
            .to_string(),
        );
        self.read_response()
    }

    fn list_tools(&mut self) -> Vec<String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(
            &json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}}).to_string(),
        );
        let resp = self.read_response();
        resp["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// Poll `read_output` until `needle` appears, from cursor 0 each time.
    fn read_until(&mut self, session: &str, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let resp = self.call_tool(
                "read_output",
                json!({ "session": session, "since_cursor": 0, "max_bytes": 262144 }),
            );
            let out = resp["result"]["structuredContent"]["data"]["output"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if out.contains(needle) || Instant::now() >= deadline {
                return out;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A live session whose buffer holds a secret-shaped value, under the
/// name `tag`. Shared by Step 5b's three `--raw` tests, which differ in
/// what they read rather than in how they get there.
///
/// The key is asserted **present in redacted form** before the caller
/// gets the session back. Without that, a `--raw` test that found no key
/// could not tell "redaction is working" from "the shell never ran the
/// command", and the two want opposite conclusions.
fn session_holding_a_secret(env: &TestEnv, tag: &str) -> (Shim, String) {
    let mut shim = Shim::start(env);
    let started = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": tag }),
    );
    assert_eq!(
        started["result"]["structuredContent"]["status"], "ok",
        "{started}"
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    shim.call_tool(
        "send_input",
        json!({ "session": session_id, "data": format!("echo {AWS_KEY}") }),
    );
    let seen = shim.read_until(&session_id, AWS_MARK);
    assert!(
        seen.contains(AWS_MARK),
        "the session never produced a redactable value; got: {seen:?}"
    );
    (shim, session_id)
}

#[test]
fn daemon_start_is_idempotent_and_status_reports_the_running_daemon() {
    let env = TestEnv::new("startstop");

    let (code, out, err) = env.run(&["daemon", "start"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("daemon started"), "{out}");
    let pid = env.daemon_pid().expect("pid file");
    assert!(alive(pid), "the daemon process {pid} is not running");

    // Second start must not spawn a second daemon.
    let (code, out, _) = env.run(&["daemon", "start"]);
    assert_eq!(code, 0);
    assert!(out.contains("already running"), "{out}");
    assert_eq!(env.daemon_pid(), Some(pid), "a second daemon was started");

    let (code, out, err) = env.run(&["daemon", "status", "--json"]);
    assert_eq!(code, 0, "stderr: {err}");
    let status: Value = serde_json::from_str(out.trim()).expect("json status");
    assert_eq!(status["pid"].as_u64(), Some(pid as u64));
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["sessions_live"], 0);

    let (code, out, err) = env.run(&["daemon", "stop"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("daemon stopped"), "{out}");

    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive(pid), "the daemon process survived `daemon stop`");
}

#[test]
fn an_explicit_runtime_dir_keeps_its_daemon_log_out_of_the_home_directory() {
    // §7.1: `HOLDFAST_RUNTIME_DIR` relocates the daemon log too, so an
    // isolated instance leaves nothing behind in `~`. §19.1's
    // `~/.holdfast/logs/daemon.log` is the *default* instance's path, and a
    // daemon that wrote there unconditionally would have every test run
    // and every scratch instance appending to the user's real log.
    let env = TestEnv::new("logdir");
    assert_eq!(env.run(&["daemon", "start"]).0, 0);

    let log = env.dir.join("logs").join("daemon.log");
    assert!(
        log.exists(),
        "the relocated daemon log was not created at {}",
        log.display()
    );
}

#[test]
fn two_daemons_under_different_runtime_dirs_do_not_see_each_others_sessions() {
    // REQ-CFG-005's first named verification, and the one nothing else
    // in this plan covers. `two_shims_racing_to_start_share_one_daemon`
    // is its mirror image — two clients, ONE runtime dir, one registry —
    // and passing that says nothing about whether the directory is
    // actually what separates two instances.
    //
    // The failure this kills is a `RuntimePaths::discover` that reads
    // `HOLDFAST_RUNTIME_DIR` for the socket but not for the registry, or a
    // process-wide singleton registry behind the daemon. Either one
    // leaks one user's sessions into a second instance's listing, which
    // is REQ-CFG-005's whole subject.
    let a = TestEnv::new("iso-a");
    let b = TestEnv::new("iso-b");
    assert_ne!(a.dir, b.dir, "the fixture must give two distinct instances");

    let mut shim_a = Shim::start(&a);
    let started = shim_a.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "only_in_a" }),
    );
    let id_a = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // The positive: A's own listing has it. Without this the negative
    // below passes against two daemons that both list nothing — a
    // registry that is broken rather than one that is isolated.
    let (code, listing_a, err) = a.run(&["list", "--json"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        listing_a.contains(&id_a),
        "instance A lost the session it created: {listing_a}"
    );

    // The negative. `holdfast list` does **not** auto-spawn — only
    // `holdfast mcp` does (§7.3) — so B's daemon is started explicitly.
    // That matters: without it `list` would exit 2 on an unreachable
    // socket and the emptiness below would be a connection failure
    // wearing the costume of isolation.
    assert_eq!(b.run(&["daemon", "start"]).0, 0);
    let (code, listing_b, err) = b.run(&["list", "--json"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        !listing_b.contains(&id_a),
        "instance B can see instance A's session {id_a}: {listing_b}"
    );
    assert_ne!(
        a.daemon_pid(),
        b.daemon_pid(),
        "two runtime directories must mean two daemon processes"
    );

    shim_a.call_tool("terminate", json!({ "session": id_a, "force": true }));
    shim_a.kill();
}

#[test]
fn stopping_a_daemon_that_is_not_running_succeeds() {
    // §3.2: idempotent, exit 0, friendly message.
    let env = TestEnv::new("stopnone");
    let (code, out, _) = env.run(&["daemon", "stop"]);
    assert_eq!(code, 0);
    assert!(out.contains("no daemon running"), "{out}");
}

#[test]
fn daemon_stop_force_kills_a_daemon_that_has_stopped_answering() {
    // §3.2: *"`--force` makes the wait 0 and immediately escalates to
    // `SIGKILL` on the daemon."* The RPC cannot deliver that on its own —
    // `daemon/stop` kills the *sessions* and asks the accept loop to
    // stop, and a wedged accept loop never hears it. A daemon that has
    // stopped answering is the only situation in which `--force` is the
    // interesting flag, and it is the situation `TestEnv::drop` assumes
    // is handled: before the escalation existed, teardown here paid the
    // full 60 s `CLI_TIMEOUT` and then leaked the process.
    if !have_proc() {
        return; // The pid confirmation is `/proc`-based; see `commands.rs`.
    }
    let env = TestEnv::new("forcewedge");
    assert_eq!(env.run(&["daemon", "start"]).0, 0);
    let pid = env.daemon_pid().expect("pid file");
    assert!(alive(pid));

    // SIGSTOP is the wedge, and it is what makes this test about
    // `--force` rather than about the healthy path: the process stays,
    // its socket stays bound and still completes a `connect` out of the
    // listen backlog, and nothing behind that socket ever runs again.
    assert!(
        signal(pid, libc::SIGSTOP),
        "SIGSTOP: {}",
        std::io::Error::last_os_error()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while proc_state(pid) != Some('T') && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        proc_state(pid),
        Some('T'),
        "the daemon never entered the stopped state, so this is not a wedged daemon"
    );

    let started = Instant::now();
    let (code, out, err) = env.run(&["daemon", "stop", "--force"]);
    let elapsed = started.elapsed();
    assert_eq!(code, 0, "stdout: {out} stderr: {err}");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ended(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        ended(pid),
        "the daemon survived `daemon stop --force`; stdout: {out} stderr: {err}"
    );
    // Promptness is part of the contract, not a performance note: the
    // control client has no timeout of its own, so a `--force` that
    // waits on the RPC before escalating waits forever against exactly
    // this daemon. Loose enough not to flake on a loaded machine,
    // tight enough that it cannot be satisfied by an unbounded wait
    // (which `TestEnv::run` would turn into a panic at 60 s instead).
    assert!(
        elapsed < Duration::from_secs(30),
        "`--force` spent {elapsed:?} on a daemon that cannot answer"
    );
}

#[test]
fn daemon_stop_force_does_not_signal_a_pid_that_is_not_this_daemon() {
    // The other half of the escalation, and the reason it is allowed to
    // exist. `holdfast.pid` is written once at startup and removed only on
    // a clean exit, so a daemon that was killed leaves it behind naming
    // a pid the kernel is free to hand to anything — and the version
    // string the file also carries says only which holdfast *wrote* it, not
    // who owns the pid now. A `--force` that trusted the file would
    // SIGKILL a stranger.
    let env = TestEnv::new("forcestale");
    assert_eq!(env.run(&["daemon", "start"]).0, 0);
    assert_eq!(env.run(&["daemon", "stop"]).0, 0);
    env.await_no_pid_file();

    let mut bystander = Command::new("sleep")
        .arg("300")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the bystander");
    let victim = bystander.id();
    env.plant_pid_file(victim);

    let (code, out, err) = env.run(&["daemon", "stop", "--force"]);
    assert_eq!(code, 0, "stderr: {err}");

    // The load-bearing assertion, and it goes first so that it is the one
    // a regression trips on rather than a message check standing in front
    // of it. `try_wait`, not `alive`: a SIGKILLed child of this process is
    // a zombie until reaped, and `kill(pid, 0)` answers `0` for a zombie —
    // so the obvious liveness check would pass against the very failure
    // this test exists to catch.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        bystander
            .try_wait()
            .expect("wait for the bystander")
            .is_none(),
        "`--force` signalled pid {victim}, which is a `sleep`, not this instance's daemon"
    );
    let _ = bystander.kill();
    let _ = bystander.wait();

    assert!(out.contains("no daemon running"), "stdout: {out}");
    // Non-vacuity. Without this, the test would also pass against a
    // `--force` that reads no pid file at all — which is the state the
    // finding describes, not the fix.
    // `daemon_stop_force_kills_a_daemon_that_has_stopped_answering` is
    // the other half: it proves the same pid file *is* acted on.
    assert!(
        err.contains(&victim.to_string()),
        "`--force` did not report the pid it declined to signal: {err}"
    );
}

#[test]
fn daemon_stop_force_does_not_kill_another_instances_daemon() {
    // The recycled pid that actually costs something. A stranger at the
    // pid is caught by any check at all; a *second holdfast daemon* at the
    // pid is caught only by one that is specific to this instance, and
    // it is the case with real sessions to lose. `--force` must confirm
    // the pid against this runtime directory's own control socket, not
    // merely against "looks like a holdfast daemon".
    if !have_proc() {
        return; // The pid confirmation is `/proc`-based; see `commands.rs`.
    }
    let a = TestEnv::new("forceiso-a");
    let b = TestEnv::new("forceiso-b");
    assert_eq!(a.run(&["daemon", "start"]).0, 0);
    assert_eq!(b.run(&["daemon", "start"]).0, 0);
    let b_pid = b.daemon_pid().expect("B's pid file");

    // A's daemon goes away and A's pid file is then made to name B's —
    // the shape a recycled pid leaves behind.
    assert_eq!(a.run(&["daemon", "stop"]).0, 0);
    a.await_no_pid_file();
    a.plant_pid_file(b_pid);

    let (code, _, force_err) = a.run(&["daemon", "stop", "--force"]);
    assert_eq!(code, 0, "stderr: {force_err}");

    // Still *serving*, which is stronger than still alive: a zombie
    // answers `kill(pid, 0)`, and only a live daemon answers
    // `daemon/status`. First, so that a regression trips on B's survival
    // rather than on the message check below it.
    let (code, out, err) = b.run(&["daemon", "status", "--json"]);
    assert_eq!(
        code, 0,
        "instance B's daemon did not survive instance A's `--force`: {err}"
    );
    let status: Value = serde_json::from_str(out.trim()).expect("json status");
    assert_eq!(
        status["pid"].as_u64(),
        Some(b_pid as u64),
        "B answered from a different process: {out}"
    );

    assert!(
        force_err.contains(&b_pid.to_string()),
        "A did not report the pid it declined to signal: {force_err}"
    );
}

#[test]
fn daemon_status_without_a_daemon_exits_2() {
    let env = TestEnv::new("statusnone");
    let (code, out, _) = env.run(&["daemon", "status"]);
    assert_eq!(code, 2, "§18.8: daemon unreachable is exit 2");
    assert!(out.contains("down"), "{out}");
}

#[test]
fn the_running_daemon_holds_no_listening_tcp_socket() {
    // REQ-D-001 / §7.2 / §9.1, checked against the kernel's view of the
    // real daemon process rather than against the source. Injecting a
    // `TcpListener::bind("127.0.0.1:0")` into `daemon::server::run`
    // turns this red.
    let env = TestEnv::new("notcp");
    assert_eq!(env.run(&["daemon", "start"]).0, 0);
    let pid = env.daemon_pid().expect("pid file");

    let (held, listening) = daemon_sockets(pid);
    assert!(
        held > 0,
        "the daemon should hold at least the Unix listener; fd scan found none"
    );
    assert!(
        listening.is_empty(),
        "daemon pid {pid} is listening on TCP: {listening:?}"
    );
}

#[test]
fn the_shim_auto_spawns_a_daemon_and_exposes_the_daemons_tool_list() {
    let env = TestEnv::new("autospawn");
    assert_eq!(env.daemon_pid(), None, "no daemon before the shim starts");

    let mut shim = Shim::start(&env);
    let pid = env
        .daemon_pid()
        .expect("the shim must have spawned a daemon");
    assert!(alive(pid));

    // The shim must serve the *daemon's* manifest verbatim (§3.5), so the
    // expectation is derived from that manifest rather than from a
    // hand-written list. A literal list here would have to be edited by
    // every milestone that adds a tool, and would fail for a reason that
    // has nothing to do with the shim.
    let mut expected: Vec<String> = holdfast_core::mcp::passthrough::passthrough_tools();
    expected.sort();
    let mut tools = shim.list_tools();
    tools.sort();
    assert_eq!(tools, expected);
    // Non-vacuous: an empty manifest on both sides would satisfy the
    // equality above.
    for required in ["start_session", "read_output", "send_input", "terminate"] {
        assert!(
            tools.iter().any(|t| t == required),
            "{required} is missing from the shim's tool list: {tools:?}"
        );
    }
    shim.kill();
}

#[test]
fn two_shims_racing_to_start_share_one_daemon() {
    // §7.3 step 2: the lock plus the re-check must collapse concurrent
    // spawns into one daemon. Two daemons would silently split the
    // session set in half — which is what the second half of this test
    // measures, because counting processes alone would pass against a
    // second daemon that had simply overwritten the first's pid file.
    let env = TestEnv::new("race");
    // Genuinely concurrent: the barrier holds both threads until both are
    // ready, so neither shim can finish its spawn before the other has
    // begun. That is the window `holdfast.lock` exists for; starting them in
    // sequence would let the first finish and the second merely connect,
    // which tests nothing.
    let gate = Barrier::new(2);
    let (mut a, mut b) = std::thread::scope(|scope| {
        let ha = scope.spawn(|| {
            gate.wait();
            Shim::start(&env)
        });
        let hb = scope.spawn(|| {
            gate.wait();
            Shim::start(&env)
        });
        (ha.join().unwrap(), hb.join().unwrap())
    });
    let pid = env.daemon_pid().expect("pid file");
    assert!(alive(pid));

    // Exactly one `daemon run` process is pointed at this runtime dir.
    let daemons = daemons_for(&env.dir);
    assert_eq!(
        daemons.len(),
        1,
        "expected exactly one daemon for this runtime dir, found {daemons:?}"
    );

    // The load-bearing assertion: a session created through one shim is
    // visible through the other. Two daemons — however they came to be —
    // would give the second shim an empty registry.
    let started = a.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "shared" }),
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let listed = b.call_tool("list_sessions", json!({}));
    let sessions = listed["result"]["structuredContent"]["data"]["sessions"]
        .as_array()
        .expect("sessions array");
    assert_eq!(
        sessions.len(),
        1,
        "the second shim sees a different registry: {listed}"
    );
    assert_eq!(sessions[0]["id"], session_id);

    // Stronger than visibility: B can *drive* the session A created, and
    // A can read what B's command produced. A shared registry that had
    // somehow handed B a read-only copy would pass the check above and
    // fail this one.
    b.call_tool(
        "send_input",
        json!({ "session": session_id, "data": "echo SHARED''_MARK" }),
    );
    let seen = a.read_until(&session_id, "SHARED_MARK");
    assert!(
        seen.contains("SHARED_MARK"),
        "the two shims are not driving one session; got: {seen:?}"
    );

    b.call_tool("terminate", json!({ "session": session_id, "force": true }));
    a.kill();
    b.kill();
}

#[test]
fn a_session_survives_the_shim_process_that_created_it() {
    // The whole point of hybrid mode (§3.3). This test restarts the shim
    // *process*; keeping an object alive in one process would prove
    // nothing.
    let env = TestEnv::new("survive");

    let mut first = Shim::start(&env);
    let started = first.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "survivor" }),
    );
    let data = &started["result"]["structuredContent"]["data"];
    assert_eq!(
        started["result"]["structuredContent"]["status"], "ok",
        "{started}"
    );
    let session_id = data["session_id"].as_str().unwrap().to_string();
    let session_pid = data["pid"].as_u64().unwrap() as u32;

    // `BEFORE''_MARK` echoes back as `BEFORE''_MARK` and *prints*
    // BEFORE_MARK, so a match can only come from a shell that ran it.
    first.call_tool(
        "send_input",
        json!({ "session": session_id, "data": "echo BEFORE''_MARK" }),
    );
    let before = first.read_until(&session_id, "BEFORE_MARK");
    assert!(before.contains("BEFORE_MARK"), "got: {before:?}");

    let daemon_pid = env.daemon_pid().expect("pid file");
    let first_pid = first.child.id();
    first.kill();

    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(first_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!alive(first_pid), "the first shim is still running");
    assert!(alive(daemon_pid), "the daemon died with the shim");
    assert!(alive(session_pid), "the session's shell died with the shim");

    let mut second = Shim::start(&env);
    assert_ne!(second.child.id(), first_pid, "same process, not a restart");
    assert_eq!(
        env.daemon_pid(),
        Some(daemon_pid),
        "the second shim must reuse the daemon, not start a new one"
    );

    // The buffer survived...
    let carried = second.read_until(&session_id, "BEFORE_MARK");
    assert!(
        carried.contains("BEFORE_MARK"),
        "the pre-restart output is gone; got: {carried:?}"
    );

    // ...and the PTY is still drivable from the new process. AFTER_MARK
    // cannot exist unless the shell executed a command sent after the
    // first shim was killed.
    second.call_tool(
        "send_input",
        json!({ "session": session_id, "data": "echo AFTER''_MARK" }),
    );
    let after = second.read_until(&session_id, "AFTER_MARK");
    assert!(
        after.contains("AFTER_MARK"),
        "the session is not drivable after the restart; got: {after:?}"
    );

    second.call_tool("terminate", json!({ "session": session_id, "force": true }));
    second.kill();
}

#[test]
fn holdfast_list_and_logs_see_sessions_created_through_the_shim() {
    // §7.2: CLI commands and MCP tool handlers share one control socket,
    // so a separate `holdfast` invocation sees the shim's sessions.
    let env = TestEnv::new("listlogs");
    let mut shim = Shim::start(&env);
    let started = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "visible" }),
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    shim.call_tool(
        "send_input",
        json!({ "session": session_id, "data": "echo CLI''_MARK" }),
    );
    let seen = shim.read_until(&session_id, "CLI_MARK");
    assert!(seen.contains("CLI_MARK"), "got: {seen:?}");

    let (code, out, err) = env.run(&["list"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains(&session_id), "`holdfast list` output: {out}");
    assert!(out.contains("visible"), "`holdfast list` output: {out}");

    let (code, out, err) = env.run(&["list", "--json"]);
    assert_eq!(code, 0, "stderr: {err}");
    let listed: Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(listed["sessions"][0]["name"], "visible");

    // `holdfast logs` reads the same buffer the agent reads. The marker was
    // produced by the shell, so it can only appear if the CLI reached
    // the real session rather than printing something of its own.
    let (code, out, err) = env.run(&["logs", "visible"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("CLI_MARK"), "`holdfast logs` output: {out}");

    // `--raw` (§3.2) reaches the same read path with redaction disabled.
    // This arm proves the flag is *plumbed* — accepted, forwarded, and
    // answered. That it changes any bytes, and that the read is audited,
    // are Step 5b's three tests; 0.0.3 has landed by the time this runs,
    // so those are finally assertable and are this milestone's, not a
    // later suite's.
    let (code, out, err) = env.run(&["logs", "visible", "--raw"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("CLI_MARK"),
        "`holdfast logs --raw` output: {out}"
    );

    let (code, out, err) = env.run(&["logs", "visible", "--tail", "5"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(!out.is_empty(), "`holdfast logs --tail` printed nothing");

    let (code, _, err) = env.run(&["logs", "sess_does_not_exist"]);
    assert_eq!(code, 1, "an unknown session is a failure; stderr: {err}");
    assert!(err.contains("session_not_found"), "stderr: {err}");

    let (code, _, err) = env.run(&["logs", "visible", "--tail", "notanumber"]);
    assert_eq!(code, 64, "§18.8: usage errors are exit 64; stderr: {err}");

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

#[test]
fn holdfast_logs_redacts_by_default() {
    // §5.2's default, on the CLI transport. The pairing test below turns
    // `--raw` off and gets the key back; this one is what says the
    // pipeline is on the path at all, rather than `--raw` being inverted.
    let env = TestEnv::new("redact");
    let (mut shim, session_id) = session_holding_a_secret(&env, "redact");

    let (code, out, err) = env.run(&["logs", "redact"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        !out.contains(AWS_KEY),
        "`holdfast logs` printed a secret with redaction on: {out}"
    );
    assert!(
        out.contains(AWS_MARK),
        "nothing in `holdfast logs` output shows the redactor ran: {out}"
    );

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

#[test]
fn holdfast_logs_raw_returns_the_unredacted_bytes() {
    // The mutation this kills is a `--raw` that PARSES AND IS IGNORED,
    // which every other test in this file passes against: they assert
    // the flag is accepted and that output comes back, and identical
    // redacted output satisfies both.
    let env = TestEnv::new("rawbytes");
    let (mut shim, session_id) = session_holding_a_secret(&env, "rawbytes");

    // The control, in the same session and the same instant: the two
    // reads differ only in the flag, so a difference between them cannot
    // be anything else.
    let (code, plain, err) = env.run(&["logs", "rawbytes"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(!plain.contains(AWS_KEY), "the control read leaked the key");

    let (code, raw, err) = env.run(&["logs", "rawbytes", "--raw"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        raw.contains(AWS_KEY),
        "`--raw` did not disable redaction; got: {raw}"
    );
    assert!(
        !raw.contains(AWS_MARK),
        "`--raw` output still carries a redaction marker: {raw}"
    );

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

#[test]
fn holdfast_logs_raw_writes_a_redaction_disabled_audit_entry() {
    // §3.2 defines `--raw` as "disable redaction, **and audit-log that
    // you did**". The test above covers the first half; until this one
    // exists the second half is an intention.
    //
    // **`client_kind` is the assertion that matters, and it is asserted
    // nowhere else in the tree.** The four `tools.rs` sites that call
    // `caller::audit_surface` and both halves it composes are
    // unit-tested, but the link *through* `tools.rs` — the one that
    // makes the recorded caller derive from the uid-checked handshake
    // rather than from anything in the request — has no other witness.
    // Reverting those four lines to the `"in_process"` literals they
    // replaced leaves every other test in the workspace green and turns
    // this one red on `cli`. Note that `read_output` has no argument
    // that could carry a caller: `"cli"` cannot have come from the
    // request body, because there is no field for it to have arrived in.
    let env = TestEnv::new("rawaudit");
    let (mut shim, session_id) = session_holding_a_secret(&env, "rawaudit");

    // The baseline, and it is not decoration: without it this passes
    // against a daemon that writes `redaction_disabled` on *every* read,
    // which would make the entry noise rather than the §9.4 signal.
    let (code, _, err) = env.run(&["logs", "rawaudit"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        env.redaction_disabled_entries().is_empty(),
        "a redacted read was audited as a raw one: {:?}",
        env.redaction_disabled_entries()
    );

    let (code, _, err) = env.run(&["logs", "rawaudit", "--raw"]);
    assert_eq!(code, 0, "stderr: {err}");

    let entries = env.redaction_disabled_entries();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one redaction_disabled entry: {entries:?}"
    );
    assert_eq!(entries[0]["tool"], "read_output", "{:?}", entries[0]);
    assert_eq!(entries[0]["client_kind"], "cli", "{:?}", entries[0]);
    assert_eq!(entries[0]["session_id"], session_id, "{:?}", entries[0]);

    // The agent's own raw read is the *other* caller, and recording both
    // as one string is the failure §9.4 splits `tool` from `client_kind`
    // to prevent. One mechanism, two accountable parties.
    shim.call_tool(
        "read_output",
        json!({ "session": session_id, "since_cursor": 0, "redact": false }),
    );
    let entries = env.redaction_disabled_entries();
    assert_eq!(entries.len(), 2, "the shim's raw read was not audited");
    assert_eq!(entries[1]["tool"], "read_output", "{:?}", entries[1]);
    assert_eq!(entries[1]["client_kind"], "shim", "{:?}", entries[1]);

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

/// §11.4's third arm — the one that was specified and never written.
///
/// The row is *"Holdback bypass for tail reads, and its three
/// non-members"*, and it is explicit that the arms have to be one
/// measurement: **"In the *same* moment assert §4.1's actual three
/// non-members: `get_screen_state` answers `held_back: true` with those
/// cells masked, `holdfast logs --tail` does not return them, and the
/// `observer` attach stream withholds them"**. It closes by naming the
/// cost of shipping without this arm:
///
/// > The bypass arm alone passes against an implementation that exempts
/// > every tail-shaped read, **which is the reading that shipped**.
///
/// It had shipped. `holdfast logs --tail N` sent `tail_lines`, which was
/// §4.1's per-call bypass, on the surface §4.1 names as a non-member by
/// name: *"`--raw` is that surface's opt-in and it is audited; `--tail`
/// is not an opt-in to anything."* Measured on a live daemon in one
/// instant, `read_output(since_cursor: 0)` answered `held_back: true`
/// and `holdfast logs --tail 50` printed the credential in the clear
/// (GH #169).
///
/// **One session, one instant, and the premise asserted before the
/// conclusion.** "`--tail` did not print the token" is satisfied by a
/// session that never produced one, by a daemon that returned nothing,
/// and by a `--tail` that returns the *head* — so the arrangement is
/// established first (the licensed bypass hands the token over whole),
/// the withholding is established second (`read_output` at the same
/// instant), and the holdback is re-checked **after** the CLI ran, which
/// is what makes "the same moment" a claim rather than a hope.
///
/// **The control is the first half of the test and it is not optional.**
/// Everything here is also satisfied by a `--tail` that returns nothing,
/// or the head, or silently less than asked. So the same session is
/// measured first with nothing in flight, where `--tail` must still be
/// byte-for-byte what the bypassing read returns.
#[test]
fn logs_tail_is_inside_the_holdback_in_the_same_moment_read_output_withholds() {
    // 35 characters. `gh[pousr]_[0-9A-Za-z]{36,}` wants 36, so this is a
    // token that is still arriving: the redactor cannot judge it, §4.1's
    // holdback is the only thing withholding it, and anything that
    // returns it returns it in the clear.
    const IN_FLIGHT_TAIL: &str = "0123456789abcdefghijABCDEFGHIJ01234";

    let env = TestEnv::new("tailholdback");
    let mut shim = Shim::start(&env);
    let started = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "tailhb" }),
    );
    assert_eq!(
        started["result"]["structuredContent"]["status"], "ok",
        "{started}"
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    // ---- the control: what `--tail` is for, with nothing in flight ----
    shim.call_tool(
        "send_input",
        json!({ "session": session_id, "data": "for i in $(seq 1 40); do echo LINE''_$i; done" }),
    );
    let seen = shim.read_until(&session_id, "LINE_40");
    assert!(
        seen.contains("LINE_40"),
        "the loop never ran; got: {seen:?}"
    );

    let (code, ordinary, err) = env.run(&["logs", "tailhb", "--tail", "10"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        ordinary.contains("LINE_40"),
        "`--tail 10` did not reach the newest line: {ordinary:?}"
    );
    assert!(
        !ordinary.contains("LINE_1\r"),
        "`--tail 10` returned the HEAD of the buffer, not the tail: {ordinary:?}"
    );
    // The sharp form of "unchanged": with nothing withheld, the held-back
    // tail read and the bypassing one are the same bytes. A fix that
    // trades this defect for a shorter `--tail` fails here.
    let bypassing = shim.call_tool(
        "read_output",
        json!({ "session": session_id, "tail_lines": 10, "max_bytes": 262144 }),
    );
    assert_eq!(
        ordinary,
        bypassing["result"]["structuredContent"]["data"]["output"]
            .as_str()
            .unwrap_or_default(),
        "with nothing in flight, `--tail` must return exactly what the \
         bypassing tail read returns"
    );
    assert!(
        err.is_empty(),
        "the ordinary case reported a holdback: {err}"
    );

    // ---- the arrangement: a secret that is still arriving -------------
    // `ghp_` and the value are separate `printf` arguments, so the shell's
    // echo of the command line carries them with a space between and is
    // not itself a candidate — the only contiguous token in the buffer is
    // the one `printf` writes. `read -r _` then parks the shell with no
    // prompt and no newline after it, which is what keeps the partial at
    // `buffer.head`: `earliest_partial` requires every byte from the
    // prefix to the end of the scan region to still be a value byte.
    shim.call_tool(
        "send_input",
        json!({
            "session": session_id,
            "data": format!("printf 'see %s%s' ghp_ {IN_FLIGHT_TAIL}; read -r _"),
        }),
    );

    let in_flight = format!("ghp_{IN_FLIGHT_TAIL}");
    let arranged = format!("see {in_flight}");
    // Wait for the arrangement itself — the token whole, at the head of
    // the buffer. **The deadline is a hang detector, not part of the
    // assertion**, which is this file's rule and not an exception to it:
    // it panics, so it can never be absorbed into a pass, and the
    // premise asserted immediately after the loop is still the only
    // thing that can make this row green. The vacuous pass §11.4 spends
    // its closing sentence on is prevented by that premise, not by
    // spinning forever — a spin adds no assertion, it only removes the
    // message that says which wait it was.
    //
    // This comment used to say `.config/nextest.toml`'s
    // `terminate-after` was the bound. On the job that runs this row
    // most, it is not: `scripts/ci-flake-hunt.sh` runs `cargo test`
    // (*"Do not 'modernise' this line"*), which reads no nextest
    // profile, and `nightly.yml` invokes it 100 times. Measured still
    // running at 400 s under plain libtest.
    //
    // `ends_with` and not `contains`: the partial has to be **at**
    // `buffer.head` for §4.1 to be withholding it at all, so relaxing
    // this would weaken the arrangement rather than the wait. Each turn
    // is a socket round trip, so it paces itself; no sleep.
    let arranged_by = Instant::now() + Duration::from_secs(60);
    let bypass = loop {
        let r = shim.call_tool(
            "read_output",
            json!({ "session": session_id, "tail_bytes": 256 }),
        );
        let data = r["result"]["structuredContent"]["data"].clone();
        if data["output"]
            .as_str()
            .unwrap_or_default()
            .ends_with(&arranged)
        {
            break data;
        }
        assert!(
            Instant::now() < arranged_by,
            "no partial secret ever reached `buffer.head`, so the \
             arrangement this row measures was never made. Every \
             assertion below would have been vacuous. Wanted a tail read \
             ending in {arranged:?}; last one was {}",
            data["output"]
        );
    };

    // Premise one, and §11.4's bypass arm: the per-call opt-in is still
    // exempt and hands the partial over whole (§4.1, REQ-O-003). Without
    // it, every "did not return the token" below is also true of a buffer
    // that never held one.
    assert!(
        bypass["output"]
            .as_str()
            .unwrap_or_default()
            .contains(&arranged),
        "the per-call tail opt-in must still return the partial: {}",
        bypass["output"]
    );
    assert_eq!(
        bypass["held_back"],
        json!(false),
        "a read that bypasses the holdback is not withholding anything"
    );

    // Premise two: in this same moment the ordinary cursor read really is
    // withholding. This is the half that makes the row a *pairing*.
    let held = shim.call_tool(
        "read_output",
        json!({ "session": session_id, "since_cursor": 0, "max_bytes": 262144 }),
    );
    let held = &held["result"]["structuredContent"]["data"];
    assert_eq!(
        held["held_back"],
        json!(true),
        "nothing is being withheld, so there is no non-membership to describe: {held}"
    );
    assert!(
        !held["output"]
            .as_str()
            .unwrap_or_default()
            .contains(&in_flight),
        "the cursor read must be withholding it: {}",
        held["output"]
    );

    // ---- the conclusion: §4.1:477's named non-member ------------------
    let (code, tail, err) = env.run(&["logs", "tailhb", "--tail", "10"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        !tail.contains(&in_flight),
        "`holdfast logs --tail` released the in-flight token that \
         `read_output` is withholding in the same moment (§4.1:477, \
         REQ-O-003, GH #169): {tail:?}"
    );
    assert!(
        !tail.contains("see ghp_"),
        "`holdfast logs --tail` returned part of the withheld region: {tail:?}"
    );
    // Withheld, not emptied and not reversed: it is still the tail, cut
    // at `holdback_boundary`, which is §4.1's shortened-read shape.
    assert!(
        tail.contains("LINE_40"),
        "`--tail` stopped returning the tail; withholding is a shorter \
         read, not a different one: {tail:?}"
    );
    assert!(
        tail.ends_with("see "),
        "`--tail` did not stop exactly at the holdback boundary: {tail:?}"
    );
    assert!(
        err.contains("stops short"),
        "a shortened read that says nothing reads as 'the output ended': {err:?}"
    );
    // The live-child wording, pinned by name so the three readings below
    // cannot collapse back into one. This child is parked in `read -r _`,
    // so a byte really may still arrive and "read again" really is the
    // advice — which is exactly what makes it the wrong thing to say on
    // a `--raw` read or a session that has ended.
    assert!(
        err.contains("may still be arriving"),
        "the live-child note no longer says what is being waited for: {err:?}"
    );
    assert!(
        !err.contains("stays that way"),
        "a session still producing output was told its tail is final: {err:?}"
    );

    // The bracket. Arms measured either side of a process spawn are only
    // "the same moment" if the holdback was still open at the end of it.
    let after = shim.call_tool(
        "read_output",
        json!({ "session": session_id, "since_cursor": 0, "max_bytes": 262144 }),
    );
    assert_eq!(
        after["result"]["structuredContent"]["data"]["held_back"],
        json!(true),
        "the holdback closed while the CLI was running, so the two arms \
         are not one measurement"
    );

    // ---- `--raw` IS the opt-in, and it IS audited ---------------------
    // §4.1:477 licenses the bypass on this surface *because* the record
    // exists. An opt-in that is licensed by an audit and then is not
    // audited is the same defect in a different hat.
    assert!(
        env.redaction_disabled_entries().is_empty(),
        "a redacted read was audited as a raw one: {:?}",
        env.redaction_disabled_entries()
    );
    let (code, raw, err) = env.run(&["logs", "tailhb", "--tail", "10", "--raw"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        raw.contains(&arranged),
        "`--raw` is this surface's opt-in and must still return the \
         in-flight bytes: {raw:?}"
    );
    let entries = env.redaction_disabled_entries();
    assert_eq!(
        entries.len(),
        1,
        "`--raw` was honoured without being audited: {entries:?}"
    );
    assert_eq!(entries[0]["tool"], "read_output", "{:?}", entries[0]);
    assert_eq!(entries[0]["client_kind"], "cli", "{:?}", entries[0]);
    assert_eq!(entries[0]["session_id"], session_id, "{:?}", entries[0]);

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

/// **The note asserted a security claim that `--raw` switches off.**
///
/// `held_back` is `safety_end < w.cap_end` (`output/mod.rs`), and three
/// rules lower `safety_end`. `redact: false` makes `holdback_boundary`
/// return `w.head` *before* the field is computed, so §4.1's holdback
/// cannot be one of them on this read — and the same read writes the
/// `redaction_disabled` row that says redaction was off. The one rule
/// left is REQ-O-008's unfinished trailing escape, which is gated on
/// `ansi == Strip` and not on `redact`.
///
/// So the old unconditional *"a secret may still be arriving (§4.1)"*
/// named a mechanism that was provably not running, on the one read of
/// this surface that is audited as unredacted. `dropped_incomplete_escape`
/// cannot be used to tell them apart: `mcp/tools.rs` does not serialise
/// it, and it flags the escape being *dropped*, which is the arm that
/// does not set `held_back` at all.
#[test]
fn raw_does_not_blame_the_secret_holdback_for_an_unfinished_escape() {
    let env = TestEnv::new("logsrawescape");
    let mut shim = Shim::start(&env);
    // `shell_integration: false` so nothing is typed into the pty behind
    // the test: the OSC 133 snippet is echoed back, and its own escapes
    // are complete, so it would move `buffer.head` past the one that is
    // not.
    let started = shim.call_tool(
        "start_session",
        json!({
            "command": "bash",
            "args": ["--norc", "--noprofile"],
            "name": "rawesc",
            "shell_integration": false,
        }),
    );
    assert_eq!(
        started["result"]["structuredContent"]["status"], "ok",
        "{started}"
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    // `ESC [` and nothing after it: a CSI introducer the child has not
    // finished, two bytes, well under `ansi_incomplete_max_bytes`.
    // `read -r _` parks the shell so it stays unfinished and the child
    // stays alive, which is what REQ-O-008 withholds on.
    shim.call_tool(
        "send_input",
        json!({ "session": session_id, "data": r"printf 'ESCMARK\033['; read -r _" }),
    );

    // The arrangement, measured the way `--raw` measures it: redaction
    // off, so only REQ-O-008's rule can answer `true`. Bounded, and the
    // expiry panics rather than falling through to a vacuous pass.
    let arranged_by = Instant::now() + Duration::from_secs(60);
    loop {
        let r = shim.call_tool(
            "read_output",
            json!({ "session": session_id, "since_cursor": 0, "redact": false, "max_bytes": 262144 }),
        );
        let data = &r["result"]["structuredContent"]["data"];
        if data["held_back"] == json!(true) {
            break;
        }
        assert!(
            Instant::now() < arranged_by,
            "no unfinished escape ever reached `buffer.head` with \
             redaction off, so this row would assert nothing: {data}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let (code, out, err) = env.run(&["logs", "rawesc", "--tail", "5", "--raw"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("ESCMARK"),
        "`--raw` did not return the bytes before the escape: {out:?}"
    );
    assert!(
        !err.is_empty(),
        "the read was shortened and said nothing: {out:?}"
    );
    assert!(
        !err.contains("may still be arriving"),
        "`--raw` blamed §4.1's secret holdback for a read on which \
         `holdback_boundary` returned `buffer.head` before `held_back` \
         was computed — and which is in the audit log as unredacted: \
         {err:?}"
    );
    assert!(
        err.contains("unfinished escape sequence"),
        "the note does not name the one rule that can still fire with \
         redaction off (REQ-O-008): {err:?}"
    );

    // The other half of the claim above: the daemon really did record
    // this read as one with redaction switched off.
    let entries = env.redaction_disabled_entries();
    assert!(
        entries.iter().any(|e| e["client_kind"] == "cli"),
        "`--raw` was honoured without being audited, so the note's claim \
         that the named mechanism is off is unrecorded: {entries:?}"
    );

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

/// **A session that has ended, and the two sentences that were false
/// about it.**
///
/// The *withhold* here is spec-correct and stays: §4.1 — *"If a process
/// stops mid-token, the partial stays withheld — correct"* — and
/// REQ-O-005 makes it normative, *"Quiescence does not release the
/// holdback."* What was wrong is everything said about it. Nothing is
/// "still arriving" from a child that has exited, and "read again to
/// pick up the rest" can never succeed: the bytes that would advance the
/// boundary do not exist and never will, so the last bytes of a
/// completed session's log were unreachable from the primary
/// human-facing command with no hint that another one would do.
///
/// §4.1 names the recourse in the same sentence as the rule — the agent
/// *"may take the audited `redact: false` path if it genuinely needs the
/// bytes"* — and §4.1:476 names `--raw` as this surface's spelling of
/// it. **So the withheld tail stays reachable through `--raw`, and the
/// note now says so.** Both halves are asserted here: taking that away
/// would be inventing a rule the spec does not have, on the only route
/// the spec does name.
///
/// This is a behaviour change against `main`, where `--tail` bypassed
/// the holdback and returned the token; `CHANGELOG.md` records it.
#[test]
fn a_completed_sessions_withheld_tail_is_named_as_final_and_reachable_through_raw() {
    // 35 characters: `gh[pousr]_[0-9A-Za-z]{36,}` wants 36, so the
    // redactor cannot judge it and §4.1's holdback is the only thing
    // withholding it.
    const IN_FLIGHT_TAIL: &str = "0123456789abcdefghijABCDEFGHIJ01234";

    let env = TestEnv::new("logsexited");
    let mut shim = Shim::start(&env);
    let started = shim.call_tool(
        "start_session",
        json!({
            "command": "bash",
            "args": [
                "--norc",
                "--noprofile",
                "-c",
                format!("printf 'see %s%s' ghp_ {IN_FLIGHT_TAIL}"),
            ],
            "name": "deadtail",
            "shell_integration": false,
        }),
    );
    assert_eq!(
        started["result"]["structuredContent"]["status"], "ok",
        "{started}"
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let in_flight = format!("ghp_{IN_FLIGHT_TAIL}");
    let exited_by = Instant::now() + Duration::from_secs(60);
    loop {
        let st = shim.call_tool("status", json!({ "session": session_id }));
        let data = &st["result"]["structuredContent"]["data"];
        if data["state"] == json!("Exited") {
            assert_eq!(data["exit_code"], json!(0), "{data}");
            break;
        }
        assert!(
            Instant::now() < exited_by,
            "the child never exited, so this row is about a live session \
             and asserts nothing it claims to: {data}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Both tail sizes, because the withhold is a property of the tail
    // and not of how much of it was asked for — and twice, because "read
    // again" was the advice and it has to be shown not to work.
    //
    // **By id, not by name.** A session that has exited has released its
    // claim on `deadtail`, which is the whole reason this case matters:
    // the log outlives the child, and the id is what still reaches it.
    for tail in ["5", "50", "5"] {
        let (code, out, err) = env.run(&["logs", &session_id, "--tail", tail]);
        assert_eq!(code, 0, "stderr: {err}");
        assert!(
            !out.contains(&in_flight),
            "a completed session released the partial its own \
             `read_output` withholds (§4.1, REQ-O-005): {out:?}"
        );
        assert!(
            out.ends_with("see "),
            "the read did not stop at the holdback boundary: {out:?}"
        );
        assert!(
            !err.contains("may still be arriving"),
            "the session has exited with code 0; nothing is arriving, \
             and this is the sentence that says otherwise: {err:?}"
        );
        assert!(
            err.contains("stays that way"),
            "the note does not say the tail is final: {err:?}"
        );
        assert!(
            err.contains("--raw"),
            "the only route §4.1 names to these bytes is unmentioned on \
             the one surface that can no longer reach them: {err:?}"
        );
    }

    // And that route works. Without this the row above is satisfied by a
    // build that made the bytes unreachable altogether.
    let (code, raw, err) = env.run(&["logs", &session_id, "--tail", "5", "--raw"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        raw.contains(&in_flight),
        "§4.1's own escape hatch does not reach the withheld tail of a \
         completed session: {raw:?}"
    );
    let entries = env.redaction_disabled_entries();
    assert!(
        entries.iter().any(|e| e["client_kind"] == "cli"),
        "`--raw` was honoured without being audited: {entries:?}"
    );

    shim.kill();
}

#[test]
fn no_daemon_mode_runs_in_process_and_starts_no_daemon() {
    // §3.4's escape hatch, and the shape the Windows build reuses in
    // 0.0.11. `Shim::spawn` asserts the `initialize` handshake on the way
    // in, so reaching this body already means the in-process server
    // answered.
    let env = TestEnv::new("nodaemon");
    let mut shim = Shim::spawn(&env, &["mcp", "--no-daemon"]);

    // Non-vacuous: "no daemon" is also true of a binary that serves
    // nothing at all, so the in-process path has to be shown working
    // before its *absence* of a daemon means anything.
    let tools = shim.list_tools();
    assert!(
        tools.iter().any(|t| t == "start_session"),
        "the in-process server advertised no tools: {tools:?}"
    );

    assert_eq!(
        env.daemon_pid(),
        None,
        "--no-daemon must not spawn a daemon"
    );
    assert!(
        !env.dir.join("control.sock").exists(),
        "--no-daemon must not bind a socket"
    );

    shim.kill();
}

#[test]
fn version_reports_the_protocol_version() {
    let env = TestEnv::new("version");
    let (code, out, _) = env.run(&["version"]);
    assert_eq!(code, 0);
    // **A literal, deliberately.** Deriving this from `PROTOCOL_MINOR`
    // would assert that the constant equals itself and go green through
    // any bump, accidental or not; the number is a wire promise and a
    // second pair of eyes on it is the whole value of the row. Moved 1.0
    // → 1.1 for `Attach.terminal` (GH #66), and 1.1 → 1.2 for
    // `holdfast/cancel` and `Request.cancel_token` (GH #127), and 1.2 →
    // 1.3 for `SecretInput.allow_echo` (GH #137), and 1.3 → 1.4 for
    // `ServerFrame::OutputGap` (GH #200), each alongside a new
    // golden — the version and the recorded shape move together or the
    // wire-shape guard fails, which is the pairing that makes this
    // literal safe to update rather than a rubber stamp.
    assert!(out.contains("protocol 1.4"), "{out}");
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "{out}");
}

#[test]
fn an_unknown_subcommand_is_a_usage_error() {
    let env = TestEnv::new("usage");
    let (code, _, err) = env.run(&["nonsense"]);
    assert_eq!(code, 64, "§18.8: usage errors are exit 64");
    assert!(err.contains("USAGE"), "{err}");
}

#[test]
fn an_invalid_config_stops_the_daemon_before_it_binds() {
    // REQ-CFG-003's normative consequence, and the reason 0.0.5 owns the
    // config file at all: an invalid config rejects daemon *startup*.
    let env = TestEnv::new("badcfg");
    env.write_config("[limits]\nmax_concurrent_sessions = 0\n");

    let (code, _, err) = env.run(&["daemon", "run"]);
    assert_ne!(code, 0, "an invalid config must not start a daemon");
    assert!(
        err.contains("max_concurrent_sessions"),
        "the error names the offending key; got: {err}"
    );
    // **This is the assertion that separates rejecting from warning.**
    // Both print something; only one leaves no socket behind.
    assert!(
        !env.dir.join("control.sock").exists(),
        "a daemon that logged a warning and started anyway is the failure \
         mode REQ-CFG-003 exists to prevent"
    );
}

#[test]
fn an_unknown_key_in_the_config_stops_the_daemon_and_names_it() {
    let env = TestEnv::new("unkcfg");
    env.write_config("[limits]\nmax_concurent_sessions = 4\n");
    let (code, _, err) = env.run(&["daemon", "run"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("max_concurent_sessions"),
        "§10.1: an unknown key is a load error and the error names the key; got: {err}"
    );
    assert!(!env.dir.join("control.sock").exists());
}

#[test]
fn a_binding_whose_regex_does_not_compile_stops_the_daemon() {
    // §9.6, 0.0.7. An operator's typo'd regex must not become a binding
    // that silently never matches — which from the outside is
    // indistinguishable from a credential store that is down.
    //
    // **The regex is a profile's slot pattern since GH #46.** It used to
    // be `match_command`; that field is retired, and a `[security.profiles.vars]`
    // entry is where an operator's regex lives now. The property is
    // unchanged and so is the daemon's answer: refuse, name the key, bind
    // no socket.
    let env = TestEnv::new("badbinding");
    env.write_config(
        "[[security.profiles]]\n\
         name = \"prod-ssh\"\n\
         program = \"ssh\"\n\
         args = [\"{host}\"]\n\
         [security.profiles.vars]\n\
         host = \"^prod-0(\"\n",
    );

    let (code, _, err) = env.run(&["daemon", "run"]);
    assert_ne!(code, 0, "an uncompilable pattern must not start a daemon");
    assert!(
        err.contains("host"),
        "the error names the offending key; got: {err}"
    );
    assert!(
        err.contains("prod-ssh"),
        "and the profile, or an operator with six of them cannot find it; got: {err}"
    );
    // The assertion that separates rejecting from warning: both print.
    assert!(
        !env.dir.join("control.sock").exists(),
        "a daemon that logged a warning and started anyway leaves a binding \
         that never matches in force"
    );
}

#[test]
fn autofill_without_a_keychain_provider_stops_the_daemon() {
    // REQ-SEC-014 + REQ-CFG-003. `autofill_on_echo_off = true` with
    // `secret_provider = "prompt"` is a switch that reads as "on" and
    // behaves as "off", for the single most consequential knob in the
    // file.
    let env = TestEnv::new("badautofill");
    env.write_config("[security]\nautofill_on_echo_off = true\nsecret_provider = \"prompt\"\n");

    let (code, _, err) = env.run(&["daemon", "run"]);
    assert_ne!(code, 0);
    assert!(err.contains("autofill_on_echo_off"), "{err}");
    assert!(err.contains("secret_provider"), "{err}");
    assert!(!env.dir.join("control.sock").exists());

    // **The pairing.** The same switch with a provider that can resolve
    // must start, or the rule has quietly become "autofill is never
    // allowed" and REQ-SEC-014's opt-in is unreachable.
    let ok = TestEnv::new("okautofill");
    ok.write_config("[security]\nautofill_on_echo_off = true\nsecret_provider = \"both\"\n");
    let (code, _, err) = ok.run(&["daemon", "start"]);
    assert_eq!(
        code, 0,
        "autofill with a keychain provider must start: {err}"
    );
    assert!(ok.dir.join("control.sock").exists());
    ok.run(&["daemon", "stop"]);
}

#[test]
fn a_valid_config_starts_the_daemon_and_reaches_it() {
    // **The pairing, and it is what makes the two rows above mean
    // anything.** Without it they pass against a `daemon run` that
    // refuses every config, or against one that cannot start at all.
    let env = TestEnv::new("okcfg");
    env.write_config("[limits]\nmax_concurrent_sessions = 3\n");

    let (code, _, err) = env.run(&["daemon", "start"]);
    assert_eq!(code, 0, "a valid config must start: {err}");
    assert!(env.dir.join("control.sock").exists(), "the socket is bound");

    // Non-vacuous: the daemon answers, so "started" is not just a file.
    let (code, out, _) = env.run(&["daemon", "status", "--json"]);
    assert_eq!(code, 0);
    let status: Value = serde_json::from_str(&out).expect("status --json");
    assert_eq!(status["sessions_live"], 0);

    env.run(&["daemon", "stop"]);
}

#[test]
fn the_published_example_config_starts_a_real_daemon() {
    // §10.2 is a fixture, not an illustration: the operator's copy-paste
    // has to *start a daemon*, not merely deserialise. This is the one
    // arm the in-process loader test cannot carry — it proves the whole
    // startup path accepts the published example, validation included.
    let env = TestEnv::new("examplecfg");
    let example = include_str!("../../holdfast-core/tests/fixtures/example_config.toml");
    env.write_config(example);

    let (code, _, err) = env.run(&["daemon", "start"]);
    assert_eq!(
        code, 0,
        "a config rejected for being correct is worse than one accepted \
         for being wrong: {err}"
    );
    assert!(env.dir.join("control.sock").exists());
    env.run(&["daemon", "stop"]);
}

#[test]
fn an_invalid_config_stops_the_no_daemon_server_before_it_serves() {
    // The `--no-daemon` half of
    // `an_invalid_config_stops_the_daemon_before_it_binds`, and it did
    // not exist because the behaviour did not: `serve_stdio` built its
    // server from `Config::default()` and never opened the file at all.
    // So this transport served every tool on the built-in values while
    // the operator's `config.toml` sat unread — and on Windows, where
    // §3.3/§3.6 leave stdio the only transport until 0.0.11, that was
    // every transport there is.
    let env = TestEnv::new("nodaemonbadcfg");
    env.write_config("[limits]\nmax_concurrent_sessions = 0\n");

    // **`run` gives the child `/dev/null` for stdin, and that is what
    // bounds this.** A server that starts reaches EOF on the MCP
    // transport immediately and exits 0 of its own accord, so the
    // pre-fix behaviour is a fast green exit rather than a wait — no
    // timeout is standing in for the assertion.
    let (code, _, err) = env.run(&["mcp", "--no-daemon"]);
    assert_eq!(
        code, 1,
        "§18.8: a refused config is \"operation failed\" (1) — the code \
         `daemon run` gives for these same bytes. Exit 0 is the server \
         having started on defaults, which is the whole defect; exit 2 \
         would send the operator hunting for a daemon this transport does \
         not have. stderr: {err}"
    );
    assert!(
        err.contains("max_concurrent_sessions"),
        "the refusal names the offending key, as REQ-CFG-003 requires of \
         the daemon: {err}"
    );
}

#[test]
fn the_no_daemon_server_honours_a_configured_session_cap() {
    // **The pairing, and the arm that survives a fix which loads the
    // file and then drops it.** The refusal above passes just as well
    // against `let _ = config::load()?;` in front of a server still
    // built from `Config::default()`; this one cannot, because the cap
    // it asserts exists nowhere but the operator's file. It is also the
    // non-vacuous half: a valid config still has to *serve*, or the
    // refusal above is indistinguishable from a transport that stopped
    // working.
    let env = TestEnv::new("nodaemoncfg");
    env.write_config("[limits]\nmax_concurrent_sessions = 1\n");

    // `$HOME` inside the test directory. `--no-daemon`'s §9.4 trail is
    // `audit::default_path()` — `$HOME/.holdfast/logs/audit.log` — and not
    // the runtime directory's, so without this the two `start_session`
    // calls below append `session_start` rows to the *developer's* real
    // audit log. Same reason `redaction_disabled_entries` reads the
    // instance's log rather than `~/.holdfast/logs`. Config discovery is
    // unaffected: §10.1 prefers `$XDG_CONFIG_HOME`, which `cmd` sets.
    let mut cmd = env.cmd();
    cmd.env("HOME", &env.dir);
    let mut shim = Shim::spawn_cmd(cmd, &["mcp", "--no-daemon"]);

    let first = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "cap-1" }),
    );
    assert_eq!(
        first["result"]["structuredContent"]["status"], "ok",
        "a cap of 1 must still admit the first session: {first}"
    );

    let second = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "cap-2" }),
    );
    assert_eq!(
        second["result"]["structuredContent"]["status"], "limit_reached",
        "the built-in cap is 8, so a second session that starts is a tool \
         surface running on `Config::default()` with the operator's file \
         unread: {second}"
    );

    shim.kill();
}

// ------------------------------------------------ GH #218, #232, #233, #178, #20

/// Run `holdfast args` with a stdout whose reader has already gone, and
/// return how it ended and what it said on stderr.
///
/// **A pipe whose read end is closed before the child starts**, rather than
/// `| head` and a race: every write the child makes to stdout then fails
/// with `EPIPE`, so the outcome does not depend on how much it prints or
/// how fast `head` exits. The dogfood pass measured `list | head -1`
/// panicking in 10 of 30 runs because it depended on exactly that.
fn run_with_stdout_closed(env: &TestEnv, args: &[&str]) -> (std::process::ExitStatus, String) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let mut child = env
        .cmd()
        .args(args)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .expect("run holdfast");
    let mut err = child.stderr.take().expect("piped stderr");
    let err_h = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + CLI_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`holdfast {}` with its stdout closed did not exit within {CLI_TIMEOUT:?}",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stderr = String::from_utf8_lossy(&err_h.join().expect("stderr reader")).into_owned();
    (status, stderr)
}

/// **GH #218: a reader that leaves early ends the CLI the way it ends
/// `cat`**, not with a panic, a backtrace note and exit 101.
///
/// Every stdout-writing one-shot subcommand, including the two that only
/// print a line — they share the write path, so one of them regressing
/// alone is exactly the case a single row would miss.
#[test]
fn a_closed_stdout_ends_the_cli_as_it_ends_cat_rather_than_panicking() {
    use std::os::unix::process::ExitStatusExt;

    let env = TestEnv::new("sigpipe");
    let mut shim = Shim::start(&env);
    let started = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "piped" }),
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    shim.call_tool(
        "send_input",
        json!({ "session": session_id, "data": "echo PIPE''_MARK" }),
    );
    let seen = shim.read_until(&session_id, "PIPE_MARK");
    assert!(seen.contains("PIPE_MARK"), "the session never printed: {seen:?}");

    for args in [
        &["version"][..],
        &["--help"][..],
        &["list"][..],
        &["list", "--json"][..],
        &["logs", "piped"][..],
        &["logs", "piped", "--tail", "5"][..],
        &["daemon", "status"][..],
    ] {
        let (status, err) = run_with_stdout_closed(&env, args);
        assert!(
            !err.contains("panicked"),
            "`holdfast {}` panicked on a closed stdout: {err}",
            args.join(" ")
        );
        assert_eq!(
            status.signal(),
            Some(libc::SIGPIPE),
            "`holdfast {}` must die of SIGPIPE, as `cat` does, when its reader has gone; \
             it ended {status} with stderr: {err}",
            args.join(" ")
        );
    }

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

/// The other half: a write that fails for any reason *but* a departed
/// reader is a real failure — said on stderr, exit 1 — and not a panic
/// with 101. `/dev/full` answers every write with `ENOSPC`, and exists
/// on Linux only.
#[test]
fn a_stdout_that_cannot_be_written_is_a_reported_failure() {
    if !Path::new("/dev/full").exists() {
        println!("skipping: no /dev/full on this platform");
        return;
    }
    let env = TestEnv::new("devfull");
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let out = env
        .cmd()
        .arg("version")
        .stdin(Stdio::null())
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .expect("run holdfast version");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(err.contains("cannot write to stdout"), "{err}");
}

/// **`holdfast watch | head` never exited** (GH #218): the watcher threw
/// its write errors away and went on rendering into nothing. It now ends
/// at the first write after its reader has gone — which, for a session
/// that is printing, is at once.
#[test]
fn watch_ends_when_its_reader_does() {
    use std::os::unix::process::ExitStatusExt;

    let env = TestEnv::new("watchpipe");
    let mut shim = Shim::start(&env);
    let started = shim.call_tool(
        "start_session",
        json!({ "command": "bash", "args": ["--norc", "--noprofile"], "name": "watched" }),
    );
    let session_id = started["result"]["structuredContent"]["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let mut watch = env
        .cmd()
        .args(["watch", "watched"])
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn holdfast watch");

    // Keep the session printing until the watcher has had something to
    // write — bounded, and every round is a fresh chance for it to notice.
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = watch.try_wait().expect("wait for watch") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = watch.kill();
            let _ = watch.wait();
            panic!("`holdfast watch` outlived its reader by 30s of session output");
        }
        shim.call_tool(
            "send_input",
            json!({ "session": session_id, "data": "echo still-printing" }),
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(
        status.signal(),
        Some(libc::SIGPIPE),
        "`holdfast watch` must end as `cat` would when its reader has gone: {status}"
    );

    shim.call_tool("terminate", json!({ "session": session_id, "force": true }));
    shim.kill();
}

/// **GH #233**: `--help`, `-h`, `help`, `--version` and `-V` were
/// `unknown subcommand`, exit 64. Help that was asked for is an answer:
/// stdout, exit 0.
#[test]
fn help_and_version_flags_answer_on_stdout() {
    let env = TestEnv::new("helpflags");
    let (code, version, _) = env.run(&["version"]);
    assert_eq!(code, 0);

    for args in [&["--help"][..], &["-h"][..], &["help"][..]] {
        let (code, out, err) = env.run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert!(out.contains("USAGE:") && out.contains("holdfast mcp"), "{args:?}: {out}");
        assert!(err.is_empty(), "{args:?} wrote to stderr: {err}");
    }
    for args in [&["--version"][..], &["-V"][..]] {
        let (code, out, err) = env.run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert_eq!(out, version, "{args:?} is not `holdfast version`");
    }

    // One subcommand's help is that subcommand's, however it is asked.
    for args in [&["logs", "--help"][..], &["logs", "-h"][..], &["help", "logs"][..]] {
        let (code, out, err) = env.run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert!(out.contains("holdfast logs <session>"), "{args:?}: {out}");
        assert!(!out.contains("holdfast list"), "{args:?} printed more than logs: {out}");
    }
    let (code, out, _) = env.run(&["daemon", "--help"]);
    assert_eq!(code, 0);
    for verb in ["run", "start", "stop", "status"] {
        assert!(out.contains(&format!("holdfast daemon {verb}")), "{out}");
    }
    let (code, out, _) = env.run(&["help", "daemon", "stop"]);
    assert_eq!(code, 0);
    assert!(out.contains("holdfast daemon stop") && !out.contains("holdfast daemon status"));

    let (code, _, err) = env.run(&["help", "nonsense"]);
    assert_eq!(code, 64, "{err}");
}

/// REQ-A-002's stated verification, verbatim: *"`holdfast --help` lists
/// exactly the documented subcommands."* It exited 64 until GH #233.
///
/// **The list is a literal**: the documented set as it stands, so adding
/// or dropping a subcommand is a deliberate edit here and not something
/// the banner can do on its own. Each one is then asked for its help, so
/// a banner line with no subcommand behind it fails too.
#[test]
fn holdfast_help_lists_exactly_the_documented_subcommands() {
    let env = TestEnv::new("reqa002");
    let (code, out, err) = env.run(&["--help"]);
    assert_eq!(code, 0, "REQ-A-002's own verification must succeed: {err}");
    let listed: Vec<String> = out
        .lines()
        .filter_map(|l| l.strip_prefix("    holdfast "))
        .map(|rest| {
            rest.split_whitespace()
                .take_while(|w| !w.starts_with('<') && !w.starts_with('['))
                .take_while(|w| w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    let documented = [
        "mcp",
        "daemon run",
        "daemon start",
        "daemon stop",
        "daemon status",
        "list",
        "logs",
        "attach",
        "watch",
        "version",
    ];
    assert_eq!(listed, documented, "the banner's subcommands:\n{out}");
    for sub in documented {
        let mut args: Vec<&str> = vec!["help"];
        args.extend(sub.split(' '));
        let (code, out, err) = env.run(&args);
        assert_eq!(code, 0, "`holdfast help {sub}`: {err}");
        assert!(out.contains(&format!("holdfast {sub}")), "{out}");
    }
}

/// **GH #233: an unknown flag was silently dropped** and the command ran
/// without it — `list --jsn` printed the table, `logs big --tial 5` the
/// whole log, exit 0 both. Worst of all is a typo on a destructive flag,
/// so the last case is a running daemon asked to `stop --forse`: it must
/// refuse, and the daemon must still be there.
#[test]
fn an_unknown_flag_is_a_usage_error_and_changes_nothing() {
    let env = TestEnv::new("badflags");
    for (args, flag) in [
        (&["list", "--jsn"][..], "--jsn"),
        (&["logs", "big", "--tial", "5"][..], "--tial"),
        (&["mcp", "--no-deamon"][..], "--no-deamon"),
        (&["version", "--json"][..], "--json"),
    ] {
        let (code, out, err) = env.run(args);
        assert_eq!(code, 64, "{args:?}: stdout {out} stderr {err}");
        assert!(err.contains(flag), "{args:?} did not name {flag}: {err}");
        assert!(out.is_empty(), "{args:?} ran anyway: {out}");
    }

    // Flags before the session are flags, not a missing session: with no
    // daemon this reaches the connect and fails *there*, exit 2.
    let (code, _, err) = env.run(&["logs", "--raw", "big"]);
    assert_eq!(code, 2, "{err}");
    assert!(!err.contains("needs a session"), "{err}");

    assert_eq!(env.run(&["daemon", "start"]).0, 0);
    let pid = env.daemon_pid().expect("pid file");
    let (code, out, err) = env.run(&["daemon", "stop", "--forse"]);
    assert_eq!(code, 64, "stdout {out} stderr {err}");
    assert!(err.contains("--forse"), "{err}");
    assert!(alive(pid), "a mistyped `daemon stop` flag stopped the daemon anyway");
    let (code, out, _) = env.run(&["daemon", "status", "--json"]);
    assert_eq!(code, 0, "the daemon stopped answering: {out}");
}

/// **GH #178: `holdfast version` said `(build unknown)` on every build
/// that was not the release pipeline's**, identical to the tag for a tree
/// a hundred commits past it. A build from a git checkout now names the
/// commit — derived here from the same place, not typed in.
#[test]
fn version_names_the_commit_it_was_built_from() {
    let env = TestEnv::new("buildid");
    let (code, out, err) = env.run(&["version"]);
    assert_eq!(code, 0, "{err}");
    let build = out
        .split("(build ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or_else(|| panic!("no `(build …)` in {out:?}"));

    // What the build script was told, if it was told anything.
    if let Some(sha) = option_env!("HOLDFAST_BUILD_SHA").filter(|s| !s.trim().is_empty()) {
        assert_eq!(build, sha.trim(), "{out}");
        return;
    }
    let git = Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(["rev-parse", "--short=12", "HEAD"])
        .output();
    let Some(sha) = git
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    else {
        println!("skipping: no git checkout to derive the expected build from");
        return;
    };
    assert!(
        build.starts_with(&sha),
        "`holdfast version` says build {build:?}; the checkout it was built from is at {sha}"
    );
}

