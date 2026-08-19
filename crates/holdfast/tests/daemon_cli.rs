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
//! which has no timeout of its own. The workspace has no `nextest.toml`
//! and no per-test harness timeout, so a mutation that turns a reply
//! into silence would hang CI rather than redden it, and a hung job
//! looks like an infrastructure problem for as long as it takes someone
//! to read the logs.
//!
//! So a wait that expires **panics**. It is never absorbed into an
//! `Ok(_) | Err(_)` that would let a timeout count as a pass.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
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

    if !PathBuf::from("/proc/self/fd").exists() {
        return; // Linux-only introspection; other platforms skip.
    }

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
    assert!(
        !inodes.is_empty(),
        "the daemon should hold at least the Unix listener; fd scan found none"
    );

    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Field 3 is the state (`0A` = TCP_LISTEN); field 9 is the inode.
            if f.len() > 9 && f[3] == "0A" && inodes.contains(f[9]) {
                panic!("daemon pid {pid} is listening on TCP: {line}");
            }
        }
    }
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
    let mut daemons = 0;
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid_n) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid_n}/cmdline")) else {
            continue;
        };
        if !String::from_utf8_lossy(&cmdline)
            .replace('\0', " ")
            .contains("daemon run")
        {
            continue;
        }
        let Ok(environ) = std::fs::read(format!("/proc/{pid_n}/environ")) else {
            continue;
        };
        if String::from_utf8_lossy(&environ)
            .replace('\0', "\n")
            .contains(&format!("HOLDFAST_RUNTIME_DIR={}", env.dir.display()))
        {
            daemons += 1;
        }
    }
    assert_eq!(
        daemons, 1,
        "expected exactly one daemon for this runtime dir"
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
    assert!(out.contains("protocol 1.0"), "{out}");
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
    // §9.6, 0.0.7. An operator's typo'd binding must not become a
    // binding that silently never matches — which from the outside is
    // indistinguishable from a credential store that is down.
    let env = TestEnv::new("badbinding");
    env.write_config(
        "[[security.secret_bindings]]\n\
         name = \"prod-ssh\"\n\
         match_command = \"^ssh (\"\n\
         match_prompt = \"\"\n\
         provider = \"secret-service\"\n\
         reference = \"service=holdfast,account=prod-ssh\"\n",
    );

    let (code, _, err) = env.run(&["daemon", "run"]);
    assert_ne!(code, 0, "an uncompilable binding must not start a daemon");
    assert!(
        err.contains("match_command"),
        "the error names the offending key; got: {err}"
    );
    assert!(
        err.contains("prod-ssh"),
        "and the binding, or an operator with six of them cannot find it; got: {err}"
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
