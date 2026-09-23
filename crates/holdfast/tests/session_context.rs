//! A shared daemon, driven by more than one client, through real shims:
//! whose directory and environment a session starts from (GH #229).
//!
//! `daemon_cli.rs` is this file's neighbour and owns the general
//! process-level suite. These rows live apart because they are about one
//! property — a daemon serving *several* clients, each of which must be
//! treated as itself — and the harness below is the smallest one that
//! can state it. It follows `daemon_cli.rs`'s one rule without
//! exception: **nothing here waits without a deadline**, and a deadline
//! that expires panics rather than counting as a pass.
#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_holdfast");

/// How long the shim may take to answer one JSON-RPC request. Generous:
/// the first call of a shim can include a daemon spawn, and the suite
/// runs in parallel on a loaded machine. Not a performance assertion.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// One private daemon instance, stopped and removed on drop.
struct Instance {
    dir: PathBuf,
}

impl Instance {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        // `/tmp`, not `target/`: a socket path must fit `sun_path`.
        let dir = PathBuf::from(format!(
            "/tmp/holdfast-ctx-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Self { dir }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env("HOLDFAST_RUNTIME_DIR", &self.dir);
        // Keep the developer's own `~/.config/holdfast/config.toml` out,
        // as `daemon_cli.rs`'s `TestEnv::cmd` does and for its reason.
        c.env("XDG_CONFIG_HOME", self.dir.with_extension("xdg"));
        c
    }

    fn daemon_pid(&self) -> Option<u32> {
        let text = std::fs::read_to_string(self.dir.join("holdfast.pid")).ok()?;
        text.split_whitespace().next()?.parse().ok()
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self
            .cmd()
            .args(["daemon", "stop", "--force"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        std::thread::sleep(Duration::from_millis(150));
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_dir_all(self.dir.with_extension("xdg"));
    }
}

/// A project directory, canonical so it compares with what the daemon
/// canonicalises and `pwd -P` prints.
struct Project(PathBuf);

impl Project {
    fn new(inst: &Instance, name: &str) -> Self {
        let dir = inst.dir.with_extension(name);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir.canonicalize().unwrap())
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `holdfast mcp` process driven over stdio with raw JSON-RPC.
struct Shim {
    child: Child,
    lines: Receiver<String>,
    next_id: u64,
}

impl Shim {
    /// A shim launched the way an MCP client launches one: in the
    /// client's directory, with the client's environment.
    fn launch(inst: &Instance, cwd: &Path, env: &[(&str, &str)], args: &[&str]) -> Self {
        let mut cmd = inst.cmd();
        cmd.current_dir(cwd);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn holdfast mcp");
        let stdout = child.stdout.take().unwrap();
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
        let init = shim.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "holdfast-test", "version": "0" }
            }),
        );
        assert!(init["result"].is_object(), "{init}");
        shim.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        shim
    }

    fn send(&mut self, msg: &Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let line = match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the shim did not answer `{method}` within {RESPONSE_TIMEOUT:?}")
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("the shim closed stdout before answering `{method}`")
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line.trim())
                .unwrap_or_else(|e| panic!("non-JSON-RPC on the MCP transport: {line:?} ({e})"));
            if value["id"] == json!(id) {
                return value;
            }
        }
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn envelope(resp: &Value) -> &Value {
    &resp["result"]["structuredContent"]
}

/// Start a `/bin/sh` that prints where it is and what it was told, then
/// read that line back. No `cwd` — which is the whole of GH #229.
///
/// `sh -c` rather than an interactive shell: its script is not echoed,
/// so the only `WHERE_OUT` line in the buffer is the one it printed, and
/// no rc file of the machine running the suite is involved.
fn where_does_a_session_start(shim: &mut Shim) -> (Value, String) {
    let started = shim.call(
        "start_session",
        json!({
            "command": "/bin/sh",
            "args": ["-c", "printf 'WHERE_OUT d=[%s] project=[%s]\\n' \"$(pwd -P)\" \"$CLAUDE_PROJECT_DIR\"; sleep 30"],
        }),
    );
    assert_eq!(envelope(&started)["status"], "ok", "{started}");
    let id = envelope(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let read = shim.call(
            "read_output",
            json!({ "session": id, "since_cursor": 0, "max_bytes": 65536 }),
        );
        let out = envelope(&read)["data"]["output"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if let Some(line) = out.lines().find(|l| l.contains("WHERE_OUT ")) {
            if line.trim_end().ends_with(']') {
                shim.call("terminate", json!({ "session": id, "force": true }));
                return (envelope(&started)["data"].clone(), line.trim().to_string());
            }
        }
        assert!(
            Instant::now() < deadline,
            "the session never printed where it was; output: {out:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// **GH #229, as the owner hit it.** Two clients in two projects share
/// one daemon — the first one spawned it — and both start a session
/// without naming a `cwd`. Each session must start in **its own**
/// client's project, with **its own** client's `CLAUDE_PROJECT_DIR`.
///
/// Before the fix the second printed the first's directory and the
/// first's project: the daemon started every session from itself, and
/// itself was whatever the first client had been.
///
/// Both halves are asserted for both clients, because each is the other's
/// negative: a daemon that always used the *latest* caller's directory
/// passes B and fails A.
#[test]
fn two_clients_in_two_projects_each_start_sessions_in_their_own() {
    let inst = Instance::new("two");
    let a = Project::new(&inst, "proj-a");
    let b = Project::new(&inst, "proj-b");

    let mut shim_a = Shim::launch(&inst, &a.0, &[("CLAUDE_PROJECT_DIR", a.path())], &["mcp"]);
    let daemon = inst
        .daemon_pid()
        .expect("the first shim spawned the daemon");
    let mut shim_b = Shim::launch(&inst, &b.0, &[("CLAUDE_PROJECT_DIR", b.path())], &["mcp"]);
    assert_eq!(
        inst.daemon_pid(),
        Some(daemon),
        "the second client must share the first's daemon, or this tests nothing"
    );

    let (_, from_a) = where_does_a_session_start(&mut shim_a);
    let (started_b, from_b) = where_does_a_session_start(&mut shim_b);

    assert_eq!(
        from_a,
        format!("WHERE_OUT d=[{}] project=[{}]", a.path(), a.path())
    );
    assert_eq!(
        from_b,
        format!("WHERE_OUT d=[{}] project=[{}]", b.path(), b.path()),
        "the second project's session started in the first project's context"
    );
    // And the response says so: the one field an agent can check before
    // it runs anything.
    assert_eq!(started_b["cwd"], b.path(), "{started_b}");

    shim_a.kill();
    shim_b.kill();
}

/// The reference the fix was measured against: `--no-daemon`, where the
/// server is the process the client launched and was always right. Kept
/// as a row so the two transports cannot drift apart again unseen.
#[test]
fn no_daemon_mode_starts_sessions_in_its_clients_project_too() {
    let inst = Instance::new("nod");
    let b = Project::new(&inst, "proj-b");
    let mut shim = Shim::launch(
        &inst,
        &b.0,
        &[("CLAUDE_PROJECT_DIR", b.path())],
        &["mcp", "--no-daemon"],
    );
    let (_, from_b) = where_does_a_session_start(&mut shim);
    assert_eq!(
        from_b,
        format!("WHERE_OUT d=[{}] project=[{}]", b.path(), b.path())
    );
    assert_eq!(inst.daemon_pid(), None, "--no-daemon must start no daemon");
    shim.kill();
}
