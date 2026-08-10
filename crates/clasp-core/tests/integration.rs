use clasp_core::pty::{InProcessPty, PtyBackend, PtySpawnConfig, Signal};
use std::time::{Duration, Instant};

fn bash() -> PtySpawnConfig {
    let mut cfg = PtySpawnConfig::new("bash");
    cfg.args = vec!["--norc".into(), "--noprofile".into()];
    cfg
}

/// Read from the PTY until `needle` appears or the deadline passes.
///
/// Callers must pick a needle that cannot appear in the *echoed command
/// line* — a PTY echoes input back, so searching for `MARKER` right after
/// writing `echo MARKER` matches the echo and proves nothing about
/// whether the child ever ran. Every marker below is written with an
/// embedded `''` so the echoed form differs from the executed output.
fn read_until(pty: &dyn PtyBackend, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut acc = String::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match pty.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if acc.contains(needle) {
                    return acc;
                }
            }
            Err(_) => break,
        }
    }
    acc
}

fn wait_for_exit(pty: &dyn PtyBackend, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while pty.is_alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    // kill(pid, 0) probes existence without signalling.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn spawns_a_shell_and_reads_output() {
    let pty = InProcessPty::spawn(&bash()).expect("spawn");

    assert!(pty.is_alive());
    assert!(pty.pid().is_some());

    // `CLASP''_MARKER` echoes as `CLASP''_MARKER` but prints CLASP_MARKER,
    // so the needle can only match real command output.
    pty.write(b"echo CLASP''_MARKER\n").unwrap();
    let out = read_until(&pty, "CLASP_MARKER", Duration::from_secs(5));
    assert!(out.contains("CLASP_MARKER"), "got: {out:?}");

    pty.signal(Signal::Kill).unwrap();
}

#[test]
fn terminate_kills_the_whole_process_group() {
    let pty = InProcessPty::spawn(&bash()).expect("spawn");

    // Background a child so shell job control puts it in its OWN process
    // group. This is the case a plain killpg(child_pid) does not reach.
    pty.write(b"sleep 300 & echo CHILD''_PID=$!\n").unwrap();
    let out = read_until(&pty, "CHILD_PID=", Duration::from_secs(5));
    let child_pid: i32 = out
        .split("CHILD_PID=")
        .nth(1)
        .map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no child pid in: {out:?}"));

    assert!(pid_alive(child_pid), "descendant never started");

    pty.signal(Signal::Kill).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    assert!(
        !pid_alive(child_pid),
        "descendant {child_pid} survived the session sweep"
    );
}

#[test]
fn interrupt_reaches_the_foreground_job_not_the_shell() {
    let pty = InProcessPty::spawn(&bash()).expect("spawn");
    pty.write(b"echo READY''_ONE\n").unwrap();
    read_until(&pty, "READY_ONE", Duration::from_secs(5));

    // Foreground sleep: job control gives it its own process group, which
    // becomes the terminal's foreground group.
    pty.write(b"sleep 300\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));

    pty.signal(Signal::Interrupt).unwrap();

    // If SIGINT had gone to the session leader instead of the foreground
    // group, `sleep` would still be running and this echo would not run
    // for 300 s. Getting the marker back within 5 s proves the signal
    // reached the job.
    pty.write(b"echo BACK''_AT_PROMPT\n").unwrap();
    let out = read_until(&pty, "BACK_AT_PROMPT", Duration::from_secs(5));
    assert!(
        out.contains("BACK_AT_PROMPT"),
        "shell did not return to a prompt after interrupt; got: {out:?}"
    );
    assert!(pty.is_alive(), "interrupt killed the shell");

    pty.signal(Signal::Kill).unwrap();
}

#[test]
fn resize_is_visible_to_the_child() {
    let mut cfg = bash();
    cfg.cols = 80;
    cfg.rows = 24;
    let pty = InProcessPty::spawn(&cfg).expect("spawn");

    pty.resize(100, 30).unwrap();
    pty.write(b"stty size\n").unwrap();
    let out = read_until(&pty, "30 100", Duration::from_secs(5));
    assert!(out.contains("30 100"), "got: {out:?}");

    pty.signal(Signal::Kill).unwrap();
}

#[test]
fn exit_code_is_reported() {
    let mut cfg = PtySpawnConfig::new("bash");
    cfg.args = vec!["-c".into(), "exit 42".into()];
    let pty = InProcessPty::spawn(&cfg).expect("spawn");

    wait_for_exit(&pty, Duration::from_secs(5));
    assert!(!pty.is_alive());
    assert_eq!(pty.exit_code(), Some(42));
}

#[test]
fn signal_after_exit_is_a_no_op() {
    let mut cfg = PtySpawnConfig::new("bash");
    cfg.args = vec!["-c".into(), "exit 0".into()];
    let pty = InProcessPty::spawn(&cfg).expect("spawn");

    wait_for_exit(&pty, Duration::from_secs(5));
    assert!(!pty.is_alive());

    // Must not sweep: the PID may have been recycled by now, and
    // signalling a stranger's session would be a serious bug.
    pty.signal(Signal::Kill)
        .expect("signal after exit must be Ok");
    pty.signal(Signal::Terminate)
        .expect("signal after exit must be Ok");
    pty.signal(Signal::Interrupt)
        .expect("signal after exit must be Ok");
}

use clasp_core::mcp::tools::{ReadOutputArgs, StartSessionArgs};
use clasp_core::mcp::ClaspServer;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;

fn body(r: &rmcp::model::CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

fn bash_args() -> Vec<String> {
    vec!["--norc".into(), "--noprofile".into()]
}

/// Poll a session's buffer until `needle` appears. Reads through the
/// `Session` API rather than the `read_output` tool, which does not exist
/// until Task 8.
fn wait_for_buffer(session: &clasp_core::session::Session, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = String::from_utf8_lossy(&session.read_from(0, 1 << 20).bytes).to_string();
        if text.contains(needle) || Instant::now() >= deadline {
            return text;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn start_session_returns_a_session_id() {
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: Some("t1".into()),
            cwd: None,
            env: None,
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();

    let b = body(&r);
    assert_eq!(b["status"], "ok");
    let id = b["data"]["session_id"].as_str().unwrap();
    assert!(id.starts_with("sess_"));
    assert_eq!(b["data"]["name"], "t1");
    assert!(b["data"]["pid"].as_u64().unwrap() > 0);
    // The default cwd is pinned to the server's own directory, not the
    // $HOME that portable-pty would otherwise fall back to.
    assert_eq!(
        b["data"]["cwd"].as_str().unwrap(),
        std::env::current_dir().unwrap().to_string_lossy()
    );

    server
        .registry
        .get(id)
        .unwrap()
        .signal(clasp_core::pty::Signal::Kill)
        .unwrap();
}

#[tokio::test]
async fn duplicate_name_is_rejected() {
    let server = ClaspServer::new();
    let mk = |name: &str| StartSessionArgs {
        command: "bash".into(),
        args: bash_args(),
        name: Some(name.into()),
        cwd: None,
        env: None,
        cols: None,
        rows: None,
    };
    let first = server.start_session(Parameters(mk("dup"))).await.unwrap();
    assert_eq!(body(&first)["status"], "ok");

    let second = server.start_session(Parameters(mk("dup"))).await.unwrap();
    assert_eq!(body(&second)["status"], "name_taken");
    assert_eq!(second.is_error, Some(true));

    for s in server.registry.all() {
        let _ = s.signal(clasp_core::pty::Signal::Kill);
    }
}

#[tokio::test]
async fn start_session_rejects_a_nonexistent_cwd() {
    // portable-pty silently discards a cwd that isn't a directory and
    // runs in $HOME instead, so without this check the agent would be
    // told `ok` while running somewhere it did not ask for.
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: None,
            cwd: Some("/no/such/directory/anywhere".into()),
            env: None,
            cols: None,
            rows: None,
        }))
        .await;
    assert!(r.is_err(), "a bad cwd must be a protocol error");
    assert!(
        server.registry.all().is_empty(),
        "nothing should have been spawned"
    );
}

#[tokio::test]
async fn start_session_reports_spawn_failed_without_leaking_the_path() {
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "clasp_definitely_not_a_real_program".into(),
            args: vec![],
            name: None,
            cwd: None,
            env: None,
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();
    let b = body(&r);
    assert_eq!(b["status"], "spawn_failed");
    assert_eq!(r.is_error, Some(true));
    let details = b["details"].as_str().unwrap();
    assert!(
        !details.contains(&std::env::var("PATH").unwrap_or_default()),
        "the spawn error must not carry $PATH into the transcript: {details:?}"
    );
    assert!(details.chars().count() <= 220, "details: {details:?}");
}

#[tokio::test]
async fn start_session_runs_in_the_requested_cwd_and_passes_env() {
    let server = ClaspServer::new();
    let dir = std::env::temp_dir().canonicalize().unwrap();
    let mut env = std::collections::HashMap::new();
    // The value never appears in the command line the test types, so the
    // PTY's echo cannot satisfy either assertion below.
    env.insert("CLASP_PROBE".to_string(), "env-plumbing-works".to_string());

    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: None,
            cwd: Some(dir.to_string_lossy().into_owned()),
            env: Some(env),
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();
    let id = body(&r)["data"]["session_id"].as_str().unwrap().to_string();

    let session = server.registry.get(&id).unwrap();
    session.write_input(b"pwd; printenv CLASP_PROBE\n").unwrap();
    let out = wait_for_buffer(&session, "env-plumbing-works");

    assert!(
        out.contains(&*dir.to_string_lossy()),
        "session did not start in the requested cwd; got: {out:?}"
    );
    assert!(
        out.contains("env-plumbing-works"),
        "env was not passed to the child; got: {out:?}"
    );

    let _ = session.signal(clasp_core::pty::Signal::Kill);
}

/// Poll read_output until `needle` appears or the attempt budget runs out.
async fn read_until_contains(
    server: &ClaspServer,
    session: &str,
    needle: &str,
    attempts: usize,
) -> String {
    let mut cursor = 0u64;
    let mut acc = String::new();
    for _ in 0..attempts {
        let r = server
            .read_output(Parameters(ReadOutputArgs {
                session: session.into(),
                since_cursor: Some(cursor),
                tail_lines: None,
                tail_bytes: None,
                max_bytes: None,
            }))
            .await
            .unwrap();
        let b = body(&r);
        acc.push_str(b["data"]["output"].as_str().unwrap_or(""));
        cursor = b["data"]["cursor"].as_u64().unwrap_or(cursor);
        if acc.contains(needle) {
            return acc;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    acc
}

async fn start_bash(server: &ClaspServer) -> String {
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: None,
            cwd: None,
            env: None,
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();
    body(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn read_output_returns_shell_output_and_advances_the_cursor() {
    let server = ClaspServer::new();
    let id = start_bash(&server).await;
    let session = server.registry.get(&id).unwrap();

    // `READ''_MARKER` echoes back as `READ''_MARKER` but *prints*
    // READ_MARKER, so the needle can only match output the shell
    // actually produced. Searching for a marker written literally would
    // match the PTY's echo of the command line and prove nothing.
    session.write_input(b"echo READ''_MARKER\n").unwrap();
    let out = read_until_contains(&server, &id, "READ_MARKER", 30).await;
    assert!(out.contains("READ_MARKER"), "got: {out:?}");

    // A capped read reports the cap and hands back a cursor to resume
    // from; `truncated_for_size` must reflect the cap, not "more bytes
    // exist" (§18.2).
    let capped = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: Some(8),
        }))
        .await
        .unwrap();
    let b = body(&capped);
    assert_eq!(b["data"]["bytes_returned"], 8);
    assert_eq!(b["data"]["cursor"], 8);
    assert_eq!(b["data"]["truncated_for_size"], true);
    assert_eq!(b["data"]["next_cursor"], 8);

    let _ = session.signal(clasp_core::pty::Signal::Kill);
}

#[tokio::test]
async fn read_output_rejects_zero_or_multiple_selectors() {
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    let none = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: None,
            tail_lines: None,
            tail_bytes: None,
            max_bytes: None,
        }))
        .await;
    assert!(none.is_err(), "zero selectors must be a protocol error");

    let both = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: Some(5),
            tail_bytes: None,
            max_bytes: None,
        }))
        .await;
    assert!(both.is_err(), "two selectors must be a protocol error");

    // Validation runs before resolution, so a schema violation is not
    // masked by an unknown session (§5.1).
    let unknown = server
        .read_output(Parameters(ReadOutputArgs {
            session: "sess_nope".into(),
            since_cursor: None,
            tail_lines: None,
            tail_bytes: None,
            max_bytes: None,
        }))
        .await;
    assert!(unknown.is_err(), "schema violation must win over lookup");

    let _ = server
        .registry
        .get(&id)
        .unwrap()
        .signal(clasp_core::pty::Signal::Kill);
}

#[tokio::test]
async fn read_output_on_unknown_session_is_an_error_envelope() {
    let server = ClaspServer::new();
    let r = server
        .read_output(Parameters(ReadOutputArgs {
            session: "sess_nope".into(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&r)["status"], "session_not_found");
    assert_eq!(r.is_error, Some(true));
}

#[tokio::test]
async fn read_output_tail_lines_respects_max_bytes() {
    // REQ-T-006: max_bytes is a raw-byte cap on every selector. Without
    // it a tail_lines read returns the whole ring buffer — up to 1 MiB
    // in one tool response.
    let server = ClaspServer::new();
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                "for i in $(seq 1 4000); do echo padding-padding-padding-$i; done; sleep 30".into(),
            ],
            name: None,
            cwd: None,
            env: None,
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();
    let id = body(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let session = server.registry.get(&id).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while session.buffer_head() < 50_000 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(session.buffer_head() >= 50_000, "child produced too little");

    let r = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: None,
            tail_lines: Some(1_000_000),
            tail_bytes: None,
            max_bytes: Some(1024),
        }))
        .await
        .unwrap();
    let b = body(&r);
    assert_eq!(b["data"]["bytes_returned"], 1024);
    assert_eq!(b["data"]["truncated_for_size"], true);

    let _ = session.signal(clasp_core::pty::Signal::Kill);
}
