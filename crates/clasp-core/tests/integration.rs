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
    assert_eq!(pty.signal_deliveries(), 0, "nothing has been signalled yet");

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
    // Positive control for `signal_after_exit_is_a_no_op`, which asserts
    // this counter stays at zero. Without a case that drives it up, a
    // counter that never incremented would make that assertion vacuous —
    // exactly the failure mode the zero-assertion exists to close.
    assert!(
        pty.signal_deliveries() > 0,
        "a live sweep must actually reach the OS"
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

    // The assertion that actually tests the guard. `Ok(())` alone does
    // not: Kill and Terminate route through `sweep`, which counts ESRCH
    // as a success, so both return `Ok` whether or not the guard is
    // there — deleting the guard used to leave this test passing on the
    // two arms that matter and failing only on `Interrupt`, which is not
    // even a 0.0.1 tool. The delivery counter is what makes "no signal
    // left this process" observable, and it is the only thing standing
    // between a recycled PID and a stranger's session.
    assert_eq!(
        pty.signal_deliveries(),
        0,
        "a signal was delivered to a PID that has already exited and may \
         since have been recycled"
    );
}

use clasp_core::mcp::tools::{ReadOutputArgs, SendInputArgs, StartSessionArgs, TerminateArgs};
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
    // Guard the empty case: `contains("")` is true for every string, so
    // an unset PATH would make this assertion fail unconditionally
    // rather than test anything.
    let path = std::env::var("PATH").unwrap_or_default();
    if !path.is_empty() {
        assert!(
            !details.contains(&path),
            "the spawn error must not carry $PATH into the transcript: {details:?}"
        );
    }
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

/// Start `bash -c <script>` and return its session id.
async fn start_script(server: &ClaspServer, script: &str) -> String {
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                script.into(),
            ],
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

async fn kill_all(server: &ClaspServer) {
    for s in server.registry.all() {
        let _ = s.signal(clasp_core::pty::Signal::Kill);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
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

    let head_before = session.buffer_head();
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

    // The cursor must still point just past the NEWEST byte, not at the
    // start of the clipped slice. An implementation returning
    // `head - dropped` would re-deliver these same bytes on every
    // subsequent `since_cursor` read — an infinite loop for any agent
    // polling with cursors. A lower bound rather than equality, because
    // the reader thread keeps appending while this test runs.
    let cursor = b["data"]["cursor"]
        .as_u64()
        .expect("cursor must be present");
    assert!(
        cursor >= head_before,
        "cursor {cursor} regressed below the pre-read head {head_before}; \
         front-clipping must not move the cursor back"
    );

    // Stronger than the bound above: kill the child so output stops, then
    // feed the cursor back. A correct cursor points past the newest byte,
    // so the follow-up read returns nothing. A cursor pointing at the
    // start of the clipped slice would re-deliver those 1024 bytes, which
    // is the actual agent-visible failure — a cursor-polling agent would
    // loop on the same output forever.
    let _ = session.signal(clasp_core::pty::Signal::Kill);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let settled = session.buffer_head();
    let again = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(settled),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: Some(4096),
        }))
        .await
        .unwrap();
    assert_eq!(
        body(&again)["data"]["bytes_returned"],
        0,
        "reading from the settled head must return nothing; a cursor that \
         regressed would re-deliver already-seen bytes"
    );
}

#[tokio::test]
async fn terminate_without_force_escalates_to_sigkill_for_a_sigterm_immune_child() {
    // The normal production path: an interactive bash IGNORES SIGTERM, so
    // every real terminate(force=false) must escalate to SIGKILL. The
    // existing SIGTERM test uses a child that traps and exits, so it never
    // reaches the escalation branch. A regression inverting that branch
    // would leave real shells alive while terminate reported ok.
    let server = ClaspServer::new();
    let id = start_bash(&server).await;
    let session = server.registry.get(&id).unwrap();
    let pid = session.pid().expect("pid") as i32;

    let r = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(false),
            timeout_secs: Some(1),
        }))
        .await
        .unwrap();
    assert_eq!(body(&r)["status"], "ok");

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !pid_alive(pid),
        "interactive bash ignores SIGTERM, so pid {pid} proves the SIGKILL \
         escalation never ran"
    );
    assert!(!session.is_alive());
}

#[tokio::test]
async fn send_input_reaches_the_shell() {
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    // Same `''` construction as the read_output test, for the same
    // reason: a literal marker would match the terminal's echo.
    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo SEND''_MARKER; echo $((6*7))".into(),
            append_newline: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&r)["status"], "ok");

    let out = read_until_contains(&server, &id, "SEND_MARKER", 30).await;
    assert!(out.contains("SEND_MARKER"), "got: {out:?}");
    // `42` appears nowhere in the bytes we wrote, so only a shell that
    // evaluated the expression can have produced it.
    assert!(out.contains("42"), "shell did not evaluate: {out:?}");

    let _ = server
        .registry
        .get(&id)
        .unwrap()
        .signal(clasp_core::pty::Signal::Kill);
}

#[tokio::test]
async fn terminate_is_idempotent_and_preserves_the_output() {
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo BEFORE''_TERMINATE".into(),
            append_newline: None,
        }))
        .await
        .unwrap();
    read_until_contains(&server, &id, "BEFORE_TERMINATE", 30).await;

    let first = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&first)["status"], "ok");
    assert_eq!(body(&first)["data"]["already_exited"], false);

    // §4.1: an exited session keeps its id, so the agent can still read
    // what the command printed before it was stopped.
    let after = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&after)["status"], "ok");
    assert!(
        body(&after)["data"]["output"]
            .as_str()
            .unwrap()
            .contains("BEFORE_TERMINATE"),
        "terminate destroyed the session's output"
    );

    // REQ-T-010: a repeat terminate is `ok` with cached exit info.
    let second = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&second)["status"], "ok");
    assert_ne!(second.is_error, Some(true));
    assert_eq!(body(&second)["data"]["already_exited"], true);
}

#[tokio::test]
async fn terminate_without_force_delivers_sigterm_first() {
    // REQ-P-004. The child traps SIGTERM and exits 77, an exit code it
    // can only reach if the graceful signal arrived — a SIGKILL-first
    // implementation reports 1 instead.
    let server = ClaspServer::new();
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                "trap 'exit 77' TERM; while true; do sleep 0.1; done".into(),
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
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let r = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(false),
            timeout_secs: Some(5),
        }))
        .await
        .unwrap();
    assert_eq!(body(&r)["status"], "ok");
    assert_eq!(
        body(&r)["data"]["exit_code"],
        77,
        "child was not given a chance to handle SIGTERM"
    );
}

#[tokio::test]
async fn send_input_to_an_exited_session_reports_session_died() {
    let server = ClaspServer::new();
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec!["-c".into(), "exit 0".into()],
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

    // Let the child exit.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id,
            data: "echo nope".into(),
            append_newline: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&r)["status"], "session_died");
    assert_ne!(
        r.is_error,
        Some(true),
        "session_died is an outcome, not an error"
    );
}

/// A child that has stopped reading its terminal must not be able to take
/// the server down with it.
///
/// Written against a hand-built runtime rather than `#[tokio::test]`
/// because both ends have to be bounded.
///
/// The runtime must be multi-threaded: before the fix the blocking write
/// ran inline on the calling worker, and on the default current-thread
/// runtime the timers below could never fire at all — the test would hang
/// rather than fail. And the shutdown must be bounded and must happen even
/// when an assertion fails, because a parked write is still parked when
/// the test ends and `Runtime::drop` waits for its thread with no
/// deadline. Hence `catch_unwind` → `shutdown_timeout` → `resume_unwind`:
/// a regression must make this test go *red*, not make the suite hang.
#[test]
fn send_input_to_a_child_that_never_reads_returns_and_leaves_the_server_usable() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(wedged_send_input_body())
    }));

    // The write is *still* parked: the kernel does not wake a blocked
    // pty-master writer when the slave closes, so killing the child does
    // not release it. Dropping the runtime would wait for that thread
    // without a deadline.
    rt.shutdown_timeout(Duration::from_secs(2));

    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

async fn wedged_send_input_body() {
    let server = ClaspServer::new();

    // `stty raw` is the whole point. In canonical mode the line
    // discipline *discards* input it cannot buffer, so a write to a
    // non-reading child returns immediately — which is why none of
    // the other tests here ever saw this. In raw mode it parks the
    // writer instead, and `exec sleep 300` guarantees nothing will
    // ever drain it.
    let wedged = start_script(&server, "stty raw -echo; exec sleep 300").await;
    let healthy = start_bash(&server).await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Comfortably past the few KiB the line discipline will hold, so
    // the write cannot complete no matter how long it waits.
    let payload = "x".repeat(64 * 1024);

    let started = Instant::now();
    let call = tokio::spawn({
        let server = server.clone();
        let session = wedged.clone();
        async move {
            server
                .send_input(Parameters(SendInputArgs {
                    session,
                    data: payload,
                    append_newline: Some(false),
                }))
                .await
        }
    });

    // While that write is parked, the server must still answer for a
    // DIFFERENT session. Before the fix each blocked write consumed a
    // worker, and a handful of them took out every tool — including
    // terminate, the only way to recover.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let other = tokio::time::timeout(
        Duration::from_secs(10),
        server.send_input(Parameters(SendInputArgs {
            session: healthy.clone(),
            data: "echo STILL''_SERVING".into(),
            append_newline: None,
        })),
    )
    .await
    .expect("the server stopped answering for an unrelated session")
    .expect("send_input must not be a protocol error");
    assert_eq!(body(&other)["status"], "ok");
    let out = read_until_contains(&server, &healthy, "STILL_SERVING", 30).await;
    assert!(out.contains("STILL_SERVING"), "got: {out:?}");

    // And the wedged call itself must come back rather than hang.
    let r = tokio::time::timeout(Duration::from_secs(20), call)
        .await
        .expect("send_input never returned; a blocking write wedged the worker")
        .expect("send_input task panicked")
        .expect("send_input must not be a protocol error");
    let elapsed = started.elapsed();
    let b = body(&r);
    assert_eq!(
        b["status"], "timeout",
        "a write the child never accepted is a timeout, not a success: {b}"
    );
    assert_ne!(
        r.is_error,
        Some(true),
        "timeout is an outcome the agent handles, not an error (§18.1)"
    );
    assert!(
        b["data"]["bytes_written"].is_null(),
        "the write may have partially landed, so a count would be a guess: {b}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "send_input took {elapsed:?}; it must return on its own deadline"
    );

    // A second write to the SAME session must also return, instead of
    // queueing behind the first one's lock forever.
    let again = tokio::time::timeout(
        Duration::from_secs(20),
        server.send_input(Parameters(SendInputArgs {
            session: wedged.clone(),
            data: "y".into(),
            append_newline: Some(false),
        })),
    )
    .await
    .expect("a second write to a wedged session never returned")
    .expect("send_input must not be a protocol error");
    assert_eq!(body(&again)["status"], "timeout");

    kill_all(&server).await;
}

#[tokio::test]
async fn send_input_rejects_an_oversized_payload() {
    // `data` was unbounded, which is what made a 256 KiB write to a
    // non-reading child possible in the first place.
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "x".repeat(64 * 1024 + 1),
            append_newline: Some(false),
        }))
        .await;
    assert!(r.is_err(), "an oversized payload must be a protocol error");

    // The cap is on size alone: the same call with a small payload works,
    // so the rejection above cannot be blamed on the session or the args.
    let ok = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo SIZE''_OK".into(),
            append_newline: None,
        }))
        .await
        .unwrap();
    assert_eq!(body(&ok)["status"], "ok");

    kill_all(&server).await;
}

#[tokio::test]
async fn read_output_does_not_claim_a_cap_that_returned_everything() {
    // The `since_cursor` branch reported `truncated_for_size: true`
    // whenever the read filled max_bytes -- including when it filled it by
    // returning the entire buffer. The response then claimed a cap and a
    // null `next_cursor` in the same breath: "there is more, and there is
    // nothing more". The identical bug was fixed twice on the tail_bytes
    // branch and never propagated here.
    let server = ClaspServer::new();
    let id = start_bash(&server).await;
    let session = server.registry.get(&id).unwrap();

    session.write_input(b"echo CAP''_MARKER\n").unwrap();
    let out = read_until_contains(&server, &id, "CAP_MARKER", 30).await;
    assert!(out.contains("CAP_MARKER"), "got: {out:?}");

    // Kill the child so the buffer stops growing; otherwise the reader
    // thread can append between the read and the assertion.
    let _ = session.signal(clasp_core::pty::Signal::Kill);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let head = session.buffer_head();
    assert!(head > 1, "the shell produced nothing to read");

    let exact = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: Some(head as usize),
        }))
        .await
        .unwrap();
    let b = body(&exact);
    assert_eq!(b["data"]["bytes_returned"], head);
    assert_eq!(
        b["data"]["truncated_for_size"], false,
        "the read returned the whole buffer, so nothing was capped: {b}"
    );
    assert!(
        b["data"]["next_cursor"].is_null(),
        "next_cursor and truncated_for_size must agree: {b}"
    );

    // The other direction, so the assertion above is not satisfied by an
    // implementation that simply never sets the flag.
    let short = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: Some(head as usize - 1),
        }))
        .await
        .unwrap();
    let b = body(&short);
    assert_eq!(b["data"]["bytes_returned"], head - 1);
    assert_eq!(
        b["data"]["truncated_for_size"], true,
        "one byte was genuinely left behind: {b}"
    );
    assert_eq!(b["data"]["next_cursor"], head - 1);
}

#[tokio::test]
async fn read_output_rejects_a_zero_max_bytes() {
    // `max_bytes: 0` returned `bytes_returned: 0, truncated_for_size:
    // true, next_cursor: <unchanged>`, so an agent following the
    // documented "retry at next_cursor" rule spun forever making no
    // progress. A read that cannot advance is a caller bug, and the tool
    // already treats schema violations as protocol errors (§5.1).
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    let zero = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: Some(0),
        }))
        .await;
    assert!(zero.is_err(), "max_bytes: 0 must be a protocol error");

    // One byte is legal, so the rejection is about zero specifically and
    // not about small caps in general.
    let one = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            tail_lines: None,
            tail_bytes: None,
            max_bytes: Some(1),
        }))
        .await
        .unwrap();
    assert_eq!(body(&one)["status"], "ok");

    kill_all(&server).await;
}

#[tokio::test]
async fn start_session_returns_the_effective_cwd_not_the_requested_one() {
    // §5.2: the returned `cwd` is the directory the child was actually
    // spawned in. Echoing the caller's own argument back tells it nothing,
    // and this is on the tool surface §23.3 freezes at 0.0.1.
    let server = ClaspServer::new();

    let relative = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: None,
            cwd: Some(".".into()),
            env: None,
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();
    let cwd = body(&relative)["data"]["cwd"]
        .as_str()
        .expect("cwd must be reported")
        .to_string();
    assert!(
        std::path::Path::new(&cwd).is_absolute(),
        "a relative cwd must round-trip as an absolute path; got {cwd:?}"
    );
    assert_eq!(
        cwd,
        std::env::current_dir()
            .unwrap()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
    );

    // Stronger than the `.` case, which an implementation that merely
    // joined the argument onto the process cwd would also satisfy: only a
    // canonicalising implementation resolves a symlink.
    let base = std::env::temp_dir().canonicalize().unwrap();
    let target = base.join(format!("clasp-cwd-target-{}", std::process::id()));
    let link = base.join(format!("clasp-cwd-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_dir_all(&target);
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let symlinked = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: None,
            cwd: Some(link.to_string_lossy().into_owned()),
            env: None,
            cols: None,
            rows: None,
        }))
        .await
        .unwrap();
    let cwd = body(&symlinked)["data"]["cwd"]
        .as_str()
        .expect("cwd must be reported")
        .to_string();

    kill_all(&server).await;
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_dir_all(&target);

    assert_eq!(
        cwd,
        target.to_string_lossy(),
        "the returned cwd must be the effective directory, not the symlink \
         the caller passed"
    );
}

/// Poll `echo_enabled` until it reports `want` or the deadline passes,
/// then return whatever it last said.
fn poll_echo(pty: &dyn PtyBackend, want: Option<bool>, timeout: Duration) -> Option<bool> {
    let deadline = Instant::now() + timeout;
    let mut last = pty.echo_enabled();
    while last != want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(60));
        last = pty.echo_enabled();
    }
    last
}

#[test]
fn echo_enabled_tracks_the_slaves_line_discipline() {
    // Spike row 2, measured: readline turns ECHO *off* while it draws a
    // prompt, and the line discipline is back on while a command runs.
    // A backend returning a constant — or `None` — fails one half or the
    // other, so both assertions are needed to pin the behaviour.
    let pty = InProcessPty::spawn(&bash()).expect("spawn");

    assert_eq!(
        poll_echo(&pty, Some(false), Duration::from_secs(5)),
        Some(false),
        "ECHO should be off once readline has drawn a prompt"
    );

    pty.write(b"sleep 3\n").unwrap();
    assert_eq!(
        poll_echo(&pty, Some(true), Duration::from_secs(5)),
        Some(true),
        "ECHO should be on while a command runs"
    );

    pty.signal(Signal::Kill).unwrap();
}

#[test]
fn echo_enabled_is_none_once_the_child_has_exited() {
    let mut cfg = PtySpawnConfig::new("bash");
    cfg.args = vec!["-c".into(), "exit 0".into()];
    let pty = InProcessPty::spawn(&cfg).expect("spawn");
    wait_for_exit(&pty, Duration::from_secs(5));
    assert!(!pty.is_alive());
    assert_eq!(
        pty.echo_enabled(),
        None,
        "a dead child's line discipline says nothing about the session"
    );
}
