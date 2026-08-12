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

/// Whether a pid still exists, via `kill(pid, 0)`.
///
/// Unix-only, and every test that calls it now carries the *same*
/// `#[cfg(unix)]` — which is the fix, not decoration. This helper was
/// already gated while its three call sites were not, so `cargo check
/// --all-targets --target x86_64-pc-windows-gnu` failed with four errors,
/// and had done for some time: the cross-check run by hand throughout 0.0.1
/// and 0.0.2, and reported in task reports as "clippy clean on
/// x86_64-pc-windows-gnu", was lib + bin only. A gated helper with unguarded
/// callers is what made a guard whose name is broader than its reach.
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

// Unix-only: the assertion is about a *descendant* pid outliving the sweep,
// probed with `kill(pid, 0)`. Windows job objects are 0.0.7's, and get
// their own test rather than a contorted version of this one. Gated at the
// test rather than at `pid_alive`, so the Linux run still carries it.
#[cfg(unix)]
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

use clasp_core::mcp::tools::{
    GetCommandHistoryArgs, PromptPatternArg, ReadOutputArgs, SendInputArgs, StartSessionArgs,
    TerminateArgs,
};
use clasp_core::mcp::ClaspServer;
use clasp_core::pty::MockPty;
use clasp_core::session::{new_session_id, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use std::sync::Arc;

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
            ..Default::default()
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
        ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

// Unix-only for the same reason as `terminate_kills_the_whole_process_group`:
// the proof that SIGKILL escalation ran is that the pid is gone, and SIGTERM
// immunity is a Unix signal behaviour with no Windows counterpart.
#[cfg(unix)]
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
            ..Default::default()
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
            ..Default::default()
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

// Unix-only: the second half resolves a *symlinked* cwd, which is what
// separates a canonicalising implementation from one that merely joins the
// argument onto the process cwd. `std::os::unix::fs::symlink` has no
// portable spelling — Windows needs a privileged, directory-vs-file-typed
// call — so the whole test is gated rather than split, which would change
// the Linux count without adding Windows coverage of anything that runs.
#[cfg(unix)]
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
            ..Default::default()
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
            ..Default::default()
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
fn echo_enabled_reports_echo_and_not_a_flag_that_moves_with_it() {
    // The sibling above cannot tell `ECHO` from `ICANON`, and cannot tell
    // `ECHO` from its own negation. Both were measured surviving the whole
    // suite.
    //
    // The cause is that `bash`'s readline toggles ECHO and ICANON together
    // across the whole raw-mode `c_lflag` group, so at every state that
    // test visits the two are perfectly correlated — and a polarity flip
    // just means `poll_echo` matches on its *first* sample instead of
    // after the transition, which no assertion distinguishes.
    //
    // `stty -echo` breaks the correlation: it clears ECHO and leaves
    // ICANON set. That is also the exact shape of a real password prompt
    // (getpass, `read -s`), the one state §8.2 exists to detect and the one
    // the ladder consumes as `echo == Some(false)`, so an ICANON reader
    // would report `Some(true)` there — inverted for the consumer.
    //
    // Sampling a *window* rather than polling until a match is what makes
    // this hold: a poll-until-`Some(false)` finds the transient at the
    // readline prompt, before the command has run at all, and lets the
    // ICANON reader through.
    let pty = InProcessPty::spawn(&bash()).expect("spawn");

    // The marker is printed *after* stty has taken effect, so reading it
    // proves the window below starts inside the `stty -echo` region rather
    // than in the canonical mode bash restores to run the line.
    pty.write(b"stty -echo; echo STTY''_DONE; sleep 3\n")
        .unwrap();
    let out = read_until(&pty, "STTY_DONE", Duration::from_secs(5));
    assert!(out.contains("STTY_DONE"), "stty never ran: {out:?}");

    let mut samples = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        samples.push(pty.echo_enabled());
        std::thread::sleep(Duration::from_millis(60));
    }
    pty.signal(Signal::Kill).unwrap();

    assert!(samples.len() >= 10, "too few samples: {}", samples.len());
    assert!(
        samples.iter().all(|s| *s == Some(false)),
        "ECHO is off for this whole window and ICANON is on; a reading of \
         Some(true) means the sample is inverted or is reading ICANON: {samples:?}"
    );
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

// ------------------------------------------------------------------
// The four `start_session` arguments 0.0.2 adds. Each one is a field
// threaded through `StartSessionArgs` -> `SessionConfig` -> the detector,
// and none of them changes anything the compiler can check: a
// `settle_threshold_ms` that never reaches `DetectionConfig`, or two
// same-typed fields swapped on the way, builds and runs exactly as
// before. So each is asserted through the tool's own response, and each
// positive is paired with the case that separates it from "the argument
// was parsed and dropped".
// ------------------------------------------------------------------

/// Poll `read_output` until the session's last logical line looks like a
/// shell prompt, then return the response's `prompt` object.
///
/// Waiting on the *detector's* last line rather than the raw buffer: the
/// scores are only meaningful once the detector has consumed the prompt.
async fn prompt_block(server: &ClaspServer, id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let r = server
            .read_output(Parameters(ReadOutputArgs {
                session: id.into(),
                tail_bytes: Some(4096),
                ..Default::default()
            }))
            .await
            .expect("read_output must not be a protocol error");
        let prompt = body(&r)["data"]["prompt"].clone();
        let line = prompt["last_line"].as_str().unwrap_or("");
        if line.ends_with("$ ") || line.ends_with("# ") {
            return prompt;
        }
        // Assert rather than return the last block seen. Returning quietly
        // is the shape `wait_for_at_prompt` was hardened out of: every
        // caller's assertion still fails, but it fails describing a
        // confidence or a tier, with nothing saying the session never
        // reached a prompt at all.
        assert!(
            Instant::now() < deadline,
            "session never reached a shell prompt; last block: {prompt}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn start_session_rejects_a_bad_prompt_pattern() {
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            prompt_patterns: Some(vec![PromptPatternArg {
                regex: "(unclosed".into(),
                score: 0.9,
            }]),
            ..Default::default()
        }))
        .await;

    // A bad regex is the caller's mistake, so it takes the protocol
    // channel (§5.1) rather than becoming an envelope status.
    let err = r.expect_err("an uncompilable regex must be rejected");
    assert!(
        err.message.contains("unclosed"),
        "the error should name the offending pattern: {err:?}"
    );
    // The detection config is built *before* the spawn precisely so this
    // holds: a rejected regex leaves nothing registered to clean up.
    assert_eq!(
        server.registry.live_count(),
        0,
        "a rejected start_session registered a session anyway"
    );

    // The same path with a pattern the size of a small file. `regex` is
    // caller-controlled, and the rejection is what carries it back into
    // the MCP transcript, where it stays: unbounded this answered with a
    // 200,044-byte `invalid_params` message.
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            prompt_patterns: Some(vec![PromptPatternArg {
                regex: "(".repeat(200_000),
                score: 0.9,
            }]),
            ..Default::default()
        }))
        .await;
    let err = r.expect_err("an uncompilable regex must be rejected");
    assert!(
        err.message.chars().count() < 400,
        "{} chars reached the transcript",
        err.message.chars().count()
    );

    // And a set larger than the cap, which is rejected on count before
    // anything is compiled at all.
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            prompt_patterns: Some(
                (0..500)
                    .map(|i| PromptPatternArg {
                        regex: format!(r"p{i}>\s*$"),
                        score: 0.5,
                    })
                    .collect(),
            ),
            ..Default::default()
        }))
        .await;
    r.expect_err("an unbounded pattern set must be rejected");
    assert_eq!(server.registry.live_count(), 0);

    // The separator: the same call with a *valid* pattern must succeed,
    // or the assertion above would pass for a `start_session` that
    // rejected everything.
    let ok = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            prompt_patterns: Some(vec![PromptPatternArg {
                regex: "(closed)".into(),
                score: 0.9,
            }]),
            ..Default::default()
        }))
        .await
        .expect("a valid pattern must be accepted");
    assert_eq!(body(&ok)["status"], "ok");

    kill_all(&server).await;
}

#[tokio::test]
async fn start_session_honours_prompt_patterns_and_replace() {
    // One extra pattern, `$`, which matches every line, scored 0.42.
    // With `replace: true` the bundled table is gone and 0.42 is the only
    // score available. With `replace: false` the bundled `\$\s*$` row
    // (0.6) is still there and scoring takes the maximum, so the answer
    // is 0.6. Neither number is reachable the other way, so this fails if
    // `prompt_patterns` is dropped (0.6 twice), if `replace` is ignored
    // (one value twice), or if the two are wired to each other's field.
    for (replace, expected) in [(true, 0.42), (false, 0.6)] {
        let server = ClaspServer::new();
        let started = server
            .start_session(Parameters(StartSessionArgs {
                command: "bash".into(),
                args: bash_args(),
                prompt_patterns: Some(vec![PromptPatternArg {
                    regex: "$".into(),
                    score: 0.42,
                }]),
                prompt_patterns_replace: Some(replace),
                ..Default::default()
            }))
            .await
            .expect("start_session");
        let id = body(&started)["data"]["session_id"]
            .as_str()
            .unwrap()
            .to_string();

        let prompt = prompt_block(&server, &id).await;
        assert_eq!(
            prompt["pattern_score"], expected,
            "replace={replace} should score {expected}; got {prompt}"
        );

        kill_all(&server).await;
    }
}

#[tokio::test]
async fn start_session_honours_settle_threshold_ms() {
    // Quiescence is `idle / threshold`, clamped. An hour-long threshold
    // cannot saturate inside a test, and the 250 ms default cannot fail
    // to. Asserting only the default would pass with the argument parsed
    // and thrown away, since the default is what it would fall back to.
    let server = ClaspServer::new();
    let slow = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            settle_threshold_ms: Some(3_600_000),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    let slow = body(&slow)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let fast = start_bash(&server).await;

    prompt_block(&server, &slow).await;
    prompt_block(&server, &fast).await;
    // Longer than the 250 ms default and a rounding error away from
    // 3_600_000 ms.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let slow_q = prompt_block(&server, &slow).await["quiescent_score"].clone();
    let fast_q = prompt_block(&server, &fast).await["quiescent_score"].clone();
    assert_eq!(
        fast_q, 1.0,
        "the default 250 ms threshold must saturate after 600 ms of silence"
    );
    assert!(
        slow_q.as_f64().is_some_and(|q| q < 0.05),
        "an hour-long threshold must leave the session unsettled; got {slow_q}"
    );

    kill_all(&server).await;
}

#[tokio::test]
async fn start_session_reports_and_can_disable_shell_integration() {
    let server = ClaspServer::new();

    let on = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    assert_eq!(
        body(&on)["data"]["shell_integration"],
        "bash",
        "an interactive bash session is integrated by default (§8.5)"
    );

    let off = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            shell_integration: Some(false),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    let data = body(&off)["data"].clone();
    // Present and null, not absent: indexing a missing key also yields
    // `Null`, so the key check is what makes the assertion mean anything
    // — and `outputSchema` declares the field either way.
    assert!(
        data.as_object().unwrap().contains_key("shell_integration"),
        "the field is reported on every start, null when nothing was injected"
    );
    assert_eq!(data["shell_integration"], Value::Null);

    kill_all(&server).await;
}

// ------------------------------------------------------------------
// 0.0.2: get_command_history's window arguments.
//
// `since_index` and `limit` are both numeric options handed to
// `command_history(since_index, limit)` positionally, which is the
// transposition hazard in its purest form: swapped, the tool still
// compiles, still returns entries, and still answers `ok`. The schema
// tests validate the *shape* of the response and cannot see it. So each
// window below is chosen so that no two of them — and no transposition of
// them — produce the same answer.
// ------------------------------------------------------------------

/// A registry-resident mock session that has already recorded `n` OSC 133
/// commands, `cmd0`..`cmd{n-1}`, in a ring of `max_entries`.
async fn history_session(server: &ClaspServer, n: usize, max_entries: usize) -> String {
    let mut bytes = Vec::new();
    for i in 0..n {
        bytes.extend_from_slice(b"\x1b]133;B\x07cmd");
        bytes.extend_from_slice(i.to_string().as_bytes());
        bytes.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
    }
    let pty = Arc::new(MockPty::new());
    pty.queue_output(&bytes);
    let session = Session::new(
        new_session_id(),
        None,
        "mock".into(),
        vec![],
        Arc::clone(&pty) as Arc<dyn clasp_core::pty::PtyBackend>,
        SessionConfig {
            history_max_entries: max_entries,
            ..SessionConfig::default()
        },
    );
    let id = session.id.clone();
    server
        .registry
        .insert(Arc::clone(&session))
        .expect("registry insert");

    let deadline = Instant::now() + Duration::from_secs(20);
    while session.command_count() < n as u64 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        session.command_count(),
        n as u64,
        "the reader never folded all {n} commands into the history"
    );
    id
}

/// `get_command_history`'s entry indices for one window.
async fn history_indices(
    server: &ClaspServer,
    id: &str,
    since_index: Option<u64>,
    limit: Option<usize>,
) -> (Vec<u64>, Value) {
    let r = server
        .get_command_history(Parameters(GetCommandHistoryArgs {
            session: id.into(),
            limit,
            since_index,
        }))
        .await
        .expect("get_command_history must not be a protocol error");
    let payload = body(&r);
    assert_eq!(payload["status"], "ok", "{payload}");
    let indices = payload["data"]["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["index"].as_u64().expect("index"))
        .collect();
    (indices, payload)
}

#[tokio::test]
async fn get_command_history_limit_and_since_index_select_different_windows() {
    let server = ClaspServer::new();
    let id = history_session(&server, 5, 100).await;

    // Neither argument: every entry, and `total` agrees with the count.
    let (all, payload) = history_indices(&server, &id, None, None).await;
    assert_eq!(all, vec![0, 1, 2, 3, 4]);
    assert_eq!(payload["data"]["total"], 5);
    // Nothing was evicted from a ring of a hundred. The positive half is
    // `get_command_history_reports_a_truncated_ring` below; a flag stuck
    // on tells the agent every history it will ever read has holes.
    assert_eq!(payload["data"]["truncated_at_tail"], false);

    // `since_index` alone keeps the *oldest* boundary; `limit` alone keeps
    // the *newest* entries. The two windows differ, so a tool that wired
    // one argument to the other's slot answers one of them wrongly.
    let (since_only, _) = history_indices(&server, &id, Some(1), None).await;
    assert_eq!(since_only, vec![1, 2, 3, 4], "since_index was ignored");
    let (limit_only, _) = history_indices(&server, &id, None, Some(2)).await;
    assert_eq!(
        limit_only,
        vec![3, 4],
        "limit kept the oldest, not the newest"
    );

    // Both at once, chosen so a transposition is visible: `(since=1,
    // limit=2)` is [3, 4]; the swapped call `(since=2, limit=1)` is [4].
    let (window, payload) = history_indices(&server, &id, Some(1), Some(2)).await;
    assert_eq!(window, vec![3, 4], "since_index and limit are transposed");
    // `total` is every command ever recorded, not the size of the window.
    // Deriving it from `entries.len()` would report 2 here.
    assert_eq!(payload["data"]["total"], 5);

    // A window past the end is empty rather than an error: the agent polls
    // `since_index: total` to ask "anything new?".
    let (empty, payload) = history_indices(&server, &id, Some(5), None).await;
    assert!(empty.is_empty(), "{payload}");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["data"]["total"], 5);
}

#[tokio::test]
async fn get_command_history_reports_a_truncated_ring() {
    // Five commands into a ring of three. Three survive, not one: at a cap
    // of two an implementation that *cleared* the ring on overflow would
    // land on the same answer as one that evicts a single entry, and
    // nothing here could tell them apart.
    let server = ClaspServer::new();
    let id = history_session(&server, 5, 3).await;

    let (indices, payload) = history_indices(&server, &id, None, None).await;
    assert_eq!(indices, vec![2, 3, 4], "the ring dropped the wrong entries");
    assert_eq!(payload["data"]["truncated_at_tail"], true);
    // `total` counts evicted commands too, which is how the agent knows
    // its `since_index` cursor skipped some.
    assert_eq!(payload["data"]["total"], 5);
}

#[tokio::test]
async fn get_command_history_bounds_its_response_at_the_ring_default() {
    // `limit` is clamped to `DEFAULT_MAX_ENTRIES`, so no caller can ask
    // for an unbounded response. That clamp is invisible with a stock
    // session — the ring holds at most `DEFAULT_MAX_ENTRIES` anyway, so
    // the cap is never the binding constraint — which is exactly why it
    // has to be exercised against a ring that is deliberately larger.
    // Delete the `.min(...)` and this returns 1002 entries.
    let server = ClaspServer::new();
    let n = clasp_core::detect::DEFAULT_MAX_ENTRIES + 2;
    let id = history_session(&server, n, n).await;

    // The documented default, which is only observable here for the same
    // reason: with five commands in the ring, "50" and "no limit at all"
    // are the same answer. `limit: 50` is what the tool's input schema
    // promises, so an implementation that defaulted to the ring size would
    // return 1000 entries to a caller that asked for nothing.
    let (defaulted, _) = history_indices(&server, &id, None, None).await;
    assert_eq!(defaulted.len(), 50, "`limit` does not default to 50");
    assert_eq!(
        *defaulted.last().expect("entries"),
        n as u64 - 1,
        "the default window kept the oldest 50 rather than the newest"
    );

    let (indices, payload) = history_indices(&server, &id, None, Some(usize::MAX)).await;
    assert_eq!(
        indices.len(),
        clasp_core::detect::DEFAULT_MAX_ENTRIES,
        "an unbounded `limit` was honoured literally"
    );
    // The newest are kept, so the clamp is a cap and not a truncation of
    // the head of the window.
    assert_eq!(*indices.last().expect("entries"), n as u64 - 1);
    assert_eq!(payload["data"]["total"], n as u64);
    // Nothing was evicted: the ring was sized to hold everything, so the
    // shortfall above is the response cap and not the ring's.
    assert_eq!(payload["data"]["truncated_at_tail"], false);
}
