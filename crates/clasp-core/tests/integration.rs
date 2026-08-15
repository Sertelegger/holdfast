use clasp_core::pty::{InProcessPty, LineDiscipline, PtyBackend, PtySpawnConfig, Signal};
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
    StatusArgs, TerminateArgs, WaitForPatternArgs,
};
use clasp_core::mcp::ClaspServer;
use clasp_core::pty::MockPty;
use clasp_core::session::{new_session_id, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::{json, Value};
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
                ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(
        body(&again)["data"]["bytes_returned"],
        0,
        "reading from the settled head must return nothing; a cursor that \
         regressed would re-deliver already-seen bytes"
    );

    // The negative that separates the cap above from the degenerate case:
    // a tail that *fits* must not claim one. `tail_lines` was the last
    // selector where "claims a cap that never happened" went unguarded —
    // `capped = len > max_bytes` mutated to `>=` left the whole suite
    // green and produced `truncated_for_size: true` beside
    // `next_cursor: null`, the "there is more, and there is nothing more"
    // contradiction already fixed twice on `tail_bytes` and once on the
    // cursor branch. The other two selectors are pinned in both
    // directions; this one only had its positive.
    //
    // `max_bytes` is set to exactly what the read returns, which is the
    // only value that tells `>` and `>=` apart. It is measured with a
    // probe rather than assumed, because the line width is the child's to
    // choose — and it is measured *after* the child is dead and the
    // buffer settled, so the two reads see the same bytes.
    let probe = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: None,
            tail_lines: Some(3),
            tail_bytes: None,
            max_bytes: Some(65536),
            ..Default::default()
        }))
        .await
        .unwrap();
    let exact = body(&probe)["data"]["bytes_returned"]
        .as_u64()
        .expect("bytes_returned must be present") as usize;
    assert!(exact > 0 && exact < 65536, "probe read {exact} bytes");

    let fits = server
        .read_output(Parameters(ReadOutputArgs {
            session: id.clone(),
            since_cursor: None,
            tail_lines: Some(3),
            tail_bytes: None,
            max_bytes: Some(exact),
            ..Default::default()
        }))
        .await
        .unwrap();
    let b = body(&fits);
    assert_eq!(
        b["data"]["bytes_returned"], exact,
        "a tail that fits must come back whole"
    );
    assert_eq!(
        b["data"]["truncated_for_size"], false,
        "a read that dropped nothing reported a cap: {b}"
    );
    assert!(
        b["data"]["next_cursor"].is_null(),
        "`truncated_for_size` beside a null `next_cursor` tells the agent \
         there is more and that there is nothing more: {b}"
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
                    ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

/// Poll `line_discipline` until its `echo` field reports `want` or the
/// deadline passes, then return whatever the whole pair last said.
///
/// The poll is on `.echo` alone and the answer is the pair, deliberately:
/// `ECHO` is the flag whose transitions the shell drives on a schedule
/// this test can wait for, and `ICANON` is what the caller then asserts
/// *at* that moment. Polling on the pair would let a caller wait for the
/// answer it wanted rather than read what was there.
fn poll_line_discipline(
    pty: &dyn PtyBackend,
    want: Option<bool>,
    timeout: Duration,
) -> LineDiscipline {
    let deadline = Instant::now() + timeout;
    let mut last = pty.line_discipline();
    while last.echo != want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(60));
        last = pty.line_discipline();
    }
    last
}

#[test]
fn line_discipline_tracks_the_slaves_line_discipline() {
    // Spike row 2, measured: readline turns ECHO *off* while it draws a
    // prompt, and the line discipline is back on while a command runs.
    // A backend returning a constant — or `UNKNOWN` — fails one half or
    // the other, so both assertions are needed to pin the behaviour.
    let pty = InProcessPty::spawn(&bash()).expect("spawn");

    assert_eq!(
        poll_line_discipline(&pty, Some(false), Duration::from_secs(5)),
        LineDiscipline {
            echo: Some(false),
            canonical: Some(false),
        },
        "at a readline prompt both flags are off — §8.2 row 1, which is \
         exactly why `ECHO` alone cannot mean `AwaitingSecret`"
    );

    pty.write(b"sleep 3\n").unwrap();
    assert_eq!(
        poll_line_discipline(&pty, Some(true), Duration::from_secs(5)),
        LineDiscipline {
            echo: Some(true),
            canonical: Some(true),
        },
        "while a command runs the shell restores both flags"
    );

    pty.signal(Signal::Kill).unwrap();
}

#[test]
fn line_discipline_reports_echo_and_canonical_as_separate_flags() {
    // The sibling above visits only states in which the two flags move
    // together, so on its own it cannot tell `ECHO` from `ICANON`, nor
    // `ECHO` from its own negation. Both were measured surviving the whole
    // suite.
    //
    // The cause is that `bash`'s readline toggles ECHO and ICANON together
    // across the whole raw-mode `c_lflag` group, so at every state that
    // test visits the two are perfectly correlated — and a polarity flip
    // just means `poll_line_discipline` matches on its *first* sample
    // instead of after the transition, which no assertion distinguishes.
    //
    // `stty -echo` breaks the correlation: it clears ECHO and leaves
    // ICANON set. That is also the exact shape of a real password prompt
    // (getpass, `read -s`), the one state §8.2 exists to detect and the one
    // the ladder consumes as `echo == Some(false) && canonical != Some(false)`.
    //
    // Sampling a *window* rather than polling until a match is what makes
    // this hold: a poll-until-`Some(false)` finds the transient at the
    // readline prompt, before the command has run at all, and lets a
    // reader that returns `ICANON` in the `echo` field through.
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
        samples.push(pty.line_discipline());
        std::thread::sleep(Duration::from_millis(60));
    }
    pty.signal(Signal::Kill).unwrap();

    assert!(samples.len() >= 10, "too few samples: {}", samples.len());
    assert!(
        samples.iter().all(|s| *s
            == LineDiscipline {
                echo: Some(false),
                canonical: Some(true),
            }),
        "ECHO is off for this whole window and ICANON is on; anything else \
         means the sample is inverted, or the two flags are one bit read \
         twice: {samples:?}"
    );
}

#[test]
fn line_discipline_separates_a_line_editor_from_a_secret_prompt() {
    // §8.2's table, the two rows that matter, on one PTY. `stty -echo
    // -icanon` is a line editor's shape and `stty -echo` is a secret
    // prompt's; they differ in exactly one bit and §8.3's rung is about to
    // start reading it. A backend that reads only ECHO answers
    // `Some(false)` for both, and both halves are needed to see that: the
    // first alone passes for a reader returning a constant `Some(false)`,
    // the second alone for one returning `Some(true)`.
    let pty = InProcessPty::spawn(&bash()).expect("spawn");
    pty.write(b"stty -echo -icanon; echo EDITOR''_SET; sleep 3\n")
        .unwrap();
    let out = read_until(&pty, "EDITOR_SET", Duration::from_secs(5));
    assert!(out.contains("EDITOR_SET"), "stty never ran: {out:?}");
    assert_eq!(
        pty.line_discipline(),
        LineDiscipline {
            echo: Some(false),
            canonical: Some(false),
        },
        "a line editor: echo off, canonical off"
    );
    pty.signal(Signal::Kill).unwrap();

    let pty = InProcessPty::spawn(&bash()).expect("spawn");
    pty.write(b"stty -echo; echo SECRET''_SET; sleep 3\n")
        .unwrap();
    let out = read_until(&pty, "SECRET_SET", Duration::from_secs(5));
    assert!(out.contains("SECRET_SET"), "stty never ran: {out:?}");
    assert_eq!(
        pty.line_discipline(),
        LineDiscipline {
            echo: Some(false),
            canonical: Some(true),
        },
        "a secret prompt: echo off, canonical ON"
    );
    pty.signal(Signal::Kill).unwrap();
}

/// Poll `foreground_group` until `pred` holds, then return the last value.
fn poll_foreground(
    pty: &dyn PtyBackend,
    mut pred: impl FnMut(Option<i32>) -> bool,
    timeout: Duration,
) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    let mut last = pty.foreground_group();
    while !pred(last) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(30));
        last = pty.foreground_group();
    }
    last
}

#[test]
fn the_foreground_group_changes_for_an_external_command_and_not_for_a_builtin() {
    // §8.3's discriminator, measured rather than assumed. Both halves are
    // needed: the first alone passes for an accessor returning the child's
    // pid plus one, and the second alone for one returning a constant.
    let pty = InProcessPty::spawn(&bash()).expect("spawn");
    let at_prompt = poll_foreground(&pty, |g| g.is_some(), Duration::from_secs(5));
    assert!(at_prompt.is_some(), "the shell never took the terminal");
    pty.write(b"sleep 3\n").unwrap();
    let running = poll_foreground(&pty, |g| g != at_prompt, Duration::from_secs(5));
    assert_ne!(
        running, at_prompt,
        "an external command must get its own group"
    );
    assert!(
        running.is_some_and(|g| g > 0),
        "and a real one: {running:?}"
    );
    pty.signal(Signal::Kill).unwrap();

    // A builtin keeps the shell's group, which is why §8.7 row 8's known
    // false negative is untouched by scoping: the shell really is the
    // program at the terminal, and the rung's premise really does hold.
    let pty = InProcessPty::spawn(&bash()).expect("spawn");
    let at_prompt = poll_foreground(&pty, |g| g.is_some(), Duration::from_secs(5));
    assert!(at_prompt.is_some(), "the shell never took the terminal");
    pty.write(b"read -s -n 1 -p 'Key: ' k\n").unwrap();
    let out = read_until(&pty, "Key: ", Duration::from_secs(5));
    assert!(out.contains("Key: "), "read never prompted: {out:?}");
    assert_eq!(
        pty.foreground_group(),
        at_prompt,
        "a builtin keeps the shell's group"
    );
    pty.signal(Signal::Kill).unwrap();
}

#[test]
fn line_discipline_is_unknown_once_the_child_has_exited() {
    let mut cfg = PtySpawnConfig::new("bash");
    cfg.args = vec!["-c".into(), "exit 0".into()];
    let pty = InProcessPty::spawn(&cfg).expect("spawn");
    wait_for_exit(&pty, Duration::from_secs(5));
    assert!(!pty.is_alive());
    assert_eq!(
        pty.line_discipline(),
        LineDiscipline::UNKNOWN,
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

// ------------------------------------------------- §9.4 `session_start`
//
// REQ-SEC-006's Tier-2 row (§11.2 "`start_session.env` audit log"). The
// three tests below are one requirement in three parts: the entry exists
// and names the keys, the *values* are absent for a value no rule could
// have masked, and the field list is §9.4's.

/// A server writing its audit trail into a temporary directory, plus the
/// path to read it back from. Never the real `~/.clasp/logs/audit.log`.
fn server_with_audit(dir: &std::path::Path) -> (ClaspServer, std::path::PathBuf) {
    let path = dir.join("audit.log");
    (
        ClaspServer::with_audit_path(Some(path.clone())),
        path.clone(),
    )
}

/// Every `session_start` line in the trail, parsed.
fn audit_entries(path: &std::path::Path, kind: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(path).expect("the audit log must exist");
    text.lines()
        .map(|l| serde_json::from_str::<Value>(l).expect("each line is one JSON object"))
        .filter(|e| e["kind"] == kind)
        .collect()
}

/// Start a session carrying `env`, run `printenv` over its keys, then
/// terminate it — so the value has been through the child, the buffer and
/// a tool response before the log is inspected.
async fn env_session_lifecycle(
    server: &ClaspServer,
    env: &[(&str, &str)],
) -> (String, std::string::String) {
    let map: std::collections::HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            env: Some(map),
            ..Default::default()
        }))
        .await
        .unwrap();
    let id = body(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let session = server.registry.get(&id).unwrap();
    let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
    session
        .write_input(format!("printenv {}\n", names.join(" ")).as_bytes())
        .unwrap();
    // Wait for the *last* value to appear, so every one of them has been
    // through the PTY before the log is read.
    let seen = wait_for_buffer(&session, env.last().expect("at least one var").1);

    let _ = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await;
    (id, seen)
}

/// REQ-SEC-006, the secret-shaped half. `env_keys` names the key; the
/// value is nowhere in the trail.
#[tokio::test]
async fn session_start_logs_env_keys_and_never_env_values() {
    let dir = tempfile::tempdir().unwrap();
    let (server, log_path) = server_with_audit(dir.path());
    const API_KEY: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
    const OTHER: &str = "sk-ant-api03-ZZZZYYYYXXXXWWWWVVVVUUUUTTTT";

    // Two keys, handed in reverse alphabetical order, so the assertion
    // below is about the key *set and order* rather than about one name.
    let (id, seen) =
        env_session_lifecycle(&server, &[("ZZ_OTHER", OTHER), ("API_KEY", API_KEY)]).await;

    // The check is only worth anything if the values really existed: a
    // spawn that silently dropped `env` would make the absence assertions
    // below pass for the wrong reason.
    assert!(
        seen.contains(API_KEY) && seen.contains(OTHER),
        "env never reached the child, so the absence checks prove nothing: {seen:?}"
    );

    let entries = audit_entries(&log_path, "session_start");
    assert_eq!(entries.len(), 1, "one spawn, one entry");
    assert_eq!(entries[0]["session_id"], id.as_str());
    assert_eq!(
        entries[0]["env_keys"],
        json!(["API_KEY", "ZZ_OTHER"]),
        "env_keys is the sorted key set"
    );

    let raw = std::fs::read_to_string(&log_path).unwrap();
    for value in [API_KEY, OTHER] {
        assert!(
            !raw.contains(value),
            "an env value reached the audit log: {raw}"
        );
    }
}

/// The pairing, and the one that matters. `correct horse battery staple`
/// matches **no** redaction rule, so a `session_start` that serialised the
/// whole `env` map and leaned on the redactor passes the test above and
/// fails this one. §9.2's row is keys-only, which is a structural
/// guarantee rather than a redaction outcome.
#[tokio::test]
async fn an_env_value_that_matches_no_rule_is_still_absent() {
    let dir = tempfile::tempdir().unwrap();
    let (server, log_path) = server_with_audit(dir.path());
    const PASSPHRASE: &str = "correct horse battery staple";

    // The premise, asserted rather than assumed: if some rule *did* match
    // this value, the test would be a second copy of the one above.
    let rules = clasp_core::output::rules::builtin_shared();
    assert_eq!(
        clasp_core::output::redact::redact_str(&rules, PASSPHRASE),
        PASSPHRASE,
        "the separator only separates while no rule matches this value"
    );

    let (id, seen) = env_session_lifecycle(&server, &[("DB_PASSWORD", PASSPHRASE)]).await;
    assert!(
        seen.contains(PASSPHRASE),
        "env never reached the child: {seen:?}"
    );

    let entries = audit_entries(&log_path, "session_start");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["session_id"], id.as_str());
    assert_eq!(entries[0]["env_keys"], json!(["DB_PASSWORD"]));

    let raw = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !raw.contains(PASSPHRASE),
        "the env map was logged and merely redacted: {raw}"
    );
}

/// §9.4's field list for `session_start`, pinned as an exact key set so a
/// field quietly added or dropped later reads red — plus the three common
/// fields every entry carries.
#[tokio::test]
async fn session_start_records_the_field_set_9_4_names() {
    let dir = tempfile::tempdir().unwrap();
    let (server, log_path) = server_with_audit(dir.path());
    let cwd = std::env::temp_dir().canonicalize().unwrap();

    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            cwd: Some(cwd.to_string_lossy().into_owned()),
            ..Default::default()
        }))
        .await
        .unwrap();
    let id = body(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let entries = audit_entries(&log_path, "session_start");
    assert_eq!(entries.len(), 1);
    let mut got: Vec<&str> = entries[0]
        .as_object()
        .expect("each entry is an object")
        .keys()
        .map(String::as_str)
        .collect();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![
            "args",
            "command",
            "cwd",
            "env_keys",
            "idle_timeout_secs",
            "kind",
            "pid",
            "redaction_enabled",
            "session_id",
            "ts",
        ],
        "§9.4's `session_start` row plus the three fields every entry carries"
    );

    // Values, not just names: a record that reported another session's
    // command, or a constant, would pass the key-set assertion alone.
    assert_eq!(entries[0]["command"], "bash");
    assert_eq!(entries[0]["args"], json!(["--norc", "--noprofile"]));
    assert_eq!(
        entries[0]["cwd"],
        cwd.to_string_lossy().as_ref(),
        "the *canonical* cwd the child was spawned in"
    );
    assert_eq!(entries[0]["env_keys"], json!([]));
    assert_eq!(entries[0]["redaction_enabled"], true);
    assert_eq!(
        entries[0]["idle_timeout_secs"],
        Value::Null,
        "no milestone has built idle reaping yet; a number here would be a \
         promise nothing keeps"
    );
    assert_eq!(
        entries[0]["pid"],
        json!(server.registry.get(&id).unwrap().pid()),
        "the entry names the child that was actually spawned"
    );

    kill_all(&server).await;
}

// --------------------------------------------------------------- 0.0.3
// Output processing against a real PTY: redaction, ANSI stripping, and
// the text_encoding matrix.

// These four `use` lines are the WHOLE import addition. `new_session_id`,
// `Session`, `SessionConfig`, `Arc`, `InProcessPty`, `PtyBackend`,
// `Signal`, `Duration`, `Instant`, `bash()` and `body()` are all already
// in scope at the top of this file (0.0.1 and 0.0.2 imported them);
// re-importing any of them is `error[E0252]`.
use clasp_core::audit::AuditLog;
use clasp_core::output::rules::RuleSet;
use clasp_core::output::{
    ansi::AnsiMode, encoding::TextEncoding, OutputProcessor, ProcessedRead, ProcessingLimits,
    ReadOptions, ReadRequest, ReadStart,
};

/// A 40-character GitHub token, assembled at runtime. It is never typed
/// into the shell as one string, so the PTY's echo of the command line
/// cannot satisfy any assertion below — only the child's own output can.
const TOKEN_TAIL: &str = "0123456789abcdefghijABCDEFGHIJ012345";

fn shell_session() -> Arc<Session> {
    let pty = InProcessPty::spawn(&bash()).expect("spawn bash");
    Session::new(
        new_session_id(),
        None,
        "bash".into(),
        vec![],
        Arc::new(pty) as Arc<dyn PtyBackend>,
        SessionConfig::with_buffer_capacity(1024 * 1024),
    )
}

/// Poll the processed read path until `needle` shows up.
///
/// `needle` must be something the echoed command line cannot contain.
fn read_until_processed(
    session: &Session,
    processor: &OutputProcessor,
    needle: &str,
    timeout: Duration,
) -> ProcessedRead {
    let deadline = Instant::now() + timeout;
    loop {
        let read = session.read_processed(&ReadRequest::since(0, 64 * 1024), processor);
        if read.output.contains(needle) {
            return read;
        }
        assert!(
            Instant::now() < deadline,
            "never saw {needle:?} in the processed output; got: {:?}",
            read.output
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn a_secret_a_real_shell_printed_is_redacted_in_place() {
    let session = shell_session();
    let processor = OutputProcessor::builtin().unwrap();
    // The `''` splits the marker so the echo reads `CLASP''_TOKEN=`, and
    // the two printf arguments keep `ghp_` and its 36 characters apart on
    // the command line. Only executing this can produce either needle.
    session
        .write_input(format!("printf 'CLASP''_TOKEN=%s%s\\n' ghp_ {TOKEN_TAIL}\n").as_bytes())
        .unwrap();

    let read = read_until_processed(
        &session,
        &processor,
        "CLASP_TOKEN=",
        Duration::from_secs(10),
    );

    let full_token = format!("ghp_{TOKEN_TAIL}");
    assert!(
        !read.output.contains(&full_token),
        "the token reached the agent: {:?}",
        read.output
    );
    // The absence check above would also pass against a read that
    // returned nothing, so require the redacted line itself.
    assert!(
        read.output.contains("CLASP_TOKEN=[REDACTED:github]"),
        "expected the line to survive with a marker; got: {:?}",
        read.output
    );
    assert_eq!(read.redactions.get("github"), Some(&1));
    assert!(!read.held_back, "the token completed before the newline");

    let _ = session.signal(Signal::Kill);
}

#[test]
fn ansi_from_a_real_shell_is_stripped_but_the_text_survives() {
    let session = shell_session();
    let processor = OutputProcessor::builtin().unwrap();
    session
        .write_input(b"printf '\\033[32mCLASP''_GREEN\\033[0m\\n'\n")
        .unwrap();

    let read = read_until_processed(&session, &processor, "CLASP_GREEN", Duration::from_secs(10));
    assert!(
        !read.output.contains('\u{1b}'),
        "an escape byte reached the agent: {:?}",
        read.output
    );
    // `CLASP_GREEN` is only producible by running the command — the echo
    // shows `CLASP''_GREEN` — so this pair means stripping ran over real
    // escape bytes rather than over an empty buffer.
    assert!(read.output.contains("CLASP_GREEN"));

    let _ = session.signal(Signal::Kill);
}

#[test]
fn base64_without_redaction_returns_the_exact_pty_bytes() {
    use base64::Engine as _;

    let session = shell_session();
    let processor = OutputProcessor::builtin().unwrap();
    session
        .write_input(b"printf '\\033[32mCLASP''_GREEN\\033[0m\\n'\n")
        .unwrap();
    read_until_processed(&session, &processor, "CLASP_GREEN", Duration::from_secs(10));

    let read = session.read_processed(
        &ReadRequest {
            start: ReadStart::Cursor(0),
            max_bytes: 64 * 1024,
            options: ReadOptions {
                ansi: AnsiMode::Raw,
                text_encoding: TextEncoding::Base64,
                redact: false,
            },
            tool: "read_output",
            client_kind: "in_process",
        },
        &processor,
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(read.output.as_bytes())
        .expect("valid base64");
    assert_eq!(
        decoded.len(),
        read.bytes_returned,
        "base64 of raw bytes decodes back to exactly the bytes counted"
    );
    assert!(
        decoded.contains(&0x1b),
        "raw mode must preserve the escape bytes the shell emitted"
    );
    assert!(
        String::from_utf8_lossy(&decoded).contains("CLASP_GREEN"),
        "and the text the child printed"
    );

    let _ = session.signal(Signal::Kill);
}

#[test]
fn a_raw_read_of_a_real_session_is_recorded_in_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let rules = Arc::new(RuleSet::builtin().unwrap());
    let audit =
        Arc::new(AuditLog::to_path(dir.path().join("audit.log"), Arc::clone(&rules)).unwrap());
    let processor = OutputProcessor::new(rules, Arc::clone(&audit), ProcessingLimits::default());

    let session = shell_session();
    session
        .write_input(format!("printf 'CLASP''_TOKEN=%s%s\\n' ghp_ {TOKEN_TAIL}\n").as_bytes())
        .unwrap();
    read_until_processed(
        &session,
        &processor,
        "CLASP_TOKEN=",
        Duration::from_secs(10),
    );

    let raw = session.read_processed(
        &ReadRequest {
            start: ReadStart::Cursor(0),
            max_bytes: 64 * 1024,
            options: ReadOptions {
                redact: false,
                ..Default::default()
            },
            tool: "read_output",
            client_kind: "in_process",
        },
        &processor,
    );
    let full_token = format!("ghp_{TOKEN_TAIL}");
    assert!(
        raw.output.contains(&full_token),
        "the escape hatch must actually return the secret"
    );

    let log = std::fs::read_to_string(audit.path().unwrap()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(entry["kind"], "redaction_disabled");
    assert_eq!(entry["tool"], "read_output");
    // No control connection exists in this milestone, so the caller
    // really is in-process. 0.0.5 derives this from the handshake and
    // the same read through the shim records `shim` (§9.4's spelling,
    // verbatim from the handshake).
    assert_eq!(entry["client_kind"], "in_process");
    assert_eq!(entry["session_id"], session.id.as_str());
    assert!(
        !log.contains(&full_token),
        "the audit log must not carry the secret it is recording the disclosure of"
    );

    let _ = session.signal(Signal::Kill);
}

// The same guarantees through the MCP tool surface.

fn read_args(session: &str) -> ReadOutputArgs {
    // Deliberately exhaustive. It names every field, so adding
    // `..Default::default()` here is `clippy::needless_update` and fails
    // `-D warnings`. Step 4b's repair does not apply to this literal.
    ReadOutputArgs {
        session: session.to_string(),
        since_cursor: Some(0),
        tail_lines: None,
        tail_bytes: None,
        max_bytes: None,
        ansi: None,
        text_encoding: None,
        redact: None,
    }
}

async fn started_session(server: &ClaspServer) -> String {
    // `..Default::default()`, not an exhaustive literal. 0.0.2 gave
    // `StartSessionArgs` four more fields and derived `Default` for
    // exactly this reason; 0.0.4 adds `screen_tracking` and 0.0.8 adds
    // more. Naming every field here is `error[E0063]: missing fields`
    // today and a re-break every milestone after.
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec!["--norc".into(), "--noprofile".into()],
            // Explicitly OFF, and not a style choice. `start_session`
            // defaults `shell_integration` to true and injects the OSC 133
            // snippet, so every prompt writes `\x1b]133;…` into the
            // buffer. A read that lands while one of those escapes is
            // half-arrived and bash is still alive is held back by
            // REQ-O-008 — correctly — and `assert_eq!(data["held_back"],
            // false)` below then fails at random. The needle these tests
            // poll for is satisfied by the command's own output, so the
            // loop can break on exactly that read. Nothing here is
            // testing shell integration.
            shell_integration: Some(false),
            ..Default::default()
        }))
        .await
        .unwrap();
    body(&r)["data"]["session_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn read_output_redacts_by_default_and_reports_the_new_flags() {
    let server = ClaspServer::new();
    let id = started_session(&server).await;
    let session = server.registry.get(&id).unwrap();
    session
        .write_input(format!("printf 'CLASP''_TOKEN=%s%s\\n' ghp_ {TOKEN_TAIL}\n").as_bytes())
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let full_token = format!("ghp_{TOKEN_TAIL}");
    loop {
        let r = server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap();
        let data = body(&r)["data"].clone();
        let out = data["output"].as_str().unwrap().to_string();
        if out.contains("CLASP_TOKEN=") {
            assert!(
                !out.contains(&full_token),
                "the tool leaked the token: {out}"
            );
            assert!(
                out.contains("CLASP_TOKEN=[REDACTED:github]"),
                "expected the surrounding line intact: {out}"
            );
            assert_eq!(data["held_back"], false);
            assert_eq!(data["truncated_at_tail"], false);
            assert_eq!(data["redactions"]["github"], 1);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never saw the printed line: {out}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let _ = session.signal(Signal::Kill);
}

/// The `redact` **tool argument**, all three of its arms.
///
/// `redact: args.redact.unwrap_or(true)` → `redact: true` survived the
/// whole suite: `disabling_redaction_returns_the_secret_verbatim` and
/// `a_raw_read_of_a_real_session_is_recorded_in_the_audit_log` both build
/// a `ReadOptions` by hand and never travel through the tool, so nothing
/// observed the argument being read at all. Under that mutation the
/// documented escape hatch becomes a silent no-op — the agent asks for raw
/// bytes, is told nothing went wrong, and receives markers — and §4.1's
/// only route to a **withheld partial** closes for ever, which is the
/// half that matters: a token one character short of its rule's minimum
/// is unreachable by any other means, `tail_bytes` included, once the
/// bytes have scrolled past.
///
/// Three arms, because two of them are separable: absent and `true` must
/// agree (that is `unwrap_or(true)`, not `unwrap_or(false)`), and `false`
/// must differ from both (that is the argument being read at all).
#[tokio::test]
async fn read_outputs_redact_argument_is_honoured_on_every_arm() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "hatch");
    let token = format!("ghp_{TOKEN_TAIL}");
    // One character short of the rule's minimum, so no rule can match it
    // and only the holdback stands in the way.
    let partial = &token[..token.len() - 1];
    let buffer = format!("t={token}\nbuilding\n{partial}");
    pty.queue_output(buffer.as_bytes());
    wait_until_head(&server.registry.get(&id).unwrap(), buffer.len() as u64);

    let read = |redact: Option<bool>| {
        let server = &server;
        let id = id.clone();
        async move {
            body(
                &server
                    .read_output(Parameters(ReadOutputArgs {
                        session: id,
                        since_cursor: Some(0),
                        redact,
                        ..Default::default()
                    }))
                    .await
                    .expect("read_output must not be a protocol error"),
            )["data"]
                .clone()
        }
    };

    let default = read(None).await;
    assert_eq!(
        default["output"], "t=[REDACTED:github]\nbuilding\n",
        "the default redacts the completed token and withholds the partial"
    );
    assert_eq!(default["held_back"], json!(true));

    // Field by field rather than object by object: `quiescent_score`
    // climbs with wall-clock time, so two identical reads a millisecond
    // apart are not equal objects.
    let explicit = read(Some(true)).await;
    for field in ["output", "held_back", "redactions", "next_cursor"] {
        assert_eq!(
            explicit[field], default[field],
            "`redact: true` and no argument at all are the same read; \
             {field} differs"
        );
    }

    let raw = read(Some(false)).await;
    assert_eq!(
        raw["output"],
        json!(buffer),
        "the audited hatch returns the bytes verbatim — including the \
         in-flight partial, which nothing else can reach"
    );
    assert_eq!(
        raw["held_back"],
        json!(false),
        "disabling redaction disables the holdback with it (§4.1)"
    );
    assert!(raw["output"].as_str().unwrap().contains(partial));

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// `status.redaction_stats` as the agent sees it.
async fn redaction_stats(server: &ClaspServer, id: &str) -> Value {
    let r = server
        .status(Parameters(StatusArgs {
            session: id.to_string(),
        }))
        .await
        .expect("status must not be a protocol error");
    body(&r)["data"]["redaction_stats"].clone()
}

/// REQ-O-012, at the two surfaces an agent actually sees.
///
/// **The point of this test is that it must FAIL against an
/// implementation that merges the two counters or aliases one to the
/// other.** Both such implementations return a plausible map from a
/// single read, so no single-read test tells them apart: serve
/// `read_output.redactions` from the session tally and the second read
/// reports 2 == 2; alias `status.redaction_stats` to the last response
/// and it reports 1 == 1. Only two *overlapping* reads of one secret
/// separate 1 from 2, which is why `assert_ne!` is the assertion and
/// "both fields are present" is not.
///
/// The clean-session assertion in front is the paired negative: an
/// implementation that counts nothing anywhere reports `{}` and `{}` —
/// equal, so `assert_ne!` catches it — and it separately pins
/// REQ-O-012's other guard, that a session which has redacted nothing
/// reports an empty map rather than omitting the key.
#[tokio::test]
async fn the_per_response_and_per_session_redaction_counts_are_different_numbers() {
    let server = ClaspServer::new();
    let id = started_session(&server).await;
    let session = server.registry.get(&id).unwrap();

    assert_eq!(
        redaction_stats(&server, &id).await,
        serde_json::json!({}),
        "a session that has redacted nothing reports an empty map, not a \
         missing key (REQ-O-012)"
    );

    session
        .write_input(format!("printf 'CLASP''_TOKEN=%s%s\\n' ghp_ {TOKEN_TAIL}\n").as_bytes())
        .unwrap();

    // Poll on the REDACTED form, so the read that breaks the loop is
    // provably the first read that redacted the token — the tally is 1
    // at that instant, not "1 or more depending on timing".
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap();
        let out = body(&r)["data"]["output"].as_str().unwrap().to_string();
        if out.contains("CLASP_TOKEN=[REDACTED:github]") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never saw the redacted line: {out}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    // The second read OVERLAPS the first: `read_args` always reads from
    // cursor 0, so it returns the same secret and redacts it again.
    let r = server
        .read_output(Parameters(read_args(&id)))
        .await
        .unwrap();
    let per_response = body(&r)["data"]["redactions"]["github"].clone();
    let per_session = redaction_stats(&server, &id).await["github"].clone();

    assert_eq!(
        per_response, 1,
        "`redactions` counts substitutions in the bytes THIS response \
         returned: {per_response}"
    );
    assert_eq!(
        per_session, 2,
        "`redaction_stats` is cumulative for the session and double-counts \
         the overlap on purpose: {per_session}"
    );
    assert_ne!(
        per_response, per_session,
        "the two surfaces must report different numbers after two \
         overlapping reads; equal means one is being served from the other"
    );

    let _ = session.signal(Signal::Kill);
}

#[tokio::test]
async fn read_output_rejects_an_unknown_text_encoding_as_a_protocol_error() {
    let server = ClaspServer::new();
    let id = started_session(&server).await;

    let mut args = read_args(&id);
    args.text_encoding = Some("rot13".into());
    let err = server
        .read_output(Parameters(args))
        .await
        .expect_err("an unknown encoding is an input-schema violation (§5.1)");
    assert!(
        err.message.contains("text_encoding"),
        "the message must name the offending argument: {}",
        err.message
    );

    let mut args = read_args(&id);
    args.ansi = Some("sideways".into());
    let err = server
        .read_output(Parameters(args))
        .await
        .expect_err("ditto");
    assert!(err.message.contains("ansi"), "{}", err.message);

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// The paired negative for the row above: the three *legal* enum values
/// are accepted and each does what it says. Without it, a `read_output`
/// that rejected every `ansi`/`text_encoding` value it was given would
/// pass the rejection test completely.
#[tokio::test]
async fn the_advertised_enum_values_are_all_accepted() {
    use base64::Engine as _;

    let server = ClaspServer::new();
    let id = started_session(&server).await;
    let session = server.registry.get(&id).unwrap();
    session
        .write_input(b"printf '\\033[32mCLASP''_GREEN\\033[0m\\n'\n")
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap();
        if body(&r)["data"]["output"]
            .as_str()
            .unwrap()
            .contains("CLASP_GREEN")
        {
            break;
        }
        assert!(Instant::now() < deadline, "the shell never printed");
        std::thread::sleep(Duration::from_millis(25));
    }

    let mut raw = read_args(&id);
    raw.ansi = Some("raw".into());
    let out = body(&server.read_output(Parameters(raw)).await.unwrap())["data"]["output"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(out.contains('\u{1b}'), "ansi=raw must keep the escapes");

    let mut stripped = read_args(&id);
    stripped.ansi = Some("strip".into());
    let out = body(&server.read_output(Parameters(stripped)).await.unwrap())["data"]["output"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!out.contains('\u{1b}'), "ansi=strip must remove them");

    let mut b64 = read_args(&id);
    b64.text_encoding = Some("base64".into());
    let out = body(&server.read_output(Parameters(b64)).await.unwrap())["data"]["output"]
        .as_str()
        .unwrap()
        .to_string();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(out.as_bytes())
        .expect("text_encoding=base64 must produce base64");
    assert!(String::from_utf8_lossy(&decoded).contains("CLASP_GREEN"));

    let mut lossy = read_args(&id);
    lossy.text_encoding = Some("lossy_printable".into());
    let out = body(&server.read_output(Parameters(lossy)).await.unwrap())["data"]["output"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(out.contains("CLASP_GREEN"));

    let _ = session.signal(Signal::Kill);
}

// ---------------------------------------------- REQ-P-007, Step 6b
//
// **These two tests assert a LIMITATION, not a feature.** §20 records it
// as "documented, not fixed in v0.1.0": `portable-pty` maps signal death
// to `code: 1`, so a child CLASP killed and a child that ran `exit 1`
// are indistinguishable in `terminate`'s response. REQ-P-007's
// Verification column asks for exactly this — assert the documented
// behaviour so it cannot drift silently — and the REQ was written after
// 0.0.1 closed, so no milestone had picked it up. The limitation was
// prose, and prose cannot fail.
//
// Whoever widens `PtyBackend` to carry an exit *status* will find these
// red. That is the intended outcome: fix them together with §20 and
// §4.4, do not "repair" them back to green.

#[tokio::test]
async fn terminate_cannot_distinguish_a_signalled_child_from_exit_1() {
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    let r = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await
        .unwrap();
    let data = body(&r)["data"].clone();
    assert_eq!(
        data["exit_code"],
        json!(1),
        "the documented wrong answer: a SIGKILLed shell reports 1, not a \
         signal (REQ-P-007, §20)"
    );
    assert_eq!(data["already_exited"], json!(false));

    kill_all(&server).await;
}

#[tokio::test]
async fn a_child_that_really_exits_1_is_reported_the_same_way() {
    // The pairing that gives the test above its meaning. Read alone, that
    // one says "signals report 1"; the defect is that these two cases are
    // *indistinguishable*, and without this half the first test passes
    // against an implementation that reports signals correctly and
    // ordinary exits wrongly.
    let server = ClaspServer::new();
    let id = start_script(&server, "exit 1").await;

    let deadline = Instant::now() + Duration::from_secs(5);
    while server.registry.get(&id).unwrap().is_alive() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let r = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(false),
            timeout_secs: None,
        }))
        .await
        .unwrap();
    let data = body(&r)["data"].clone();
    assert_eq!(
        data["exit_code"],
        json!(1),
        "a genuine `exit 1` reports the same 1 the signalled child did"
    );
    assert_eq!(
        data["already_exited"],
        json!(true),
        "and it really had exited on its own"
    );

    kill_all(&server).await;
}

// ------------------------------------------- REQ-T-011, Step 5c
// `status` and `list_sessions` shipped `command`, `args` and
// `prompt.last_line` unredacted through 0.0.2. This milestone builds the
// redactor, so this is where they stop.

/// A live AWS-shaped key. Split so the constant itself is not the string
/// the assertions look for; only the concatenation is.
fn aws_key() -> String {
    format!("AKIA{}", "IOSFODNN7EXAMPLE")
}

async fn status_data(server: &ClaspServer, id: &str) -> Value {
    let r = server
        .status(Parameters(StatusArgs {
            session: id.to_string(),
        }))
        .await
        .expect("status must not be a protocol error");
    body(&r)["data"].clone()
}

#[tokio::test]
async fn status_redacts_the_command_that_started_the_session() {
    let server = ClaspServer::new();
    let key = aws_key();
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                format!("sleep 30 # {key}"),
            ],
            shell_integration: Some(false),
            ..Default::default()
        }))
        .await
        .unwrap();
    let id = body(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let data = status_data(&server, &id).await;
    let args = data["args"].as_array().unwrap();
    let joined = args
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        !joined.contains(&key),
        "status handed the credential back: {joined}"
    );
    // `aws`, not `aws-access-key-id`: the marker carries the rule's
    // `kind`, and the `aws-access-key-id` rule's kind is `aws` — one kind
    // covers the access-key and secret-key rules both, so the agent is
    // told what class of credential was withheld rather than which regex
    // caught it.
    assert!(
        joined.contains("[REDACTED:aws]"),
        "expected a marker naming the kind that fired: {joined}"
    );

    kill_all(&server).await;
}

#[tokio::test]
async fn status_leaves_an_ordinary_command_byte_identical() {
    // The negative half. Without it, replacing `redact_str` with a
    // function that returns `"[REDACTED]"` unconditionally passes the
    // test above.
    let server = ClaspServer::new();
    let id = start_bash(&server).await;

    let data = status_data(&server, &id).await;
    assert_eq!(data["command"], json!("bash"));
    assert_eq!(data["args"], json!(["--norc", "--noprofile"]));

    kill_all(&server).await;
}

#[tokio::test]
async fn list_sessions_redacts_args_element_wise() {
    // Joining `args` before redacting would hide the secret *and* return
    // one string where the agent expects an array, so the shape assertion
    // is what separates the two implementations.
    let server = ClaspServer::new();
    let token = format!("ghp_{TOKEN_TAIL}");
    let started = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                format!("sleep 30 # --token {token} --verbose"),
            ],
            shell_integration: Some(false),
            ..Default::default()
        }))
        .await
        .unwrap();
    let id = body(&started)["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let r = server.list_sessions().await.unwrap();
    let sessions = body(&r)["data"]["sessions"].as_array().unwrap().clone();
    let entry = sessions
        .iter()
        .find(|s| s["id"] == json!(id))
        .expect("the session we just started");
    let args = entry["args"].as_array().expect("args is still an array");
    assert_eq!(args.len(), 4, "element-wise redaction preserves the shape");
    assert_eq!(args[0], json!("--norc"));
    assert_eq!(args[1], json!("--noprofile"));
    assert_eq!(args[2], json!("-c"));
    let script = args[3].as_str().unwrap();
    assert!(!script.contains(&token), "the token survived: {script}");
    assert!(
        script.contains("[REDACTED:github]") && script.contains("--verbose"),
        "the surrounding argument text must survive: {script}"
    );

    kill_all(&server).await;
}

#[tokio::test]
async fn prompt_last_line_is_redacted_on_every_prompt_bearing_tool() {
    // Redacting at one call site instead of inside `with_detection`
    // passes a single-tool version of this test with three surfaces
    // still leaking, which is why all four are driven here.
    let server = ClaspServer::new();
    let id = started_session(&server).await;
    let session = server.registry.get(&id).unwrap();
    let full_token = format!("ghp_{TOKEN_TAIL}");

    // Printed WITHOUT a trailing newline, so it stays the last line.
    session
        .write_input(format!("printf 'CLASP''_LAST=%s%s' ghp_ {TOKEN_TAIL}\n").as_bytes())
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let last = status_data(&server, &id).await["prompt"]["last_line"]
            .as_str()
            .unwrap()
            .to_string();
        if last.contains("CLASP_LAST=") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the shell never printed the line: {last:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let read = body(
        &server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap(),
    );
    let sent = body(
        &server
            .send_input(Parameters(SendInputArgs {
                session: id.clone(),
                data: String::new(),
                append_newline: Some(false),
                ..Default::default()
            }))
            .await
            .unwrap(),
    );
    let stat = status_data(&server, &id).await;
    let listed = body(&server.list_sessions().await.unwrap())["data"]["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == json!(id))
        .expect("the session")
        .clone();

    for (tool, line) in [
        ("read_output", read["data"]["prompt"]["last_line"].clone()),
        ("send_input", sent["data"]["prompt"]["last_line"].clone()),
        ("status", stat["prompt"]["last_line"].clone()),
        ("list_sessions", listed["prompt"]["last_line"].clone()),
    ] {
        let line = line.as_str().unwrap_or_default().to_string();
        assert!(
            !line.contains(&full_token),
            "{tool} leaked the token in prompt.last_line: {line:?}"
        );
        // Paired: the line itself must still be there, or a tool that
        // reported an empty `last_line` would pass the absence check.
        assert!(
            line.contains("CLASP_LAST=[REDACTED:github]"),
            "{tool} lost the line instead of redacting it: {line:?}"
        );
    }

    kill_all(&server).await;
}

// ------------------------------------------- §9.2's `last_line` rule
//
// F2 and F1 measured against 0.0.3's HEAD, end to end through the tools an
// agent actually calls. Both were closed only for part of their class by
// the per-line clip: it looks at one line, and it looks at a *whole* one.

/// F2. The review's wording, verbatim: *the bytes the holdback is
/// withholding, in the same response.* `read_output` answered `held_back:
/// true` with the boundary at the `-----BEGIN`; `status` — `readOnlyHint:
/// true`, reading no buffer at all — handed back a full key-body line.
///
/// **Paired in the same session rather than in a second test**: once the
/// `-----END` lands the holdback releases and an ordinary prompt is
/// reported again. Without the second phase, a `last_line` wired to the
/// empty string passes the first.
#[tokio::test]
async fn status_withholds_the_last_line_while_a_key_is_still_streaming() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "streaming-key");
    let key_body = "PjLkMnBvCxZaSdFgHjKlQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJk";
    let head = format!("$ cat id_rsa\n-----BEGIN RSA PRIVATE KEY-----\n{key_body}");
    pty.queue_output(head.as_bytes());
    let session = server.registry.get(&id).unwrap();
    wait_until_head(&session, head.len() as u64);
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.detection().last_line != key_body && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let read = body(
        &server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap(),
    )["data"]
        .clone();
    let stat = status_data(&server, &id).await;

    assert_eq!(
        read["held_back"],
        json!(true),
        "the arrangement must really be withholding: {read}"
    );
    assert_eq!(
        read["output"],
        json!("$ cat id_rsa\n"),
        "the read stops at the `-----BEGIN`"
    );
    assert_eq!(
        stat["prompt"]["last_line"],
        json!(""),
        "the same region, reconstructed, is not reportable either"
    );
    for (tool, payload) in [("read_output", &read), ("status", &stat)] {
        assert!(
            !payload.to_string().contains(key_body),
            "{tool} returned the key body: {payload}"
        );
    }

    // Phase 2 — the negative. The block completes, the holdback releases,
    // and the prompt behind it comes back.
    pty.queue_output(b"\n-----END RSA PRIVATE KEY-----\nuser@host:~$ ");
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.detection().last_line != "user@host:~$ " && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let after = status_data(&server, &id).await;
    assert_eq!(
        after["prompt"]["last_line"],
        json!("user@host:~$ "),
        "an ordinary prompt is still reported once nothing is withheld"
    );
    let after_read = body(
        &server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap(),
    )["data"]
        .clone();
    assert_eq!(after_read["held_back"], json!(false));
    assert!(
        !after_read.to_string().contains(key_body),
        "the completed block is redacted, not released: {after_read}"
    );

    kill_all(&server).await;
}

/// F1. A JWT of 643 characters: `read_output.output` correctly returns
/// `[REDACTED:jwt]` while `status.prompt.last_line` returned 512 verbatim
/// characters, signature segment included. Nothing is in flight and
/// `held_back` is `false` — the line simply outgrew the 512-byte tail the
/// scanner keeps, taking the `eyJ` both mechanisms anchor on with it.
#[tokio::test]
async fn status_withholds_a_last_line_too_long_to_carry_its_own_anchor() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "long-jwt");
    let signature = "S".repeat(202);
    let jwt = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ{}.{signature}",
        "A".repeat(400)
    );
    assert_eq!(jwt.len(), 643);
    let stream = format!("$ echo $T\n{jwt}");
    pty.queue_output(stream.as_bytes());
    let session = server.registry.get(&id).unwrap();
    wait_until_head(&session, stream.len() as u64);
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.detection().last_line.len() != 512 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let read = body(
        &server
            .read_output(Parameters(read_args(&id)))
            .await
            .unwrap(),
    )["data"]
        .clone();
    let stat = status_data(&server, &id).await;

    // The half that was already right, asserted so the other half cannot
    // be mistaken for a holdback case.
    assert_eq!(read["output"], json!("$ echo $T\n[REDACTED:jwt]"));
    assert_eq!(read["held_back"], json!(false), "nothing is in flight");
    assert_eq!(stat["prompt"]["last_line"], json!(""));
    assert!(
        !stat.to_string().contains(&signature),
        "the signature segment survived: {stat}"
    );

    // The negative, and the one that bounds the cost: the record is a
    // property of the **current** line. A flag that stayed set once tripped
    // would mean one `cat` of a long file suppressed every prompt for the
    // rest of the session's life — an availability failure far worse than
    // the disclosure it closes, and invisible to a fixture that stops at
    // the long line.
    pty.queue_output(b"\nuser@host:~$ ");
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.detection().last_line != "user@host:~$ " && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        status_data(&server, &id).await["prompt"]["last_line"],
        json!("user@host:~$ "),
        "the next line starts clean"
    );

    kill_all(&server).await;
}

#[tokio::test]
async fn exited_at_is_absent_while_the_child_lives_and_set_once_after_it_dies() {
    let server = ClaspServer::new();
    let id = started_session(&server).await;

    let alive = status_data(&server, &id).await;
    assert_eq!(
        alive["exited_at_unix_secs"],
        Value::Null,
        "a live session has no exit time"
    );
    let started_at = alive["started_at_unix_secs"].as_u64().unwrap();

    let session = server.registry.get(&id).unwrap();
    let _ = session.signal(Signal::Kill);
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.is_alive() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let first = status_data(&server, &id).await;
    let at = first["exited_at_unix_secs"]
        .as_u64()
        .expect("an exited session reports when that was observed");
    assert!(
        at >= started_at,
        "the exit cannot precede the start: {at} < {started_at}"
    );

    // Latched, not restamped. A plain `store` passes a single read and
    // drifts on the second, which is the whole reason this reads twice
    // with a second of real time in between.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = status_data(&server, &id).await;
    assert_eq!(
        second["exited_at_unix_secs"],
        json!(at),
        "the observation instant must not move on later reads"
    );

    kill_all(&server).await;
}

// ------------------------------------------- wait_for_pattern, Step 5d
//
// A `MockPty` session inserted into the server's own registry, so the
// arrival of an in-flight secret is deterministic. A real shell cannot be
// made to stop mid-token on demand, and a test that waits for the race to
// happen by luck is a test that fails by luck.

fn mock_session_in(server: &ClaspServer, name: &str) -> (String, Arc<MockPty>) {
    let pty = Arc::new(MockPty::new());
    let session = Session::new(
        new_session_id(),
        Some(name.to_string()),
        "bash".into(),
        vec![],
        Arc::clone(&pty) as Arc<dyn PtyBackend>,
        SessionConfig::with_buffer_capacity(64 * 1024),
    );
    let id = session.id.clone();
    server.registry.insert(session).expect("registry insert");
    (id, pty)
}

fn wait_args(session: &str, pattern: &str) -> WaitForPatternArgs {
    WaitForPatternArgs {
        session: session.to_string(),
        pattern: pattern.to_string(),
        timeout_secs: Some(2),
        since_cursor: Some(0),
        max_bytes: None,
    }
}

async fn wait_data(server: &ClaspServer, args: WaitForPatternArgs) -> Value {
    let r = server
        .wait_for_pattern(Parameters(args))
        .await
        .expect("wait_for_pattern must not be a protocol error");
    body(&r)
}

fn wait_until_head(session: &Session, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.buffer_head() < n && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(session.buffer_head() >= n, "the reader never caught up");
}

/// REQ-O-004 and §4.1's worked example: a match that intersects the
/// withheld region comes back as `timeout` with its offset and **no
/// text**, and the surrounding context is clipped before the match so the
/// withheld bytes cannot return through it.
#[tokio::test]
async fn a_pattern_matching_an_in_flight_secret_is_withheld_with_its_offset() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "withheld");
    // A partial token: nine bytes of line, then `ghp_` and too few
    // characters for the rule to complete. The boundary sits at 9.
    pty.queue_output(b"line one\nghp_abcdef");
    wait_until_head(&server.registry.get(&id).unwrap(), 18);

    let payload = wait_data(&server, wait_args(&id, r"ghp_\w+")).await;
    let data = &payload["data"];
    assert_eq!(
        payload["status"], "timeout",
        "a withheld match is not a delivered result: {payload}"
    );
    assert_eq!(data["matched"], json!(true));
    assert_eq!(
        data["match"]["offset"],
        json!(9),
        "the raw offset is always reported"
    );
    assert!(
        data["match"].get("text").is_none(),
        "the text is omitted, not nulled: {}",
        data["match"]
    );
    assert_eq!(data["held_back"], json!(true));
    assert_eq!(
        data["next_cursor"],
        json!(9),
        "the agent retries from the boundary"
    );
    assert_eq!(
        data["output_since_start"], "line one\n",
        "the context is clipped before the match, so the withheld bytes \
         cannot come back through it"
    );

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// The paired negative, and the common case: no secret in flight, so
/// nothing is withheld and the text comes back. Without this, a
/// withhold-everything implementation passes the row above completely.
#[tokio::test]
async fn an_ordinary_match_is_not_withheld() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "ordinary");
    pty.queue_output(b"building\nREADY\n");
    wait_until_head(&server.registry.get(&id).unwrap(), 14);

    let payload = wait_data(&server, wait_args(&id, "READY")).await;
    let data = &payload["data"];
    assert_eq!(payload["status"], "ok");
    assert_eq!(data["matched"], json!(true));
    assert_eq!(data["match"]["offset"], json!(9));
    assert_eq!(data["match"]["text"], json!("READY"));
    assert_eq!(data["held_back"], json!(false));
    assert_eq!(data["output_since_start"], "building\nREADY\n");

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// A match whose *text* is a secret is redacted rather than withheld:
/// the token is complete, so the holdback has nothing to hold, and §5.2's
/// "match.text is routed through the OutputProcessor" is what applies.
#[tokio::test]
async fn a_completed_secret_match_returns_the_redacted_text() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "complete");
    let token = format!("ghp_{TOKEN_TAIL}");
    pty.queue_output(format!("t={token}\ndone\n").as_bytes());
    wait_until_head(&server.registry.get(&id).unwrap(), 48);

    let payload = wait_data(&server, wait_args(&id, r"ghp_\w+")).await;
    let data = &payload["data"];
    assert_eq!(payload["status"], "ok");
    assert_eq!(data["match"]["text"], json!("[REDACTED:github]"));
    assert!(
        !payload.to_string().contains(&token),
        "the token reached the agent: {payload}"
    );
    assert_eq!(
        data["match"]["offset"],
        json!(2),
        "the offset is the raw one, redacted or not"
    );

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// The sibling `a_completed_secret_match_returns_the_redacted_text` could
/// not catch: its `ghp_…` is a **prefix** rule, which self-identifies from
/// the value alone and is therefore redacted even by a redactor run over
/// the match span in isolation. A **context** rule keys on a label lying
/// *outside* the caller's match — `DD_API_KEY=` sits eleven bytes before
/// the 32 hex characters the pattern selects — so redacting a zero-width
/// window can never fire it. 8 of the 51 built-in rules are that shape,
/// and this returned the value verbatim beside an `output_since_start`
/// that showed `[REDACTED:datadog]` for the very same bytes.
///
/// §5.2 says `match.text` is "routed through the OutputProcessor"; the
/// assertion that the two fields agree is what that sentence means.
#[tokio::test]
async fn a_match_whose_rule_keys_on_a_label_outside_it_is_still_redacted() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "context-rule");
    let value = "0123456789abcdef0123456789abcdef";
    pty.queue_output(format!("DD_API_KEY={value}\ndone\n").as_bytes());
    wait_until_head(&server.registry.get(&id).unwrap(), 49);

    let payload = wait_data(&server, wait_args(&id, "[0-9a-f]{32}")).await;
    let data = &payload["data"];
    assert_eq!(payload["status"], "ok");
    assert_eq!(data["match"]["offset"], json!(11), "the raw offset stands");
    assert_eq!(data["match"]["text"], json!("[REDACTED:datadog]"));
    assert_eq!(
        data["output_since_start"], "DD_API_KEY=[REDACTED:datadog]\ndone\n",
        "the two fields see the same window, so they agree"
    );
    assert!(
        !payload.to_string().contains(value),
        "the key reached the agent: {payload}"
    );

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

#[tokio::test]
async fn a_pattern_that_never_matches_reports_timeout_without_a_match() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "notimeout");
    pty.queue_output(b"nothing here\n");
    wait_until_head(&server.registry.get(&id).unwrap(), 13);

    let mut args = wait_args(&id, "NEVER");
    args.timeout_secs = Some(1);
    let payload = wait_data(&server, args).await;
    assert_eq!(payload["status"], "timeout");
    assert_eq!(payload["data"]["matched"], json!(false));
    assert_eq!(payload["data"]["match"], Value::Null);
    assert_eq!(payload["data"]["held_back"], json!(false));

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// REQ-T-008. `0` is "no caller deadline", which the daemon still bounds;
/// the agent is told the deadline it will really get.
#[tokio::test]
async fn a_zero_timeout_is_clamped_to_the_hour_cap_and_says_so() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "clamped");
    pty.queue_output(b"READY\n");
    wait_until_head(&server.registry.get(&id).unwrap(), 6);

    let mut args = wait_args(&id, "READY");
    // The pattern is already in the buffer, so this returns at once — the
    // clamp is observable without waiting an hour for it.
    args.timeout_secs = Some(0);
    let payload = wait_data(&server, args).await;
    assert_eq!(payload["status"], "ok");
    assert_eq!(
        payload["data"]["clamped_timeout_secs"],
        json!(3600),
        "0 means no *caller* deadline, not no deadline"
    );

    let mut args = wait_args(&id, "READY");
    args.timeout_secs = Some(99_999);
    let payload = wait_data(&server, args).await;
    assert_eq!(payload["data"]["clamped_timeout_secs"], json!(3600));

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

/// The paired negative: a deadline inside the cap is not clamped, and the
/// field is **absent**. A field that is always present carries no
/// information, which is what emitting it unconditionally would produce.
#[tokio::test]
async fn an_ordinary_timeout_reports_no_clamp_field() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session_in(&server, "unclamped");
    pty.queue_output(b"READY\n");
    wait_until_head(&server.registry.get(&id).unwrap(), 6);

    let mut args = wait_args(&id, "READY");
    args.timeout_secs = Some(30);
    let payload = wait_data(&server, args).await;
    assert_eq!(payload["status"], "ok");
    assert!(
        payload["data"].get("clamped_timeout_secs").is_none(),
        "an agent that asked for 30s must never see this field: {payload}"
    );

    let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
}

#[tokio::test]
async fn an_invalid_pattern_is_a_protocol_error_and_never_reaches_the_shell() {
    let server = ClaspServer::new();
    let (id, _pty) = mock_session_in(&server, "badregex");
    let mut args = wait_args(&id, "((((");
    args.timeout_secs = Some(1);
    let err = server
        .wait_for_pattern(Parameters(args))
        .await
        .expect_err("a bad regex is an input-schema violation (§5.1)");
    assert!(err.message.contains("regex"), "{}", err.message);

    // And through `send_input`, where it matters more: a pattern
    // rejected *after* the write would have typed into a live shell.
    let session = server.registry.get(&id).unwrap();
    let err = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo hi".into(),
            wait_for: Some("((((".into()),
            ..Default::default()
        }))
        .await
        .expect_err("ditto");
    assert!(err.message.contains("regex"), "{}", err.message);
    assert!(
        session.read_from(0, 4096).bytes.is_empty(),
        "the rejected call still wrote to the session"
    );

    let _ = session.signal(Signal::Kill);
}

/// `send_input(wait_for=)` and `wait_for_pattern` are the same code path,
/// not a parallel one (§5.2). Driven against the identical arrangement —
/// a partial token arriving *after* the call starts — the eight shared
/// fields must agree.
#[tokio::test]
async fn send_input_wait_for_returns_the_identical_shape() {
    let server = ClaspServer::new();
    let (wid, wpty) = mock_session_in(&server, "shape-wait");
    let (sid, spty) = mock_session_in(&server, "shape-send");

    for pty in [Arc::clone(&wpty), Arc::clone(&spty)] {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            pty.queue_output(b"line one\nghp_abcdef");
        });
    }

    let mut args = wait_args(&wid, r"ghp_\w+");
    args.since_cursor = None; // live-only, like send_input's
    args.timeout_secs = Some(2);

    // Concurrently, because both waits must be *running* when the bytes
    // land: each one's scan starts at the head it saw when it began, and
    // running them in sequence leaves the second starting after its
    // session's output had already arrived.
    let (waited, sent) = tokio::join!(async { wait_data(&server, args).await }, async {
        body(
            &server
                .send_input(Parameters(SendInputArgs {
                    session: sid.clone(),
                    // Empty and no newline: nothing is typed, so the
                    // two sessions see the same bytes.
                    data: String::new(),
                    append_newline: Some(false),
                    wait_for: Some(r"ghp_\w+".into()),
                    timeout_secs: Some(2),
                }))
                .await
                .expect("send_input must not be a protocol error"),
        )
    });

    assert_eq!(waited["status"], sent["status"], "{waited} vs {sent}");
    for key in [
        "matched",
        "match",
        "output_since_start",
        "truncated_at_tail",
        "truncated_for_size",
        "held_back",
        "next_cursor",
    ] {
        assert_eq!(
            waited["data"][key], sent["data"][key],
            "{key} differs between wait_for_pattern and send_input(wait_for=)"
        );
    }
    // And the shape really is the withheld one, so the agreement above is
    // agreement about something.
    assert_eq!(waited["data"]["held_back"], json!(true));
    assert!(waited["data"]["match"].get("text").is_none());

    for id in [wid, sid] {
        let _ = server.registry.get(&id).unwrap().signal(Signal::Kill);
    }
}

#[test]
fn send_input_wait_for_sees_the_echo_of_its_own_write() {
    // A real PTY, because the echo is the point. `output_since_start`
    // starts at the `pre_write_head` the *writer task* sampled, so the
    // terminal's echo of the submitted line is inside it. Sampling that
    // cursor in the handler instead races the echo, and the echo then
    // disappears from the context the agent is shown.
    //
    // `CLASP''_ECHOED` can only be produced by the echo — running the
    // command prints `CLASP_ECHOED` — so the two forms tell the echo and
    // the output apart.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let server = ClaspServer::new();
        let id = started_session(&server).await;

        let sent = body(
            &server
                .send_input(Parameters(SendInputArgs {
                    session: id.clone(),
                    data: "echo CLASP''_ECHOED".into(),
                    wait_for: Some("CLASP_ECHOED".into()),
                    timeout_secs: Some(10),
                    ..Default::default()
                }))
                .await
                .expect("send_input must not be a protocol error"),
        );
        assert_eq!(sent["status"], "ok", "{sent}");
        let context = sent["data"]["output_since_start"].as_str().unwrap();
        assert!(
            context.contains("CLASP''_ECHOED"),
            "the echo of the write is missing from output_since_start: {context:?}"
        );
        assert!(
            context.contains("CLASP_ECHOED"),
            "and the command's own output: {context:?}"
        );
        assert_eq!(sent["data"]["bytes_written"], json!(20));

        kill_all(&server).await;
    });
}
