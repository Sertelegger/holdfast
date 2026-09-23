//! `terminate` on an interactive shell hangs it up instead of waiting out
//! the grace for a `SIGTERM` it ignores (GH #234).
//!
//! **The timing assertions are fractions of a grace the row chooses, not
//! wall-clock budgets.** Every row asks for a 10 s grace and asserts the
//! call came back in under half of it. Before the fix each of these
//! waited the whole grace and then escalated to `SIGKILL`, so the margin
//! between the two outcomes is five seconds wide — nothing a loaded
//! machine can close — and the row that must *wait* (the foreground job
//! cleaning up) waits on a file the job writes, not on a duration.
//!
//! Unix-only: the subject is a signal.
#![cfg(unix)]

use holdfast_core::mcp::tools::{StartSessionArgs, TerminateArgs};
use holdfast_core::mcp::HoldfastServer;
use holdfast_core::session::Session;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

const GRACE_SECS: u32 = 10;

fn body(r: &rmcp::model::CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

async fn interactive_bash(server: &HoldfastServer) -> (String, Arc<Session>) {
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: Some("bash".into()),
            args: vec!["--norc".into(), "--noprofile".into()],
            ..Default::default()
        }))
        .await
        .unwrap();
    let id = body(&r)["data"]["session_id"].as_str().unwrap().to_string();
    let session = server.registry.get(&id).unwrap();
    (id, session)
}

/// Poll the session's own buffer for a line the *command* printed. Every
/// needle is written with `''` in it where it is typed, so the echo of
/// the typed line cannot match.
fn wait_for(session: &Session, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let text = String::from_utf8_lossy(&session.read_from(0, 1 << 20).bytes).to_string();
        if text.contains(needle) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "{needle:?} never appeared: {text:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// `kill(pid, 0)`, which a zombie also answers — so the callers wait,
/// bounded, for it to be reaped rather than asking once.
fn gone_within(pid: i32, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

async fn terminate(server: &HoldfastServer, id: &str) -> (Value, Duration) {
    let started = Instant::now();
    let r = server
        .terminate(Parameters(TerminateArgs {
            session: id.into(),
            force: Some(false),
            timeout_secs: Some(GRACE_SECS),
        }))
        .await
        .unwrap();
    (body(&r), started.elapsed())
}

/// **GH #234, the reported case**: an idle interactive `bash` with two
/// background jobs. It ignores the `SIGTERM` sweep, so the call used to
/// wait out its whole grace (5.16 s at the default 5) and escalate. Now
/// the shell is hung up as soon as it is back at its prompt, and passes
/// the hangup to its jobs — every one of which must be gone too, which is
/// the property the old `SIGKILL` delivered and this must not lose.
#[tokio::test]
async fn terminate_hangs_up_an_idle_shell_instead_of_waiting_out_its_grace() {
    let server = HoldfastServer::new();
    let (id, session) = interactive_bash(&server).await;
    let shell = session.pid().unwrap() as i32;
    session
        .write_input(b"sleep 300 & sleep 301 & echo JOBS''_UP $!\n")
        .unwrap();
    let text = wait_for(&session, "JOBS_UP ");
    let last_job: i32 = text
        .split("JOBS_UP ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
        .expect("the shell printed its last job's pid");

    let (b, took) = terminate(&server, &id).await;

    assert_eq!(b["status"], "ok", "{b}");
    assert!(
        took < Duration::from_secs(u64::from(GRACE_SECS) / 2),
        "terminate took {took:?} of a {GRACE_SECS} s grace: the shell sat out the \
         SIGTERM it ignores instead of being hung up"
    );
    assert!(
        gone_within(shell, Duration::from_secs(5)),
        "the shell {shell} is still running"
    );
    assert!(
        gone_within(last_job, Duration::from_secs(5)),
        "background job {last_job} outlived its session"
    );
}

/// **The hangup waits for a foreground job that is cleaning up.** The
/// job caught the `SIGTERM` and spends a second writing a file; a shell
/// hung up during that second would pass the hangup on and the file would
/// never appear. So the hangup has to wait until the job has finished and
/// the shell has the terminal back — and then the call still ends well
/// inside the grace.
#[tokio::test]
async fn a_foreground_job_finishes_its_cleanup_before_the_shell_is_hung_up() {
    let dir = std::env::temp_dir().join(format!(
        "holdfast-hangup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let done = dir.join("cleaned");

    let server = HoldfastServer::new();
    let (id, session) = interactive_bash(&server).await;
    let shell = session.pid().unwrap() as i32;
    let job = format!(
        "sh -c 'trap \"sleep 1; echo cleaned > {}; exit 0\" TERM; echo JOB''_UP; \
         while :; do sleep 0.1; done'\n",
        done.display()
    );
    session.write_input(job.as_bytes()).unwrap();
    wait_for(&session, "JOB_UP");

    let (b, took) = terminate(&server, &id).await;

    assert_eq!(b["status"], "ok", "{b}");
    let cleaned = std::fs::read_to_string(&done).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        cleaned.trim(),
        "cleaned",
        "the foreground job was cut off during its SIGTERM cleanup — the shell \
         was hung up while it still had a job in front of it"
    );
    assert!(
        took < Duration::from_secs(u64::from(GRACE_SECS) / 2),
        "terminate took {took:?} of a {GRACE_SECS} s grace"
    );
    assert!(
        gone_within(shell, Duration::from_secs(5)),
        "the shell {shell} is still running"
    );
}

/// The exit code this reports is REQ-P-007's documented one — a shell
/// that died of a signal reads `1`, as it did when the signal was
/// `SIGKILL` — and **not** something the hangup invented. Pinned so a
/// change to it is a decision, not a side effect of this one.
#[tokio::test]
async fn a_hung_up_shell_reports_the_same_exit_code_the_sigkill_did() {
    let server = HoldfastServer::new();
    let (id, session) = interactive_bash(&server).await;
    session.write_input(b"echo READY''_MARK\n").unwrap();
    wait_for(&session, "READY_MARK");
    let (b, _) = terminate(&server, &id).await;
    assert_eq!(b["data"]["exit_code"], 1, "{b}");
    assert_eq!(b["data"]["already_exited"], false, "{b}");
}
