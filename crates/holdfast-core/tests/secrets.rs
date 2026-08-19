//! `request_secret_input` end to end: the tool on one side, a real
//! `attach.sock` client on the other (§5.2, §9.5, REQ-SEC-010a).
//!
//! **Why the negative assertions here are not vacuous, and how to keep
//! them that way.** §9.2 names the trap by hand: *"the secret is absent
//! from the log"* passes trivially against an implementation that never
//! produced a secret at all. Every absence assertion in this file is
//! therefore paired with two controls, and a change that drops either
//! has silently deleted the assertion it sits beside:
//!
//! 1. **Positive control — the value arrived.** The child reads it and
//!    prints a *transform* of it, so arrival is asserted on the child's
//!    own output rather than on our having sent something.
//! 2. **Leak-detector control — the harness would have caught a leak.**
//!    The same byte string, sent to the same session as an ordinary
//!    `Input` frame, **must** show up in the ring buffer. If that ever
//!    passes by absence, every assertion beside it means nothing.
//!
//! The fixture is `sh -c 'stty -echo; …'` everywhere, and never
//! `read -s`: rev. 36's classification has an **ICANON** rung, so a shell
//! that clears ICANON as well does not classify as `AwaitingSecret` at
//! all — and `sh` is `dash` on most CI images, where `read -s` does not
//! exist and neither fails loudly nor disables echo. The fixture also
//! **prints its prompt**, because the `AwaitingSecret` edge is computed
//! per read chunk: a child that drops `ECHO` and writes nothing raises no
//! request until its next byte of output.

use holdfast_core::attach::frames::{decode_server_frame, ClientFrame, ServerFrame};
use holdfast_core::attach::{AttachMode, AttachRole};
use holdfast_core::clock::Clock;
use holdfast_core::daemon::attach_server;
use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::server::{self, Daemon};
use holdfast_core::mcp::tools::RequestSecretInputArgs;
use holdfast_core::protocol::frame;
use holdfast_core::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use holdfast_core::pty::{InProcessPty, PtyBackend, PtySpawnConfig, Signal};
use holdfast_core::session::{new_session_id, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;

/// A value that matches **no** built-in redaction rule, so an absence
/// assertion over it cannot pass because a redactor got there first.
const PROBE: &str = "hunter2";

/// The one echo-off fixture, spelled the same way in every row. It
/// prints a prompt (so the edge fires), reads with echo off, and prints
/// a *transform* of what it read (so arrival is assertable without the
/// value ever being printed).
const ECHO_OFF_FIXTURE: &str = "stty -echo; printf 'Password: '; read x; stty echo; \
     printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"";

/// A child that drops `ECHO`, prints its prompt — and then restores echo
/// **without ever reading**. `user_cancelled`'s only producer (Q6): §7.5's
/// client-frame catalogue carries no cancellation frame, so the echo-off
/// condition clearing is the only signal there is.
///
/// The trailing `printf` is load-bearing, for the same reason
/// `ECHO_OFF_FIXTURE` prints its prompt: the classification is computed
/// per read chunk, so a child that restores echo and then writes nothing
/// leaves the session sitting in `AwaitingSecret` until its next byte of
/// output. The `sleep 3` is a margin over the plan's `1`, which is not
/// enough time for a test to attach, observe the raise, place a call and
/// see its waiter register before the window it is measuring has closed.
const ABANDONED_READ_FIXTURE: &str =
    "stty -echo; printf 'Password: '; sleep 3; stty echo; printf 'gave-up\\n'; sleep 30";

struct TestDaemon {
    daemon: Arc<Daemon>,
    paths: RuntimePaths,
}

impl TestDaemon {
    async fn start(tag: &str) -> Self {
        Self::start_with(tag, Clock::system()).await
    }

    async fn start_with(tag: &str, clock: Clock) -> Self {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let paths = RuntimePaths::with_dir(PathBuf::from(format!(
            "/tmp/holdfast-secrets-{tag}-{}",
            &unique[..8]
        )));
        let (control, _c) = server::bind_control(&paths).expect("bind control.sock");
        let (attach, _a) = attach_server::bind_attach(&paths).expect("bind attach.sock");
        let daemon = Daemon::with_clock(paths.clone(), clock);
        tokio::spawn(server::serve(Arc::clone(&daemon), control));
        tokio::spawn(attach_server::serve_attach(Arc::clone(&daemon), attach));
        for _ in 0..200 {
            if UnixStream::connect(paths.attach_sock()).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::task::yield_now().await;
        Self { daemon, paths }
    }

    /// A session on a real PTY. Every row here needs one: echo comes from
    /// the tty and not from us, and `AwaitingSecret` is a termios fact.
    fn shell_running(&self, script: &str) -> Arc<Session> {
        let mut cfg = PtySpawnConfig::new("sh");
        cfg.args = vec!["-c".to_string(), script.to_string()];
        let pty = InProcessPty::spawn(&cfg).expect("spawn a real shell");
        let s = Session::new(
            new_session_id(),
            None,
            "sh".into(),
            cfg.args.clone(),
            Arc::new(pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(256 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        s
    }

    async fn dial(&self) -> UnixStream {
        UnixStream::connect(self.paths.attach_sock())
            .await
            .expect("connect attach.sock")
    }

    /// Call the tool, exactly as the daemon would.
    async fn call(&self, args: RequestSecretInputArgs) -> CallToolResult {
        self.daemon
            .server
            .request_secret_input(Parameters(args))
            .await
            .expect("request_secret_input")
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.daemon.shutdown();
        for _ in 0..20 {
            match std::fs::remove_dir_all(self.paths.dir()) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }
}

fn attach_frame(session: &str, mode: AttachMode) -> ClientFrame {
    ClientFrame::Attach {
        session: session.to_string(),
        mode,
        role: AttachRole::Interactive,
        client_kind: ClientKind::Cli,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
    }
}

async fn send(s: &mut UnixStream, f: &ClientFrame) {
    frame::write_frame(s, f).await.expect("write client frame");
}

/// One server frame, or a failed test — **never a hang.** The workspace
/// has no `nextest.toml`, so a bare `await` on a daemon that stopped
/// answering is a hung CI job rather than a red row.
async fn recv(s: &mut UnixStream) -> ServerFrame {
    let body = tokio::time::timeout(Duration::from_secs(10), frame::read_frame_body(s))
        .await
        .expect("no frame arrived within 10s")
        .expect("a frame body");
    decode_server_frame(&body).expect("a decodable server frame")
}

async fn attach_ok(d: &TestDaemon, session: &str, mode: AttachMode) -> UnixStream {
    let mut c = d.dial().await;
    send(&mut c, &attach_frame(session, mode)).await;
    match recv(&mut c).await {
        ServerFrame::Attached { .. } => c,
        other => panic!("expected Attached, got {other:?}"),
    }
}

/// The next `AwaitingSecret`, skipping the child's output.
async fn next_awaiting_secret(c: &mut UnixStream, secs: u64) -> (String, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match recv(c).await {
            ServerFrame::AwaitingSecret {
                request_id,
                prompt_text,
            } => return (request_id, prompt_text),
            ServerFrame::Output { .. } | ServerFrame::Resize { .. } => {}
            other => panic!("expected AwaitingSecret, got {other:?}"),
        }
    }
    panic!("no AwaitingSecret arrived");
}

/// The next `SecretRequestClosed`, skipping the child's output.
async fn next_secret_closed(c: &mut UnixStream, secs: u64) -> (String, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match recv(c).await {
            ServerFrame::SecretRequestClosed {
                request_id,
                outcome,
            } => return (request_id, outcome),
            ServerFrame::Output { .. }
            | ServerFrame::Resize { .. }
            | ServerFrame::AwaitingSecret { .. } => {}
            other => panic!("expected SecretRequestClosed, got {other:?}"),
        }
    }
    panic!("no SecretRequestClosed arrived");
}

/// Accumulate `Output` until `needle` shows up, returning **everything**
/// seen — the negative half of every assertion here needs the whole
/// stream, not the last frame.
async fn stream_until(c: &mut UnixStream, needle: &[u8], secs: u64) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut acc: Vec<u8> = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let body = match tokio::time::timeout(
            deadline - tokio::time::Instant::now(),
            frame::read_frame_body(&mut *c),
        )
        .await
        {
            Ok(Ok(b)) => b,
            _ => break,
        };
        match decode_server_frame(&body).expect("a decodable server frame") {
            ServerFrame::Output { bytes, .. } => acc.extend_from_slice(&bytes),
            ServerFrame::AwaitingSecret { .. } | ServerFrame::SecretRequestClosed { .. } => {}
            other => panic!("expected Output, got {other:?}"),
        }
        if acc.windows(needle.len()).any(|w| w == needle) {
            return acc;
        }
    }
    acc
}

/// Block until the tool call has really registered its waiter.
///
/// **Read-only, deliberately.** Polling with `raise_or_adopt` would
/// *adopt* — the poller becomes the waiter, the call it was waiting for
/// collides, and the test measures something it created. That is what
/// `has_waiter` exists for.
async fn await_waiter(d: &TestDaemon, session_id: &str, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !d
        .daemon
        .server
        .attach_hub()
        .secrets()
        .has_waiter(session_id)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} never registered a waiter"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Run the tool call on its own task, so the test can go on to answer it.
///
/// Every row that both calls the tool and drives a client needs this: the
/// call blocks until the request resolves, and the thing that resolves it
/// is the test.
fn spawn_call(
    d: &TestDaemon,
    args: RequestSecretInputArgs,
) -> tokio::task::JoinHandle<CallToolResult> {
    let server = d.daemon.server.clone();
    tokio::spawn(async move {
        server
            .request_secret_input(Parameters(args))
            .await
            .expect("request_secret_input")
    })
}

/// Join a spawned call **with a ceiling**, so a deadline that never fires
/// is a red row rather than a hung job.
///
/// The ceiling is deliberately far above every `timeout_secs` these rows
/// pass and far below the 120 s default: a call that ignored its argument
/// and took the default would hit this and fail, which is the whole point
/// of the rows that measure elapsed time.
async fn joined(call: tokio::task::JoinHandle<CallToolResult>, what: &str) -> Value {
    let r = tokio::time::timeout(Duration::from_secs(25), call)
        .await
        .unwrap_or_else(|_| panic!("{what} never returned; its deadline did not fire"))
        .expect("the call");
    body(&r)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn body(r: &CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// The ordinary call these rows make: everything defaulted except the
/// session and the deadline being measured.
fn secret_args(session: &str, timeout_secs: u32) -> RequestSecretInputArgs {
    RequestSecretInputArgs {
        session: session.to_string(),
        prompt_text: "a credential".into(),
        timeout_secs: Some(timeout_secs),
        ..Default::default()
    }
}

/// The `reason` on a `secret_cancelled` response — and an assertion that
/// it *is* one, so a row collecting reasons cannot quietly collect a
/// `secret_provided`.
fn cancelled_reason(payload: &Value) -> String {
    assert_eq!(
        payload["status"], "secret_cancelled",
        "expected a cancellation, got {payload}"
    );
    payload["data"]["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("a secret_cancelled with no reason: {payload}"))
        .to_string()
}

// ------------------------------------------------------- the three layers

/// **Layers 2 and 3 in one session, plus layer 1's controls.**
///
/// The agent asks for a credential, a human at an attached client types
/// it, the child gets it — and it appears on no surface the agent or any
/// other client can read. The arrival proof is what makes the absence
/// proof mean anything: an implementation that dropped the value on the
/// floor satisfies every "not present" assertion below.
#[tokio::test]
async fn a_secret_the_agent_requested_reaches_the_child_and_none_of_the_surfaces() {
    let d = TestDaemon::start("threelayer").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    let mut typist = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut watcher = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;

    // The agent's call blocks; the human answers it.
    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "the deploy user's sudo password".into(),
                timeout_secs: Some(30),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    let (request_id, _) = next_awaiting_secret(&mut typist, 20).await;
    send(
        &mut typist,
        &ClientFrame::SecretInput {
            request_id: request_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    // Layer 2 — the positive control. The child transformed what it read.
    let seen = stream_until(&mut typist, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );

    // The agent's answer: a **count**, against the id it was given.
    let payload = body(&call.await.expect("the waiting call"));
    assert_eq!(payload["status"], "secret_provided");
    assert_eq!(
        payload["data"]["request_id"], request_id,
        "the tool answered against an id nobody broadcast"
    );
    assert_eq!(
        payload["data"]["bytes_written"],
        (PROBE.len() + 1) as u64,
        "seven bytes plus the appended newline"
    );

    // Layer 3 — the surfaces, all four.
    let whole = payload.to_string();
    assert!(
        !whole.contains(PROBE),
        "the value reached the MCP response: {whole}"
    );
    assert!(
        !contains(&seen, PROBE.as_bytes()),
        "the value came back on the submitting client's own stream"
    );
    let watched = stream_until(&mut watcher, b"got=HUNTER2", 20).await;
    assert!(
        !contains(&watched, PROBE.as_bytes()),
        "§9.2: the value was broadcast to another attached client"
    );
    // The ring buffer, read raw rather than through `read_output`, which
    // redacts — a redacted read would pass whether or not it was there.
    let buffered = s.buffer_slice(s.buffer_tail(), s.buffer_head());
    assert!(
        !contains(&buffered, PROBE.as_bytes()),
        "the value reached the ring buffer: {}",
        String::from_utf8_lossy(&buffered)
    );
    let audit = std::fs::read_to_string(d.paths.audit_log()).unwrap_or_default();
    assert!(
        !audit.contains(PROBE),
        "the value reached the audit log:\n{audit}"
    );

    let _ = s.signal(Signal::Kill);
}

/// **The leak-detector control.** The identical bytes, sent to an
/// identical session as ordinary `Input`, *are* in the ring buffer.
///
/// Without this row the assertion above passes against a harness that
/// could not have seen a leak in the first place — a buffer that was
/// never written, a comparison that never matched, a probe misspelled in
/// both places.
#[tokio::test]
async fn the_same_bytes_sent_as_ordinary_input_do_reach_the_buffer() {
    let d = TestDaemon::start("leakcontrol").await;
    let s = d.shell_running("cat");

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: format!("{PROBE}\n").into_bytes(),
        },
    )
    .await;
    let seen = stream_until(&mut c, PROBE.as_bytes(), 20).await;
    assert!(
        contains(&seen, PROBE.as_bytes()),
        "the control saw nothing: the harness could not have caught a leak"
    );
    let buffered = s.buffer_slice(s.buffer_tail(), s.buffer_head());
    assert!(
        contains(&buffered, PROBE.as_bytes()),
        "an ordinary write did not reach the ring buffer, so the absence assertion \
         in the row above is about a buffer nothing writes to"
    );
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------- raise, adopt, collide

#[tokio::test]
async fn a_tool_call_on_a_vacant_slot_raises_and_broadcasts() {
    let d = TestDaemon::start("raise").await;
    // `cat`, not the echo-off fixture: the slot must be **vacant** when
    // the call arrives, so nothing may have raised one already.
    let s = d.shell_running("cat");
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "a token for the registry".into(),
                timeout_secs: Some(1),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    let (broadcast_id, prompt) = next_awaiting_secret(&mut c, 20).await;
    assert!(broadcast_id.starts_with("secreq_"), "{broadcast_id}");
    assert_eq!(prompt, "a token for the registry");

    // **The two ids are compared to each other.** Returning a fresh id to
    // the agent while broadcasting another is two ids for one request,
    // and no single-side assertion can see it.
    let payload = body(&call.await.expect("the call"));
    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(
        payload["data"]["request_id"], broadcast_id,
        "the agent's id and the client's id are different requests"
    );
    let _ = s.signal(Signal::Kill);
}

/// REQ-SEC-010a, end to end, and §16.4 steps 3–7 are exactly this.
#[tokio::test]
async fn a_tool_call_adopts_an_echo_raised_request() {
    let d = TestDaemon::start("adopt").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    // The echo drop raises first, with no call behind it.
    let (raised_id, raised_prompt) = next_awaiting_secret(&mut c, 20).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "a completely different label".into(),
                timeout_secs: Some(30),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });
    await_waiter(&d, &s.id, "the adopting call").await;

    // Answer it, and assert the call **completes** against the raised id.
    //
    // **The id alone is not enough, and asserting only the id is a test
    // that cannot fail.** Measured: with adoption removed — collide on
    // any occupied slot rather than on one with a waiter — the refusal
    // carries `request_id: <the raised id>` too, because §9.4 binds a
    // colliding call to the request it collided with. An id-only
    // assertion is green against the exact mutation this row exists to
    // kill. The outcome is what separates them.
    //
    // **Exactly one `AwaitingSecret` for the whole flow**, checked while
    // the request is still open — an adopting call must not re-announce
    // a request a human may already be typing into.
    let second = tokio::time::timeout(Duration::from_millis(500), recv(&mut c)).await;
    if let Ok(ServerFrame::AwaitingSecret { request_id, .. }) = second {
        panic!("the adopting call re-broadcast the request it adopted: {request_id}");
    }

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: raised_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = body(&call.await.expect("the call"));
    assert_eq!(
        payload["status"], "secret_provided",
        "the call refused or re-allocated instead of adopting; REQ-SEC-010a makes \
         adoption the ordinary case, not an edge case"
    );
    assert_ne!(
        payload["data"]["reason"], "concurrent_request_pending",
        "adoption became a collision"
    );
    assert_eq!(
        payload["data"]["request_id"], raised_id,
        "the adopting call answered against an id nobody broadcast"
    );

    // The raised prompt is the child's own line, redacted; it may
    // legitimately be empty (REQ-O-013), so nothing here asserts it is
    // not.
    let _ = raised_prompt;
    let _ = s.signal(Signal::Kill);
}

/// The adopting call's `prompt_text` must not replace the raised one.
///
/// Asserted through a **second client attaching after adoption**: a
/// same-client assertion cannot see this, because that client already has
/// the original frame. The late attacher's replay is what does.
#[tokio::test]
async fn an_adopted_request_keeps_the_prompt_it_was_raised_with() {
    let d = TestDaemon::start("adoptprompt").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut first = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, raised_prompt) = next_awaiting_secret(&mut first, 20).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "AGENT SUPPLIED LABEL".into(),
                timeout_secs: Some(10),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    // Attach late, while the call is still waiting, and read the replay.
    let mut late = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    let (replayed_id, replayed_prompt) = next_awaiting_secret(&mut late, 20).await;
    assert_eq!(replayed_id, raised_id);
    assert_eq!(
        replayed_prompt, raised_prompt,
        "the adopting call rewrote the prompt a human may already be typing into"
    );
    assert_ne!(
        replayed_prompt, "AGENT SUPPLIED LABEL",
        "the agent relabelled the request"
    );

    send(
        &mut first,
        &ClientFrame::SecretInput {
            request_id: raised_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        body(&call.await.expect("the call"))["status"],
        "secret_provided"
    );
    let _ = s.signal(Signal::Kill);
}

/// `concurrent_request_pending` is a **second-caller** condition, and the
/// first caller's request is untouched.
#[tokio::test]
async fn a_second_caller_collides_and_the_first_still_completes() {
    let d = TestDaemon::start("collide").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let first = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "the first caller".into(),
                timeout_secs: Some(30),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    // Wait until the first call is really waiting, or the "second" caller
    // is the first one and this row is about nothing.
    await_waiter(&d, &s.id, "the first call").await;

    let second = body(
        &d.call(RequestSecretInputArgs {
            session: s.id.clone(),
            prompt_text: "the second caller".into(),
            timeout_secs: Some(30),
            ..Default::default()
        })
        .await,
    );
    assert_eq!(second["status"], "secret_cancelled");
    assert_eq!(second["data"]["reason"], "concurrent_request_pending");
    assert_eq!(
        second["data"]["request_id"], request_id,
        "the collision reported an id that is not the request it collided with"
    );

    // **The first caller goes on to complete.** Closing the request on
    // collision is the mutation that turns a race into data loss, and
    // only this half can see it.
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = body(&first.await.expect("the first call"));
    assert_eq!(
        payload["status"], "secret_provided",
        "the second caller cancelled the first"
    );
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------------------ the id check

/// §18.4: a `SecretInput` naming no outstanding request leaves the
/// connection open and writes **nothing** — and the child is still
/// blocked afterwards, which is what proves it.
#[tokio::test]
async fn a_wrong_request_id_writes_nothing_and_the_right_one_still_works() {
    let d = TestDaemon::start("wrongid").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    // The named authority agrees with the wire, in both directions.
    let slots = d.daemon.server.attach_hub().secrets();
    assert!(slots.matches_outstanding(&s.id, &request_id));
    assert!(!slots.matches_outstanding(&s.id, "secreq_notours"));

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: "secreq_notours".into(),
            bytes: b"WRONGVALUE".to_vec(),
        },
    )
    .await;
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "unknown_request_id");
            assert_eq!(frame_kind.as_deref(), Some("SecretInput"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }

    // The connection is still usable and the child is still blocked: the
    // correct id, immediately afterwards, still works.
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut c, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the refused submission left the request unanswerable: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !contains(&seen, b"WRONGVALUE"),
        "the refused submission was written to the child anyway"
    );
    let _ = s.signal(Signal::Kill);
}

// ----------------------------------------------------------- the deadline

/// §5.2, on a hand rather than a wall clock: an **unadopted** request has
/// no deadline of its own, because `timeout_secs` is an argument of the
/// *tool*.
///
/// **The pairing is what makes the first half mean anything.** In the
/// same test, an *adopted* request given the same advance does close —
/// so the clock demonstrably drives deadlines, and the assertion above is
/// not green because nothing is wired to it.
#[tokio::test]
async fn an_unadopted_request_has_no_deadline_and_an_adopted_one_does() {
    let clock = Clock::manual(std::time::Instant::now());
    let d = TestDaemon::start_with("nodeadline", clock.clone()).await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut c, 20).await;

    // Five minutes, in microseconds. Nobody called the tool.
    clock.advance(Duration::from_secs(300));
    tokio::task::yield_now().await;
    assert!(
        d.daemon
            .server
            .attach_hub()
            .secrets()
            .matches_outstanding(&s.id, &raised_id),
        "a raise with no call was given the tool's deadline, which §5.2 forbids in as \
         many words"
    );
    let quiet = tokio::time::timeout(Duration::from_millis(300), recv(&mut c)).await;
    if let Ok(frame) = quiet {
        assert!(
            !matches!(frame, ServerFrame::SecretRequestClosed { .. }),
            "an unadopted request closed on a clock nobody asked it to read"
        );
    }

    // The pairing: adopt it, advance the same amount, and it closes.
    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "now with a caller".into(),
                timeout_secs: Some(120),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });
    // Wait for the call to be parked on the clock before moving the hand,
    // or the advance lands before the sleep is registered and the test
    // hangs rather than failing.
    await_waiter(&d, &s.id, "the adopting call").await;
    clock.advance(Duration::from_secs(300));

    let payload = body(
        &tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect("the adopted call did not answer when its deadline passed")
            .expect("the call"),
    );
    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "timeout");
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------ max_secret_bytes

/// The cap applies to the **received** bytes, and it applies *before*
/// anything is copied.
#[tokio::test]
async fn an_oversize_submission_is_rejected_without_reaching_the_child() {
    let d = TestDaemon::start("toolarge").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(16),
            ..secret_args(&s.id, 20)
        },
    );
    await_waiter(&d, &s.id, "the capped call").await;

    let oversize = "0123456789abcdefg";
    assert_eq!(oversize.len(), 17, "the fixture must exceed the cap by one");
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: request_id.clone(),
            bytes: oversize.as_bytes().to_vec(),
        },
    )
    .await;

    let payload = joined(call, "the over-cap call").await;
    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "too_large");
    assert_eq!(payload["data"]["request_id"], request_id);

    // **The child's silence is the assertion.** The status alone is green
    // against a write-then-reject implementation, which answers
    // `too_large` having already typed the value into a program that was
    // at that moment reading one.
    let seen = stream_until(&mut c, b"got=", 2).await;
    assert!(
        !contains(&seen, b"got="),
        "the child completed its read, so the over-cap value was written: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !contains(&seen, oversize.as_bytes()),
        "the refused value came back on the wire"
    );
    let _ = s.signal(Signal::Kill);
}

/// Normalisation strips a trailing newline and may append one, so
/// `bytes_written` can differ from the received length by one in either
/// direction. Checking the wrong one puts the boundary where the client's
/// newline habit put it.
///
/// **Both halves in one run, one byte of cap apart**, because either half
/// alone is green against a constant.
#[tokio::test]
async fn the_cap_is_measured_before_normalisation() {
    let d = TestDaemon::start("prenorm").await;

    // Seven bytes received, six after the strip. A `bytes_written` check
    // admits this; the received-length check refuses it.
    let over = d.shell_running(ECHO_OFF_FIXTURE);
    let mut co = attach_ok(&d, &over.id, AttachMode::ReadWrite).await;
    let (over_id, _) = next_awaiting_secret(&mut co, 20).await;
    let over_call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(6),
            ..secret_args(&over.id, 20)
        },
    );
    await_waiter(&d, &over.id, "the six-byte call").await;
    send(
        &mut co,
        &ClientFrame::SecretInput {
            request_id: over_id,
            bytes: b"secret\n".to_vec(),
        },
    )
    .await;
    let refused = joined(over_call, "the six-byte call").await;
    assert_eq!(
        cancelled_reason(&refused),
        "too_large",
        "seven bytes were measured after the strip, not as received"
    );

    // The pairing: one byte of cap higher, the identical submission.
    let under = d.shell_running(ECHO_OFF_FIXTURE);
    let mut cu = attach_ok(&d, &under.id, AttachMode::ReadWrite).await;
    let (under_id, _) = next_awaiting_secret(&mut cu, 20).await;
    let under_call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(7),
            ..secret_args(&under.id, 20)
        },
    );
    await_waiter(&d, &under.id, "the seven-byte call").await;
    send(
        &mut cu,
        &ClientFrame::SecretInput {
            request_id: under_id,
            bytes: b"secret\n".to_vec(),
        },
    )
    .await;
    let allowed = joined(under_call, "the seven-byte call").await;
    assert_eq!(
        allowed["status"], "secret_provided",
        "a cap of exactly the received length refused it, so the boundary is off by one"
    );
    assert_eq!(
        allowed["data"]["bytes_written"], 7,
        "six bytes after the strip plus the appended newline"
    );
    let seen = stream_until(&mut cu, b"got=SECRET", 20).await;
    assert!(
        contains(&seen, b"got=SECRET"),
        "the accepted value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );

    let _ = over.signal(Signal::Kill);
    let _ = under.signal(Signal::Kill);
}

// -------------------------------------------------- the call's own window

/// §5.2: the window is the **tool call's**, measured in wall time here
/// because the thing under test is that the argument was read at all.
#[tokio::test]
async fn a_call_that_nobody_answers_times_out_at_its_own_deadline() {
    let d = TestDaemon::start("owndeadline").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let _ = next_awaiting_secret(&mut c, 20).await;

    let t0 = std::time::Instant::now();
    let payload = joined(spawn_call(&d, secret_args(&s.id, 2)), "the two-second call").await;
    let elapsed = t0.elapsed();

    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "timeout");
    assert!(
        elapsed >= Duration::from_secs(2),
        "the call returned before its own deadline: {elapsed:?}"
    );
    // `joined`'s 25 s ceiling is the other half: an implementation that
    // ignored the argument and took the 120 s default never returns
    // inside it, and the panic names that.
    assert!(
        elapsed < Duration::from_secs(20),
        "the call ignored timeout_secs and used the default: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.2: *"On adoption, the adopting call's `timeout_secs` window starts
/// at that call and not at the raise."*
///
/// The discriminator is the **lower** bound. A timer started at the raise
/// has already burnt three seconds of a two-second window, so it returns
/// `timeout` almost instantly — which looks like a fast deadline rather
/// than a wrong one, and only an elapsed-time floor separates them.
#[tokio::test]
async fn the_adopting_calls_window_starts_at_the_call() {
    let d = TestDaemon::start("adoptwindow").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut c, 20).await;

    tokio::time::sleep(Duration::from_secs(3)).await;

    let t0 = std::time::Instant::now();
    let payload = joined(spawn_call(&d, secret_args(&s.id, 2)), "the adopting call").await;
    let elapsed = t0.elapsed();

    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "timeout");
    assert_eq!(
        payload["data"]["request_id"], raised_id,
        "the adopting call answered against an id nobody broadcast"
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "the window was measured from the raise, not from the call: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.2: *"There is no separate `no_client_attached` reason."* Rev. 6
/// removed the short-circuit; §7.8.4 argues at length against putting it
/// back.
#[tokio::test]
async fn no_client_attached_still_waits_the_full_window() {
    let d = TestDaemon::start("noclient").await;
    let s = d.shell_running("cat");

    let t0 = std::time::Instant::now();
    let payload = joined(spawn_call(&d, secret_args(&s.id, 3)), "the unattended call").await;
    let elapsed = t0.elapsed();

    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(
        payload["data"]["reason"], "timeout",
        "a reason outside §18.1's four, invented for a condition §5.2 refuses to name"
    );
    assert!(
        elapsed >= Duration::from_secs(3),
        "the call short-circuited because nothing was attached: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// **The pairing for the row above**, and what makes waiting the right
/// behaviour rather than merely the specified one: the window is long
/// enough for somebody to arrive and answer.
#[tokio::test]
async fn a_client_attaching_mid_window_can_still_answer() {
    let d = TestDaemon::start("lateclient").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    // Nothing attached, so nothing raised: the call itself finds a vacant
    // slot. `SessionEvent` is consumed per connection, so with no client
    // the echo drop raises nothing.
    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the unattended call").await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut late = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (replayed_id, _) = next_awaiting_secret(&mut late, 20).await;

    send(
        &mut late,
        &ClientFrame::SecretInput {
            request_id: replayed_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = joined(call, "the call the late client answered").await;
    assert_eq!(
        payload["status"], "secret_provided",
        "a wait that never re-checks for clients cannot be answered by one that arrives"
    );
    assert_eq!(payload["data"]["request_id"], replayed_id);
    let seen = stream_until(&mut late, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------- the other two resolutions

/// `user_cancelled`'s only producer (Q6): the echo-off condition clears
/// with no value written.
#[tokio::test]
async fn the_child_abandoning_its_read_cancels_the_call() {
    let d = TestDaemon::start("abandoned").await;
    let s = d.shell_running(ABANDONED_READ_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call on an abandoned read").await;

    let payload = joined(call, "the abandoned call").await;
    assert_eq!(
        cancelled_reason(&payload),
        "user_cancelled",
        "mapping the echo restore onto `timeout` makes `user_cancelled` unreachable \
         and leaves a reason in the schema no response produces"
    );
    assert_eq!(payload["data"]["request_id"], raised_id);

    let (closed_id, outcome) = next_secret_closed(&mut c, 20).await;
    assert_eq!(closed_id, raised_id);
    assert_eq!(
        outcome, "cancelled",
        "§7.5's frame outcome, which is not the tool status"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.1: a session that exits under a waiting call answers `session_died`
/// with the code, not `timeout` two minutes later.
#[tokio::test]
async fn a_session_that_exits_mid_wait_returns_session_died() {
    let d = TestDaemon::start("diedmidwait").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let _ = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call that outlives its session").await;

    let _ = s.signal(Signal::Kill);
    let payload = joined(call, "the call on a dead session").await;
    assert_eq!(
        payload["status"], "session_died",
        "the call sat out its window for a child that was already gone: {payload}"
    );
    assert!(
        payload["data"]["exit_code"].is_number(),
        "§5.1 wants the code, and `null` tells an operator nothing: {payload}"
    );
}

// --------------------------------------------- the four, all in one run

/// **Every reason driven for real, in one run, against an exhaustive
/// match.**
///
/// Not a set assembled from what the other rows happened to observe —
/// that form is green whenever the suite is green. Each arm below drives
/// its own arrangement, and the comparison is against a `match` over
/// [`CancelReason`], so a fifth variant fails to **compile** here until
/// something in this test emits it.
#[tokio::test]
async fn every_secret_cancelled_reason_is_reachable() {
    use holdfast_core::secret::CancelReason;
    use std::collections::BTreeSet;

    let expected: BTreeSet<&str> = CancelReason::ALL
        .iter()
        .map(|r| match r {
            CancelReason::UserCancelled => "user_cancelled",
            CancelReason::Timeout => "timeout",
            CancelReason::TooLarge => "too_large",
            CancelReason::ConcurrentRequestPending => "concurrent_request_pending",
        })
        .collect();

    let d = TestDaemon::start("allreasons").await;
    let mut observed: BTreeSet<String> = BTreeSet::new();

    // too_large — an over-cap submission.
    {
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let (id, _) = next_awaiting_secret(&mut c, 20).await;
        let call = spawn_call(
            &d,
            RequestSecretInputArgs {
                max_secret_bytes: Some(1),
                ..secret_args(&s.id, 20)
            },
        );
        await_waiter(&d, &s.id, "the over-cap call").await;
        send(
            &mut c,
            &ClientFrame::SecretInput {
                request_id: id,
                bytes: b"AB".to_vec(),
            },
        )
        .await;
        observed.insert(cancelled_reason(&joined(call, "the over-cap call").await));
        let _ = s.signal(Signal::Kill);
    }

    // timeout — an elapsed deadline.
    {
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let _ = next_awaiting_secret(&mut c, 20).await;
        observed.insert(cancelled_reason(
            &joined(spawn_call(&d, secret_args(&s.id, 2)), "the timing-out call").await,
        ));
        let _ = s.signal(Signal::Kill);
    }

    // user_cancelled — echo restored with no read.
    {
        let s = d.shell_running(ABANDONED_READ_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let _ = next_awaiting_secret(&mut c, 20).await;
        let call = spawn_call(&d, secret_args(&s.id, 20));
        await_waiter(&d, &s.id, "the abandoned call").await;
        observed.insert(cancelled_reason(&joined(call, "the abandoned call").await));
        let _ = s.signal(Signal::Kill);
    }

    // concurrent_request_pending — a second caller.
    {
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let (id, _) = next_awaiting_secret(&mut c, 20).await;
        let first = spawn_call(&d, secret_args(&s.id, 20));
        await_waiter(&d, &s.id, "the first call").await;
        observed.insert(cancelled_reason(&body(
            &d.call(secret_args(&s.id, 20)).await,
        )));
        // Release the first caller rather than leaving it parked for its
        // whole window while the rest of the test runs.
        send(
            &mut c,
            &ClientFrame::SecretInput {
                request_id: id,
                bytes: PROBE.as_bytes().to_vec(),
            },
        )
        .await;
        assert_eq!(
            joined(first, "the first call").await["status"],
            "secret_provided",
            "the colliding call resolved the request it collided with"
        );
        let _ = s.signal(Signal::Kill);
    }

    let observed: BTreeSet<&str> = observed.iter().map(String::as_str).collect();
    assert_eq!(
        observed, expected,
        "a `secret_cancelled` reason the schema declares and nothing produces — \
         REQ-T-017's defect one level down, in a `reason` rather than a `status`"
    );
}

// ------------------------------------------------------- Q1's re-raise

/// **Q1.** §5.2 makes the deadline close the *request*, not merely the
/// call — but the raise is edge-triggered on the transition *into*
/// `AwaitingSecret`, so closing it while the child is still sitting at its
/// echo-off prompt removes the human's only affordance and nothing will
/// ever put it back.
///
/// **The pairing is the second half**, and without it this row is green
/// against an implementation that re-raises unconditionally: on a session
/// that is *not* awaiting a secret, the same timeout must raise nothing.
#[tokio::test]
async fn a_caller_timeout_re_raises_while_the_child_is_still_asking() {
    let d = TestDaemon::start("reraise").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (first_id, _) = next_awaiting_secret(&mut c, 20).await;

    let payload = joined(spawn_call(&d, secret_args(&s.id, 2)), "the timing-out call").await;
    assert_eq!(cancelled_reason(&payload), "timeout");
    assert_eq!(payload["data"]["request_id"], first_id);

    let (closed_id, outcome) = next_secret_closed(&mut c, 20).await;
    assert_eq!(closed_id, first_id);
    assert_eq!(outcome, "timeout", "§7.5's third outcome");

    // A **fresh** request, with a fresh id — sequential, never
    // concurrent — and the human can still answer it.
    let (again_id, _) = next_awaiting_secret(&mut c, 20).await;
    assert_ne!(
        again_id, first_id,
        "the re-raise reused the id of a request it had just closed"
    );
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: again_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut c, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the re-raised request could not be answered: {}",
        String::from_utf8_lossy(&seen)
    );
    let _ = s.signal(Signal::Kill);

    // The pairing: a child that is **not** at an echo-off prompt. Its
    // timeout closes the request and raises nothing.
    let plain = d.shell_running("cat");
    let mut pc = attach_ok(&d, &plain.id, AttachMode::ReadWrite).await;
    let call = spawn_call(&d, secret_args(&plain.id, 2));
    let (raised_id, _) = next_awaiting_secret(&mut pc, 20).await;
    assert_eq!(
        cancelled_reason(&joined(call, "the plain call").await),
        "timeout"
    );
    let (plain_closed, _) = next_secret_closed(&mut pc, 20).await;
    assert_eq!(plain_closed, raised_id);
    let quiet = tokio::time::timeout(Duration::from_millis(500), recv(&mut pc)).await;
    if let Ok(ServerFrame::AwaitingSecret { request_id, .. }) = quiet {
        panic!("a session that is not awaiting a secret was handed one anyway: {request_id}");
    }
    let _ = plain.signal(Signal::Kill);
}
