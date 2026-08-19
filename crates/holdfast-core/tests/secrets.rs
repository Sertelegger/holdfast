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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn body(r: &CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
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
