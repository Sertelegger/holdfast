//! The §7.5 attach protocol over a real `attach.sock` (spec §11.5).
//!
//! Every test gets its own runtime directory and its own daemon, so a
//! wedged one cannot poison the next and the file can run in parallel.
//!
//! **Read every assertion here with "what would a broken daemon have to
//! do to still pass this?" in hand.** Two failure modes matter more than
//! the rest and are worth naming up front:
//!
//! * Both peers are built from this crate, so a test that encodes with
//!   the same derived `serde` impl it decodes with round-trips perfectly
//!   against a wire §7.5 does not describe. The byte-level pinning of
//!   the frames themselves lives in `attach::frames`' own key-set tests;
//!   what is asserted here is *behaviour* — which frame, in which order,
//!   and whether the socket is still open afterwards.
//! * "The connection closed" and "the daemon died" look identical from
//!   one socket. Every close assertion here is therefore followed by a
//!   fresh, well-formed attach that must still succeed.

use holdfast_core::attach::frames::{decode_server_frame, ClientFrame, ServerFrame};
use holdfast_core::attach::{AttachMode, AttachRole, SignalName};
use holdfast_core::daemon::attach_server;
use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::server::{self, Daemon};
use holdfast_core::protocol::client::ControlClient;
use holdfast_core::protocol::frame::{self, FrameError, MAX_FRAME_BYTES};
use holdfast_core::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use holdfast_core::pty::{MockPty, PtyBackend};
use holdfast_core::session::{new_session_id, Session, SessionConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;

/// A daemon serving **both** sockets in this test's own process.
struct TestDaemon {
    daemon: Arc<Daemon>,
    paths: RuntimePaths,
}

impl TestDaemon {
    async fn start(tag: &str) -> Self {
        let paths = RuntimePaths::with_dir(scratch_dir(tag));
        let (control, _c) = server::bind_control(&paths).expect("bind control.sock");
        let (attach, _a) = attach_server::bind_attach(&paths).expect("bind attach.sock");
        let daemon = Daemon::new(paths.clone());
        tokio::spawn(server::serve(Arc::clone(&daemon), control));
        tokio::spawn(attach_server::serve_attach(Arc::clone(&daemon), attach));
        // The kernel backlog accepts a connection before `serve_attach`
        // is polled, so this proves the socket file is bound and nothing
        // more; the `yield_now` below is what waits for the accept loop
        // to have run at least once.
        for _ in 0..200 {
            if UnixStream::connect(paths.attach_sock()).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::task::yield_now().await;
        Self { daemon, paths }
    }

    /// Register a live `MockPty`-backed session and return it.
    fn session(&self, name: Option<&str>) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            name.map(String::from),
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(256 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        (s, pty)
    }

    async fn dial(&self) -> UnixStream {
        UnixStream::connect(self.paths.attach_sock())
            .await
            .expect("connect attach.sock")
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

fn scratch_dir(tag: &str) -> PathBuf {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    PathBuf::from(format!("/tmp/holdfast-ap-{tag}-{}", &unique[..8]))
}

fn attach_to(session: &str) -> ClientFrame {
    attach_at(session, PROTOCOL_MAJOR)
}

fn attach_at(session: &str, protocol_major: u32) -> ClientFrame {
    attach_as(session, AttachMode::ReadWrite, AttachRole::Interactive)
        .with_protocol_major(protocol_major)
}

/// The handshake with `mode` and `role` chosen explicitly.
///
/// **The two are orthogonal and this helper keeps them so** (§7.5): a
/// builder that took one argument and derived the other is exactly the
/// inference the protocol forbids, and every ReadOnly/observer test below
/// would then be asserting the helper's opinion rather than the daemon's.
fn attach_as(session: &str, mode: AttachMode, role: AttachRole) -> ClientFrame {
    ClientFrame::Attach {
        session: session.to_string(),
        mode,
        role,
        client_kind: ClientKind::Cli,
        client_version: "test".into(),
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
    }
}

trait WithProtocolMajor {
    fn with_protocol_major(self, major: u32) -> Self;
}

impl WithProtocolMajor for ClientFrame {
    fn with_protocol_major(mut self, major: u32) -> Self {
        if let ClientFrame::Attach { protocol_major, .. } = &mut self {
            *protocol_major = major;
        }
        self
    }
}

async fn send(s: &mut UnixStream, f: &ClientFrame) {
    frame::write_frame(s, f).await.expect("write client frame");
}

/// One server frame, or a failed test — never a hang.
///
/// The bug most of these rows guard against is a daemon that keeps the
/// connection open, and as a bare `await` that is a hung CI job rather
/// than a red row.
async fn recv(s: &mut UnixStream) -> ServerFrame {
    let body = tokio::time::timeout(Duration::from_secs(5), frame::read_frame_body(s))
        .await
        .expect("no frame arrived within 5s")
        .expect("a frame body");
    decode_server_frame(&body).expect("a decodable server frame")
}

/// Assert the peer closed. `Ok(Err(Eof))` only — a timeout is
/// `Err(Elapsed)` and must **not** read as success, which is exactly
/// what `matches!(x, Ok(Err(_)) | Err(_))` would have done.
async fn expect_eof(s: &mut UnixStream, what: &str) {
    let r = tokio::time::timeout(Duration::from_secs(5), frame::read_frame_body(s)).await;
    assert!(
        matches!(r, Ok(Err(FrameError::Eof))),
        "{what}: expected the daemon to close, got {r:?}"
    );
}

/// A well-formed attach on a fresh connection must still work. Every
/// close assertion is paired with this, because "the connection closed"
/// and "the daemon died" are the same thing from one socket.
async fn assert_daemon_survives(d: &TestDaemon, session: &str) {
    let mut fresh = d.dial().await;
    send(&mut fresh, &attach_to(session)).await;
    assert!(
        matches!(recv(&mut fresh).await, ServerFrame::Attached { .. }),
        "the daemon did not survive"
    );
}

// ------------------------------------------------------ the handshake

#[tokio::test]
async fn a_well_formed_attach_receives_attached_with_the_canonical_id() {
    let d = TestDaemon::start("canon").await;
    let (s, _pty) = d.session(Some("build"));

    // **By name**, which is the half that matters: a daemon that echoed
    // the requested string back passes this only if you always attach by
    // id.
    let mut c = d.dial().await;
    send(&mut c, &attach_to("build")).await;
    match recv(&mut c).await {
        ServerFrame::Attached {
            session_id, name, ..
        } => {
            assert!(
                session_id.starts_with("sess_"),
                "Attached echoed the request instead of answering with the \
                 canonical id: {session_id}"
            );
            assert_eq!(session_id, s.id);
            assert_eq!(name.as_deref(), Some("build"));
        }
        other => panic!("expected Attached, got {other:?}"),
    }
}

#[tokio::test]
async fn attached_reports_the_current_pty_size() {
    let d = TestDaemon::start("size").await;
    let (s, _pty) = d.session(None);
    // The same funnel `resize` the MCP tool reaches: it clamps, calls
    // the backend, and *then* stores, so `size()` reports the geometry
    // the terminal got rather than the one that was asked for.
    s.resize(132, 43).expect("resize");

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&s.id)).await;
    match recv(&mut c).await {
        // Unequal dimensions on purpose: a square terminal cannot detect
        // a transposition, and `Session::size()` returns `(cols, rows)`.
        ServerFrame::Attached { cols, rows, .. } => {
            assert_eq!(
                (cols, rows),
                (132, 43),
                "cols/rows are the wrong way round, or hardcoded"
            );
        }
        other => panic!("expected Attached, got {other:?}"),
    }
}

#[tokio::test]
async fn attached_reports_the_same_state_strings_as_the_mcp_surface() {
    // §18.2a's bare tokens, with the code in the sibling field. The
    // mutation is serialising the Rust `Debug` — `"Exited(7)"` — which
    // no consumer can match on. §25 records `dead_reason` as proposed
    // and **rejected**, so nothing here should grow one.
    let d = TestDaemon::start("state").await;
    let (running, _p1) = d.session(Some("live"));
    let (dead, dead_pty) = d.session(Some("doomed"));
    let dead_id = dead.id.clone();

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&running.id)).await;
    let alive = recv(&mut c).await;
    match &alive {
        ServerFrame::Attached {
            state, exit_code, ..
        } => {
            assert_eq!(state, "Running");
            assert_eq!(*exit_code, None, "a live session has no exit code");
        }
        other => panic!("expected Attached, got {other:?}"),
    }

    dead_pty.exit(7);

    // By **id**, which still resolves after the child is gone — that is
    // the registry's rule and the only way `Exited` is observable at all.
    let mut c2 = d.dial().await;
    send(&mut c2, &attach_to(&dead_id)).await;
    let exited = recv(&mut c2).await;
    match &exited {
        ServerFrame::Attached {
            state, exit_code, ..
        } => {
            assert_eq!(
                state, "Exited",
                "the bare §18.2a token, never \"Exited(7)\""
            );
            assert_eq!(*exit_code, Some(7), "the code lives in its own field");
        }
        other => panic!("expected Attached, got {other:?}"),
    }

    // The *string* appears in no frame at all. Asserted over the whole
    // debug rendering of both frames, because a `Debug` leak could
    // arrive in any field, not only in `state`.
    for f in [&alive, &exited] {
        let rendered = format!("{f:?}");
        assert!(
            !rendered.contains("Exited(7)"),
            "the Rust Debug spelling reached the wire: {rendered}"
        );
    }

    // By **name**, an exited session has released its name, so this is
    // the third state string's negative: a fresh attach is refused.
    let mut c3 = d.dial().await;
    send(&mut c3, &attach_to("doomed")).await;
    match recv(&mut c3).await {
        ServerFrame::AttachReject { reason, .. } => assert_eq!(reason, "session_not_found"),
        other => panic!("expected AttachReject, got {other:?}"),
    }
    expect_eof(&mut c3, "a refused attach").await;
}

#[tokio::test]
async fn a_version_mismatched_client_is_rejected_over_attach_sock_in_both_directions() {
    // REQ-D-004a's integration clause, and the reason the unit tests in
    // `attach::handshake` alone do not cover it. Four assertions per
    // direction: (a) the frame is an `AttachReject`, which closes
    // "asserted the connection closed" — that also passes if the daemon
    // panicked mid-frame; (b) the two reasons are the right ones **and
    // differ**, which is what a three-arm match with a catch-all fails,
    // on the *older* client only; (c) the next read is `Eof`, which
    // closes "sent the frame but held the socket"; (d) a fresh attach
    // still works, which closes "took the daemon down with it".
    let d = TestDaemon::start("version").await;
    let (s, _pty) = d.session(None);

    let mut reasons = Vec::new();
    for (major, expected) in [
        (PROTOCOL_MAJOR + 1, "protocol_too_new"),
        (PROTOCOL_MAJOR - 1, "protocol_too_old"),
    ] {
        let mut c = d.dial().await;
        send(&mut c, &attach_at(&s.id, major)).await;
        match recv(&mut c).await {
            ServerFrame::AttachReject { reason, message } => {
                assert_eq!(reason, expected, "wrong token for major {major}");
                assert!(message.starts_with(expected), "{message}");
                reasons.push(reason);
            }
            other => panic!("expected AttachReject for major {major}, got {other:?}"),
        }
        expect_eof(&mut c, "a version refusal").await;
        assert_daemon_survives(&d, &s.id).await;
    }
    assert_ne!(
        reasons[0], reasons[1],
        "one token for both directions passes each half alone"
    );
}

#[tokio::test]
async fn the_two_sockets_advertise_the_same_protocol_version() {
    // REQ-D-004a's version-aliasing clause, asserted on the **wire**
    // rather than between two imports of one constant. A unit assertion
    // inside `attach::handshake` cannot see this: that file imports the
    // control protocol's constants and would be comparing each with
    // itself. Introducing an `ATTACH_PROTOCOL_MAJOR` is what this kills.
    let d = TestDaemon::start("alias").await;
    let (s, _pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&s.id)).await;
    let (attach_major, attach_minor) = match recv(&mut c).await {
        ServerFrame::Attached {
            protocol_major,
            protocol_minor,
            ..
        } => (protocol_major, protocol_minor),
        other => panic!("expected Attached, got {other:?}"),
    };

    let control = ControlClient::connect(&d.paths.control_sock(), ClientKind::Cli)
        .await
        .expect("control handshake");
    let info = control.daemon_info();
    assert_eq!(
        (attach_major, attach_minor),
        (info.protocol_major, info.protocol_minor),
        "one daemon advertises one version on both sockets (§7.5)"
    );
}

// ------------------------------------------- pre-handshake refusals

#[tokio::test]
async fn a_non_attach_first_frame_is_no_handshake_and_closes() {
    let d = TestDaemon::start("nohs").await;
    let (s, _pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &ClientFrame::Input { bytes: b"x".into() }).await;
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "no_handshake");
            assert_eq!(frame_kind.as_deref(), Some("Input"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    expect_eof(&mut c, "a pre-handshake violation").await;
    assert_daemon_survives(&d, &s.id).await;
}

#[tokio::test]
async fn an_unknown_session_is_rejected_and_the_daemon_survives() {
    let d = TestDaemon::start("nosess").await;
    let (s, _pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &attach_to("sess_nothinghere")).await;
    match recv(&mut c).await {
        ServerFrame::AttachReject { reason, message } => {
            assert_eq!(reason, "session_not_found");
            assert!(message.contains("sess_nothinghere"), "{message}");
        }
        other => panic!("expected AttachReject, got {other:?}"),
    }
    expect_eof(&mut c, "an unknown session").await;
    assert_daemon_survives(&d, &s.id).await;
}

// ------------------------------------------------------- the frame cap

#[tokio::test]
async fn an_oversized_frame_is_refused_and_closes() {
    // **Before** the handshake. Only the prefix goes on the wire: a
    // daemon that allocated the declared length before checking it is a
    // trivial memory amplifier — four attacker-chosen bytes for 16 MiB —
    // and would answer `Eof` here rather than `frame_too_large`.
    let d = TestDaemon::start("toobig").await;
    let (s, _pty) = d.session(None);

    let mut c = d.dial().await;
    let prefix = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
    use tokio::io::AsyncWriteExt;
    c.write_all(&prefix).await.expect("write prefix");
    c.flush().await.expect("flush");
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "frame_too_large");
            assert_eq!(
                frame_kind, None,
                "the body was never read, so there is no kind to name"
            );
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    expect_eof(&mut c, "an oversized pre-handshake frame").await;
    assert_daemon_survives(&d, &s.id).await;
}

#[tokio::test]
async fn a_frame_of_exactly_the_cap_is_read_not_refused() {
    // The pairing without which the row above is green under `>=` as
    // well as under `>`. §7.4's bound is **exclusive**: a body of
    // exactly `MAX_FRAME_BYTES` is legal. Its contents are not a frame,
    // so the answer is `protocol_violation` — the point is that it was
    // *read*.
    let d = TestDaemon::start("atcap").await;
    let (s, _pty) = d.session(None);

    let mut c = d.dial().await;
    use tokio::io::AsyncWriteExt;
    c.write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes())
        .await
        .expect("write prefix");
    // 0xff repeated is not valid CBOR ("break" outside an indefinite
    // container), so this is malformed rather than an unknown type.
    c.write_all(&vec![0xffu8; MAX_FRAME_BYTES])
        .await
        .expect("write body");
    c.flush().await.expect("flush");
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(
                reason, "protocol_violation",
                "a body of exactly the cap must be read, then judged on its contents"
            );
            assert_eq!(frame_kind, None);
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    expect_eof(&mut c, "a malformed pre-handshake frame").await;
    assert_daemon_survives(&d, &s.id).await;
}

#[tokio::test]
async fn an_oversized_frame_after_the_handshake_also_closes() {
    // The half a blanket *"post-handshake `ProtocolError` never closes"*
    // reading loses. **The pairing is what makes it prove anything**: on
    // the *same* connection, an unknown `type` is answered
    // `protocol_violation` and the connection survives to carry an
    // `Input` through to the PTY, so "this daemon closes on every
    // post-handshake ProtocolError" cannot pass both halves.
    let d = TestDaemon::start("bigpost").await;
    let (s, pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut c).await, ServerFrame::Attached { .. }));

    // Half one: survivable.
    write_raw_map(&mut c, "Nonsense").await;
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "protocol_violation");
            assert_eq!(frame_kind.as_deref(), Some("Nonsense"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"still here\n".to_vec(),
        },
    )
    .await;
    wait_for_written(&pty, b"still here\n").await;

    // Half two: not survivable, and with **no `Detached`** before the
    // close. REQ-D-009's connection-level-fault clause: the framing is
    // lost, so the connection cannot be resynchronised in either phase,
    // and `ProtocolError { frame_too_large }` is where that is said.
    use tokio::io::AsyncWriteExt;
    c.write_all(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
        .await
        .expect("write prefix");
    c.flush().await.expect("flush");
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "frame_too_large");
            assert_eq!(frame_kind, None);
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    expect_eof(&mut c, "an oversized post-handshake frame").await;
    assert_daemon_survives(&d, &s.id).await;
}

#[tokio::test]
async fn a_post_handshake_protocol_error_keeps_the_connection_open() {
    // §7.5's explicit rule and the one most likely to be got backwards.
    let d = TestDaemon::start("keepopen").await;
    let (s, pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut c).await, ServerFrame::Attached { .. }));

    write_raw_map(&mut c, "Nonsense").await;
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "protocol_violation");
            assert_eq!(frame_kind.as_deref(), Some("Nonsense"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"after\n".to_vec(),
        },
    )
    .await;
    wait_for_written(&pty, b"after\n").await;
}

// -------------------------------------------------------- the stream

#[tokio::test]
async fn attached_precedes_every_output_frame() {
    // §7.5: *"The frame is sent before any `Output` frames."*
    //
    // **Scope, stated honestly.** This kills three mutations: no
    // subscription at all, output ahead of `Attached`, and a partial
    // stream. It does **not** kill a subscription moved a few
    // instructions later than the `Attached` send — that window is
    // sub-microsecond and no test in this file can widen it. What makes
    // the ordering structural rather than a race is that `Attached` is
    // *queued* on the same FIFO the forwarder pushes into, and the
    // subscription is taken before the queue exists; that is asserted by
    // reading, not argued here.
    let d = TestDaemon::start("order").await;
    let (s, pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&s.id)).await;
    assert!(
        matches!(recv(&mut c).await, ServerFrame::Attached { .. }),
        "frame 1 must be Attached"
    );

    let payload = vec![b'q'; 64 * 1024];
    pty.queue_output(&payload);

    // The **byte count**, not merely "an Output arrived": a fan-out that
    // dropped frames delivers a first `Output` and then stops.
    let mut got = 0usize;
    while got < payload.len() {
        match recv(&mut c).await {
            ServerFrame::Output { session, bytes } => {
                assert_eq!(session, s.id, "an Output carried the wrong session id");
                got += bytes.len();
            }
            other => panic!("expected Output, got {other:?}"),
        }
    }
    assert_eq!(got, payload.len());
}

#[tokio::test]
async fn no_attach_reject_is_limit_reached_in_v0_1_0() {
    // §18.4b reserves `limit_reached` for post-v0.1.0. An
    // implementation that quietly enforced a per-session cap would be
    // undetectable otherwise.
    let d = TestDaemon::start("sixteen").await;
    let (s, _pty) = d.session(None);

    let mut clients = Vec::new();
    for i in 0..16 {
        let mut c = d.dial().await;
        send(&mut c, &attach_to(&s.id)).await;
        match recv(&mut c).await {
            ServerFrame::Attached { .. } => {}
            ServerFrame::AttachReject { reason, .. } => {
                panic!("client {i} was refused with {reason}: v0.1.0 has no per-session limit")
            }
            other => panic!("client {i} got {other:?}"),
        }
        clients.push(c);
    }
    assert_eq!(clients.len(), 16);
}

// -------------------------------- fan-out, slow consumer, accounting

#[tokio::test]
async fn output_broadcasts_to_every_attached_client() {
    let d = TestDaemon::start("fanout").await;
    let (s, pty) = d.session(None);

    let mut a = d.dial().await;
    send(&mut a, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut a).await, ServerFrame::Attached { .. }));
    let mut b = d.dial().await;
    send(&mut b, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut b).await, ServerFrame::Attached { .. }));

    pty.queue_output(b"MARK");
    // **Both**, not "at least one": sending to only the first (or only
    // the last) registered client passes a single-client assertion.
    for (name, c) in [("A", &mut a), ("B", &mut b)] {
        match recv(c).await {
            ServerFrame::Output { bytes, .. } => {
                assert_eq!(bytes, b"MARK", "client {name} got the wrong bytes")
            }
            other => panic!("client {name} got {other:?}"),
        }
    }
}

#[tokio::test]
async fn output_does_not_reach_a_connection_that_never_handshook() {
    // **The pairing.** Registering at `accept` rather than at `Attach`
    // is a bug the positive test above cannot see: both attached
    // clients still get the marker.
    let d = TestDaemon::start("silent").await;
    let (s, pty) = d.session(None);

    let mut a = d.dial().await;
    send(&mut a, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut a).await, ServerFrame::Attached { .. }));

    // Opened, and silent.
    let silent = d.dial().await;

    pty.queue_output(b"MARK");
    match recv(&mut a).await {
        ServerFrame::Output { bytes, .. } => assert_eq!(bytes, b"MARK"),
        other => panic!("expected Output, got {other:?}"),
    }

    // `try_read`, not a timeout: `WouldBlock` is a definite "nothing is
    // there", where a timeout that expired would be indistinguishable
    // from a slow daemon.
    let mut buf = [0u8; 1];
    match silent.try_read(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(0) => panic!("the daemon closed a silent connection instead of leaving it idle"),
        other => panic!("a connection that never handshook received data: {other:?}"),
    }
    assert_eq!(
        d.daemon.status().attach_clients,
        1,
        "a socket that never handshook is not an attached client"
    );
}

#[tokio::test]
async fn output_does_not_reach_a_client_attached_to_a_different_session() {
    // The second half of the pairing, and it fails against a *different*
    // bug from the one above: a fan-out keyed on nothing, i.e. one
    // global broadcast.
    let d = TestDaemon::start("twosess").await;
    let (a_sess, a_pty) = d.session(Some("alpha"));
    let (b_sess, b_pty) = d.session(Some("beta"));

    let mut a = d.dial().await;
    send(&mut a, &attach_to(&a_sess.id)).await;
    assert!(matches!(recv(&mut a).await, ServerFrame::Attached { .. }));
    let mut b = d.dial().await;
    send(&mut b, &attach_to(&b_sess.id)).await;
    assert!(matches!(recv(&mut b).await, ServerFrame::Attached { .. }));

    a_pty.queue_output(b"AAAA");
    match recv(&mut a).await {
        ServerFrame::Output { session, bytes } => {
            assert_eq!(session, a_sess.id);
            assert_eq!(bytes, b"AAAA");
        }
        other => panic!("expected Output on A, got {other:?}"),
    }

    // B's own marker, so the assertion is "B received *its* bytes and
    // not A's" rather than "B received nothing", which a dead fan-out
    // also satisfies.
    b_pty.queue_output(b"BBBB");
    match recv(&mut b).await {
        ServerFrame::Output { session, bytes } => {
            assert_eq!(session, b_sess.id);
            assert_eq!(
                bytes, b"BBBB",
                "session A's marker crossed into session B's client"
            );
        }
        other => panic!("expected Output on B, got {other:?}"),
    }
}

#[tokio::test]
async fn an_attach_client_receives_only_bytes_never_offsets() {
    // REQ-D-007 / §4.1: *"raw offsets are not part of the public attach
    // protocol in v0.1.0."* A **field-presence** assertion over the
    // decoded map, not a value assertion — `start`/`end` leaking as two
    // extra keys is invisible to anything that only reads `bytes`.
    let d = TestDaemon::start("nooffsets").await;
    let (s, pty) = d.session(None);

    let mut c = d.dial().await;
    send(&mut c, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut c).await, ServerFrame::Attached { .. }));

    pty.queue_output(b"MARK");
    let body = tokio::time::timeout(Duration::from_secs(5), frame::read_frame_body(&mut c))
        .await
        .expect("no Output within 5s")
        .expect("a frame body");
    let value: ciborium::value::Value =
        holdfast_core::protocol::frame::decode(&body).expect("decodable");
    let ciborium::value::Value::Map(entries) = value else {
        panic!("a frame must encode as a CBOR map");
    };
    let mut keys: Vec<String> = entries
        .iter()
        .map(|(k, _)| k.as_text().expect("text keys").to_string())
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["bytes".to_string(), "session".into(), "type".into()],
        "Output carries exactly type/session/bytes"
    );
}

#[tokio::test]
async fn a_slow_consumer_is_detached_and_the_reader_keeps_running() {
    // §4.3, §11.2. Three assertions, and (b) and (c) are what make this
    // able to fail: detaching the whole *session*, or blocking the
    // reader, both satisfy (a) on its own.
    let d = TestDaemon::start("slow").await;
    let (s, pty) = d.session(None);

    // The client that never reads.
    let mut slow = d.dial().await;
    send(&mut slow, &attach_to(&s.id)).await;
    // Deliberately does **not** read its own `Attached`.

    // A second client that drains everything.
    let mut fast = d.dial().await;
    send(&mut fast, &attach_to(&s.id)).await;
    assert!(matches!(
        recv(&mut fast).await,
        ServerFrame::Attached { .. }
    ));
    let fast_reader = tokio::spawn(async move {
        let mut seen = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_secs(10), frame::read_frame_body(&mut fast))
                .await
            {
                Ok(Ok(body)) => {
                    if let Ok(ServerFrame::Output { bytes, .. }) = decode_server_frame(&body) {
                        seen += bytes.len();
                        if bytes.windows(4).any(|w| w == b"LAST") {
                            return (seen, true);
                        }
                    }
                }
                _ => return (seen, false),
            }
        }
    });

    // Far more than 64 frames, and far more than any socket buffer.
    let head_before = s.buffer_head();
    for _ in 0..400 {
        pty.queue_output(&vec![b'z'; 16 * 1024]);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    pty.queue_output(b"LAST");

    // (a) the slow client is detached. It reads now, drains whatever the
    // socket buffered, and must reach EOF — bounded, so a daemon that
    // kept it attached is a red row rather than a hang.
    let detached = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match frame::read_frame_body(&mut slow).await {
                Ok(_) => continue,
                Err(FrameError::Eof) => return true,
                Err(_) => return false,
            }
        }
    })
    .await;
    assert_eq!(
        detached,
        Ok(true),
        "a client that stopped draining must be detached, not tolerated"
    );

    // (b) the draining client still receives every byte afterwards.
    let (seen, saw_last) = fast_reader.await.expect("reader task");
    assert!(
        saw_last,
        "the draining client stopped receiving when the slow one was detached ({seen} bytes seen)"
    );

    // (c) the session's reader kept running: the ring buffer advanced by
    // everything that was queued.
    assert!(
        s.buffer_head() >= head_before + 400 * 16 * 1024,
        "the PTY reader stalled behind a slow attach client (head {} -> {})",
        head_before,
        s.buffer_head()
    );
}

#[tokio::test]
async fn daemon_status_counts_live_attach_clients() {
    // The hardcoded `0` 0.0.5 shipped passes every test that only checks
    // the empty case, so **the non-zero assertion is the load-bearing
    // one** — and the return to zero is what stops a counter that only
    // ever goes up.
    let d = TestDaemon::start("count").await;
    let (s, _pty) = d.session(None);
    assert_eq!(d.daemon.status().attach_clients, 0);

    let mut a = d.dial().await;
    send(&mut a, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut a).await, ServerFrame::Attached { .. }));
    let mut b = d.dial().await;
    send(&mut b, &attach_to(&s.id)).await;
    assert!(matches!(recv(&mut b).await, ServerFrame::Attached { .. }));
    assert_eq!(d.daemon.status().attach_clients, 2);

    send(&mut a, &ClientFrame::Detach).await;
    send(&mut b, &ClientFrame::Detach).await;
    drop(a);
    drop(b);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while d.daemon.status().attach_clients != 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        d.daemon.status().attach_clients,
        0,
        "detached clients are still counted"
    );
}

// -------------------------------------- the redaction role (§9.2, Task 7)

/// A GitHub token matching the shipped `github-token` rule, whose kind —
/// and therefore whose marker — is `github`.
const GH_TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

/// Accumulate `Output` bytes until `needle` appears, or fail.
///
/// Returns the whole stream seen, because every assertion below is about
/// what did **and did not** cross the socket, and a helper that returned
/// only the last frame would make the negative half unwritable.
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
            other => panic!("expected Output, got {other:?}"),
        }
        if acc.windows(needle.len()).any(|w| w == needle) {
            return acc;
        }
    }
    panic!(
        "{:?} never arrived; stream so far ({} bytes): {:?}",
        String::from_utf8_lossy(needle),
        acc.len(),
        String::from_utf8_lossy(&acc[acc.len().saturating_sub(256)..])
    );
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// An RSA-2048-shaped PEM: far past the 512-byte bound an earlier
/// revision of the carry used, which is the whole point of the fixture.
fn rsa_pem() -> Vec<u8> {
    let mut v = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
    while v.len() < 1700 {
        v.extend_from_slice(b"MIIEpAIBAAKCAQEA7uJ8xk3nQ2s5vT1wY0zL9pR4bN6cH8dF2gJ5kM7nP0qS3tU\n");
    }
    v.extend_from_slice(b"-----END RSA PRIVATE KEY-----\n");
    v
}

#[tokio::test]
async fn the_same_bytes_reach_an_interactive_client_raw_and_an_observer_redacted() {
    // **The load-bearing pairing.** One session, one token printed once,
    // two clients attached simultaneously. "Redact everybody" fails the
    // first assertion and "redact nobody" fails the second; neither can
    // pass both.
    let d = TestDaemon::start("roleraw").await;
    let (s, pty) = d.session(None);

    let mut raw = d.dial().await;
    send(
        &mut raw,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Interactive),
    )
    .await;
    assert!(matches!(recv(&mut raw).await, ServerFrame::Attached { .. }));

    let mut watch = d.dial().await;
    send(
        &mut watch,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Observer),
    )
    .await;
    assert!(matches!(
        recv(&mut watch).await,
        ServerFrame::Attached { .. }
    ));

    pty.queue_output(format!("token={GH_TOKEN}\nEOM\n").as_bytes());

    let raw_seen = stream_until(&mut raw, b"EOM", 5).await;
    assert!(
        contains(&raw_seen, GH_TOKEN.as_bytes()),
        "the interactive client did not get raw fidelity: {:?}",
        String::from_utf8_lossy(&raw_seen)
    );

    let watched = stream_until(&mut watch, b"EOM", 5).await;
    assert!(
        contains(&watched, b"[REDACTED:github]"),
        "the observer got no marker: {:?}",
        String::from_utf8_lossy(&watched)
    );
    assert!(
        !contains(&watched, GH_TOKEN.as_bytes()),
        "the token reached an observer"
    );
}

#[tokio::test]
async fn the_role_is_read_from_the_frame_not_inferred_from_the_mode() {
    // §7.5's orthogonality paragraph. Inferring `role` from `mode` passes
    // every test that only exercises the two conventional pairings, which
    // is exactly why both unconventional ones are here.
    let d = TestDaemon::start("roleorth").await;
    let (s, pty) = d.session(None);

    let mut ro_raw = d.dial().await;
    send(
        &mut ro_raw,
        &attach_as(&s.id, AttachMode::ReadOnly, AttachRole::Interactive),
    )
    .await;
    assert!(matches!(
        recv(&mut ro_raw).await,
        ServerFrame::Attached { .. }
    ));

    let mut rw_redacted = d.dial().await;
    send(
        &mut rw_redacted,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Observer),
    )
    .await;
    assert!(matches!(
        recv(&mut rw_redacted).await,
        ServerFrame::Attached { .. }
    ));

    pty.queue_output(format!("token={GH_TOKEN}\nEOM\n").as_bytes());

    let ro_seen = stream_until(&mut ro_raw, b"EOM", 5).await;
    assert!(
        contains(&ro_seen, GH_TOKEN.as_bytes()),
        "ReadOnly + interactive was redacted: role was inferred from mode"
    );
    let rw_seen = stream_until(&mut rw_redacted, b"EOM", 5).await;
    assert!(
        !contains(&rw_seen, GH_TOKEN.as_bytes()),
        "ReadWrite + observer got raw bytes: role was inferred from mode"
    );
    assert!(contains(&rw_seen, b"[REDACTED:github]"));
}

#[tokio::test]
async fn a_secret_split_across_two_chunks_is_still_redacted() {
    // Per-chunk redaction with no carry is invisible to a single-chunk
    // test: each half matches nothing on its own.
    let d = TestDaemon::start("straddle").await;
    let (s, pty) = d.session(None);

    let mut watch = d.dial().await;
    send(
        &mut watch,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Observer),
    )
    .await;
    assert!(matches!(
        recv(&mut watch).await,
        ServerFrame::Attached { .. }
    ));

    let (head, tail) = GH_TOKEN.split_at(10);
    pty.queue_output(head.as_bytes());
    tokio::time::sleep(Duration::from_millis(50)).await;
    pty.queue_output(format!("{tail}\nEOM\n").as_bytes());

    let seen = stream_until(&mut watch, b"EOM", 5).await;
    assert!(
        !contains(&seen, GH_TOKEN.as_bytes()),
        "the straddled token crossed the socket whole"
    );
    assert!(
        !contains(&seen, b"ghp_"),
        "the first half was streamed before it could be judged: {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert_eq!(
        String::from_utf8_lossy(&seen)
            .matches("[REDACTED:github]")
            .count(),
        1
    );
}

#[tokio::test]
async fn ordinary_output_is_never_held_back_from_an_observer() {
    // 0.0.3's REQ-O-003 regression guard, restated for the stream: the
    // holdback is *targeted*, so output with no secret-shaped prefix is
    // never delayed and never dropped.
    //
    // The mutation this kills is a blanket holdback, and what kills it is
    // **completeness** — under a blanket carry the sentinel never
    // arrives at all and `stream_until` fails. The elapsed bound is
    // deliberately loose beside it: a 250 ms assertion on a loaded box is
    // a flake, not a guard.
    let d = TestDaemon::start("noholdback").await;
    let (s, pty) = d.session(None);

    let mut watch = d.dial().await;
    send(
        &mut watch,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Observer),
    )
    .await;
    assert!(matches!(
        recv(&mut watch).await,
        ServerFrame::Attached { .. }
    ));

    let mut payload = Vec::new();
    let mut line = 0u32;
    while payload.len() < 256 * 1024 {
        payload.extend_from_slice(format!("   Compiling widget v0.{line}.0\n").as_bytes());
        line += 1;
    }
    payload.extend_from_slice(b"EOM\n");
    let started = std::time::Instant::now();
    pty.queue_output(&payload);

    let seen = stream_until(&mut watch, b"EOM", 10).await;
    let elapsed = started.elapsed();
    assert_eq!(
        seen.len(),
        payload.len(),
        "an observer lost bytes that no rule claimed"
    );
    assert_eq!(seen, payload, "an observer's bytes were altered");
    assert!(
        elapsed < Duration::from_secs(3),
        "256 KiB of ordinary output took {elapsed:?} to reach an observer"
    );
}

#[tokio::test]
async fn a_private_key_longer_than_the_old_carry_is_redacted_not_streamed() {
    // **The size fixture a 512-byte carry could not judge**: it flushes
    // the body at byte 512 and redacts nothing after it. Neither this row
    // nor the 40-byte straddle above is reachable from the other — that
    // one fits inside any bound.
    let d = TestDaemon::start("pemwatch").await;
    let (s, pty) = d.session(None);

    let mut raw = d.dial().await;
    send(
        &mut raw,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Interactive),
    )
    .await;
    assert!(matches!(recv(&mut raw).await, ServerFrame::Attached { .. }));

    let mut watch = d.dial().await;
    send(
        &mut watch,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Observer),
    )
    .await;
    assert!(matches!(
        recv(&mut watch).await,
        ServerFrame::Attached { .. }
    ));

    let key = rsa_pem();
    let mut payload = key.clone();
    payload.extend_from_slice(b"EOM\n");
    pty.queue_output(&payload);

    let body = &key[40..key.len() - 40];
    let watched = stream_until(&mut watch, b"EOM", 10).await;
    assert!(
        contains(&watched, b"[REDACTED:private-key]"),
        "the observer got no marker for a whole PEM"
    );
    for w in body.windows(16).step_by(31) {
        assert!(
            !contains(&watched, w),
            "16 bytes of the key body reached an observer: {:?}",
            String::from_utf8_lossy(w)
        );
    }

    // The pairing: the interactive client on the same session does get
    // the body verbatim, so the absence above is a decision and not a
    // dead stream.
    let raw_seen = stream_until(&mut raw, b"EOM", 10).await;
    assert!(
        contains(&raw_seen, body),
        "the interactive client lost the key body it is supposed to render"
    );
}

// ------------------------------------------- ReadOnly enforcement (§7.5)

/// The four write frames §7.5's ReadOnly rule ranges over, each paired
/// with the `frame_kind` string it must be refused under.
///
/// One list, used by both the refusal test and its ReadWrite pairing, so
/// the two cannot drift apart into asserting different frames — which is
/// how "reject everything" survives a pairing that exercises a smaller
/// set on the permitted side.
fn write_frames() -> Vec<(ClientFrame, &'static str)> {
    vec![
        (
            ClientFrame::Input {
                bytes: b"XYZZY\n".to_vec(),
            },
            "Input",
        ),
        (
            ClientFrame::SecretInput {
                request_id: "secreq_none".into(),
                bytes: b"XYZZY\n".to_vec(),
            },
            "SecretInput",
        ),
        (
            ClientFrame::Resize {
                cols: 100,
                rows: 30,
            },
            "Resize",
        ),
        (
            ClientFrame::Signal {
                sig: SignalName::Int,
            },
            "Signal",
        ),
    ]
}

async fn attach_ok(d: &TestDaemon, session: &str, mode: AttachMode) -> UnixStream {
    let mut c = d.dial().await;
    send(&mut c, &attach_as(session, mode, AttachRole::Interactive)).await;
    match recv(&mut c).await {
        ServerFrame::Attached { .. } => c,
        other => panic!("expected Attached for {mode:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn every_write_frame_is_rejected_from_a_readonly_client() {
    // §7.5: *"ReadOnly enforcement is server-side."* All four write
    // frames on **one** connection, so the refusals are also proof that
    // each rejection left the connection usable for the next frame.
    let d = TestDaemon::start("rowrite").await;
    let (s, pty) = d.session(None);

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    for (f, kind) in write_frames() {
        send(&mut c, &f).await;
        match recv(&mut c).await {
            ServerFrame::ProtocolError { reason, frame_kind } => {
                assert_eq!(reason, "read_only_attach", "{kind} was not refused");
                // §7.5: *"`frame_kind` echoes which one"*. A single
                // generic rejection carrying a fixed string passes a
                // `reason`-only assertion for all four.
                assert_eq!(
                    frame_kind.as_deref(),
                    Some(kind),
                    "the refusal named the wrong frame"
                );
            }
            other => panic!("{kind} from a ReadOnly client got {other:?}"),
        }
    }

    // §4.3: a refused frame reaches neither the PTY, nor the signal
    // path, nor the session's geometry. Asserting only the frame leaves
    // "answer `read_only_attach` **and** apply it" passing.
    //
    // **The PTY line below is a supplement, not the guard, and it was
    // measured that way.** An `Input` that fell through to the write
    // queue arrives asynchronously, so this assertion can run before it
    // lands: injecting exactly that bug ("refuse and apply anyway") left
    // this row green and turned only `a_rejected_frame_does_not_reach_
    // the_pty` red — which establishes a happens-before by waiting for a
    // *ReadWrite* client's marker first. The two below it are different:
    // `signal` and `resize` are applied inline in the read loop, so they
    // have landed by the time the refusal frame is on the wire.
    assert!(
        pty.written().is_empty(),
        "a refused Input reached the child: {:?}",
        String::from_utf8_lossy(&pty.written())
    );
    assert!(
        pty.signals().is_empty(),
        "a refused Signal was delivered: {:?}",
        pty.signals()
    );
    assert_eq!(
        s.size(),
        (120, 40),
        "a refused Resize changed the session's geometry"
    );
}

#[tokio::test]
async fn the_identical_frames_are_accepted_from_a_readwrite_client() {
    // **The pairing.** The same four frames, the same bytes, the same
    // session — and no `read_only_attach`. Without this, "refuse every
    // write frame from everybody" passes the row above completely.
    //
    // What is asserted per frame is the *absence of the mode refusal*
    // plus `Input`'s effect; the observable effects of `Resize` and
    // `Signal` are asserted by Task 9's rows, which is the commit that
    // routes them. `SecretInput` is permitted to answer
    // `unknown_request_id` (§18.4) once Task 10 lands — that is a refusal
    // about *state*, not about mode, and tolerating it here is what keeps
    // this row true across that commit instead of turning it red for the
    // right behaviour.
    let d = TestDaemon::start("rwwrite").await;
    let (s, pty) = d.session(None);

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    for (f, _kind) in write_frames() {
        send(&mut c, &f).await;
    }
    drain_until_marker(&mut c, &pty, b"RWOK").await;

    wait_for_written(&pty, b"XYZZY\n").await;
}

/// Queue `marker` on the PTY and drain the connection until it arrives,
/// returning every frame seen on the way.
///
/// The frames are read in FIFO order off the connection's own queue, so
/// anything the daemon answered to a frame sent *before* the marker was
/// queued is in the returned vector. A `read_only_attach` hiding behind
/// the marker is what this exists to surface.
async fn drain_until_marker(c: &mut UnixStream, pty: &Arc<MockPty>, marker: &[u8]) {
    // The daemon has to have processed the frames already sent before the
    // marker is queued, or the ordering argument above is not available.
    tokio::time::sleep(Duration::from_millis(100)).await;
    pty.queue_output(marker);
    loop {
        let f = recv(c).await;
        if let ServerFrame::ProtocolError { reason, frame_kind } = &f {
            assert_ne!(
                reason, "read_only_attach",
                "a ReadWrite connection was refused as ReadOnly ({frame_kind:?})"
            );
        }
        if matches!(&f, ServerFrame::Output { bytes, .. } if bytes.windows(marker.len()).any(|w| w == marker))
        {
            return;
        }
    }
}

#[tokio::test]
async fn a_rejected_frame_does_not_reach_the_pty() {
    // Replying `ProtocolError` **and** applying the operation is a bug
    // the frame assertion cannot see. The control is the second half:
    // the identical bytes from a ReadWrite client on the same session
    // **do** reach the child, so "nothing ever reaches the PTY" — which
    // satisfies the absence on its own — is red.
    let d = TestDaemon::start("ropty").await;
    let (s, pty) = d.session(None);

    let mut ro = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    send(
        &mut ro,
        &ClientFrame::Input {
            bytes: b"XYZZY\n".to_vec(),
        },
    )
    .await;
    match recv(&mut ro).await {
        ServerFrame::ProtocolError { reason, .. } => assert_eq!(reason, "read_only_attach"),
        other => panic!("expected ProtocolError, got {other:?}"),
    }

    let mut rw = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    send(
        &mut rw,
        &ClientFrame::Input {
            bytes: b"PLUGH\n".to_vec(),
        },
    )
    .await;
    wait_for_written(&pty, b"PLUGH\n").await;

    // The ReadWrite write arrived, so the write path is live and the
    // absence below is a decision rather than a dead channel.
    let written = pty.written();
    assert!(
        !written.windows(5).any(|w| w == b"XYZZY"),
        "the refused bytes reached the child: {:?}",
        String::from_utf8_lossy(&written)
    );
}

#[tokio::test]
async fn the_connection_stays_open_after_a_read_only_rejection() {
    // §18.4: `read_only_attach` does not close. A daemon that dropped the
    // connection would make a ReadOnly client that fat-fingers one
    // keystroke lose its whole stream.
    let d = TestDaemon::start("rostay").await;
    let (s, pty) = d.session(None);

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"nope\n".to_vec(),
        },
    )
    .await;
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, .. } => assert_eq!(reason, "read_only_attach"),
        other => panic!("expected ProtocolError, got {other:?}"),
    }

    pty.queue_output(b"STILLHERE");
    match recv(&mut c).await {
        ServerFrame::Output { bytes, .. } => assert_eq!(bytes, b"STILLHERE"),
        other => panic!("the stream stopped after a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn a_second_attach_is_refused_under_read_only_attach_from_a_readonly_client() {
    // **The reachability pairing for the `Attach` row of the table.**
    // §18.4's `read_only_attach` is *"any frame but `Detach` from a
    // `ReadOnly` client"*, with no carve-out for an out-of-order one — so
    // the gate runs before the `Attach` arm. Check the arm first and
    // `ClientFrameKind::Attach`'s row in the allowlist can never be
    // reached by any input, which is a policy nobody can observe.
    //
    // The ReadWrite half is what stops "answer `read_only_attach` to
    // every second `Attach`" passing: the same frame, a different mode, a
    // different reason.
    let d = TestDaemon::start("roattach").await;
    let (s, _pty) = d.session(None);

    let mut ro = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    send(
        &mut ro,
        &attach_as(&s.id, AttachMode::ReadOnly, AttachRole::Interactive),
    )
    .await;
    match recv(&mut ro).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "read_only_attach");
            assert_eq!(frame_kind.as_deref(), Some("Attach"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }

    let mut rw = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    send(
        &mut rw,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Interactive),
    )
    .await;
    match recv(&mut rw).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(
                reason, "protocol_violation",
                "a second Attach is out of order, not a write"
            );
            assert_eq!(frame_kind.as_deref(), Some("Attach"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
}

#[tokio::test]
async fn detach_is_allowed_from_both_modes() {
    // The one row of the allowlist that is `true`. Gating `Detach` on
    // mode strands a ReadOnly client with no way to leave except killing
    // the process.
    let d = TestDaemon::start("rodetach").await;
    let (s, _pty) = d.session(None);

    for mode in [AttachMode::ReadOnly, AttachMode::ReadWrite] {
        let mut c = attach_ok(&d, &s.id, mode).await;
        send(&mut c, &ClientFrame::Detach).await;
        expect_eof(&mut c, "a Detach").await;
        // The **session** outlives the client, in both modes. A `Detach`
        // that took the session down with it would satisfy the EOF above.
        assert!(s.is_alive(), "Detach from {mode:?} ended the session");
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while d.daemon.status().attach_clients != 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(d.daemon.status().attach_clients, 0);
    assert_daemon_survives(&d, &s.id).await;
}

// ------------------------------------------------------------ helpers

/// Write a CBOR map `{"type": <name>}` by hand.
///
/// Hand-built rather than encoded from `ClientFrame`, because the whole
/// point is a `type` the enum cannot express.
async fn write_raw_map(s: &mut UnixStream, type_name: &str) {
    let value = ciborium::value::Value::Map(vec![(
        ciborium::value::Value::Text("type".into()),
        ciborium::value::Value::Text(type_name.into()),
    )]);
    frame::write_frame(s, &value).await.expect("write raw map");
}

/// Poll until the child has been written `needle`, or fail.
async fn wait_for_written(pty: &Arc<MockPty>, needle: &[u8]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let w = pty.written();
        if w.windows(needle.len()).any(|c| c == needle) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "input never reached the PTY; child saw {:?}",
        String::from_utf8_lossy(&pty.written())
    );
}
