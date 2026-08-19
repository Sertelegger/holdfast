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
use holdfast_core::attach::{AttachMode, AttachRole};
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
    ClientFrame::Attach {
        session: session.to_string(),
        mode: AttachMode::ReadWrite,
        role: AttachRole::Interactive,
        client_kind: ClientKind::Cli,
        client_version: "test".into(),
        protocol_major,
        protocol_minor: PROTOCOL_MINOR,
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
