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
use holdfast_core::clock::Clock;
use holdfast_core::daemon::attach_server;
use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::server::{self, Daemon};
use holdfast_core::protocol::client::ControlClient;
use holdfast_core::protocol::frame::{self, FrameError, MAX_FRAME_BYTES};
use holdfast_core::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use holdfast_core::pty::{InProcessPty, MockPty, PtyBackend, PtySpawnConfig, Signal};
use holdfast_core::session::{new_session_id, Reaper, Session, SessionConfig};
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
        Self::start_with(tag, Clock::system()).await
    }

    /// A daemon whose clock is the caller's, so a test can drive the idle
    /// reaper instead of sleeping past a 30-second scan interval.
    async fn start_with(tag: &str, clock: Clock) -> Self {
        let paths = RuntimePaths::with_dir(scratch_dir(tag));
        let (control, _c) = server::bind_control(&paths).expect("bind control.sock");
        let (attach, _a) = attach_server::bind_attach(&paths).expect("bind attach.sock");
        let daemon = Daemon::with_clock(paths.clone(), clock);
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
        self.session_backed(name, Arc::new(MockPty::new()), SessionConfig::default())
    }

    fn session_backed(
        &self,
        name: Option<&str>,
        pty: Arc<MockPty>,
        cfg: SessionConfig,
    ) -> (Arc<Session>, Arc<MockPty>) {
        let s = Session::new(
            new_session_id(),
            name.map(String::from),
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                buffer_capacity: 256 * 1024,
                ..cfg
            },
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        (s, pty)
    }

    /// A session on an arbitrary backend, for the one row that needs a
    /// child which does not die the instant it is signalled.
    fn session_on(&self, backend: Arc<dyn PtyBackend>) -> Arc<Session> {
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            backend,
            SessionConfig::with_buffer_capacity(256 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        s
    }

    /// A session on a **real** PTY running a real shell.
    ///
    /// Three of Task 9's rows are not writable against `MockPty`: an echo
    /// comes from the tty and not from us, `stty size` is the only reading
    /// of the geometry the child itself can see, and §4.4's foreground
    /// group is a property of a real process tree. Everything else here
    /// stays on the mock, where the assertions are deterministic.
    fn real_session(&self) -> Arc<Session> {
        self.real_session_running("bash", &["--norc", "--noprofile"])
    }

    fn real_session_running(&self, command: &str, args: &[&str]) -> Arc<Session> {
        let mut cfg = PtySpawnConfig::new(command);
        cfg.args = args.iter().map(|a| (*a).to_string()).collect();
        let pty = InProcessPty::spawn(&cfg).expect("spawn a real shell");
        let s = Session::new(
            new_session_id(),
            None,
            command.into(),
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
            // The two secret-request edges are out of band and may
            // interleave with output on any connection; the tests that
            // care about *them* read them with `recv` and assert their
            // order there. Everything else is still a failure, because a
            // `Resize` or a `ProtocolError` arriving mid-stream is a
            // defect in whatever row is running.
            ServerFrame::AwaitingSecret { .. } | ServerFrame::SecretRequestClosed { .. } => {}
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

    // **Queued in pieces on purpose.** A whole PEM delivered in one read
    // completes its match inside a single window, so nothing is ever
    // carried and the size of the carry bound cannot matter — measured,
    // a single-chunk version of this row stays green with the bound
    // shrunk to 512. In pieces the partial stays open across chunks and
    // the carry has to hold the whole ~1.7 KiB body.
    let key = rsa_pem();
    for piece in key.chunks(256) {
        pty.queue_output(piece);
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    pty.queue_output(b"EOM\n");

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

// ------------------------------- write frames: Input, Resize, Signal

#[tokio::test]
async fn a_keystroke_from_an_attached_client_is_echoed_by_the_pty() {
    // **The echo comes from the tty, not from us**, so the assertion that
    // distinguishes "we wrote to the PTY" from "we wrote to the ring
    // buffer" is the child's *reaction*. `ZZ''TOP` echoes with the quotes
    // and prints without them, so the two are separately visible: the
    // first proves the bytes reached the terminal, the second proves the
    // shell ran them.
    let d = TestDaemon::start("keystroke").await;
    let s = d.real_session();

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"echo ZZ''TOP\n".to_vec(),
        },
    )
    .await;

    let seen = stream_until(&mut c, b"ZZTOP\r\n", 10).await;
    assert!(
        contains(&seen, b"ZZ''TOP"),
        "the keystrokes were never echoed by the terminal: {:?}",
        String::from_utf8_lossy(&seen)
    );

    // And the ring buffer has it too — the same bytes, by the same route
    // as any other output.
    let buffered = s.buffer_slice(s.buffer_tail(), s.buffer_head());
    assert!(
        contains(&buffered, b"ZZTOP"),
        "the child's output never reached the ring buffer"
    );
    let _ = s.signal(Signal::Kill);
}

#[tokio::test]
async fn input_from_either_of_two_clients_reaches_the_pty() {
    // §11.2's scenario. Keying the write path to the first-registered
    // client passes a single-client test completely.
    let d = TestDaemon::start("twowrite").await;
    let (s, pty) = d.session(None);

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    send(
        &mut a,
        &ClientFrame::Input {
            bytes: b"FROM_A\n".to_vec(),
        },
    )
    .await;
    send(
        &mut b,
        &ClientFrame::Input {
            bytes: b"FROM_B\n".to_vec(),
        },
    )
    .await;

    wait_for_written(&pty, b"FROM_A\n").await;
    wait_for_written(&pty, b"FROM_B\n").await;
}

#[tokio::test]
async fn a_resize_from_one_client_is_broadcast_to_the_other() {
    // §7.5: *"canonical PTY size, e.g. when another client resizes."*
    // Applying the resize without broadcasting leaves the other terminal
    // rendering at the wrong width with no error anywhere.
    let d = TestDaemon::start("resizebc").await;
    let s = d.real_session();

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    // **Out of range first, and that ordering is the point.** §7.5 says
    // the broadcast carries the *canonical* PTY size. `Session::resize`
    // clamps to §4.2's bounds, so a request nobody can satisfy is the
    // only input that tells "re-read the size from the session" apart
    // from "echo the request back" — every in-range pair, including the
    // 100×30 below, makes the two indistinguishable.
    send(
        &mut a,
        &ClientFrame::Resize {
            cols: 5000,
            rows: 30,
        },
    )
    .await;
    assert_eq!(
        next_resize(&mut b).await,
        (1000, 30),
        "the other client was told the geometry that was asked for rather \
         than the one the terminal got"
    );

    send(
        &mut a,
        &ClientFrame::Resize {
            cols: 100,
            rows: 30,
        },
    )
    .await;
    assert_eq!(
        next_resize(&mut b).await,
        (100, 30),
        "the other client was never told"
    );

    // And the **child** sees it, which is the half a frame-only assertion
    // cannot reach: `stty size` reads the kernel's idea of the window,
    // not ours.
    send(
        &mut a,
        &ClientFrame::Input {
            bytes: b"stty size\n".to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut a, b"30 100", 10).await;
    assert!(contains(&seen, b"30 100"), "the PTY was not resized");
    let _ = s.signal(Signal::Kill);
}

#[tokio::test]
async fn the_resizing_client_does_not_receive_its_own_resize_back() {
    // The negative half. Broadcasting to all makes a client that reflows
    // on every `Resize` loop against itself.
    let d = TestDaemon::start("resizeself").await;
    let (s, pty) = d.session(None);

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    send(
        &mut a,
        &ClientFrame::Resize {
            cols: 100,
            rows: 30,
        },
    )
    .await;
    // B's frame is the happens-before: once the daemon has told B, it has
    // decided what to tell A.
    match recv(&mut b).await {
        ServerFrame::Resize { cols, rows } => assert_eq!((cols, rows), (100, 30)),
        other => panic!("expected Resize on B, got {other:?}"),
    }

    // A gets output, not its own resize back.
    pty.queue_output(b"AFTER");
    match recv(&mut a).await {
        ServerFrame::Output { bytes, .. } => assert_eq!(bytes, b"AFTER"),
        ServerFrame::Resize { .. } => {
            panic!("the resizing client was told about its own resize")
        }
        other => panic!("expected Output on A, got {other:?}"),
    }
    assert_eq!(s.size(), (100, 30));
}

#[tokio::test]
async fn a_signal_frame_reaches_the_foreground_process_group() {
    // §4.4: `int` goes to the **foreground** group (`tcgetpgrp`) — the
    // command being interrupted — and not to the session's pgid, which
    // would take the shell hosting it down too. A test that only asserts
    // "something died" cannot tell those apart, so both halves are here.
    let d = TestDaemon::start("fgsignal").await;
    let s = d.real_session();

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"sleep 300\n".to_vec(),
        },
    )
    .await;
    // The echoed command line proves the shell has it; the sleep is now
    // the foreground job.
    stream_until(&mut c, b"sleep 300", 10).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    send(
        &mut c,
        &ClientFrame::Signal {
            sig: SignalName::Int,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // **Not "the sleep printed something next"**: an interactive bash
    // abandons the whole command line on SIGINT, so `sleep 300; echo X`
    // never reaches the `echo` — measured, and it is the shell's
    // behaviour rather than ours. What proves the `sleep` died is that
    // the shell is prompting again and runs the next thing it is given,
    // inside seconds rather than five minutes.
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"echo SHELL''_ALIVE\n".to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut c, b"SHELL_ALIVE\r\n", 10).await;
    assert!(contains(&seen, b"SHELL_ALIVE"));
    // …and the shell itself is still there, which is the half that fails
    // when `pgid` is signalled instead of `tcgetpgrp`.
    assert!(
        s.is_alive(),
        "the interrupt took the session's shell down with the job"
    );
    let _ = s.signal(Signal::Kill);
}

/// The next `Resize` frame on this connection, skipping output.
async fn next_resize(c: &mut UnixStream) -> (u16, u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match recv(c).await {
            ServerFrame::Resize { cols, rows } => return (cols, rows),
            ServerFrame::Output { .. } => {}
            other => panic!("expected Resize, got {other:?}"),
        }
    }
    panic!("no Resize arrived within 5s");
}

/// Write a `Signal` frame by hand so `sig` can be something the enum
/// cannot express.
async fn write_raw_signal(s: &mut UnixStream, sig: ciborium::value::Value) {
    let value = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("type".into()),
            ciborium::value::Value::Text("Signal".into()),
        ),
        (ciborium::value::Value::Text("sig".into()), sig),
    ]);
    frame::write_frame(s, &value)
        .await
        .expect("write raw signal");
}

#[tokio::test]
async fn signal_wire_names_are_the_three_documented_values() {
    // §18.4c's closed set, and §11.2's adversarial list by name. The
    // mutation is accepting arbitrary signal names — a remote `kill -9`
    // primitive with no enumeration — and `"stop"` is on the list because
    // Holdfast exposes no `cont` on any surface, so SIGSTOP would be an
    // unrecoverable session reachable from any ReadWrite client.
    let d = TestDaemon::start("signames").await;
    let (good, good_pty) = d.session(None);
    let (bad, bad_pty) = d.session(None);

    // The three that are real, in catalogue order, delivered to the
    // backend as the three `pty::Signal` values.
    let mut g = attach_ok(&d, &good.id, AttachMode::ReadWrite).await;
    for sig in [SignalName::Int, SignalName::Term, SignalName::Kill] {
        send(&mut g, &ClientFrame::Signal { sig }).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while good_pty.signals().len() < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        good_pty.signals(),
        vec![Signal::Interrupt, Signal::Terminate, Signal::Kill],
        "the three wire names did not map onto the three §4.4 deliveries"
    );

    // Everything else: refused by name, nothing delivered, nothing bumped.
    let mut c = attach_ok(&d, &bad.id, AttachMode::ReadWrite).await;
    let before = bad.last_activity_ms();
    for sig in [
        ciborium::value::Value::Text("stop".into()),
        ciborium::value::Value::Text("cont".into()),
        ciborium::value::Value::Text("9".into()),
        ciborium::value::Value::Integer(9.into()),
    ] {
        write_raw_signal(&mut c, sig.clone()).await;
        match recv(&mut c).await {
            ServerFrame::ProtocolError { reason, frame_kind } => {
                assert_eq!(reason, "protocol_violation", "for sig {sig:?}");
                // A `reason`-only assertion passes against an
                // implementation that cannot name the frame at all, which
                // is what the whole `BadFields` split is for.
                assert_eq!(
                    frame_kind.as_deref(),
                    Some("Signal"),
                    "the refusal did not name the frame, for sig {sig:?}"
                );
            }
            other => panic!("sig {sig:?} got {other:?}"),
        }
        assert!(
            bad_pty.signals().is_empty(),
            "a signal was delivered for {sig:?}"
        );
        assert!(bad.is_alive(), "the child died for {sig:?}");
        assert_eq!(
            bad.last_activity_ms(),
            before,
            "a rejected frame bumped last_activity for {sig:?}"
        );
    }

    // The connection is still open: a following valid frame is answered.
    send(
        &mut c,
        &ClientFrame::Input {
            bytes: b"STILL_HERE\n".to_vec(),
        },
    )
    .await;
    wait_for_written(&bad_pty, b"STILL_HERE\n").await;
}

#[tokio::test]
async fn term_does_not_escalate_to_kill() {
    // REQ-D-008 / §18.4c. The escalating form with its `timeout_secs` is
    // the `terminate` **tool**, and the two are deliberately not the same
    // operation.
    //
    // On a `MockPty` that traps SIGTERM rather than a real shell with
    // `trap '' TERM`: the mock models exactly that (`ignoring_terminate`)
    // and lets the assertion be *"the signal list is `[Terminate]` and
    // nothing else"* rather than "still alive after 3 s of sleeping",
    // which is both slower and weaker — a helpful escalation 4 s later
    // would pass it.
    let d = TestDaemon::start("noescalate").await;
    let (s, pty) = d.session_backed(
        None,
        Arc::new(MockPty::ignoring_terminate()),
        SessionConfig::default(),
    );

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    send(
        &mut c,
        &ClientFrame::Signal {
            sig: SignalName::Term,
        },
    )
    .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while pty.signals().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert_eq!(
        pty.signals(),
        vec![Signal::Terminate],
        "term escalated on its own"
    );
    assert!(s.is_alive(), "the child that ignores SIGTERM was killed");

    // The pairing: without it, "term does nothing at all" passes.
    send(
        &mut c,
        &ClientFrame::Signal {
            sig: SignalName::Kill,
        },
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while s.is_alive() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!s.is_alive(), "an explicit kill did not end it");
}

#[tokio::test]
async fn a_session_ended_by_a_signal_frame_is_audited_as_attach_signal() {
    // §9.4 / REQ-D-008: a session a human killed from an attached client
    // is not logged as one that ended on its own.
    //
    // **The plan pairs this with "an ordinary child exit asserted as
    // `child_exit`", and that pairing is unwritable here**: no writer for
    // `session_terminate` exists anywhere in the tree, and Task 9's own
    // instruction is to add the `attach_signal` case only and leave the
    // other five reasons to their owners. The achievable pairing — and
    // the one that still kills "log everything as attach_signal" — is a
    // second session that exits on its own and produces **no**
    // `session_terminate` line at all.
    let d = TestDaemon::start("auditsig").await;
    let (killed, _kpty) = d.session(None);
    let (natural, npty) = d.session(None);
    let (interrupted, ipty) = d.session(None);

    let mut c = attach_ok(&d, &killed.id, AttachMode::ReadWrite).await;
    send(
        &mut c,
        &ClientFrame::Signal {
            sig: SignalName::Kill,
        },
    )
    .await;

    // A signal that does **not** end a session, which is what stops "log
    // every Signal frame as a session_terminate" passing: §9.4's entry is
    // written when a session *ends* because of one.
    let mut i = attach_ok(&d, &interrupted.id, AttachMode::ReadWrite).await;
    send(
        &mut i,
        &ClientFrame::Signal {
            sig: SignalName::Int,
        },
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while ipty.signals().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(ipty.signals(), vec![Signal::Interrupt]);
    assert!(interrupted.is_alive());

    // The other session ends by itself, with nobody attached.
    npty.exit(3);

    let log = d.paths.audit_log();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut lines = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        lines = text
            .lines()
            .filter(|l| l.contains("session_terminate"))
            .map(str::to_string)
            .collect();
        if !lines.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        lines.len(),
        1,
        "expected exactly one session_terminate entry, got {lines:?}"
    );
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("an audit line is JSON");
    assert_eq!(entry["kind"], "session_terminate");
    assert_eq!(entry["session_id"], killed.id.as_str());
    assert_eq!(
        entry["reason"], "attach_signal",
        "a session ended from an attached client was not attributed to it"
    );
    assert_eq!(
        entry["signal"], "kill",
        "which of the three is not recorded"
    );
    assert_eq!(
        entry["force"], false,
        "force belongs to the escalating terminate tool, which this is not"
    );
    assert!(
        !lines[0].contains(natural.id.as_str()),
        "a session that ended on its own was logged as attach_signal"
    );
    assert!(
        !lines[0].contains(interrupted.id.as_str()),
        "a signal that did not end a session was logged as a termination"
    );
}

#[tokio::test]
async fn a_rejected_readonly_frame_does_not_extend_the_idle_deadline() {
    // REQ-C-005 / REQ-S-006: a watching client cannot keep a session
    // alive. **The clock is driven, not slept through** — 0.0.5's reaper
    // scans every ~30 s off an injectable clock, so a wall-clock version
    // of this either hangs or passes vacuously.
    //
    // This row is Task 8's and lands here because its second half is not
    // writable until this commit: nothing bumps `last_activity` on a
    // `Resize` until the frame is routed, so the ReadWrite pairing would
    // have been red at Task 8 for the right reason.
    let clock = Clock::manual(std::time::Instant::now());
    let d = TestDaemon::start_with("roidle", clock.clone()).await;

    let cfg = SessionConfig {
        idle_timeout_secs: 60,
        clock: clock.clone(),
        ..SessionConfig::default()
    };
    let (watched, _wp) = d.session_backed(None, Arc::new(MockPty::new()), cfg.clone());
    let (worked, _kp) = d.session_backed(None, Arc::new(MockPty::new()), cfg);

    let mut ro = attach_ok(&d, &watched.id, AttachMode::ReadOnly).await;
    let mut rw = attach_ok(&d, &worked.id, AttachMode::ReadWrite).await;

    // The same frame from both, at the same points on the clock.
    for _ in 0..3 {
        send(&mut ro, &ClientFrame::Resize { cols: 90, rows: 25 }).await;
        match recv(&mut ro).await {
            ServerFrame::ProtocolError { reason, .. } => assert_eq!(reason, "read_only_attach"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        send(&mut rw, &ClientFrame::Resize { cols: 90, rows: 25 }).await;
        // The ReadWrite one is applied; wait for the effect so the
        // activity stamp is known to have happened before the clock moves.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while worked.size() != (90, 25) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            worked.size(),
            (90, 25),
            "the ReadWrite resize never applied"
        );
        clock.advance(Duration::from_secs(21));
    }

    // 63 s of clock has passed and the timeout is 60 s. One scan.
    let reaper = Reaper::new(Arc::clone(&d.daemon.server.registry), d.daemon.clock());
    assert_eq!(
        reaper.scan_once(),
        1,
        "the ReadOnly-watched session was not reaped, or the busy one was"
    );

    assert!(
        !watched.is_alive(),
        "a rejected frame extended the idle deadline"
    );
    assert!(
        worked.is_alive(),
        "an applied Resize did not count as activity — which is the half \
         that stops 'nothing ever bumps activity' passing"
    );
}

// ------------------------------------- SecretInput (§5.2, §9.5, §9.6)

/// The probe value.
///
/// **Chosen against 0.0.3's defaults, not 0.0.1's.** `read_output` at
/// `HEAD` is ANSI-stripped and secret-redacted by default, so a probe
/// matching a built-in rule would be redacted out of every read surface
/// and the "absent from `read_output`" clause would pass for the wrong
/// reason. `hunter2`-class, deliberately not `ghp_`- or `AKIA`-class.
const PROBE: &str = "hunter2";

/// The next `AwaitingSecret` on this connection, skipping output.
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

#[tokio::test]
async fn awaiting_secret_is_broadcast_when_echo_drops_with_no_agent_call() {
    // REQ-SEC-010: the trigger is the **termios `ECHO` drop**, through
    // 0.0.2's detector, and not a pattern list over output. That is what
    // makes a genuine secret prompt distinguishable from ordinary output
    // that happens to end in `Password:` — and no MCP call is involved,
    // so the agent never learns a secret was solicited.
    let d = TestDaemon::start("awaiting").await;
    let (secret_sess, spty) = d.session(None);
    let (ordinary, opty) = d.session(None);

    let mut a = attach_ok(&d, &secret_sess.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &secret_sess.id, AttachMode::ReadOnly).await;
    let mut plain = attach_ok(&d, &ordinary.id, AttachMode::ReadWrite).await;

    // The edge is computed per read chunk, so the prompt bytes are what
    // makes the daemon look.
    spty.set_echo(Some(false));
    spty.queue_output(b"[sudo] password for ada: ");

    let (id_a, prompt) = next_awaiting_secret(&mut a, 5).await;
    let (id_b, _) = next_awaiting_secret(&mut b, 5).await;
    assert!(id_a.starts_with("secreq_"), "{id_a}");
    assert_eq!(
        id_a, id_b,
        "two clients on one session were told two different request ids"
    );
    assert!(prompt.contains("password for ada"), "{prompt:?}");

    // **The negative half**, without which "broadcast always" passes: an
    // echo-on session's clients hear nothing. Read with `recv` rather
    // than `stream_until`, which *skips* `AwaitingSecret` — measured, a
    // `stream_until` version of this assertion is vacuous and stayed
    // green under "classify every live session as AwaitingSecret".
    opty.queue_output(b"Password: this is just output\n");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut got_output = false;
    while tokio::time::Instant::now() < deadline && !got_output {
        match recv(&mut plain).await {
            ServerFrame::Output { bytes, .. } => {
                got_output = contains(&bytes, b"just output");
            }
            ServerFrame::AwaitingSecret { .. } => {
                panic!("a session whose child never dropped ECHO raised a secret request")
            }
            other => panic!("expected Output, got {other:?}"),
        }
    }
    assert!(got_output, "the ordinary session's output never arrived");
    // **And then keep listening.** The reader publishes a chunk's output
    // to the broadcast *before* it classifies that chunk, so a spurious
    // raise arrives strictly after the `Output` that provoked it —
    // measured: without this drain, "classify every live session as
    // AwaitingSecret" left the loop above green, because it stopped at
    // the marker.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(
            Duration::from_millis(400),
            frame::read_frame_body(&mut plain),
        )
        .await
        {
            Ok(Ok(body)) => {
                if let ServerFrame::AwaitingSecret { .. } =
                    decode_server_frame(&body).expect("decodable")
                {
                    panic!("a session whose child never dropped ECHO raised a secret request");
                }
            }
            _ => break,
        }
    }

    // **And exactly one request while the prompt stays up.** The raise is
    // an *edge*, not a level: more output arriving with echo still off
    // must not re-prompt. A per-chunk raise re-sends the same
    // `request_id` forever, and a client that renders a masked field on
    // each one is unusable — measured, nothing else in this file can see
    // it, because every other row reads one frame and moves on.
    spty.queue_output(b"still waiting");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(400), frame::read_frame_body(&mut a)).await
        {
            Ok(Ok(body)) => match decode_server_frame(&body).expect("decodable") {
                ServerFrame::AwaitingSecret { .. } => {
                    panic!("the request was raised again while it was still outstanding")
                }
                _ => continue,
            },
            _ => break,
        }
    }
}

#[tokio::test]
async fn a_client_attaching_mid_request_receives_the_replay() {
    // §7.5: *"Clients that arrive after the request is in flight receive
    // a replay of the most recent un-fulfilled `AwaitingSecret` frame."*
    // Frame order is `Attached`, then `AwaitingSecret`, then output — and
    // it is structural, because both are queued on the connection's own
    // FIFO before the forwarder exists.
    let d = TestDaemon::start("replay").await;
    let (s, pty) = d.session(None);

    // The echo drops with **nobody** attached, which is also the case
    // where nobody was there to raise the request.
    pty.set_echo(Some(false));
    pty.queue_output(b"Passphrase: ");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !s.is_awaiting_secret() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(s.is_awaiting_secret(), "the fixture never dropped echo");

    let mut c = d.dial().await;
    send(
        &mut c,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Interactive),
    )
    .await;
    match recv(&mut c).await {
        ServerFrame::Attached { .. } => {}
        other => panic!("frame 1 must be Attached, got {other:?}"),
    }
    match recv(&mut c).await {
        ServerFrame::AwaitingSecret { request_id, .. } => {
            assert!(request_id.starts_with("secreq_"), "{request_id}")
        }
        other => panic!("frame 2 must be the replayed AwaitingSecret, got {other:?}"),
    }
}

#[tokio::test]
async fn a_mismatched_request_id_is_rejected_and_writes_nothing() {
    // §18.4's `unknown_request_id`. The connection stays open and the
    // child is still blocked — proved by a later *correct* submission
    // succeeding, which is what stops "reject everything" passing.
    let d = TestDaemon::start("wrongid").await;
    let (s, pty) = d.session(None);

    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    pty.set_echo(Some(false));
    pty.queue_output(b"Password: ");
    let (real_id, _) = next_awaiting_secret(&mut c, 5).await;

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: "secreq_wrong".into(),
            bytes: PROBE.as_bytes().to_vec(),
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
    assert!(
        pty.written().is_empty(),
        "a secret was written for a request nobody raised: {:?}",
        String::from_utf8_lossy(&pty.written())
    );

    // The right id still works, so the refusal was about the id and not
    // about the frame.
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: real_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    wait_for_written(&pty, b"hunter2\n").await;
}

#[tokio::test]
async fn fulfilling_the_request_closes_it_for_every_other_client() {
    // §7.5: a `SecretInput` closes the request immediately, and every
    // client is told — including the ones that were also showing a prompt
    // and must now stop.
    let d = TestDaemon::start("closeall").await;
    let (s, pty) = d.session(None);

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;

    pty.set_echo(Some(false));
    pty.queue_output(b"Password: ");
    let (id, _) = next_awaiting_secret(&mut a, 5).await;
    let (id_b, _) = next_awaiting_secret(&mut b, 5).await;
    assert_eq!(id, id_b);

    send(
        &mut a,
        &ClientFrame::SecretInput {
            request_id: id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    // **B**, which did not submit, is told — and told nothing about the
    // value.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut closed = None;
    while tokio::time::Instant::now() < deadline && closed.is_none() {
        match recv(&mut b).await {
            ServerFrame::SecretRequestClosed {
                request_id,
                outcome,
            } => closed = Some((request_id, outcome)),
            ServerFrame::Output { bytes, .. } => assert!(
                !contains(&bytes, PROBE.as_bytes()),
                "the value was broadcast to another client"
            ),
            other => panic!("expected SecretRequestClosed, got {other:?}"),
        }
    }
    assert_eq!(closed, Some((id, "fulfilled".to_string())));
}

#[tokio::test]
async fn a_secret_input_from_a_readonly_client_is_rejected() {
    // Also in Task 8's table, and asserted here against a **real
    // outstanding request**, so the refusal cannot be an artefact of
    // there being nothing to fulfil.
    let d = TestDaemon::start("rosecret").await;
    let (s, pty) = d.session(None);

    let mut rw = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut ro = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    pty.set_echo(Some(false));
    pty.queue_output(b"Password: ");
    let (id, _) = next_awaiting_secret(&mut rw, 5).await;
    let (id_ro, _) = next_awaiting_secret(&mut ro, 5).await;
    assert_eq!(id, id_ro, "the ReadOnly client sees the same request");

    send(
        &mut ro,
        &ClientFrame::SecretInput {
            request_id: id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    match recv(&mut ro).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "read_only_attach");
            assert_eq!(frame_kind.as_deref(), Some("SecretInput"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
    assert!(
        pty.written().is_empty(),
        "a ReadOnly client's secret reached the child"
    );

    // The request is still open: the refusal did not consume it.
    send(
        &mut rw,
        &ClientFrame::SecretInput {
            request_id: id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    wait_for_written(&pty, b"hunter2\n").await;
}

#[tokio::test]
async fn an_ordinary_input_frame_does_leak_the_same_bytes() {
    // **The control, and it runs first.** Every absence assertion in the
    // row below is worthless unless this one passes: it proves the
    // detector is looking in places where bytes really do show up.
    let d = TestDaemon::start("leakctl").await;
    let s = d.real_session();

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    send(
        &mut a,
        &ClientFrame::Input {
            bytes: format!("echo {PROBE}\n").into_bytes(),
        },
    )
    .await;

    // (a) the second attached client's stream…
    let seen = stream_until(&mut b, PROBE.as_bytes(), 10).await;
    assert!(contains(&seen, PROBE.as_bytes()));
    // (b) …and the ring buffer.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut buffered = Vec::new();
    while tokio::time::Instant::now() < deadline {
        buffered = s.buffer_slice(s.buffer_tail(), s.buffer_head());
        if contains(&buffered, PROBE.as_bytes()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        contains(&buffered, PROBE.as_bytes()),
        "an ordinary Input did not reach the ring buffer, so the absence \
         assertions in the secret row would mean nothing"
    );
    let _ = s.signal(Signal::Kill);
}

#[tokio::test]
async fn a_secret_submitted_over_attach_reaches_the_child_and_none_of_the_surfaces() {
    // **Layer 2 and Layer 3 in one session, because the arrival proof is
    // what makes the absence proof mean anything.** The child transforms
    // the value it read and prints the transform, so "it arrived" is
    // asserted on the child's own output rather than on our having sent
    // it — an implementation that threw the value away satisfies every
    // absence assertion below.
    let d = TestDaemon::start("secretleak").await;
    // **The fixture prints its prompt, and that is not decoration.** The
    // `AwaitingSecret` edge is computed per read chunk, so a child that
    // drops `ECHO` and writes *nothing* raises no request until its next
    // byte of output — measured, `sh -c 'stty -echo; read x'` produces no
    // output at all and the request never fires. Every real secret prompt
    // draws one, which is why the reader loop is where §8.7's edge
    // belongs; the residual is recorded beside the edge in `session`.
    //
    // `stty -echo` and not `read -s`: rev. 36's ICANON rung means a
    // fixture whose shell also clears ICANON does not classify as
    // `AwaitingSecret`, and would fail for a reason that looks like the
    // edge detector being broken.
    let s = d.real_session_running(
        "sh",
        &[
            "-c",
            "stty -echo; printf 'Password: '; read x; stty echo; \
             printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"",
        ],
    );

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut watcher = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;

    let (id, _) = next_awaiting_secret(&mut a, 10).await;
    send(
        &mut a,
        &ClientFrame::SecretInput {
            request_id: id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    // Layer 2: it arrived, exactly.
    let seen = stream_until(&mut a, b"got=HUNTER2", 10).await;
    assert!(contains(&seen, b"got=HUNTER2"));

    // Layer 3, surface 1: the submitting client's own stream never
    // carried the value back (the child had echo off, and we do not echo
    // it either).
    assert!(
        !contains(&seen, PROBE.as_bytes()),
        "the value came back on the submitting client's stream"
    );
    // Surface 2: the second attached client. §9.2: *"no broadcast to
    // other attached clients."*
    let watched = stream_until(&mut watcher, b"got=HUNTER2", 10).await;
    assert!(
        !contains(&watched, PROBE.as_bytes()),
        "the value was broadcast to another attached client"
    );
    // Surface 3: the ring buffer, which `read_output` and `holdfast logs`
    // both read from. Asserted on the raw bytes rather than through
    // `read_output`, which redacts — a redacted read would pass whether
    // or not the value was there.
    let buffered = s.buffer_slice(s.buffer_tail(), s.buffer_head());
    assert!(
        !contains(&buffered, PROBE.as_bytes()),
        "the value reached the ring buffer: {:?}",
        String::from_utf8_lossy(&buffered)
    );
    // Surface 4: the audit log, every line.
    let audit = std::fs::read_to_string(d.paths.audit_log()).unwrap_or_default();
    assert!(
        !audit.contains(PROBE),
        "the value reached the audit log:\n{audit}"
    );
    let _ = s.signal(Signal::Kill);
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

// ------------------------------------ Task 12: §9.4's two attach rows
//
// The audit trail is the only record that an attachment happened at all:
// `Attached` and `Detached` are frames on a socket nobody keeps, and
// `daemon/status`'s `attach_clients` is an instantaneous count. §9.4's
// pair is what makes "who watched this session, in which mode, seeing raw
// or redacted bytes, and for how long" answerable after the fact.

/// Every audit line of one `kind`, parsed, polled until `want` of them
/// exist or a deadline elapses.
///
/// The write happens on the daemon's own task, so a single read taken
/// straight after the frame that caused it is a race. Returning what it
/// found rather than panicking lets a caller assert **fewer** rows than
/// it asked for, which is what the negative rows below need.
async fn audit_entries(d: &TestDaemon, kind: &str, want: usize) -> Vec<serde_json::Value> {
    let path = d.paths.audit_log();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        // `unwrap_or_default`: the file does not exist until something
        // has been recorded, which for a negative row is the point.
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let found: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|e| e["kind"] == kind)
            .collect();
        if found.len() >= want || tokio::time::Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The `role` of each row, sorted, so two clients can be compared without
/// depending on which of them the daemon logged first.
fn roles_of(rows: &[serde_json::Value]) -> Vec<String> {
    let mut r: Vec<String> = rows
        .iter()
        .map(|e| e["role"].as_str().unwrap_or("<no role field>").to_string())
        .collect();
    r.sort();
    r
}

#[tokio::test]
async fn both_attach_audit_rows_carry_the_role() {
    // REQ-SEC-008a's audit clause. §9.4 carries `role` on **both** rows
    // and a normative paragraph beneath the table says so in as many
    // words, because the two entries share no connection identifier:
    // without it, "did this client receive raw output, and for how long?"
    // means pairing connects to disconnects by ordering and hoping.
    //
    // Two clients whose roles **differ** while their `client_kind`
    // agrees, which is what stops a hardcoded `"observer"` passing.
    let d = TestDaemon::start("auditrole").await;
    let (s, _pty) = d.session(None);

    let mut raw = d.dial().await;
    send(
        &mut raw,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Interactive),
    )
    .await;
    assert!(matches!(recv(&mut raw).await, ServerFrame::Attached { .. }));

    let mut obs = d.dial().await;
    send(
        &mut obs,
        &attach_as(&s.id, AttachMode::ReadOnly, AttachRole::Observer),
    )
    .await;
    assert!(matches!(recv(&mut obs).await, ServerFrame::Attached { .. }));

    // **A third client, crossed: `ReadWrite` + `observer`.** Measured —
    // without it, a row that derived `role` from `mode` produced the
    // identical audit trail, because the first two clients use the two
    // *conventional* pairings and nothing distinguished a field that was
    // read from one that was inferred. §7.5's orthogonality paragraph is
    // about exactly this, and Task 7 asserts it for the stream; this is
    // the same claim for the trail.
    let mut crossed = d.dial().await;
    send(
        &mut crossed,
        &attach_as(&s.id, AttachMode::ReadWrite, AttachRole::Observer),
    )
    .await;
    assert!(matches!(
        recv(&mut crossed).await,
        ServerFrame::Attached { .. }
    ));

    send(&mut raw, &ClientFrame::Detach).await;
    send(&mut obs, &ClientFrame::Detach).await;
    send(&mut crossed, &ClientFrame::Detach).await;
    expect_eof(&mut raw, "after Detach").await;
    expect_eof(&mut obs, "after Detach").await;
    expect_eof(&mut crossed, "after Detach").await;

    let connects = audit_entries(&d, "attach_connect", 3).await;
    let disconnects = audit_entries(&d, "attach_disconnect", 3).await;
    assert_eq!(connects.len(), 3, "attach_connect rows: {connects:?}");
    assert_eq!(
        disconnects.len(),
        3,
        "attach_disconnect rows: {disconnects:?}"
    );

    let expected = vec![
        "interactive".to_string(),
        "observer".to_string(),
        "observer".to_string(),
    ];
    assert_eq!(
        roles_of(&connects),
        expected,
        "attach_connect: {connects:?}"
    );
    assert_eq!(
        roles_of(&disconnects),
        expected,
        "attach_disconnect is the half a connect-only assertion cannot \
         see, and rev. 33's normative paragraph exists to prevent exactly \
         its omission: {disconnects:?}"
    );
    // The other half of the pairing: the two clients agree about
    // `client_kind`, so a row that reported `role` by copying
    // `client_kind` would have produced two identical values above.
    for row in connects.iter().chain(disconnects.iter()) {
        assert_eq!(row["client_kind"].as_str(), Some("cli"), "{row:?}");
    }
    // And `mode` is recorded independently of `role` (§7.5's
    // orthogonality): one client is ReadWrite/interactive, the other
    // ReadOnly/observer, so a `mode` derived from `role` would still
    // agree here — but a `mode` that was dropped entirely would not.
    let mut modes: Vec<String> = connects
        .iter()
        .map(|e| e["mode"].as_str().unwrap_or("<no mode>").to_string())
        .collect();
    modes.sort();
    assert_eq!(
        modes,
        vec![
            "ReadOnly".to_string(),
            "ReadWrite".to_string(),
            "ReadWrite".to_string()
        ],
        "§9.4's `mode` column is CamelCase, the wire spelling: {connects:?}"
    );
    // And the crossed client is really crossed on the wire: one row is
    // `ReadWrite` **and** `observer`, which is the pairing a derived
    // `role` cannot produce.
    assert!(
        connects
            .iter()
            .any(|e| e["mode"] == "ReadWrite" && e["role"] == "observer"),
        "the crossed pairing did not survive into the trail: {connects:?}"
    );
    assert!(
        disconnects
            .iter()
            .any(|e| e["mode"] == "ReadWrite" && e["role"] == "observer"),
        "the crossed pairing did not survive into the disconnect row: {disconnects:?}"
    );
}

#[tokio::test]
async fn a_rejected_attach_writes_no_audit_entry() {
    // §9.4: the row is written **after** a successful `Attached`. Logging
    // at accept time would make the trail count probes as connections.
    //
    // **With a positive control on the same daemon**, because "no
    // `attach_connect` line" is also what a daemon that never writes one
    // produces.
    let d = TestDaemon::start("auditreject").await;
    let (s, _pty) = d.session(None);

    let mut bad = d.dial().await;
    send(&mut bad, &attach_to("no-such-session")).await;
    assert!(matches!(
        recv(&mut bad).await,
        ServerFrame::AttachReject { .. }
    ));
    expect_eof(&mut bad, "a rejected attach").await;

    let mut good = d.dial().await;
    send(&mut good, &attach_to(&s.id)).await;
    assert!(matches!(
        recv(&mut good).await,
        ServerFrame::Attached { .. }
    ));

    let rows = audit_entries(&d, "attach_connect", 1).await;
    assert_eq!(
        rows.len(),
        1,
        "exactly the accepted attach is a connection: {rows:?}"
    );
    assert_eq!(
        rows[0]["session_id"].as_str(),
        Some(s.id.as_str()),
        "the one row must be the accepted one: {rows:?}"
    );
}

#[tokio::test]
async fn the_audit_entry_names_the_client_kind_from_the_handshake() {
    // §9.4: `client_kind` comes from the handshake on a uid-checked
    // connection — attribution, never authorisation, and *"must never
    // become a redaction switch"*. The **uid** beside it is the checked
    // one, whatever the client said about itself.
    //
    // Also the `ClientKind::Shim` decision: §9.4's column enumerates
    // `"cli" | "ui-bridge"` and the third variant exists. It is
    // **accepted and recorded verbatim** — refusing a connection over an
    // attribution field would make the log's honesty a connectivity
    // requirement, and the column is the expected set rather than a
    // validator.
    let d = TestDaemon::start("auditkind").await;
    let (s, _pty) = d.session(None);

    for kind in [ClientKind::UiBridge, ClientKind::Shim] {
        let mut c = d.dial().await;
        send(
            &mut c,
            &ClientFrame::Attach {
                session: s.id.clone(),
                mode: AttachMode::ReadOnly,
                role: AttachRole::Observer,
                client_kind: kind,
                client_version: "test".into(),
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
            },
        )
        .await;
        assert!(
            matches!(recv(&mut c).await, ServerFrame::Attached { .. }),
            "{kind:?} must be accepted: the field is attribution, not \
             authorisation"
        );
        send(&mut c, &ClientFrame::Detach).await;
        expect_eof(&mut c, "after Detach").await;
    }

    let rows = audit_entries(&d, "attach_connect", 2).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let mut kinds: Vec<String> = rows
        .iter()
        .map(|e| e["client_kind"].as_str().unwrap_or("<none>").to_string())
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        vec!["shim".to_string(), "ui-bridge".to_string()],
        "recorded verbatim, as declared: {rows:?}"
    );

    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    for row in &rows {
        assert_eq!(
            row["peer_uid"].as_u64(),
            Some(u64::from(me)),
            "the uid is the kernel's, not the client's: {row:?}"
        );
    }
}

/// The next `Detached` on this connection, skipping whatever legitimately
/// precedes it.
///
/// `SessionExited` *does* precede it on the exit path, and an `Output`
/// may. Fails on a deadline rather than hanging.
async fn next_detached(c: &mut UnixStream, secs: u64) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match recv(c).await {
            ServerFrame::Detached { reason } => return reason,
            ServerFrame::Output { .. }
            | ServerFrame::SessionExited { .. }
            | ServerFrame::Resize { .. } => {}
            other => panic!("expected Detached, got {other:?}"),
        }
    }
    panic!("no Detached arrived within {secs}s");
}

#[tokio::test]
async fn each_disconnect_reason_is_recorded_once() {
    // All four §9.4 values, each reachable and each producing exactly one
    // row. Four daemons, because two of the four end the daemon or the
    // session and a shared audit file could not tell whose row was whose.

    // 1. client_detach — audited, and deliberately **not** a wire value.
    {
        let d = TestDaemon::start("reasondetach").await;
        let (s, _pty) = d.session(None);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        send(&mut c, &ClientFrame::Detach).await;
        expect_eof(&mut c, "client detach").await;
        let rows = audit_entries(&d, "attach_disconnect", 1).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reason"].as_str(), Some("client_detach"));
        assert!(
            rows[0]["duration_secs"].as_f64().unwrap_or(0.0) > 0.0,
            "a zero duration means the connect time was never recorded: {:?}",
            rows[0]
        );
    }

    // 2. session_exit.
    {
        let d = TestDaemon::start("reasonexit").await;
        let (_s, pty) = d.session(None);
        let mut c = attach_ok(&d, &_s.id, AttachMode::ReadWrite).await;
        pty.exit(7);
        assert_eq!(next_detached(&mut c, 10).await, "session_exit");
        let rows = audit_entries(&d, "attach_disconnect", 1).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reason"].as_str(), Some("session_exit"));
        assert!(rows[0]["duration_secs"].as_f64().unwrap_or(0.0) > 0.0);
    }

    // 3. daemon_shutdown.
    {
        let d = TestDaemon::start("reasonshutdown").await;
        let (s, _pty) = d.session(None);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        d.daemon.shutdown();
        assert_eq!(next_detached(&mut c, 10).await, "daemon_shutdown");
        let rows = audit_entries(&d, "attach_disconnect", 1).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reason"].as_str(), Some("daemon_shutdown"));
        assert!(rows[0]["duration_secs"].as_f64().unwrap_or(0.0) > 0.0);
    }

    // 4. slow_consumer — Task 6's teardown, which had no audit row at
    // all until this task.
    {
        let d = TestDaemon::start("reasonslow").await;
        let (_s, pty) = d.session(None);
        let mut slow = d.dial().await;
        send(&mut slow, &attach_to(&_s.id)).await;
        // Deliberately never reads, not even its own `Attached`.
        for _ in 0..400 {
            pty.queue_output(&vec![b'z'; 16 * 1024]);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let rows = audit_entries(&d, "attach_disconnect", 1).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reason"].as_str(), Some("slow_consumer"));
        assert!(rows[0]["duration_secs"].as_f64().unwrap_or(0.0) > 0.0);
        drop(slow);
    }
}

// ------------------------- Task 12 Step 3b: REQ-D-009 on the wire
//
// `each_disconnect_reason_is_recorded_once` above drives all four *audit*
// reasons and asserts nothing about the wire, so it passes whatever the
// wire does. §7.5's *Connection teardown* makes four claims the audit
// table cannot see.

#[tokio::test]
async fn a_client_initiated_detach_sends_no_detached_frame() {
    // §11.2, verbatim: *"a client-initiated `Detach` produces no
    // `Detached` at all."* §7.5's reason: *"The client sent `Detach`;
    // there is nobody left to tell."*
    //
    // This is the §23.3 two-products item 0.0.6 introduces: the audit set
    // has four reasons and the wire set has three, which reads as a
    // missing wire value and is exactly the shape a reviewer "fixes" by
    // emitting `Detached { reason: "client_detach" }` before closing. It
    // compiles, breaks nothing visibly, and turns a closed set of three
    // into four on a surface the web UI mirrors verbatim (§7.6.3).
    //
    // **Paired with a daemon-initiated close on the same session that
    // does deliver one**, so "this client never receives anything" cannot
    // pass.
    let d = TestDaemon::start("nodetached").await;
    let (s, pty) = d.session(None);

    let mut leaver = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut stayer = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    send(&mut leaver, &ClientFrame::Detach).await;
    // The very next read. `expect_eof` accepts `Ok(Err(Eof))` only, so a
    // `Detached` arriving here is `Ok(Ok(body))` and the row is red.
    expect_eof(
        &mut leaver,
        "a client-initiated Detach must produce no Detached frame at all",
    )
    .await;

    // The pairing: the same session, a daemon-initiated close, and one
    // does arrive.
    pty.exit(0);
    assert_eq!(
        next_detached(&mut stayer, 10).await,
        "session_exit",
        "the daemon-initiated half must still deliver a Detached, or the \
         assertion above is satisfied by a daemon that never sends one"
    );
}

#[tokio::test]
async fn a_session_exit_sends_session_exited_then_detached_then_closes() {
    // REQ-D-009's order, on both attached clients. §7.5 fixes it because
    // it is what lets a renderer show the exit code **before** it tears
    // the view down; sending only one of the two frames, or sending them
    // the other way round, are the two mutations.
    let d = TestDaemon::start("exitorder").await;
    let (s, pty) = d.session(None);

    let mut a = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut b = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;

    pty.exit(7);

    for (who, c) in [("a", &mut a), ("b", &mut b)] {
        // Frame one: the code. `7`, not a truthy "it ended" — a client
        // believes this number.
        match recv(c).await {
            ServerFrame::SessionExited { code } => assert_eq!(code, 7, "{who}"),
            other => panic!("{who}: expected SessionExited first, got {other:?}"),
        }
        // Frame two: the teardown, and *why*.
        match recv(c).await {
            ServerFrame::Detached { reason } => assert_eq!(reason, "session_exit", "{who}"),
            other => panic!("{who}: expected Detached after SessionExited, got {other:?}"),
        }
        // Frame three: nothing. The socket closes.
        expect_eof(c, "after Detached").await;
    }
}

#[tokio::test]
async fn daemon_shutdown_outranks_session_exit() {
    // Both reasons are technically true when a `daemon/stop` kills a live
    // session, and §7.5 fixes which one the wire carries. Picking
    // whichever fires first is a race — and the wrong answer tells a
    // reconnecting client a child died when the daemon went away.
    //
    // **The fixture is the whole row, and the obvious one cannot fail.**
    // Measured: with `Daemon::shutdown()` and a `MockPty` — which dies
    // inside `signal()` — the flag and the kill happen microseconds
    // apart while the reader thread needs a `READER_IDLE_POLL` to notice,
    // so the shutdown is *always* visible first and the ordering rule is
    // never exercised. A mutation that deleted the tie-break **and**
    // inverted the `select!`'s bias left that version of this row green.
    //
    // `SlowTerminatePty` creates the window the rule exists for: SIGTERM
    // starts a timer, the child dies ~120 ms later, the reader thread
    // sees it within 5 ms, and `shutdown_graceful`'s 50 ms poll has not
    // yet reached its "all dead" break — so the exit is observed *first*
    // and only `shutdown_requested()`, raised at the method's first
    // statement, can still tell the connection why.
    let d = TestDaemon::start("shutdownwins").await;
    let inner = Arc::new(MockPty::new());
    let s =
        d.session_on(Arc::new(SlowTerminatePty::new(Arc::clone(&inner))) as Arc<dyn PtyBackend>);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    d.daemon.shutdown_graceful(Duration::from_secs(10)).await;

    assert_eq!(
        next_detached(&mut c, 10).await,
        "daemon_shutdown",
        "the session ended because the daemon was stopping, and §7.5 says \
         so on the wire — picking whichever event fired first answers \
         `session_exit` here"
    );
    // The fixture really did produce the ordering the row needs: the
    // child was signalled and did end. Without this the row could pass
    // against a daemon that reported `daemon_shutdown` for a session that
    // was never touched.
    assert!(!s.is_alive(), "the fixture's child never died");
}

/// A backend whose child takes its time dying.
///
/// `MockPty::signal` marks the child dead **inside the call**, so with it
/// every shutdown is observed before the death it caused and
/// `daemon_shutdown_outranks_session_exit` has no race to adjudicate.
/// Here `Terminate` starts a timer instead, which is what a real child
/// does.
#[derive(Debug)]
struct SlowTerminatePty {
    inner: Arc<MockPty>,
}

impl SlowTerminatePty {
    fn new(inner: Arc<MockPty>) -> Self {
        Self { inner }
    }
}

impl PtyBackend for SlowTerminatePty {
    fn write(&self, data: &[u8]) -> holdfast_core::Result<()> {
        self.inner.write(data)
    }
    fn read(&self, buf: &mut [u8]) -> holdfast_core::Result<usize> {
        self.inner.read(buf)
    }
    fn signal(&self, sig: Signal) -> holdfast_core::Result<()> {
        if matches!(sig, Signal::Terminate) {
            let inner = Arc::clone(&self.inner);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(120));
                inner.exit(0);
            });
            return Ok(());
        }
        self.inner.signal(sig)
    }
    fn resize(&self, cols: u16, rows: u16) -> holdfast_core::Result<()> {
        self.inner.resize(cols, rows)
    }
    fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }
    fn exit_code(&self) -> Option<i32> {
        self.inner.exit_code()
    }
    fn pid(&self) -> Option<u32> {
        self.inner.pid()
    }
}

#[tokio::test]
async fn a_pre_handshake_close_never_sends_detached() {
    // §7.5: *"`Detached` says this attachment ended, and a rejected
    // connection never had one."* Three refusals, each of which closes,
    // and none of which may be preceded or followed by a `Detached`.
    let d = TestDaemon::start("prehandshake").await;
    let (s, _pty) = d.session(None);

    // 1. An unknown session.
    {
        let mut c = d.dial().await;
        send(&mut c, &attach_to("no-such-session")).await;
        match recv(&mut c).await {
            ServerFrame::AttachReject { reason, .. } => assert_eq!(reason, "session_not_found"),
            other => panic!("expected AttachReject, got {other:?}"),
        }
        expect_eof(&mut c, "an unknown session").await;
    }

    // 2. A non-`Attach` first frame.
    {
        let mut c = d.dial().await;
        send(&mut c, &ClientFrame::Detach).await;
        match recv(&mut c).await {
            ServerFrame::ProtocolError { reason, .. } => assert_eq!(reason, "no_handshake"),
            other => panic!("expected ProtocolError, got {other:?}"),
        }
        expect_eof(&mut c, "a non-Attach first frame").await;
    }

    // 3. An oversized frame. Only the prefix goes on the wire.
    {
        let mut c = d.dial().await;
        let prefix = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        use tokio::io::AsyncWriteExt;
        c.write_all(&prefix).await.expect("write prefix");
        c.flush().await.expect("flush");
        match recv(&mut c).await {
            ServerFrame::ProtocolError { reason, .. } => assert_eq!(reason, "frame_too_large"),
            other => panic!("expected ProtocolError, got {other:?}"),
        }
        expect_eof(&mut c, "an oversized pre-handshake frame").await;
    }

    assert_daemon_survives(&d, &s.id).await;
}
