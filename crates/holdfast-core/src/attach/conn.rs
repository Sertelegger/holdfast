//! One attach connection: §7.5's handshake, session lookup, and the
//! duplex loop that runs until either side stops.
//!
//! **`ProtocolError.reason` is enumerated once, in §18.4, and §7.5
//! defers to it.** The rule, in one sentence: *a post-handshake
//! `ProtocolError` leaves the connection open and the client may
//! continue sending valid frames; a pre-handshake one, **and any
//! frame-cap violation**, closes it.* The five reasons and where each is
//! produced:
//!
//! | `reason` | Closes | Emitted when |
//! |---|---|---|
//! | `read_only_attach` | no | any frame but `Detach` from a `ReadOnly` client |
//! | `unknown_request_id` | no | a `SecretInput` naming no outstanding prompt |
//! | `protocol_violation` | pre-handshake yes, post-handshake no | malformed CBOR, an out-of-order frame, an unknown `type`, or a closed-enum field outside its catalogue. **No part of the frame is applied** |
//! | `no_handshake` | yes (pre-handshake only) | a non-`Attach` initial frame |
//! | `frame_too_large` | **yes, in both phases** | a length prefix over `MAX_FRAME_BYTES` |
//!
//! The last row is the one a blanket *"post-handshake errors never
//! close"* reading loses. A cap applied only to the handshake frame
//! leaves a 16 MiB pre-allocation reachable for the life of every
//! attached connection (REQ-D-002).
//!
//! **A `frame_too_large` close sends no `Detached`, and the reason is
//! the *kind of event*.** REQ-D-009 guarantees exactly one `Detached
//! { reason }` from the closed set `slow_consumer` / `daemon_shutdown` /
//! `session_exit` before every daemon-initiated post-handshake close —
//! except where the close was forced by a **connection-level fault**
//! rather than by an attachment-level event. An attachment-level event
//! (the session ended, the daemon is going away, this client stopped
//! consuming) is what `Detached` exists to name. A connection-level
//! fault (the framing is lost) is the connection failing, and it is
//! stated where the fault is.
//!
//! **Not "the cause was already stated".** That phrasing is wrong and
//! deletes two live frames: on the WebSocket a `slow_consumer` teardown
//! states its cause twice — `Detached { reason: "slow_consumer" }` and
//! close code `1008` — and §18.6 resolves the redundancy the other way
//! round; and on this socket `SessionExited { code }` names the child's
//! end one frame before `Detached { reason: "session_exit" }`, which the
//! same reading would suppress. Adding a fourth `Detached.reason` is
//! equally wrong: it is a wire-shape change on a §23.3 surface the web
//! UI mirrors verbatim.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::frames::{
    AttachMode, AttachRole, ClientDecode, ClientFrame, ClientFrameKind, ServerFrame,
};
use super::handshake::{evaluate_attach, REJECT_SESSION_NOT_FOUND};
use crate::daemon::server::Daemon;
use crate::protocol::frame::{self, FrameError};
use crate::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use crate::session::{Session, SessionState, WriteRequest};

pub use super::hub::{AttachConn, ATTACH_QUEUE_FRAMES};

/// The `Attach` frame's fields, once it is known to be one.
struct Handshake {
    session: String,
    mode: AttachMode,
    role: AttachRole,
    client_kind: ClientKind,
    client_version: String,
    protocol_major: u32,
}

/// Serve one accepted, uid-checked attach connection to completion.
///
/// The peer's credentials were checked by the accept loop **before this
/// is reached and before a byte was parsed** (`daemon::attach_server`),
/// which is the same ordering `control.sock` uses.
pub async fn run(daemon: Arc<Daemon>, stream: UnixStream) {
    let (mut rd, mut wr) = stream.into_split();

    let Some(hs) = read_handshake(&mut rd, &mut wr).await else {
        return;
    };

    // §7.5's version gate, in *both* directions (REQ-D-004a). The same
    // constants `control.sock` advertises, because one daemon advertises
    // one version on both sockets.
    if let Some((reason, message)) = evaluate_attach(hs.protocol_major) {
        let _ = frame::write_frame(
            &mut wr,
            &ServerFrame::AttachReject {
                reason: reason.to_string(),
                message,
            },
        )
        .await;
        return;
    }

    // Id **or** name — 0.0.1's registry resolves both, and `Attached`
    // answers with the canonical id either way.
    let session = match daemon.server.registry.get(&hs.session) {
        Ok(s) => s,
        Err(_) => {
            let _ = frame::write_frame(
                &mut wr,
                &ServerFrame::AttachReject {
                    reason: REJECT_SESSION_NOT_FOUND.to_string(),
                    message: format!("no live session matched {:?}", hs.session),
                },
            )
            .await;
            return;
        }
    };

    // **Subscribe before `Attached` is written.** §7.5: *"The frame is
    // sent before any `Output` frames"* — which is an ordering claim and
    // also a completeness one. Subscribing afterwards is a race that
    // loses whatever the child printed while `Attached` was in flight,
    // and it loses it *silently*: the frames still arrive in the right
    // order, so an ordering-only assertion cannot see it.
    let output = session.subscribe();

    let (tx, rx) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
    let conn = Arc::new(AttachConn {
        client_id: daemon.attach_hub().next_client_id(),
        session_id: session.id.clone(),
        mode: hs.mode,
        role: hs.role,
        client_kind: hs.client_kind,
        client_version: hs.client_version,
        tx: tx.clone(),
        connected_at: Instant::now(),
    });

    // Queued first, so the FIFO is what makes it frame one rather than a
    // timing argument about two tasks.
    if tx.send(attached_frame(&session)).await.is_err() {
        return;
    }

    // **Registered only now**, after the handshake was accepted — never
    // at `accept`. A connection that opened the socket and said nothing
    // is not an attached client, and `daemon/status` counting it would
    // report clients on a session nobody is watching.
    daemon.attach_hub().register(Arc::clone(&conn));

    let writer = tokio::spawn(write_loop(wr, rx));
    let mut forwarder = tokio::spawn(forward_output(conn.session_id.clone(), output, tx.clone()));

    // Either half can end the connection. The forwarder ends it when
    // this client stopped draining (§4.3's slow consumer) or when the
    // socket died under the writer; without the `select!` a detached
    // slow consumer would keep its read half open forever, because the
    // read loop holds a `Sender` and the writer only stops when every
    // `Sender` is gone.
    tokio::select! {
        () = read_loop(&daemon, &session, &conn, &mut rd, &tx) => {}
        _ = &mut forwarder => {}
    }

    daemon
        .attach_hub()
        .unregister(&conn.session_id, conn.client_id);

    // Dropping every `Sender` ends the write loop, which drains what is
    // still queued and *then* closes the socket — so a `ProtocolError`
    // written on the way out reaches the client before the EOF that
    // follows it.
    forwarder.abort();
    drop(tx);
    drop(conn);
    let _ = writer.await;
}

/// Read the mandatory first frame, answering §7.5's two pre-handshake
/// refusals. `None` means the connection is over.
async fn read_handshake(
    rd: &mut tokio::net::unix::OwnedReadHalf,
    wr: &mut tokio::net::unix::OwnedWriteHalf,
) -> Option<Handshake> {
    let body = match frame::read_frame_body(rd).await {
        Ok(b) => b,
        Err(FrameError::TooLarge { .. }) => {
            // Both phases. The framing is lost, so the stream cannot be
            // resynchronised even here, where nothing has been agreed
            // yet.
            let _ = frame::write_frame(wr, &protocol_error("frame_too_large", None)).await;
            return None;
        }
        // A peer that hung up before sending anything is not an error and
        // gets no frame: there is nobody to read it.
        Err(_) => return None,
    };

    match super::frames::decode_client_frame(&body) {
        ClientDecode::Frame(ClientFrame::Attach {
            session,
            mode,
            role,
            client_kind,
            client_version,
            protocol_major,
            protocol_minor: _,
        }) => Some(Handshake {
            session,
            mode,
            role,
            client_kind,
            client_version,
            protocol_major,
        }),
        // A well-formed frame of the wrong kind. §7.5:
        // *"pre-handshake violations close."*
        ClientDecode::Frame(other) => {
            let _ = frame::write_frame(
                wr,
                &protocol_error("no_handshake", Some(other.kind().as_str().to_string())),
            )
            .await;
            None
        }
        ClientDecode::UnknownType(name) => {
            let _ = frame::write_frame(wr, &protocol_error("protocol_violation", Some(name))).await;
            None
        }
        ClientDecode::Malformed => {
            let _ = frame::write_frame(wr, &protocol_error("protocol_violation", None)).await;
            None
        }
    }
}

/// The duplex loop's read half. Returns when the connection is over.
async fn read_loop(
    daemon: &Arc<Daemon>,
    session: &Arc<Session>,
    conn: &AttachConn,
    rd: &mut tokio::net::unix::OwnedReadHalf,
    tx: &mpsc::Sender<ServerFrame>,
) {
    let _ = daemon;
    loop {
        let body = match frame::read_frame_body(rd).await {
            Ok(b) => b,
            Err(FrameError::TooLarge { .. }) => {
                // **Closes, and with no `Detached` before it.** A
                // connection-level fault, not an attachment-level event:
                // the framing is gone and the daemon cannot resynchronise
                // the stream, which is what `ProtocolError` says here.
                let _ = tx.send(protocol_error("frame_too_large", None)).await;
                return;
            }
            Err(_) => return,
        };

        match super::frames::decode_client_frame(&body) {
            ClientDecode::Frame(ClientFrame::Detach) => return,
            ClientDecode::Frame(ClientFrame::Input { bytes }) => {
                // §4.3's queue, not a direct write: it is what serialises
                // two clients typing at once, and a direct write here
                // would be a second door with no ordering relationship to
                // the first.
                let (req, _ack) = WriteRequest::input(bytes);
                if session.write_queue().send(req).await.is_err() {
                    return;
                }
            }
            // Post-handshake, a second `Attach` is an out-of-order frame:
            // §18.4's `protocol_violation`, no part of it applied, and the
            // connection stays open.
            ClientDecode::Frame(ClientFrame::Attach { .. }) => {
                if tx
                    .send(protocol_error(
                        "protocol_violation",
                        Some(ClientFrameKind::Attach.as_str().to_string()),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // `Resize`, `Signal` and `SecretInput` are Task 9's and Task
            // 10's write frames. They are **not** answered
            // `protocol_violation` — they are valid §7.5 frames and
            // saying otherwise would be a wire-level lie a client cannot
            // recover from — and they are not applied here either,
            // because applying a signal without the §9.4
            // `session_terminate` entry REQ-D-008 requires would be worse
            // than not applying it. This arm is the hand-off, written
            // down rather than left as a silent fall-through.
            ClientDecode::Frame(ClientFrame::Resize { .. })
            | ClientDecode::Frame(ClientFrame::Signal { .. })
            | ClientDecode::Frame(ClientFrame::SecretInput { .. }) => {}
            ClientDecode::UnknownType(name) => {
                // Post-handshake: answered, ignored, and the connection
                // **stays open**. §7.5's explicit rule and the one most
                // likely to be got backwards.
                if tx
                    .send(protocol_error("protocol_violation", Some(name)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            ClientDecode::Malformed => {
                if tx
                    .send(protocol_error("protocol_violation", None))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        let _ = conn;
    }
}

/// Drain the per-connection queue onto the socket.
///
/// **The one place frames are written, which is the one place
/// [`ServerFrame::Unknown`] must not appear.** That variant carries
/// `#[serde(skip)]`, which under ciborium is a *runtime* error at
/// encode and not a compile error, so "never encoded" is a claim
/// nothing enforces. The `debug_assert` makes a debug build fail at the
/// line that built the frame instead of dropping it in release.
async fn write_loop(mut wr: tokio::net::unix::OwnedWriteHalf, mut rx: mpsc::Receiver<ServerFrame>) {
    while let Some(f) = rx.recv().await {
        debug_assert!(
            !matches!(f, ServerFrame::Unknown { .. }),
            "Unknown is decode-only (§7.5)"
        );
        if frame::write_frame(&mut wr, &f).await.is_err() {
            return;
        }
    }
}

/// Forward this session's live output onto the connection's queue.
///
/// **Attach clients receive only bytes** (REQ-D-007). The internal
/// frame carries `start`/`end`; the wire carries `Output { session,
/// bytes }` and §4.1 is explicit that *"raw offsets are not part of the
/// public attach protocol in v0.1.0"*. The conversion is this one place.
/// **A client that does not drain is detached, not tolerated** (§4.3,
/// §11.2). `try_send`, never `send().await`: a queue that blocked here
/// would hold this task, and — once the broadcast filled behind it —
/// would be one lagging client's back-pressure on a channel every other
/// client and `wait_for_pattern` share.
///
/// The `Detached { reason: "slow_consumer" }` is **best effort and
/// genuinely may not arrive**, which is worth stating rather than
/// hoping. The queue only fills because the *socket* is full, so the
/// writer is already parked in `write_frame`; a frame appended behind it
/// has nowhere to go. What the client observes is the close. §18.6
/// reasons about the WebSocket's version of this, where the same frame
/// *is* deliverable.
async fn forward_output(
    session_id: String,
    mut output: tokio::sync::broadcast::Receiver<crate::session::OutputFrame>,
    tx: mpsc::Sender<ServerFrame>,
) {
    use tokio::sync::broadcast::error::RecvError;
    use tokio::sync::mpsc::error::TrySendError;
    loop {
        match output.recv().await {
            Ok(f) => {
                let frame = ServerFrame::Output {
                    session: session_id.clone(),
                    bytes: f.bytes.to_vec(),
                };
                match tx.try_send(frame) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        crate::diag!(
                            "holdfast daemon: detaching a slow attach client on {session_id}"
                        );
                        let _ = tx.try_send(ServerFrame::Detached {
                            reason: "slow_consumer".to_string(),
                        });
                        return;
                    }
                    Err(TrySendError::Closed(_)) => return,
                }
            }
            // §4.3: *"Attach clients that are only rendering live bytes
            // do not attempt replay."* Resync by **continuing** — a
            // backfill from the ring buffer would interleave stale bytes
            // into a live terminal, and returning here would end the
            // stream for a client that is otherwise fine.
            Err(RecvError::Lagged(n)) => {
                crate::diag!("holdfast daemon: attach client on {session_id} lagged {n} frames");
            }
            Err(RecvError::Closed) => return,
        }
    }
}

fn protocol_error(reason: &str, frame_kind: Option<String>) -> ServerFrame {
    ServerFrame::ProtocolError {
        reason: reason.to_string(),
        frame_kind,
    }
}

/// §7.5's `Attached`, built from the session rather than echoed from the
/// request.
///
/// `state` is `SessionState::as_str()` — the same `"Starting" |
/// "Running" | "Exited" | "Dead"` the MCP surface emits — with the code
/// in the sibling `exit_code`. §7.5 wrote this as `"Exited(code)"`; rev.
/// 33 corrected it to the §18.2a bare token, *"never `\"Exited(0)\"`"*.
/// Serialising the Rust `Debug` here would produce a string no consumer
/// can match on.
fn attached_frame(session: &Arc<Session>) -> ServerFrame {
    let state = session.state();
    // `(cols, rows)`, in that order.
    let (cols, rows) = session.size();
    ServerFrame::Attached {
        session_id: session.id.clone(),
        name: session.name.clone(),
        cols,
        rows,
        state: state.as_str().to_string(),
        exit_code: match state {
            SessionState::Exited(code) => Some(code),
            _ => None,
        },
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::{MockPty, PtyBackend};
    use crate::session::{new_session_id, SessionConfig, OUTPUT_BROADCAST_FRAMES};

    /// One byte per `read`, so the *frame* count is the test's and not
    /// the scheduler's. `MockPty::read` drains its whole queue into a
    /// single frame, which is exactly why 0.0.3 could never provoke a
    /// `Lagged` at all.
    #[derive(Debug)]
    struct DribblePty(Arc<MockPty>);

    impl PtyBackend for DribblePty {
        fn write(&self, data: &[u8]) -> crate::Result<()> {
            self.0.write(data)
        }
        fn read(&self, buf: &mut [u8]) -> crate::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
        fn signal(&self, sig: crate::pty::Signal) -> crate::Result<()> {
            self.0.signal(sig)
        }
        fn resize(&self, cols: u16, rows: u16) -> crate::Result<()> {
            self.0.resize(cols, rows)
        }
        fn is_alive(&self) -> bool {
            self.0.is_alive()
        }
        fn exit_code(&self) -> Option<i32> {
            self.0.exit_code()
        }
        fn pid(&self) -> Option<u32> {
            self.0.pid()
        }
    }

    #[tokio::test]
    async fn broadcast_lag_does_not_replay_stale_bytes() {
        // REQ-C-003 / §4.3: *"Attach clients that are only rendering live
        // bytes do not attempt replay."*
        //
        // **Forced deterministically, at the one seam where it can be.**
        // Over a socket the forwarder drains the broadcast with
        // `try_send` and detaches instead of falling behind, so a
        // `Lagged` is unreachable from a client. Here the receiver is
        // taken, starved past the 256-frame bound, and only *then*
        // handed to `forward_output` — which is the same code path a
        // scheduler-starved forwarder takes.
        let inner = Arc::new(MockPty::new());
        let session = crate::session::Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::new(DribblePty(Arc::clone(&inner))) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(64 * 1024),
        );

        // Subscribed, then starved: one frame per byte, comfortably past
        // the bound, with nothing reading.
        let rx = session.subscribe();
        let burst = OUTPUT_BROADCAST_FRAMES * 2;
        inner.queue_output(&vec![b'x'; burst]);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while session.buffer_head() < burst as u64 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(
            session.buffer_head(),
            burst as u64,
            "the fixture must actually overrun the channel"
        );

        let (tx, mut out) = mpsc::channel::<ServerFrame>(4096);
        let forwarder = tokio::spawn(forward_output("sess_x".to_string(), rx, tx));
        inner.queue_output(b"Z");

        let mut delivered = 0usize;
        let mut saw_marker = false;
        let stop = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < stop {
            match tokio::time::timeout(std::time::Duration::from_millis(200), out.recv()).await {
                Ok(Some(ServerFrame::Output { bytes, .. })) => {
                    delivered += bytes.len();
                    if bytes.contains(&b'Z') {
                        saw_marker = true;
                        break;
                    }
                }
                Ok(Some(other)) => panic!("expected Output, got {other:?}"),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        forwarder.abort();

        // The stream **continues** past the gap. A `Lagged` arm that
        // returned would end it here, and the client would go silent for
        // the life of the session with nothing said.
        assert!(
            saw_marker,
            "the forwarder stopped at the lag instead of resyncing by continuing"
        );
        // And it does **not** backfill. The receiver lost
        // `burst - OUTPUT_BROADCAST_FRAMES` frames while it was starved;
        // a "helpful" replay out of the ring buffer would deliver those
        // bytes too, so anything above the channel's own capacity is
        // stale bytes interleaved into a live terminal.
        assert!(
            delivered <= OUTPUT_BROADCAST_FRAMES + 1,
            "the forwarder replayed {delivered} bytes for a channel that can hold \
             {OUTPUT_BROADCAST_FRAMES}: bytes lost to a lag are gone, not backfilled"
        );
    }
}
