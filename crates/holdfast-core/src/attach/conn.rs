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

use super::frames::{ClientDecode, ClientFrame, ClientFrameKind, ServerFrame};
use super::handshake::{evaluate_attach, REJECT_SESSION_NOT_FOUND};
use super::{AttachMode, AttachRole};
use crate::daemon::server::Daemon;
use crate::protocol::frame::{self, FrameError};
use crate::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use crate::session::{Session, SessionState, WriteRequest};

/// §4.3's per-connection outbound bound. **Not configurable in
/// v0.1.0.** Overflow detaches this client and never blocks the reader.
pub const ATTACH_QUEUE_FRAMES: usize = 64;

/// One attached client, as the hub and the audit trail see it.
pub struct AttachConn {
    pub session_id: String,
    pub mode: AttachMode,
    /// **Attribution only, never a redaction switch.** §7.5's
    /// orthogonality paragraph forbids deriving `role` from
    /// `client_kind`; what decides whether this connection gets raw
    /// bytes is `role`, and nothing else.
    pub role: AttachRole,
    /// Derived server-side from the uid-checked handshake, and the
    /// audit surface is derived from *this*, never from a request
    /// argument (§9.4, `mcp::caller`'s precedent).
    pub client_kind: ClientKind,
    pub client_version: String,
    /// Bounded per-connection queue (§4.3: *"their own bounded mpsc,
    /// default 64 frames"*). Overflow detaches this client and never
    /// blocks the reader task.
    pub tx: mpsc::Sender<ServerFrame>,
    pub connected_at: Instant,
}

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
    let conn = AttachConn {
        session_id: session.id.clone(),
        mode: hs.mode,
        role: hs.role,
        client_kind: hs.client_kind,
        client_version: hs.client_version,
        tx: tx.clone(),
        connected_at: Instant::now(),
    };

    // Queued first, so the FIFO is what makes it frame one rather than a
    // timing argument about two tasks.
    if tx.send(attached_frame(&session)).await.is_err() {
        return;
    }

    let writer = tokio::spawn(write_loop(wr, rx));
    let forwarder = tokio::spawn(forward_output(conn.session_id.clone(), output, tx.clone()));

    read_loop(&daemon, &session, &conn, &mut rd, &tx).await;

    // Dropping every `Sender` ends the write loop, which drains what is
    // still queued and *then* closes the socket — so a `ProtocolError`
    // written on the way out reaches the client before the EOF that
    // follows it.
    drop(tx);
    drop(conn);
    forwarder.abort();
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
async fn forward_output(
    session_id: String,
    mut output: tokio::sync::broadcast::Receiver<crate::session::OutputFrame>,
    tx: mpsc::Sender<ServerFrame>,
) {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        match output.recv().await {
            Ok(f) => {
                let frame = ServerFrame::Output {
                    session: session_id.clone(),
                    bytes: f.bytes.to_vec(),
                };
                if tx.send(frame).await.is_err() {
                    return;
                }
            }
            // §4.3: *"Attach clients that are only rendering live bytes
            // do not attempt replay."* Resync by continuing — a backfill
            // from the ring buffer would interleave stale bytes into a
            // live terminal.
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
