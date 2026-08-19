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
//!
//! **The two reason sets are different sizes, deliberately.** §9.4's
//! `attach_disconnect.reason` carries **four** values and §7.5's
//! `Detached.reason` carries **three**: `client_detach` is audited and
//! never put on the wire, because *"the client sent `Detach`; there is
//! nobody left to tell."* [`Ending`] holds both derivations so they
//! cannot be reconciled by accident in either direction.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::frames::{
    AttachMode, AttachRole, ClientDecode, ClientFrame, ClientFrameKind, ServerFrame, SignalName,
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
pub async fn run(daemon: Arc<Daemon>, stream: UnixStream, peer_pid: Option<i32>, peer_uid: u32) {
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
                    // **Begins with the §18.4b token**, like every other
                    // `AttachReject.message`. §7.5's rule is that the
                    // message *"carries a whole sentence and always
                    // begins with one of these, so a client branches on
                    // the cause without matching prose"* — and this arm
                    // did not, so `holdfast attach` printing the message
                    // verbatim reported a missing session with no way for
                    // an operator to tell it from a version refusal.
                    // Found by Task 11's client-side row; the separator
                    // is `evaluate_attach`'s, space + em dash + space.
                    message: format!(
                        "{REJECT_SESSION_NOT_FOUND} — no live session matched {:?}",
                        hs.session
                    ),
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
    // **The event subscriptions are taken here too, and this is a fix
    // rather than tidiness.** They used to be taken where the tasks are
    // spawned, which is *after* the `is_awaiting_secret()` replay check
    // below — so an `AwaitingSecretEntered` edge that fired between the
    // check and the subscription was lost by this connection entirely:
    // the check saw `false`, and the subscription arrived too late for a
    // broadcast that keeps nothing for receivers that do not yet exist.
    //
    // The window was a few instructions wide and the suite never lost
    // it, until §9.4's `attach_connect` write landed between the two and
    // made it ~1.5 ms — at which point
    // `a_secret_submitted_over_attach_reaches_the_child_and_none_of_the_surfaces`
    // failed 3/3 in isolation, having passed 5/5 the commit before.
    // Measured by bisection, not inferred: removing the audit write
    // restored it, and moving the subscription above the check fixes it
    // with the write still there.
    //
    // Taken **before** the check, so the ordering is now the safe one:
    // an edge before the check is caught by the check, an edge after it
    // is caught by the subscription, and an edge *between* them is
    // caught by both — which is what `replayed` below de-duplicates.
    let exit_events = session.subscribe_events();
    let secret_events = session.subscribe_events();

    let (tx, rx) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
    let conn = Arc::new(AttachConn {
        client_id: daemon.attach_hub().next_client_id(),
        session_id: session.id.clone(),
        mode: hs.mode,
        role: hs.role,
        client_kind: hs.client_kind,
        client_version: hs.client_version,
        peer_pid,
        peer_uid,
        tx: tx.clone(),
        connected_at: Instant::now(),
    });

    // Queued first, so the FIFO is what makes it frame one rather than a
    // timing argument about two tasks.
    if tx.send(attached_frame(&session)).await.is_err() {
        return;
    }

    // §7.5's replay: *"Clients that arrive after the request is in flight
    // receive a replay of the most recent un-fulfilled `AwaitingSecret`
    // frame."* Queued on the same FIFO immediately behind `Attached`, so
    // the ordering is structural rather than a race between two tasks.
    //
    // `raise_secret` rather than a plain read, because the request may
    // not exist yet: the echo can drop while **nobody** is attached, and
    // then the first client to arrive is the first that could have raised
    // it. Idempotent, so an existing request is returned unchanged and
    // every client sees one `request_id`.
    let mut replayed: Option<String> = None;
    if session.is_awaiting_secret() {
        let (req, _first) = daemon
            .attach_hub()
            .raise_secret(&session.id, &session.prompt_last_line_redacted());
        replayed = Some(req.request_id.clone());
        if tx
            .send(ServerFrame::AwaitingSecret {
                request_id: req.request_id,
                prompt_text: req.prompt_text,
            })
            .await
            .is_err()
        {
            return;
        }
    }

    // **Registered only now**, after the handshake was accepted — never
    // at `accept`. A connection that opened the socket and said nothing
    // is not an attached client, and `daemon/status` counting it would
    // report clients on a session nobody is watching.
    daemon.attach_hub().register(Arc::clone(&conn));

    // §9.4's `attach_connect`, **after** a successful `Attached` and
    // never for a rejected attach: every refusal above returned before
    // reaching this line, so "a reject is not a connection" is structural
    // rather than a condition somebody has to remember. The surface is
    // derived server-side — `client_kind` off the uid-checked handshake,
    // the uid from `SO_PEERCRED` — the same rule `mcp::caller` follows
    // for the control socket.
    daemon.server.processor.audit.record_attach_connect(
        &conn.session_id,
        conn.client_kind.as_str(),
        conn.mode.as_str(),
        conn.role.as_str(),
        conn.peer_pid,
        conn.peer_uid,
    );

    // **§9.2's split is by role, and the role is read off the frame.**
    // Not from `client_kind` (which is attribution only, derived
    // server-side from the uid-checked handshake), not from `mode`, and
    // not from which CLI dialled in: §7.5's orthogonality paragraph
    // forbids all three, and a client with a live pane and a watching
    // pane opens one connection per pane. One `StreamRedactor` **per
    // connection**, never per session — two observers must not share
    // carry state, and an interactive client must not pay for one.
    let redactor = match conn.role {
        AttachRole::Interactive => None,
        AttachRole::Observer => Some(super::redact_stream::StreamRedactor::new(Arc::clone(
            &daemon.server.processor,
        ))),
    };

    let writer = tokio::spawn(write_loop(wr, rx));
    let mut forwarder = tokio::spawn(forward_output(
        Arc::clone(&session),
        conn.session_id.clone(),
        output,
        exit_events,
        tx.clone(),
        redactor,
    ));
    let events = tokio::spawn(forward_events(
        Arc::clone(&daemon),
        conn.session_id.clone(),
        secret_events,
        tx.clone(),
        replayed,
    ));
    let mut shutdown = daemon.shutdown_signalled();

    // Any of four things can end the connection, and §9.4 names all four
    // while §7.5 puts only three of them on the wire.
    //
    // **`biased`, and the order is the tie-break.** A `daemon/stop` that
    // kills a session makes `daemon_shutdown` and `session_exit` both
    // true; §7.5 says the shutdown wins, and picking whichever future
    // happened to be polled first is exactly the race REQ-D-009 forbids.
    // The `shutdown_requested()` re-check below closes the other half of
    // it — the watch flips only after the graceful stop's grace, so an
    // exit observed *during* that grace reaches the forwarder first.
    let ending = tokio::select! {
        biased;
        _ = shutdown.changed() => Ending::DaemonShutdown,
        forwarded = &mut forwarder => match forwarded {
            Ok(Forwarded::SessionExit) => Ending::SessionExit,
            // A forwarder that ended any other way ended because this
            // client stopped draining (§4.3) or because the socket died
            // under the writer. Either way the attachment is over.
            _ => Ending::SlowConsumer,
        },
        // Last, and only because the two above are cheap channel waits
        // that park immediately. Without the `select!` at all, a detached
        // slow consumer would keep its read half open forever: the read
        // loop holds a `Sender` and the writer only stops when every
        // `Sender` is gone.
        () = read_loop(&daemon, &session, &conn, &mut rd, &tx) => Ending::ClientDetach,
    };
    let ending = match ending {
        Ending::SessionExit if daemon.shutdown_requested() => Ending::DaemonShutdown,
        other => other,
    };

    daemon
        .attach_hub()
        .unregister(&conn.session_id, conn.client_id);

    // **The one place `Detached` is emitted**, for all three of its wire
    // reasons. `client_detach` is deliberately absent — §7.5: *"The
    // client sent `Detach`; there is nobody left to tell."* Adding it
    // would turn a closed set of three into four on a §23.3 surface the
    // web UI mirrors verbatim, and it is exactly the change that looks
    // like completing a set.
    //
    // `try_send` and not `send().await`: on the `slow_consumer` path the
    // queue only filled because the *socket* is full, so the writer is
    // already parked and a frame appended behind it has nowhere to go.
    // The frame is best effort and genuinely may not arrive there; what
    // that client observes is the close. On the other two paths the
    // queue is empty and it arrives.
    if let Some(reason) = ending.wire_reason() {
        let _ = tx.try_send(ServerFrame::Detached {
            reason: reason.to_string(),
        });
    }

    // §9.4's `attach_disconnect`, paired with the `attach_connect` above
    // and carrying `role` for the reason REQ-SEC-008a gives: the two
    // entries share no connection identifier, so the role is what makes
    // "did this client receive raw output, and for how long?" answerable.
    daemon.server.processor.audit.record_attach_disconnect(
        &conn.session_id,
        conn.client_kind.as_str(),
        conn.mode.as_str(),
        conn.role.as_str(),
        ending.audit_reason(),
        conn.connected_at.elapsed().as_secs_f64(),
    );

    // Dropping every `Sender` ends the write loop, which drains what is
    // still queued and *then* closes the socket — so the `Detached` above
    // (and a `ProtocolError` written on the way out) reaches the client
    // before the EOF that follows it.
    forwarder.abort();
    events.abort();
    drop(tx);
    drop(conn);
    let _ = writer.await;
}

/// Why one attachment ended.
///
/// **The two reason sets are different sizes and that is the point.**
/// §9.4's `attach_disconnect.reason` has four values; §7.5's
/// `Detached.reason` has three. `client_detach` is in the audit set and
/// deliberately not on the wire. Keeping both derivations on one enum is
/// what stops the sets being reconciled by accident in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The client sent `Detach`, or its socket went away.
    ClientDetach,
    /// §4.3: this client stopped draining its bounded queue.
    SlowConsumer,
    /// The child ended (REQ-D-009).
    SessionExit,
    /// A shutdown was asked for. **Outranks `SessionExit`** when both are
    /// true, per §7.5.
    DaemonShutdown,
}

impl Ending {
    /// §9.4's `attach_disconnect.reason` — all four.
    fn audit_reason(self) -> &'static str {
        match self {
            Self::ClientDetach => "client_detach",
            Self::SlowConsumer => "slow_consumer",
            Self::SessionExit => "session_exit",
            Self::DaemonShutdown => "daemon_shutdown",
        }
    }

    /// §7.5's `Detached.reason` — three, and `None` for the fourth.
    fn wire_reason(self) -> Option<&'static str> {
        match self {
            Self::ClientDetach => None,
            Self::SlowConsumer => Some("slow_consumer"),
            Self::SessionExit => Some("session_exit"),
            Self::DaemonShutdown => Some("daemon_shutdown"),
        }
    }
}

/// How [`forward_output`] stopped.
enum Forwarded {
    /// The child ended, and `SessionExited { code }` has been queued.
    SessionExit,
    /// This client stopped draining, or the queue went away with it.
    Stopped,
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
        // A known `type` whose fields did not fit — including a broken
        // `Attach` itself. `protocol_violation` and **not** `no_handshake`:
        // the frame did not decode, so nothing here can say it was a
        // well-formed frame of the wrong kind. It closes either way.
        ClientDecode::BadFields(kind) => {
            let _ = frame::write_frame(
                wr,
                &protocol_error("protocol_violation", Some(kind.as_str().to_string())),
            )
            .await;
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
    loop {
        let mut body = match frame::read_frame_body(rd).await {
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

        let decoded = super::frames::decode_client_frame(&body);

        // **§7.5's ReadOnly gate, and it runs before every arm below.**
        // Server-side, on the mode the *handshake* carried — a client
        // does not get to re-declare it, and there is no second place a
        // write can enter from, because every write arm is downstream of
        // this check. §4.3: a rejected frame does not reach `write_tx`,
        // does not signal, mutates no session state, does not bump
        // `last_activity`, and leaves the connection open.
        //
        // Ordering: the gate precedes the out-of-order `Attach` arm on
        // purpose. §18.4's `read_only_attach` is *"any frame but `Detach`
        // from a `ReadOnly` client"* with no carve-out, and checking the
        // arms first would leave `ClientFrameKind::Attach`'s row in the
        // table unreachable by any input at all.
        if let ClientDecode::Frame(f) = &decoded {
            let kind = f.kind();
            if conn.mode == AttachMode::ReadOnly && !kind.readonly_allowed() {
                if tx
                    .send(protocol_error(
                        "read_only_attach",
                        Some(kind.as_str().to_string()),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
        }

        match decoded {
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
            ClientDecode::Frame(ClientFrame::Resize { cols, rows }) => {
                if let Err(e) = session.resize(cols, rows) {
                    crate::diag!("holdfast daemon: attach resize failed: {e}");
                    continue;
                }
                // §4.1: an attach `Resize` from a ReadWrite client is
                // activity. The `resize` **tool** is not, which is why
                // the stamp is here and not inside `Session::resize`.
                session.note_activity();

                // §7.5: *"canonical PTY size, e.g. when another client
                // resizes."* The size is re-read from the session rather
                // than echoed from the request, so what the other panes
                // reflow to is the geometry the terminal actually got —
                // `Session::resize` clamps, and a client that asked for
                // 5000 columns must not tell everybody else it succeeded.
                let (cols, rows) = session.size();
                for other in daemon.attach_hub().clients_of(&conn.session_id) {
                    // The originator is excluded: it already knows, and a
                    // client that reflows on every `Resize` would loop.
                    if other.client_id == conn.client_id {
                        continue;
                    }
                    // `try_send`, like the output path: a resize
                    // notification is not worth blocking this read loop
                    // behind a client that stopped draining, and that
                    // client is on its way out anyway.
                    let _ = other.tx.try_send(ServerFrame::Resize { cols, rows });
                }
            }
            ClientDecode::Frame(ClientFrame::Signal { sig }) => {
                // §4.4's per-value delivery, reached through
                // `Session::signal` rather than re-implemented: `int` goes
                // to the **foreground** group (`tcgetpgrp`) — the command
                // being interrupted, not the shell hosting it — and
                // `term`/`kill` sweep the session's process groups.
                //
                // **No escalation** (§18.4c, REQ-D-008): `term` sweeps
                // once with SIGTERM and does not follow with SIGKILL. The
                // escalating form with its `timeout_secs` is the
                // `terminate` *tool*, and the two are deliberately not the
                // same operation.
                let delivered = match sig {
                    SignalName::Int => crate::pty::Signal::Interrupt,
                    SignalName::Term => crate::pty::Signal::Terminate,
                    SignalName::Kill => crate::pty::Signal::Kill,
                };
                if let Err(e) = session.signal(delivered) {
                    crate::diag!("holdfast daemon: attach signal failed: {e}");
                    continue;
                }
                // `Session::signal` stamps activity itself.
                if ended_by_signal(session, sig).await {
                    daemon
                        .server
                        .processor
                        .audit
                        .record_session_terminate_attach_signal(
                            &session.id,
                            sig_wire_name(sig),
                            session.exit_code(),
                        );
                }
            }
            ClientDecode::Frame(ClientFrame::SecretInput { request_id, bytes }) => {
                // The request is closed **before** the write is queued and
                // by the same atomic step that decides whether this
                // client is the one fulfilling it: two clients answering
                // the same prompt must produce one write, not two, and a
                // check-then-clear would let both through.
                match daemon
                    .attach_hub()
                    .close_secret(&conn.session_id, Some(&request_id))
                {
                    Some(req) => {
                        // §5.2's normalisation is applied here, by the
                        // daemon, so the behaviour does not depend on
                        // which client submitted. `append_newline` is
                        // `true`: 0.0.6 raises from an echo drop with no
                        // tool call behind it, and an echo-off prompt is
                        // waiting for a line.
                        let (write, _ack) = WriteRequest::secret(
                            super::secret::SecretBytes::normalise(bytes, true),
                        );
                        if session.write_queue().send(write).await.is_err() {
                            return;
                        }
                        // The frame body still holds the value in
                        // cleartext and is about to be reused for the
                        // next frame; `SecretBytes` owns only the decoded
                        // copy.
                        super::secret::zero_bytes(&mut body);
                        // §4.1 lists a `SecretInput` from a ReadWrite
                        // client as activity — and it must be, or a
                        // session idle-reaps while a human is typing a
                        // password.
                        session.note_activity();
                        broadcast_secret_closed(
                            daemon,
                            &conn.session_id,
                            &req.request_id,
                            "fulfilled",
                        );
                    }
                    // §18.4: the connection stays open and nothing is
                    // written. A client whose request was superseded
                    // between the prompt and the keystrokes must not have
                    // its password typed into whatever came next.
                    None => {
                        super::secret::zero_bytes(&mut body);
                        if tx
                            .send(protocol_error(
                                "unknown_request_id",
                                Some(ClientFrameKind::SecretInput.as_str().to_string()),
                            ))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            // A `type` this build implements whose fields did not fit:
            // §18.4c's `sig: "stop"` case, and the reason `BadFields`
            // exists as its own variant. The kind **is** nameable here,
            // the connection stays open, and nothing was applied.
            ClientDecode::BadFields(kind) => {
                if tx
                    .send(protocol_error(
                        "protocol_violation",
                        Some(kind.as_str().to_string()),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
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
    session: Arc<Session>,
    session_id: String,
    mut output: tokio::sync::broadcast::Receiver<crate::session::OutputFrame>,
    mut exits: tokio::sync::broadcast::Receiver<crate::session::SessionEvent>,
    tx: mpsc::Sender<ServerFrame>,
    mut redactor: Option<super::redact_stream::StreamRedactor>,
) -> Forwarded {
    use tokio::sync::broadcast::error::RecvError;

    // **The client that arrived after the edge had already passed.**
    // `SessionEvent::Exited` is sent once, by the reader thread, and a
    // connection that subscribed afterwards can never see it. Nor does
    // the output broadcast ever close: §5.5.1 retains exited sessions
    // for the daemon's lifetime — deliberately, so `holdfast logs` can
    // still read one — `SessionRegistry::remove` has no caller anywhere
    // in the tree, and the `Session` holds its own `Sender`. So without
    // this the task parked forever on two channels that were never going
    // to produce anything, and `holdfast watch <exited-session>` hung
    // until the operator found Ctrl-C.
    //
    // **Read the state rather than replay the edge**, because the state
    // is what the daemon already knows: `Attached.state` said `"Exited"`
    // in frame one all along. And checked **here**, after `run` has
    // subscribed to both channels, not before — a session that dies in
    // the window between the subscribe and this line is caught by the
    // event instead, so the two together have no gap. Whichever fires,
    // the task returns at the first one, so there is no double
    // `SessionExited`.
    if !session.is_alive() {
        // **Drain first, exactly as the loop below does.** This check
        // short-circuits the `biased` select, and with it the
        // output-before-exit ordering that select exists to impose — so
        // the drain has to be done here explicitly or the child's last
        // bytes are dropped on the floor.
        //
        // **The window is the whole of `run`'s setup, not an
        // instant.** `run` subscribes before writing `Attached` and does
        // not spawn this task until after the `is_awaiting_secret`
        // replay check, the `Attached` write, the §9.4 audit write and
        // three `tokio::spawn`s. Everything the child printed across
        // that span is already in *this* receiver's 256-frame ring, and
        // returning straight to `send_exit` told the client
        // `SessionExited` having sent it no `Output` at all. Covered by
        // `a_session_that_exited_during_the_handshake_still_delivers_its_last_bytes`,
        // which is red without these lines with the whole frame list
        // being `[SessionExited { code: 7 }]`.
        //
        // `try_recv` and not `recv().await`: the child is already gone,
        // so anything not in the ring now is never coming, and awaiting
        // would park this task on a channel with no producer left.
        loop {
            match output.try_recv() {
                Ok(f) => match forward_chunk(&session_id, &f.bytes, &mut redactor, &tx) {
                    Queued::Sent => {}
                    // The queue filled or the socket died: there is
                    // nowhere to put a `SessionExited` either.
                    Queued::Stopped => return Forwarded::Stopped,
                },
                // §4.3 again: a lag is resynced by continuing, never by
                // backfilling out of the ring buffer.
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                // `Empty` is the ordinary end of the drain; `Closed`
                // means the `Session` itself is gone and there is
                // nothing further to read.
                Err(_) => break,
            }
        }
        return send_exit(
            &session_id,
            reported_exit_code(&session),
            &tx,
            &mut redactor,
        );
    }

    loop {
        // **`biased`, output first, and it is what orders the two
        // channels against each other.** The child's last bytes and its
        // death arrive on different broadcasts, published in that order
        // by the same reader thread — so by the time `Exited` is
        // readable the final `Output` is already queued behind it here.
        // Polling output first drains it before the exit is acted on,
        // which is what makes §7.5's *"`SessionExited` before the view is
        // torn down"* an ordering of the child's own bytes and not just
        // of two frames.
        let next = tokio::select! {
            biased;
            r = output.recv() => Either::Output(r),
            r = exits.recv() => Either::Event(r),
        };
        let next = match next {
            Either::Output(r) => r,
            // §7.5's exit sequence starts here. Everything the redactor
            // is still carrying is flushed **first** — a session that
            // died mid-token must not silently swallow its last line —
            // and `flush` emits nothing while withholding, which is the
            // half that keeps this path from becoming the leak the carry
            // bound exists to stop.
            Either::Event(Ok(crate::session::SessionEvent::Exited { code })) => {
                return send_exit(&session_id, code, &tx, &mut redactor);
            }
            // The secret edges belong to `forward_events`, which is the
            // task that can reach the hub. Ignored rather than matched
            // exhaustively-by-accident: a future event variant must not
            // silently become an exit.
            Either::Event(Ok(_)) => continue,
            // An edge is not a stream; a lag on this channel loses an
            // edge that a later one re-synchronises. `Closed` cannot
            // happen while the `Session` lives, and if it does there is
            // no exit to report.
            Either::Event(Err(RecvError::Lagged(_))) => continue,
            Either::Event(Err(RecvError::Closed)) => return Forwarded::Stopped,
        };
        match next {
            // Redaction and the wire conversion both live in
            // [`forward_chunk`] — see its docs for why there is exactly
            // one of each and why this arm is not allowed to inline them.
            Ok(f) => match forward_chunk(&session_id, &f.bytes, &mut redactor, &tx) {
                Queued::Sent => {}
                Queued::Stopped => return Forwarded::Stopped,
            },
            // §4.3: *"Attach clients that are only rendering live bytes
            // do not attempt replay."* Resync by **continuing** — a
            // backfill from the ring buffer would interleave stale bytes
            // into a live terminal, and returning here would end the
            // stream for a client that is otherwise fine.
            Err(RecvError::Lagged(n)) => {
                crate::diag!("holdfast daemon: attach client on {session_id} lagged {n} frames");
            }
            // **The second flush trigger, and the one that hardly ever
            // fires.** The output broadcast is closed only when the
            // `Session` itself is dropped — the `Session` keeps its own
            // `Sender`, so a child that merely exits does not close it —
            // which is why `SessionEvent::Exited` above is the trigger
            // that matters and this one is the backstop for a session
            // torn out from under a live connection.
            Err(RecvError::Closed) => {
                if let Some(tail) = redactor.as_mut().map(|r| r.flush()) {
                    let _ = queue_output(&session_id, tail, &tx);
                }
                return Forwarded::Stopped;
            }
        }
    }
}

/// §7.5's exit sequence, from whichever of its two triggers reached it.
///
/// **One function and not two copies**, because the ordering is the
/// requirement: everything the redactor is still carrying is flushed
/// *first* — a session that died mid-token must not silently swallow its
/// last line — and only then does `SessionExited` go on the queue. Both
/// callers put their frames on the same FIFO that `write_loop` drains, so
/// `Detached` (queued by `run` when this returns) is still last. Two
/// hand-written copies of that could drift, and the one that drifted
/// would be the rarely-taken one.
///
/// **Only the flush, never a drain.** Both callers have already emptied
/// the output receiver — the loop by polling it first under `biased`,
/// the pre-loop check by draining with `try_recv` — so this function's
/// one job is the redactor's carry. Putting a drain in here as well
/// would double-drain the loop's caller.
fn send_exit(
    session_id: &str,
    code: i32,
    tx: &mpsc::Sender<ServerFrame>,
    redactor: &mut Option<super::redact_stream::StreamRedactor>,
) -> Forwarded {
    // The carry has already been through `feed`; it goes to the queue
    // directly rather than back through [`forward_chunk`], which would
    // redact it twice.
    if let Some(tail) = redactor.as_mut().map(|r| r.flush()) {
        let _ = queue_output(session_id, tail, tx);
    }
    let _ = tx.try_send(ServerFrame::SessionExited { code });
    Forwarded::SessionExit
}

/// Whether one chunk reached the connection's queue, or the connection
/// is over.
///
/// A named two-state answer rather than a `bool`, because the caller's
/// obligation on the second one is to *stop* — a `bool` at a call site
/// reads as "delivered?" and invites being ignored.
enum Queued {
    /// On the queue, or deliberately nothing to send.
    Sent,
    /// The client stopped draining (§4.3) or the socket died under the
    /// writer. Either way this attachment is over.
    Stopped,
}

/// Redact one live chunk and queue it — **the single redaction point**
/// for bytes on their way to an attach client.
///
/// One place, for the same reason [`queue_output`] is one place: a
/// second call site that fed the redactor could be a call site that
/// forgot to, and §9.2's guarantee is that an observer never sees an
/// unredacted byte. Both of `forward_output`'s paths to a live chunk —
/// the loop, and the pre-loop drain for a session that died during the
/// handshake — come through here.
fn forward_chunk(
    session_id: &str,
    bytes: &[u8],
    redactor: &mut Option<super::redact_stream::StreamRedactor>,
    tx: &mpsc::Sender<ServerFrame>,
) -> Queued {
    let bytes = match redactor.as_mut() {
        Some(r) => r.feed(bytes),
        None => bytes.to_vec(),
    };
    queue_output(session_id, bytes, tx)
}

/// Build §7.5's `Output` and put it on the connection's queue — **the
/// single conversion point to the wire frame**.
///
/// It is the single conversion point for the reason it is also the
/// single offset-stripping point: the internal [`OutputFrame`] carries
/// `start`/`end` and §4.1 is explicit that *"raw offsets are not part of
/// the public attach protocol in v0.1.0"*, so a second place that built
/// an `Output` would be a second place that could forget. The same
/// argument covers the other two rules folded in here — the empty frame
/// is suppressed, and a full queue is §4.3's slow consumer — which is
/// why the exit path's flush and the pre-loop drain call this rather
/// than writing `ServerFrame::Output` themselves.
///
/// [`OutputFrame`]: crate::session::OutputFrame
fn queue_output(session_id: &str, bytes: Vec<u8>, tx: &mpsc::Sender<ServerFrame>) -> Queued {
    use tokio::sync::mpsc::error::TrySendError;

    // A chunk held whole (a secret still arriving) produces nothing to
    // send, and so does a redactor flush with an empty carry. An empty
    // `Output` would be a frame that says the child printed nothing,
    // which it did not.
    if bytes.is_empty() {
        return Queued::Sent;
    }
    match tx.try_send(ServerFrame::Output {
        session: session_id.to_string(),
        bytes,
    }) {
        Ok(()) => Queued::Sent,
        Err(TrySendError::Full(_)) => {
            // The `Detached { reason: "slow_consumer" }` is **not**
            // written here. `run` writes all three wire reasons at one
            // place, so the closed set of three cannot grow a fourth in
            // a corner.
            crate::diag!("holdfast daemon: detaching a slow attach client on {session_id}");
            Queued::Stopped
        }
        Err(TrySendError::Closed(_)) => Queued::Stopped,
    }
}

/// The status a `SessionExited` reports for a session that had already
/// ended before this connection existed.
///
/// **The same derivation [`attached_frame`] uses for `Attached.exit_code`
/// and the reader thread uses for the edge**, so the two fields cannot
/// disagree about one child. `Session::state()` folds
/// `backend.exit_code().unwrap_or(-1)` itself; the fallback below is for
/// `Dead`, which carries a reason and no wait status, and `-1` is
/// already this protocol's "no status available".
fn reported_exit_code(session: &Arc<Session>) -> i32 {
    match session.state() {
        SessionState::Exited(code) => code,
        _ => session.exit_code().unwrap_or(-1),
    }
}

/// Which of [`forward_output`]'s two channels produced the next item.
///
/// A named type rather than a tuple of `Option`s, so the `match` below
/// is exhaustive over the *sources* and adding a third channel is a
/// compile error rather than a silently unhandled arm.
enum Either {
    Output(Result<crate::session::OutputFrame, tokio::sync::broadcast::error::RecvError>),
    Event(Result<crate::session::SessionEvent, tokio::sync::broadcast::error::RecvError>),
}

/// Turn this session's non-output edges into §7.5 frames for one
/// connection.
///
/// **Every connection runs one of these and they do not coordinate.** The
/// hub's `raise_secret`/`close_secret` are idempotent, so the first
/// connection to see an edge allocates the `request_id` and the rest get
/// the same one back — which is what makes one request reach every
/// client without a designated leader, and what lets a client that
/// attached *after* the drop raise the request nobody was there to raise.
/// `replayed` is the `request_id` [`run`] already sent as §7.5's replay,
/// if it sent one. The subscription is taken *before* that check, so an
/// edge landing between the two reaches both — and this is what stops the
/// client seeing the same `request_id` twice and re-prompting for a
/// password it has already been asked for.
async fn forward_events(
    daemon: Arc<Daemon>,
    session_id: String,
    mut events: tokio::sync::broadcast::Receiver<crate::session::SessionEvent>,
    tx: mpsc::Sender<ServerFrame>,
    mut replayed: Option<String>,
) {
    use crate::session::SessionEvent;
    use tokio::sync::broadcast::error::RecvError;
    loop {
        match events.recv().await {
            Ok(SessionEvent::AwaitingSecretEntered { prompt_text }) => {
                let (req, _first) = daemon.attach_hub().raise_secret(&session_id, &prompt_text);
                // Exactly one suppression, and only of the id `run`
                // already sent. A *superseded* request gets a fresh id
                // from `SecretRequest::new`, so this cannot swallow a
                // later prompt.
                if replayed.take().is_some_and(|id| id == req.request_id) {
                    continue;
                }
                if tx
                    .send(ServerFrame::AwaitingSecret {
                        request_id: req.request_id,
                        prompt_text: req.prompt_text,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // §5.2's supersede: echo came back with no submission. Exactly
            // one connection's `close_secret` returns `Some`, so exactly
            // one fan-out happens even though every one of them tries.
            Ok(SessionEvent::AwaitingSecretLeft) => {
                if let Some(req) = daemon.attach_hub().close_secret(&session_id, None) {
                    broadcast_secret_closed(&daemon, &session_id, &req.request_id, "cancelled");
                }
            }
            // **The exit is `forward_output`'s, not this task's**, and
            // the reason is the redactor: it lives in that task, one per
            // connection, and §7.5's `SessionExited` must come after its
            // flush. Two tasks queueing on the same FIFO could not order
            // a flush against a frame without a rendezvous neither needs.
            Ok(SessionEvent::Exited { .. }) => {}
            // An edge is not a stream: a connection that fell behind has
            // already been re-synchronised by the next edge, and the slot
            // it would have read is still in the hub.
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return,
        }
    }
}

/// Tell every client on this session that the request is over.
///
/// `try_send`, like the output path: a client that stopped draining is on
/// its way out, and a closure notice is not worth parking the sender.
fn broadcast_secret_closed(
    daemon: &Arc<Daemon>,
    session_id: &str,
    request_id: &str,
    outcome: &str,
) {
    for c in daemon.attach_hub().clients_of(session_id) {
        let _ = c.tx.try_send(ServerFrame::SecretRequestClosed {
            request_id: request_id.to_string(),
            outcome: outcome.to_string(),
        });
    }
}

/// §18.4c's wire spelling of a signal — the one the audit trail records,
/// because it is what Holdfast *sent*.
fn sig_wire_name(sig: SignalName) -> &'static str {
    match sig {
        SignalName::Int => "int",
        SignalName::Term => "term",
        SignalName::Kill => "kill",
    }
}

/// Did this signal end the session? Bounded, and only the answer to
/// *"was this the thing that ended it"* — §9.4's `session_terminate`
/// entry is written when a session **ends** because of a `Signal` frame,
/// not when one is sent.
///
/// **`int` is not waited for and the asymmetry is deliberate.** Ctrl-C is
/// the frequent case on an interactive attach and it normally ends a
/// *command*, not the session; parking this read loop for half a second
/// on every one of them would queue the keystrokes behind it. A child
/// that does die of SIGINT is still caught, by the immediate check. For
/// `term`/`kill` the client has asked for the session to end, so the wait
/// costs nothing anybody is waiting on — and without it the answer is
/// simply wrong, since a real child takes milliseconds to die and
/// `is_alive` would still say yes.
async fn ended_by_signal(session: &Arc<Session>, sig: SignalName) -> bool {
    if matches!(sig, SignalName::Int) {
        return !session.is_alive();
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        if !session.is_alive() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    false
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
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".to_string(),
            rx,
            session.subscribe_events(),
            tx,
            None,
        ));
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

    /// §7.5's exit sequence must still carry the child's **last bytes**
    /// when the child died during the handshake.
    ///
    /// **The window this covers is the whole of `run`'s setup.** The
    /// output receiver is subscribed before `Attached` is written, and
    /// `forward_output` is not spawned until after the
    /// `is_awaiting_secret` replay check, the `Attached` write, the
    /// audit write and three `tokio::spawn`s. Everything the child
    /// prints across that span is already sitting in *this connection's*
    /// receiver — 256 frames of it — so a pre-loop `is_alive()` check
    /// that returned straight to `send_exit` dropped it on the floor,
    /// and the client was told `SessionExited` having received no
    /// `Output` at all.
    ///
    /// **Deterministic, at the same seam
    /// `broadcast_lag_does_not_replay_stale_bytes` uses.** Over a socket
    /// the ordering is a scheduler race nothing can pin; here the
    /// receiver is taken first, the line is published into it (proved by
    /// `buffer_head`, not by a sleep), the child is exited (proved by
    /// `is_alive`, not by a sleep), and only *then* is the forwarder
    /// handed the receiver. The event receiver is taken after the exit,
    /// so the `Exited` edge is genuinely gone and the state check is the
    /// only thing left to catch it — which is precisely the arrangement
    /// that makes the drop visible. Watched failing at `b1bb9a6` with
    /// the whole frame list being `[SessionExited { code: 7 }]`.
    ///
    /// **None of the three rows that came with the check can see
    /// this**: `attaching_to_an_already_exited_session_is_told_and_torn_down`
    /// exits the session before dialling, so its ring is empty by
    /// construction, and the two CLI rows assert only `wait_exit` plus
    /// the "session exited (N)" line.
    #[tokio::test]
    async fn a_session_that_exited_during_the_handshake_still_delivers_its_last_bytes() {
        let inner = Arc::new(MockPty::new());
        let session = crate::session::Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&inner) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(64 * 1024),
        );

        // Subscribed where `run` subscribes: before anything else in the
        // setup, and long before the forwarder exists.
        let rx = session.subscribe();

        const LAST_LINE: &[u8] = b"LAST-LINE\n";
        inner.queue_output(LAST_LINE);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while session.buffer_head() < LAST_LINE.len() as u64 && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        // The publish is what puts the frame in `rx`'s ring, and it has
        // to have happened *after* the subscribe for this test to be
        // about anything.
        assert_eq!(
            session.buffer_head(),
            LAST_LINE.len() as u64,
            "the fixture must publish the child's last line into the subscribed receiver"
        );

        inner.exit(7);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while session.is_alive() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert!(
            !session.is_alive(),
            "the fixture must actually have the child gone before the forwarder starts"
        );

        let (tx, mut out) = mpsc::channel::<ServerFrame>(4096);
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".to_string(),
            rx,
            session.subscribe_events(),
            tx,
            None,
        ));

        // Ends at `SessionExited` or at 200 ms of silence, and the
        // silent end is the one that matters: under the defect there is
        // no `Output` to wait for and the assertions below have to run
        // anyway rather than hanging.
        let mut frames = Vec::new();
        while let Ok(Some(f)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), out.recv()).await
        {
            let last = matches!(f, ServerFrame::SessionExited { .. });
            frames.push(f);
            if last {
                break;
            }
        }
        forwarder.abort();

        let carries_last_line = |f: &ServerFrame| match f {
            ServerFrame::Output { bytes, .. } => {
                bytes.windows(LAST_LINE.len()).any(|w| w == LAST_LINE)
            }
            _ => false,
        };
        let line_at = frames.iter().position(carries_last_line);
        let exit_at = frames
            .iter()
            .position(|f| matches!(f, ServerFrame::SessionExited { code: 7 }));

        // **The harm, not the diagnosis.** The bytes are simply absent
        // under the defect — this is not a mis-ordering, so an
        // ordering-only assertion is green through it.
        let line_at = line_at.unwrap_or_else(|| {
            panic!("the child's last line was dropped; frames were: {frames:?}")
        });
        let exit_at = exit_at
            .unwrap_or_else(|| panic!("no SessionExited {{ code: 7 }}; frames were: {frames:?}"));
        assert!(
            line_at < exit_at,
            "§7.5 flushes the child's bytes before SessionExited; frames were: {frames:?}"
        );
    }
}
