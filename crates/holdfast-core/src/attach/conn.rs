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
//! | `unknown_request_id` | no | a `SecretInput` naming no outstanding prompt, **or an `ApproveBinding` naming no outstanding approval** — `frame_kind` says which |
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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, Notify};

use super::frames::{
    AttachMode, AttachRole, ClientDecode, ClientFrame, ClientFrameKind, ServerFrame, SignalName,
};
use super::handshake::{evaluate_attach, REJECT_SESSION_NOT_FOUND, REJECT_TERMINAL_BUSY};
use crate::daemon::server::Daemon;
use crate::protocol::frame::{self, FrameError};
use crate::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use crate::session::{SecretWrite, Session, SessionState, WriteRequest};

use super::hub::{queue_ancillary, ENDING_SLOTS};
pub use super::hub::{AttachConn, ATTACH_QUEUE_BYTES, ATTACH_QUEUE_FRAMES, ATTACH_STALL_TIMEOUT};

/// Slots of the per-connection queue the **stream** leaves for the
/// ancillary frames — `Resize`, `AwaitingSecret`, `SecretRequestClosed`,
/// `BindingApprovalRequired` — on top of the [`ENDING_SLOTS`] it leaves
/// for the ending (GH #210).
///
/// **New because the stream now waits instead of being refused.** A
/// forwarder that pauses on a full queue sits at its limit for as long as
/// its client is slow, and an ancillary frame refused at
/// [`ENDING_SLOTS`] would then be refused for that whole time — a human
/// on a slow link would never see a secret prompt raised while output
/// was backed up behind it. Eight is several of each kind at once; they
/// are human-paced, and `broadcast_size` already dedups the one that
/// floods.
const ANCILLARY_SLOTS: usize = 8;

/// The most live output the forwarder puts in one `Output` frame.
///
/// **Batching is what makes the queue count bursts rather than PTY
/// reads** (GH #210). A backlog the forwarder finds waiting — frames on
/// the broadcast, or a stretch of ring buffer it is catching up on — goes
/// out as one frame per this many bytes instead of one per `read` the
/// reader happened to make, so a 1,500-line burst is a handful of frames
/// and a handful of socket writes, not 1,500 of each. Well under
/// `MAX_FRAME_BYTES`; big enough that the per-frame cost is noise.
const MAX_BATCH_BYTES: usize = 64 * 1024;

/// The chunk size a ring-buffer catch-up is fed to an `observer`'s
/// redactor in (GH #210).
///
/// **One reader-thread `read`, which is what the redactor was built
/// against.** Live frames are fed exactly as the reader produced them;
/// bytes read back out of the ring have lost those boundaries, and
/// feeding the redactor a 64 KiB stretch in one call would change its
/// residuals rather than preserve them — `StreamRedactor`'s withholding
/// drops the rest of the chunk it overflows in, so a larger chunk is a
/// larger loss on a certificate dump than §9.2 states. At the reader's
/// own buffer size the redactor sees the regime it already sees.
const BACKFILL_CHUNK_BYTES: usize = 8192;

/// The byte half of §4.3's per-connection bound, shared by the one task
/// that fills the queue and the one that drains it (GH #210).
///
/// `queued` counts `Output` payload bytes that are on the queue or being
/// written; `drained` is rung by the writer every time a frame leaves,
/// which is what a paused forwarder waits on. One `Notify` with one
/// waiter, so `notify_one`'s stored permit is what closes the window
/// between the forwarder deciding to wait and starting to.
#[derive(Default)]
struct Budget {
    queued: AtomicUsize,
    drained: Notify,
}

impl Budget {
    fn charge(&self, n: usize) {
        self.queued.fetch_add(n, Ordering::AcqRel);
    }

    /// **Saturating**, because an underflow here is not a wrong number
    /// but a wedged connection: a count wrapped to `usize::MAX` reads as
    /// a spent budget forever, and the forwarder never queues again.
    fn release(&self, n: usize) {
        if n > 0 {
            let _ = self
                .queued
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |q| {
                    Some(q.saturating_sub(n))
                });
        }
        self.drained.notify_one();
    }

    /// Take back a charge for a frame that was not queued, **without**
    /// ringing `drained` — nothing left the queue, and a ring here would
    /// wake the forwarder that is about to wait on it.
    fn uncharge(&self, n: usize) {
        let _ = self
            .queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |q| {
                Some(q.saturating_sub(n))
            });
    }

    fn spent(&self) -> bool {
        self.queued.load(Ordering::Acquire) >= ATTACH_QUEUE_BYTES
    }
}

/// The `Attach` frame's fields, once it is known to be one.
struct Handshake {
    session: String,
    mode: AttachMode,
    role: AttachRole,
    client_kind: ClientKind,
    client_version: String,
    protocol_major: u32,
    /// The client's terminal, as it declared it (GH #66). `None` from a
    /// pipe or from a client older than the field.
    terminal: Option<String>,
}

/// Tell every client attached to `session_id` the geometry, skipping any
/// that already knows it.
///
/// **One rule, replacing two** (GH #66 review). The originator used to be
/// handled by "tell it when the answer is not what it asked" and everybody
/// else by "tell them when the size changed". The first re-sent an
/// identical frame on every `SIGWINCH` of a drag that changed nothing — a
/// 120-column client against an 80-column peer got one per frame — which
/// is the flood this issue is about, moved from the terminal to a bounded
/// 64-frame queue where it can get its own sender dropped as a slow
/// consumer. (Since GH #210 a full queue detaches nobody; a flood would
/// instead fill the [`ANCILLARY_SLOTS`] a secret prompt raised meanwhile
/// needs, which is the same reason to send each client each size once.)
///
/// Asking whether the client already knows subsumes both, and it is the
/// question the two rules were separately approximating.
fn broadcast_size(
    daemon: &Arc<Daemon>,
    session_id: &str,
    size: (u16, u16),
    origin: Option<(u64, (u16, u16))>,
) {
    for c in daemon.attach_hub().clients_of(session_id) {
        {
            let mut told = c.last_told.lock();
            // **A client knows a geometry if it was told it, or if it
            // asked for exactly it.** Both halves are load-bearing.
            //
            // Without the second, the originator of a resize that
            // succeeded exactly as requested is sent its own request back,
            // and `the_resizing_client_does_not_receive_its_own_resize_back`
            // is red for the reason it names: a client that reflows on
            // every `Resize` loops against itself.
            //
            // Without the first, a client is told the same thing over and
            // over — which is what happens to a 120-column client dragging
            // against an 80-column peer, one identical frame per
            // `SIGWINCH`, into a bounded queue.
            let asked_for_this =
                matches!(origin, Some((id, asked)) if id == c.client_id && asked == size);
            if *told == Some(size) || asked_for_this {
                *told = Some(size);
                continue;
            }
            *told = Some(size);
        }
        // Never `send().await`: a resize notification is not worth
        // blocking a read loop behind a client that stopped draining,
        // and that client is on its way out anyway. Through
        // [`queue_ancillary`] so it cannot spend the ending's reserve.
        queue_ancillary(
            &c.tx,
            ServerFrame::Resize {
                cols: size.0,
                rows: size.1,
            },
        );
    }
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

    // **A second writer on a terminal that already has one is refused**
    // (GH #66, `terminal_busy`). Checked here and not in
    // `evaluate_attach`: it is the one refusal that depends on the other
    // clients attached rather than on this connection's own version, and
    // it is checked *after* the registry so a wrong session name is still
    // reported as `session_not_found`.
    //
    // This is not multi-attach being restricted. Two terminals on one
    // session is the feature §4.3 builds the hub for and it is untouched;
    // what cannot work is two *keyboards* that are physically the same
    // keyboard, because the kernel hands each byte to exactly one reader
    // and the operator's `Ctrl-B d` is split between them.
    //
    // **A claim and not a question.** Asking "is it busy" here and
    // registering a hundred lines later is a check-then-act across several
    // `await` points, and every attach connection is its own task — two
    // clients starting together both got "no" and both attached. The claim
    // is test-and-set under one lock, and `_terminal_claim` must stay
    // bound for the life of the connection: its `Drop` is the release, and
    // dropping it here would give the terminal back while still holding it.
    let mut terminal_claim = None;
    if let (AttachMode::ReadWrite, Some(terminal)) = (hs.mode, hs.terminal.as_deref()) {
        match daemon.attach_hub().claim_terminal(terminal, &session.id) {
            Ok(claim) => terminal_claim = Some(claim),
            Err(owner) => {
                let same = owner == session.id;
                let _ = frame::write_frame(
                    &mut wr,
                    &ServerFrame::AttachReject {
                        reason: REJECT_TERMINAL_BUSY.to_string(),
                        // Begins with the token, like every other arm
                        // (§7.5), and then says what to do about it — an
                        // operator told only "busy" will try again and get
                        // the same answer. **Naming the other session
                        // matters when it is a different one**: the advice
                        // "detach that one first" is unfollowable if the
                        // operator is looking at the wrong window.
                        message: if same {
                            format!(
                                "{REJECT_TERMINAL_BUSY} — this terminal already has an \
                                 interactive client on that session; detach that one first, \
                                 or attach from another terminal."
                            )
                        } else {
                            format!(
                                "{REJECT_TERMINAL_BUSY} — this terminal already has an \
                                 interactive client, attached to session {owner}; detach \
                                 that one first, or attach from another terminal. Two \
                                 clients on one keyboard are handed alternate keystrokes \
                                 by the kernel, so neither reliably sees a detach."
                            )
                        },
                    },
                )
                .await;
                return;
            }
        }
    }

    // **Subscribe before `Attached` is written.** §7.5: *"The frame is
    // sent before any `Output` frames"* — which is an ordering claim and
    // also a completeness one. Subscribing afterwards is a race that
    // loses whatever the child printed while `Attached` was in flight,
    // and it loses it *silently*: the frames still arrive in the right
    // order, so an ordering-only assertion cannot see it.
    let output = session.subscribe();
    // **Where this connection's stream starts, and the picture it starts
    // from** (GH #235, GH #200). The floor is read after the subscribe and
    // before the capture, and both orderings are load-bearing:
    //
    // * after the subscribe, so every byte past the floor is either in
    //   this receiver or still in the ring buffer — `forward_output`
    //   resyncs from the ring whenever the receiver cannot account for an
    //   offset, so nothing between the two is lost, it is only fetched
    //   from a different place;
    // * before the capture, because the capture reflects the screen
    //   tracker's position and the tracker only moves forward. A floor
    //   read *after* it could land past what the picture shows and skip
    //   the bytes in between with no gap to say so; read before, the
    //   worst case is a few bytes drawn twice (`Session::stream_floor`).
    //
    // It is also the origin a gap is measured from: a connection that
    // falls behind the ring's tail is told the distance from *here*, not
    // from the start of the session — which `a_client_that_falls_behind_is_never_detached_and_loses_nothing_silently`
    // pins at runtime by printing past the ring before it joins.
    let floor = session.stream_floor();
    let snapshot = screen_snapshot(&session, &daemon.server.processor);
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
        last_size: parking_lot::Mutex::new(None),
        // Seeded with what `Attached` is about to carry: a geometry this
        // client has already been told, so the first correction it gets is
        // a real change rather than an echo of its own handshake.
        last_told: parking_lot::Mutex::new(Some(session.size())),
    });

    // Queued first, so the FIFO is what makes it frame one rather than a
    // timing argument about two tasks.
    if tx.send(attached_frame(&session)).await.is_err() {
        return;
    }
    // **The screen, second, and before the replayed prompt** (GH #235).
    // A renderer paints the snapshot over the whole terminal, so anything
    // drawn ahead of it is painted over — the replayed `AwaitingSecret`
    // below included, which is the one frame here a human must not miss.
    if let Some(frame) = snapshot {
        if tx.send(frame).await.is_err() {
            return;
        }
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
                raised_by: Some(req.raised_by.as_str().to_string()),
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
    //
    // **Seeded from the ring behind the floor, never started empty**
    // (`StreamRedactor::resume_at`). A redactor that starts at the join
    // has not seen the key header whose body a pager is about to repaint,
    // or the partial a key still printing holds open, and sends that body
    // raw to the one client that joined late.
    let redactor = match conn.role {
        AttachRole::Interactive => None,
        AttachRole::Observer => Some(super::redact_stream::StreamRedactor::resume_at(
            Arc::clone(&daemon.server.processor),
            &stream_behind(&session, floor),
            floor,
        )),
    };

    // §4.3's bound for this connection, in bytes, shared by the one task
    // that fills the queue and the one that drains it (GH #210) — and the
    // stall bound, which is the writer's alone, because the writer is the
    // only task that can see whether the socket is accepting anything.
    let budget = Arc::new(Budget::default());
    let (stalled_tx, mut stalled) = oneshot::channel::<()>();
    let writer = tokio::spawn(write_loop(
        wr,
        rx,
        Arc::clone(&budget),
        daemon.attach_hub().stall_timeout(),
        stalled_tx,
    ));
    let mut forwarder = tokio::spawn(forward_output(
        Arc::clone(&session),
        conn.session_id.clone(),
        output,
        exit_events,
        tx.clone(),
        redactor,
        floor,
        budget,
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
            // **Not `SlowConsumer` any more** (GH #210). The forwarder
            // used to be the task that detected a slow client, by finding
            // the queue full; it now waits for room instead, so the only
            // way it stops without an exit is the queue closing under it
            // — the writer left because the socket failed, which is the
            // peer going away. A stalled peer is the writer's to report,
            // one arm down.
            _ => Ending::ClientDetach,
        },
        // §4.3's slow consumer, **as a stall rather than an overflow**
        // (GH #210): the socket accepted no bytes for the stall bound
        // while the writer had bytes for it. A writer that ended without
        // reporting one dropped the sender, which is the socket failing —
        // the peer went away, and that is a detach, not a verdict.
        stall = &mut stalled => match stall {
            Ok(()) => Ending::SlowConsumer,
            Err(_) => Ending::ClientDetach,
        },
        // Last, and only because the three above are cheap channel waits
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

    // **A departing writer relaxes the minimum** (GH #66). The session is
    // sized to the smallest attached writer, so the client that was
    // holding it narrow leaving must give the columns back — otherwise a
    // 200-column terminal stays clamped to the 80 of a peer that is no
    // longer there, and nothing but a manual resize would ever free it.
    //
    // Ordered **after** `unregister` so this connection is already out of
    // the fold, and under the same lock as the read-loop's sequence so the
    // two cannot interleave into a stale apply. The comparison is
    // clamped-against-clamped: `writer_min_size` now folds clamped values,
    // so an out-of-range claim can no longer make this test permanently
    // true and turn every detach into a broadcast of a size that did not
    // move.
    if conn.mode == AttachMode::ReadWrite && conn.last_size.lock().is_some() {
        let achieved = daemon.attach_hub().with_resize_decision(|| {
            // **With no writers left this is the agent's desired size**, so
            // the last human detaching returns the session to what a tool
            // asked for rather than stranding it at a departed client's
            // geometry — which nothing could observe or undo (GH #75).
            let want = daemon
                .attach_hub()
                .effective_size(&conn.session_id, session.desired_size())?;
            if want == session.size() {
                return None;
            }
            match session.resize(want.0, want.1) {
                Ok(()) => Some(session.size()),
                Err(e) => {
                    crate::diag!("holdfast daemon: resize after detach failed: {e}");
                    None
                }
            }
        });
        if let Some(achieved) = achieved {
            // No originator: nobody asked for this, the constraint simply
            // lifted, so every remaining client is learning it.
            broadcast_size(&daemon, &conn.session_id, achieved, None);
        }
    }

    // **The claim goes here, not when this task ends.** `run` continues
    // past this point into `writer.await`, which parks for as long as the
    // peer's socket stays full — on the `slow_consumer` ending it is
    // already parked by definition. A claim held that long is a terminal
    // no other client can use, whose refusal advises detaching a client
    // the daemon has already detached.
    drop(terminal_claim);

    // **The one place `Detached` is emitted**, for all three of its wire
    // reasons. `client_detach` is deliberately absent — §7.5: *"The
    // client sent `Detach`; there is nobody left to tell."* Adding it
    // would turn a closed set of three into four on a §23.3 surface the
    // web UI mirrors verbatim, and it is exactly the change that looks
    // like completing a set.
    //
    // `try_send` and not `send().await`: the writer may be parked on a
    // full socket, and this task must not park behind it.
    //
    // **It arrives, and that is new** (GH #200). This paragraph used to
    // say the frame was best effort and genuinely might not arrive on
    // the `slow_consumer` path — true, because it was written onto the
    // very queue whose overflow caused the ending, and it is exactly why
    // `holdfast watch` reported a bare EOF as *"the daemon closed the
    // connection"* after losing nine tenths of a burst. [`ENDING_SLOTS`]
    // keeps room for it now, and `write_loop` drains what is queued
    // before the socket closes, so a `try_send` here cannot fail for
    // want of space on any of the three paths.
    //
    // **On the `slow_consumer` path it arrives if the client comes back
    // within one more stall bound, and not otherwise** (GH #210). The
    // client is detached *because* its socket accepted nothing, so a
    // frame queued behind that socket can only reach a client that
    // starts reading again; `write_loop` keeps trying for one more
    // [`ATTACH_STALL_TIMEOUT`] and then closes. A client suspended for
    // longer than both reads a bare EOF when it resumes — and the daemon
    // does not hold a socket open indefinitely for a peer that may never
    // read it, which is the leak #209's revert was about.
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
    /// The queue closed under it: the writer is gone, because the socket
    /// failed. **Not a slow consumer** any more — since GH #210 a full
    /// queue makes the forwarder wait rather than give up, and a stalled
    /// client is reported by the writer.
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
            terminal,
        }) => Some(Handshake {
            session,
            mode,
            role,
            client_kind,
            client_version,
            protocol_major,
            terminal,
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
            ClientDecode::Frame(ClientFrame::Resize {
                cols: asked_cols,
                rows: asked_rows,
            }) => {
                // **What this client can display, not what the session
                // becomes** (GH #66). Recorded first, then folded with
                // every other writer's: the session gets the minimum, so
                // no attached terminal is ever asked to show more columns
                // than it has. tmux's rule, and for tmux's reason.
                // **Clamped on the way in, and a degenerate report is
                // not a claim at all** (GH #66 review). `TIOCGWINSZ`
                // answers `0` on a pty that was never sized — a harness,
                // an emulator's startup transient, ssh before
                // negotiation — and the client forwards it verbatim as its
                // opening `Resize`. Stored raw, that `0` won every
                // minimum, `Session::resize` clamped it to the 2x2 floor,
                // and **no other writer could lift it**: under
                // last-writer-wins the next frame from anyone repaired it,
                // under a fold only that client can. Reproduced at 2x2
                // with a 120x40 peer unable to move it.
                //
                // A client that cannot state a size is therefore recorded
                // as having stated none, rather than as claiming the
                // smallest one representable.
                let claim = if asked_cols == 0 || asked_rows == 0 {
                    None
                } else {
                    Some(crate::pty::clamp_geometry(asked_cols, asked_rows))
                };

                // **Fold, apply and read back under one lock.** The fold
                // is order-independent; the sequence was not. Two writers
                // on a multi-thread runtime could each fold and then apply
                // in the opposite order, leaving the session at a departed
                // or stale writer's geometry with no further event to
                // correct it — the state this policy exists to prevent.
                let outcome = daemon.attach_hub().with_resize_decision(|| {
                    *conn.last_size.lock() = claim;
                    let before = session.size();
                    // Folded with what the *agent* asked for, so a client's
                    // window narrows the session without erasing the size a
                    // tool set (GH #75).
                    let want = daemon
                        .attach_hub()
                        .effective_size(&conn.session_id, session.desired_size());
                    match want {
                        Some((c, r)) => match session.resize(c, r) {
                            Ok(()) => Some((before, session.size())),
                            Err(e) => {
                                crate::diag!("holdfast daemon: attach resize failed: {e}");
                                None
                            }
                        },
                        // Nobody is claiming a size — this client withdrew
                        // the only one. Leaving the geometry alone beats
                        // resizing to a default nobody asked for.
                        None => None,
                    }
                });
                let Some((before, achieved)) = outcome else {
                    continue;
                };
                // §4.1: an attach `Resize` from a ReadWrite client is
                // activity. The `resize` **tool** is not, which is why
                // the stamp is here and not inside `Session::resize`.
                session.note_activity();
                let _ = before;

                // §7.5: *"canonical PTY size, e.g. when another client
                // resizes."* The size is re-read from the session rather
                // than echoed from the request, so what the other panes
                // reflow to is the geometry the terminal actually got —
                // `Session::resize` clamps, and a client that asked for
                // 5000 columns must not tell everybody else it succeeded.
                //
                // **Told-once, per client.** This replaces two separate
                // rules — "others hear it if it changed" and "the
                // originator hears it if it is not what it asked" — with
                // the question both were approximating: does this client
                // already know? The originator rule alone re-sent an
                // identical correction on every frame of a drag that
                // changed nothing, which is a flood on the wire rather
                // than on the terminal, and enough of one to have a client
                // dropped as a slow consumer by its own window drag.
                broadcast_size(
                    daemon,
                    &conn.session_id,
                    achieved,
                    // **What it actually asked, not the clamped claim.**
                    // A client that asked for 5000 columns and got 1000
                    // does not know the answer, and passing the clamped
                    // value here would say it does.
                    Some((conn.client_id, (asked_cols, asked_rows))),
                );
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
            ClientDecode::Frame(ClientFrame::SecretInput {
                request_id,
                bytes,
                allow_echo,
            }) => {
                // **Into the zeroing type before anything else looks at
                // it, including the cap check.** `received` does not copy
                // or normalise; it takes the decoded allocation, so every
                // exit *from this arm* zeroes the plaintext by dropping
                // it — the two refusals below and the accept path.
                //
                // GH #57 filed the refusals as forgetting to zero. They
                // did, but the reason they could is that this was a bare
                // `Vec<u8>` with three exits and a discipline; it is now
                // one value with one `Drop`.
                //
                // **This arm is not the whole story, and review found the
                // first version of this comment claiming it was.** A
                // `SecretInput` that never reaches here — refused by the
                // ReadOnly gate above, or decoded as `BadFields` — still
                // drops its cleartext frame un-zeroed, across an `await`.
                // That is GH #82, and it is a wider hole than the one
                // this line closes. There is also no cancellation window
                // between here and the write: no suspension point sits
                // between them, so there is nothing for a `select!` to
                // cancel.
                let bytes = super::secret::SecretBytes::received(bytes);

                // **The cap is measured here, on the received bytes and
                // before anything is copied.** Normalisation strips a
                // trailing newline and may append one, so a check made
                // afterwards would put the boundary where the client's
                // newline habit put it — and an implementation that
                // normalised first has already built the short-lived type
                // around a value it is about to throw away.
                //
                // **An unadopted raise inherits the operator's ceiling
                // rather than no bound at all** (GH #126's class, found
                // by review of GH #127). `RaisedRequest.max_secret_bytes`
                // is a *waiting call's* argument, so every raise with no
                // call on it carries `None` — §7.5's replay, §8.3's echo
                // drop, and the re-raise a caller's ending leaves behind.
                // Read as "unbounded", the only thing left standing
                // between a human's keystrokes and the child is
                // `MAX_FRAME_BYTES`, 16 MiB, against an operator ceiling
                // of 64 KiB. `[security] max_secret_bytes_ceiling` is the
                // operator's stated limit on every credential this daemon
                // will accept from any path, so the paths with no caller
                // to narrow it inherit the widest thing the operator
                // agreed to — the same reading `autofill_on_echo_drop`
                // gives the unattended provider path, for the same
                // reason. A limit accepted and not applied is worse than
                // one refused.
                let ceiling = daemon.server.config.security.max_secret_bytes_ceiling;
                let cap = daemon
                    .attach_hub()
                    .secrets()
                    .submission_bounds(&conn.session_id, &request_id)
                    .map_or(ceiling, |(cap, _)| cap.unwrap_or(ceiling));
                // Widened to `usize` rather than narrowing the length:
                // a cast the other way truncates, and a truncation here
                // turns an oversized submission into an accepted one.
                let over_cap = bytes.len() > cap as usize;

                // The request is closed **before** the write is queued and
                // by the same atomic step that decides whether this
                // client is the one fulfilling it: two clients answering
                // the same prompt must produce one write, not two, and a
                // check-then-clear would let both through.
                match daemon
                    .attach_hub()
                    .close_secret(&conn.session_id, Some(&request_id))
                {
                    // Over the waiting call's `max_secret_bytes`. Nothing
                    // is written, nothing is normalised, and the request
                    // closes: the child is still blocked, and the agent is
                    // told which of the four reasons it was.
                    //
                    // **`drop` is the zeroing**, and it is explicit rather
                    // than left to the end of the arm so the plaintext is
                    // gone before `settle` runs rather than after.
                    Some(raised) if over_cap => {
                        drop(bytes);
                        super::secret::zero_bytes(&mut body);
                        SecretAnswer::new(daemon, session, raised).settle(
                            crate::secret::Resolution::Cancelled(
                                crate::secret::CancelReason::TooLarge,
                            ),
                            "cancelled",
                        );
                    }
                    Some(raised) => {
                        // §5.2's normalisation is applied here, by the
                        // daemon, so the behaviour does not depend on
                        // which client submitted. `append_newline`
                        // defaults to `true` — an echo-off prompt is
                        // waiting for a line — and is the waiting call's
                        // own argument when there is one.
                        let value = bytes.normalised(raised.append_newline);
                        // **GH #137: gated unless the human opted out.**
                        // `WriteRequest::secret` performs the write
                        // unconditionally, and this arm used it for every
                        // submission — so a credential typed at a prompt
                        // the *agent* raised, into a child that had not
                        // dropped `ECHO`, was echoed by the line
                        // discipline into the ring buffer and handed back
                        // to that same agent by `read_output`. The
                        // condition is evaluated on the writer thread one
                        // statement before the write, against the tty
                        // rather than a cache of it.
                        //
                        // **`expect_writes` is `None` and that is not the
                        // same omission.** The counter guards a provider
                        // round trip, and this path has none: the
                        // keystrokes go from the socket to the queue in
                        // this arm with no await in between. What it
                        // shares with the autofill is only that nobody
                        // consulted the child.
                        //
                        // **`allow_echo` is the human's decision, not the
                        // agent's.** It reaches no tool argument and no
                        // config key; it arrives on the frame a person at
                        // an attached client sent, which is the only
                        // party who can see whether the terminal echoes
                        // and accept that it does. A TOTP prompt or a
                        // REPL that never clears `ECHO` stays reachable
                        // through the masked path this way — pushing it
                        // to `send_input` would be strictly worse, since
                        // that has no masking at all.
                        let (write, ack) = if allow_echo {
                            let (w, rx) = WriteRequest::secret(value);
                            (w, Submitted::EchoAllowed(rx))
                        } else {
                            let (w, rx) = WriteRequest::secret_if_echo_off(value);
                            (w, Submitted::Gated(rx))
                        };
                        // The frame body still holds the value in
                        // cleartext and is about to be reused for the
                        // next frame; `SecretBytes` owns only the decoded
                        // copy.
                        //
                        // **Before the first await, not after it.** This
                        // read loop is one branch of `run`'s `select!` and
                        // is therefore dropped where it stands whenever
                        // either of the two branches above it completes;
                        // a `zero_bytes` sited past an await point is a
                        // `zero_bytes` a cancellation skips, and what it
                        // skips is a full cleartext copy of the
                        // credential.
                        super::secret::zero_bytes(&mut body);

                        // **From here the request is owned, and
                        // `SecretAnswer` is what makes "owned" survive
                        // this future being dropped.** Taking a
                        // `RaisedRequest` out of the slot takes the only
                        // `oneshot::Sender` the waiting tool call has with
                        // it; dropping it unanswered strands that call and
                        // leaves every other attached client believing the
                        // request is still outstanding.
                        let answer = SecretAnswer::new(daemon, session, raised);

                        if session.write_queue().send(write).await.is_err() {
                            // `mpsc::Sender::send` is cancel-safe in the
                            // direction that matters here: a `send` future
                            // dropped before it completes does not deliver
                            // the message, so a cancellation on this line
                            // leaves nothing queued for the child and
                            // `answer`'s `Drop` reports that truthfully.
                            return;
                        }
                        // §4.1 lists a `SecretInput` from a ReadWrite
                        // client as activity — and it must be, or a
                        // session idle-reaps while a human is typing a
                        // password.
                        session.note_activity();
                        // **The count, and only the count.** The writer
                        // thread reports how many bytes the PTY took;
                        // that number is the whole of what a waiting tool
                        // call learns. A dropped sender means the session
                        // died under the write, which is not a `Provided`.
                        //
                        // **Waited for in a task this connection's
                        // `select!` does not own** — the shape `run`
                        // already uses for `forward_output` and
                        // `forward_events`. Past the `send` above the
                        // write is on the FIFO and the writer thread will
                        // perform it, so a cancellation here would tell
                        // the agent nothing about a credential that
                        // *reached the child*. The enqueue itself stays on
                        // this loop, so a `SecretInput` still orders ahead
                        // of whatever frame follows it on the same
                        // connection.
                        let for_ack = Arc::clone(session);
                        tokio::spawn(async move {
                            match ack.resolve().await {
                                Submission::Written(n) => answer.settle(
                                    crate::secret::Resolution::Provided {
                                        bytes_written: n as u64,
                                    },
                                    "fulfilled",
                                ),
                                // **The human is told, and that is half
                                // the fix** (GH #137). A silently dropped
                                // secret is its own defect: the person who
                                // typed it believes it was delivered and
                                // the child sits at its prompt forever.
                                //
                                // The route is the one §9.6's autofill
                                // already uses for a declined write — the
                                // `SecretRequestClosed.outcome` word and a
                                // `daemon.log` line — with the correction
                                // that the autofill throws the reason away
                                // and broadcasts a bare `cancelled`. The
                                // word is the specific one here, on the
                                // precedent `caller_cancelled` set: the
                                // field is a free `String` whose golden
                                // records `"<str>"`, `holdfast attach`
                                // prints whatever word it is handed, and
                                // the agent's `secret_cancelled.reason`
                                // carries the same token so the two
                                // vocabularies cannot drift.
                                Submission::Declined(why) => {
                                    crate::diag!(
                                        "holdfast: a submitted secret was not written to \
                                         the session: {why:?}"
                                    );
                                    // **Matched, not assumed.**
                                    // `expect_writes` is `None`, so
                                    // `write_secret_if_unread` cannot
                                    // return `OtherWriteIntervened` and
                                    // the second arm is unreachable —
                                    // which is exactly why it is written
                                    // out. A `_ =>` here would turn a
                                    // third condition added later into a
                                    // *wrong word on the wire*, silently:
                                    // the agent's `secret_cancelled.reason`
                                    // and every attached client's
                                    // `SecretRequestClosed.outcome` would
                                    // name a refusal that did not happen.
                                    // Exhaustive, so that change is a
                                    // compile error instead.
                                    let reason = match why {
                                        crate::session::DeclineReason::NotEchoOff
                                        | crate::session::DeclineReason::OtherWriteIntervened => {
                                            crate::secret::CancelReason::NotEchoOff
                                        }
                                    };
                                    // **A dead session is not an echoing
                                    // one, and the backend cannot tell
                                    // them apart.** `InProcessPty::line_discipline`
                                    // answers `UNKNOWN` for a child that
                                    // has exited, and the gate refuses
                                    // `!= Some(false)` — so a session that
                                    // died between the raise and the write
                                    // declines `NotEchoOff`. Reported as
                                    // such it tells the human *"this
                                    // session's terminal is still echoing,
                                    // re-attach with `--allow-echo`"*,
                                    // which is false and unactionable: the
                                    // session is gone and the flag would
                                    // change nothing.
                                    //
                                    // Classified by liveness, which is the
                                    // rule `SecretAnswer::Drop` already
                                    // applies one screen down and for the
                                    // same reason — where the refusal came
                                    // from says nothing about why the
                                    // request is over.
                                    if for_ack.is_alive() {
                                        answer.settle(
                                            crate::secret::Resolution::Cancelled(reason),
                                            reason.as_str(),
                                        );
                                    } else {
                                        answer.settle(
                                            crate::secret::Resolution::SessionDied {
                                                exit_code: for_ack.exit_code(),
                                            },
                                            "cancelled",
                                        );
                                    }
                                }
                                // **`"fulfilled"` is wrong here and is
                                // left wrong deliberately** — recorded as
                                // a divergence rather than repaired from
                                // this lane (Global Constraint 16).
                                //
                                // The session died under the write, so
                                // whether the child received the bytes is
                                // *unknown*; the MCP call is told
                                // `session_died`, which is honest, and
                                // every attached client is told the
                                // credential was delivered, which is not.
                                // §7.5's `outcome` set carries no word for
                                // "unknown" and `cancelled` would claim
                                // non-delivery just as falsely, so this is
                                // a wire-vocabulary decision on a §23.3
                                // surface rather than a local repair, and
                                // it predates GH #137 — this commit only
                                // moved the expression into a named
                                // variant. Filed rather than guessed.
                                Submission::SessionDied => answer.settle(
                                    crate::secret::Resolution::SessionDied {
                                        exit_code: for_ack.exit_code(),
                                    },
                                    "fulfilled",
                                ),
                            }
                        });
                    }
                    // §18.4: the connection stays open and nothing is
                    // written. A client whose request was superseded
                    // between the prompt and the keystrokes must not have
                    // its password typed into whatever came next.
                    //
                    // **`drop` before the `await`.** The send below is a
                    // suspension point, and a submission that was
                    // superseded is exactly the one most likely to be
                    // sitting here when the connection goes away. `Drop`
                    // would zero it on cancellation regardless; doing it
                    // here means it is gone before the wait rather than
                    // during it.
                    None => {
                        drop(bytes);
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
            // §17.5's `Approved`/`Denied` edge (§7.5, §9.6).
            //
            // **`decided_by` is `conn.client_kind`, off the uid-checked
            // handshake, and never a field of the frame** — the frame has
            // no such field, which is REQ-SEC-018's rule for
            // `redaction_disabled` applied structurally rather than by
            // discipline. A client cannot name itself in an
            // authorisation record.
            //
            // **The ReadOnly gate above has already run.** §18.4's row
            // names this frame: *"an authorisation decision, not an
            // observation."* Nothing here re-checks it, for the same
            // reason no other write arm does — every write arm is
            // downstream of the one gate, and a second check in one arm
            // is how the arms come to disagree.
            //
            // Everything the decision does — resolving the reference,
            // injecting, zeroing, both audit entries — belongs to the
            // waiting call. This arm's whole job is to hand the decision
            // over atomically, which is why `decide` removes and answers
            // under one lock: two clients pressing *approve* on one
            // dialog must produce one resolution.
            ClientDecode::Frame(ClientFrame::ApproveBinding {
                approval_id,
                decision,
            }) => {
                match daemon.attach_hub().approvals().decide(
                    &conn.session_id,
                    &approval_id,
                    decision,
                    conn.client_kind.as_str(),
                ) {
                    crate::secret::Decide::Recorded => {
                        // §4.1 does not list this frame, and it is
                        // activity for the same reason a `SecretInput`
                        // is: a human is at the keyboard and the session
                        // must not idle-reap out from under the approval
                        // they just gave. Stamped **after** the decision
                        // landed and only on the arm that landed one —
                        // a rejected or stale frame moves nothing, which
                        // is REQ-C-005/REQ-S-006's rule and what
                        // `a_rejected_approve_binding_does_not_bump_activity`
                        // pins from the ReadOnly side.
                        session.note_activity();
                    }
                    // No approval outstanding, or one under a different
                    // id: it expired, was superseded, or somebody else
                    // decided it first. **The connection stays open and
                    // nothing is applied**, exactly as the
                    // `SecretInput` arm's `None` branch does — and it is
                    // answered rather than dropped, because a human
                    // whose button did nothing and said nothing presses
                    // it again.
                    //
                    // **`unknown_request_id` is §18.4's nearest
                    // catalogued reason and its Meaning column names
                    // only `SecretInput.request_id`.** The condition is
                    // the same one — *the id you named is not the
                    // outstanding one* — and `frame_kind` is what
                    // distinguishes the two producers, which is what
                    // that field is for. Inventing a sixth reason for a
                    // §23.3 surface would be worse; so would silence.
                    // Recorded as a divergence rather than repaired
                    // from this lane (Global Constraint 16).
                    crate::secret::Decide::UnknownApprovalId => {
                        if tx
                            .send(protocol_error(
                                "unknown_request_id",
                                Some(ClientFrameKind::ApproveBinding.as_str().to_string()),
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

/// Drain the per-connection queue onto the socket, and report a peer
/// that has stopped reading.
///
/// **The one place frames are written, which is the one place
/// [`ServerFrame::Unknown`] must not appear.** That variant carries
/// `#[serde(skip)]`, which under ciborium is a *runtime* error at
/// encode and not a compile error, so "never encoded" is a claim
/// nothing enforces. The `debug_assert` makes a debug build fail at the
/// line that built the frame instead of dropping it in release.
///
/// **And the one task that can tell a slow client from a stopped one**
/// (GH #210). Every socket `write` is given `stall` to accept *any*
/// bytes; one that accepts some resets the clock, however few. So a
/// client draining a burst over a slow link is never detached, and one
/// that has stopped reading is reported through `stalled` exactly
/// `stall` after its socket filled. An occupancy bound cannot make that
/// distinction — a full queue looks the same from the forwarder's side
/// in both cases — which is why #209's attempt to raise one had to pick
/// between detaching a live client and never detaching a dead one.
///
/// **After a stall the writer keeps going for one more `stall`, and then
/// it stops whether or not the queue is empty.** `run` has queued
/// `Detached { reason: "slow_consumer" }` by then; a client that resumes
/// inside the window reads everything queued ahead of it and then the
/// frame, and one that does not is closed on rather than waited for.
/// Bounded either way, which is the property the two tasks and the
/// socket this holds needed.
///
/// A writer that ends for any other reason — the socket failed, or every
/// `Sender` is gone — drops `stalled` unsent, which `run` reads as the
/// peer having gone away.
async fn write_loop(
    mut wr: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::Receiver<ServerFrame>,
    budget: Arc<Budget>,
    stall: std::time::Duration,
    stalled: oneshot::Sender<()>,
) {
    // **A writer that leaves rings the forwarder on its way out.** A
    // forwarder waiting for room waits on `drained`, and a writer that
    // returns on a failed socket would otherwise leave it parked until
    // `run` aborts it; woken, it sees the queue closed and stops itself.
    struct WakeOnExit(Arc<Budget>);
    impl Drop for WakeOnExit {
        fn drop(&mut self) {
            self.0.drained.notify_one();
        }
    }
    let _wake = WakeOnExit(Arc::clone(&budget));

    let mut stalled = Some(stalled);
    let mut give_up_at: Option<tokio::time::Instant> = None;
    while let Some(f) = rx.recv().await {
        debug_assert!(
            !matches!(f, ServerFrame::Unknown { .. }),
            "Unknown is decode-only (§7.5)"
        );
        let charged = stream_bytes(&f);
        let Ok(encoded) = frame::encode(&f) else {
            // Nothing the daemon builds exceeds `MAX_FRAME_BYTES` — the
            // largest is one `MAX_BATCH_BYTES` batch — so this is a bug,
            // and the connection cannot carry on with a frame missing
            // from the middle of it.
            return;
        };
        let mut written = 0usize;
        while written < encoded.len() {
            let deadline = give_up_at.unwrap_or_else(|| tokio::time::Instant::now() + stall);
            match tokio::time::timeout_at(deadline, wr.write(&encoded[written..])).await {
                Ok(Ok(0)) | Ok(Err(_)) => return,
                Ok(Ok(n)) => written += n,
                Err(_) if give_up_at.is_some() => return,
                Err(_) => {
                    if let Some(tx) = stalled.take() {
                        let _ = tx.send(());
                    }
                    give_up_at = Some(tokio::time::Instant::now() + stall);
                }
            }
        }
        budget.release(charged);
    }
}

/// The bytes a frame counts against [`ATTACH_QUEUE_BYTES`]: an `Output`'s
/// payload, and nothing for anything else. The ancillary frames and the
/// ending are bounded by their slots, not their size.
fn stream_bytes(f: &ServerFrame) -> usize {
    match f {
        ServerFrame::Output { bytes, .. } => bytes.len(),
        _ => 0,
    }
}

/// Forward this session's live output onto the connection's queue.
///
/// **Attach clients receive only bytes** (REQ-D-007). The internal
/// frame carries `start`/`end`; the wire carries `Output { session,
/// bytes }` and §4.1 is explicit that *"raw offsets are not part of the
/// public attach protocol in v0.1.0"*. The conversion is [`Stream`]'s.
///
/// **A cursor into the ring buffer, with the broadcast as its doorbell**
/// (GH #210). The connection owns one number — the offset of the next
/// byte it is owed — and takes that byte from whichever place still has
/// it: the broadcast frame in hand when it is keeping up, the session's
/// ring buffer when it is not. That is REQ-C-006's resync, which every
/// other offset-aware consumer already did, and which attach clients were
/// the one exception to. The exception was the defect. With the broadcast
/// as the only source, 256 frames was the whole of a connection's
/// headroom — 256 PTY reads, which a 1,500-line test run overflows by a
/// factor of six — and everything past it was either a gap or, one bound
/// earlier, a `slow_consumer` detach. The ring holds a megabyte by
/// default and counts bytes, which is the unit a burst is measured in.
///
/// So:
///
/// * a **lag** is not a loss. The receiver cannot account for the next
///   offset any more, so the forwarder reads it out of the ring — every
///   byte, in order, exactly once, because a frame that ends at or before
///   the cursor is skipped and one that starts past it sends the cursor
///   to the ring for the difference;
/// * a **full queue** is not a detach. The forwarder stops reading until
///   the writer drains ([`Budget`]), and what it has not read waits in
///   the ring, which the reader fills regardless — the reader is never
///   blocked, and a paused forwarder holds no more memory than it did;
/// * only what the ring has **evicted** is lost, and it is announced as
///   `OutputGap` with the exact byte count: the distance from the cursor
///   to the ring's tail. A client must fall a whole ring behind for that,
///   which is a statement about the client and not about how the child
///   happened to chunk its output.
///
/// **Detaching a client that has stopped reading is `write_loop`'s job**,
/// by the clock rather than by occupancy — see [`ATTACH_STALL_TIMEOUT`]
/// for why those had to become two mechanisms.
///
/// **Redaction is fed the chunks the reader produced when there are any,
/// and reader-sized chunks when there are not** (§9.2, GH #135). Frames
/// taken live go to `StreamRedactor::feed` one at a time, exactly as
/// before, and only their *outputs* are batched; a stretch read back out
/// of the ring is fed in [`BACKFILL_CHUNK_BYTES`] pieces. A gap is still
/// deliberately **not** used to reset the redactor: its lookbehind would
/// then straddle a discontinuity, which changes what matches.
#[allow(clippy::too_many_arguments)]
async fn forward_output(
    session: Arc<Session>,
    session_id: String,
    mut output: tokio::sync::broadcast::Receiver<crate::session::OutputFrame>,
    mut exits: tokio::sync::broadcast::Receiver<crate::session::SessionEvent>,
    tx: mpsc::Sender<ServerFrame>,
    redactor: Option<super::redact_stream::StreamRedactor>,
    start: u64,
    budget: Arc<Budget>,
) -> Forwarded {
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};

    let mut stream = Stream {
        session_id,
        tx,
        budget,
        redactor,
        next: start,
        behind: false,
    };

    // **The client that arrived after the edge had already passed.**
    // `SessionEvent::Exited` is sent once, by the reader thread, and a
    // connection that subscribed afterwards can never see it. Nor does
    // the output broadcast ever close: §5.5.1 retains exited sessions
    // — deliberately, so `holdfast logs` can still read one — and the
    // `Session` holds its own `Sender`. So without this the task parked
    // forever on two channels that were never going to produce
    // anything, and `holdfast watch <exited-session>` hung until the
    // operator found Ctrl-C.
    //
    // **Keyed on the reader having finished, not only on the child being
    // dead** (GH #210, GH #42's distinction). The edge is published after
    // `reader_finished`, and `run` subscribed before this task existed,
    // so a reader still draining when this line runs will publish an
    // edge this connection receives — the loop below handles that case,
    // with the whole of the child's output. Only a reader that finished
    // before the check can have published an edge this connection
    // missed, and then the buffer is final and everything owed is in the
    // ring. The old check read `is_alive()` alone and drained the
    // broadcast's ring of frames; a reader still pushing the child's
    // last bytes then lost them.
    //
    // Everything the connection is owed goes out **before**
    // `SessionExited`: `a_session_that_exited_during_the_handshake_still_delivers_its_last_bytes`
    // is red with the whole frame list being `[SessionExited { code: 7 }]`
    // when this path skips the catch-up.
    if !session.is_alive() && session.reader_finished() {
        if let Queued::Stopped = stream.catch_up(&session).await {
            return Forwarded::Stopped;
        }
        return stream.exit(reported_exit_code(&session)).await;
    }

    loop {
        if stream.behind {
            match stream.read_ring(&session).await {
                Queued::Sent => continue,
                Queued::Stopped => return Forwarded::Stopped,
            }
        }
        // **Room first, then read.** A forwarder that pulled frames it
        // had nowhere to put would hold them in its own memory; one that
        // waits leaves them on the broadcast, and a broadcast that laps
        // it costs nothing but a trip to the ring.
        if let Queued::Stopped = stream.room().await {
            return Forwarded::Stopped;
        }
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
        let first = match next {
            Either::Output(Ok(f)) => f,
            // §4.3: a lag is resynced by continuing — **from the ring**,
            // which still holds what the channel dropped (GH #210).
            Either::Output(Err(RecvError::Lagged(n))) => {
                crate::diag!(
                    "holdfast daemon: attach client on {} lagged {n} frames; \
                     resuming from the ring buffer",
                    stream.session_id
                );
                stream.behind = true;
                continue;
            }
            // **The backstop that hardly ever fires.** The output
            // broadcast is closed only when the `Session` itself is
            // dropped — the `Session` keeps its own `Sender` — so this is
            // a session torn out from under a live connection, which this
            // task's own `Arc<Session>` rules out. Flushed best effort
            // for the reason `exit` flushes, and not waited for: there is
            // no exit code to follow it with.
            Either::Output(Err(RecvError::Closed)) => {
                if let Some(tail) = stream.redactor.as_mut().map(|r| r.flush()) {
                    if !tail.is_empty() {
                        stream.budget.charge(tail.len());
                        let _ = offer_stream(
                            &stream.tx,
                            ServerFrame::Output {
                                session: stream.session_id.clone(),
                                bytes: tail,
                            },
                        );
                    }
                }
                return Forwarded::Stopped;
            }
            // §7.5's exit sequence starts here, with everything the
            // connection is still owed: the reader published this edge
            // after its last push, so the ring is final and a catch-up
            // reaches the child's last byte.
            Either::Event(Ok(crate::session::SessionEvent::Exited { code })) => {
                if let Queued::Stopped = stream.catch_up(&session).await {
                    return Forwarded::Stopped;
                }
                return stream.exit(code).await;
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

        // **Batch what is already waiting** (GH #210): the frame in hand
        // and every frame behind it that is readable now, up to one
        // batch. A forwarder that fell behind while descheduled catches
        // up in a few frames rather than one per PTY read.
        let mut batch = Vec::new();
        stream.take(&first, &mut batch);
        while batch.len() < MAX_BATCH_BYTES && !stream.behind {
            match output.try_recv() {
                Ok(f) => stream.take(&f, &mut batch),
                Err(TryRecvError::Lagged(_)) => stream.behind = true,
                Err(_) => break,
            }
        }
        if let Queued::Stopped = stream.send_output(batch).await {
            return Forwarded::Stopped;
        }
    }
}

/// One connection's position in the session's byte stream, and the
/// queue it feeds (GH #210).
struct Stream {
    session_id: String,
    tx: mpsc::Sender<ServerFrame>,
    budget: Arc<Budget>,
    redactor: Option<super::redact_stream::StreamRedactor>,
    /// Absolute offset of the next byte this connection is owed. Only
    /// ever moves forward, which is what makes "each byte at most once"
    /// a property of the arithmetic.
    next: u64,
    /// The broadcast cannot account for `next` — it lagged, or handed
    /// over a frame that starts past it — so the ring is the source until
    /// the cursor catches up.
    behind: bool,
}

impl Stream {
    /// Put the part of `f` this connection has not had yet into `batch`,
    /// redacted.
    ///
    /// Three cases, by offset alone: a frame wholly behind the cursor was
    /// already delivered from the ring and is skipped; a frame that
    /// starts **past** the cursor means bytes in between never reached
    /// this receiver, so the ring is asked for them (the frame's own
    /// bytes are in the ring too, and are read in order with the rest);
    /// anything else is sent from the cursor on.
    fn take(&mut self, f: &crate::session::OutputFrame, batch: &mut Vec<u8>) {
        if f.end <= self.next {
            return;
        }
        if f.start > self.next {
            self.behind = true;
            return;
        }
        let skip = usize::try_from(self.next - f.start).unwrap_or(f.bytes.len());
        batch.extend(redact(&mut self.redactor, &f.bytes[skip..]));
        self.next = f.end;
    }

    /// Wait until the stream may queue another frame: a slot beyond the
    /// ending's and the ancillaries' reserves, and budget left. `Stopped`
    /// if the queue closed — the writer is gone.
    async fn room(&self) -> Queued {
        loop {
            if self.tx.is_closed() {
                return Queued::Stopped;
            }
            if self.tx.capacity() > ENDING_SLOTS + ANCILLARY_SLOTS && !self.budget.spent() {
                return Queued::Sent;
            }
            self.budget.drained.notified().await;
        }
    }

    /// Queue one stream frame, **waiting for room rather than being
    /// refused** (GH #210) — the refusal was the detach.
    async fn send(&self, frame: ServerFrame) -> Queued {
        let charged = stream_bytes(&frame);
        let mut frame = frame;
        loop {
            if let Queued::Stopped = self.room().await {
                return Queued::Stopped;
            }
            self.budget.charge(charged);
            match offer_stream(&self.tx, frame) {
                Offered::Queued => return Queued::Sent,
                // An ancillary frame took the slot between the check and
                // the send. Uncharged without ringing `drained`, or the
                // next `room` would wake itself and spin.
                Offered::Full(back) => {
                    self.budget.uncharge(charged);
                    frame = back;
                }
                Offered::Closed => {
                    self.budget.uncharge(charged);
                    return Queued::Stopped;
                }
            }
        }
    }

    /// §7.5's `Output`, from bytes already through the redactor. **The
    /// single conversion point to the wire frame**, for the reason it is
    /// also the single offset-stripping point: a second place that built
    /// an `Output` would be a second place that could forget. Empty
    /// output — a chunk held whole, an empty flush — sends nothing: an
    /// empty `Output` would say the child printed nothing, which it did
    /// not.
    async fn send_output(&self, bytes: Vec<u8>) -> Queued {
        if bytes.is_empty() {
            return Queued::Sent;
        }
        self.send(ServerFrame::Output {
            session: self.session_id.clone(),
            bytes,
        })
        .await
    }

    /// One batch from the ring buffer, from the cursor on — and, if the
    /// ring has already evicted the cursor, the exact size of the hole
    /// first (GH #200's `OutputGap`, GH #210's only remaining source of
    /// one).
    ///
    /// **The notice goes on the queue first**, so a renderer draws the
    /// hole where it happened rather than after the bytes that followed
    /// it. Exact for `interactive`; for an `observer` the redactor may
    /// still be carrying pre-gap bytes, which then land after the notice
    /// — bounded by its carry, and stated rather than repaired, because
    /// flushing the carry to fix the position would emit the bytes the
    /// carry exists to withhold.
    async fn read_ring(&mut self, session: &Session) -> Queued {
        if let Queued::Stopped = self.room().await {
            return Queued::Stopped;
        }
        let read = session.read_from(self.next, MAX_BATCH_BYTES);
        let start = read.cursor - read.bytes.len() as u64;
        if start > self.next {
            let missing = start - self.next;
            self.next = start;
            let gap = ServerFrame::OutputGap {
                session: self.session_id.clone(),
                bytes: missing,
            };
            if let Queued::Stopped = self.send(gap).await {
                return Queued::Stopped;
            }
        }
        // Fewer than a whole batch means the read reached the head: the
        // receiver accounts for everything after it again, because any
        // byte pushed later is published later, to a receiver that has
        // been subscribed all along.
        self.behind = read.bytes.len() >= MAX_BATCH_BYTES;
        let mut out = Vec::with_capacity(read.bytes.len());
        for chunk in read.bytes.chunks(BACKFILL_CHUNK_BYTES) {
            out.extend(redact(&mut self.redactor, chunk));
        }
        self.next = read.cursor;
        self.send_output(out).await
    }

    /// Everything up to the ring's head, for a session whose reader has
    /// finished and whose buffer is therefore final.
    async fn catch_up(&mut self, session: &Session) -> Queued {
        self.behind = true;
        while self.behind {
            if let Queued::Stopped = self.read_ring(session).await {
                return Queued::Stopped;
            }
        }
        Queued::Sent
    }

    /// §7.5's exit sequence, from whichever of its two triggers reached
    /// it.
    ///
    /// **One function and not two copies**, because the ordering is the
    /// requirement: everything the redactor is still carrying is flushed
    /// *first* — a session that died mid-token must not silently swallow
    /// its last line — and only then does `SessionExited` go on the
    /// queue. `Detached` (queued by `run` when this returns) is still
    /// last, on the same FIFO. `flush` emits nothing while withholding,
    /// which is the half that keeps this path from becoming the leak the
    /// carry bound exists to stop.
    ///
    /// **The carry waits for room like any other output** (GH #210), and
    /// that retires the branch GH #200 added here. The flush used to be
    /// refused on a queue at the reserve and was then reported as an
    /// `OutputGap` so it would not vanish in silence; a stream that waits
    /// cannot be refused, so the carry is delivered instead of counted.
    /// A client that never makes room is detached by the writer's stall
    /// bound, and an exit it never read is not one it needed.
    ///
    /// `SessionExited` itself is a `try_send` into [`ENDING_SLOTS`], which
    /// the stream never takes.
    async fn exit(mut self, code: i32) -> Forwarded {
        if let Some(tail) = self.redactor.as_mut().map(|r| r.flush()) {
            if let Queued::Stopped = self.send_output(tail).await {
                return Forwarded::Stopped;
            }
        }
        let _ = self.tx.try_send(ServerFrame::SessionExited { code });
        Forwarded::SessionExit
    }
}

/// Whether a stream frame reached the connection's queue, or the
/// connection is over.
///
/// A named two-state answer rather than a `bool`, because the caller's
/// obligation on the second one is to *stop* — a `bool` at a call site
/// reads as "delivered?" and invites being ignored.
enum Queued {
    /// On the queue, or deliberately nothing to send.
    Sent,
    /// The queue closed: the writer is gone.
    Stopped,
}

/// What one non-waiting attempt to queue a stream frame did.
enum Offered {
    Queued,
    /// Refused, and handed back: the queue is at the ending's reserve.
    Full(ServerFrame),
    Closed,
}

/// Put a stream frame on the queue **without spending [`ENDING_SLOTS`]**,
/// or hand it back.
///
/// The synchronous half of [`Stream::send`], which is the only caller
/// that waits; the reserve is checked here, before the send, because
/// `try_send` reports "full" and cannot report "full except for the
/// reserve".
fn offer_stream(tx: &mpsc::Sender<ServerFrame>, frame: ServerFrame) -> Offered {
    use tokio::sync::mpsc::error::TrySendError;
    if tx.capacity() <= ENDING_SLOTS {
        return Offered::Full(frame);
    }
    match tx.try_send(frame) {
        Ok(()) => Offered::Queued,
        Err(TrySendError::Full(back)) => Offered::Full(back),
        Err(TrySendError::Closed(_)) => Offered::Closed,
    }
}

/// Redact one chunk for this connection — **the single redaction point**
/// for bytes on their way to an attach client.
///
/// One place, for the reason [`Stream::send_output`] is one place: a
/// second call site that fed the redactor could be a call site that
/// forgot to, and §9.2's guarantee is that an observer never sees an
/// unredacted byte. Every path to a byte — a live frame, a catch-up from
/// the ring, the exit flush aside — comes through here.
fn redact(redactor: &mut Option<super::redact_stream::StreamRedactor>, bytes: &[u8]) -> Vec<u8> {
    match redactor.as_mut() {
        Some(r) => r.feed(bytes),
        None => bytes.to_vec(),
    }
}

/// The ring's bytes that end at `floor` — as many as a joining
/// observer's redactor is seeded with, fewer where the ring has already
/// evicted them.
///
/// The read starts [`RESUME_CONTEXT_BYTES`] behind the floor and is cut
/// at the floor, so what it returns ends exactly there: the redactor's
/// offsets and the stream's then agree, and a byte after the floor is
/// never context — it is the stream, and the stream's to send.
///
/// [`RESUME_CONTEXT_BYTES`]: super::redact_stream::RESUME_CONTEXT_BYTES
fn stream_behind(session: &Session, floor: u64) -> Vec<u8> {
    use super::redact_stream::RESUME_CONTEXT_BYTES;
    let read = session.read_from(
        floor.saturating_sub(RESUME_CONTEXT_BYTES as u64),
        RESUME_CONTEXT_BYTES,
    );
    let start = read.cursor - read.bytes.len() as u64;
    let mut bytes = read.bytes;
    bytes.truncate(usize::try_from(floor.saturating_sub(start)).unwrap_or(usize::MAX));
    bytes
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
            Ok(SessionEvent::AwaitingSecretEntered {
                episode,
                prompt_text,
            }) => {
                // **`raise_secret_on_edge` and not `raise_secret`**, and
                // this is the only call site of it: a raise made *here* is
                // a reaction to one echo-drop edge, so it is the one raise
                // that may claim a credential §9.6's autofill wrote with
                // no raise to close (GH #105). §7.5's replay in `run` and
                // `await_secret`'s re-raise keep the plain door, because
                // neither names a read.
                let (req, _first) =
                    daemon
                        .attach_hub()
                        .raise_secret_on_edge(&session_id, &prompt_text, episode);
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
                        raised_by: Some(req.raised_by.as_str().to_string()),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // Echo came back, which ends the request — but **not always
            // as §5.2's supersede**, and the whole of what that means is
            // `close_secret_on_echo_return`. Exactly one connection's
            // close returns `Some`, so exactly one fan-out happens even
            // though every one of them tries.
            //
            // **`user_cancelled` is still the word this edge produces, and
            // this edge is no longer entitled to assume it** (GH #105). An
            // earlier revision of this comment claimed the reason had
            // exactly one producer and that it was this line: §7.5's
            // client-frame catalogue has no cancellation frame, so — it
            // argued — the only way a request ends without a value while
            // somebody is waiting is a human aborting or the child
            // abandoning its read.
            //
            // There is a third way, and the premise is what hid it.
            // §9.6's autofill can have written the credential **already**,
            // which is precisely *why* echo came back. It reaches the slot
            // through `take_if_unadopted_matching`, and when its snapshot
            // predates this connection's raise it finds the slot `Vacant`,
            // writes, and closes nothing — so the raise this arm then
            // takes is a request the writer never saw. "Echo cleared with
            // no submission *to this raise*" is not "the user cancelled":
            // measured 1 failure in 50 contended runs of
            // `the_listener_and_a_connections_raise_ride_the_same_edge`.
            //
            // So the raise above claims that credential when it announces
            // the same edge, and this arm reports what the request itself
            // carries. Not a lookup keyed by the edge — an episode is one
            // run of echo-off and `sudo` asking twice puts two reads
            // inside one, so a lookup hands the second read's raise the
            // first read's answer.
            //
            // The two subscribers are deliberately not ordered against
            // each other: they are independent receivers on one broadcast
            // and `broadcast::send` wakes them one at a time.
            Ok(SessionEvent::AwaitingSecretLeft) => {
                daemon.attach_hub().close_secret_on_echo_return(&session_id);
            }
            // **The exit is `forward_output`'s, not this task's**, and
            // the reason is the redactor: it lives in that task, one per
            // connection, and §7.5's `SessionExited` must come after its
            // flush. Two tasks queueing on the same FIFO could not order
            // a flush against a frame without a rendezvous neither needs.
            // **The `SessionExited` *frame* is `forward_output`'s, not
            // this task's**, and the reason is the redactor: it lives in
            // that task, one per connection, and §7.5's `SessionExited`
            // must come after its flush. Two tasks queueing on the same
            // FIFO could not order a flush against a frame without a
            // rendezvous neither needs.
            //
            // What *is* this task's is the secret slot. 0.0.6 left this
            // arm empty and the slot outlived the session — a per-daemon
            // entry keyed by a dead session id that nothing ever removed,
            // and, once a tool call can wait on one, a call that would
            // sit out its whole deadline for a child that is already
            // gone. §5.1: the answer is `session_died` with the code.
            Ok(SessionEvent::Exited { code }) => {
                if let Some(raised) = daemon.attach_hub().close_secret(&session_id, None) {
                    let id = raised.request_id().to_string();
                    raised.answer(crate::secret::Resolution::SessionDied {
                        exit_code: Some(code),
                    });
                    daemon
                        .attach_hub()
                        .broadcast_secret_closed(&session_id, &id, "cancelled");
                }
            }
            // An edge is not a stream: a connection that fell behind has
            // already been re-synchronised by the next edge, and the slot
            // it would have read is still in the hub.
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return,
        }
    }
}

/// The two acks `attach::conn`'s `SecretInput` arm can be waiting on, and
/// the one answer it acts on (GH #137).
///
/// **A type rather than two `tokio::spawn`s.** The gated write and the
/// opted-out one differ in exactly one thing — whether the writer is
/// allowed to refuse — and everything downstream of the ack is identical:
/// the same `SecretAnswer`, the same three outcomes, the same broadcast.
/// Two spawned tasks would be two copies of that, and the copy that
/// mattered would be the one nobody updated.
enum Submitted {
    /// `SecretInput.allow_echo: true`. [`WriteRequest::secret`], which
    /// cannot refuse and whose ack is therefore a plain count.
    EchoAllowed(tokio::sync::oneshot::Receiver<crate::error::Result<usize>>),
    /// The default. [`WriteRequest::secret_if_echo_off`], whose ack can
    /// say the write did not happen.
    Gated(tokio::sync::oneshot::Receiver<crate::error::Result<SecretWrite>>),
}

/// What became of a submission, with the two ack shapes collapsed.
enum Submission {
    Written(usize),
    Declined(crate::session::DeclineReason),
    /// The writer never answered, or answered an error: the session died
    /// under the write. **Not a decline** — nothing was refused, and the
    /// caller's answer is `session_died` rather than `secret_cancelled`.
    SessionDied,
}

impl Submitted {
    async fn resolve(self) -> Submission {
        match self {
            Self::EchoAllowed(rx) => match rx.await {
                Ok(Ok(n)) => Submission::Written(n),
                _ => Submission::SessionDied,
            },
            Self::Gated(rx) => match rx.await {
                Ok(Ok(SecretWrite::Written(n))) => Submission::Written(n),
                Ok(Ok(SecretWrite::Declined(why))) => Submission::Declined(why),
                _ => Submission::SessionDied,
            },
        }
    }
}

/// A [`RaisedRequest`] taken out of its slot, which is answered exactly
/// once **whether or not the future holding it runs to completion**.
///
/// [`RaisedRequest`]: crate::secret::RaisedRequest
///
/// **Why a guard and not discipline.** `read_loop` is one branch of
/// `run`'s `biased` `select!`, so it is a future that gets dropped where
/// it stands the moment `shutdown.changed()` fires or the output
/// forwarder returns — and the forwarder returns on a session exit *and*
/// on a client whose socket died or whose queue overflowed. Its
/// `SecretInput` arm is the one place in the daemon that holds a taken
/// request across an await, and taking a request takes the only
/// `oneshot::Sender` the waiting `request_secret_input` has. Dropping it
/// unanswered is four separate defects at once: the waiting call's
/// receiver resolves `Err` (GH #38's double poll, reached through
/// `await_secret`'s `Err(_)` arm), the queued write still reaches the
/// child, and no `SecretRequestClosed` is broadcast, so every other
/// attached client is left with a dialog pointing at nothing.
///
/// So the duty lives in a value rather than in a code path: there is no
/// way to hold the request without also holding the thing that discharges
/// it, and no way to drop that thing silently.
///
/// **`Drop` classifies by the session's liveness, not by where the drop
/// happened** — the same rule `mcp::tools::lost_approval` applies to a
/// lost approval, and for the same reason: the place a future was
/// cancelled says nothing about why the request is over, and a classifier
/// with no parameter for it cannot be made to lie about it.
struct SecretAnswer {
    daemon: Arc<Daemon>,
    session: Arc<Session>,
    request_id: String,
    /// `None` once the request has been answered. Every read is a `take`,
    /// which is what makes "exactly once" a property of the type.
    raised: Option<crate::secret::RaisedRequest>,
}

impl SecretAnswer {
    fn new(
        daemon: &Arc<Daemon>,
        session: &Arc<Session>,
        raised: crate::secret::RaisedRequest,
    ) -> Self {
        Self {
            daemon: Arc::clone(daemon),
            session: Arc::clone(session),
            request_id: raised.request_id().to_string(),
            raised: Some(raised),
        }
    }

    /// Answer deliberately, and tell the other clients which of §7.5's
    /// outcomes it was. Consumes, so `Drop` finds nothing left to do.
    fn settle(mut self, outcome: crate::secret::Resolution, wire_outcome: &str) {
        if let Some(raised) = self.raised.take() {
            raised.answer(outcome);
            self.daemon.attach_hub().broadcast_secret_closed(
                &self.session.id,
                &self.request_id,
                wire_outcome,
            );
        }
    }
}

impl Drop for SecretAnswer {
    fn drop(&mut self) {
        let Some(raised) = self.raised.take() else {
            return;
        };
        // Nothing was written — the only await this guard is held across
        // before the hand-off is the FIFO `send`, and a cancelled `send`
        // delivers nothing. What ended the request is therefore the
        // submitting client going away, or the session going away under
        // it, and `is_alive()` is what tells the two apart.
        let outcome = if self.session.is_alive() {
            crate::secret::Resolution::Cancelled(crate::secret::CancelReason::UserCancelled)
        } else {
            crate::secret::Resolution::SessionDied {
                exit_code: self.session.exit_code(),
            }
        };
        raised.answer(outcome);
        self.daemon.attach_hub().broadcast_secret_closed(
            &self.session.id,
            &self.request_id,
            "cancelled",
        );
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

/// §7.5's `ScreenSnapshot` (GH #235): **`get_screen_state`'s capture,
/// through `get_screen_state`'s mask**, and no rendering of this
/// module's own.
///
/// `Session::screen_state` is the tool's entry point verbatim, with
/// `redact: true` and the daemon's processor, so whatever the tool's grid
/// masks this frame masks — and whatever the tool's grid is fixed to mask
/// next, this frame inherits. That is the whole reason it is not built
/// from the ring buffer here: a second renderer would be a second masker,
/// and a second masker is a second place for a key body to get through.
///
/// `None` only for a delta, which a capture with no `diff_from` never is.
fn screen_snapshot(
    session: &Arc<Session>,
    processor: &crate::output::OutputProcessor,
) -> Option<ServerFrame> {
    match session.screen_state(None, true, processor) {
        crate::screen::ScreenCapture::Full(grid) => Some(ServerFrame::ScreenSnapshot {
            session: session.id.clone(),
            cols: grid.cols,
            rows: grid.rows,
            cursor_row: grid.cursor_row,
            cursor_col: grid.cursor_col,
            cursor_visible: grid.cursor_visible,
            alt_screen: grid.alt_screen,
            lines: grid.lines,
            held_back: grid.held_back,
        }),
        crate::screen::ScreenCapture::Delta(_) => None,
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
    use crate::session::{new_session_id, SessionConfig};

    /// A `MockPty` that hands the reader at most `.1` bytes per `read`,
    /// so the *frame* count is the test's and not the scheduler's.
    /// `MockPty::read` drains its whole queue into a single frame, which
    /// is exactly why 0.0.3 could never provoke a `Lagged` at all. Not 1,
    /// so a frame count and a byte count are different numbers and an
    /// assertion in the wrong unit cannot pass by coincidence.
    #[derive(Debug)]
    struct ChunkedPty(Arc<MockPty>, usize);

    impl PtyBackend for ChunkedPty {
        fn write(&self, data: &[u8]) -> crate::Result<()> {
            self.0.write(data)
        }
        fn read(&self, buf: &mut [u8]) -> crate::Result<usize> {
            let n = self.1.min(buf.len());
            if n == 0 {
                return Ok(0);
            }
            self.0.read(&mut buf[..n])
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

    /// A session on `backend`, with a chosen ring and broadcast size.
    fn session_on(
        backend: Arc<dyn PtyBackend>,
        ring: usize,
        broadcast: usize,
    ) -> Arc<crate::session::Session> {
        crate::session::Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            backend,
            SessionConfig {
                output_broadcast_capacity: broadcast,
                ..SessionConfig::with_buffer_capacity(ring)
            },
        )
    }

    /// Until the ring's head reaches `n` — a published fact, not a sleep.
    async fn wait_head(session: &crate::session::Session, n: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while session.buffer_head() < n && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(
            session.buffer_head(),
            n,
            "the fixture never published its bytes"
        );
    }

    /// Distinct bytes, so a reordering or a duplicate is visible in the
    /// output rather than hidden in a run of `x`.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| b'a' + (i % 23) as u8).collect()
    }

    /// Everything a connection's queue receives until an `Output` carries
    /// `until`, draining the way `write_loop` does — every frame taken off
    /// releases its bytes and rings the forwarder. Returns the frames in
    /// order.
    async fn drain_until(
        rx: &mut mpsc::Receiver<ServerFrame>,
        budget: &Budget,
        until: u8,
    ) -> Vec<ServerFrame> {
        let mut frames = Vec::new();
        let stop = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < stop {
            match tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await {
                Ok(Some(f)) => {
                    budget.release(stream_bytes(&f));
                    let done =
                        matches!(&f, ServerFrame::Output { bytes, .. } if bytes.contains(&until));
                    frames.push(f);
                    if done {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        frames
    }

    fn output_of(frames: &[ServerFrame]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            if let ServerFrame::Output { bytes, .. } = f {
                out.extend_from_slice(bytes);
            }
        }
        out
    }

    fn gaps_of(frames: &[ServerFrame]) -> Vec<u64> {
        frames
            .iter()
            .filter_map(|f| match f {
                ServerFrame::OutputGap { bytes, .. } => Some(*bytes),
                _ => None,
            })
            .collect()
    }

    /// **The context a joining observer's redactor is seeded with ends
    /// exactly at the floor** — the seam GH #235's join and the seeded
    /// redactor share.
    ///
    /// A byte past the floor fed as context would be judged and never
    /// sent — the stream starts at the floor, and the redactor emits
    /// nothing before where its context ended — so the context must stop
    /// at the floor even when the head has moved on. And where the ring has
    /// evicted part of the window it is shorter, not shifted: what comes
    /// back still ends at the floor.
    #[tokio::test]
    async fn the_context_behind_a_join_ends_at_the_floor() {
        use super::super::redact_stream::RESUME_CONTEXT_BYTES;
        for ring in [64 * 1024, 4096] {
            let pty = Arc::new(MockPty::new());
            let session = session_on(Arc::clone(&pty) as Arc<dyn PtyBackend>, ring, 16);
            let bytes = pattern(RESUME_CONTEXT_BYTES + 5000);
            pty.queue_output(&bytes);
            wait_head(&session, bytes.len() as u64).await;
            let tail = bytes.len().saturating_sub(ring);
            for floor in [bytes.len(), bytes.len() - 100, tail + 10, tail] {
                let got = stream_behind(&session, floor as u64);
                let from = floor.saturating_sub(RESUME_CONTEXT_BYTES).max(tail);
                assert_eq!(
                    got,
                    bytes[from..floor],
                    "ring {ring}, floor {floor}: the context must be the ring's bytes \
                     that end at the floor"
                );
            }
        }
    }

    /// **A broadcast lag is not a loss** (GH #210, REQ-C-006).
    ///
    /// The receiver is taken, starved far past the broadcast's capacity,
    /// and only then handed to the forwarder — the same position a
    /// descheduled forwarder is in after a burst, reached
    /// deterministically. Before GH #210 that position was a hole: every
    /// frame the channel dropped was gone, announced as an `OutputGap` at
    /// best, and 1,500 lines of test output at a loaded machine's
    /// scheduling were enough to reach it. The ring buffer still holds
    /// every one of those bytes, and a connection that resumes from it
    /// delivers them.
    ///
    /// **Byte-for-byte equality, not a count.** Distinct bytes in a known
    /// order, so a duplicate, a reordering and a hole each fail it, and
    /// the forwarder's dedup — a frame wholly behind the cursor is skipped
    /// — is under test as much as its resync.
    #[tokio::test]
    async fn a_lag_is_resynced_from_the_ring_and_every_byte_arrives_once() {
        const CHUNK: usize = 7;
        const BROADCAST: usize = 16;
        let inner = Arc::new(MockPty::new());
        let session = session_on(
            Arc::new(ChunkedPty(Arc::clone(&inner), CHUNK)),
            64 * 1024,
            BROADCAST,
        );
        let rx = session.subscribe();
        let burst = pattern(BROADCAST * 40 * CHUNK);
        inner.queue_output(&burst);
        wait_head(&session, burst.len() as u64).await;

        let (tx, mut out) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let budget = Arc::new(Budget::default());
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".into(),
            rx,
            session.subscribe_events(),
            tx,
            None,
            0,
            Arc::clone(&budget),
        ));
        inner.queue_output(b"Z");
        let frames = drain_until(&mut out, &budget, b'Z').await;
        forwarder.abort();

        let mut expected = burst.clone();
        expected.push(b'Z');
        assert_eq!(
            gaps_of(&frames),
            Vec::<u64>::new(),
            "a lag the ring still covers was reported as lost output"
        );
        assert!(
            output_of(&frames) == expected,
            "the stream across a lag is not the session's bytes, once each, in order: \
             got {} bytes, expected {}",
            output_of(&frames).len(),
            expected.len()
        );
        // **And batched.** One frame per PTY read was the unit that
        // filled the queue; a catch-up that sent one per `CHUNK` would
        // pass the equality above and be the defect.
        let outputs = frames
            .iter()
            .filter(|f| matches!(f, ServerFrame::Output { .. }))
            .count();
        assert!(
            outputs * 4 < burst.len() / CHUNK,
            "{outputs} Output frames for {} PTY reads — the catch-up was not batched",
            burst.len() / CHUNK
        );
    }

    /// **A stream that starts before the receiver's first frame is filled
    /// from the ring, not skipped to it** (GH #235, GH #210).
    ///
    /// The position `run` is in whenever the join's floor is behind the
    /// buffer's head: the floor is the screen tracker's offset, which lags
    /// the head by the chunk the reader has pushed and not yet fed it, and
    /// that chunk was published before this receiver existed. So the
    /// receiver's first frame starts *past* the cursor, with no `Lagged`
    /// to announce it — and a forwarder that trusted the frame over the
    /// cursor would jump to it and lose the bytes in between silently,
    /// in neither the opening picture nor the stream.
    ///
    /// Found by mutation: with the hole check in `Stream::take` replaced
    /// by a jump, every other row stayed green, because each of them
    /// reaches the ring through a `Lagged` first.
    #[tokio::test]
    async fn a_stream_starting_before_the_receivers_first_frame_is_filled_from_the_ring() {
        let inner = Arc::new(MockPty::new());
        let session = session_on(Arc::new(ChunkedPty(Arc::clone(&inner), 64)), 64 * 1024, 64);
        inner.queue_output(b"BEFORE-THE-RECEIVER|");
        wait_head(&session, 20).await;

        // Subscribed only now, so nothing before offset 20 is in it.
        let rx = session.subscribe();
        let (tx, mut out) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let budget = Arc::new(Budget::default());
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".into(),
            rx,
            session.subscribe_events(),
            tx,
            None,
            0,
            Arc::clone(&budget),
        ));
        inner.queue_output(b"AFTER-Z");
        let frames = drain_until(&mut out, &budget, b'Z').await;
        forwarder.abort();
        assert_eq!(
            output_of(&frames),
            b"BEFORE-THE-RECEIVER|AFTER-Z".to_vec(),
            "the bytes between the stream's start and the receiver's first frame were lost"
        );
        assert!(
            gaps_of(&frames).is_empty(),
            "the ring still holds them; nothing was lost"
        );
    }

    /// **A catch-up from the ring is fed to an observer's redactor in
    /// reader-sized chunks, so §9.2's stated loss bound still holds**
    /// (GH #210).
    ///
    /// `StreamRedactor`'s withholding drops the rest of whatever chunk it
    /// overflows in and resumes `2 × STREAM_CARRY_BYTES` later, so the
    /// chunk size is part of how much an observer loses to an
    /// unjudgeable prefix — §9.2's residual (a), an unterminated key
    /// block whose opening prefix scrolls out of the window. Fed as the
    /// reader feeds it, the dump costs one marker and a few carries; fed
    /// as 64 KiB ring reads, it costs every read the withholding touches,
    /// which here is all of it. Driven through the lag path, so every byte
    /// reaches the redactor out of the ring.
    #[tokio::test]
    async fn a_ring_catch_up_keeps_the_observers_stated_loss_bound() {
        use crate::attach::redact_stream::STREAM_CARRY_BYTES;
        let inner = Arc::new(MockPty::new());
        let session = session_on(
            Arc::new(ChunkedPty(Arc::clone(&inner), 8192)),
            1024 * 1024,
            2,
        );
        let rx = session.subscribe();
        let mut dump = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        while dump.len() < 128 * 1024 {
            dump.extend_from_slice(
                b"MIIEpAIBAAKCAQEA7uJ8xk3nQ2s5vT1wY0zL9pR4bN6cH8dF2gJ5kM7nP0qS3tU\n",
            );
        }
        inner.queue_output(&dump);
        wait_head(&session, dump.len() as u64).await;

        let redactor = Some(crate::attach::redact_stream::StreamRedactor::new(Arc::new(
            crate::output::OutputProcessor::builtin().expect("processor"),
        )));
        let (tx, mut out) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let budget = Arc::new(Budget::default());
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".into(),
            rx,
            session.subscribe_events(),
            tx,
            redactor,
            0,
            Arc::clone(&budget),
        ));
        inner.queue_output(b"\nTAIL-Z\n");
        let frames = drain_until(&mut out, &budget, b'Z').await;
        forwarder.abort();
        let shown = output_of(&frames);
        assert!(
            shown
                .windows(b"[REDACTED:unresolved]".len())
                .any(|w| w == b"[REDACTED:unresolved]"),
            "the fixture never reached the redactor's withholding, so it tests nothing"
        );
        let lost = (dump.len() + b"\nTAIL-Z\n".len()).saturating_sub(shown.len());
        assert!(
            lost <= 4 * STREAM_CARRY_BYTES,
            "an observer lost {lost} bytes of an unterminated key block through the ring \
             path, where the reader's own chunking loses a few carries of \
             {STREAM_CARRY_BYTES} — the catch-up was fed in larger chunks than the reader's"
        );
    }

    /// **What the ring has evicted is the only loss, and it is reported
    /// to the byte** — measured from where this connection's stream had
    /// reached (GH #200's origin, GH #210's only remaining source of a
    /// gap).
    ///
    /// Three origins against one ring, and the third is the separating
    /// negative: a connection that started at zero is told the whole
    /// evicted history, which is why `run` must hand the forwarder where
    /// the join found the session rather than assume a stream starts at 0.
    #[tokio::test]
    async fn an_evicted_cursor_is_an_exact_gap_measured_from_the_cursor() {
        const RING: usize = 1000;
        const PRINTED: usize = 5000;
        async fn run_from(start: u64) -> (Vec<u64>, Vec<u8>, Vec<u8>) {
            let inner = Arc::new(MockPty::new());
            let session = session_on(Arc::new(ChunkedPty(Arc::clone(&inner), 7)), RING, 16);
            let rx = session.subscribe();
            let printed = pattern(PRINTED);
            inner.queue_output(&printed);
            wait_head(&session, PRINTED as u64).await;
            let (tx, mut out) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
            let budget = Arc::new(Budget::default());
            let forwarder = tokio::spawn(forward_output(
                Arc::clone(&session),
                "sess_x".into(),
                rx,
                session.subscribe_events(),
                tx,
                None,
                start,
                Arc::clone(&budget),
            ));
            // **The marker only once the forwarder has read the ring.**
            // With a 1000-byte ring, the marker's own byte evicts one more
            // at the tail, so a marker pushed before the forwarder's first
            // read makes the hole one byte wider — correctly, since the
            // ring really had evicted it — and the row's exact figure
            // wrong. It failed that way once in a full contended run. The
            // first frame is queued after the ring read that measures the
            // hole (`Stream::read_ring` reads, then queues), so it is the
            // positive fact to wait on, not a sleep.
            let first = tokio::time::timeout(std::time::Duration::from_secs(10), out.recv())
                .await
                .expect("the forwarder queued nothing")
                .expect("the queue closed");
            budget.release(stream_bytes(&first));
            inner.queue_output(b"Z");
            let mut frames = vec![first];
            frames.extend(drain_until(&mut out, &budget, b'Z').await);
            forwarder.abort();
            (gaps_of(&frames), output_of(&frames), printed)
        }

        let tail = (PRINTED - RING) as u64;

        // Inside the ring: nothing lost, and nothing before the cursor.
        let (gaps, got, printed) = run_from(tail + 300).await;
        assert_eq!(
            gaps,
            Vec::<u64>::new(),
            "a cursor the ring still holds lost nothing"
        );
        assert_eq!(&got[..got.len() - 1], &printed[(tail + 300) as usize..]);

        // Behind the ring: exactly the evicted distance from the cursor.
        let (gaps, got, printed) = run_from(tail - 1234).await;
        assert_eq!(
            gaps,
            vec![1234],
            "the gap must be the distance from this connection's cursor to the ring's tail"
        );
        assert_eq!(
            &got[..got.len() - 1],
            &printed[tail as usize..],
            "after the gap the stream resumes at the ring's tail, with every byte it holds"
        );

        // A zero origin reports the session's whole evicted history —
        // asserted as the wrong answer, so the row says what it defends.
        let (gaps, _, _) = run_from(0).await;
        assert_eq!(gaps, vec![tail]);
    }

    /// **A full queue is a pause, not a detach and not a loss** (GH
    /// #210).
    ///
    /// The queue here has two stream slots beyond its reserves and
    /// nothing drains it. The forwarder must stop at two frames — neither
    /// return (the old `slow_consumer`) nor keep reading into its own
    /// memory — and, once draining starts, deliver everything the
    /// session printed while it waited, from the ring, with no gap.
    #[tokio::test]
    async fn a_forwarder_with_no_room_waits_and_then_loses_nothing() {
        let inner = Arc::new(MockPty::new());
        let session = session_on(Arc::new(ChunkedPty(Arc::clone(&inner), 64)), 64 * 1024, 4);
        let rx = session.subscribe();
        let (tx, mut out) = mpsc::channel::<ServerFrame>(ENDING_SLOTS + ANCILLARY_SLOTS + 2);
        let budget = Arc::new(Budget::default());
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".into(),
            rx,
            session.subscribe_events(),
            tx.clone(),
            None,
            0,
            Arc::clone(&budget),
        ));

        // Separate bursts, so the forwarder has several frames to send.
        let mut printed = Vec::new();
        for i in 0..40 {
            let line = format!("line {i:04} {}\n", "y".repeat(40)).into_bytes();
            inner.queue_output(&line);
            printed.extend_from_slice(&line);
            wait_head(&session, printed.len() as u64).await;
        }
        // Until the stream has taken its share — a positive fact, polled,
        // rather than a sleep a loaded machine can outlast — and then a
        // moment more, so a forwarder that kept going past its share, or
        // gave up, has the chance to.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while tx.capacity() > ENDING_SLOTS + ANCILLARY_SLOTS && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            !forwarder.is_finished(),
            "the forwarder gave up on a full queue — that is the slow_consumer detach GH #210 \
             removed from this task"
        );
        assert_eq!(
            tx.capacity(),
            ENDING_SLOTS + ANCILLARY_SLOTS,
            "the stream took more than its share of the queue, or stopped short of it"
        );

        inner.queue_output(b"Z");
        printed.push(b'Z');
        let frames = drain_until(&mut out, &budget, b'Z').await;
        forwarder.abort();
        assert_eq!(gaps_of(&frames), Vec::<u64>::new());
        assert!(
            output_of(&frames) == printed,
            "bytes printed while the forwarder waited did not all arrive, once, in order"
        );
    }

    /// **A paused forwarder the ring overtakes reports the hole from
    /// where it had reached** — not from where it started, and not from
    /// where the lag began (GH #200's `a_gap_is_measured_from_the_last_frame_delivered`,
    /// restated for GH #210's cursor).
    #[tokio::test]
    async fn a_paused_forwarder_the_ring_overtakes_reports_the_hole_from_its_cursor() {
        const RING: usize = 512;
        let inner = Arc::new(MockPty::new());
        // A read size above the first write, so it is published as one
        // frame and the cursor after it is exactly 100.
        let session = session_on(Arc::new(ChunkedPty(Arc::clone(&inner), 128)), RING, 4);
        let rx = session.subscribe();
        let (tx, mut out) = mpsc::channel::<ServerFrame>(ENDING_SLOTS + ANCILLARY_SLOTS + 1);
        let budget = Arc::new(Budget::default());
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".into(),
            rx,
            session.subscribe_events(),
            tx,
            None,
            0,
            Arc::clone(&budget),
        ));

        // One frame's worth is delivered, and fills the one stream slot.
        inner.queue_output(&[b'a'; 100]);
        wait_head(&session, 100).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while budget.queued.load(Ordering::Acquire) < 100 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(
            budget.queued.load(Ordering::Acquire),
            100,
            "the first frame never queued"
        );

        // Now the ring laps the paused cursor at 100.
        inner.queue_output(&[b'b'; 3000]);
        wait_head(&session, 3100).await;
        inner.queue_output(b"Z");
        wait_head(&session, 3101).await;

        let frames = drain_until(&mut out, &budget, b'Z').await;
        forwarder.abort();
        let tail = 3101 - RING as u64;
        assert_eq!(
            gaps_of(&frames),
            vec![tail - 100],
            "the hole is from the cursor (100) to the ring's tail ({tail})"
        );
        assert_eq!(output_of(&frames).len(), 100 + RING);
    }

    /// **A redactor carry reaches the client at the exit, however full
    /// the queue was** (GH #200, restated for GH #210).
    ///
    /// GH #200 found `send_exit` discarding the carry on a queue at the
    /// reserve and then reporting a clean exit — exit 0 on a view missing
    /// its last line — and repaired it by counting the loss. With a
    /// stream that waits for room the loss does not happen: the carry is
    /// queued as soon as the client makes room, then `SessionExited`, and
    /// the ending still fits behind them.
    #[tokio::test]
    async fn a_carry_is_delivered_at_the_exit_even_from_a_full_queue() {
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(ENDING_SLOTS + ANCILLARY_SLOTS + 1);
        let budget = Arc::new(Budget::default());
        // Fill the stream's share, the way a burst does — charged, as
        // `Stream::send` charges it, or the drain below releases bytes
        // nobody charged.
        loop {
            budget.charge(2);
            let offered = offer_stream(
                &tx,
                ServerFrame::Output {
                    session: "s".into(),
                    bytes: b"xx".to_vec(),
                },
            );
            assert!(
                matches!(offered, Offered::Queued),
                "the fixture's queue refused output"
            );
            if tx.capacity() <= ENDING_SLOTS + ANCILLARY_SLOTS {
                break;
            }
        }
        let mut redactor = Some(crate::attach::redact_stream::StreamRedactor::new(Arc::new(
            crate::output::OutputProcessor::new(
                crate::output::rules::builtin_shared(),
                Arc::new(crate::audit::AuditLog::disabled(
                    crate::output::rules::builtin_shared(),
                )),
                crate::output::ProcessingLimits::default(),
            ),
        )));
        let carried = redactor.as_mut().unwrap().feed(b"ghp_0123456789");
        assert!(
            carried.is_empty(),
            "the fixture needs the redactor holding the prefix"
        );

        let stream = Stream {
            session_id: "s".into(),
            tx: tx.clone(),
            budget: Arc::clone(&budget),
            redactor,
            next: 0,
            behind: false,
        };
        let exiting = tokio::spawn(stream.exit(0));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !exiting.is_finished(),
            "the exit did not wait for room; with the queue full it can only have dropped the \
             carry or spent the ending's reserve"
        );

        let mut frames = Vec::new();
        let stop = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < stop {
            match tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await {
                Ok(Some(f)) => {
                    budget.release(stream_bytes(&f));
                    let last = matches!(f, ServerFrame::SessionExited { .. });
                    frames.push(f);
                    if last {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(matches!(exiting.await, Ok(Forwarded::SessionExit)));
        let tail_at = frames.iter().position(
            |f| matches!(f, ServerFrame::Output { bytes, .. } if bytes == b"ghp_0123456789"),
        );
        let exit_at = frames
            .iter()
            .position(|f| matches!(f, ServerFrame::SessionExited { .. }));
        assert!(
            matches!((tail_at, exit_at), (Some(t), Some(e)) if t < e),
            "the fourteen carried bytes must arrive, before SessionExited: {frames:?}"
        );
        assert!(
            gaps_of(&frames).is_empty(),
            "a delivered carry was also counted as lost"
        );
    }

    /// **The reserve is a reserve against *every* sender, not only the
    /// stream** (GH #200).
    ///
    /// Five paths write this queue besides the output stream:
    /// `broadcast_size`'s `Resize`, and the hub's `AwaitingSecret`,
    /// `SecretRequestClosed` and `BindingApprovalRequired` fan-outs.
    /// Each was a bare `let _ = try_send`, so each could spend the room
    /// §7.5's ending is holding — and with the reserve at two, **one**
    /// interloper was enough to cost the client its `Detached`.
    ///
    /// Not hypothetical: `broadcast_size`'s own dedup comment records
    /// that a window-drag flood was already *"enough of one to have a
    /// client dropped as a slow consumer by its own window drag"*, so
    /// the flood and the teardown are documented in this file as
    /// co-occurring. A human dragging their terminal while the session
    /// ends is the case.
    #[tokio::test]
    async fn an_ancillary_frame_cannot_spend_the_endings_reserve() {
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(8);
        while let Offered::Queued = offer_stream(
            &tx,
            ServerFrame::Output {
                session: "sess_x".into(),
                bytes: b"xx".to_vec(),
            },
        ) {}

        // One window drag, several geometries, none of them deduplicated
        // because each differs from the last.
        for (cols, rows) in [(100u16, 50u16), (104, 55), (108, 60), (112, 62)] {
            queue_ancillary(&tx, ServerFrame::Resize { cols, rows });
        }

        // Before the drain: the whole §7.5 exit sequence must still fit.
        let fits = [
            ServerFrame::OutputGap {
                session: "sess_x".into(),
                bytes: 1,
            },
            ServerFrame::SessionExited { code: 0 },
            ServerFrame::Detached {
                reason: "session_exit".into(),
            },
        ]
        .into_iter()
        .all(|f| tx.try_send(f).is_ok());
        assert!(
            fits,
            "an ancillary fan-out ate the ending's room; a client watching a \
             session end while its terminal is being resized gets a bare EOF"
        );

        // And the separating negative: the resizes were *dropped*, not
        // queued behind the reserve. A `queue_ancillary` that blocked or
        // grew the queue would satisfy the assertion above.
        let mut resizes = 0usize;
        while let Ok(f) = rx.try_recv() {
            if matches!(f, ServerFrame::Resize { .. }) {
                resizes += 1;
            }
        }
        assert_eq!(
            resizes, 0,
            "a frame that could not be sent without spending the reserve must be \
             dropped, exactly as a full queue dropped it before"
        );
    }

    /// **A stream at its limit still leaves the ancillary frames room**
    /// (GH #210).
    ///
    /// New with the waiting forwarder: a stream that pauses on a full
    /// queue sits at its limit for as long as its client is slow, and if
    /// that limit were the ending's reserve an `AwaitingSecret` raised
    /// meanwhile would be refused for all of it — a human on a slow link
    /// would never be shown the prompt the session is blocked on.
    #[tokio::test]
    async fn a_stream_at_its_limit_leaves_room_for_a_secret_prompt() {
        let (tx, _rx) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let budget = Arc::new(Budget::default());
        let stream = Stream {
            session_id: "s".into(),
            tx: tx.clone(),
            budget,
            redactor: None,
            next: 0,
            behind: false,
        };
        // Fill through the waiting path until it waits.
        loop {
            let sent = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                stream.send_output(b"xx".to_vec()),
            )
            .await;
            if sent.is_err() {
                break;
            }
        }
        queue_ancillary(
            &tx,
            ServerFrame::AwaitingSecret {
                request_id: "r".into(),
                prompt_text: "Password:".into(),
                raised_by: None,
            },
        );
        assert_eq!(
            tx.capacity(),
            ANCILLARY_SLOTS + ENDING_SLOTS - 1,
            "the secret prompt was refused by a stream that had taken the ancillaries' room"
        );
    }

    /// §7.5's teardown guarantee, at the seam where it used to fail:
    /// **a queue full of output still has room for the ending** (GH
    /// #200).
    ///
    /// Driven at the two calls rather than over a socket because that is
    /// where the property lives and where it is deterministic: fill the
    /// queue through the stream path until it refuses, then send the
    /// ending the way `run` does. A reserve of zero makes the second
    /// call fail.
    #[tokio::test]
    async fn a_full_output_queue_still_admits_the_ending() {
        let (tx, mut written) = mpsc::channel::<ServerFrame>(8);

        let mut queued = 0usize;
        while let Offered::Queued = offer_stream(
            &tx,
            ServerFrame::Output {
                session: "sess_x".into(),
                bytes: b"xxxx".to_vec(),
            },
        ) {
            queued += 1;
            assert!(queued < 100, "the stream path never refused a full queue");
        }
        assert!(
            queued > 0,
            "the queue refused the first frame, so nothing was under test"
        );

        // The two frames §7.5 can still owe at this point, in its order.
        assert!(
            tx.try_send(ServerFrame::SessionExited { code: 0 }).is_ok(),
            "a queue that filled with output had no room left for SessionExited"
        );
        assert!(
            tx.try_send(ServerFrame::Detached {
                reason: "slow_consumer".into()
            })
            .is_ok(),
            "a queue that filled with output had no room left for the one \
             Detached reason that describes it"
        );

        let mut seen = Vec::new();
        while let Ok(f) = written.try_recv() {
            seen.push(f);
        }
        assert_eq!(
            seen.len(),
            queued + 2,
            "the ending displaced queued output instead of fitting beside it"
        );
    }

    /// A socket pair for `write_loop`: our write half, our read half
    /// (held only so our end stays open), and the peer the test reads.
    fn pair() -> (
        tokio::net::unix::OwnedWriteHalf,
        tokio::net::unix::OwnedReadHalf,
        UnixStream,
    ) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let (rd, wr) = ours.into_split();
        (wr, rd, theirs)
    }

    fn big_output(n: usize) -> ServerFrame {
        ServerFrame::Output {
            session: "s".into(),
            bytes: vec![b'q'; n],
        }
    }

    /// **A peer that stops reading is reported a stall bound after its
    /// socket fills — and not before** (GH #210).
    ///
    /// The writer is the only task that can see this: from the queue's
    /// side a stopped client and a slow one look identical. The positive
    /// arm fills a socket nobody reads and asserts the report arrives
    /// inside a bounded window; the negative arm — a stall bound far
    /// longer than the test — asserts that the same full socket is not
    /// reported early, which is the half an occupancy check would fail.
    #[tokio::test]
    async fn a_peer_that_stops_reading_is_reported_after_the_stall_bound() {
        const STALL: std::time::Duration = std::time::Duration::from_millis(300);
        let (wr, _keep, _theirs) = pair();
        let (tx, rx) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let budget = Arc::new(Budget::default());
        let (stalled_tx, stalled_rx) = oneshot::channel();
        let started = tokio::time::Instant::now();
        let writer = tokio::spawn(write_loop(wr, rx, Arc::clone(&budget), STALL, stalled_tx));
        // Far more than any socket buffer.
        for _ in 0..64 {
            if tx.try_send(big_output(64 * 1024)).is_err() {
                break;
            }
        }
        let reported = tokio::time::timeout(std::time::Duration::from_secs(10), stalled_rx)
            .await
            .expect("a peer that never read was never reported stalled");
        assert!(
            reported.is_ok(),
            "the writer ended instead of reporting the stall"
        );
        assert!(
            started.elapsed() >= STALL,
            "reported after {:?}, before the socket could have gone {STALL:?} without \
             progress",
            started.elapsed()
        );
        // **Then it gives up, one more bound later**, with frames still
        // queued — the socket and the task are not held for a peer that
        // may never come back.
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(10), writer)
            .await
            .expect("the writer held the socket past its grace for a peer that never read")
            .expect("writer task");

        // The negative: the same full socket, a bound longer than the
        // observation, and no report.
        let (wr, _keep, _theirs) = pair();
        let (tx, rx) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let (stalled_tx, mut stalled_rx) = oneshot::channel();
        let writer = tokio::spawn(write_loop(
            wr,
            rx,
            Arc::new(Budget::default()),
            std::time::Duration::from_secs(60),
            stalled_tx,
        ));
        for _ in 0..64 {
            if tx.try_send(big_output(64 * 1024)).is_err() {
                break;
            }
        }
        tokio::time::sleep(STALL * 2).await;
        assert!(
            matches!(
                stalled_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "a full socket was reported stalled before its bound elapsed"
        );
        writer.abort();
    }

    /// **A peer that reads slowly is never reported, however long the
    /// transfer takes — nor however long one frame takes** (GH #210).
    ///
    /// The half of the requirement an occupancy bound cannot meet, and
    /// the half a *per-frame* deadline cannot either: this reader takes
    /// longer than the bound to drain any single 64 KiB frame, and makes
    /// progress every few milliseconds throughout. Measuring progress per
    /// socket `write` is what keeps it attached; a deadline on the whole
    /// frame would detach a client on a slow link that has never stopped.
    ///
    /// **The socket buffer is shrunk, and that is what lets the row
    /// discriminate.** A Linux Unix socket wakes its writer only once the
    /// reader has drained most of the send buffer, so at the default size
    /// a writer's progress arrives in steps of a couple of hundred
    /// kilobytes — and a reader slow enough that one step outlasts the
    /// bound is, to the writer, indistinguishable from a stopped one. At
    /// a few kilobytes the steps are small and the row measures the
    /// writer, not the kernel.
    #[tokio::test]
    async fn a_peer_that_reads_slowly_is_never_reported_stalled() {
        use std::os::unix::io::AsRawFd;
        use tokio::io::AsyncReadExt;
        // A second: long enough that a reader pausing a few tens of
        // milliseconds between reads is not reported for being
        // descheduled on a loaded machine, and short enough that one frame
        // below still takes longer than it to drain.
        const STALL: std::time::Duration = std::time::Duration::from_millis(1000);
        const FRAME: usize = 192 * 1024;
        const FRAMES: usize = 2;
        const READ: usize = 2 * 1024;
        const PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

        let (wr, _keep, mut theirs) = pair();
        let small: libc::c_int = 4096;
        // SAFETY: `setsockopt` reads one `c_int` from a live local and
        // touches no other memory; the fd is our own socket's.
        let rc = unsafe {
            libc::setsockopt(
                wr.as_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&small as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "could not shrink the send buffer");

        let (tx, rx) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let (stalled_tx, mut stalled_rx) = oneshot::channel();
        let writer = tokio::spawn(write_loop(
            wr,
            rx,
            Arc::new(Budget::default()),
            STALL,
            stalled_tx,
        ));
        for _ in 0..FRAMES {
            tx.send(big_output(FRAME)).await.expect("queue");
        }
        drop(tx);
        let reader = tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let mut total = 0usize;
            let mut buf = vec![0u8; READ];
            loop {
                match theirs.read(&mut buf).await {
                    Ok(0) | Err(_) => return (total, started.elapsed()),
                    Ok(n) => total += n,
                }
                tokio::time::sleep(PAUSE).await;
            }
        });
        let (total, took) = tokio::time::timeout(std::time::Duration::from_secs(60), reader)
            .await
            .expect("the slow reader never finished")
            .expect("reader task");
        writer.await.expect("writer task");
        assert!(
            total > FRAMES * FRAME,
            "the reader did not receive the transfer"
        );
        // The fixture's own control: one frame must take longer than the
        // bound to drain, or a per-frame deadline passes this row too.
        assert!(
            took / FRAMES as u32 > STALL,
            "one frame drained in {:?}, inside the {STALL:?} bound, so this row cannot tell \
             progress per write from a deadline per frame",
            took / FRAMES as u32
        );
        assert!(
            !matches!(stalled_rx.try_recv(), Ok(())),
            "a peer that read the whole transfer was reported stalled"
        );
    }

    /// **The queue is bounded in bytes, not in frames** (GH #210).
    ///
    /// A forwarder with nobody draining it stops at the byte budget — one
    /// batch over it at most, because a batch is admitted while the
    /// budget has room — and long before it runs out of frame slots, which
    /// is what makes the frame count a ceiling on messages rather than the
    /// bound a burst meets.
    #[tokio::test]
    async fn the_queue_is_bounded_in_bytes_not_frames() {
        let inner = Arc::new(MockPty::new());
        let session = session_on(
            Arc::new(ChunkedPty(Arc::clone(&inner), 8192)),
            4 * 1024 * 1024,
            16,
        );
        let rx = session.subscribe();
        let (tx, _out) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let budget = Arc::new(Budget::default());
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".into(),
            rx,
            session.subscribe_events(),
            tx.clone(),
            None,
            0,
            Arc::clone(&budget),
        ));
        inner.queue_output(&vec![b'q'; 2 * 1024 * 1024]);
        wait_head(&session, 2 * 1024 * 1024).await;
        // Until it stops moving.
        let mut last = usize::MAX;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let now = budget.queued.load(Ordering::Acquire);
            if now == last {
                break;
            }
            last = now;
        }
        forwarder.abort();
        let queued = budget.queued.load(Ordering::Acquire);
        assert!(
            (ATTACH_QUEUE_BYTES..ATTACH_QUEUE_BYTES + MAX_BATCH_BYTES).contains(&queued),
            "{queued} bytes queued against a {ATTACH_QUEUE_BYTES}-byte budget"
        );
        let frames = ATTACH_QUEUE_FRAMES - tx.capacity();
        assert!(
            frames < ATTACH_QUEUE_FRAMES - ENDING_SLOTS - ANCILLARY_SLOTS,
            "{frames} frames queued — the frame slots ran out before the byte budget, so \
             bytes are not what bound the queue"
        );
    }

    /// A release past zero reads as an empty budget, not a spent one — a
    /// wrapped counter would wedge the connection for good.
    #[test]
    fn a_budget_released_past_zero_is_empty_not_spent() {
        let b = Budget::default();
        b.charge(10);
        b.release(25);
        assert!(!b.spent(), "an underflowed budget reads as spent forever");
        assert_eq!(b.queued.load(Ordering::Acquire), 0);
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
    /// `a_lag_is_resynced_from_the_ring_and_every_byte_arrives_once` uses.** Over a socket
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

        let (tx, mut out) = mpsc::channel::<ServerFrame>(ATTACH_QUEUE_FRAMES);
        let forwarder = tokio::spawn(forward_output(
            Arc::clone(&session),
            "sess_x".to_string(),
            rx,
            session.subscribe_events(),
            tx,
            None,
            0,
            Arc::new(Budget::default()),
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
