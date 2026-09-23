//! The per-daemon set of attached clients (§4.3, §7.5).
//!
//! **What this is not: the output fan-out.** Live bytes reach every
//! attached client through `Session::subscribe()` — 0.0.3's
//! `broadcast::Sender<OutputFrame>`, whose capacity is §4.2's
//! `output_broadcast_capacity` (live since GH #210) — and each connection
//! forwards from its own receiver, and from the session's ring buffer
//! when it falls behind, into its own bounded `mpsc`. Keying *that* on a
//! session is the session's job and it already does it, which is why
//! "output reached a client attached to a different session" is
//! structurally impossible rather than a rule this file enforces.
//!
//! What the hub is for is everything the broadcast cannot answer:
//! **how many clients are attached right now** (`daemon/status`'s
//! `attach_clients`, hardcoded `0` since 0.0.5), which of them belong to
//! a given session, and — from 0.0.7 — where a session-scoped frame such
//! as `AwaitingSecret` has to go.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use super::frames::{AttachMode, AttachRole, ServerFrame};
use crate::protocol::handshake::ClientKind;

/// How many **frames** the per-connection queue holds (§4.3). **Not
/// configurable in v0.1.0**, and since GH #210 not the bound that decides
/// anything about a burst.
///
/// **The unit was the defect** (GH #200, GH #210). A frame is one PTY
/// `read`, so 64 of them was anywhere from a few kilobytes of line-sized
/// reads to half a megabyte of 8 KiB ones, and a burst of ordinary test
/// output — 1,500 short lines — filled it and detached `holdfast watch`
/// four runs in four on the dogfood pass. Three things changed together,
/// and the reason they had to is that §4.3's two bounds are in series:
///
/// * the stream is bounded in **bytes**, by [`ATTACH_QUEUE_BYTES`], and
///   the forwarder batches a backlog into one `Output` rather than one
///   per PTY read — so this frame count is a ceiling on *messages*, which
///   a batching forwarder does not approach;
/// * a full queue **pauses** the forwarder rather than detaching the
///   client, and what it has not read yet stays in the session's ring
///   buffer, which is where it resumes from (`conn::forward_output`) —
///   so the broadcast's 256 frames stopped being a loss bound at all;
/// * a client is detached for **making no progress**, not for occupancy:
///   [`ATTACH_STALL_TIMEOUT`] without the socket accepting a byte.
///
/// The revert #209 recorded — a megabyte of queue headroom, after which a
/// client that drained nothing was never detached — was the first bullet
/// without the third. A bound that only ever detaches on occupancy cannot
/// be raised without also raising how long a dead client is kept, because
/// the two are the same number; separating them is the fix.
pub const ATTACH_QUEUE_FRAMES: usize = 64;

/// How many bytes of `Output` payload one connection may have queued and
/// not yet written (GH #210).
///
/// **Not the headroom a slow client gets, and sizing it as though it were
/// is the mistake to avoid.** The headroom is the session's ring buffer:
/// a forwarder that finds this budget spent stops reading and resumes
/// from the ring at the offset it had reached, so a client that is behind
/// loses nothing until the ring itself evicts the bytes it has not been
/// sent — and then it is told exactly how many (`OutputGap`). This
/// number is only how much of that backlog is copied out of the ring
/// into per-connection memory ahead of the socket, which is why it is
/// small: a quarter of the ring's 1 MiB default, and four of the
/// forwarder's largest batches.
pub const ATTACH_QUEUE_BYTES: usize = 256 * 1024;

/// How long a connection's socket may accept **no bytes at all**, while
/// the daemon has bytes waiting for it, before the client is detached
/// `slow_consumer` (§4.3, GH #210).
///
/// **Progress, not occupancy, and not a deadline on the whole write.** A
/// client on a slow link that takes a minute to drain a burst is making
/// progress the whole time and is never detached; one that has stopped
/// reading — suspended, frozen, or a peer that simply never calls
/// `read` — is detached this long after the socket filled, however much
/// or little the session printed. That is the half #209's revert showed
/// an occupancy bound cannot give: its bound had to be small to detach a
/// dead client promptly and large to let a live one through a burst, and
/// no number was both.
///
/// **Thirty seconds, and the direction of the error is the argument.**
/// Too short detaches a human who pressed `Ctrl-S` on a `holdfast watch`
/// to read a screen, or suspended it with `Ctrl-Z` for a moment. Too long
/// costs one socket, two parked tasks and at most [`ATTACH_QUEUE_BYTES`]
/// plus a socket buffer — memory that does not grow with the session's
/// output, because a paused forwarder reads nothing. The second is cheap
/// and the first is the defect this issue is about, so the number is
/// long.
///
/// **A client with nothing waiting for it is not stalled.** A suspended
/// watcher on an idle session holds its socket until output backs up
/// behind it, exactly as a suspended `ssh` does; the clock starts when
/// the daemon has something it cannot write.
///
/// Per daemon, through [`AttachHub::stall_timeout`], so a test can drive
/// the detach without waiting half a minute; nothing in production sets
/// it.
pub const ATTACH_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many slots of the per-connection queue the **stream** may never
/// take, so that the attachment's ending always has somewhere to go.
///
/// **Three, and the third is now spare rather than owed.** §7.5's exit
/// sequence is `SessionExited` then `Detached`, which is two. The third
/// was `conn::send_exit`'s `OutputGap` for a redactor carry that did not
/// fit (GH #200); since GH #210 the stream waits for room instead of
/// being refused, so the carry always fits and the gap is never sent.
/// Kept at three rather than tightened, because the reserve is what the
/// ending relies on and a margin on it costs three slots of a
/// [`ATTACH_QUEUE_FRAMES`]-frame queue.
///
/// **Three, not two, was measured rather than reasoned.** At two the
/// exit path consumed the reserve exactly, so a single interloper — the
/// four `AwaitingSecret`/`SecretRequestClosed`/`BindingApprovalRequired`
/// hub fan-outs, or `conn::broadcast_size`'s `Resize` — cost the client its
/// `Detached`. Those now go through [`queue_ancillary`], which honours
/// the reserve, so they cannot; the margin is belt and braces for a
/// sixth sender nobody has written yet.
///
/// **This is what makes §7.5's teardown guarantee true rather than
/// aspirational** (GH #200). `Detached { reason: "slow_consumer" }` was
/// written with a `try_send` onto the very queue whose overflow had just
/// caused the ending, so it failed by construction in exactly the case
/// it names, and a `holdfast watch` that had lost nine tenths of a burst
/// reported the tidy `the daemon closed the connection` of an EOF. The
/// frame is not raced against the close either: `run` drops every
/// `Sender`, and `write_loop` drains what is queued *before* the socket
/// goes away.
pub(super) const ENDING_SLOTS: usize = 3;

/// Put a frame that is neither the stream nor the ending on the queue,
/// **without spending [`ENDING_SLOTS`]**.
///
/// `Resize`, `AwaitingSecret`, `SecretRequestClosed` and
/// `BindingApprovalRequired` are session events this connection is owed
/// and none of them is worth detaching over, so a refusal here is a
/// silent drop exactly as the bare `let _ = try_send` it replaces was on
/// a full queue. What changes is *where* the refusal starts: a frame
/// that would eat the ending's room is refused, so the reserve is a
/// reserve rather than a convention the stream alone observes.
///
/// **Measured, not hypothesised** (GH #200). With the reserve honoured
/// only by `conn::queue_stream`, two `Resize` frames from one window drag
/// landed on a queue at the reserve and cost the client both its
/// `SessionExited` and its `Detached` — and `conn::broadcast_size`'s own
/// dedup comment records that a drag flood is already *"enough of one to
/// have a client dropped as a slow consumer by its own window drag"*, so
/// the flood and the teardown are documented in this file as
/// co-occurring rather than merely conceivable.
pub(super) fn queue_ancillary(tx: &mpsc::Sender<ServerFrame>, frame: ServerFrame) {
    if tx.capacity() <= ENDING_SLOTS {
        return;
    }
    let _ = tx.try_send(frame);
}

/// One attached client, as the hub and the audit trail see it.
pub struct AttachConn {
    /// Monotonic and never reused, so an `unregister` cannot remove a
    /// connection that happened to land in the same slot.
    pub client_id: u64,
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
    /// The peer's pid from `SO_PEERCRED`, when the platform gives one.
    ///
    /// §9.4's `attach_connect.peer_pid` is `int?` precisely because it is
    /// not universally available. **Kernel-supplied, never declared** —
    /// the whole point of the two `peer_*` fields is that they are the
    /// only identity on this connection a client cannot choose.
    pub peer_pid: Option<i32>,
    /// The peer's uid from `SO_PEERCRED`, checked against the daemon's
    /// owner **before a byte of this connection was parsed**.
    pub peer_uid: u32,
    /// Bounded per-connection queue (§4.3). Bounded in frames by
    /// [`ATTACH_QUEUE_FRAMES`] and, for the output stream, in bytes by
    /// [`ATTACH_QUEUE_BYTES`] (GH #210). **A full queue no longer detaches
    /// anybody**: the forwarder waits for room and the session's reader
    /// is never involved, and a client is detached only for making no
    /// progress for [`ATTACH_STALL_TIMEOUT`]. The ending still fits:
    /// `ENDING_SLOTS` keeps room for it (GH #200).
    pub tx: mpsc::Sender<ServerFrame>,
    pub connected_at: Instant,
    /// The geometry this client was last *sent*, so it is not sent again.
    ///
    /// Initialised to the size carried by its own `Attached` frame, which
    /// is a thing it has already been told. Without this the originator of
    /// a resize received one identical correction per `SIGWINCH` of a drag
    /// — the flood this issue is about, relocated from the terminal to the
    /// wire, where a client already behind on its socket can be dropped as
    /// a slow consumer by its own window drag.
    pub last_told: Mutex<Option<(u16, u16)>>,
    /// The geometry this client last asked for, or `None` until it asks.
    ///
    /// The session's size is the **minimum** over the writers that have
    /// reported one, so this is a per-client input to that fold rather
    /// than a record of what the session ended up at. §7.5 is what
    /// restricts the fold to writers: *"the canonical PTY size is set by
    /// writers; observers don't influence it"*.
    pub last_size: Mutex<Option<(u16, u16)>>,
}

/// A writer's hold on one terminal, released when this is dropped.
///
/// Held for the life of the connection by `attach::conn::run`. Dropping is
/// the *only* release path on purpose: the connection has several early
/// returns between claiming and registering, and a manual release would be
/// a list to keep in step with them.
pub struct TerminalClaim {
    hub: Arc<AttachHub>,
    terminal: String,
}

impl Drop for TerminalClaim {
    fn drop(&mut self) {
        self.hub.terminals.lock().remove(&self.terminal);
    }
}

/// Every live attach connection, grouped by the session it is attached
/// to.
#[derive(Default)]
pub struct AttachHub {
    clients: Mutex<HashMap<String, Vec<Arc<AttachConn>>>>,
    /// §5.2's outstanding secret request, **one per session and not
    /// configurable** in v0.1.0.
    ///
    /// It lives here rather than on the `Session` because the request is
    /// an attach-protocol object: its `request_id` is answered by a
    /// `SecretInput` frame, and a session with no attached client has
    /// nobody who could answer. What the session owns is the *edge* that
    /// raises it.
    ///
    /// The state machine itself is [`crate::secret::SecretSlots`]; the
    /// hub holds it because the hub is what can *reach* the clients a
    /// raise has to be told to.
    secrets: crate::secret::SecretSlots,
    /// §17.5's outstanding binding approval, **one per session**.
    ///
    /// Here for the same reason `secrets` is: the decision arrives as an
    /// `ApproveBinding` frame from an attached client, and the hub is
    /// what can reach the clients a raise has to be told to.
    ///
    /// **A second map and not a second state on `secrets`.** The two can
    /// be outstanding on one session at once — §5.2's fall-through raises
    /// a *secret request* immediately after an approval is denied or
    /// expires — so one slot holding both would make the fall-through
    /// overwrite the thing it fell through from.
    approvals: crate::secret::BindingApprovals,
    /// Terminal device -> the session whose writer holds it.
    ///
    /// A map rather than a count: the question is only ever *"is this
    /// terminal taken"*, and a count would have to be decremented correctly
    /// on every path a guard now handles for free.
    ///
    /// **Keyed on the terminal alone, not on `(session, terminal)`.** The
    /// failure is that two processes `read()`ing one terminal device are
    /// handed alternate bytes by the kernel; which session each is attached
    /// to has no bearing on it. A `(session, terminal)` key let
    /// `holdfast attach s1 & holdfast attach s2` in one window through —
    /// two writers, one keyboard, the measured failure verbatim, and worse
    /// than the same-session case because the first to exit restores cooked
    /// mode out from under the survivor.
    ///
    /// The value is the session id so the refusal can name what holds it.
    terminals: Mutex<HashMap<String, String>>,
    /// Serialises "fold the writers' sizes, apply, read back".
    ///
    /// The fold itself is order-independent, which is the property that
    /// makes a minimum converge — but the *sequence* was not: two tasks on
    /// a multi-thread runtime could both fold, then apply in the other
    /// order, leaving the session at a stale writer's geometry with no
    /// further event to correct it. `writer_min_size` releases every lock
    /// it takes before returning, so nothing it does can span the apply.
    ///
    /// Coarse on purpose. Resizes are human-paced, and one mutex is easier
    /// to prove acyclic than a per-session map: the order is always this,
    /// then `clients`, then `last_size`, and never the reverse.
    resize_decisions: Mutex<()>,
    /// Monotonic, process-wide. **Never reused**, so an `unregister`
    /// arriving after the slot was refilled cannot remove somebody
    /// else's connection — the same reasoning that puts an `O_PATH` pin
    /// behind the socket identity, one scale down.
    next_id: AtomicU64,
    /// [`ATTACH_STALL_TIMEOUT`] for this daemon, in milliseconds, or `0`
    /// for the constant. See [`AttachHub::set_stall_timeout`].
    stall_timeout_ms: AtomicU64,
}

impl AttachHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// How long a connection may accept no bytes, with bytes waiting,
    /// before it is detached `slow_consumer` — [`ATTACH_STALL_TIMEOUT`]
    /// unless [`set_stall_timeout`](Self::set_stall_timeout) said
    /// otherwise.
    ///
    /// Read once per connection, when its writer starts.
    pub fn stall_timeout(&self) -> std::time::Duration {
        match self.stall_timeout_ms.load(Ordering::Relaxed) {
            0 => ATTACH_STALL_TIMEOUT,
            ms => std::time::Duration::from_millis(ms),
        }
    }

    /// Shorten (or lengthen) the stall bound for connections opened
    /// **after** this call.
    ///
    /// **A test seam, and the only way to reach the detach without
    /// sitting out half a minute per row.** Nothing in production calls
    /// it: the bound is not an operator knob in v0.1.0, for the reason
    /// §4.2 gives the queue's own bound — a number an operator can set is
    /// a number the documentation has to promise something about. A
    /// zero is refused by being the "unset" value, so no connection can
    /// be given a stall bound that detaches it before its first write.
    pub fn set_stall_timeout(&self, timeout: std::time::Duration) {
        let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.stall_timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// A fresh client id. Taken **before** the connection is built, so
    /// the id a connection carries is the one it was registered under.
    pub fn next_client_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Claim `terminal` for a writer, or `None` if one already holds it.
    ///
    /// **Atomic, and that is the whole reason this is not a predicate.**
    /// The obvious shape — ask whether the terminal is busy, then register
    /// if it is not — is a check-then-act across the 100-odd lines and
    /// several `await` points between the handshake and `register`, and
    /// every attach connection is its own task. Two clients starting from
    /// one terminal at once both saw "not busy" and both attached, which is
    /// precisely the state the check exists to prevent. Test-and-set under
    /// one lock has no such window.
    ///
    /// **Not folded into `clients`**, because the claim has to be taken
    /// before the `AttachConn` exists: registering early to reserve a slot
    /// would let another client's broadcast reach this connection's queue
    /// ahead of its own `Attached`, and §7.5 makes `Attached` frame one.
    ///
    /// Callers claim only for [`AttachMode::ReadWrite`] and only when the
    /// client declared a terminal — an observer never reads the keyboard,
    /// and a client with no terminal cannot be sharing one.
    ///
    /// The returned guard releases on drop, and callers drop it as soon as
    /// the attachment ends rather than when the task does: the writer task
    /// can stay parked on a full socket long after the client stopped
    /// being attached, and a claim held that long is a terminal nobody can
    /// use and no advice can free.
    pub fn claim_terminal(
        self: &Arc<Self>,
        terminal: &str,
        session_id: &str,
    ) -> Result<TerminalClaim, String> {
        let mut held = self.terminals.lock();
        if let Some(owner) = held.get(terminal) {
            return Err(owner.clone());
        }
        held.insert(terminal.to_string(), session_id.to_string());
        drop(held);
        Ok(TerminalClaim {
            hub: Arc::clone(self),
            terminal: terminal.to_string(),
        })
    }

    /// Run `f` with the resize sequence serialised. See
    /// [`Self::resize_decisions`].
    pub fn with_resize_decision<T>(&self, f: impl FnOnce() -> T) -> T {
        let _guard = self.resize_decisions.lock();
        f()
    }

    /// The session geometry every attached writer can display: the
    /// **minimum** of the sizes they have reported, or `None` if none has.
    ///
    /// §7.5 restricts the fold to writers — *"the canonical PTY size is
    /// set by writers; observers don't influence it"* — and the minimum is
    /// tmux's rule, for tmux's reason: a column the smallest terminal
    /// cannot show is a column that is wrapped or lost for that client,
    /// while a column a larger one leaves blank costs nothing.
    ///
    /// **This is what makes the size converge.** Last-writer-wins let two
    /// clients dragging at once alternate between their own readings
    /// forever, which is GH #66's unexplained "the sizes oscillate rather
    /// than converging on a final geometry". A minimum has no such
    /// ordering dependence: the same set of clients yields the same answer
    /// whoever reported last.
    /// The geometry to put in force: what the agent asked for, narrowed by
    /// what every attached writer can display (GH #75).
    ///
    /// **`desired` is the floor when nobody is attached**, which is the half
    /// that was missing. The fold used to answer `None` with no writers and
    /// the caller left the session alone — so a session an agent had sized
    /// for a TUI stayed at the geometry of whichever human client had most
    /// recently held it, forever, and the agent had no way to observe or
    /// undo that. Now the last writer detaching returns the session to the
    /// size it was asked for.
    ///
    /// A minimum in both directions on purpose: an attached human must not
    /// be asked to render columns their terminal does not have, and an agent
    /// asking for fewer than a human's terminal gets those fewer.
    pub fn effective_size(
        &self,
        session_id: &str,
        desired: Option<(u16, u16)>,
    ) -> Option<(u16, u16)> {
        match (self.writer_min_size(session_id), desired) {
            (Some(w), Some(d)) => Some((w.0.min(d.0), w.1.min(d.1))),
            (Some(w), None) => Some(w),
            (None, Some(d)) => Some(d),
            // Nobody is attached and nothing has been asked for: there is no
            // geometry to put in force, and inventing one would resize a
            // session to a default nobody chose.
            (None, None) => None,
        }
    }

    pub fn writer_min_size(&self, session_id: &str) -> Option<(u16, u16)> {
        self.clients_of(session_id)
            .iter()
            .filter(|c| c.mode == AttachMode::ReadWrite)
            .filter_map(|c| *c.last_size.lock())
            .reduce(|(ac, ar), (bc, br)| (ac.min(bc), ar.min(br)))
    }

    pub fn register(&self, conn: Arc<AttachConn>) {
        self.clients
            .lock()
            .entry(conn.session_id.clone())
            .or_default()
            .push(conn);
    }

    /// Remove one connection.
    ///
    /// The session's entry is removed outright when its last client
    /// goes, so `live_client_count` cannot be made to read `0` while the
    /// map still holds empty vectors — and so a long-running daemon does
    /// not accumulate one entry per session that was ever attached to.
    pub fn unregister(&self, session_id: &str, client_id: u64) {
        let mut clients = self.clients.lock();
        let Some(list) = clients.get_mut(session_id) else {
            return;
        };
        list.retain(|c| c.client_id != client_id);
        if list.is_empty() {
            clients.remove(session_id);
        }
    }

    /// `daemon/status`'s `attach_clients` (§7.4.1).
    pub fn live_client_count(&self) -> u64 {
        self.clients.lock().values().map(|v| v.len() as u64).sum()
    }

    /// Every client attached to one session, cloned out from under the
    /// lock so a caller can send to them without holding it.
    pub fn clients_of(&self, session_id: &str) -> Vec<Arc<AttachConn>> {
        self.clients
            .lock()
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Raise a secret request on this session, or return the one already
    /// outstanding.
    ///
    /// **Idempotent, and that is what makes one `request_id` reach every
    /// client.** Every connection sees the same `AwaitingSecretEntered`
    /// event and every one of them calls this; the first allocates and
    /// the rest get the same request back, so the frames they send agree
    /// without any of them coordinating. It is also what lets a client
    /// attaching *after* the drop raise the request nobody was there to
    /// raise (§7.5's replay).
    ///
    /// The `bool` is `true` for the caller that allocated, which is how
    /// exactly one of them takes responsibility for a fan-out.
    pub fn raise_secret(
        &self,
        session_id: &str,
        prompt_text: &str,
    ) -> (super::secret::SecretRequest, bool) {
        self.secrets
            .raise(session_id, prompt_text, crate::secret::RaisedBy::EchoDrop)
    }

    pub fn outstanding_secret(&self, session_id: &str) -> Option<super::secret::SecretRequest> {
        self.secrets.outstanding(session_id)
    }

    /// The slot state machine, for the callers that need more of it than
    /// the four convenience methods here expose — the waiting-caller
    /// layer in particular (§5.2, REQ-SEC-010a).
    pub fn secrets(&self) -> &crate::secret::SecretSlots {
        &self.secrets
    }

    /// Clear the outstanding request, returning it **only** to the caller
    /// that actually cleared it.
    ///
    /// `expect_id` is `Some` for a fulfilment, which must not close a
    /// request that has already been replaced by a later one, and `None`
    /// for the supersede path. Either way exactly one caller gets a
    /// `Some`, so exactly one `SecretRequestClosed` fan-out happens even
    /// though every connection tries.
    pub fn close_secret(
        &self,
        session_id: &str,
        expect_id: Option<&str>,
    ) -> Option<crate::secret::RaisedRequest> {
        self.secrets.take(session_id, expect_id)
    }

    /// §8.3's echo-drop edge, raised — **the one raise entitled to claim
    /// an answer §9.6's autofill left behind** (GH #105).
    ///
    /// [`raise_secret`](Self::raise_secret) stays what it is and is what
    /// §7.5's replay and `await_secret`'s re-raise keep using. This one is
    /// for `attach::conn::forward_events`' reaction to the edge itself,
    /// which is the only raise tied to a particular read. See
    /// [`crate::secret::SecretSlots::raise_on_echo_drop_edge`].
    pub fn raise_secret_on_edge(
        &self,
        session_id: &str,
        prompt_text: &str,
        episode: u64,
    ) -> (super::secret::SecretRequest, bool) {
        self.secrets
            .raise_on_echo_drop_edge(session_id, prompt_text, episode)
    }

    /// §5.2's echo return, **whole**: close the request, answer the call
    /// waiting on it, and tell every attached client — in that order and
    /// without the caller being able to do two of the three.
    ///
    /// **One function because there are two callers and they must not
    /// drift** (GH #105). `attach::conn::forward_events` runs this per
    /// connection; `secret::binding`'s `spawn_forwarder` runs it in a
    /// target that cannot build an `Arc<Daemon>`. A test-module copy of
    /// the arm is a copy that stays green while the original is reverted —
    /// measured: reverting the production arm to its pre-fix form left
    /// **all** of GH #105's new rows and all 120 `secret::` rows passing,
    /// because none of them reached it.
    ///
    /// The word comes from [`crate::secret::echo_return_resolution`] via
    /// the request's own [`answered`], never from this edge: echo comes
    /// back both when a human abandons a prompt and when the daemon
    /// answered it.
    ///
    /// Exactly one caller gets a `Some`, like every other close here, so
    /// exactly one fan-out happens even though every connection tries.
    ///
    /// [`answered`]: crate::secret::RaisedRequest::answered
    pub fn close_secret_on_echo_return(&self, session_id: &str) -> Option<(String, &'static str)> {
        let raised = self.close_secret(session_id, None)?;
        let id = raised.request_id().to_string();
        let answered = self.secrets.claim_echo_return_answer(session_id, &raised);
        let (resolution, outcome) = crate::secret::echo_return_resolution(answered);
        raised.answer(resolution);
        self.broadcast_secret_closed(session_id, &id, outcome);
        Some((id, outcome))
    }

    /// Tell every client attached to this session that a request is
    /// outstanding (§7.5).
    ///
    /// Non-blocking rather than `send`: §4.3's per-connection queue is
    /// bounded and overflow detaches that client. A fan-out that blocked
    /// on one slow client would hold up the tool call, the write path, or
    /// whatever else happened to be doing the raising.
    pub fn broadcast_awaiting_secret(&self, session_id: &str, request_id: &str, prompt_text: &str) {
        for c in self.clients_of(session_id) {
            queue_ancillary(
                &c.tx,
                ServerFrame::AwaitingSecret {
                    request_id: request_id.to_string(),
                    prompt_text: prompt_text.to_string(),
                },
            );
        }
    }

    /// Tell every client attached to this session that the request is
    /// over, and how (§7.5: `fulfilled` | `cancelled` | `timeout`).
    pub fn broadcast_secret_closed(&self, session_id: &str, request_id: &str, outcome: &str) {
        for c in self.clients_of(session_id) {
            queue_ancillary(
                &c.tx,
                ServerFrame::SecretRequestClosed {
                    request_id: request_id.to_string(),
                    outcome: outcome.to_string(),
                },
            );
        }
    }

    /// §17.5's approval registry, for the callers that need more of it
    /// than [`broadcast_binding_approval`](Self::broadcast_binding_approval)
    /// exposes — the waiting tool call, and `attach::conn`'s
    /// `ApproveBinding` arm.
    pub fn approvals(&self) -> &crate::secret::BindingApprovals {
        &self.approvals
    }

    /// Tell every client attached to this session that a `require_confirm`
    /// binding is waiting on a human (§7.5, §9.6).
    ///
    /// **Built from the [`Approval`] rather than from the binding**, and
    /// that is REQ-SEC-016 held structurally: the frame's field list and
    /// the approval record's are the same list, and neither type has a
    /// field able to carry the reference or the value. A fan-out that took
    /// a `&SecretBinding` would be one `serde_json::to_value` away from
    /// putting the reference on the wire.
    ///
    /// Non-blocking, like the other two fan-outs: §4.3's per-connection
    /// queue is bounded, and a slow client must not hold up a tool call.
    /// Through `conn::queue_ancillary`, so a fan-out cannot spend the
    /// room §7.5's ending is holding (GH #200).
    ///
    /// [`Approval`]: crate::secret::Approval
    pub fn broadcast_binding_approval(&self, approval: &crate::secret::Approval) {
        for c in self.clients_of(&approval.session_id) {
            queue_ancillary(
                &c.tx,
                ServerFrame::BindingApprovalRequired {
                    approval_id: approval.approval_id.clone(),
                    binding_name: approval.binding_name.clone(),
                    command_line: approval.command_line.clone(),
                    provider: approval.provider.clone(),
                    session: approval.session_id.clone(),
                    prompt_text: approval.prompt_text.clone(),
                },
            );
        }
    }
}
