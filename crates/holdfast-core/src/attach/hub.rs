//! The per-daemon set of attached clients (§4.3, §7.5).
//!
//! **What this is not: the output fan-out.** Live bytes reach every
//! attached client through `Session::subscribe()` — 0.0.3's
//! `broadcast::Sender<OutputFrame>`, capacity
//! `OUTPUT_BROADCAST_FRAMES = 256` — and each connection forwards from
//! its own receiver into its own bounded `mpsc`. Keying *that* on a
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

/// §4.3's per-connection outbound bound. **Not configurable in
/// v0.1.0.** Overflow detaches this client and never blocks the reader.
pub const ATTACH_QUEUE_FRAMES: usize = 64;

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
    /// Bounded per-connection queue (§4.3: *"their own bounded mpsc,
    /// default 64 frames"*). Overflow detaches this client and never
    /// blocks the reader task.
    pub tx: mpsc::Sender<ServerFrame>,
    pub connected_at: Instant,
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
    /// Monotonic, process-wide. **Never reused**, so an `unregister`
    /// arriving after the slot was refilled cannot remove somebody
    /// else's connection — the same reasoning that puts an `O_PATH` pin
    /// behind the socket identity, one scale down.
    next_id: AtomicU64,
}

impl AttachHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh client id. Taken **before** the connection is built, so
    /// the id a connection carries is the one it was registered under.
    pub fn next_client_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
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

    /// Tell every client attached to this session that a request is
    /// outstanding (§7.5).
    ///
    /// `try_send` rather than `send`: §4.3's per-connection queue is
    /// bounded and overflow detaches that client. A fan-out that blocked
    /// on one slow client would hold up the tool call, the write path, or
    /// whatever else happened to be doing the raising.
    pub fn broadcast_awaiting_secret(&self, session_id: &str, request_id: &str, prompt_text: &str) {
        for c in self.clients_of(session_id) {
            let _ = c.tx.try_send(ServerFrame::AwaitingSecret {
                request_id: request_id.to_string(),
                prompt_text: prompt_text.to_string(),
            });
        }
    }

    /// Tell every client attached to this session that the request is
    /// over, and how (§7.5: `fulfilled` | `cancelled` | `timeout`).
    pub fn broadcast_secret_closed(&self, session_id: &str, request_id: &str, outcome: &str) {
        for c in self.clients_of(session_id) {
            let _ = c.tx.try_send(ServerFrame::SecretRequestClosed {
                request_id: request_id.to_string(),
                outcome: outcome.to_string(),
            });
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
    /// `try_send`, like the other two fan-outs: §4.3's per-connection
    /// queue is bounded, and a slow client must not hold up a tool call.
    ///
    /// [`Approval`]: crate::secret::Approval
    pub fn broadcast_binding_approval(&self, approval: &crate::secret::Approval) {
        for c in self.clients_of(&approval.session_id) {
            let _ = c.tx.try_send(ServerFrame::BindingApprovalRequired {
                approval_id: approval.approval_id.clone(),
                binding_name: approval.binding_name.clone(),
                provider: approval.provider.clone(),
                session: approval.session_id.clone(),
                prompt_text: approval.prompt_text.clone(),
            });
        }
    }
}
