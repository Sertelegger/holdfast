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

use parking_lot::Mutex;

use super::conn::AttachConn;

/// Every live attach connection, grouped by the session it is attached
/// to.
#[derive(Default)]
pub struct AttachHub {
    clients: Mutex<HashMap<String, Vec<Arc<AttachConn>>>>,
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
}
