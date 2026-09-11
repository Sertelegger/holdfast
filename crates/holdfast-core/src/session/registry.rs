//! Owns every session this process knows about, in two sets that are
//! deliberately not the same thing.
//!
//! **Live sessions** are the ones with a running child. They are what
//! the concurrency limit counts and what the live-name uniqueness rule
//! applies to (spec §4.1: names are unique among *live* sessions; an
//! exited session releases its name).
//!
//! **Completed records** are what §5.5.1 keeps so that a caller can
//! still read what happened — `list_sessions`, `status`, `read_output`,
//! `holdfast logs`, the `holdfast://session/{id}/buffer` resource and an
//! attach client arriving after the end all depend on them, and none of
//! that changes here.
//!
//! ## Why the split exists (GH #129)
//!
//! One map served both, and it meant a finished session went on owning
//! everything a *running* one needs. Measured on this tree at `68ad7f2`,
//! with the live limit set to 1 and 24 further sessions created and
//! completed: 24 parked writer threads (`/proc/self/status` `Threads:`
//! 2 → 26) and 24 MiB of ring buffer, with zero live sessions at the
//! end. The thread is the part that is not a decision — a writer exists
//! to serve a child that can still read its terminal — and it stayed
//! parked because the retained `Session` still owned the sending half of
//! its queue.
//!
//! So [`SessionRegistry::retire_exited`] does two separable things:
//!
//! 1. Moves each session whose child is gone out of the live set and
//!    calls [`Session::retire`], which drops the queue sender and lets
//!    the writer thread leave. **Nothing observable is given up** — see
//!    that method for the enumeration.
//! 2. Bounds the completed set, in **records and in bytes**. A cap on
//!    records alone still admits unbounded memory the moment one session
//!    prints a lot, and a cap on bytes alone lets a daemon accumulate
//!    thousands of empty records.
//!
//! ## Why the limits are constants and not `[limits]` keys
//!
//! GH #128 is open because this project has configuration that parses
//! and is never applied, so a key that is accepted and inert would be
//! worse than none. The two below are applied — they are the only
//! values [`Retention`] is ever built from outside tests — but they are
//! **not** in `config.toml`, for a reason worth stating rather than
//! leaving to be discovered:
//!
//! §4.2's `[limits]` table is specified, published in §10.2 and read by
//! a `deny_unknown_fields` deserializer, and this crate's `config.rs`
//! records the exact table it was written against. The design spec lives
//! in the git-ignored `docs/` tree, which is **not present in this
//! checkout**, so whether §4.2 names a retention key — and what it
//! spells it — cannot be checked here. Inventing one would be inventing
//! spec surface. [`SessionRegistry::with_retention`] takes the values as
//! a parameter, so wiring a key to them later is one line in
//! `HoldfastServer`, exactly as `max_concurrent_sessions` already is.

use super::{Session, SessionId};
use crate::{HoldfastError, Result};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub const DEFAULT_MAX_SESSIONS: usize = 8;
pub const DEFAULT_BUFFER_BYTES: usize = 1024 * 1024;

/// How many finished sessions stay addressable.
///
/// Eight times the default live limit: an agent driving short commands
/// through one session at a time still finds its last morning's work in
/// `list_sessions`, and the record itself — id, name, argv, history,
/// exit code — is small.
pub const DEFAULT_RETAINED_RECORDS: usize = 64;

/// How many bytes of finished sessions' output stay in memory.
///
/// Twice what the shipped live limits can hold at once
/// (`max_concurrent_sessions` 8 × `output_buffer_bytes` 1 MiB), so a
/// daemon's history costs about what its live sessions do rather than
/// growing without end. The 24 MiB the GH #129 measurement retained
/// came from 24 completed sessions of 1 MiB each and is what this bounds.
pub const DEFAULT_RETAINED_BYTES: u64 = 16 * 1024 * 1024;

/// The bound on [`SessionRegistry`]'s completed records — **both halves,
/// because either alone is unbounded in the other's direction.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Most completed records kept. The oldest goes first.
    pub max_records: usize,
    /// Most bytes of completed sessions' ring buffers kept.
    ///
    /// Occupancy, not capacity — see [`Session::retained_output_bytes`].
    /// **The newest record is never evicted by this bound**, so an
    /// operator who sets `output_buffer_bytes` larger than this gets one
    /// record of history rather than none.
    pub max_bytes: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_records: DEFAULT_RETAINED_RECORDS,
            max_bytes: DEFAULT_RETAINED_BYTES,
        }
    }
}

/// Both sets behind **one** lock.
///
/// Two locks would be a race with no test able to see it: a `get` that
/// missed the live map and then took the completed one would answer
/// `session_not_found` for a session that a concurrent
/// [`SessionRegistry::retire_exited`] had moved between the two reads.
/// There is no ordering of two locks that closes that; holding one lock
/// across both reads is what closes it.
#[derive(Default)]
struct Records {
    live: HashMap<SessionId, Arc<Session>>,
    /// Oldest completion first, so eviction is `pop_front`.
    completed: VecDeque<Arc<Session>>,
}

pub struct SessionRegistry {
    records: RwLock<Records>,
    max_sessions: usize,
    retention: Retention,
}

impl SessionRegistry {
    pub fn new(max_sessions: usize) -> Self {
        Self::with_retention(max_sessions, Retention::default())
    }

    /// A registry whose completed-record bound is not the shipped one.
    ///
    /// The seam the tests drive: retiring 64 sessions and 16 MiB to
    /// watch an eviction would be a slow row that proves the same thing
    /// a four-record budget proves in milliseconds.
    pub fn with_retention(max_sessions: usize, retention: Retention) -> Self {
        Self {
            records: RwLock::new(Records::default()),
            max_sessions,
            retention,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_SESSIONS)
    }

    pub fn retention(&self) -> Retention {
        self.retention
    }

    /// Number of sessions whose child is still running.
    ///
    /// Still a filter and not `live.len()`: a session that has just died
    /// stays in the live set until the next sweep, and this must report
    /// it as gone the moment its child is, exactly as it did when there
    /// was one map.
    pub fn live_count(&self) -> usize {
        self.records
            .read()
            .live
            .values()
            .filter(|s| s.is_alive())
            .count()
    }

    /// How many finished sessions are still addressable.
    pub fn retained_count(&self) -> usize {
        self.records.read().completed.len()
    }

    /// Bytes of output this registry is holding, across every session it
    /// knows about — the number GH #129 measured.
    pub fn retained_output_bytes(&self) -> u64 {
        let records = self.records.read();
        records
            .live
            .values()
            .chain(records.completed.iter())
            .map(|s| s.retained_output_bytes())
            .sum()
    }

    /// Insert a session, enforcing the limit and name rules.
    pub fn insert(&self, session: Arc<Session>) -> Result<()> {
        // Both checks and the insert share one write lock. Taking a read
        // lock per check and a write lock to insert would let two
        // concurrent inserts each observe the same name as free.
        let mut records = self.records.write();
        // **Before the checks, not after**, and not merely as an economy.
        // A session that has exited already releases its name and its
        // slot (`exited_session_releases_its_name`,
        // `limit_counts_only_live_sessions`), so the two answers below
        // are the same either way — but a `start_session` loop is the
        // one call pattern that reliably reaches this code, and sweeping
        // here is what makes the writer thread of the session that just
        // finished go away without waiting for the daemon's 30-second
        // tick. The whole GH #129 shape is exactly this loop.
        let evicted = Self::sweep(&mut records, self.retention);
        // The checks are a separate function rather than `return`s in
        // this body, so that the two orderly drops below happen on the
        // refusal paths too: an early `return` from here would drop
        // `evicted` — declared after the guard, so first — while the
        // write lock is still held.
        let admitted = Self::admit(&mut records, session, self.max_sessions);
        drop(records);
        // Outside the lock: dropping the last `Arc` of an evicted record
        // frees a ring buffer, and a registry that held its own write
        // lock through a megabyte of deallocation would block every
        // reader for it.
        drop(evicted);
        admitted
    }

    /// The limit and name rules, with the lock already held.
    fn admit(records: &mut Records, session: Arc<Session>, max_sessions: usize) -> Result<()> {
        if let Some(name) = session.name.as_deref() {
            let taken = records
                .live
                .values()
                .any(|s| s.is_alive() && s.name.as_deref() == Some(name));
            if taken {
                return Err(HoldfastError::NameTaken(name.to_string()));
            }
        }
        if records.live.values().filter(|s| s.is_alive()).count() >= max_sessions {
            return Err(HoldfastError::LimitReached(max_sessions));
        }
        records.live.insert(session.id.clone(), session);
        Ok(())
    }

    /// Move every session whose child has gone out of the live set,
    /// shut its writer down, and bring the completed set back inside its
    /// bounds. Returns how many were newly retired.
    ///
    /// **Called from two places and it must stay that way.**
    /// [`SessionRegistry::insert`] covers the busy daemon, where the
    /// next `start_session` is the natural moment; the daemon's periodic
    /// tick (`daemon::server::reaper_loop`) covers the quiet one, where
    /// there is no next call and a session that finished an hour ago
    /// would otherwise keep its thread until the process ended. Neither
    /// alone is enough, and a third caller would be a third answer to
    /// "when does a session stop being live".
    pub fn retire_exited(&self) -> usize {
        let mut records = self.records.write();
        let before = records.completed.len();
        let evicted = Self::sweep(&mut records, self.retention);
        let retired = records.completed.len() + evicted.len() - before;
        drop(records);
        drop(evicted);
        retired
    }

    /// The body of a sweep, with the lock already held.
    ///
    /// Returns the evicted records so the caller can drop them outside
    /// the lock.
    fn sweep(records: &mut Records, retention: Retention) -> Vec<Arc<Session>> {
        let mut finished: Vec<Arc<Session>> = records
            .live
            .values()
            .filter(|s| !s.is_alive())
            .map(Arc::clone)
            .collect();
        // A `HashMap`'s iteration order is randomised per process, so
        // two sessions that finished between one sweep and the next
        // would otherwise queue for eviction in an order that changes
        // run to run. Observation time first — it is what §5.2 already
        // reports as `exited_at_unix_secs` — and creation time to break
        // the ties its one-second granularity leaves.
        finished.sort_by_key(|s| (s.exited_at_secs().unwrap_or(0), s.created_at));
        for session in finished {
            records.live.remove(&session.id);
            // The whole point of the split: a finished session gives up
            // the queue its writer thread is parked on, and keeps
            // everything a caller can still ask it for.
            session.retire();
            records.completed.push_back(session);
        }

        let mut evicted = Vec::new();
        while records.completed.len() > retention.max_records {
            if let Some(s) = records.completed.pop_front() {
                evicted.push(s);
            }
        }
        // `> 1` and not `> 0`: the newest record is never evicted by the
        // byte budget. See [`Retention::max_bytes`].
        while records.completed.len() > 1 && Self::completed_bytes(records) > retention.max_bytes {
            if let Some(s) = records.completed.pop_front() {
                evicted.push(s);
            }
        }
        evicted
    }

    /// Recomputed per sweep rather than carried as a running total.
    ///
    /// A retired session's buffer is not quite final at the instant it
    /// is retired: the child's death and the reader thread leaving its
    /// loop are two different observations (GH #42), so a few hundred
    /// bytes can still arrive afterwards. A cached total taken at
    /// retirement would drift below the truth by exactly that much, per
    /// session, forever.
    ///
    /// **Budgeted:** the set is bounded by `max_records`, so a sweep
    /// that evicts nothing pays at most 64 uncontended mutex
    /// acquisitions — a couple of microseconds, against a
    /// `start_session` that is about to fork a process — and one more
    /// pass per record it does evict.
    fn completed_bytes(records: &Records) -> u64 {
        records
            .completed
            .iter()
            .map(|s| s.retained_output_bytes())
            .sum()
    }

    /// Resolve by session id, or by the name of a live session. Ids
    /// resolve whether or not the session is still running; names only
    /// resolve to live sessions, since an exited session releases its
    /// name and a later session may have taken it.
    ///
    /// **An id stops resolving once its record has been evicted**, which
    /// is what the retention bound means and the one thing about a
    /// finished session that this change alters. `session_not_found` is
    /// already the answer for an id from a previous daemon (§5.5.1's
    /// *"until the registry cleans up the record, typically at daemon
    /// restart"*); this makes the cleanup happen on a bound rather than
    /// only on a restart.
    pub fn get(&self, id_or_name: &str) -> Result<Arc<Session>> {
        let records = self.records.read();
        if let Some(s) = records.live.get(id_or_name) {
            return Ok(Arc::clone(s));
        }
        if let Some(s) = records.completed.iter().find(|s| s.id == id_or_name) {
            return Ok(Arc::clone(s));
        }
        records
            .live
            .values()
            .find(|s| s.is_alive() && s.name.as_deref() == Some(id_or_name))
            .map(Arc::clone)
            .ok_or_else(|| HoldfastError::SessionNotFound(id_or_name.to_string()))
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        let mut records = self.records.write();
        if let Some(s) = records.live.remove(id) {
            return Some(s);
        }
        let at = records.completed.iter().position(|s| s.id == id)?;
        records.completed.remove(at)
    }

    /// Every session this registry holds, live and finished alike.
    ///
    /// The order is unspecified, as it was when this was one `HashMap`
    /// — `mcp::resources::list_resources` sorts its own output for
    /// exactly that reason.
    pub fn all(&self) -> Vec<Arc<Session>> {
        let records = self.records.read();
        records
            .live
            .values()
            .chain(records.completed.iter())
            .cloned()
            .collect()
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::MockPty;
    use crate::session::{new_session_id, Session};

    fn mock_session(name: Option<&str>) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            name.map(String::from),
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn crate::pty::PtyBackend>,
            crate::session::SessionConfig::with_buffer_capacity(4096),
        );
        (s, pty)
    }

    #[test]
    fn session_ids_are_prefixed_and_unique() {
        let a = new_session_id();
        let b = new_session_id();
        assert!(a.starts_with("sess_"));
        assert_ne!(a, b);
    }

    #[test]
    fn insert_and_get_by_id() {
        let reg = SessionRegistry::with_defaults();
        let (s, _p) = mock_session(None);
        let id = s.id.clone();
        reg.insert(s).unwrap();
        assert_eq!(reg.get(&id).unwrap().id, id);
    }

    #[test]
    fn get_by_name_resolves_live_sessions() {
        let reg = SessionRegistry::with_defaults();
        let (s, _p) = mock_session(Some("build"));
        let id = s.id.clone();
        reg.insert(s).unwrap();
        assert_eq!(reg.get("build").unwrap().id, id);
    }

    #[test]
    fn duplicate_live_name_is_rejected() {
        let reg = SessionRegistry::with_defaults();
        let (a, _pa) = mock_session(Some("build"));
        let (b, _pb) = mock_session(Some("build"));
        reg.insert(a).unwrap();
        assert!(matches!(reg.insert(b), Err(HoldfastError::NameTaken(_))));
    }

    #[test]
    fn exited_session_releases_its_name() {
        let reg = SessionRegistry::with_defaults();
        let (a, pa) = mock_session(Some("build"));
        reg.insert(a).unwrap();
        pa.exit(0);
        let (b, _pb) = mock_session(Some("build"));
        reg.insert(b)
            .expect("name should be free once the holder exits");
    }

    #[test]
    fn exited_session_still_resolves_by_id() {
        // The agent must still be able to read the final output and exit
        // code of a session that has finished.
        let reg = SessionRegistry::with_defaults();
        let (a, pa) = mock_session(Some("build"));
        let id = a.id.clone();
        reg.insert(a).unwrap();
        pa.exit(3);
        assert_eq!(reg.get(&id).unwrap().id, id);
        assert!(matches!(
            reg.get("build"),
            Err(HoldfastError::SessionNotFound(_))
        ));
    }

    #[test]
    fn a_retired_session_still_resolves_by_id() {
        // The row above, with the sweep that moves the record between
        // the two sets actually run. `get` must not care which set a
        // session is in.
        let reg = SessionRegistry::with_defaults();
        let (a, pa) = mock_session(Some("build"));
        let id = a.id.clone();
        reg.insert(a).unwrap();
        pa.exit(3);
        assert_eq!(reg.retire_exited(), 1);
        assert_eq!(reg.retained_count(), 1);
        assert_eq!(reg.get(&id).unwrap().id, id);
        assert_eq!(reg.all().len(), 1);
    }

    #[test]
    fn limit_counts_only_live_sessions() {
        let reg = SessionRegistry::new(2);
        let (a, pa) = mock_session(None);
        let (b, _pb) = mock_session(None);
        reg.insert(a).unwrap();
        reg.insert(b).unwrap();

        let (c, _pc) = mock_session(None);
        assert!(matches!(reg.insert(c), Err(HoldfastError::LimitReached(2))));

        pa.exit(0);
        let (d, _pd) = mock_session(None);
        reg.insert(d).expect("slot freed by the exited session");
    }

    #[test]
    fn missing_session_is_an_error() {
        let reg = SessionRegistry::with_defaults();
        assert!(matches!(
            reg.get("nope"),
            Err(HoldfastError::SessionNotFound(_))
        ));
    }

    #[test]
    fn a_live_session_is_never_retired() {
        let reg = SessionRegistry::with_defaults();
        let (a, _pa) = mock_session(None);
        let id = a.id.clone();
        reg.insert(a).unwrap();
        assert_eq!(reg.retire_exited(), 0);
        assert_eq!(reg.retained_count(), 0);
        assert_eq!(reg.live_count(), 1);
        // And its queue is untouched, which is the thing a wrong sweep
        // would take away from two attach clients mid-conversation.
        assert!(!reg.get(&id).unwrap().write_queue().is_closed());
    }

    #[test]
    fn retiring_twice_retires_a_session_once() {
        let reg = SessionRegistry::with_defaults();
        let (a, pa) = mock_session(None);
        reg.insert(a).unwrap();
        pa.exit(0);
        assert_eq!(reg.retire_exited(), 1);
        assert_eq!(reg.retire_exited(), 0);
        assert_eq!(reg.retained_count(), 1);
    }
}
