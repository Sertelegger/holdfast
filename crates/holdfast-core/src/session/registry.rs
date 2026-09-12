//! Owns every session this process knows about, in two sets that are
//! deliberately not the same thing — and, since GH #131, a third that
//! holds no session at all (see [`Reservation`]).
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
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Every set behind **one** lock.
///
/// Two locks would be a race with no test able to see it: a `get` that
/// missed the live map and then took the completed one would answer
/// `session_not_found` for a session that a concurrent
/// [`SessionRegistry::retire_exited`] had moved between the two reads.
/// There is no ordering of two locks that closes that; holding one lock
/// across both reads is what closes it.
///
/// [`Records::reserved`] joins them for the same reason and not merely
/// by analogy: a reservation exists to make *"is this name free"* and
/// *"take it"* one indivisible step, and a reservation set behind its own
/// lock would reintroduce the very gap it was added to close.
#[derive(Default)]
struct Records {
    live: HashMap<SessionId, Arc<Session>>,
    /// Oldest completion first, so eviction is `pop_front`.
    completed: VecDeque<Arc<Session>>,
    /// Slots claimed by a `start_session` whose child does not exist
    /// yet — the name it asked for, or `None` for an unnamed session.
    ///
    /// **It owns no [`Session`]**, which is what keeps [`Self::sweep`],
    /// [`SessionRegistry::retire_exited`], the two `retained_*` counters,
    /// [`SessionRegistry::get`] and [`SessionRegistry::all`] unchanged by
    /// GH #131: none of them has anything to say about a session that has
    /// not been created. The two things that *do* change are the two that
    /// decide admission — the live-name rule and the concurrency limit —
    /// and they change in one place each ([`SessionRegistry::name_is_held`]
    /// and [`SessionRegistry::occupancy`]).
    reserved: HashMap<ReservationId, Option<String>>,
}

/// Identifies one outstanding [`Reservation`] so that dropping it
/// releases *that* claim.
///
/// A plain counter rather than the reserved name, because an unnamed
/// reservation has no name to be identified by and two of them are
/// otherwise indistinguishable.
type ReservationId = u64;

pub struct SessionRegistry {
    records: RwLock<Records>,
    max_sessions: usize,
    retention: Retention,
    /// Never reused, never wrapped in practice: at one reservation per
    /// `start_session`, exhausting a `u64` would take longer than the
    /// heat death of anything.
    next_reservation: AtomicU64,
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
            next_reservation: AtomicU64::new(0),
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
    ///
    /// **Outstanding reservations are not counted**, and that is not an
    /// oversight: this answers *"how many children are running"*, and a
    /// reservation has no child. The number the limit is checked against
    /// is [`Self::occupancy`], which counts both.
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

    /// How many claims are outstanding — slots that will become live
    /// sessions or be released, and are neither yet.
    ///
    /// Exists so a test can assert a reservation was *given up*. Nothing
    /// in the daemon reads it: a caller that wants to know whether it may
    /// start a session calls [`Self::reserve`] and finds out by taking
    /// the slot, which is the whole point.
    pub fn reserved_count(&self) -> usize {
        self.records.read().reserved.len()
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

    /// Claim a live-session slot — and a name, when one is given —
    /// **before** the child that will fill it exists.
    ///
    /// This is the call `start_session` makes ahead of
    /// `InProcessPty::spawn`; see [`Reservation`] for why the claim has
    /// to come first, why it is released by `Drop`, and why it has no
    /// TTL. The refusals are the same two values [`Self::insert`]
    /// returns — [`HoldfastError::NameTaken`] and
    /// [`HoldfastError::LimitReached`] — so the envelope the agent sees
    /// is unchanged; only *when* it is decided moves.
    ///
    /// It sweeps first, exactly as [`Self::insert`] does and for the
    /// same GH #129 reason: a `start_session` loop is the one call
    /// pattern that reliably reaches this code, and the sweep is what
    /// frees the slot and the name of the session that just finished
    /// without waiting for the daemon's tick. Since the reservation is
    /// now the first thing `start_session` does to the registry, this is
    /// also the call that has to do it — leaving the sweep on `insert`
    /// alone would mean a loop refusing itself with `limit_reached`
    /// against sessions that had already exited.
    pub fn reserve(&self, name: Option<&str>) -> Result<Reservation<'_>> {
        let mut records = self.records.write();
        let evicted = Self::sweep(&mut records, self.retention);
        // A separate function for the same reason `admit` is one: an
        // early `return` from this body would drop `evicted` — declared
        // after the guard, so dropped first — with the write lock held.
        let claimed = Self::claim(
            &mut records,
            name,
            self.max_sessions,
            self.next_reservation.fetch_add(1, Ordering::Relaxed),
        );
        drop(records);
        drop(evicted);
        claimed.map(|id| Reservation {
            registry: self,
            id,
            released: false,
        })
    }

    /// The limit and name rules for a claim, with the lock already held.
    fn claim(
        records: &mut Records,
        name: Option<&str>,
        max_sessions: usize,
        id: ReservationId,
    ) -> Result<ReservationId> {
        if let Some(name) = name {
            if Self::name_is_held(records, name) {
                return Err(HoldfastError::NameTaken(name.to_string()));
            }
        }
        if Self::occupancy(records) >= max_sessions {
            return Err(HoldfastError::LimitReached(max_sessions));
        }
        records.reserved.insert(id, name.map(String::from));
        Ok(id)
    }

    /// Turn a claim into the session it was taken for, in one lock
    /// acquisition.
    ///
    /// **One acquisition and not two**, which is the reason this is a
    /// registry method rather than a `release` followed by an `insert`
    /// inside [`Reservation::commit`]: a window between giving the slot
    /// up and filling it is exactly the window the reservation exists to
    /// close, and it would be a window no test could see.
    fn commit_reservation(&self, id: ReservationId, session: Arc<Session>) {
        let mut records = self.records.write();
        debug_assert_eq!(
            records.reserved.get(&id),
            Some(&session.name),
            "a reservation must be committed with the session whose name it claimed; \
             committing a different name would leave that name unprotected"
        );
        records.reserved.remove(&id);
        records.live.insert(session.id.clone(), session);
    }

    fn release_reservation(&self, id: ReservationId) {
        self.records.write().reserved.remove(&id);
    }

    /// Whether a name is spoken for — by a live session **or** by an
    /// outstanding claim.
    ///
    /// The second half is GH #131's name race: two concurrent
    /// `start_session` calls sharing a name both found it free, both
    /// spawned, and one was then refused with its command already run.
    ///
    /// §4.1: *"The name is **unique among live sessions only**: when a
    /// session exits, it keeps its session id but releases its name,
    /// freeing that name for reuse by a new live session."* A claim is a
    /// live session that has not started yet, so it holds the name on
    /// the same terms — and gives it up on the same terms, which is what
    /// [`Reservation`]'s `Drop` is for.
    fn name_is_held(records: &Records, name: &str) -> bool {
        records
            .live
            .values()
            .any(|s| s.is_alive() && s.name.as_deref() == Some(name))
            || records
                .reserved
                .values()
                .any(|n| n.as_deref() == Some(name))
    }

    /// What `max_sessions` is checked against: running children **plus**
    /// the children that are about to be forked.
    ///
    /// Counting only the first is the over-limit half of GH #131. The
    /// limit was enforced on registry membership and never on process
    /// creation, so K concurrent calls could all reach `fork`/`exec`
    /// before any one of them reached admission — measured at a limit of
    /// 8 with 8 live sessions, where 8 of 8 refusals had each already
    /// left a transient ninth live child.
    fn occupancy(records: &Records) -> usize {
        records.live.values().filter(|s| s.is_alive()).count() + records.reserved.len()
    }

    /// Insert a session, enforcing the limit and name rules.
    ///
    /// **No production caller since GH #131** — `start_session` reserves
    /// and then [`Reservation::commit`]s instead, and that it was the
    /// *one* caller is what made moving it safe. What is left is the
    /// direct-admission path the tests use to stand a registry up in a
    /// known state, and it still enforces both rules against
    /// reservations as well as against live sessions, so it cannot be
    /// used to overshoot a limit a reservation is holding.
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
    ///
    /// The two predicates are shared with [`Self::claim`] rather than
    /// spelled twice: a registry that admitted on one rule and reserved
    /// on a slightly different one would have two answers to *"may this
    /// session exist"*, and the disagreement would only ever show up
    /// under concurrency.
    fn admit(records: &mut Records, session: Arc<Session>, max_sessions: usize) -> Result<()> {
        if let Some(name) = session.name.as_deref() {
            if Self::name_is_held(records, name) {
                return Err(HoldfastError::NameTaken(name.to_string()));
            }
        }
        if Self::occupancy(records) >= max_sessions {
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

/// A claim on a live-session slot, and on a name when one was asked for,
/// held from before the child is spawned until it is admitted.
///
/// ## The defect it closes (GH #131)
///
/// `start_session` spawned the child and *then* asked the registry to
/// admit it, so every refusal was the refusal of a process that had
/// already run. Reproduced at run time against the shipped binary: a
/// `name_taken` refusal ran its command **10 times out of 10**, and
/// against a limit of 8 with 8 sessions live, **8 refusals out of 8** ran
/// theirs — each leaving a transient ninth live child.
///
/// Two user-visible properties fall out of one cause. A refused
/// `start_session` must not have run its command; and the process count
/// must not transiently exceed `max_concurrent_sessions`. The limit was
/// enforced on registry *membership* and never on process *creation*, so
/// K concurrent calls all fork and exec before any of them reaches
/// admission — which is why a check-then-spawn "peek" is not the fix.
/// A peek answers the sequential question and leaves both concurrent
/// ones exactly where they were, because between its check and its
/// insert it holds nothing.
///
/// The rule this broke was already written down, sixty lines above the
/// spawn it broke it at: *"Detection config is built before the spawn: a
/// bad regex is the caller's error and must not leave a live child
/// behind."* A name that is already taken, and a limit that is already
/// reached, are the caller's error in exactly that sense.
///
/// ## Released by `Drop`, never by a `release()` the caller calls
///
/// The path that matters is `start_session`'s `spawn_failed` early
/// return, ten lines below where the reservation is taken, and an
/// explicit release is precisely the thing that gets forgotten on an
/// early return — which is the same class of mistake as the
/// `signal(Kill)` remedy this replaces. `Drop` runs on every path out,
/// including a panic and including paths nobody has written yet.
///
/// ## The name does not survive a failed spawn
///
/// It must not, and the spec is unambiguous in two places at once. §4.1:
/// *"The name is **unique among live sessions only**: when a session
/// exits, it keeps its session id but releases its name, freeing that
/// name for reuse by a new live session."* §5.2, on `start_session`:
/// *"**Returns (status `spawn_failed`):** `{ command }` with a trimmed
/// `details` string; no session is created and no id is issued."*
///
/// Put together: a reservation that outlived a failed spawn would hold a
/// name against a session that does not exist and never will, and the
/// caller would have **no `terminate` target to release it with**,
/// because no id was issued. That is a name-space denial of service
/// reachable by typing the name of a program that is not installed.
///
/// ## Why there is no TTL
///
/// A reservation that expired after N seconds would be a duration
/// standing in for an ordering. What ends a reservation is the spawn
/// resolving — one way or the other — not time passing, and the two only
/// look alike while the spawn is fast. Pick the TTL too short and a slow
/// `fork` on a loaded box loses a slot it legitimately holds, with the
/// child already running and nothing left to admit it; pick it too long
/// and it is not a bound on anything. The scope of the claim is a
/// straight-line region of one function with no `await` in it, so the
/// ordering is already total and a clock adds only a way to get it
/// wrong.
pub struct Reservation<'a> {
    registry: &'a SessionRegistry,
    id: ReservationId,
    /// Set by [`Self::commit`] so the `Drop` that follows it is a no-op.
    ///
    /// Set *before* the registry call rather than after, so the two
    /// cannot be ordered wrongly by a later edit.
    ///
    /// **No test can tell it from its absence today, and that is stated
    /// rather than left to be discovered.** `commit` has already removed
    /// the id, so an unconditional `Drop` would remove an id that is not
    /// there — correct, and a second write-lock acquisition on the one
    /// path every successful `start_session` takes. What the flag buys is
    /// that saved acquisition, plus a `commit` that means *this claim is
    /// settled* rather than one that relies on remove-of-absent staying a
    /// no-op if `release_reservation` ever grows a second statement.
    released: bool,
}

impl Reservation<'_> {
    /// Fill the claimed slot with the session it was claimed for.
    ///
    /// **Infallible, and that is the property rather than a
    /// convenience.** The slot and the name are already held, so there
    /// is nothing left to refuse; and because there is nothing left to
    /// refuse there is no "registry rejected it, kill the child" remedy
    /// to write, forget, or get wrong. The `session.signal(Signal::Kill)`
    /// that stood on `start_session`'s admission-failure path is gone
    /// because that path is gone.
    pub fn commit(mut self, session: Arc<Session>) {
        self.released = true;
        self.registry.commit_reservation(self.id, session);
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_reservation(self.id);
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

    // ---- GH #131: the claim taken before the spawn -------------------
    //
    // Every row below is ordering, not timing: no thread, no clock, no
    // sleep. The concurrent failures these pin — two `start_session`
    // calls racing for one name, K calls racing for the last slot — are
    // *expressed* here as "a claim is outstanding and the registry is
    // asked the same question", because that is the state the race
    // produces and it is the state a check-then-spawn "peek" never
    // enters. A peek holds nothing between its check and its insert, so
    // there is no version of these rows it passes.

    #[test]
    fn a_reservation_holds_its_name_before_any_session_exists() {
        let reg = SessionRegistry::with_defaults();
        let claim = reg.reserve(Some("build")).expect("the name is free");
        // Nothing exists yet — this is the window in which the child was
        // being forked.
        assert_eq!(reg.live_count(), 0);
        assert!(reg.all().is_empty());

        let (b, _pb) = mock_session(Some("build"));
        assert!(
            matches!(reg.insert(b), Err(HoldfastError::NameTaken(_))),
            "a claimed name is taken even though no session holds it"
        );
        drop(claim);
    }

    #[test]
    fn a_reservation_holds_a_slot_before_any_session_exists() {
        let reg = SessionRegistry::new(1);
        let claim = reg.reserve(None).expect("the slot is free");
        let (b, _pb) = mock_session(None);
        assert!(
            matches!(reg.insert(b), Err(HoldfastError::LimitReached(1))),
            "a claimed slot counts against the limit before it is filled"
        );
        drop(claim);
    }

    #[test]
    fn outstanding_claims_cannot_exceed_the_limit() {
        // The over-limit half of GH #131, stated directly: what bounds
        // the number of children that may be forked at once is the
        // number of claims that may be outstanding at once.
        let reg = SessionRegistry::new(2);
        let a = reg.reserve(None).expect("first slot");
        let b = reg.reserve(None).expect("second slot");
        assert!(matches!(
            reg.reserve(None),
            Err(HoldfastError::LimitReached(2))
        ));
        assert_eq!(reg.reserved_count(), 2);
        // …and with no session in existence at all, which is what makes
        // this a bound on process *creation* rather than on registry
        // membership.
        assert_eq!(reg.live_count(), 0);
        assert!(reg.all().is_empty());
        drop(a);
        drop(b);
        assert_eq!(reg.reserved_count(), 0);
    }

    #[test]
    fn a_dropped_reservation_gives_back_its_name() {
        // `start_session`'s `spawn_failed` early return. §5.2 issues no
        // id for it, so a claim that survived would hold the name with
        // no `terminate` target able to release it.
        let reg = SessionRegistry::with_defaults();
        drop(reg.reserve(Some("build")).expect("the name is free"));
        assert_eq!(reg.reserved_count(), 0);
        let (b, _pb) = mock_session(Some("build"));
        reg.insert(b)
            .expect("a claim that was never committed frees its name");
    }

    #[test]
    fn a_dropped_reservation_gives_back_its_slot() {
        let reg = SessionRegistry::new(1);
        drop(reg.reserve(None).expect("the slot is free"));
        let (b, _pb) = mock_session(None);
        reg.insert(b)
            .expect("a claim that was never committed frees its slot");
    }

    #[test]
    fn a_committed_reservation_becomes_exactly_one_live_session() {
        // The claim must be *converted*, not added to: a commit that
        // left the claim standing would halve the effective limit, and a
        // commit that dropped the claim before inserting would reopen
        // the window it exists to close.
        let reg = SessionRegistry::new(1);
        let claim = reg.reserve(Some("build")).expect("the slot is free");
        let (a, _pa) = mock_session(Some("build"));
        let id = a.id.clone();
        claim.commit(Arc::clone(&a));

        assert_eq!(reg.reserved_count(), 0);
        assert_eq!(reg.live_count(), 1);
        assert_eq!(reg.get(&id).unwrap().id, id);
        assert_eq!(reg.get("build").unwrap().id, id);

        let (b, _pb) = mock_session(None);
        assert!(
            matches!(reg.insert(b), Err(HoldfastError::LimitReached(1))),
            "the committed session occupies the slot its claim held"
        );
    }

    #[test]
    fn a_reservation_is_not_a_session() {
        // PR #136's `Records` split is what makes this cheap: the claim
        // owns no `Session`, so nothing that reads sessions has anything
        // to say about it. Asserted rather than argued, because the
        // cheapest wrong implementation of a claim is a placeholder
        // `Session`, and every one of these would then answer 1.
        let reg = SessionRegistry::with_defaults();
        let claim = reg.reserve(Some("build")).expect("the name is free");
        assert_eq!(reg.live_count(), 0);
        assert_eq!(reg.retained_count(), 0);
        assert_eq!(reg.retained_output_bytes(), 0);
        assert_eq!(reg.retire_exited(), 0);
        assert!(reg.all().is_empty());
        assert!(matches!(
            reg.get("build"),
            Err(HoldfastError::SessionNotFound(_))
        ));
        drop(claim);
    }

    #[test]
    fn an_exited_session_frees_its_name_and_slot_for_a_reservation() {
        // `reserve` sweeps first, exactly as `insert` does. It has to:
        // it is now the first thing `start_session` asks the registry,
        // so a loop would otherwise refuse itself against sessions that
        // had already finished.
        let reg = SessionRegistry::new(1);
        let (a, pa) = mock_session(Some("build"));
        reg.insert(a).unwrap();
        assert!(matches!(
            reg.reserve(Some("build")),
            Err(HoldfastError::NameTaken(_))
        ));
        pa.exit(0);
        let claim = reg
            .reserve(Some("build"))
            .expect("an exited session releases both");
        assert_eq!(reg.retained_count(), 1, "and the sweep actually ran");
        drop(claim);
    }
}
