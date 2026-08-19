//! The idle reaper (§16.7, REQ-S-004, REQ-S-005).
//!
//! A daemon-lifetime timer over the [`SessionRegistry`]: every ~30
//! seconds it looks for sessions past their idle deadline, sends each
//! one **SIGTERM**, and after a **5-second grace** sends **SIGKILL** to
//! whatever is still alive. Both timings go through [`Clock`], so a test
//! drives a 30-minute timeout in microseconds instead of not running.
//!
//! **The reaper signals; it does not remove the registry entry.** The
//! spec says three different things about that, so the ruling and its
//! reasoning live here rather than being left to whichever sentence an
//! implementer reads first:
//!
//! - §16.7 step 4 says the session *"was removed from the registry"* and
//!   later calls return `session_not_found`.
//! - §5.5.1 (with §5.2, §5.5.4 and §4.1) says exited sessions *"remain
//!   ID-addressable … until the registry cleans up the record, typically
//!   at daemon restart"*, and §5.2's `terminate` says outright that **the
//!   session is not removed from the registry**.
//! - §17.1 says `Dead(reason)` is removed *"at next reaper sweep"*.
//!
//! **§5.5.1's reading wins, and it wins on dependents rather than on
//! seniority.** Three shipped things are false under either of the
//! others. `terminate` idempotence (REQ-T-010) turns on the entry
//! surviving — that is what makes the repeat call `ok`.
//! `sessions_exited_retained` is published on `daemon/status` (§7.4.1)
//! and in §3.2's CLI line, and would be permanently `0` under §16.7's
//! reading and a ≤30 s transient under §17.1's. And `resources/list`
//! omitting terminal sessions is only a *behaviour* if terminal sessions
//! are still in the registry to omit.
//!
//! So a reaped session keeps its id, its buffer and its registry entry:
//! `tool/status` and `tool/read_output` still resolve it,
//! `clasp://session/{id}/buffer` still resolves it, `resources/list`
//! omits it, the name is released for reuse (REQ-S-002), and
//! `sessions_exited_retained` counts it. **`session_not_found` after a
//! reap is not this milestone's behaviour and no test asserts it.**
//! §17.1's `Dead(reason) → (removed)` row has no implementer in v0.1.0.
//!
//! **Surfaced, not decided:** whether the reaper should latch
//! `Dead("reaped")`. §16.7 step 3 reads `Running → Exited(code) →
//! Dead("reaped")` and §17.1 closes the `Dead` set at `spawn_failed`,
//! `backend_error`, `reaped`. It is mechanically free —
//! `SessionState::Dead(String)` exists, `Session::state()` only
//! overwrites `Starting | Running` so a latch survives, and `exit_code()`
//! reads the backend rather than the state variant — but it is **not**
//! free on the wire, because `SessionState::as_str()` renders `"Dead"`
//! and a reaped session's `state` would change from `"Exited"` to
//! `"Dead"` on `status` and `list_sessions`. 0.0.9's Decision 9 wants it
//! (it has no other way to emit `session_reaped` rather than
//! `session_exited`); no requirement obliges 0.0.5 to make that wire
//! change and no test pins either answer. It is left alone here, and if
//! it lands it lands with a §23.3 note.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::{SessionId, SessionRegistry};
use crate::clock::Clock;
use crate::pty::Signal;

/// How often the reaper looks at the registry (§16.7 step 2,
/// REQ-S-005).
pub const SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// How long a session gets between SIGTERM and SIGKILL (REQ-S-005,
/// §16.7 step 2).
///
/// **Five seconds, and it is not the daemon's ten.** Three graces meet
/// in this milestone and they are not interchangeable: `daemon/stop`'s
/// is §7.4.1's and §3.2's **10 s** and covers every session sweeping
/// down at once, `terminate(force=false)`'s is §5.2's 5 s, and this one
/// covers a single session at a time.
pub const REAP_GRACE: Duration = Duration::from_secs(5);

/// The idle reaper: one per daemon, holding the registry and the clock.
pub struct Reaper {
    registry: Arc<SessionRegistry>,
    clock: Clock,
    scan_interval: Duration,
    grace: Duration,
    /// Sessions that have been sent SIGTERM and are inside their grace,
    /// with the instant the SIGTERM went out **on the reaper's clock**.
    ///
    /// The escalation cannot re-derive "still idle" from
    /// `last_activity_ms`, because [`super::Session::signal`] bumps it —
    /// a reaper that checked the stamp again after signalling would
    /// never reach SIGKILL, and `the_reaper_escalates_to_sigkill_after_
    /// the_grace_period` is what says so.
    pending: Mutex<HashMap<SessionId, Instant>>,
}

impl Reaper {
    pub fn new(registry: Arc<SessionRegistry>, clock: Clock) -> Self {
        Self {
            registry,
            clock,
            scan_interval: SCAN_INTERVAL,
            grace: REAP_GRACE,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// A reaper with non-default timings, for tests that want a shorter
    /// grace than five seconds of a manual clock's hand.
    pub fn with_timings(
        registry: Arc<SessionRegistry>,
        clock: Clock,
        scan_interval: Duration,
        grace: Duration,
    ) -> Self {
        Self {
            registry,
            clock,
            scan_interval,
            grace,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Run exactly one sweep and return how many sessions it **newly**
    /// reaped — that is, how many received their first SIGTERM on this
    /// pass. A second sweep over the same sessions returns 0 even though
    /// it may escalate them.
    ///
    /// Synchronous and non-blocking on purpose. An `async` sweep that
    /// slept out its own grace would, on a manual clock, park until the
    /// test advanced the hand again — and a test that forgot would hang
    /// rather than fail. There is no `nextest.toml` in this repo, so a
    /// hung sweep is a hung CI job. Escalation is therefore a *second*
    /// sweep's job, and [`Reaper::next_tick`] is what keeps the
    /// production loop honest about when that second sweep is due.
    ///
    /// This is also the entry point 0.0.6's over-`attach.sock` test
    /// takes: it runs one sweep rather than advancing the hand and
    /// hoping the 30-second tick landed inside the window.
    pub fn scan_once(&self) -> usize {
        let now_ms = self.clock.now_ms();
        let now = self.clock.now();
        let mut pending = self.pending.lock();
        let mut newly_reaped = 0;

        for session in self.registry.all() {
            // A session that has already exited is not reaped — it is
            // *done*. Its registry entry stays either way (§5.5.1), and
            // signalling a corpse would put it in the count.
            if !session.is_alive() {
                pending.remove(&session.id);
                continue;
            }

            match pending.get(&session.id).copied() {
                Some(sent_at) => {
                    // Inside the grace: escalate only once it is spent.
                    if now.saturating_duration_since(sent_at) >= self.grace {
                        let _ = session.signal(Signal::Kill);
                        pending.remove(&session.id);
                    }
                }
                None => {
                    // The reaper **reads** `last_activity_ms` and must
                    // never write it (REQ-S-006). A scan that touched
                    // the session record would keep every session alive
                    // forever, and the scan is the only thing that would
                    // ever observe it.
                    if session.is_past_idle_deadline(now_ms) {
                        // §4.4's session sweep: `Session::signal` goes to
                        // the child's whole process group, not
                        // `killpg(pgid)` alone. Reused rather than
                        // re-implemented, because targeting is where
                        // §4.4 records a measured failure.
                        let _ = session.signal(Signal::Terminate);
                        pending.insert(session.id.clone(), now);
                        newly_reaped += 1;
                    }
                }
            }
        }
        newly_reaped
    }

    /// Whether a sweep is owed sooner than the scan interval because a
    /// grace is running.
    pub fn has_pending_escalation(&self) -> bool {
        !self.pending.lock().is_empty()
    }

    /// How long until the next sweep is due.
    ///
    /// The grace when one is running, the scan interval otherwise. A
    /// loop that always waited the scan interval would give a
    /// SIGTERM-trapping child 30 seconds instead of REQ-S-005's five —
    /// invisible to a test that drives `scan_once` by hand, which is why
    /// this is a function with its own assertion rather than a literal
    /// inside the loop.
    pub fn next_tick(&self) -> Duration {
        if self.has_pending_escalation() {
            self.grace
        } else {
            self.scan_interval
        }
    }

    /// Sleep until the next sweep is due, **on the reaper's clock**.
    pub async fn wait_for_next_tick(&self) {
        let deadline = self.clock.now() + self.next_tick();
        self.clock.sleep_until(deadline).await;
    }

    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::MockPty;
    use crate::session::{Session, SessionConfig};

    fn registry() -> Arc<SessionRegistry> {
        Arc::new(SessionRegistry::with_defaults())
    }

    fn session(id: &str, idle_timeout_secs: u64, clock: Clock) -> Arc<Session> {
        Session::new(
            id.to_string(),
            None,
            "mock".into(),
            vec![],
            Arc::new(MockPty::new()),
            SessionConfig {
                idle_timeout_secs,
                clock,
                ..SessionConfig::default()
            },
        )
    }

    #[test]
    fn an_idle_session_is_reaped_after_its_timeout() {
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let s = session("sess_idle", 1800, clock.clone());
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        assert_eq!(reaper.scan_once(), 0, "not yet past its deadline");
        assert!(s.is_alive());

        clock.advance(Duration::from_secs(1801));
        assert_eq!(reaper.scan_once(), 1, "a reaper that scans and never acts");
        assert!(
            !s.is_alive(),
            "the session survived its SIGTERM — the mock backend dies on Terminate"
        );
        // §5.5.1's ruling: the entry stays.
        assert!(
            reg.get("sess_idle").is_ok(),
            "the reaper removed the registry entry, which is §16.7 step 4 \
             and not this milestone's behaviour"
        );
    }

    #[test]
    fn a_busy_session_is_never_reaped() {
        // The pairing, and the one that matters: a reaper that ignores
        // `last_activity` and reaps on *age* passes the row above
        // perfectly and kills every long-running session on schedule.
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let s = session("sess_busy", 60, clock.clone());
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        for _ in 0..3 {
            clock.advance(Duration::from_secs(40));
            // Real ReadWrite input, which is what REQ-S-006 says bumps
            // activity. The deadline must move with it.
            s.write_input_acked(b"x").expect("write");
            assert_eq!(
                reaper.scan_once(),
                0,
                "a session driven inside its window was reaped"
            );
            assert!(s.is_alive());
        }
    }

    #[test]
    fn idle_timeout_zero_disables_reaping_for_that_session() {
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let s = session("sess_forever", 0, clock.clone());
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        assert_eq!(
            s.idle_deadline_ms(),
            None,
            "a disabled session must be skipped, not given a far-future \
             sentinel — a sentinel eventually arrives"
        );
        clock.advance(Duration::from_secs(7 * 86_400));
        assert_eq!(
            reaper.scan_once(),
            0,
            "`0` was treated as \"reap immediately\", which is what a naive \
             `now >= last + 0` does"
        );
        assert!(s.is_alive());
    }

    #[test]
    fn the_reaper_escalates_to_sigkill_after_the_grace_period() {
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        // A backend that ignores SIGTERM, which is what an interactive
        // shell does (§4.4) and what makes the escalation load-bearing.
        let s = Session::new(
            "sess_trap".into(),
            None,
            "trap".into(),
            vec![],
            Arc::new(MockPty::ignoring_terminate()),
            SessionConfig {
                idle_timeout_secs: 60,
                clock: clock.clone(),
                ..SessionConfig::default()
            },
        );
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        clock.advance(Duration::from_secs(61));
        assert_eq!(reaper.scan_once(), 1);
        assert!(
            s.is_alive(),
            "a SIGTERM-trapping child must survive the SIGTERM, or this row \
             proves nothing about the escalation"
        );
        assert!(reaper.has_pending_escalation());
        assert_eq!(
            reaper.next_tick(),
            REAP_GRACE,
            "the loop must come back within the grace, not in 30 s"
        );

        // Short of the grace: still alive. This arm is what stops the
        // row passing against an unconditional SIGKILL.
        clock.advance(Duration::from_secs(4));
        assert_eq!(reaper.scan_once(), 0);
        assert!(s.is_alive(), "escalated before the grace was spent");

        clock.advance(Duration::from_secs(2));
        reaper.scan_once();
        assert!(
            !s.is_alive(),
            "sending SIGTERM only leaves a trapping child running forever"
        );
        assert!(!reaper.has_pending_escalation());
        assert_eq!(reaper.next_tick(), SCAN_INTERVAL);
    }

    #[test]
    fn the_reaper_does_not_bump_activity_while_scanning() {
        // A scan that touched the session record silently disables the
        // whole feature, and the scan is the only thing that would ever
        // observe it.
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let s = session("sess_untouched", 1800, clock.clone());
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        let before = s.last_activity_ms();
        let deadline_before = s.idle_deadline_ms();
        for _ in 0..5 {
            clock.advance(Duration::from_secs(60));
            assert_eq!(reaper.scan_once(), 0);
        }
        assert_eq!(
            s.last_activity_ms(),
            before,
            "a scan bumped last_activity_ms"
        );
        assert_eq!(s.idle_deadline_ms(), deadline_before);

        // And it still reaps on schedule, which is the half that catches
        // a "scan" that does nothing at all.
        clock.advance(Duration::from_secs(1801));
        assert_eq!(reaper.scan_once(), 1);
    }

    #[test]
    fn a_reaped_session_keeps_its_registry_entry() {
        // Step 3's ruling, and the row that stops §16.7 step 4 from
        // being implemented by accident. The same mutation reddens
        // `daemon_status_reports_real_session_counts` and
        // `an_exited_session_disappears_from_the_resource_list`; this row
        // is what makes those failures legible as one ruling instead of
        // three unrelated bugs.
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let s = session("sess_kept", 60, clock.clone());
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        clock.advance(Duration::from_secs(61));
        assert_eq!(reaper.scan_once(), 1);
        assert!(!s.is_alive());

        let found = reg
            .get("sess_kept")
            .expect("a reaped session still resolves by id (§5.5.1, REQ-T-010)");
        assert_eq!(found.id, "sess_kept");
        assert_eq!(reg.all().len(), 1);
        assert_eq!(
            reg.live_count(),
            0,
            "it counts as exited-retained, not as live"
        );
    }

    #[test]
    fn an_already_exited_session_is_not_counted_as_reaped() {
        // Otherwise every sweep after the first reports the same corpse
        // and `scan_once`'s return value means nothing.
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let s = session("sess_done", 60, clock.clone());
        reg.insert(Arc::clone(&s)).unwrap();
        let reaper = Reaper::new(Arc::clone(&reg), clock.clone());

        clock.advance(Duration::from_secs(61));
        assert_eq!(reaper.scan_once(), 1);
        clock.advance(Duration::from_secs(61));
        assert_eq!(reaper.scan_once(), 0, "a corpse was reaped a second time");
        assert!(!reaper.has_pending_escalation());
    }

    #[test]
    fn the_scan_interval_and_the_grace_are_the_two_the_spec_names() {
        // Pinned as literals, not against each other: the reaper's 5 s is
        // the one that leaked into `daemon/stop`'s grace in an earlier
        // revision, and two constants that read each other agree while
        // both being wrong.
        assert_eq!(SCAN_INTERVAL, Duration::from_secs(30));
        assert_eq!(REAP_GRACE, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn the_tick_sleeps_on_the_reapers_own_clock() {
        // No `Instant::now()` and no `tokio::time::sleep` anywhere in
        // this file: a reaper that read wall time in one of its two
        // timers is drivable only in the half that does not need driving.
        let reg = registry();
        let clock = Clock::manual(Instant::now());
        let reaper = Arc::new(Reaper::new(Arc::clone(&reg), clock.clone()));

        let waiter = {
            let reaper = Arc::clone(&reaper);
            tokio::spawn(async move { reaper.wait_for_next_tick().await })
        };
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(SCAN_INTERVAL + Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the tick never fired after the hand passed it")
            .expect("tick task panicked");
    }
}
