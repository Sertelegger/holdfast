//! The injectable time source. One clock for every deadline in the
//! daemon (§16.7, REQ-S-005), so that "advance the clock" means one
//! thing in every suite that says it.
//!
//! `System` is wall time. `Manual` is a hand a test moves, and
//! [`Clock::sleep_until`] on it parks a waiter that only wakes when
//! [`Clock::advance`] moves the hand past its deadline — so a test
//! drives a 30-minute timeout in microseconds instead of not running.
//!
//! This is a **crate-level** module rather than a reaper detail on
//! purpose: 0.0.6 needs the reaper's deadline drivable from an
//! integration test over `attach.sock`, and 0.0.7 will build a second
//! `Clock` in `secret/clock.rs` unless this one exports `now`,
//! `sleep_until` and `advance`. Two manual clocks in one crate is not
//! redundancy — it is two answers to "what time is it" that a single
//! test can hold at once.
//!
//! **What must not read this clock:** `daemon::server::unix_secs_now`,
//! which stamps `stopped_at_unix_secs` from `SystemTime`. That is a
//! wall-clock fact reported to a caller, not a deadline, and putting it
//! on a manual clock would let a test emit a timestamp from 1970.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::oneshot;

/// An injectable time source shared by the daemon, the reaper and any
/// test that wants to drive a deadline.
///
/// `Clone` is on the type because all three hold the *same* hand; the
/// `Arc` inside is what makes that one hand rather than three.
#[derive(Clone)]
pub struct Clock(Arc<Inner>);

enum Inner {
    System,
    Manual {
        now: Mutex<Instant>,
        waiters: Mutex<Vec<(Instant, oneshot::Sender<()>)>>,
        /// Where the hand started, and the Unix-epoch millisecond it
        /// stood at then.
        ///
        /// `Instant` is monotonic and has no epoch, but
        /// `Session::last_activity_ms` is Unix-epoch milliseconds — so a
        /// purely `Instant`-based clock cannot be compared with the one
        /// value the reaper's whole decision rests on. Anchoring the
        /// hand to an epoch here keeps that comparison inside one clock
        /// instead of quietly mixing two.
        start: Instant,
        epoch_ms: i64,
    },
}

impl Clock {
    /// Wall time. The production constructor.
    pub fn system() -> Self {
        Clock(Arc::new(Inner::System))
    }

    /// A hand a test moves. `start` is where the hand begins; use
    /// `Instant::now()` unless a test needs something else.
    pub fn manual(start: Instant) -> Self {
        Clock(Arc::new(Inner::Manual {
            now: Mutex::new(start),
            waiters: Mutex::new(Vec::new()),
            start,
            epoch_ms: system_now_ms(),
        }))
    }

    /// True when this clock is a hand rather than wall time. Used by
    /// callers that must not busy-poll a manual clock.
    pub fn is_manual(&self) -> bool {
        matches!(*self.0, Inner::Manual { .. })
    }

    /// The current time **on this clock**.
    pub fn now(&self) -> Instant {
        match &*self.0 {
            Inner::System => Instant::now(),
            Inner::Manual { now, .. } => *now.lock(),
        }
    }

    /// The current time **on this clock**, in Unix-epoch milliseconds.
    ///
    /// This is the view the reaper needs: `Session::last_activity_ms`
    /// and `Session::idle_deadline_ms` are epoch millis, so comparing
    /// them against `Instant`s would be comparing two clocks. On
    /// `Manual` it advances only when [`Clock::advance`] does, which is
    /// what lets a test drive a 30-minute timeout in microseconds.
    pub fn now_ms(&self) -> i64 {
        match &*self.0 {
            Inner::System => system_now_ms(),
            Inner::Manual {
                now,
                start,
                epoch_ms,
                ..
            } => {
                let elapsed = now.lock().saturating_duration_since(*start);
                epoch_ms.saturating_add(elapsed.as_millis() as i64)
            }
        }
    }

    /// Resolves once `deadline` has passed **on this clock**. `System`
    /// is a `tokio::time::sleep_until`; `Manual` parks a waiter and
    /// returns only when [`Clock::advance`] moves the hand past it.
    pub async fn sleep_until(&self, deadline: Instant) {
        match &*self.0 {
            Inner::System => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            }
            Inner::Manual { now, waiters, .. } => {
                let rx = {
                    // `now` is taken before `waiters` here and in
                    // `advance`, so the two can never deadlock; holding
                    // both across the push is what stops an `advance`
                    // landing between the check and the registration.
                    let hand = now.lock();
                    if *hand >= deadline {
                        return;
                    }
                    let (tx, rx) = oneshot::channel();
                    waiters.lock().push((deadline, tx));
                    drop(hand);
                    rx
                };
                // A dropped sender means the clock went away; treat it
                // as elapsed rather than parking forever.
                let _ = rx.await;
            }
        }
    }

    /// `Manual` only — **panics on `System`**, because a production
    /// caller reaching this is a bug that must not be silent. Moves the
    /// hand and wakes every waiter whose deadline is now in the past, in
    /// deadline order.
    pub fn advance(&self, by: Duration) {
        match &*self.0 {
            Inner::System => {
                panic!("Clock::advance called on the system clock: only a manual clock has a hand")
            }
            Inner::Manual { now, waiters, .. } => {
                let mut fired = {
                    // Same lock order as `sleep_until`: `now`, then
                    // `waiters`. Holding both across the split is what
                    // stops a registration landing mid-advance.
                    let mut hand = now.lock();
                    *hand += by;
                    let reached = *hand;
                    let mut parked = waiters.lock();
                    let mut fired = Vec::with_capacity(parked.len());
                    let mut still = Vec::with_capacity(parked.len());
                    for (deadline, tx) in parked.drain(..) {
                        if deadline <= reached {
                            fired.push((deadline, tx));
                        } else {
                            still.push((deadline, tx));
                        }
                    }
                    *parked = still;
                    fired
                };
                // Deadline order, not insertion order: the reaper's
                // grace and its scan tick are registered in whichever
                // order the tasks happen to run, and a `Vec` drained as
                // inserted reorders one against the other.
                fired.sort_by_key(|(deadline, _)| *deadline);
                for (_, tx) in fired {
                    let _ = tx.send(());
                }
            }
        }
    }
}

fn system_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.0 {
            Inner::System => f.write_str("Clock::System"),
            Inner::Manual { .. } => f.write_str("Clock::Manual"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anything that awaits a manual waiter is bounded, because a
    /// manual clock that never fires is an unbounded wait and there is
    /// no `nextest.toml` in this repo to turn that into a red run.
    const WAKE_BOUND: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn advancing_a_manual_clock_wakes_a_waiter_past_its_deadline() {
        let clock = Clock::manual(Instant::now());
        let deadline = clock.now() + Duration::from_secs(30);
        let waiter = {
            let clock = clock.clone();
            tokio::spawn(async move { clock.sleep_until(deadline).await })
        };
        // Let the spawned task register before the hand moves.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(31));
        tokio::time::timeout(WAKE_BOUND, waiter)
            .await
            .expect("the waiter never woke after the hand passed its deadline")
            .expect("waiter task panicked");
    }

    #[tokio::test]
    async fn advancing_short_of_a_deadline_leaves_the_waiter_parked() {
        let clock = Clock::manual(Instant::now());
        let deadline = clock.now() + Duration::from_secs(30);
        let waiter = {
            let clock = clock.clone();
            tokio::spawn(async move { clock.sleep_until(deadline).await })
        };
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(29));
        // Here the timeout *is* the evidence: the waiter must still be
        // pending, so elapsing is the pass.
        let outcome = tokio::time::timeout(Duration::from_millis(150), waiter).await;
        assert!(
            outcome.is_err(),
            "a waiter at +30 s woke on advance(29 s): every deadline fires at once"
        );
    }

    #[test]
    #[should_panic(expected = "Clock::advance called on the system clock")]
    fn advance_on_the_system_clock_panics() {
        Clock::system().advance(Duration::from_secs(1));
    }

    #[tokio::test]
    async fn waiters_wake_in_deadline_order() {
        let clock = Clock::manual(Instant::now());
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));

        // Registered LATE-deadline first on purpose: if insertion order
        // matched deadline order this row would pass against a `Vec`
        // drained as inserted, which is the mutation it exists to kill.
        let far = {
            let clock = clock.clone();
            let order = Arc::clone(&order);
            let deadline = clock.now() + Duration::from_secs(20);
            tokio::spawn(async move {
                clock.sleep_until(deadline).await;
                order.lock().push("twenty");
            })
        };
        // Yield so `far` registers before `near` does.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let near = {
            let clock = clock.clone();
            let order = Arc::clone(&order);
            let deadline = clock.now() + Duration::from_secs(10);
            tokio::spawn(async move {
                clock.sleep_until(deadline).await;
                order.lock().push("ten");
            })
        };
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        clock.advance(Duration::from_secs(25));

        tokio::time::timeout(WAKE_BOUND, near)
            .await
            .expect("the +10 s waiter never woke")
            .expect("waiter task panicked");
        tokio::time::timeout(WAKE_BOUND, far)
            .await
            .expect("the +20 s waiter never woke")
            .expect("waiter task panicked");

        assert_eq!(
            &*order.lock(),
            &["ten", "twenty"],
            "waiters woke in insertion order, not deadline order"
        );
    }

    #[tokio::test]
    async fn a_deadline_already_past_returns_without_parking() {
        let clock = Clock::manual(Instant::now());
        let deadline = clock.now();
        clock.advance(Duration::from_secs(1));
        tokio::time::timeout(WAKE_BOUND, clock.sleep_until(deadline))
            .await
            .expect("a deadline already behind the hand parked forever");
    }

    #[test]
    fn the_epoch_view_advances_with_the_hand_and_not_with_wall_time() {
        // The reaper compares `Clock::now_ms()` against
        // `Session::last_activity_ms`, which is Unix-epoch millis. A
        // `now_ms` that read `SystemTime::now()` even on a manual clock
        // would make every "advance the clock" reaper test a wall-clock
        // test — the exact failure `Clock` exists to prevent, one field
        // deeper.
        let clock = Clock::manual(Instant::now());
        let before = clock.now_ms();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(before, clock.now_ms(), "the epoch view followed wall time");
        clock.advance(Duration::from_secs(1800));
        assert_eq!(clock.now_ms(), before + 1_800_000);
    }

    #[test]
    fn the_system_epoch_view_is_real_wall_time() {
        // The pairing: a `now_ms` that always returned a frozen value
        // would pass the row above and stop the production reaper dead.
        let clock = Clock::system();
        let a = clock.now_ms();
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            clock.now_ms() > a,
            "the system clock's epoch view did not move"
        );
    }

    #[test]
    fn a_manual_clock_only_moves_when_advanced() {
        let clock = Clock::manual(Instant::now());
        let first = clock.now();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            first,
            clock.now(),
            "a manual clock followed wall time: every `advance the clock` test is a wall-clock test"
        );
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), first + Duration::from_secs(5));
    }
}
