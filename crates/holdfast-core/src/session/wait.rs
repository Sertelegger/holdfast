//! `wait_for_pattern`'s two-phase scan (spec §5.2, REQ-T-007, REQ-C-006).
//!
//! **The ordering is the requirement.** Subscribe to the session's output
//! broadcast *first*, then snapshot the buffer, then scan history, then
//! drain whatever queued while the historical scan ran, then go live.
//! Subscribing after the snapshot loses every byte written in between, and
//! that window is exactly where a fast command's output lands.
//!
//! **The matcher is stateful across chunks**, which §5.2 requires in
//! terms: a pattern split across two broadcast frames must still be found,
//! so the regex may not be run independently on each frame. This
//! implementation takes §5.2's explicitly permitted second option — a
//! **coalesced buffer**: bytes are appended to one window that carries its
//! own absolute start offset, and the pattern is searched over that
//! window. A `regex-automata` streaming DFA would be the other option; it
//! buys throughput this milestone has no measurement calling for, and
//! costs the ability to report the match's *text*, which §5.2 requires.
//!
//! On broadcast lag the window is rebuilt from
//! `max(clamp_since_cursor, buffer.tail)` — **not** from the frame
//! boundary the receiver happened to reach (REQ-C-006). The difference
//! shows up only for a match whose start bytes preceded the lag and are
//! still in the ring; rebuilding from the frame boundary misses it
//! silently.

use super::{OutputFrame, Session};
use regex::bytes::Regex;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;

/// How much of the scanned stream the coalesced window keeps.
///
/// A wait with no deadline over a chatty session would otherwise grow one
/// allocation without bound. Dropping from the front can only lose a match
/// whose *start* is more than this far behind the newest byte, which is
/// the same class of loss the ring buffer itself has, one order of
/// magnitude earlier.
const SCAN_WINDOW_BYTES: usize = 256 * 1024;

/// How often the wait loop wakes to re-check liveness when no frame has
/// arrived. A child that exits produces no bytes, so nothing would wake a
/// pure `recv().await` until the caller's deadline.
const LIVENESS_POLL: Duration = Duration::from_millis(50);

/// Where the scan starts and how long it may run.
#[derive(Debug, Clone, Copy)]
pub struct WaitSpec {
    /// Absolute offset to begin scanning from. `None` means live-only,
    /// which resolves to `buffer.head` at subscription time (§5.2).
    pub since_cursor: Option<u64>,
    /// The already-clamped deadline (REQ-T-008 resolves it).
    pub timeout: Duration,
}

/// One match, in absolute buffer offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchSpan {
    pub start: u64,
    pub end: u64,
}

/// Why the wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitEnd {
    Matched,
    TimedOut,
    SessionDied,
}

#[derive(Debug, Clone)]
pub struct WaitOutcome {
    pub end: WaitEnd,
    pub found: Option<MatchSpan>,
    /// The offset the scan actually started from, after clamping to the
    /// live buffer tail.
    pub scan_start: u64,
    /// The requested `since_cursor` was older than `buffer.tail`, so
    /// matches between the two may have been missed (§5.2).
    pub truncated_at_tail: bool,
}

/// Run the two-phase scan. Cancel-safe only at the granularity of the
/// caller's own timeout: the loop owns its deadline.
pub async fn for_pattern(session: &Session, pattern: &Regex, spec: WaitSpec) -> WaitOutcome {
    let deadline = Instant::now() + spec.timeout;

    // 1. Subscribe BEFORE the snapshot. Everything written from here on is
    //    queued for us even while the historical scan runs.
    let mut rx = session.subscribe();

    // 2. Snapshot under the buffer lock; scan outside it.
    let (mut window, mut window_start, snapshot_head, truncated_at_tail) = {
        let (tail, head) = session.buffer_extent();
        let requested = spec.since_cursor.unwrap_or(head);
        let clamped = requested.clamp(tail, head);
        let bytes = session.buffer_slice(clamped, head);
        (bytes, clamped, head, clamped > requested)
    };
    let scan_start = window_start;
    let mut scan_cursor = snapshot_head;

    let mut outcome = WaitOutcome {
        end: WaitEnd::TimedOut,
        found: None,
        scan_start,
        truncated_at_tail,
    };

    // 3. History.
    if let Some(found) = search(pattern, &window, window_start) {
        outcome.end = WaitEnd::Matched;
        outcome.found = Some(found);
        return outcome;
    }

    // 4-8. Drain what queued, then stay live until match, death, or the
    // deadline. `recv` is polled with a short timeout rather than awaited
    // outright, because a child that has exited writes nothing and would
    // otherwise hold the caller until its full deadline.
    loop {
        let now = Instant::now();
        if now >= deadline {
            outcome.end = WaitEnd::TimedOut;
            return outcome;
        }
        let slice = LIVENESS_POLL.min(deadline - now);
        match tokio::time::timeout(slice, rx.recv()).await {
            Ok(Ok(frame)) => {
                if feed(&mut window, &mut window_start, &mut scan_cursor, &frame) {
                    if let Some(found) = search(pattern, &window, window_start) {
                        outcome.end = WaitEnd::Matched;
                        outcome.found = Some(found);
                        return outcome;
                    }
                }
            }
            Ok(Err(RecvError::Lagged(_))) => {
                // REQ-C-006: rebuild from the earliest still-buffered
                // search start, not from where the receiver resumed.
                let rebuilt = resync(session, scan_start, &mut outcome);
                window = rebuilt.window;
                window_start = rebuilt.window_start;
                scan_cursor = rebuilt.scan_cursor;
                if let Some(found) = search(pattern, &window, window_start) {
                    outcome.end = WaitEnd::Matched;
                    outcome.found = Some(found);
                    return outcome;
                }
            }
            // The session (and with it the sender) is gone.
            Ok(Err(RecvError::Closed)) => {
                outcome.end = WaitEnd::SessionDied;
                return outcome;
            }
            Err(_elapsed) => {
                if !session.is_alive() {
                    // One last look: the reader may have appended after the
                    // frame we last saw and before it noticed the exit.
                    let (tail, head) = session.buffer_extent();
                    let start = scan_start.max(tail);
                    let final_window = session.buffer_slice(start, head);
                    if let Some(found) = search(pattern, &final_window, start) {
                        outcome.end = WaitEnd::Matched;
                        outcome.found = Some(found);
                    } else {
                        outcome.end = WaitEnd::SessionDied;
                    }
                    return outcome;
                }
            }
        }
    }
}

/// The window a lagged waiter starts again from.
struct Resync {
    window: Vec<u8>,
    window_start: u64,
    scan_cursor: u64,
}

/// Rebuild the scan window after a broadcast lag (REQ-C-006).
///
/// **From `max(scan_start, buffer.tail)`, not from the frame boundary the
/// receiver resumed at.** The two differ only for a match whose *start*
/// bytes preceded the lag and are still in the ring — which is precisely
/// the case a lag creates, so rebuilding from the boundary loses exactly
/// the matches lag recovery exists to save. Where the tail has moved past
/// the requested start, bytes really were lost and `truncated_at_tail`
/// says so.
fn resync(session: &Session, scan_start: u64, outcome: &mut WaitOutcome) -> Resync {
    let (tail, head) = session.buffer_extent();
    let resync_start = scan_start.max(tail);
    if resync_start > scan_start {
        outcome.truncated_at_tail = true;
    }
    let mut window = session.buffer_slice(resync_start, head);
    let mut window_start = resync_start;
    trim(&mut window, &mut window_start);
    Resync {
        window,
        window_start,
        scan_cursor: head,
    }
}

/// Append a frame's unscanned suffix. Returns whether anything was added.
fn feed(
    window: &mut Vec<u8>,
    window_start: &mut u64,
    scan_cursor: &mut u64,
    frame: &OutputFrame,
) -> bool {
    // The historical scan already covered everything below `scan_cursor`,
    // so a frame that straddles the cutover contributes only its suffix —
    // which is what the frame's absolute span is carried for.
    let from = frame.start.max(*scan_cursor);
    if from >= frame.end {
        return false;
    }
    // A frame that begins past the window's end would leave a hole; that
    // can only happen after a lag, which resyncs instead.
    if from > *window_start + window.len() as u64 {
        return false;
    }
    window.extend_from_slice(&frame.bytes[(from - frame.start) as usize..]);
    *scan_cursor = frame.end;
    trim(window, window_start);
    true
}

fn trim(window: &mut Vec<u8>, window_start: &mut u64) {
    if window.len() > SCAN_WINDOW_BYTES {
        let drop = window.len() - SCAN_WINDOW_BYTES;
        window.drain(..drop);
        *window_start += drop as u64;
    }
}

fn search(pattern: &Regex, window: &[u8], window_start: u64) -> Option<MatchSpan> {
    pattern.find(window).map(|m| MatchSpan {
        start: window_start + m.start() as u64,
        end: window_start + m.end() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::{MockPty, PtyBackend};
    use crate::session::{new_session_id, SessionConfig};
    use std::sync::Arc;

    fn mock() -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(4096),
        );
        (s, pty)
    }

    fn re(p: &str) -> Regex {
        Regex::new(p).unwrap()
    }

    fn spec(since: Option<u64>, ms: u64) -> WaitSpec {
        WaitSpec {
            since_cursor: since,
            timeout: Duration::from_millis(ms),
        }
    }

    #[tokio::test]
    async fn a_pattern_already_in_the_buffer_is_found_in_the_historical_phase() {
        let (s, pty) = mock();
        pty.queue_output(b"one\nREADY\ntwo\n");
        // Give the reader time to land the bytes before the scan starts.
        while s.buffer_head() < 14 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let out = for_pattern(&s, &re("READY"), spec(Some(0), 2000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
        assert_eq!(out.found, Some(MatchSpan { start: 4, end: 9 }));
        assert!(!out.truncated_at_tail);
    }

    /// The default is live-only, so a pattern that already went past is
    /// **not** a match. Without this, `since_cursor: None` resolving to 0
    /// would look identical to the test above.
    #[tokio::test]
    async fn a_live_only_wait_does_not_match_what_already_arrived() {
        let (s, pty) = mock();
        pty.queue_output(b"READY\n");
        while s.buffer_head() < 6 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let out = for_pattern(&s, &re("READY"), spec(None, 200)).await;
        assert_eq!(out.end, WaitEnd::TimedOut);
        assert_eq!(out.found, None);
    }

    #[tokio::test]
    async fn a_pattern_that_arrives_after_the_snapshot_is_found_live() {
        let (s, pty) = mock();
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            writer.queue_output(b"still working\nREADY\n");
        });
        let out = for_pattern(&s, &re("READY"), spec(None, 5000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
        let found = out.found.expect("a match");
        assert_eq!(found.end - found.start, 5);
    }

    /// REQ-T-007's real content: the matcher is stateful across frames.
    /// Each half of the pattern arrives in its own broadcast frame, so a
    /// per-frame regex finds nothing.
    #[tokio::test]
    async fn a_pattern_split_across_two_frames_is_found() {
        let (s, pty) = mock();
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            writer.queue_output(b"SPLI");
            std::thread::sleep(Duration::from_millis(60));
            writer.queue_output(b"T_ME\n");
        });
        let out = for_pattern(&s, &re("SPLIT_ME"), spec(None, 5000)).await;
        assert_eq!(out.end, WaitEnd::Matched, "the match spans two frames");
        let found = out.found.expect("a match");
        assert_eq!(found.start, 0);
        assert_eq!(found.end, 8);
    }

    /// The paired negative. Without it, the row above is satisfied by a
    /// "matcher" that only ever reports across boundaries — one that never
    /// resets and never matches within a single frame.
    #[tokio::test]
    async fn a_pattern_wholly_inside_one_frame_is_found_too() {
        let (s, pty) = mock();
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            writer.queue_output(b"SPLIT_ME\n");
        });
        let out = for_pattern(&s, &re("SPLIT_ME"), spec(None, 5000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
        let found = out.found.expect("a match");
        assert_eq!(found.start, 0);
        assert_eq!(found.end, 8);
    }

    #[tokio::test]
    async fn a_stale_cursor_is_clamped_to_the_tail_and_reported() {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(16),
        );
        pty.queue_output(b"0123456789abcdef");
        pty.queue_output(b"GHIJKLMNOPQRSTUV");
        while s.buffer_head() < 32 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let out = for_pattern(&s, &re("NOPQ"), spec(Some(0), 2000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
        assert!(
            out.truncated_at_tail,
            "cursor 0 is below the live tail, so earlier matches were missed"
        );
        assert_eq!(out.scan_start, 16, "the scan began at the live tail");
    }

    /// The negative half: a cursor still inside the buffer sets no flag.
    #[tokio::test]
    async fn a_live_cursor_reports_no_truncation() {
        let (s, pty) = mock();
        pty.queue_output(b"hello READY\n");
        while s.buffer_head() < 12 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let out = for_pattern(&s, &re("READY"), spec(Some(0), 2000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
        assert!(!out.truncated_at_tail);
        assert_eq!(out.scan_start, 0);
    }

    #[tokio::test]
    async fn a_child_that_exits_without_matching_ends_the_wait_early() {
        let (s, pty) = mock();
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            writer.queue_output(b"nothing interesting\n");
            writer.exit(0);
        });
        let started = Instant::now();
        // A 30 s deadline the test must NOT wait out: the exit is what
        // ends it. A wait that only honoured the deadline would take the
        // full thirty seconds and time this test out.
        let out = for_pattern(&s, &re("READY"), spec(None, 30_000)).await;
        assert_eq!(out.end, WaitEnd::SessionDied);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait ran on past the child's exit: {:?}",
            started.elapsed()
        );
    }

    /// A match that lands in the same breath as the exit is still a match:
    /// death is checked only after the final rescan.
    #[tokio::test]
    async fn output_written_just_before_an_exit_still_matches() {
        let (s, pty) = mock();
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            writer.queue_output(b"READY\n");
            writer.exit(0);
        });
        let out = for_pattern(&s, &re("READY"), spec(None, 5000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
    }

    #[tokio::test]
    async fn a_pattern_that_never_arrives_times_out() {
        let (s, pty) = mock();
        pty.queue_output(b"working\n");
        let started = Instant::now();
        let out = for_pattern(&s, &re("NEVER"), spec(None, 300)).await;
        assert_eq!(out.end, WaitEnd::TimedOut);
        assert_eq!(out.found, None);
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "the deadline was not honoured: {:?}",
            started.elapsed()
        );
    }

    /// REQ-C-006, over the rule itself.
    ///
    /// **Written against `resync` directly, and that is deliberate.** The
    /// obvious version — force a real broadcast lag by flooding a slow
    /// consumer — does not lag: measured, a `panic!` planted in the
    /// `Lagged` arm never fires, because `MockPty::read` drains its whole
    /// queue into one frame and the waiter keeps up with anything a test
    /// can produce. That test passes whatever the recovery does, which is
    /// the shape this milestone exists to stop shipping. This one asserts
    /// the rule the arm applies.
    #[tokio::test]
    async fn a_lag_resync_rebuilds_from_the_earliest_still_buffered_byte() {
        let (s, pty) = mock();
        pty.queue_output(b"LAGxxxxGED\n");
        while s.buffer_head() < 11 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut outcome = WaitOutcome {
            end: WaitEnd::TimedOut,
            found: None,
            scan_start: 0,
            truncated_at_tail: false,
        };
        let rebuilt = resync(&s, 0, &mut outcome);
        assert_eq!(
            rebuilt.window_start, 0,
            "the scan start is still buffered, so recovery begins there — \
             not at the frame boundary the receiver resumed at"
        );
        assert_eq!(rebuilt.scan_cursor, 11);
        assert_eq!(
            search(&re(r"LAGx+GED"), &rebuilt.window, rebuilt.window_start),
            Some(MatchSpan { start: 0, end: 10 }),
            "a match whose start preceded the lag is recovered whole"
        );
        assert!(
            !outcome.truncated_at_tail,
            "nothing was lost: the requested start is still in the ring"
        );

        // The other arm of the `max`: a caller that asked to start at 4
        // must not be handed bytes 0..4 back. With `tail == scan_start`
        // above, `max(scan_start, tail)` and a bare `tail` are the same
        // expression; here they are not.
        let rebuilt = resync(&s, 4, &mut outcome);
        assert_eq!(rebuilt.window_start, 4);
        assert_eq!(rebuilt.window, b"xxxGED\n");
    }

    /// The other arm of the same rule: once the tail has moved past the
    /// requested start, bytes really were lost and the flag says so.
    /// Without this, a `resync` that always started at `buffer.tail` — and
    /// never set the flag — would satisfy the test above.
    #[tokio::test]
    async fn a_lag_resync_past_the_tail_reports_the_loss() {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(8),
        );
        pty.queue_output(b"0123456789abcdef");
        while s.buffer_head() < 16 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut outcome = WaitOutcome {
            end: WaitEnd::TimedOut,
            found: None,
            scan_start: 0,
            truncated_at_tail: false,
        };
        let rebuilt = resync(&s, 0, &mut outcome);
        assert_eq!(rebuilt.window_start, 8, "clamped up to the live tail");
        assert_eq!(rebuilt.window, b"89abcdef");
        assert!(
            outcome.truncated_at_tail,
            "the requested start rolled out of the ring; the agent is told"
        );
    }

    /// A burst of frames larger than the broadcast bound loses no match.
    /// This is what the flood test can honestly assert: whether or not the
    /// receiver lags, the pattern is found.
    #[tokio::test]
    async fn a_match_spanning_a_burst_of_frames_is_still_found() {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(1 << 20),
        );
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            writer.queue_output(b"LAG");
            for _ in 0..(super::super::OUTPUT_BROADCAST_FRAMES * 2) {
                writer.queue_output(b"x");
                std::thread::sleep(Duration::from_micros(200));
            }
            writer.queue_output(b"GED\n");
        });
        let out = for_pattern(&s, &re(r"LAGx+GED"), spec(None, 10_000)).await;
        assert_eq!(out.end, WaitEnd::Matched);
        assert_eq!(out.found.expect("a match").start, 0);
    }
}
