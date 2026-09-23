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
//! **The window is kept twice, and a pattern is matched against both**
//! (GH #238). An agent writes its regex from the text it reads, and what
//! it reads — `read_output`'s default, `output_since_start`, `match.text`
//! — has had its ANSI escapes removed. The bytes the program wrote have
//! not: cargo prints `test result: \x1b[32mok\x1b[m`, so
//! `wait_for: "test result: ok"` timed out after its whole deadline on a
//! run that succeeded, with the matching text sitting in the same
//! response's `output_since_start`. So the window carries an escape-free
//! view beside the raw bytes, built by the read path's own
//! [`AnsiStripper`] with a map from every text byte back to its raw
//! offset, and the pattern is searched in both. The earlier match wins,
//! by raw offset; a tie goes to the raw one, whose span is exact.
//!
//! Both, rather than the text alone, because a pattern that spells an
//! escape (`\x1b\[32mok`) is a thing callers were told they could write —
//! the tool's own documentation said "raw output bytes" — and it must keep
//! matching. **`match.offset` stays a raw byte offset** (§5.2): a text
//! match starts at the raw offset of its first byte and ends just past its
//! last, so escapes *inside* the match are inside the span and escapes
//! around it are not.
//!
//! On broadcast lag the window is rebuilt from
//! `max(clamp_since_cursor, buffer.tail)` — **not** from the frame
//! boundary the receiver happened to reach (REQ-C-006). The difference
//! shows up only for a match whose start bytes preceded the lag and are
//! still in the ring; rebuilding from the frame boundary misses it
//! silently.

use super::{OutputFrame, Session};
use crate::detect::InteractionMode;
use crate::output::ansi::AnsiStripper;
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

/// Whether a **pattern-less** wait may answer with `Fullscreen` or
/// `AwaitingSecret` yet (GH #248).
///
/// Those two answer at once rather than at the deadline, and the reason
/// stands: a TUI never returns to a prompt, and a secret prompt wants
/// `request_secret_input`, not patience. What was wrong is *which* sample
/// they answer from. An agent sends `q` to `less` and waits; the key is in
/// the pty but `less` has not read it yet, so the wait's first sample is
/// the `Fullscreen` from **before** the write — and it was returned in
/// 0.0 s, 2 times in 5, with `AtPrompt` half a second later. An agent
/// acting on that presses `q` again and leaves a stray `q` at the shell.
/// `AwaitingSecret` has the same shape one step later: a secret handed in
/// by `request_secret_input` and not yet read still shows echo off.
///
/// So a mode **already showing at the first sample** is not the answer
/// until there is evidence it is not the pre-write one:
///
/// - **The wait watched it arrive** — any change since the first sample —
///   and it answers at once, as before.
/// - **The child has written something since the last input reached it**
///   ([`Session::output_since_last_write`]) and the mode has held for
///   `hold`, the detector's own settle window: the program reacted and is
///   still in this mode — `less` scrolled.
/// - **Nothing has come back since the write**, and the mode has held for
///   [`CARRIED_WITHOUT_OUTPUT_HOLD`]: the key produced no output at all.
///
/// **The first form of this fix held every carried mode for the settle
/// window alone, and that only moved the stale answer** (review of GH
/// #248). `less` takes longer than 250 ms to read a key it was sent while
/// starting, under the load the dogfood pass ran at; the wait then
/// answered `Fullscreen` at ~260 ms, 7 times in 42, and `status` said
/// `AtPrompt` a moment later. A wait cannot see a key being read, but it
/// can see that nothing has answered it yet, and while nothing has, a
/// longer hold costs nothing but the rare key a program ignores silently.
/// Measured with a raw-mode program that reads its key 600 ms after it
/// arrives: the settle-only hold answered `Fullscreen` 10 times in 10,
/// this one `AtPrompt` 10 times in 10, in ~0.6 s.
///
/// **Residuals, all three on the side of the old behaviour.** The longer
/// hold is a bound, not a proof: a program slower than it and still silent
/// is answered from the stale sample. Output that is not an answer to the
/// key counts as one — the tail of a draw still in flight when the key
/// went in, or the line discipline's own echo of the key, which happens at
/// the write whenever `ECHO` is on. `less` sets raw mode before it enters
/// the alternate screen (measured), so neither applies to it once it shows.
#[derive(Debug, Default)]
pub struct CarriedMode {
    first: Option<(InteractionMode, Instant)>,
    moved: bool,
}

/// How long a mode carried into a pattern-less wait is held when nothing
/// has come back since the last write — see [`CarriedMode`].
///
/// Long against the delays that produced GH #248's stale answers (a
/// `less` still starting took ~1 s to read its `q` at load 18–36) and
/// short against a deadline, because it is only ever paid by a key that
/// makes a full-screen program print nothing. Never shorter than the
/// settle window, which an operator can raise past it.
pub const CARRIED_WITHOUT_OUTPUT_HOLD: Duration = Duration::from_secs(2);

impl CarriedMode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one sample and say whether `mode` may be the answer now.
    /// Call it for **every** sample, whatever the mode, or a change the
    /// wait did watch goes unrecorded and the mode it produced waits out a
    /// window it should not.
    ///
    /// `reacted` is [`Session::output_since_last_write`] at this sample;
    /// `hold` applies when it is true, and `silent_hold` when it is not.
    pub fn answerable(
        &mut self,
        mode: InteractionMode,
        now: Instant,
        reacted: bool,
        hold: Duration,
        silent_hold: Duration,
    ) -> bool {
        let (first, since) = *self.first.get_or_insert((mode, now));
        if mode != first {
            self.moved = true;
        }
        let held = now.saturating_duration_since(since);
        self.moved || held >= if reacted { hold } else { silent_hold }
    }
}

/// Run the two-phase scan. Cancel-safe only at the granularity of the
/// caller's own timeout: the loop owns its deadline.
pub async fn for_pattern(session: &Session, pattern: &Regex, spec: WaitSpec) -> WaitOutcome {
    let deadline = Instant::now() + spec.timeout;

    // 1. Subscribe BEFORE the snapshot. Everything written from here on is
    //    queued for us even while the historical scan runs.
    let mut rx = session.subscribe();

    // 2. Snapshot under the buffer lock; scan outside it.
    let (mut window, snapshot_head, truncated_at_tail) = {
        let (tail, head) = session.buffer_extent();
        let requested = spec.since_cursor.unwrap_or(head);
        let clamped = requested.clamp(tail, head);
        let bytes = session.buffer_slice(clamped, head);
        (Window::new(clamped, &bytes), head, clamped > requested)
    };
    let scan_start = window.start;
    let mut scan_cursor = snapshot_head;

    let mut outcome = WaitOutcome {
        end: WaitEnd::TimedOut,
        found: None,
        scan_start,
        truncated_at_tail,
    };

    // 3. History.
    if let Some(found) = window.search(pattern) {
        outcome.end = WaitEnd::Matched;
        outcome.found = Some(found);
        return outcome;
    }

    // 4-8. Drain what queued, then stay live until match, death, or the
    // deadline. `recv` is polled with a short timeout rather than awaited
    // outright, because a child that has exited writes nothing and would
    // otherwise hold the caller until its full deadline.
    // Whether this wait ever observed the session dead. Only used at the
    // deadline, to keep answering `SessionDied` rather than `TimedOut` for
    // a session that is definitely gone but whose reader never signalled
    // completion — a stuck reader must not turn a known death into a
    // timeout, which would be a *new* wrong answer bought with the fix for
    // an old one.
    let mut saw_death = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            if saw_death {
                return final_rescan(session, pattern, scan_start, outcome);
            }
            outcome.end = WaitEnd::TimedOut;
            return outcome;
        }
        let slice = LIVENESS_POLL.min(deadline - now);
        match tokio::time::timeout(slice, rx.recv()).await {
            Ok(Ok(frame)) => {
                if window.feed(&mut scan_cursor, &frame) {
                    if let Some(found) = window.search(pattern) {
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
                scan_cursor = rebuilt.scan_cursor;
                if let Some(found) = window.search(pattern) {
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
                    saw_death = true;
                    // **Wait for the reader, not for the child — GH #42.**
                    // `is_alive()` goes false the moment the child exits,
                    // but the reader breaks only once `read` returns 0
                    // *and* the backend is dead, so the child's last line
                    // is still in the pty for however long the scheduler
                    // takes to run one more `read`. Rescanning on the
                    // child's death alone therefore searched a buffer that
                    // did not yet hold the bytes, and answered
                    // `SessionDied` for output the session really produced
                    // and `read_output` would return a moment later.
                    //
                    // Measured causally rather than by sampling: a 150 ms
                    // delay inserted before the reader's `buffer.push`
                    // turned `output_written_just_before_an_exit_still_matches`
                    // from green into **10 failures in 10**, with exactly
                    // the CI signature (`left: SessionDied, right:
                    // Matched`). The row is otherwise green in 60 isolated
                    // and 8 whole-lib contended runs on a 2-core box,
                    // which is why it read as a flake for so long.
                    //
                    // `reader_finished()` is the positive fact: the reader
                    // has left its loop, so the buffer is final. Its
                    // `Release` store pairs with that method's `Acquire`
                    // load, which is what makes every `buffer.push` before
                    // it visible here.
                    //
                    // **Not `RecvError::Closed`**, which would be the
                    // obvious signal and does not work: `Session` holds
                    // `output_tx` itself, so the sender outlives the
                    // reader thread and that arm is unreachable while the
                    // caller holds an `Arc<Session>` — which it always
                    // does, since `session` is borrowed from one.
                    if session.reader_finished() {
                        return final_rescan(session, pattern, scan_start, outcome);
                    }
                }
            }
        }
    }
}

/// The last look at a finished session's buffer, shared by the two places
/// that take it so they cannot come to disagree about what "one last look"
/// means.
///
/// The caller must already have established that no further output is
/// coming — `Session::reader_finished()` — or the search races the reader
/// that GH #42 is about.
fn final_rescan(
    session: &Session,
    pattern: &Regex,
    scan_start: u64,
    mut outcome: WaitOutcome,
) -> WaitOutcome {
    let (tail, head) = session.buffer_extent();
    let start = scan_start.max(tail);
    let final_window = Window::new(start, &session.buffer_slice(start, head));
    if let Some(found) = final_window.search(pattern) {
        outcome.end = WaitEnd::Matched;
        outcome.found = Some(found);
    } else {
        outcome.end = WaitEnd::SessionDied;
    }
    outcome
}

/// The window a lagged waiter starts again from.
struct Resync {
    window: Window,
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
    let mut window = Window::new(resync_start, &session.buffer_slice(resync_start, head));
    window.trim();
    Resync {
        window,
        scan_cursor: head,
    }
}

/// The coalesced scan window (§5.2's second option), kept in two views.
///
/// `raw` is the stream exactly as the program wrote it. `text` is the same
/// stream with its escape sequences removed by the read path's own
/// [`AnsiStripper`], and `runs` maps `text` back to raw offsets — which is
/// what lets a match found in `text` be reported in raw offsets, as §5.2
/// requires of `match.offset`. See the module doc for why both are
/// searched.
///
/// **The map is one entry per escape, not one per byte**, and that is a
/// budget rather than a nicety. The historical and final-rescan windows are
/// not trimmed: they run from the requested cursor to the head of a ring
/// an operator can configure to any size, so a per-byte `u64` table was
/// eight bytes of bookkeeping for every byte a `since_cursor: 0` wait
/// covered — 8 MiB beside the default 1 MiB ring, and proportionally more
/// beside a larger one. Runs cost what the output's escapes cost.
///
/// The stripper is resumable, so an escape split across two frames is
/// removed exactly as one inside a frame is. A window rebuilt from the
/// ring (`new`, after a lag or at the final rescan) starts its stripper
/// at `Ground`; if the rebuild point falls inside a sequence, that
/// sequence's tail reads as text until the next escape — the same
/// best-effort `read_output` gives a cursor that lands mid-sequence.
struct Window {
    raw: Vec<u8>,
    /// Absolute offset of `raw[0]`.
    start: u64,
    text: Vec<u8>,
    /// Maximal runs of `text` that were contiguous in the raw stream, as
    /// `(index in text of the run's first byte, its raw offset)`, in order.
    /// A new run starts wherever the stripper removed something.
    runs: Vec<(usize, u64)>,
    stripper: AnsiStripper,
}

impl Window {
    fn new(start: u64, bytes: &[u8]) -> Self {
        let mut w = Self {
            raw: Vec::with_capacity(bytes.len()),
            start,
            text: Vec::with_capacity(bytes.len()),
            runs: Vec::new(),
            stripper: AnsiStripper::new(),
        };
        w.push(bytes);
        w
    }

    /// Absolute offset just past the last raw byte.
    fn end(&self) -> u64 {
        self.start + self.raw.len() as u64
    }

    fn push(&mut self, bytes: &[u8]) {
        let from = self.end();
        self.raw.extend_from_slice(bytes);
        for (at, &b) in (from..).zip(bytes) {
            if let Some(t) = self.stripper.feed(at, b) {
                let continues = matches!(
                    self.runs.last(),
                    Some(&(first, raw)) if raw + (self.text.len() - first) as u64 == at
                );
                if !continues {
                    self.runs.push((self.text.len(), at));
                }
                self.text.push(t);
            }
        }
    }

    /// Append a frame's unscanned suffix. Returns whether anything was
    /// added.
    fn feed(&mut self, scan_cursor: &mut u64, frame: &OutputFrame) -> bool {
        // The historical scan already covered everything below
        // `scan_cursor`, so a frame that straddles the cutover contributes
        // only its suffix — which is what the frame's absolute span is
        // carried for.
        let from = frame.start.max(*scan_cursor);
        if from >= frame.end {
            return false;
        }
        // A frame that begins past the window's end would leave a hole;
        // that can only happen after a lag, which resyncs instead.
        if from > self.end() {
            return false;
        }
        self.push(&frame.bytes[(from - frame.start) as usize..]);
        *scan_cursor = frame.end;
        self.trim();
        true
    }

    /// Drop from the front past `SCAN_WINDOW_BYTES` of raw stream, and the
    /// text that came from what was dropped.
    fn trim(&mut self) {
        if self.raw.len() > SCAN_WINDOW_BYTES {
            let drop = self.raw.len() - SCAN_WINDOW_BYTES;
            self.raw.drain(..drop);
            self.start += drop as u64;
            // The first text byte still inside the window: text offsets
            // rise with their index, so this is a binary search.
            let (mut lo, mut hi) = (0, self.text.len());
            while lo < hi {
                let mid = (lo + hi) / 2;
                if self.raw_offset(mid) < self.start {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if lo > 0 {
                let first = (lo < self.text.len()).then(|| self.raw_offset(lo));
                self.text.drain(..lo);
                let kept = self.runs.partition_point(|&(i, _)| i <= lo);
                let mut runs: Vec<(usize, u64)> = first.map(|o| (0, o)).into_iter().collect();
                runs.extend(self.runs[kept..].iter().map(|&(i, o)| (i - lo, o)));
                self.runs = runs;
            }
        }
    }

    /// The raw offset `text[i]` came from. `i` must be a text index.
    fn raw_offset(&self, i: usize) -> u64 {
        let run = self.runs.partition_point(|&(first, _)| first <= i) - 1;
        let (first, raw) = self.runs[run];
        raw + (i - first) as u64
    }

    /// The earlier of the raw match and the text match, in raw offsets.
    fn search(&self, pattern: &Regex) -> Option<MatchSpan> {
        let raw = pattern.find(&self.raw).map(|m| MatchSpan {
            start: self.start + m.start() as u64,
            end: self.start + m.end() as u64,
        });
        let text = pattern.find(&self.text).map(|m| {
            // A text position maps to the raw offset of the byte there, or
            // to the window's end when it is one past the last text byte —
            // which only an empty match can be.
            let at = |i: usize| {
                if i < self.text.len() {
                    self.raw_offset(i)
                } else {
                    self.end()
                }
            };
            let start = at(m.start());
            let end = if m.end() > m.start() {
                self.raw_offset(m.end() - 1) + 1
            } else {
                start
            };
            MatchSpan { start, end }
        });
        match (raw, text) {
            (Some(r), Some(t)) if t.start < r.start => Some(t),
            (Some(r), _) => Some(r),
            (None, t) => t,
        }
    }
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

    /// **The same claim as the row below, made deterministic** (GH #42).
    ///
    /// That row is a coin: the window between the child's death and the
    /// reader's next `read` is normally microseconds, so it stayed green
    /// in 60 isolated and 8 whole-lib contended runs on a 2-core box while
    /// failing on a slower CI host. This one widens the window on purpose,
    /// so the assertion fails whenever the bug is present rather than
    /// whenever the machine is unlucky.
    ///
    /// **The delay is the mutation, and it was measured before the fix
    /// existed**: a 150 ms stall inserted ahead of the reader's
    /// `buffer.push` turned the row below into 10 failures in 10, with
    /// exactly the CI signature (`left: SessionDied, right: Matched`).
    /// Reverting the `reader_finished()` guard in `for_pattern` reddens
    /// this row for that reason and no other.
    #[tokio::test]
    async fn a_slow_reader_does_not_turn_a_match_into_a_death() {
        let (s, pty) = mock();
        // Long enough that the child is observably dead while its last
        // line is still sitting unread in the pty.
        pty.set_read_delay(Duration::from_millis(150));
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            writer.queue_output(b"READY\n");
            writer.exit(0);
        });
        // Comfortably longer than the delay, so a failure here is the
        // wrong answer and never an impatient deadline.
        let out = for_pattern(&s, &re("READY"), spec(None, 5000)).await;
        assert_eq!(
            out.end,
            WaitEnd::Matched,
            "the wait answered over a buffer the reader had not finished \
             filling: the bytes were in the pty, not lost"
        );
    }

    /// **The same claim again, for the *other* of the two windows**
    /// (GH #149).
    ///
    /// The row above widens the gap in which a child's output can arrive
    /// and still be *read*: `set_read_delay` stalls the reader *before* it
    /// drains, which is GH #42's window and was closed in the waiter. This
    /// one pins the gap between a read that already drained nothing and
    /// the separate `is_alive()` that judges it — two lock acquisitions on
    /// the backend. A child that queued its last line and exited in *that*
    /// gap had the line abandoned by the reader, which then published
    /// `reader_finished` all the same. This wait therefore did everything
    /// right — saw the death, honoured the `reader_finished()` guard,
    /// rescanned — over a buffer that was final and empty, and answered
    /// `SessionDied`. Same signature as GH #42's (`left: SessionDied,
    /// right: Matched`), a different window, and the fix is in the reader
    /// rather than here.
    ///
    /// **`on_empty_read` is the pin; `set_read_delay` is only a margin.**
    /// The hook fires inside the gap, so the interleaving is an ordering
    /// guarantee rather than a race a writer thread has to win. The 150 ms
    /// stall is there for an unrelated reason: `since_cursor: None`
    /// resolves to `buffer.head` *at subscription time*, so bytes that
    /// reached the buffer before this wait subscribed would be correctly
    /// unmatched and the row would go red for something that is not the
    /// defect. `for_pattern` subscribes synchronously, ahead of its first
    /// `await`, so the stall puts five orders of magnitude between the
    /// subscription and the hook.
    ///
    /// **It is not a tunable margin, and the number is here so nobody
    /// tidies it away.** Measured against the *correct* reader with the
    /// `set_read_delay` line deleted and nothing else changed: red **5
    /// times in 20**, with `left: SessionDied, right: Matched` — the real
    /// defect's signature exactly. A reader who trimmed it would get a
    /// row that is 25% flaky and reads like #149 reopening.
    #[tokio::test]
    async fn output_queued_in_the_read_liveness_gap_still_matches() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (s, pty) = mock();
        pty.set_read_delay(Duration::from_millis(150));

        let fired = Arc::new(AtomicBool::new(false));
        let weak_pty = Arc::downgrade(&pty);
        let latch = Arc::clone(&fired);
        pty.on_empty_read(move || {
            // Once: the hook runs on every empty read, and a second firing
            // would re-queue the bytes whose collection is under test.
            if latch.swap(true, Ordering::SeqCst) {
                return;
            }
            let Some(pty) = weak_pty.upgrade() else {
                return;
            };
            pty.queue_output(b"READY\n");
            pty.exit(0);
        });

        // Comfortably longer than two stalls, so a failure here is the
        // wrong answer and never an impatient deadline. The CI failure
        // this row is written against took 0.447 s against 5000 ms.
        let out = for_pattern(&s, &re("READY"), spec(None, 5000)).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "the read/liveness gap was never entered, so this row proved nothing"
        );
        assert_eq!(
            out.end,
            WaitEnd::Matched,
            "the reader abandoned the child's last line in the gap between its \
             zero-read and its liveness check, then called the buffer final"
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
            rebuilt.window.start, 0,
            "the scan start is still buffered, so recovery begins there — \
             not at the frame boundary the receiver resumed at"
        );
        assert_eq!(rebuilt.scan_cursor, 11);
        assert_eq!(
            rebuilt.window.search(&re(r"LAGx+GED")),
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
        assert_eq!(rebuilt.window.start, 4);
        assert_eq!(rebuilt.window.raw, b"xxxGED\n");
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
        assert_eq!(rebuilt.window.start, 8, "clamped up to the live tail");
        assert_eq!(rebuilt.window.raw, b"89abcdef");
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

    /// GH #238's reproduction, byte for byte: cargo colours the verdict, so
    /// the text an agent reads as `test result: ok` is written as
    /// `test result: \x1b[32mok\x1b[m`. A pattern copied from the text
    /// never matched the bytes, and the wait timed out after its whole
    /// deadline on a run that had succeeded.
    ///
    /// The offsets are the contract half: `match.offset` is a **raw** byte
    /// offset (§5.2), so the span starts at the `t` and ends just past the
    /// `k`, with the colour escape between them inside it and the reset
    /// after it outside.
    #[tokio::test]
    async fn a_pattern_written_from_the_text_matches_coloured_output() {
        let (s, pty) = mock();
        let out = b"running 3 tests\r\ntest result: \x1b[32mok\x1b[m. 3 passed\r\n";
        pty.queue_output(out);
        while s.buffer_head() < out.len() as u64 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let o = for_pattern(&s, &re("test result: ok"), spec(Some(0), 2000)).await;
        assert_eq!(
            o.end,
            WaitEnd::Matched,
            "the escape inside the verdict hid it"
        );
        let start = out.windows(11).position(|w| w == b"test result").unwrap() as u64;
        let k = out.windows(2).position(|w| w == b"ok").unwrap() as u64 + 1;
        assert_eq!(o.found, Some(MatchSpan { start, end: k + 1 }));
    }

    /// The same, arriving live and split mid-escape across two frames —
    /// the stripper is resumable, so the second frame's `2mok` is not
    /// taken for text.
    #[tokio::test]
    async fn a_coloured_match_split_inside_its_escape_across_frames_is_found() {
        let (s, pty) = mock();
        let writer = Arc::clone(&pty);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            writer.queue_output(b"error\x1b[0m: could not compile\r\ntest result: \x1b[3");
            std::thread::sleep(Duration::from_millis(60));
            writer.queue_output(b"2mok\x1b[m.\r\n");
        });
        let o = for_pattern(&s, &re("test result: ok\\."), spec(None, 5000)).await;
        assert_eq!(o.end, WaitEnd::Matched);
        let found = o.found.expect("a match");
        assert_eq!(
            s.buffer_slice(found.start, found.end),
            b"test result: \x1b[32mok\x1b[m.".to_vec(),
            "the span is the raw bytes the text match came from"
        );
    }

    /// The other view keeps working: a pattern that spells an escape was a
    /// thing callers were told they could write ("raw output bytes"), and
    /// it matches nothing in the text view.
    #[tokio::test]
    async fn a_pattern_that_spells_an_escape_still_matches_the_raw_bytes() {
        let (s, pty) = mock();
        let out = b"test result: \x1b[32mok\x1b[m.\r\n";
        pty.queue_output(out);
        while s.buffer_head() < out.len() as u64 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let o = for_pattern(&s, &re(r"\x1b\[32mok"), spec(Some(0), 2000)).await;
        assert_eq!(o.end, WaitEnd::Matched);
        assert_eq!(o.found, Some(MatchSpan { start: 13, end: 20 }));
    }

    /// The tie-break and the ordering rule, over the window directly: the
    /// earlier match wins **by raw offset** whichever view found it, and a
    /// tie goes to the raw view, whose span is exact.
    #[test]
    fn the_earlier_match_wins_by_raw_offset_whichever_view_found_it() {
        // `ok` appears first coloured (text view only sees it whole) and
        // later plain (both views).
        let w = Window::new(100, b"a \x1b[1mo\x1b[0mk b ok");
        assert_eq!(
            w.search(&re("ok")),
            Some(MatchSpan {
                start: 106,
                end: 112
            }),
            "the coloured `ok` is earlier and the raw view cannot see it"
        );
        // Plain text: both views find the same `ok` and agree exactly.
        let w = Window::new(100, b"say ok");
        assert_eq!(
            w.search(&re("ok")),
            Some(MatchSpan {
                start: 104,
                end: 106
            })
        );
        // An escape before and after the match is not part of it.
        let w = Window::new(0, b"\x1b[32mok\x1b[m");
        assert_eq!(w.search(&re("o.")), Some(MatchSpan { start: 5, end: 7 }));
        // An empty match at the very end maps to the window's end rather
        // than past its offset table.
        // A tie at the same start goes to the raw view: here the raw match
        // runs through the reset escape and the text match stops at `k`.
        let w = Window::new(0, b"ok\x1b[m tail");
        assert_eq!(
            w.search(&re(r"ok\S*")),
            Some(MatchSpan { start: 0, end: 5 })
        );
        let w = Window::new(10, b"ab\x1b[m");
        assert_eq!(w.search(&re("$")), Some(MatchSpan { start: 15, end: 15 }));
    }

    /// Trimming drops the text that came from the trimmed bytes and no
    /// more, so a text match never reports an offset below the window.
    #[test]
    fn trimming_keeps_the_two_views_aligned() {
        let mut w = Window::new(0, &[]);
        let mut cursor = 0;
        let mut body = vec![b'x'; SCAN_WINDOW_BYTES];
        body.extend_from_slice(b"\x1b[31mRED\x1b[0m");
        let frame = OutputFrame {
            start: 0,
            end: body.len() as u64,
            bytes: Arc::from(&body[..]),
        };
        assert!(w.feed(&mut cursor, &frame));
        assert_eq!(w.raw.len(), SCAN_WINDOW_BYTES);
        assert_eq!(w.raw_offset(0), w.start, "the first text byte left behind");
        assert_eq!(w.runs.first().map(|r| r.0), Some(0));
        let found = w.search(&re("RED")).expect("found");
        assert_eq!(found.start, SCAN_WINDOW_BYTES as u64 + 5);
    }

    /// The run map's one invariant, checked exhaustively rather than at
    /// the two offsets the rows above happen to look at: every text byte
    /// maps back to the raw byte it came from, across frames that split
    /// escapes and across trims that cut through runs, escapes and the
    /// boundary between them.
    #[test]
    fn every_text_byte_maps_back_to_the_raw_byte_it_came_from() {
        // A deterministic mixture: plain text, SGR, OSC 133 with both
        // terminators, a charset designator, and bare text between them.
        let pieces: [&[u8]; 7] = [
            b"plain text ",
            b"\x1b[1;32m",
            b"GREEN",
            b"\x1b]133;D;0;holdfast=1\x07",
            b"\x1b]0;title\x1b\\",
            b"\x1b(B",
            b"tail\r\n",
        ];
        let mut stream = Vec::new();
        let mut i = 0usize;
        while stream.len() < SCAN_WINDOW_BYTES * 2 + 4096 {
            stream.extend_from_slice(pieces[i % pieces.len()]);
            i = i.wrapping_mul(31).wrapping_add(7);
        }
        let mut w = Window::new(0, &[]);
        let mut cursor = 0u64;
        // Frames of an awkward size, so escapes straddle them. The whole
        // map is checked every eighth frame and after the last — every
        // frame is quadratic and costs seconds in a debug build.
        let chunks: Vec<&[u8]> = stream.chunks(997).collect();
        for (n, chunk) in chunks.iter().enumerate() {
            let frame = OutputFrame {
                start: cursor,
                end: cursor + chunk.len() as u64,
                bytes: Arc::from(*chunk),
            };
            assert!(w.feed(&mut cursor, &frame));
            if n % 8 != 0 && n + 1 != chunks.len() {
                continue;
            }
            for (k, &t) in w.text.iter().enumerate() {
                let raw = w.raw_offset(k);
                assert!(raw >= w.start && raw < w.end(), "text {k} maps outside");
                assert_eq!(
                    stream[raw as usize], t,
                    "text byte {k} maps to raw {raw}, which holds another byte"
                );
            }
        }
        assert!(w.start > 0, "the fixture must have trimmed");
    }

    /// GH #248: a mode already showing at the wait's first sample may be
    /// the one from **before** the write the wait follows. Once the child
    /// has answered the write, the settle window is enough.
    #[test]
    fn a_carried_mode_the_child_has_answered_since_is_answered_once_it_has_held() {
        use crate::detect::InteractionMode::*;
        let (hold, silent) = (Duration::from_millis(250), Duration::from_secs(2));
        let t0 = Instant::now();
        let mut c = CarriedMode::new();
        assert!(
            !c.answerable(Fullscreen, t0, true, hold, silent),
            "the first sample"
        );
        assert!(!c.answerable(
            Fullscreen,
            t0 + Duration::from_millis(200),
            true,
            hold,
            silent
        ));
        assert!(
            c.answerable(Fullscreen, t0 + hold, true, hold, silent),
            "a mode that held for the window after the child answered is the answer"
        );
    }

    /// The review's case: **nothing has come back since the write**, so the
    /// mode is the pre-write one however long it has held — `less` still
    /// starting when its `q` went in, answered from at 260 ms 7 times in
    /// 42 when the settle window was the only hold. Only the longer hold
    /// makes it the answer, and output arriving makes it the answer at once
    /// if the settle window has already passed.
    #[test]
    fn a_carried_mode_nothing_has_answered_since_the_write_waits_the_longer_hold() {
        use crate::detect::InteractionMode::*;
        let (hold, silent) = (Duration::from_millis(250), Duration::from_secs(2));
        let t0 = Instant::now();
        let mut c = CarriedMode::new();
        assert!(!c.answerable(Fullscreen, t0, false, hold, silent));
        assert!(
            !c.answerable(Fullscreen, t0 + Duration::from_secs(1), false, hold, silent),
            "held past the settle window with nothing back since the write: \
             this is the sample from before the key"
        );
        assert!(
            c.answerable(Fullscreen, t0 + silent, false, hold, silent),
            "a key that makes the program print nothing is answered, eventually"
        );

        let mut c = CarriedMode::new();
        assert!(!c.answerable(AwaitingSecret, t0, false, hold, silent));
        assert!(!c.answerable(AwaitingSecret, t0 + hold, false, hold, silent));
        assert!(
            c.answerable(
                AwaitingSecret,
                t0 + Duration::from_millis(600),
                true,
                hold,
                silent
            ),
            "the child answered the write and the settle window has passed"
        );
    }

    /// The other half: a mode the wait watched arrive is fresh by
    /// construction and answers at once — including the first mode coming
    /// back after something else was seen, and whatever `reacted` says.
    #[test]
    fn a_mode_the_wait_watched_arrive_is_answered_at_once() {
        use crate::detect::InteractionMode::*;
        let (hold, silent) = (Duration::from_millis(250), Duration::from_secs(2));
        let t0 = Instant::now();
        let mut c = CarriedMode::new();
        assert!(!c.answerable(AwaitingSecret, t0, false, hold, silent));
        c.answerable(
            Executing,
            t0 + Duration::from_millis(1),
            false,
            hold,
            silent,
        );
        assert!(c.answerable(
            AwaitingSecret,
            t0 + Duration::from_millis(2),
            false,
            hold,
            silent
        ));

        let mut c = CarriedMode::new();
        c.answerable(AtPrompt, t0, false, hold, silent);
        assert!(c.answerable(
            Fullscreen,
            t0 + Duration::from_millis(1),
            false,
            hold,
            silent
        ));
    }
}
