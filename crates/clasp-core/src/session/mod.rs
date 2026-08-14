//! A single PTY-backed session.

pub mod registry;
pub use registry::SessionRegistry;

use crate::buffer::{BufferRead, OutputBuffer};
use crate::detect::history::{CommandEntry, CommandHistory, DEFAULT_MAX_ENTRIES};
use crate::detect::{Detection, DetectionConfig, Osc133Source, PromptDetector, Shell};
use crate::pty::{PtyBackend, Signal};
use crate::{ClaspError, Result};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub type SessionId = String;

/// How long the reader waits before retrying a backend that reported no
/// bytes but is still alive. Only reached by non-blocking backends; a
/// real PTY blocks in `read`, so this never costs anything in production.
const READER_IDLE_POLL: Duration = Duration::from_millis(5);

pub fn new_session_id() -> SessionId {
    let u = uuid::Uuid::new_v4().simple().to_string();
    format!("sess_{}", &u[..12])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Starting,
    Running,
    Exited(i32),
    Dead(String),
}

impl SessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Exited(_) => "Exited",
            Self::Dead(_) => "Dead",
        }
    }
}

/// Everything a session needs beyond its backend. Introduced in 0.0.2:
/// `Session::new` already took six positional arguments and detection adds
/// three more, so the tail became a struct rather than a longer list.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub buffer_capacity: usize,
    pub detection: DetectionConfig,
    pub history_max_entries: usize,
    /// When set, CLASP types the shell's OSC 133 integration snippet into
    /// the session at start-up (spec §8.5).
    pub shell_integration: Option<Shell>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: registry::DEFAULT_BUFFER_BYTES,
            detection: DetectionConfig::default(),
            history_max_entries: DEFAULT_MAX_ENTRIES,
            shell_integration: None,
        }
    }
}

impl SessionConfig {
    /// A config with a non-default buffer size and everything else stock.
    pub fn with_buffer_capacity(buffer_capacity: usize) -> Self {
        Self {
            buffer_capacity,
            ..Self::default()
        }
    }
}

pub struct Session {
    pub id: SessionId,
    pub name: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    backend: Arc<dyn PtyBackend>,
    buffer: Arc<Mutex<OutputBuffer>>,
    detector: Arc<Mutex<PromptDetector>>,
    history: Arc<Mutex<CommandHistory>>,
    /// Which shell integration was injected, if any.
    pub shell_integration: Option<Shell>,
    state: Mutex<SessionState>,
    last_activity_ms: Arc<AtomicI64>,
    pub created_at: std::time::SystemTime,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Session {
    /// Wrap a spawned backend and start the reader thread draining it
    /// into the buffer.
    pub fn new(
        id: SessionId,
        name: Option<String>,
        command: String,
        args: Vec<String>,
        backend: Arc<dyn PtyBackend>,
        config: SessionConfig,
    ) -> Arc<Self> {
        let buffer = Arc::new(Mutex::new(OutputBuffer::new(config.buffer_capacity)));
        let detector = Arc::new(Mutex::new(PromptDetector::new(config.detection)));
        let history = Arc::new(Mutex::new(CommandHistory::new(config.history_max_entries)));
        let last_activity_ms = Arc::new(AtomicI64::new(now_ms()));

        let session = Arc::new(Self {
            id,
            name,
            command,
            args,
            backend: Arc::clone(&backend),
            buffer: Arc::clone(&buffer),
            detector: Arc::clone(&detector),
            history: Arc::clone(&history),
            shell_integration: config.shell_integration,
            state: Mutex::new(SessionState::Running),
            last_activity_ms: Arc::clone(&last_activity_ms),
            created_at: std::time::SystemTime::now(),
        });

        // Blocking PTY reads live on a dedicated thread so they never
        // occupy a tokio worker.
        //
        // The thread deliberately captures a `Weak` to the buffer rather
        // than an `Arc<Session>`: a strong reference would be a cycle,
        // since the thread's exit condition belongs to the session it
        // would be keeping alive.
        let weak_buffer = Arc::downgrade(&buffer);
        let weak_detector = Arc::downgrade(&detector);
        let weak_history = Arc::downgrade(&history);
        let activity = Arc::clone(&last_activity_ms);
        let reader_backend = Arc::clone(&backend);
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            // A read error ends the output stream, so `while let Ok` is
            // the whole loop condition. (`loop` + an inner `match` that
            // breaks on `Err` trips clippy::while_let_loop.)
            while let Ok(n) = reader_backend.read(&mut buf) {
                if n == 0 {
                    // EOF for a blocking backend, "nothing yet" for a
                    // non-blocking one. Liveness decides, not the count.
                    if !reader_backend.is_alive() {
                        break;
                    }
                    // The session was dropped while we idled.
                    if weak_buffer.strong_count() == 0 {
                        break;
                    }
                    std::thread::sleep(READER_IDLE_POLL);
                    continue;
                }
                // Upgrade only around the push, so the thread never holds
                // a strong reference across a sleep or a blocking read —
                // that would defeat the `strong_count` check above.
                let (Some(buffer), Some(detector), Some(history)) = (
                    weak_buffer.upgrade(),
                    weak_detector.upgrade(),
                    weak_history.upgrade(),
                ) else {
                    break;
                };
                // The detector needs the offset the chunk landed at, so
                // OSC 133 spans line up with agent-visible cursors. Read
                // the head and append under one lock; nothing else writes
                // to this buffer, so the pair cannot interleave.
                let base = {
                    let mut b = buffer.lock();
                    let base = b.head();
                    b.push(&buf[..n]);
                    base
                };
                drop(buffer);

                // Detection runs outside the buffer lock: §4.3's invariant
                // is that no lock is held across work that can block, and
                // each of these has its own short critical section.
                //
                // The owner sample belongs with the scan, not with the
                // classification (§8.3): a shell's `D`/`A` markers arrive
                // in the same write in which it regains the terminal, so
                // recording the owner only at classification would
                // discard the markers that had just re-armed the licence,
                // at every prompt.
                let mut detector_guard = detector.lock();
                let foreground = reader_backend.foreground_group();
                let events = detector_guard.feed(&buf[..n], base, foreground);
                drop(detector_guard);
                if !events.is_empty() {
                    let at = now_ms();
                    let mut h = history.lock();
                    for ev in &events {
                        h.apply(ev, at);
                    }
                }
                drop(detector);
                drop(history);
                activity.store(now_ms(), Ordering::Relaxed);
            }
        });

        // Typed, not exported: rc files run after the environment is read
        // and would clobber an inherited PS1 (§8.5). A write failure here
        // is not fatal — the session simply degrades to tier 2.
        if let Some(shell) = config.shell_integration {
            let mut line = shell.integration_snippet().as_bytes().to_vec();
            line.push(b'\n');
            let _ = backend.write(&line);
        }

        session
    }

    /// The current classification (spec §8.3). One `tcgetattr` and a
    /// bounded scan of state the reader already maintains, so it is cheap
    /// enough to call on every tool response.
    ///
    /// **The `ECHO` sample is taken with the detector held**, and the order
    /// is the whole point rather than a style choice. §8.3's echo rung
    /// combines `echo == false` with the *current* bracketed-paste mode,
    /// and the two come from different places: the mode from bytes the
    /// reader has fed, the flag from `tcgetattr`. Sampled first and
    /// classified afterwards, the reader can feed the `\x1b[?2004l` that a
    /// submitted command emits *in between* — and the ladder then pairs a
    /// readline prompt's echo-off with that command's bracketed-paste-off
    /// and answers `AwaitingSecret` at 0.95, telling the agent (§8.4) to
    /// interrupt a human for a password no program asked for. The window is
    /// exactly one contended `detector.lock()`, and the reader holds that
    /// lock while it feeds, so the contention is the common case rather
    /// than an exotic one.
    ///
    /// Holding the detector across the sample removes the window instead of
    /// narrowing it: no chunk can be classified between the sample and the
    /// classification, so the value handed to the ladder is never older
    /// than the newest byte the ladder has seen. Nothing here can block —
    /// `is_alive` is a `WNOHANG` wait, `line_discipline` is one ioctl and
    /// `foreground_group` is one more — so §4.3's "no lock across blocking
    /// work" invariant is intact.
    ///
    /// The foreground sample is taken under the same lock and for the same
    /// reason (§8.3, REQ-PD-025): it decides whether the availability
    /// records the ladder is about to read still license anything, so a
    /// chunk classified between the sample and the answer would let the
    /// two describe different instants.
    pub fn detection(&self) -> Detection {
        let alive = self.backend.is_alive();
        let mut detector = self.detector.lock();
        let line = self.backend.line_discipline();
        let foreground = self.backend.foreground_group();
        detector.snapshot(alive, line, foreground)
    }

    /// Whose OSC 133 markers this session is **using** (§18.2a, §8.5.1).
    ///
    /// Not the same question as `shell_integration`, which records only
    /// what CLASP injected and is fixed at spawn: a session can report
    /// `shell_integration: Some(Fish)` with `Osc133Source::External`, the
    /// snippet installed and firing and every one of its markers dropped
    /// on arrival. `None` until the first marker arrives.
    pub fn osc133_source(&self) -> Option<Osc133Source> {
        self.detector.lock().osc133_source()
    }

    /// True once any OSC 133 marker has arrived, i.e. shell integration is
    /// actually working for this session.
    pub fn history_active(&self) -> bool {
        self.history.lock().is_active()
    }

    /// Commands recorded so far, including ones evicted from the ring.
    pub fn command_count(&self) -> u64 {
        self.history.lock().total()
    }

    pub fn history_truncated(&self) -> bool {
        self.history.lock().truncated_at_tail()
    }

    pub fn command_history(&self, since_index: u64, limit: usize) -> Vec<CommandEntry> {
        self.history.lock().entries(since_index, limit)
    }

    pub fn state(&self) -> SessionState {
        // Refresh from the backend so an exited child is observed even
        // if nothing has read since.
        if !self.backend.is_alive() {
            let code = self.backend.exit_code().unwrap_or(-1);
            let mut s = self.state.lock();
            if matches!(*s, SessionState::Starting | SessionState::Running) {
                *s = SessionState::Exited(code);
            }
            return s.clone();
        }
        self.state.lock().clone()
    }

    pub fn is_alive(&self) -> bool {
        self.backend.is_alive()
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.backend.exit_code()
    }

    pub fn pid(&self) -> Option<u32> {
        self.backend.pid()
    }

    pub fn last_activity_ms(&self) -> i64 {
        self.last_activity_ms.load(Ordering::Relaxed)
    }

    pub fn buffer_head(&self) -> u64 {
        self.buffer.lock().head()
    }

    pub fn buffer_tail(&self) -> u64 {
        self.buffer.lock().tail()
    }

    pub fn read_from(&self, since: u64, max_bytes: usize) -> BufferRead {
        self.buffer.lock().read_from(since, max_bytes)
    }

    pub fn read_tail_bytes(&self, n: usize) -> BufferRead {
        self.buffer.lock().read_tail_bytes(n)
    }

    pub fn read_tail_lines(&self, n: usize) -> BufferRead {
        self.buffer.lock().read_tail_lines(n)
    }

    pub fn write_input(&self, data: &[u8]) -> Result<usize> {
        // A real PTY fails a write to a dead child with EIO, but a
        // non-blocking test backend does not. Checking here means the
        // behaviour is the same on both.
        if !self.backend.is_alive() {
            return Err(ClaspError::SessionDied);
        }
        self.backend.write(data)?;
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
        Ok(data.len())
    }

    /// Signals are *not* liveness-guarded: terminating an
    /// already-exited session is a no-op, not an error, so `terminate`
    /// stays idempotent.
    pub fn signal(&self, sig: Signal) -> Result<()> {
        self.backend.signal(sig)?;
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{DetectionTier, InteractionMode, PatternSet, PromptPattern};
    use crate::pty::MockPty;
    use std::time::Instant;

    fn mock_session() -> (Arc<Session>, Arc<MockPty>) {
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

    /// Poll until the session's buffer holds at least `n` bytes.
    fn wait_for_bytes(s: &Session, n: u64) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while s.buffer_head() < n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            s.buffer_head() >= n,
            "reader never accumulated {n} bytes (head = {})",
            s.buffer_head()
        );
    }

    /// Poll until `pred` holds.
    ///
    /// The reader appends to the buffer *before* it feeds the detector, so
    /// `wait_for_bytes` returning does not mean detection has caught up
    /// with those bytes. Measured, that window is lost roughly once in
    /// forty runs, not once in a million: the reader's 5 ms idle poll and
    /// this one drift into phase, so the sampling is correlated with the
    /// gap rather than independent of it. Anything derived from the
    /// detector or the history therefore has to wait on the detector's own
    /// state, not on the buffer's.
    fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !pred() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(pred(), "timed out waiting for {what}");
    }

    #[test]
    fn reader_accumulates_output_produced_after_start() {
        // The reader must survive an empty backend and keep draining.
        // If it broke on Ok(0) it would die before the first write.
        let (s, pty) = mock_session();
        std::thread::sleep(Duration::from_millis(20));

        pty.queue_output(b"first ");
        wait_for_bytes(&s, 6);
        pty.queue_output(b"second");
        wait_for_bytes(&s, 12);

        let read = s.read_from(0, 4096);
        assert_eq!(String::from_utf8_lossy(&read.bytes), "first second");
    }

    #[test]
    fn reader_advances_last_activity() {
        let (s, pty) = mock_session();
        let before = s.last_activity_ms();
        std::thread::sleep(Duration::from_millis(10));
        pty.queue_output(b"x");
        wait_for_bytes(&s, 1);

        // Strictly greater: `>=` holds even if the reader never touched
        // the stamp, so it would pass against the very bug this guards.
        // Poll rather than assert once -- the stamp is stored just AFTER
        // the push, so wait_for_bytes can return in between the two.
        let deadline = Instant::now() + Duration::from_secs(2);
        while s.last_activity_ms() <= before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            s.last_activity_ms() > before,
            "reader never advanced the activity stamp"
        );
    }

    #[test]
    fn write_after_exit_is_rejected() {
        let (s, pty) = mock_session();
        s.write_input(b"echo hi\n").expect("write while alive");
        pty.exit(0);
        assert!(matches!(
            s.write_input(b"more\n"),
            Err(ClaspError::SessionDied)
        ));
    }

    #[test]
    fn state_reports_exit_code_after_the_child_exits() {
        let (s, pty) = mock_session();
        assert_eq!(s.state(), SessionState::Running);
        pty.exit(7);
        assert_eq!(s.state(), SessionState::Exited(7));
        assert_eq!(s.state().as_str(), "Exited");
    }

    #[test]
    fn signal_after_exit_is_not_an_error() {
        let (s, pty) = mock_session();
        pty.exit(0);
        s.signal(Signal::Terminate)
            .expect("terminate must stay idempotent");
    }

    // ---- 0.0.2: detection wiring ----

    #[test]
    fn the_reader_feeds_the_detector() {
        let (s, pty) = mock_session();
        assert_eq!(
            s.detection().interaction_mode,
            InteractionMode::Executing,
            "no signal has arrived yet"
        );

        pty.queue_output(b"\x1b[?2004hbash-5.3$ ");
        wait_for_bytes(&s, 10);
        wait_until("the detector to consume the prompt", || {
            s.detection().interaction_mode == InteractionMode::AtPrompt
        });

        let d = s.detection();
        assert_eq!(d.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(d.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(d.last_line, "bash-5.3$ ");
    }

    #[test]
    fn detection_reads_echo_from_the_backend() {
        // A 60 s settle threshold pins the tier-3 combiner near zero for
        // the whole test. Without it the first assertion is a *race*, not
        // a fact: "Password: " scores 0.95 on the bundled pattern table
        // and this session has no deterministic signal, so once
        // quiescence passes 0.53 the heuristic answers `AtPrompt` and the
        // assertion flips. `wait_for_bytes` returns within ~5 ms of the
        // push, so it normally holds — but 132 ms of scheduler delay
        // between the two lines is all it takes to make this test flaky
        // on a loaded machine, and a flaky guard gets deleted.
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                detection: DetectionConfig {
                    settle_threshold_ms: 60_000,
                    ..DetectionConfig::default()
                },
                ..SessionConfig::with_buffer_capacity(4096)
            },
        );
        // A program that turned echo off with no bracketed paste in play.
        pty.queue_output(b"Password: ");
        wait_for_bytes(&s, 10);
        // Wait on the *detector*, not on the buffer. `Executing` is also
        // what a detector that has seen nothing answers, so asserting it
        // straight after the push can pass without those bytes ever having
        // been classified — the assertion would then be about an empty
        // detector rather than about echo. Waiting does not reintroduce
        // the race the 60 s threshold above guards: that threshold pins
        // *quiescence*, and consuming bytes does not move quiescence.
        wait_until("the detector to consume the prompt line", || {
            s.detection().last_line == "Password: "
        });
        assert_eq!(
            s.detection().interaction_mode,
            InteractionMode::Executing,
            "echo is still on, so this is just output that looks like a prompt"
        );

        // The echo branch sits above T3 in the ladder, so flipping ECHO
        // changes the answer regardless of quiescence. That is the point:
        // the mode has to come from the backend, not from the tail line.
        pty.set_echo(Some(false));
        assert_eq!(
            s.detection().interaction_mode,
            InteractionMode::AwaitingSecret
        );
    }

    #[test]
    fn command_history_spans_address_the_real_buffer() {
        let (s, pty) = mock_session();
        // Put something in the buffer FIRST, and let the reader drain it,
        // so the marker chunk lands at a non-zero offset. Without this the
        // test cannot tell a correct base offset from a hardcoded 0.
        pty.queue_output(b"login banner\r\n");
        wait_for_bytes(&s, 14);
        assert_eq!(s.buffer_head(), 14);

        pty.queue_output(b"\x1b]133;A\x07$ \x1b]133;B\x07echo hi\r\n\x1b]133;C\x07");
        pty.queue_output(b"hi\r\n\x1b]133;D;0\x07");
        wait_for_bytes(&s, 14 + 49);
        wait_until("the command to be recorded and closed", || {
            s.command_history(0, 10)
                .first()
                .is_some_and(|e| e.output_end_cursor.is_some())
        });

        assert!(s.history_active());
        assert_eq!(s.command_count(), 1);
        // The negative half of the truncation pair asserted in
        // `every_session_config_field_reaches_what_it_configures`: one
        // command into a ring of a thousand drops nothing, and a flag that
        // is always on tells the agent every history has holes.
        assert!(!s.history_truncated());
        let entries = s.command_history(0, 10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command, "echo hi");
        assert_eq!(entries[0].exit_code, Some(0));

        // The cursors must address the session's own buffer: reading the
        // recorded span has to return exactly that command's output. An
        // off-by-one in the offset bookkeeping fails here.
        let start = entries[0].output_start_cursor;
        let end = entries[0].output_end_cursor.expect("command finished");
        let read = s.read_from(start, (end - start) as usize);
        assert_eq!(String::from_utf8_lossy(&read.bytes), "hi\r\n");
    }

    #[test]
    fn history_is_empty_without_shell_integration() {
        let (s, pty) = mock_session();
        pty.queue_output(b"$ ls\r\nfile\r\n$ ");
        wait_for_bytes(&s, 14);
        assert!(!s.history_active());
        assert!(s.command_history(0, 10).is_empty());
    }

    #[test]
    fn the_integration_snippet_is_typed_at_start_up() {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                shell_integration: Some(Shell::Bash),
                ..SessionConfig::with_buffer_capacity(4096)
            },
        );
        assert_eq!(s.shell_integration, Some(Shell::Bash));

        let written = String::from_utf8_lossy(&pty.written()).into_owned();
        assert!(
            written.contains("133;A"),
            "no snippet was written: {written:?}"
        );
        assert!(written.ends_with('\n'), "the snippet was never submitted");
    }

    #[test]
    fn no_snippet_is_typed_when_integration_is_off() {
        let (_s, pty) = mock_session();
        assert!(pty.written().is_empty(), "wrote to a non-shell session");
    }

    #[test]
    fn the_reader_thread_exits_when_the_session_is_dropped() {
        // 0.0.1's `Weak` discipline, asserted mechanically. The reader now
        // captures three weak handles instead of one, and a strong
        // `Arc<Session>` — or any strong handle hoisted out of the loop and
        // held across the idle sleep — is a reference cycle: the thread's
        // exit condition belongs to the state it would be keeping alive.
        // Nothing else in the tree fails if that regresses; the leak is
        // silent and the process just accumulates threads.
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(4096),
        );
        pty.queue_output(b"some output\r\n");
        wait_for_bytes(&s, 13);
        // This test, the session's `backend` field, and the reader's own
        // handle. An extra clone here would mean a handle nobody releases.
        assert_eq!(Arc::strong_count(&pty), 3);

        drop(s);
        wait_until("the reader thread to release the backend", || {
            Arc::strong_count(&pty) == 1
        });
    }

    #[test]
    fn detection_reads_liveness_from_the_backend() {
        // The pair to `detection_reads_echo_from_the_backend`, for the
        // other argument `snapshot` takes. Without it, a `detection()`
        // that hardcodes `alive` reports a dead session as sitting at a
        // prompt and no test in the tree notices.
        let (s, pty) = mock_session();
        pty.queue_output(b"\x1b[?2004hbash-5.3$ ");
        wait_for_bytes(&s, 10);
        // The same bytes classify as a live prompt while the child is
        // running, so `Exited` below cannot have come from the byte
        // stream — only from liveness being sampled off the backend.
        //
        // `wait_until`, not a bare assertion: the reader pushes to the
        // buffer *before* it feeds the detector, so `wait_for_bytes`
        // returning does not mean these bytes have been classified. This
        // test was written after that rule was established and never
        // re-examined against it, and it is the sole killer of the mutant
        // that hardcodes `alive` — the one that makes a dead session
        // report AtPrompt.
        wait_until("the detector to consume the prompt", || {
            s.detection().interaction_mode == InteractionMode::AtPrompt
        });

        pty.exit(0);
        let d = s.detection();
        assert_eq!(d.interaction_mode, InteractionMode::Exited);
        assert_eq!(d.confidence, 0.0);
        // The tier the session had reached is still reported, so this is
        // the exited classification of a detected session rather than one
        // that fell back to the heuristic.
        assert_eq!(d.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn history_entries_are_stamped_with_a_real_clock() {
        // The reader computes `now_ms()` and hands it to the history, and
        // nothing asserted that what arrives is a clock. Replacing it with
        // a constant `0` passed the entire workspace: `history.rs`'s own
        // duration assertion cannot see it, because its `replay` helper
        // supplies its own clock and so constrains `CommandHistory::apply`
        // rather than this plumbing.
        //
        // `started_at_unix_ms` is agent-visible on every history entry
        // (§5.2), so a frozen clock reports every command as having
        // started at the epoch.
        let (s, pty) = mock_session();
        let before = now_ms();
        pty.queue_output(b"\x1b]133;C\x07out\r\n\x1b]133;D;0\x07");
        wait_until("the command to be recorded", || s.command_count() == 1);

        let entry = s.command_history(0, 10).remove(0);
        let after = now_ms();
        assert!(
            entry.started_at_unix_ms >= before,
            "started_at_unix_ms is {} — not a clock (test began at {before})",
            entry.started_at_unix_ms
        );
        assert!(
            entry.started_at_unix_ms <= after,
            "started_at_unix_ms is {} — ahead of the clock (test ended at {after})",
            entry.started_at_unix_ms
        );
    }

    #[test]
    fn no_output_is_classified_between_the_echo_sample_and_the_answer() {
        // §8.3's echo rung reads two signals from two places — the
        // bracketed-paste mode from bytes the reader has fed, `ECHO` from
        // the backend — and is only sound if they describe the same
        // instant. `detection()` sampled `ECHO` *before* it took the
        // detector, so a chunk could be classified in between, and the one
        // chunk that matters is the `\x1b[?2004l` readline writes when a
        // command is submitted: paired with the echo-off readline had at
        // the prompt it just left, the ladder answers `AwaitingSecret` at
        // 0.95 and §8.4 tells the agent to interrupt a human for a
        // password. For `sleep 5`.
        //
        // The window is one contended `detector.lock()` — and the reader
        // holds that lock while it feeds, so contention is the ordinary
        // case, not an exotic one. This test does not wait for it: the
        // backend's `on_line_discipline_sample` hook makes the interleaving happen on
        // purpose, at the one instant it has to happen at.
        //
        // The chunk carries an OSC 133 `C` as well, for observability: the
        // reader applies it to the history strictly *after* `feed` returns,
        // so `command_count() == 1` is proof that the detector consumed
        // those bytes — which the buffer's own head is not, since the
        // reader pushes before it feeds.
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(4096),
        );
        // A readline prompt: bracketed paste on, and ECHO off because
        // readline echoes characters itself (§8.2).
        pty.set_echo(Some(false));
        pty.queue_output(b"\x1b[?2004hbash-5.3$ ");
        wait_until("the prompt to be classified", || {
            s.detection().interaction_mode == InteractionMode::AtPrompt
        });

        let weak = Arc::downgrade(&s);
        let queue = Arc::clone(&pty);
        pty.on_line_discipline_sample(move || {
            let Some(s) = weak.upgrade() else { return };
            if s.command_count() > 0 {
                return; // already delivered; this is a later sample
            }
            queue.queue_output(b"\x1b[?2004l\x1b]133;C\x07");
            // Give the reader every chance to classify it. Correctly
            // ordered it cannot: it is blocked on the detector this call
            // is running underneath, so this waits out the deadline and
            // that is the pass. Incorrectly ordered it takes milliseconds.
            let deadline = Instant::now() + Duration::from_secs(1);
            while s.command_count() == 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let d = s.detection();
        assert_ne!(
            d.interaction_mode,
            InteractionMode::AwaitingSecret,
            "the classifier was handed an ECHO reading older than the \
             terminal modes it was combined with: {d:?}"
        );
        // And the answer is the *right* one rather than merely not that
        // one: this sample was taken while the session was still at the
        // prompt, so it is the prompt's answer.
        assert_eq!(d.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(d.detection_tier, DetectionTier::TerminalMode);

        // The chunk is not discarded — it is only deferred. Once the
        // reader gets the detector, the session moves on to `Executing`
        // with a *fresh* echo sample, which is the answer §8.7 row 2
        // requires. Without this half the test would also pass against a
        // backend that dropped the bytes on the floor.
        pty.set_echo(Some(true));
        wait_until("the submitted command to be classified", || {
            s.detection().interaction_mode == InteractionMode::Executing
        });
        assert_eq!(s.command_count(), 1, "the chunk never reached the history");
    }

    #[test]
    fn the_reader_records_who_owned_each_availability_conferring_signal() {
        // §8.3 requires the foreground group to be sampled at **two**
        // points: at classification, and at the moment the scanner
        // observes an availability-conferring signal, to record that
        // signal's owner. This is the second one, and it is the half no
        // detector unit test can reach — those hand `feed_at` an owner
        // directly, so deleting the reader thread's sample leaves every
        // one of them green while the licence silently reverts to session
        // scope for every real session (REQ-PD-025).
        //
        // The reader is the only place that can take this sample, because
        // it is the only place that knows *when* the bytes arrived.
        // Sampling only at classification would break T1 outright: a
        // shell's `D`/`A` markers arrive in the same write in which it
        // regains the terminal.
        let pty = Arc::new(MockPty::new());
        pty.set_foreground_group(Some(100));
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(4096),
        );

        // bash drives bracketed paste at its prompt and turns it off to
        // run something, all while it still holds the terminal. The
        // trailing `working` is what the wait below keys on: `Executing`
        // is also what a detector that has seen *nothing* answers, so
        // waiting on the mode would return before these bytes were fed and
        // both assertions below would be about an empty detector.
        pty.queue_output(b"\x1b[?2004h\x1b[?2004lsleep 2\r\nworking");
        wait_until("the submitted command to be classified", || {
            s.detection().last_line == "working"
        });

        // The positive: owner and holder are the same group, so the T2
        // executing rung is licensed and answers deterministically. Half
        // of the pair — without it a reader that recorded a *wrong* owner,
        // or a rule that never licenses anything, would satisfy the
        // negative below.
        assert_eq!(
            s.detection().detection_tier,
            DetectionTier::TerminalMode,
            "the program that drove the paste still holds the terminal"
        );

        // The negative, and the whole point: an external command takes the
        // terminal. Nothing new is fed, so the only thing that can move
        // the answer is the owner the reader recorded earlier being
        // compared against the holder sampled now. A reader that passed
        // `None` records an unknown owner, unknown never withholds, and
        // this stays `TerminalMode` — the rev.-36 behaviour, restored in
        // silence.
        pty.set_foreground_group(Some(200));
        let d = s.detection();
        assert_eq!(
            d.detection_tier,
            DetectionTier::Heuristic,
            "bash's bracketed paste licenses nothing about the command it \
             launched: {d:?}"
        );
        // The mode is unchanged by the narrowing, which is why the tier is
        // the field asserted: an assertion on the mode alone cannot see
        // this direction at all.
        assert_eq!(d.interaction_mode, InteractionMode::Executing);
    }

    #[test]
    fn every_session_config_field_reaches_what_it_configures() {
        // `buffer_capacity` and `history_max_entries` are both `usize`, so
        // swapping them compiles silently — the hazard `SessionConfig`
        // introduces by turning positional arguments into named fields.
        // Each assertion below is chosen to fail if its field is defaulted
        // *or* transposed with the other one.
        let mut bytes = Vec::new();
        for i in 0..3u8 {
            bytes.extend_from_slice(b"\x1b]133;B\x07cmd");
            bytes.push(b'0' + i);
            bytes.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
        }
        // A tail that the bundled table scores 0.0 on, so a session-supplied
        // pattern is the only thing that can produce a non-zero score.
        bytes.extend_from_slice(b"clasp~ ");

        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                // Smaller than the bytes below, and the stock 1 MiB is not.
                buffer_capacity: 64,
                history_max_entries: 2,
                detection: DetectionConfig {
                    patterns: PatternSet::build(
                        &[PromptPattern {
                            regex: r"clasp~\s*$".into(),
                            score: 0.9,
                        }],
                        false,
                    )
                    .unwrap(),
                    ..DetectionConfig::default()
                },
                shell_integration: None,
            },
        );
        pty.queue_output(&bytes);
        wait_for_bytes(&s, bytes.len() as u64);
        wait_until("all three commands to be folded into the history", || {
            s.command_count() == 3
        });

        assert!(
            s.buffer_tail() > 0,
            "buffer_capacity was ignored: {} bytes fit without eviction",
            bytes.len()
        );
        assert_eq!(s.command_count(), 3, "all three commands were recorded");
        let entries = s.command_history(0, 10);
        // Three commands into a ring of two: exactly two survive, and they
        // are the *newest* two. One surviving entry would mean the ring was
        // cleared rather than evicted; three would mean the cap was
        // defaulted or swapped for the buffer's.
        assert_eq!(entries.len(), 2, "history_max_entries was not honoured");
        assert_eq!(
            entries.iter().map(|e| e.index).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(s.history_truncated());
        assert!(
            (s.detection().pattern_score - 0.9).abs() < 1e-6,
            "the session's own pattern table was not used"
        );
    }
}
