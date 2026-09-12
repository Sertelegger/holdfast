//! Deterministic in-memory PTY for tests. Output is queued up front;
//! writes are recorded for assertions.

use super::{LineDiscipline, PtyBackend, Signal};
use crate::Result;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Debug, Default)]
struct MockState {
    to_read: VecDeque<u8>,
    written: Vec<u8>,
    signals: Vec<Signal>,
    alive: bool,
    exit_code: Option<i32>,
    size: (u16, u16),
    echo: Option<bool>,
    canonical: Option<bool>,
    foreground: Option<i32>,
    /// When set, SIGTERM is recorded and ignored; only SIGKILL kills.
    /// An interactive shell behaves this way (§4.4), and without a
    /// double that does, the reaper's SIGTERM-then-SIGKILL escalation is
    /// unobservable — a child that dies on the first signal proves
    /// nothing about the second.
    traps_terminate: bool,
    /// How long `read` stalls before draining, modelling a reader that
    /// the scheduler has not run yet. See [`MockPty::set_read_delay`].
    read_delay: Duration,
}

/// Something to run when `line_discipline` is sampled — see
/// `MockPty::on_line_discipline_sample`.
type LineDisciplineSampleHook = Box<dyn Fn() + Send + Sync>;

/// Something to run when `write` is called — see `MockPty::on_write`.
type WriteHook = Box<dyn Fn() + Send + Sync>;

/// Something to run when a `read` is about to return zero — see
/// `MockPty::on_empty_read`.
type EmptyReadHook = Box<dyn Fn() + Send + Sync>;

pub struct MockPty {
    state: Mutex<MockState>,
    /// Run on every `line_discipline` call, with `state` **not** held.
    on_line_discipline_sample: Mutex<Option<LineDisciplineSampleHook>>,
    /// Run on every `write` call, before the bytes are recorded and with
    /// `state` **not** held.
    on_write: Mutex<Option<WriteHook>>,
    /// Run after a `read` has drained nothing and before it returns 0,
    /// with `state` **not** held.
    on_empty_read: Mutex<Option<EmptyReadHook>>,
}

// Manual, because a boxed `Fn` is not `Debug`. Deliberately does not lock:
// a `Debug` impl that blocks is a debugging hazard, and this type is a
// test double whose interesting state is asserted through its own
// accessors rather than through formatting.
impl std::fmt::Debug for MockPty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockPty").finish_non_exhaustive()
    }
}

impl MockPty {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MockState {
                alive: true,
                size: (120, 40),
                // A real PTY starts with ECHO on; tests that care set it.
                echo: Some(true),
                // A real PTY starts canonical, and stays canonical for
                // every secret prompt in §8.7. A line editor is what
                // clears it.
                canonical: Some(true),
                // One program holds the terminal, and it does not change
                // unless a test says so. Any positive value will do; the
                // scoping rule only ever compares two of these.
                foreground: Some(1),
                ..Default::default()
            }),
            on_line_discipline_sample: Mutex::new(None),
            on_write: Mutex::new(None),
            on_empty_read: Mutex::new(None),
        }
    }

    /// A mock that ignores SIGTERM and dies only on SIGKILL, the way an
    /// interactive shell does (§4.4).
    pub fn ignoring_terminate() -> Self {
        let mock = Self::new();
        mock.state.lock().traps_terminate = true;
        mock
    }

    /// Queue bytes that subsequent `read` calls will return.
    pub fn queue_output(&self, bytes: &[u8]) {
        self.state.lock().to_read.extend(bytes.iter().copied());
    }

    /// Stall every subsequent `read` by `d` before it drains.
    ///
    /// **This models scheduling, not a slow device**, and it exists to
    /// make GH #42 deterministic. That defect is a race between a child's
    /// death and the reader thread's next `read`: the window is normally
    /// microseconds, so the row that covers it was green in 60 isolated
    /// and 8 whole-lib contended runs on a 2-core box while failing on a
    /// slower CI host. Widening the window turns "fails when the machine
    /// is unlucky" into "fails whenever the bug is present", which is the
    /// difference between a test and a coin.
    pub fn set_read_delay(&self, d: Duration) {
        self.state.lock().read_delay = d;
    }

    /// Everything written to the child so far.
    pub fn written(&self) -> Vec<u8> {
        self.state.lock().written.clone()
    }

    /// Signals delivered so far.
    pub fn signals(&self) -> Vec<Signal> {
        self.state.lock().signals.clone()
    }

    /// Mark the child exited with the given code.
    pub fn exit(&self, code: i32) {
        let mut s = self.state.lock();
        s.alive = false;
        s.exit_code = Some(code);
    }

    pub fn size(&self) -> (u16, u16) {
        self.state.lock().size
    }

    /// Set what `line_discipline` reports for `ECHO`. `None` models a
    /// backend that cannot sample the line discipline at all.
    pub fn set_echo(&self, echo: Option<bool>) {
        self.state.lock().echo = echo;
    }

    /// Set what `line_discipline` reports for `ICANON`. `None` models a
    /// backend that can read `ECHO` and not the canonical bit — a state no
    /// real platform in this tree produces, and the only way REQ-PD-021's
    /// degradation rule can be made to fail.
    pub fn set_canonical(&self, canonical: Option<bool>) {
        self.state.lock().canonical = canonical;
    }

    /// Set which process group `foreground_group` reports holds the
    /// terminal. `None` models a platform with no `tcgetpgrp` — ConPTY —
    /// or an ioctl that failed, which §8.3 treats as *unknown* and not as
    /// a change (REQ-PD-025).
    pub fn set_foreground_group(&self, g: Option<i32>) {
        self.state.lock().foreground = g;
    }

    /// Run `f` at the instant `line_discipline` is sampled.
    ///
    /// The one thing a caller of `detection()` cannot otherwise steer is
    /// *what else happens between the line-discipline sample and the
    /// classification that consumes it* — and that interval is where §8.3's
    /// echo rung can be handed a reading older than the terminal modes it
    /// is combined with. This hook turns that interleaving into something a
    /// test drives rather than races for.
    pub fn on_line_discipline_sample(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.on_line_discipline_sample.lock() = Some(Box::new(f));
    }

    /// Run `f` at the instant `write` is called, **before** the bytes are
    /// recorded and with `state` not held, so a hook may inspect or move
    /// the rest of the mock while it parks. (It does hold the hook slot
    /// itself, exactly as `on_line_discipline_sample` does, so a hook must
    /// not re-register one.)
    ///
    /// The sibling of [`on_line_discipline_sample`](Self::on_line_discipline_sample),
    /// and it exists for the same reason: the one interval a caller of the
    /// write queue cannot otherwise steer is *how long the writer thread
    /// spends inside the write*, and that interval is where a `SecretInput`
    /// sits on the FIFO with its acknowledgement outstanding. A hook that
    /// parks turns that into something a test drives rather than races
    /// for.
    ///
    /// It runs on the caller's thread — for the write queue, the session's
    /// own writer `std::thread` — so a hook that blocks blocks the writer
    /// and nothing else.
    pub fn on_write(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.on_write.lock() = Some(Box::new(f));
    }

    /// Run `f` at the instant a `read` has found the queue empty and is
    /// about to return `Ok(0)`, **after** the drain and with `state` not
    /// held — so a hook may `queue_output` and `exit` the mock from
    /// inside it.
    ///
    /// **This is the read/liveness gap, made into something a test drives
    /// rather than races for** (GH #149). The session reader's exit
    /// condition is a zero-byte `read` judged by a separate `is_alive`,
    /// and those are two lock acquisitions: bytes queued *between* them,
    /// by a child that then dies, are bytes the reader can abandon while
    /// still publishing `reader_finished` — the flag that means *the
    /// buffer is final*.
    ///
    /// [`set_read_delay`](Self::set_read_delay) is the nearest relative
    /// and deliberately not the tool for this. It stalls *before* the
    /// drain, which widens the window a child's output can arrive in and
    /// still be read — GH #42's window, one layer up. Widening the gap
    /// *after* the drain with a sleep would leave the interleaving to a
    /// writer thread that has to win a race against it, which is a coin
    /// dressed as a test. A hook that fires *inside* the gap is an
    /// ordering guarantee: the queue was empty when the read decided, and
    /// the bytes and the death are both in place before the reader gets
    /// to look at liveness. Every run, on every machine.
    ///
    /// It runs on the caller's thread — the session's reader `std::thread`
    /// — and on **every** empty read, so a hook that must act once has to
    /// latch that itself.
    ///
    /// **It holds the hook slot while it runs**, exactly as
    /// [`on_write`](Self::on_write) does, so a hook must not re-register
    /// one — and, less obviously, **must not call `read` on this mock**.
    /// `read` is the only path to this slot and `parking_lot::Mutex` is
    /// not reentrant, so a hook that tries to "drain the rest of it"
    /// deadlocks against itself. Note the asymmetry with
    /// [`on_line_discipline_sample`](Self::on_line_discipline_sample),
    /// which releases its slot before it touches `state`: an
    /// `on_empty_read` hook that calls `line_discipline` and a
    /// `line_discipline` hook that calls `read`, on two threads, are an
    /// A→B/B→A pair. Nothing in tree does either.
    pub fn on_empty_read(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.on_empty_read.lock() = Some(Box::new(f));
    }
}

impl Default for MockPty {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyBackend for MockPty {
    fn write(&self, data: &[u8]) -> Result<()> {
        // Before `state` is taken — a hook that parks here holds up its
        // own caller and leaves the rest of the mock readable, which is
        // the point.
        if let Some(hook) = self.on_write.lock().as_ref() {
            hook();
        }
        self.state.lock().written.extend_from_slice(data);
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // **Slept before the lock, never under it.** Holding `state`
        // across a sleep would block `queue_output` and `exit` too, which
        // would serialise the very interleaving this delay exists to
        // expose.
        let delay = self.state.lock().read_delay;
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let n = {
            let mut s = self.state.lock();
            let n = s.to_read.len().min(buf.len());
            for (i, b) in s.to_read.drain(..n).enumerate() {
                buf[i] = b;
            }
            n
        };
        // **After the drain and with `state` released**, because the
        // hook's whole purpose is to `queue_output` and `exit` a mock this
        // read has already decided is empty — both of which need `state`,
        // and `parking_lot::Mutex` is not reentrant. See
        // [`MockPty::on_empty_read`].
        if n == 0 {
            if let Some(hook) = self.on_empty_read.lock().as_ref() {
                hook();
            }
        }
        Ok(n)
    }

    fn signal(&self, sig: Signal) -> Result<()> {
        let mut s = self.state.lock();
        s.signals.push(sig);
        let fatal = match sig {
            Signal::Kill => true,
            Signal::Terminate => !s.traps_terminate,
            Signal::Interrupt => false,
        };
        if fatal {
            s.alive = false;
            s.exit_code.get_or_insert(0);
        }
        Ok(())
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.state.lock().size = (cols, rows);
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.state.lock().alive
    }

    fn line_discipline(&self) -> LineDiscipline {
        // Before `state` is taken, and while no lock of this backend's is
        // held: the hook exists to let output arrive mid-sample, and
        // `queue_output` needs `state`.
        if let Some(hook) = self.on_line_discipline_sample.lock().as_ref() {
            hook();
        }
        let s = self.state.lock();
        if !s.alive {
            // Both flags, so a dead mock matches a dead `InProcessPty`.
            return LineDiscipline::UNKNOWN;
        }
        LineDiscipline {
            echo: s.echo,
            canonical: s.canonical,
        }
    }

    fn foreground_group(&self) -> Option<i32> {
        let s = self.state.lock();
        // A reaped child leaves `tcgetpgrp` answering 0, which
        // `InProcessPty` reports as unknown. Matching that here keeps the
        // two backends telling the exited path the same story.
        if !s.alive {
            return None;
        }
        s.foreground
    }

    fn exit_code(&self) -> Option<i32> {
        self.state.lock().exit_code
    }

    fn pid(&self) -> Option<u32> {
        Some(4242)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_output_is_readable() {
        let p = MockPty::new();
        p.queue_output(b"hello");
        let mut buf = [0u8; 16];
        let n = p.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(p.read(&mut buf).unwrap(), 0, "drained");
    }

    #[test]
    fn writes_are_recorded() {
        let p = MockPty::new();
        p.write(b"ls\n").unwrap();
        assert_eq!(p.written(), b"ls\n");
    }

    /// The negative half of the hook's contract: a read that returned
    /// bytes is not the gap. Without this, a hook fired unconditionally
    /// would still satisfy the row below.
    #[test]
    fn the_empty_read_hook_does_not_run_on_a_read_that_drained_something() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let p = MockPty::new();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        p.on_empty_read(move || {
            seen.fetch_add(1, Ordering::SeqCst);
        });

        p.queue_output(b"hello");
        let mut buf = [0u8; 16];
        assert_eq!(p.read(&mut buf).unwrap(), 5);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(p.read(&mut buf).unwrap(), 0, "drained");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// The ordering that makes GH #149's row a window rather than a coin:
    /// the queue was *already* empty when the hook ran, so bytes the hook
    /// queues belong to the next read and never to this one — and the
    /// death it declares is in place before the caller can sample it.
    #[test]
    fn the_empty_read_hook_runs_after_the_drain_and_before_the_read_returns() {
        use std::sync::Arc;

        let p = Arc::new(MockPty::new());
        let weak = Arc::downgrade(&p);
        p.on_empty_read(move || {
            if let Some(p) = weak.upgrade() {
                p.queue_output(b"late");
                p.exit(0);
            }
        });

        let mut buf = [0u8; 16];
        assert_eq!(
            p.read(&mut buf).unwrap(),
            0,
            "the drain had already decided when the hook queued"
        );
        assert!(
            !p.is_alive(),
            "and the death is in place by the time the read returns"
        );
        let n = p.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late", "the bytes are still there to collect");
    }

    #[test]
    fn terminate_marks_not_alive() {
        let p = MockPty::new();
        assert!(p.is_alive());
        p.signal(Signal::Terminate).unwrap();
        assert!(!p.is_alive());
        assert_eq!(p.exit_code(), Some(0));
        assert_eq!(p.signals(), vec![Signal::Terminate]);
    }

    #[test]
    fn interrupt_does_not_kill() {
        let p = MockPty::new();
        p.signal(Signal::Interrupt).unwrap();
        assert!(p.is_alive());
        // An impl that sets exit_code while keeping alive=true would pass
        // the alive check above but fail here.
        assert_eq!(p.exit_code(), None);
    }

    #[test]
    fn kill_marks_not_alive() {
        let p = MockPty::new();
        assert!(p.is_alive());
        p.signal(Signal::Kill).unwrap();
        assert!(!p.is_alive());
        assert_eq!(p.exit_code(), Some(0));
        assert_eq!(p.signals(), vec![Signal::Kill]);
    }

    #[test]
    fn both_line_discipline_flags_are_settable_and_unreportable_once_the_child_is_gone() {
        let p = MockPty::new();
        assert_eq!(
            p.line_discipline(),
            LineDiscipline {
                echo: Some(true),
                canonical: Some(true)
            },
            "a fresh PTY echoes and is canonical"
        );
        p.set_echo(Some(false));
        assert_eq!(
            p.line_discipline(),
            LineDiscipline {
                echo: Some(false),
                canonical: Some(true)
            },
            "a secret prompt's shape: setting one flag must not move the other"
        );
        p.set_canonical(Some(false));
        assert_eq!(
            p.line_discipline(),
            LineDiscipline {
                echo: Some(false),
                canonical: Some(false)
            },
            "a line editor's shape"
        );
        // `None` is not `Some(false)`: "echo is off" and "this backend
        // cannot say" are different answers, and the detector treats them
        // differently (§8.2).
        p.set_echo(None);
        assert_eq!(
            p.line_discipline(),
            LineDiscipline {
                echo: None,
                canonical: Some(false)
            }
        );
        // The mixed state no real platform in this tree produces, and the
        // only shape that can falsify REQ-PD-021's degradation rule: `ECHO`
        // readable, `ICANON` not. A backend modelling the pair as one
        // `Option` cannot express it, which is why they are two fields.
        p.set_echo(Some(false));
        p.set_canonical(None);
        assert_eq!(
            p.line_discipline(),
            LineDiscipline {
                echo: Some(false),
                canonical: None
            }
        );
        // A dead child reports UNKNOWN even with both flags set, so an
        // impl that just returned the stored fields would fail here.
        p.set_echo(Some(true));
        p.set_canonical(Some(true));
        p.exit(0);
        assert_eq!(p.line_discipline(), LineDiscipline::UNKNOWN);
    }

    #[test]
    fn resize_is_recorded() {
        let p = MockPty::new();
        p.resize(80, 24).unwrap();
        assert_eq!(p.size(), (80, 24));
    }
}
