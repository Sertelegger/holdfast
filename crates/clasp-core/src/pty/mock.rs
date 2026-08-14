//! Deterministic in-memory PTY for tests. Output is queued up front;
//! writes are recorded for assertions.

use super::{LineDiscipline, PtyBackend, Signal};
use crate::Result;
use parking_lot::Mutex;
use std::collections::VecDeque;

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
}

/// Something to run when `line_discipline` is sampled — see
/// `MockPty::on_line_discipline_sample`.
type LineDisciplineSampleHook = Box<dyn Fn() + Send + Sync>;

pub struct MockPty {
    state: Mutex<MockState>,
    /// Run on every `line_discipline` call, with `state` **not** held.
    on_line_discipline_sample: Mutex<Option<LineDisciplineSampleHook>>,
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
        }
    }

    /// Queue bytes that subsequent `read` calls will return.
    pub fn queue_output(&self, bytes: &[u8]) {
        self.state.lock().to_read.extend(bytes.iter().copied());
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
}

impl Default for MockPty {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyBackend for MockPty {
    fn write(&self, data: &[u8]) -> Result<()> {
        self.state.lock().written.extend_from_slice(data);
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut s = self.state.lock();
        let n = s.to_read.len().min(buf.len());
        for (i, b) in s.to_read.drain(..n).enumerate() {
            buf[i] = b;
        }
        Ok(n)
    }

    fn signal(&self, sig: Signal) -> Result<()> {
        let mut s = self.state.lock();
        s.signals.push(sig);
        if matches!(sig, Signal::Terminate | Signal::Kill) {
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
