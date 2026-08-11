//! Deterministic in-memory PTY for tests. Output is queued up front;
//! writes are recorded for assertions.

use super::{PtyBackend, Signal};
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
}

#[derive(Debug)]
pub struct MockPty {
    state: Mutex<MockState>,
}

impl MockPty {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MockState {
                alive: true,
                size: (120, 40),
                // A real PTY starts with ECHO on; tests that care set it.
                echo: Some(true),
                ..Default::default()
            }),
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

    /// Set what `echo_enabled` reports. `None` models a backend that
    /// cannot sample the line discipline at all.
    pub fn set_echo(&self, echo: Option<bool>) {
        self.state.lock().echo = echo;
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

    fn echo_enabled(&self) -> Option<bool> {
        let s = self.state.lock();
        if !s.alive {
            return None;
        }
        s.echo
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
    fn echo_is_settable_and_unreportable_once_the_child_is_gone() {
        let p = MockPty::new();
        assert_eq!(p.echo_enabled(), Some(true), "a fresh PTY echoes");
        p.set_echo(Some(false));
        assert_eq!(p.echo_enabled(), Some(false));
        // `None` is not `Some(false)`: "echo is off" and "this backend
        // cannot say" are different answers, and the detector treats them
        // differently (§8.2).
        p.set_echo(None);
        assert_eq!(p.echo_enabled(), None);
        // A dead child reports `None` even with echo left on, so an impl
        // that just returned the stored field would fail here.
        p.set_echo(Some(true));
        p.exit(0);
        assert_eq!(p.echo_enabled(), None);
    }

    #[test]
    fn resize_is_recorded() {
        let p = MockPty::new();
        p.resize(80, 24).unwrap();
        assert_eq!(p.size(), (80, 24));
    }
}
