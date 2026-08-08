//! A single PTY-backed session.

pub mod registry;
pub use registry::SessionRegistry;

use crate::buffer::{BufferRead, OutputBuffer};
use crate::pty::{PtyBackend, Signal};
use crate::{ClaspError, Result};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
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

pub struct Session {
    pub id: SessionId,
    pub name: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    backend: Arc<dyn PtyBackend>,
    buffer: Arc<Mutex<OutputBuffer>>,
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
        buffer_capacity: usize,
    ) -> Arc<Self> {
        let buffer = Arc::new(Mutex::new(OutputBuffer::new(buffer_capacity)));
        let last_activity_ms = Arc::new(AtomicI64::new(now_ms()));

        let session = Arc::new(Self {
            id,
            name,
            command,
            args,
            backend: Arc::clone(&backend),
            buffer: Arc::clone(&buffer),
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
                let Some(buffer) = weak_buffer.upgrade() else {
                    break;
                };
                buffer.lock().push(&buf[..n]);
                drop(buffer);
                activity.store(now_ms(), Ordering::Relaxed);
            }
        });

        session
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
            4096,
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
        assert!(matches!(s.write_input(b"more\n"), Err(ClaspError::SessionDied)));
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
        s.signal(Signal::Terminate).expect("terminate must stay idempotent");
    }
}
