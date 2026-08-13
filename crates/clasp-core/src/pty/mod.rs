//! The PTY seam. `InProcessPty` is the only implementation in 0.0.1;
//! the trait exists so later milestones can vary the isolation model
//! without touching session logic.

pub mod in_process;
pub mod mock;

pub use in_process::InProcessPty;
pub use mock::MockPty;

use crate::Result;

/// Signals CLASP delivers to a session's process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Interrupt,
    Terminate,
    Kill,
}

/// How to spawn a session's child process.
#[derive(Debug, Clone)]
pub struct PtySpawnConfig {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
}

impl PtySpawnConfig {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            cols: 120,
            rows: 40,
        }
    }
}

/// A spawned PTY and its child process.
///
/// Implementations must be `Send + Sync`: the reader task, the writer
/// path, and tool calls all touch the same backend from different tasks.
pub trait PtyBackend: Send + Sync {
    /// Write bytes to the child's stdin.
    fn write(&self, data: &[u8]) -> Result<()>;

    /// Read available bytes. Returns `Ok(0)` at EOF. Blocking.
    fn read(&self, buf: &mut [u8]) -> Result<usize>;

    /// Deliver a signal to the child's **process group**, not just the
    /// leader, so descendants do not survive (spec §4.4).
    fn signal(&self, sig: Signal) -> Result<()>;

    /// Resize the terminal, triggering `SIGWINCH` in the child.
    fn resize(&self, cols: u16, rows: u16) -> Result<()>;

    /// Non-blocking liveness check.
    fn is_alive(&self) -> bool;

    /// Whether the slave's line discipline currently has `ECHO` set, read
    /// from the master with `tcgetattr` (spec §8.2). `None` when the
    /// backend cannot report it — the detector then treats the `ECHO`
    /// signal as unavailable rather than assuming a value.
    ///
    /// **The answer must describe the line discipline at the moment of the
    /// call.** An implementation may cache only if the cached value cannot
    /// outlive the state it describes, which in practice means it may not
    /// cache at all: §8.3 combines this reading with the *current*
    /// bracketed-paste mode, and a reading from even a few milliseconds ago
    /// pairs a readline prompt's echo-off with a submitted command's
    /// bracketed-paste-off — the signature of `AwaitingSecret` at 0.95, for
    /// a command that wants no input. §4.5 previously asked for a 50 ms
    /// cache here "per §4.1 `is_alive` policy"; that produced exactly this
    /// reading and is withdrawn. See `InProcessPty::sample_echo` for the
    /// measurement.
    ///
    /// Cheap, though: it is sampled on every prompt-bearing response. One
    /// `tcgetattr` (524 ns measured) is within budget; anything that blocks
    /// is not.
    ///
    /// Added in 0.0.2 *with a default*, so the seven methods 0.0.1
    /// settled on are unchanged and existing implementors still compile.
    fn echo_enabled(&self) -> Option<bool> {
        None
    }

    /// Exit code once the child has exited, else `None`.
    fn exit_code(&self) -> Option<i32>;

    /// The child's PID.
    fn pid(&self) -> Option<u32>;
}
