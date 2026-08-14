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

/// The slave's line-discipline flags, read from **one** `tcgetattr` on the
/// master (spec §8.2). The master reports the slave's `c_lflag`, which is
/// what §8.3's echo rung consults.
///
/// **Both fields are tri-state and independent.** `Some(true)`,
/// `Some(false)`, or `None` — a backend that cannot sample the line
/// discipline reports `None` rather than guessing a value, and §8.3
/// requires the two flags to degrade separately: the rung fires when
/// `echo` is *known* off and is suppressed only when `canonical` is
/// *known* off, so an unreadable `ICANON` reproduces the pre-rev.-36
/// answer exactly instead of taking a third path (REQ-PD-021).
///
/// No platform in this tree produces `echo: Some(_), canonical: None`.
/// It is representable anyway because REQ-PD-021's degradation rule is
/// only falsifiable if it is, and `MockPty` is what produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineDiscipline {
    /// `c_lflag & ECHO`. Off at every readline prompt — §8.7 finding 1 —
    /// so it means nothing alone and everything in combination.
    pub echo: Option<bool>,
    /// `c_lflag & ICANON`. A program wanting a secret *line* stays
    /// canonical because it wants the kernel to assemble the line; a line
    /// editor leaves canonical mode because it draws the characters
    /// itself (§8.2).
    pub canonical: Option<bool>,
}

impl LineDiscipline {
    /// What a backend that cannot sample the line discipline reports.
    pub const UNKNOWN: Self = Self {
        echo: None,
        canonical: None,
    };
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

    /// The slave's line-discipline flags, from **one** `tcgetattr` on the
    /// master (spec §8.2, §8.3). `LineDiscipline::UNKNOWN` when the
    /// backend cannot report them — the detector then treats the flags as
    /// unavailable rather than assuming values.
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
    /// reading, measured at 267 spurious samples under load, and is
    /// withdrawn (REQ-PD-019). See `InProcessPty::sample_line_discipline`.
    ///
    /// **One method, not two, and that is a correctness property rather
    /// than an ergonomic one.** `ECHO` and `ICANON` come out of the same
    /// `termios`. Two accessor methods mean two `tcgetattr`s that can
    /// straddle the child's own `tcsetattr`, so the pair the ladder sees
    /// would describe two different instants — reopening the freshness gap
    /// above by a narrower window, which is the same defect and not a
    /// smaller one.
    ///
    /// Cheap: one `tcgetattr` (524 ns measured) is within budget on every
    /// prompt-bearing response; anything that blocks is not.
    ///
    /// Added in 0.0.2 *with a default*, so the seven methods 0.0.1
    /// settled on are unchanged and existing implementors still compile.
    fn line_discipline(&self) -> LineDiscipline {
        LineDiscipline::UNKNOWN
    }

    /// The PTY's **foreground process group** — the terminal's own notion
    /// of which program holds it, and the same one the kernel uses for
    /// signal delivery and `SIGTTOU`/`SIGTTIN` (spec §8.3, §4.4).
    ///
    /// `None` is **unknown**, and unknown is not a change: the platform
    /// has no such call, the ioctl failed, or no valid group came back
    /// (measured: `tcgetpgrp` returns 0 once the child is reaped). §8.3
    /// withholds a licence only when the owner and the current holder are
    /// **both known and differ**, so unknown reproduces the pre-rev.-37
    /// session-scoped classification exactly rather than taking a third
    /// path — the same guardrail REQ-PD-021 applies to an unreadable
    /// `ICANON`, and what covers ConPTY (§3.6, §24: Windows has no
    /// `tcgetpgrp`).
    ///
    /// **This is not `interrupt`'s accessor and must not become it.**
    /// `InProcessPty::foreground_pgid` reads
    /// `process_group_leader().or(pgid())`, which is correct for signal
    /// targeting and wrong here: the fallback re-asserts session scope
    /// while looking like a known answer. One accessor cannot serve both
    /// (REQ-PD-025).
    ///
    /// Cheap: one `tcgetpgrp`. Sampled at classification **and** at the
    /// moment the scanner observes an availability-conferring signal —
    /// a handful of times per prompt cycle, not per chunk.
    fn foreground_group(&self) -> Option<i32> {
        None
    }

    /// Exit code once the child has exited, else `None`.
    fn exit_code(&self) -> Option<i32>;

    /// The child's PID.
    fn pid(&self) -> Option<u32>;
}
