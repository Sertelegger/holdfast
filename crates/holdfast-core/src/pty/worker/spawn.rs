//! The daemon's half of bringing a worker up: the argv, the three
//! standard streams, and the handshake (§3.1, §4.1, §7.3, milestone
//! 0.0.10a Task 3).
//!
//! # Why this file exists, when the plan's file table has no row for it
//!
//! Task 3's brief says it builds "the worker binary and the daemon-side
//! handshake". The plan's table puts the daemon side in `backend.rs`,
//! which is `SubprocessPty` and is **Task 4's** file — so writing it
//! there would mean Task 3 leaving Task 4 a half-built module to finish
//! around. This is the other half of the pair `socket.rs` already
//! started: that module binds and accepts, this one spawns and greets,
//! and `backend.rs` will compose the three into a `PtyBackend`.
//!
//! The name is `daemon::spawn`'s, deliberately. That module does the
//! exactly analogous job for the daemon process — build an argv over
//! `current_exe`, choose the child's three streams, and wait, bounded,
//! for it to answer — and the two should read as the same shape because
//! they are.
//!
//! # `hide`, in a binary with no clap
//!
//! The plan says "hidden from `--help` (clap's `hide = true`)". **There
//! is no clap in this workspace** — `crates/holdfast/src/main.rs` matches
//! on `std::env::args()` and prints a `USAGE` string literal — so
//! "hidden" here means the subcommand is dispatched but is absent from
//! that literal, and `holdfast pty-worker --help` answers anyway.
//! `the_worker_is_absent_from_help` asserts both halves.
//!
//! # The three standard streams, and the two single-character mistakes
//!
//! * **`stdin`: null.** The worker reads its instructions from the
//!   socket and nothing else.
//! * **`stdout`: null.** `holdfast mcp` already nulls its `daemon start`
//!   child's stdout for a related reason (§7.3) — there the stdout *was*
//!   the JSON-RPC transport. Here the reason is stronger: the worker
//!   holds raw PTY bytes, and its stdout goes wherever the daemon's went
//!   — a terminal, a log, or nothing.
//! * **`stderr`: a pipe this module drains into `daemon.log`, capped and
//!   rate-limited. Not inherited, and not null.** A panic message must
//!   be recoverable, which rules out null. An *inherited* stderr from a
//!   process holding raw PTY bytes is a new place unredacted output can
//!   leave the daemon, which REQ-SPTY-004 forbids — and it also bypasses
//!   [`crate::diag!`], so nothing would redact it. Draining it puts the
//!   worker's diagnostics behind the same boundary every other daemon
//!   diagnostic already sits behind.
//!
//!   Both mistakes are one character wide (`Stdio::inherit()` /
//!   `Stdio::null()`) and only one of them is caught by an assertion
//!   that the marker *arrives*. [`WORKER_LOG_PREFIX`] is what separates
//!   them: an inherited stderr delivers the worker's bytes verbatim, and
//!   a drained one delivers them behind a prefix this module wrote.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use super::frames::{encode_frame, read_frame, DaemonFrame, WorkerFrame, WORKER_PROTOCOL_TAG};
use crate::pty::PtySpawnConfig;
use crate::HoldfastError;

/// The hidden subcommand. One spelling, shared by the spawner and by
/// `main.rs`'s dispatch, so the two cannot drift.
pub const WORKER_SUBCOMMAND: &str = "pty-worker";

/// The worker's only flag.
///
/// **The socket path is on the argv and the spawn config is not**, and
/// the difference is not stylistic: `/proc/<pid>/cmdline` is
/// world-readable on Linux and `ps` shows an argv to every local user
/// everywhere, while `start_session.env` can carry credentials (§9.2
/// records only `env_keys` for exactly that reason). A path inside a
/// `0700` directory naming a `0600` socket is not a secret; an `env` map
/// is. See `child.rs`'s header and
/// `the_spawn_config_never_appears_on_the_workers_command_line`.
pub const WORKER_SOCKET_FLAG: &str = "--socket";

/// What every drained worker stderr line is prefixed with in `daemon.log`.
///
/// Load-bearing rather than cosmetic: it is the only thing that
/// distinguishes "the daemon drained the worker's stderr" from "the
/// daemon inherited it", because both put the same bytes on the same fd.
/// `{}` is filled with the worker's pid, so a `daemon.log` hosting many
/// sessions says which worker spoke.
pub const WORKER_LOG_PREFIX: &str = "holdfast pty-worker";

/// Bytes of one worker stderr line that reach `daemon.log` before the
/// rest is dropped.
///
/// A cap rather than a truncation of the *log*: a worker that dies
/// printing a megabyte-long line — a `{:?}` of something large, a
/// corrupted buffer — must not be able to write that megabyte into the
/// daemon's log through a pipe the daemon is obliged to drain. 2 KiB
/// holds a panic message with its location.
pub const WORKER_STDERR_LINE_CAP: usize = 2048;

/// Lines per [`WORKER_STDERR_WINDOW`] before the drain starts counting
/// instead of writing.
pub const WORKER_STDERR_BURST: usize = 64;

/// The rate-limit window.
///
/// A worker in a diagnostic loop is a worker whose stderr would
/// otherwise fill a disk the daemon shares with the audit log. When the
/// budget runs out the drain says so once, with a count, at the end of
/// the window — silence would be worse than the flood it prevents.
pub const WORKER_STDERR_WINDOW: Duration = Duration::from_secs(10);

/// How long the daemon waits for each frame of the handshake.
///
/// [`WORKER_ACCEPT_TIMEOUT`] again, and for the reason that constant
/// gives: one "something local should have answered by now" number an
/// operator can reason about, rather than three differing by a second
/// each. The whole handshake is a `connect`, four frames and one
/// `InProcessPty::spawn`.
///
/// [`WORKER_ACCEPT_TIMEOUT`]: super::socket::WORKER_ACCEPT_TIMEOUT
pub const WORKER_HANDSHAKE_TIMEOUT: Duration = super::socket::WORKER_ACCEPT_TIMEOUT;

/// A spawned `holdfast pty-worker`, and the thread draining its stderr.
///
/// Dropping this kills the worker. **That is a floor, not the orphan
/// policy** — Tasks 6 and 7 own what happens when each side dies without
/// the other — but a handle whose owner has gone is a session nobody can
/// reach, and this milestone's constraint 13 makes a leftover
/// `pty-worker` after a green suite a failed task rather than a stray
/// process.
#[derive(Debug)]
pub struct WorkerProcess {
    child: Child,
    pid: u32,
    reaped: bool,
}

impl WorkerProcess {
    /// The worker's pid — the value
    /// [`WorkerSocket::accept_worker`](super::socket::WorkerSocket::accept_worker)
    /// is told to expect, and the one `/proc/<pid>/cmdline` is read from.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Reap the worker if it has already exited.
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    /// Wait for the worker to exit. **Blocking**, and therefore not for
    /// the runtime: every caller either runs it under `spawn_blocking`
    /// or is a test that has already bounded it.
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }

    /// `SIGKILL`, then reap. Idempotent once the worker has been reaped.
    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
        Ok(())
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Spawn `<exe> pty-worker --socket <socket>`.
///
/// The socket must already be bound and listening — that ordering is
/// `socket.rs`'s rule and the whole reason the accept can be a bounded
/// wait instead of a readiness poll.
///
/// **The environment is inherited and nothing is added to it.** The
/// spawn config travels in [`DaemonFrame::Spawn`]; putting the session's
/// `env` on the worker's own environment would move the leak from
/// `/proc/<pid>/cmdline` to `/proc/<pid>/environ`, which is the same
/// mistake one directory along.
pub fn start_worker(exe: &Path, socket: &Path) -> std::io::Result<WorkerProcess> {
    let mut child = Command::new(exe)
        .arg(WORKER_SUBCOMMAND)
        .arg(WORKER_SOCKET_FLAG)
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let stderr = child
        .stderr
        .take()
        .expect("stderr was requested as a pipe just above");

    // A plain thread rather than `spawn_blocking`: this outlives any one
    // runtime task, it must survive a runtime shutting down while a
    // worker is still dying, and it ends by itself when the pipe reaches
    // EOF — which the kernel delivers when the worker exits, whatever
    // killed it. Detached for the same reason: nothing waits on it, and
    // the thing it would report is already in `daemon.log`.
    std::thread::spawn(move || drain_stderr(pid, stderr));

    Ok(WorkerProcess {
        child,
        pid,
        reaped: false,
    })
}

/// Read the worker's stderr to EOF, one line at a time, into `daemon.log`.
///
/// Byte-oriented (`read_until`) rather than `lines()`, because a worker
/// holding raw PTY bytes can put invalid UTF-8 on its stderr and
/// `BufRead::lines` yields an `Err` for it — which would end the drain at
/// the first such line and lose everything after, including the panic
/// that mattered.
fn drain_stderr(pid: u32, stderr: std::process::ChildStderr) {
    let mut reader = BufReader::new(stderr);
    let mut line = Vec::new();
    let mut window = Instant::now();
    let mut in_window = 0usize;
    let mut suppressed = 0usize;
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }

        if window.elapsed() >= WORKER_STDERR_WINDOW {
            if suppressed > 0 {
                crate::diag!(
                    "{WORKER_LOG_PREFIX}[{pid}]: suppressed {suppressed} further stderr line(s)"
                );
                suppressed = 0;
            }
            window = Instant::now();
            in_window = 0;
        }
        if in_window >= WORKER_STDERR_BURST {
            suppressed += 1;
            continue;
        }
        in_window += 1;

        // `from_utf8_lossy` on the *truncated* slice, so a cap landing
        // mid-sequence produces one U+FFFD rather than an error — PTY
        // bytes reach this pipe only through a diagnostic, but a
        // diagnostic that quotes one is exactly the case a cap has to
        // survive.
        let (head, dropped) = if line.len() > WORKER_STDERR_LINE_CAP {
            (
                &line[..WORKER_STDERR_LINE_CAP],
                line.len() - WORKER_STDERR_LINE_CAP,
            )
        } else {
            (&line[..], 0)
        };
        let text = String::from_utf8_lossy(head);
        // One `diag!` per line, so the redactor sees each line whole. It
        // is the same boundary `daemon.log` already has; the worker gets
        // no redactor of its own (REQ-SPTY-004).
        if dropped > 0 {
            crate::diag!("{WORKER_LOG_PREFIX}[{pid}]: {text} […{dropped} more bytes]");
        } else {
            crate::diag!("{WORKER_LOG_PREFIX}[{pid}]: {text}");
        }
    }
    if suppressed > 0 {
        crate::diag!("{WORKER_LOG_PREFIX}[{pid}]: suppressed {suppressed} further stderr line(s)");
    }
}

/// Why the daemon refused, or lost, the worker it had just spawned.
///
/// Every arm maps onto `HoldfastError::Pty` and therefore onto the
/// `spawn_failed` status `start_session` already produces for a PTY that
/// could not be opened. **0.0.10a adds no `Status` value**
/// (REQ-SPTY-001), and the reason each arm is *named* here rather than
/// collapsed into one string is that they call for opposite responses
/// from whoever reads `daemon.log`: a build mismatch is a stale binary on
/// disk, a silence is a worker that did not run, a `SpawnFailed` is a
/// command that does not exist.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The link failed at the codec or at the socket.
    #[error("worker link: {0}")]
    Link(String),
    /// The worker's [`WorkerFrame::Ready`] named a different build.
    ///
    /// **Refused, never negotiated.** §23.4: both peers are the same
    /// build of the same binary and one spawned the other, so there is no
    /// skew to survive — a mismatch means the operator has a stale binary
    /// somewhere, and the honest answer is a refusal with a named reason.
    /// Downgrading to a negotiated common subset is the shape that
    /// section rules out for this link.
    #[error("build mismatch: the worker is {theirs}, this daemon is {ours}")]
    BuildMismatch { ours: String, theirs: String },
    /// A frame arrived where the handshake expected another.
    #[error("expected {expected} but the worker sent {got}")]
    OutOfOrder {
        expected: &'static str,
        got: &'static str,
    },
    /// The worker answered, and could not create the child.
    ///
    /// `message` is the worker's, which is `InProcessPty::spawn`'s own —
    /// the same string the in-process backend would have produced for the
    /// same failure, which is what keeps the two backends' `spawn_failed`
    /// responses indistinguishable above the trait.
    #[error("the worker could not spawn the child: {0}")]
    SpawnRefused(String),
    /// The worker connected and then said nothing.
    #[error("the worker sent no {expected} within {timeout:?}")]
    TimedOut {
        expected: &'static str,
        timeout: Duration,
    },
}

/// **The one mapping**, for the reason `socket.rs`'s `AcceptError`
/// conversion gives: `Pty` is the variant `InProcessPty::spawn` returns
/// for every one of its failures, and `start_session` turns a backend
/// construction `Err` into `Status::SpawnFailed` without inspecting it.
/// Landing worker-side failures in the same variant is what lets the
/// backend seam stay invisible above the trait.
impl From<HandshakeError> for HoldfastError {
    fn from(e: HandshakeError) -> Self {
        HoldfastError::Pty(e.to_string())
    }
}

/// What the daemon learns from a completed handshake.
///
/// **`pgid` and `sid` are load-bearing and are not diagnostics.** The
/// fallback sweep — the one that runs when the worker dies without
/// retiring the child's groups — has nothing else to aim at, because the
/// worker holds the master fd and the daemon never did (Task 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerHandshake {
    pub child_pid: u32,
    pub pgid: Option<i32>,
    pub sid: Option<i32>,
}

/// `Ready` → `Hello` → `Spawn` → `Started`, each bounded.
///
/// The worker speaks first: it has just `connect(2)`ed and the daemon is
/// holding an accept deadline open, so its `Ready` is what ends the wait.
/// **The build is checked before `Spawn` is sent, and that ordering is
/// the assertion `a_build_mismatch_refuses_the_link_and_reports_spawn_failed`
/// makes**: a refusal that happened after the config went out would have
/// created a child nobody owns.
pub async fn handshake(
    stream: &mut UnixStream,
    session_id: &str,
    cfg: &PtySpawnConfig,
) -> Result<WorkerHandshake, HandshakeError> {
    handshake_as(stream, WORKER_PROTOCOL_TAG, session_id, cfg).await
}

/// [`handshake`] with the build string supplied.
///
/// `pub` and parameterised for the reason `accept_worker_within` is:
/// this link's refusal path is only observable if a test can present the
/// other build, and a mismatch cannot otherwise be produced without two
/// checkouts. Every production caller goes through [`handshake`], which
/// passes [`WORKER_PROTOCOL_TAG`] — there is exactly one place the daemon
/// decides what build it claims to be.
pub async fn handshake_as(
    stream: &mut UnixStream,
    ours: &str,
    session_id: &str,
    cfg: &PtySpawnConfig,
) -> Result<WorkerHandshake, HandshakeError> {
    let ready = expect(stream, "Ready").await?;
    let WorkerFrame::Ready { build } = ready else {
        return Err(HandshakeError::OutOfOrder {
            expected: "Ready",
            got: tag_of(&ready),
        });
    };
    if build != ours {
        // Returning here is the refusal: the caller drops the stream, the
        // worker's next read is EOF, and **no `Spawn` frame was ever
        // sent**, so the worker has forked nothing.
        return Err(HandshakeError::BuildMismatch {
            ours: ours.to_string(),
            theirs: build,
        });
    }

    send(
        stream,
        &DaemonFrame::Hello {
            build: ours.to_string(),
            session_id: session_id.to_string(),
        },
    )
    .await?;
    send(stream, &DaemonFrame::Spawn { cfg: cfg.clone() }).await?;

    match expect(stream, "Started").await? {
        WorkerFrame::Started {
            child_pid,
            pgid,
            sid,
        } => Ok(WorkerHandshake {
            child_pid,
            pgid,
            sid,
        }),
        WorkerFrame::SpawnFailed { message } => Err(HandshakeError::SpawnRefused(message)),
        other => Err(HandshakeError::OutOfOrder {
            expected: "Started",
            got: tag_of(&other),
        }),
    }
}

/// One inbound frame under [`WORKER_HANDSHAKE_TIMEOUT`], skipping any
/// `type` this build does not know.
///
/// The skip is `frames.rs`'s asymmetry applied where it was designed to
/// be applied: the daemon is the side that *observes*, so an unknown
/// frame is stepped over rather than allowed to kill the link. The
/// deadline is what stops that becoming an unbounded loop against a peer
/// sending nothing but unknowns.
async fn expect(
    stream: &mut UnixStream,
    what: &'static str,
) -> Result<WorkerFrame, HandshakeError> {
    let deadline = tokio::time::Instant::now() + WORKER_HANDSHAKE_TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, read_frame::<_, WorkerFrame>(stream)).await {
            Ok(Ok(WorkerFrame::Unknown { .. })) => continue,
            Ok(Ok(f)) => return Ok(f),
            Ok(Err(e)) => return Err(HandshakeError::Link(e.to_string())),
            Err(_elapsed) => {
                return Err(HandshakeError::TimedOut {
                    expected: what,
                    timeout: WORKER_HANDSHAKE_TIMEOUT,
                })
            }
        }
    }
}

/// A [`WorkerFrame`]'s wire `type`, for an error that names what arrived.
fn tag_of(f: &WorkerFrame) -> &'static str {
    use super::frames::LinkFrame;
    f.tag().unwrap_or("an unknown frame type")
}

async fn send(stream: &mut UnixStream, frame: &DaemonFrame) -> Result<(), HandshakeError> {
    let bytes = encode_frame(frame).map_err(|e| HandshakeError::Link(e.to_string()))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| HandshakeError::Link(e.to_string()))
}

/// The argv the daemon will use, for a caller that wants to assert on it
/// without spawning.
///
/// Exists so `the_spawn_config_never_appears_on_the_workers_command_line`
/// has something to compare `/proc/<pid>/cmdline` *against* — the row
/// asserts the real process's argv, and this is the claim about what that
/// argv should be.
pub fn worker_argv(exe: &Path, socket: &Path) -> Vec<PathBuf> {
    vec![
        exe.to_path_buf(),
        PathBuf::from(WORKER_SUBCOMMAND),
        PathBuf::from(WORKER_SOCKET_FLAG),
        socket.to_path_buf(),
    ]
}
