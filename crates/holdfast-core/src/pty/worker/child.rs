//! The worker side of the link: connect, handshake, spawn, pump, retire
//! (§3.1, §3.2, §4.1, milestone 0.0.10a Task 3).
//!
//! This is the body of `holdfast pty-worker`, and it lives here rather
//! than in `crates/holdfast/src/commands.rs` for the reason §3.5 gives
//! for every other subcommand: parsing and printing are the CLI's,
//! state is `holdfast-core`'s. The subcommand is nine lines of argv
//! handling over [`run`].
//!
//! # What is deliberately *not* on the argv
//!
//! **[`PtySpawnConfig`] arrives in [`DaemonFrame::Spawn`], and the only
//! thing on the worker's command line is the socket path.** `start_session`'s
//! `env` map can carry credentials — §9.2 has a row for it and the audit
//! log records only `env_keys` — and `/proc/<pid>/cmdline` is
//! world-readable on Linux while `ps` shows an argv to every local user
//! everywhere. Passing the config as a JSON argv element is the shortest
//! implementation of this subcommand and it creates a leak surface that
//! did not exist before the worker did. The socket path is on the argv
//! because it is not a secret: it is a name inside a `0700` directory,
//! and the socket itself is `0600`.
//!
//! # The worker never writes PTY bytes anywhere but the socket
//!
//! Global constraint 8 of this milestone, and the reason this file has
//! no `print!`/`println!`/`eprintln!` of any kind: everything it says
//! goes through [`crate::diag!`], which redacts and which the daemon
//! drains out of the worker's stderr pipe into `daemon.log`
//! ([`super::spawn::start_worker`]). `source_guards.rs`'s
//! `no_module_in_this_crate_can_print_around_the_redactor` already scans
//! this file, because it scans every `.rs` under `holdfast-core/src`.
//!
//! **And no diagnostic here interpolates a PTY byte.** The one frame
//! whose payload is *composed* rather than copied is
//! [`WorkerFrame::Fault`], and [`fault`] is the only thing that builds
//! one: it takes a `&'static str` and a `&dyn Display`, so a read buffer
//! cannot be handed to it without someone deliberately stringifying the
//! buffer first. That is a shape, not a proof — `String::from_utf8_lossy`
//! is `Display` — which is why `a_fault_frame_carries_no_pty_bytes` in
//! `crates/holdfast/tests/worker_process.rs` asserts the behaviour as
//! well.
//!
//! # The four tasks, and why the outbound frames go through a channel
//!
//! A PTY master is a **blocking** fd in this tree (`InProcessPty::read`
//! is `Read::read` and `write` is `write_all` + `flush`), so the two
//! directions cannot both live on the runtime:
//!
//! * **reader** (`spawn_blocking`) — `backend.read` into a fixed
//!   [`PTY_READ_BUF`] buffer, one [`WorkerFrame::Output`] per read, then
//!   [`WorkerFrame::Exited`] at EOF;
//! * **writer** (`spawn_blocking`) — `backend.write` per
//!   [`DaemonFrame::Write`], serialised on its own queue so a child that
//!   has stopped draining its terminal parks *this* task and not the one
//!   reading the socket;
//! * **link-in** (async) — one [`super::frames::read_frame`] at a time,
//!   dispatching;
//! * **link-out** (async) — the *only* writer of the socket, draining an
//!   `mpsc` the other three feed.
//!
//! One outbound task is what makes the ordering claim in
//! [`WorkerFrame::Exited`]'s doc comment true: `Output` frames and the
//! `Exited` that follows them are queued by the same task in that order,
//! and drained by a single writer, so nothing can overtake. (Task 5 is
//! the milestone that *tests* it end to end; this is the structure that
//! lets it hold.)

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::frames::{
    encode_frame, read_frame, DaemonFrame, QueryKind, QueryResult, SignalOutcome, WorkerFrame,
    WORKER_PROTOCOL_TAG,
};
use crate::pty::{clamp_geometry, InProcessPty, PtyBackend, PtySpawnConfig, Signal};

/// One PTY read, and therefore one [`WorkerFrame::Output`].
///
/// **64 KiB, matching `file_transfer_chunk_bytes`**, and the number is
/// the plan's rather than this file's. What matters here is the
/// consequence: an `Output` frame is bounded by this buffer and by the
/// CBOR byte-string header in front of it, which puts it three orders of
/// magnitude below
/// [`MAX_FRAME_BYTES`](crate::protocol::frame::MAX_FRAME_BYTES). The
/// 16 MiB cap is therefore unreachable on this link rather than
/// load-bearing on it — and `the_worker_never_constructs_a_frame_near_the_cap`
/// asserts that against *observed* frame sizes, never against this
/// constant, which would be a tautology.
pub const PTY_READ_BUF: usize = 64 * 1024;

/// How long the worker waits for each of the daemon's two opening frames.
///
/// The same 5 s every other "something local should have answered by
/// now" deadline in this tree uses — `LOCK_TIMEOUT`,
/// `HANDSHAKE_TIMEOUT`, [`WORKER_ACCEPT_TIMEOUT`]. It is the mirror of
/// the daemon's accept deadline and exists for the mirror reason: a
/// worker whose daemon connected and then said nothing must exit rather
/// than hold a PTY-less process open forever.
///
/// [`WORKER_ACCEPT_TIMEOUT`]: super::socket::WORKER_ACCEPT_TIMEOUT
pub const WORKER_HELLO_TIMEOUT: Duration = super::socket::WORKER_ACCEPT_TIMEOUT;

/// How many outbound frames may be queued before the reader blocks.
///
/// Backpressure rather than buffering: at [`PTY_READ_BUF`] per `Output`
/// this is at most 4 MiB in flight, and a daemon that has stopped
/// draining the socket should park the worker's *reader* — which in turn
/// stops draining the PTY and parks the child — rather than let the
/// worker grow without bound on behalf of a peer that is not listening.
/// That is the same shape the kernel already gives an in-process PTY,
/// which is the behaviour the trait must not change.
const OUTBOUND_QUEUE: usize = 64;

/// Why the worker gave up.
///
/// Every arm is a refusal to continue, and every one of them is reported
/// to the daemon as `spawn_failed` or as a closed link — 0.0.10a adds no
/// `Status` value (REQ-SPTY-001).
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// `connect(2)` on `--socket` failed, or the link died.
    #[error("worker link: {0}")]
    Link(String),
    /// The daemon's [`DaemonFrame::Hello`] named a different build.
    ///
    /// **Refused, never negotiated** (§23.4). Both peers come from one
    /// `current_exe`, so a mismatch is not an older peer to accommodate;
    /// it is evidence that the two processes are not the same build.
    #[error("build mismatch: the daemon is {theirs}, this worker is {ours}")]
    BuildMismatch { ours: String, theirs: String },
    /// [`DaemonFrame::Hello`]'s `session_id` is not the one this
    /// socket's name says it is.
    #[error("this socket is {expected}'s, but the daemon greeted {got}")]
    WrongSession { expected: String, got: String },
    /// A frame arrived where the handshake expected another.
    #[error("expected {expected} but the daemon sent {got}")]
    OutOfOrder {
        expected: &'static str,
        got: &'static str,
    },
    /// The daemon connected and then said nothing.
    #[error("the daemon sent no {expected} within {timeout:?}")]
    Silent {
        expected: &'static str,
        timeout: Duration,
    },
}

/// `holdfast pty-worker --socket <path>`.
///
/// Returns `Ok(())` when the child has been retired and the link closed
/// deliberately; every `Err` is a refusal the caller turns into a
/// non-zero exit status. **Nothing here spawns a child before
/// [`DaemonFrame::Spawn`] arrives**, which is what makes "no child
/// process was created" assertable on every refusal path above:
/// a worker that refuses the handshake has forked nothing to leak.
pub async fn run(socket: &Path) -> Result<(), WorkerError> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| WorkerError::Link(format!("connect to {}: {e}", socket.display())))?;

    // `Ready` first and unconditionally: the daemon is holding an accept
    // deadline open and this frame is what ends it. Sending it before
    // reading anything also means a daemon that refuses *our* build
    // learns which build we are, rather than timing out with nothing to
    // put in the log.
    send(
        &mut stream,
        &WorkerFrame::Ready {
            build: WORKER_PROTOCOL_TAG.to_string(),
        },
    )
    .await?;

    let cfg = handshake(&mut stream, socket).await?;

    // The one construction. **`InProcessPty::spawn`, literally** — the
    // same code path the daemon runs today, in a different process. That
    // is not a shortcut: it is what makes Task 13's equivalence suite
    // meaningful, because both arms share the spawn implementation and
    // differ only in where it runs.
    let backend = match InProcessPty::spawn(&cfg) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            // A refusal the daemon maps onto the `spawn_failed` it
            // already has. No child exists, so there is nothing to
            // retire and nothing to sweep.
            let _ = send(
                &mut stream,
                &WorkerFrame::SpawnFailed {
                    message: e.to_string(),
                },
            )
            .await;
            return Ok(());
        }
    };

    let Some(child_pid) = backend.pid() else {
        // Unreachable on Unix — `portable-pty`'s Unix child reports a pid
        // for every successful spawn — and refused rather than papered
        // over, because the alternative is a `Started` carrying a pid the
        // daemon's fallback sweep cannot aim at. A child the daemon
        // cannot retire is worse than a session that did not start.
        let _ = send(
            &mut stream,
            &WorkerFrame::SpawnFailed {
                message: "the child reported no pid".to_string(),
            },
        )
        .await;
        let _ = backend.signal(Signal::Kill);
        return Ok(());
    };
    let (pgid, sid) = child_groups(child_pid);
    send(
        &mut stream,
        &WorkerFrame::Started {
            child_pid,
            pgid,
            sid,
        },
    )
    .await?;

    pump(stream, backend).await
}

/// The child's process group and session, **read from the kernel**.
///
/// `portable-pty` `setsid`s the child, so in practice `pgid == sid ==
/// child_pid` — and reading them anyway is the whole point of this
/// function. Task 9's fallback sweep is only as correct as these two
/// numbers, and the daemon has no way to check them: it never held the
/// master fd and, once the worker is gone, the process it would ask
/// about may already be reaped. Assuming the equality here would put a
/// guess where the sweep expects a measurement, and the guess is right
/// often enough that nothing would notice until it was not.
///
/// `None` for a non-positive answer, matching `in_process.rs`'s
/// `valid_group`: both calls return `-1` with `ESRCH` for a child that
/// has already been reaped, and a `-1` process group is a wildcard the
/// kernel would happily accept.
fn child_groups(child_pid: u32) -> (Option<i32>, Option<i32>) {
    let pid = child_pid as libc::pid_t;
    // SAFETY: both take a pid by value, touch no memory, and report
    // failure as -1. Neither can fail in a way that is unsound.
    let (pgid, sid) = unsafe { (libc::getpgid(pid), libc::getsid(pid)) };
    // No cast: `libc::pid_t` *is* `i32` on every Unix this tree builds
    // for, and `in_process.rs`'s `valid_group` already assumes it. A
    // platform where it is not would be a compile error here, which is
    // the honest outcome — a widening cast would silently change what
    // the sweep is aimed at.
    let valid = |g: libc::pid_t| (g > 0).then_some(g);
    (valid(pgid), valid(sid))
}

/// Read [`DaemonFrame::Hello`] and [`DaemonFrame::Spawn`], in that order,
/// each under [`WORKER_HELLO_TIMEOUT`].
///
/// # Two checks, and the second is the one the frame's `session_id` is for
///
/// `Hello.build` must equal [`WORKER_PROTOCOL_TAG`]. And `Hello.session_id`
/// must equal the stem of the socket path we were handed, because that
/// is the only cross-check available to a process whose entire input is
/// one path: it turns *"I connected to whatever `--socket` named"* into
/// *"I connected to the socket the daemon believes it bound for this
/// session"*. Neither can arise from a correct install — `spawn.rs`
/// binds `workers/<sid>.sock` and passes that same path — which is the
/// point: both are claims about a **decoder**, not about a deployment.
async fn handshake(stream: &mut UnixStream, socket: &Path) -> Result<PtySpawnConfig, WorkerError> {
    let hello = expect(stream, "Hello").await?;
    let DaemonFrame::Hello { build, session_id } = hello else {
        return Err(WorkerError::OutOfOrder {
            expected: "Hello",
            got: tag_of(&hello),
        });
    };
    if build != WORKER_PROTOCOL_TAG {
        return Err(WorkerError::BuildMismatch {
            ours: WORKER_PROTOCOL_TAG.to_string(),
            theirs: build,
        });
    }
    if let Some(expected) = session_of(socket) {
        if expected != session_id {
            return Err(WorkerError::WrongSession {
                expected,
                got: session_id,
            });
        }
    }

    let spawn = expect(stream, "Spawn").await?;
    match spawn {
        DaemonFrame::Spawn { cfg } => Ok(cfg),
        other => Err(WorkerError::OutOfOrder {
            expected: "Spawn",
            got: tag_of(&other),
        }),
    }
}

/// The session id a worker socket's path names, or `None` if the path is
/// not one this tree would have produced.
///
/// `RuntimePaths::worker_sock` builds `workers/<session_id>.sock`, so the
/// stem is the id. `None` rather than an error for anything else: a test
/// or a future caller may hand the worker a socket under some other name,
/// and refusing *that* would be this function inventing a naming rule
/// rather than checking the one that exists.
fn session_of(socket: &Path) -> Option<String> {
    if socket.extension()? != "sock" {
        return None;
    }
    Some(socket.file_stem()?.to_string_lossy().into_owned())
}

/// One inbound frame, under [`WORKER_HELLO_TIMEOUT`], with the elapsed
/// arm an error rather than a wait.
async fn expect(stream: &mut UnixStream, what: &'static str) -> Result<DaemonFrame, WorkerError> {
    match tokio::time::timeout(WORKER_HELLO_TIMEOUT, read_frame::<_, DaemonFrame>(stream)).await {
        Ok(Ok(f)) => Ok(f),
        Ok(Err(e)) => Err(WorkerError::Link(e.to_string())),
        Err(_elapsed) => Err(WorkerError::Silent {
            expected: what,
            timeout: WORKER_HELLO_TIMEOUT,
        }),
    }
}

/// A [`DaemonFrame`]'s wire `type`, for an error message that names what
/// actually arrived.
///
/// `LinkFrame::tag` returns `Option` because the *worker* direction has a
/// decode-only variant; the daemon direction has none, so the `None` arm
/// here is unreachable and says so rather than pretending otherwise.
fn tag_of(f: &DaemonFrame) -> &'static str {
    use super::frames::LinkFrame;
    f.tag().unwrap_or("an unnameable frame")
}

/// Compose a [`WorkerFrame::Fault`].
///
/// **The signature is the guard.** `context` is a `&'static str` — a
/// literal from this file — and `cause` is a `&dyn Display`, so the read
/// buffer (`[u8]`, no `Display`) cannot be handed to it without someone
/// first stringifying it deliberately. `Fault` is the one frame whose
/// message is *composed* rather than copied from the wire, which makes it
/// the one place a `{:?}` of a PTY read buffer would put raw child output
/// into a string the daemon logs — a leak on no output path, and
/// therefore invisible to every guard that watches one (REQ-SPTY-004,
/// and `super`'s invariant 3).
fn fault(context: &'static str, cause: &dyn Display) -> WorkerFrame {
    WorkerFrame::Fault {
        message: format!("{context}: {cause}"),
    }
}

/// The steady state: four tasks over one socket and one backend.
///
/// Returns when the link closes, when [`DaemonFrame::Shutdown`] arrives,
/// or when an outbound write fails — and in every one of those cases the
/// child is retired on the way out. **A worker that exits leaving its
/// child alive is the orphan this milestone exists to prevent**; Tasks 6
/// and 7 own the policy for the two directions of that failure, and this
/// is the floor underneath both.
async fn pump(stream: UnixStream, backend: Arc<InProcessPty>) -> Result<(), WorkerError> {
    let (mut rx_sock, mut tx_sock) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<WorkerFrame>(OUTBOUND_QUEUE);

    // ---------------------------------------------------------- link-out
    //
    // The only writer of the socket. Everything else queues, so `Output`
    // and the `Exited` behind it cannot be reordered by two writers
    // racing for the fd.
    let link_out = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let bytes = match encode_frame(&frame) {
                Ok(b) => b,
                Err(e) => {
                    // Unreachable on this link — an `Output` is bounded
                    // by `PTY_READ_BUF` and every other frame is smaller
                    // still — so this is a claim about the encoder, not
                    // about a payload. No frame content in the message.
                    crate::diag!("holdfast pty-worker: a frame could not be encoded: {e}");
                    break;
                }
            };
            if tx_sock.write_all(&bytes).await.is_err() {
                // The daemon is gone. Nothing to report to and nothing
                // to report it on: the `Fault` that would say so would
                // go down the same dead socket.
                break;
            }
        }
        let _ = tx_sock.shutdown().await;
    });

    // ----------------------------------------------------------- writer
    //
    // Its own blocking task, so a child that has stopped reading its
    // terminal parks this and not the socket reader. `InProcessPty::write`
    // is `write_all` + `flush` on a blocking fd and can park for as long
    // as the child refuses to drain — the same property the daemon's own
    // `send_input` already runs off the runtime for.
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE);
    let writer_backend = Arc::clone(&backend);
    let writer_out = out_tx.clone();
    let writer = tokio::task::spawn_blocking(move || {
        while let Some(bytes) = write_rx.blocking_recv() {
            if let Err(e) = writer_backend.write(&bytes) {
                // `DaemonFrame::Write` is uncorrelated — `send_input`'s
                // deadline is the daemon's answer for a wedged write —
                // so a failed write has no reply to fail. `Fault` is the
                // only way to say it happened, and it says it with the
                // error and nothing else: `bytes` here may be a
                // `SecretInput` value on its way to a prompt.
                let _ = writer_out.blocking_send(fault("pty write failed", &e));
                break;
            }
        }
    });

    // ----------------------------------------------------------- reader
    //
    // One `Output` per read, `Exited` after the last of them. The buffer
    // is allocated once and reused, which is exactly why nothing may
    // interpolate it into a message: after the child exits it still holds
    // the bytes of the last read.
    let reader_backend = Arc::clone(&backend);
    let reader_out = out_tx.clone();
    let reader = tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; PTY_READ_BUF];
        loop {
            match reader_backend.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if reader_out
                        .blocking_send(WorkerFrame::Output {
                            bytes: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    // Unreachable through `portable-pty` 0.9.0 on Unix,
                    // which maps the master's `EIO` — the slave has
                    // closed — onto `Ok(0)` so that `Read::read_to_end`
                    // terminates gracefully (`unix.rs:94`). Written
                    // anyway, and written with `fault`, because "cannot
                    // arise" is a claim about a dependency: the arm that
                    // exists must be the one that cannot leak.
                    let _ = reader_out.blocking_send(fault("pty read failed", &e));
                    return;
                }
            }
        }
        // EOF on the master means the child's last byte has already been
        // queued above, so `Exited` lands behind it on a queue with one
        // drainer. This is the 0.0.6 defect's shape and the ordering is
        // the whole of the fix (Task 5 tests it end to end).
        let _ = reader_out.blocking_send(WorkerFrame::Exited {
            code: reader_backend.exit_code(),
            // REQ-P-007: the trait cannot carry *how* a child died and
            // widening it is an above-the-trait change REQ-SPTY-001
            // forbids. `None` until the milestone that revisits the seam.
            signal: None,
        });
    });

    // ---------------------------------------------------------- link-in
    let outcome = link_in(&mut rx_sock, &backend, &out_tx, &write_tx).await;

    // Retire the child before anything else: `Shutdown` and a closed
    // socket are both "this session is over", and the harm this milestone
    // is about is a shell that outlives the daemon that owns it.
    let _ = backend.signal(Signal::Terminate);

    drop(write_tx);
    drop(out_tx);
    let _ = writer.await;
    let _ = reader.await;
    let _ = link_out.await;
    outcome
}

/// Read and dispatch daemon frames until the link ends.
async fn link_in(
    rx: &mut tokio::net::unix::OwnedReadHalf,
    backend: &Arc<InProcessPty>,
    out: &mpsc::Sender<WorkerFrame>,
    writes: &mpsc::Sender<Vec<u8>>,
) -> Result<(), WorkerError> {
    loop {
        // **No deadline, and that is deliberate.** After the handshake
        // the daemon is entitled to say nothing for as long as the
        // session is idle; the wait that must be bounded is the one on
        // the *daemon's* side, where a wedged worker would park a tool
        // call. What ends this loop is the socket closing, which a dead
        // daemon produces immediately.
        let frame = match read_frame::<_, DaemonFrame>(rx).await {
            Ok(f) => f,
            Err(crate::protocol::frame::FrameError::Eof) => return Ok(()),
            Err(e) => {
                // A `DaemonFrame` this build cannot read is an
                // instruction it cannot act on, and silently discarding
                // a `Write` or a `Signal` is worse than refusing the
                // link (`frames.rs`'s asymmetry). The error carries a
                // serde message, never a body byte.
                let _ = out.send(fault("undecodable daemon frame", &e)).await;
                return Err(WorkerError::Link(e.to_string()));
            }
        };
        match frame {
            DaemonFrame::Write { bytes } => {
                if writes.send(bytes).await.is_err() {
                    return Ok(());
                }
            }
            DaemonFrame::Signal { id, sig } => {
                // Through `Result<(), String>` and the `From` impl rather
                // than matching on the two arms here: `SignalOutcome`
                // exists only because ciborium cannot carry `Ok(())`, and
                // routing every construction through the conversion is
                // what keeps that substitution at the wire instead of
                // spreading a second spelling of "delivered" into the
                // callers (`frames.rs`).
                let outcome: SignalOutcome = backend.signal(sig).map_err(|e| e.to_string()).into();
                if out
                    .send(WorkerFrame::Reply {
                        id,
                        result: QueryResult::Signalled(outcome),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            DaemonFrame::Resize { cols, rows } => {
                // **Clamped again, on this side.** Every daemon-side
                // caller already clamps before the backend call — the
                // response reports the size the terminal reached — but a
                // worker must not trust its peer even when its peer is
                // itself, and `vt100` underflows below `MIN_COLS`/
                // `MIN_ROWS` rather than erroring.
                let (cols, rows) = clamp_geometry(cols, rows);
                if let Err(e) = backend.resize(cols, rows) {
                    if out.send(fault("pty resize failed", &e)).await.is_err() {
                        return Ok(());
                    }
                }
            }
            DaemonFrame::Query { id, what } => {
                let result = match what {
                    QueryKind::LineDiscipline => QueryResult::Discipline(backend.line_discipline()),
                    QueryKind::ForegroundGroup => {
                        QueryResult::ForegroundGroup(backend.foreground_group())
                    }
                };
                if out.send(WorkerFrame::Reply { id, result }).await.is_err() {
                    return Ok(());
                }
            }
            DaemonFrame::Shutdown => return Ok(()),
            // Both are handshake frames and both are refused here rather
            // than ignored: a second `Spawn` would be a second child this
            // process could not retire, and a second `Hello` is a peer
            // that has lost track of the link.
            other @ (DaemonFrame::Hello { .. } | DaemonFrame::Spawn { .. }) => {
                let msg = format!("{} after the handshake", tag_of(&other));
                let _ = out.send(fault("protocol violation", &msg)).await;
                return Err(WorkerError::OutOfOrder {
                    expected: "a steady-state frame",
                    got: tag_of(&other),
                });
            }
        }
    }
}

/// Encode and write one frame directly, before [`pump`]'s outbound task
/// exists.
async fn send(stream: &mut UnixStream, frame: &WorkerFrame) -> Result<(), WorkerError> {
    let bytes = encode_frame(frame).map_err(|e| WorkerError::Link(e.to_string()))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| WorkerError::Link(e.to_string()))
}

/// The argv `holdfast pty-worker` accepts, parsed.
///
/// Here rather than in the CLI crate because the *shape* of this argv is
/// a protocol decision — one flag, and specifically not the spawn config
/// — and the assertion that guards it
/// (`the_spawn_config_never_appears_on_the_workers_command_line`) reads
/// the worker's `/proc/<pid>/cmdline`. Keeping the parser beside the
/// reason means the next person to add a flag reads the reason first.
#[derive(Debug, PartialEq, Eq)]
pub enum Argv {
    /// `--socket <path>`.
    Run(PathBuf),
    /// `--help`, which is answered even though the subcommand is hidden:
    /// hidden means *absent from the banner*, not *undiagnosable*.
    Help,
    /// Anything else, with the reason.
    Usage(String),
}

/// Parse everything after `pty-worker`.
pub fn parse_argv(args: &[String]) -> Argv {
    let mut socket = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Argv::Help,
            "--socket" => match args.get(i + 1) {
                Some(p) => {
                    socket = Some(PathBuf::from(p));
                    i += 2;
                }
                None => return Argv::Usage("`--socket` needs a path".to_string()),
            },
            other => {
                // The reason is echoed back, and it is the *flag* that is
                // echoed and never a value: an operator does not run this
                // subcommand, so the only reader of this line is
                // `daemon.log` by way of the stderr drain.
                return Argv::Usage(format!("unknown argument `{other}`"));
            }
        }
    }
    match socket {
        Some(p) => Argv::Run(p),
        None => Argv::Usage("`pty-worker` needs `--socket <path>`".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The argv is one flag, and the config is not on it.
    ///
    /// A unit row beside the parser; the property that matters — the
    /// config never reaches `/proc/<pid>/cmdline` — is asserted against a
    /// real worker process in
    /// `crates/holdfast/tests/worker_process.rs`, because a parser that
    /// *accepts* only `--socket` says nothing about what the daemon
    /// *passes*.
    #[test]
    fn the_argv_accepts_a_socket_and_refuses_everything_else() {
        assert_eq!(
            parse_argv(&["--socket".into(), "/tmp/x.sock".into()]),
            Argv::Run(PathBuf::from("/tmp/x.sock"))
        );
        assert_eq!(parse_argv(&["--help".into()]), Argv::Help);
        assert!(matches!(parse_argv(&[]), Argv::Usage(_)));
        assert!(matches!(parse_argv(&["--socket".into()]), Argv::Usage(_)));
        // The shape this task exists to refuse: a spawn config on the
        // command line. It is not a flag this parser has, and the refusal
        // names the flag rather than quoting whatever followed it.
        let refused = parse_argv(&[
            "--config".into(),
            "{\"env\":{\"API_KEY\":\"s3cret\"}}".into(),
        ]);
        let Argv::Usage(why) = refused else {
            panic!("`--config` must not be accepted: {refused:?}");
        };
        assert!(why.contains("--config"), "{why}");
        assert!(
            !why.contains("s3cret"),
            "the refusal quoted the value: {why}"
        );
    }

    #[test]
    fn a_worker_socket_path_names_its_session() {
        assert_eq!(
            session_of(Path::new("/run/holdfast/workers/sess_0123456789ab.sock")).as_deref(),
            Some("sess_0123456789ab")
        );
        // Not a name this tree produces: no rule to check, so no refusal
        // invented.
        assert_eq!(session_of(Path::new("/tmp/anything")), None);
    }
}
