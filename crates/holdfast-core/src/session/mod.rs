//! A single PTY-backed session.

pub mod reaper;
pub mod registry;
pub mod wait;
pub use reaper::Reaper;
pub use registry::SessionRegistry;

use crate::attach::secret::SecretBytes;
use crate::buffer::{BufferRead, OutputBuffer};
use crate::clock::Clock;
use crate::detect::history::{CommandEntry, CommandHistory, DEFAULT_MAX_ENTRIES};
use crate::detect::{
    Detection, DetectionConfig, InteractionMode, Osc133Source, PromptDetector, Shell,
};
use crate::output::rules::RuleSet;
use crate::output::{
    OutputProcessor, ProcessedRead, ReadOptions, ReadRequest, ReadStart, WindowSnapshot,
};
use crate::pty::{clamp_geometry, PtyBackend, Signal};
use crate::screen::{
    CursorSignal, QueryResponder, ScreenCapture, ScreenConfig, ScreenTracker,
    DEFAULT_TERMINAL_QUERY_REPLIES_PER_MIN,
};
use crate::{HoldfastError, Result};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

pub type SessionId = String;

/// How many frames the per-session output broadcast holds before a slow
/// consumer starts losing them (§4.3's default). A consumer that lags gets
/// `RecvError::Lagged` and resyncs from the ring buffer rather than from
/// the frame it happened to be holding (REQ-C-006); the reader is never
/// blocked, which is the property the bound exists to guarantee.
pub const OUTPUT_BROADCAST_FRAMES: usize = 256;

/// One chunk the reader appended, with the absolute span it occupies.
///
/// The span is what makes the two-phase scan in `wait::for_pattern`
/// possible: a waiter that has already scanned history up to
/// `snapshot_head` can skip the part of a queued frame that lies below it
/// and feed only the suffix, so no byte is scanned twice and none is
/// missed (§5.2).
#[derive(Debug, Clone)]
pub struct OutputFrame {
    pub start: u64,
    pub end: u64,
    /// `Arc` rather than `Vec`: the broadcast hands a clone to every
    /// subscriber, and 0.0.5 adds attach clients to that set.
    pub bytes: Arc<[u8]>,
}

/// How long the reader waits before retrying a backend that reported no
/// bytes but is still alive. Only reached by non-blocking backends; a
/// real PTY blocks in `read`, so this never costs anything in production.
const READER_IDLE_POLL: Duration = Duration::from_millis(5);

/// How long the reader thread waits, **after** its read loop has ended,
/// for the child to be reaped before it gives up on naming an exit code.
///
/// The master's `EIO` and the `WNOHANG` wait that produces the code are
/// two different observations of the same death, and on Linux the first
/// routinely precedes the second. `SessionEvent::Exited` is emitted once
/// and a client believes the number, so the wait buys the difference
/// between a correct code and `-1`. It is bounded because a read that
/// failed for some *other* reason must not park this thread against a
/// child that is still running.
const EXIT_REAP_GRACE: Duration = Duration::from_millis(250);

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
    /// When set, Holdfast types the shell's OSC 133 integration snippet into
    /// the session at start-up (spec §8.5).
    pub shell_integration: Option<Shell>,
    /// §4.2 `terminal_queries`, default **true**. `false` accepts the
    /// §4.5.1 stall in exchange for writing nothing into the child's
    /// input — the knob exists for a session that must be byte-exact
    /// about what enters the child, and it is off by default in no
    /// configuration.
    pub terminal_queries: bool,
    /// §4.2 `terminal_query_replies_per_min`, default **60**.
    pub terminal_query_replies_per_min: u32,
    /// §4.2 `default_idle_timeout_secs`, default **1800** (REQ-S-004).
    ///
    /// **`0` disables reaping for this session** — and a disabled session
    /// is *skipped*, not given a deadline far in the future, because a
    /// sentinel deadline eventually arrives. The resolved value is
    /// `start_session(idle_timeout_secs:)` when the caller supplied one,
    /// and `[limits] default_idle_timeout_secs` otherwise; that is
    /// REQ-CFG-001's precedence pair, and the two names differ on
    /// purpose.
    pub idle_timeout_secs: u64,
    /// The time source for this session's **activity stamps**.
    ///
    /// It has to be the reaper's clock and not wall time, or the two
    /// halves of one decision are read off two different clocks: the
    /// reaper asks "is `now` past the deadline" on the injectable clock
    /// while the deadline was written from `SystemTime::now()`, and every
    /// `advance the clock` test silently measures the gap between them
    /// instead of the timeout. `Clock::system()` by default, which is
    /// wall time and what production uses.
    ///
    /// **`exited_at_secs` deliberately does not read it.** That is a
    /// wall-clock fact reported to a caller, not a deadline — the same
    /// rule `daemon::server::unix_secs_now` follows.
    pub clock: Clock,
    /// §9.6's operator-declared session profile this session was started
    /// from, if any (GH #46). **This is what a `SecretBinding` selects
    /// on**, and it is `None` for every session started with
    /// `command`/`args` — which is the whole of *"a session started with
    /// `command`/`args` can never receive a keychain credential"*.
    ///
    /// It is a **name the operator wrote**, copied from
    /// `SecurityConfig::profiles` by `start_session` after the profile was
    /// looked up. The agent supplies a name to look one *up* by; it
    /// cannot supply the value that lands here, because a name that
    /// matches no profile is an argument error and the call never reaches
    /// a spawn.
    pub profile: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: registry::DEFAULT_BUFFER_BYTES,
            detection: DetectionConfig::default(),
            history_max_entries: DEFAULT_MAX_ENTRIES,
            shell_integration: None,
            terminal_queries: true,
            terminal_query_replies_per_min: DEFAULT_TERMINAL_QUERY_REPLIES_PER_MIN,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            clock: Clock::system(),
            // The default is *no profile*, which is the shape that
            // resolves no credential. A session has to be given one
            // deliberately.
            profile: None,
        }
    }
}

/// §4.2's `default_idle_timeout_secs` (REQ-S-004). The config file
/// overrides it globally and `start_session` per session.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 1800;

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
    /// §9.6's session profile this session was started from, or `None` for
    /// a `command`/`args` session. See [`SessionConfig::profile`]; it is
    /// the **only** thing `secret::binding::select` selects on.
    pub profile: Option<String>,
    backend: Arc<dyn PtyBackend>,
    buffer: Arc<Mutex<OutputBuffer>>,
    /// Tier-B terminal state (spec §4.5). Locked *before* `buffer` on the
    /// one path that needs both — a re-seed reads the ring buffer — so
    /// nothing may ever take `buffer` and then this.
    screen: Arc<Mutex<ScreenTracker>>,
    /// The PTY's **current** dimensions, packed `cols << 16 | rows`.
    ///
    /// Nothing tracked this before: `PtySpawnConfig`'s `cols`/`rows` are
    /// consumed at `openpty` and then forgotten, so the only thing a
    /// `resize` tool could report was the argument it was handed — which
    /// reports success for a resize that failed. Seeded at construction
    /// with `PtySpawnConfig::new`'s defaults, corrected by
    /// `set_screen_config` (which is where the real geometry arrives), and
    /// written by `resize` *after* the backend call.
    ///
    /// Atomic rather than behind the screen mutex because `size()` is a
    /// cheap read on the control path, and because the two are updated
    /// together under `resize` anyway.
    size: AtomicU32,
    /// The geometry **asked for**, as distinct from the one in force.
    ///
    /// The agent's `resize` tool sets this; `size` is what the PTY actually
    /// has, which is this folded with what every attached writer can
    /// display (GH #75). They differ whenever a human's terminal is
    /// narrower than the size an agent wanted for a TUI, and the difference
    /// is the whole point: the human sees something legible, and when they
    /// detach the session returns here rather than staying stuck at the
    /// geometry of a client that has gone.
    desired_size: AtomicU32,
    /// Spec §9.2 rule table, shared with the screen tracker so
    /// `set_screen_config` can rebuild it. Sourced from
    /// `output::rules::builtin_shared()` (0.0.3) — the process-wide table
    /// every session shares. **Not** the `Arc` an `OutputProcessor` holds:
    /// `Session` owns no processor, and `OutputProcessor::builtin`
    /// compiles a fresh `RuleSet` anyway, so the two are different
    /// allocations even when they hold identical rules.
    rules: Arc<RuleSet>,
    detector: Arc<Mutex<PromptDetector>>,
    history: Arc<Mutex<CommandHistory>>,
    /// Which shell integration was injected, if any.
    pub shell_integration: Option<Shell>,
    state: Mutex<SessionState>,
    /// Cumulative `{rule kind: count}` for this session — §5.2's
    /// `status.redaction_stats` (§9.2, REQ-O-012).
    ///
    /// **Not the same number `read_output.redactions` reports, and never
    /// derived from it.** That one describes a single response; this one
    /// describes the session. Two overlapping reads of one secret leave
    /// each response reporting 1 while this reaches 2, and that
    /// difference is the contract.
    redaction_stats: Mutex<BTreeMap<String, u64>>,
    /// §9.6's `max_uses` budget, `{binding name: resolutions}` — 0.0.7.
    ///
    /// **The counter lives with the session and not with the binding**,
    /// which is the whole of what §9.6's *"bounds blast radius if a
    /// session is doing something unexpected"* means: two sessions
    /// matching one binding get one budget each, and a global tally would
    /// let the first session on the box starve every other one.
    ///
    /// It is here, on `Session`, rather than in a map keyed by session id
    /// somewhere longer-lived, for the reason that shape has already cost
    /// this project once (GH #24): a per-session tally held anywhere but
    /// the session is a per-session tally that has to be *cleaned up*, and
    /// nothing sweeps a session that resolved a binding and then simply
    /// ended. Here it is freed with the session and there is no lifetime
    /// to get wrong.
    ///
    /// Shaped after `redaction_stats` above — the same `BTreeMap` behind
    /// the session's own lock, a read-only snapshot getter, and the
    /// mutation confined to one pair of methods.
    binding_uses: Mutex<BTreeMap<String, u32>>,
    /// Live output fan-out. `wait_for_pattern` subscribes to this *before*
    /// it snapshots the buffer, which is the ordering that stops a fast
    /// command's output from landing in the gap between the two.
    output_tx: broadcast::Sender<OutputFrame>,
    /// §7.5's non-output edges, on the same shape as `output_tx` and for
    /// the same reason: a connection converts them into frames, and the
    /// session never names one.
    events_tx: broadcast::Sender<SessionEvent>,
    /// The last `interaction_mode == AwaitingSecret` the reader saw. Held
    /// beside the detector rather than in it, because 0.0.2's
    /// `PromptDetector` is a pure classifier with no previous mode and an
    /// edge is not computable from its state.
    awaiting_secret: Arc<std::sync::atomic::AtomicBool>,
    /// How many writes this session's PTY has actually **taken**, bumped
    /// in [`Session::write_input_acked`] after the backend accepted them.
    ///
    /// **A performed count, not a queued one, and that is the whole
    /// point.** §9.6's autofill decides to write a credential and then
    /// goes away for as long as `keychain_provider_timeout_secs` while a
    /// credential store answers. Anything written to the child in that
    /// window may have satisfied the very read the credential was
    /// resolved for — after which the credential lands in the child's
    /// *next* read, which is usually echoing, and the line discipline
    /// puts it straight into the ring buffer. Sampling this before the
    /// provider call and comparing it in the writer thread is how that is
    /// refused; see [`WriteRequest::SecretIfUnread`].
    writes_performed: Arc<AtomicU64>,
    /// §4.3's write queue — the *push* half of the same fan-out
    /// `output_tx` is the pull half of.
    ///
    /// **A second door to the same PTY, not a replacement for the
    /// first.** `write_input`/`write_input_acked` stay exactly as they
    /// are and the MCP `send_input` path keeps calling them
    /// synchronously; this exists because 0.0.6 is the first milestone
    /// with a *second* writer, and two attach clients typing at once
    /// have to be serialised somewhere. This channel is that somewhere,
    /// and §7.5's last-writer-wins is FIFO through it and nothing more:
    /// no arbitration, no lock, and no ordering guarantee between two
    /// clients beyond the order their frames arrived.
    write_tx: tokio::sync::mpsc::Sender<WriteRequest>,
    last_activity_ms: Arc<AtomicI64>,
    /// Unix seconds at which the exit was *first observed*, 0 while alive.
    /// Observation time, not the child's true death instant: nothing in
    /// the tree can see the latter, and a field that implies it would be
    /// a more precise lie than no field at all.
    exited_at_secs: Arc<AtomicI64>,
    /// The absolute instant this session becomes reapable, in the same
    /// Unix-epoch milliseconds `last_activity_ms` uses. **0 means reaping
    /// is disabled** for this session (REQ-S-004's `idle_timeout_secs =
    /// 0`), which the reaper skips rather than treating as a deadline in
    /// the past.
    ///
    /// An `AtomicI64` beside `last_activity_ms` and **not behind the
    /// session mutex** (REQ-S-007): the reaper reads every session on
    /// every 30-second sweep, and taking a per-session lock to read a
    /// deadline would put it in contention with the read path for no
    /// reason. Written at exactly the sites that bump activity, so it can
    /// never be stale with respect to the value it is derived from.
    idle_deadline_ms: Arc<AtomicI64>,
    /// `idle_timeout_secs * 1000`, or 0 when reaping is disabled. Fixed
    /// at construction — 0.0.5 has no surface that changes a session's
    /// timeout after `start_session` — so the reader thread captures it
    /// by value rather than sharing an atomic it would never see change.
    idle_timeout_ms: i64,
    /// The clock the activity stamps above are written from. Held so
    /// `touch` and the reaper cannot disagree about what time it is.
    clock: Clock,
    pub created_at: std::time::SystemTime,
}

/// How many writes §4.3's queue holds before a producer has to wait.
///
/// §4.3's per-connection bound, and **not configurable in v0.1.0**. A
/// full queue is backpressure on the attach connection that filled it
/// and never on the reader — the two directions share nothing but the
/// PTY.
pub const WRITE_QUEUE_FRAMES: usize = 64;

/// One item on §4.3's write queue.
///
/// **An `enum` from the first variant, deliberately** — and the second
/// variant has now arrived exactly as predicted. `Secret` carries a
/// [`SecretBytes`] *as itself* rather than the bytes inside one, so the
/// zeroing `Drop` runs in the writer thread **after** the PTY has the
/// value and no unzeroed copy ever exists. A variant carrying a
/// `Vec<u8>` would have undone the whole design at the one call site
/// that matters.
///
/// **The ack is `Result<usize>` and not the shipped [`WriteAck`], and
/// the narrowing is deliberate.** §4.3's normative writer ack is
/// `{ result, pre_write_head }`, which is exactly `WriteAck`. The attach
/// path has no use for `pre_write_head`: it exists so `send_input` can
/// hand the agent a cursor to read from, and an attach client renders a
/// live broadcast rather than reading from a cursor. Said here rather
/// than silently dropped — if a later surface needs it, the variant
/// carries a `WriteAck` and nothing else changes.
#[derive(Debug)]
pub enum WriteRequest {
    Input {
        bytes: Vec<u8>,
        /// Dropping the receiving half is how a caller says it does not
        /// care; the send then fails and is ignored.
        ack: tokio::sync::oneshot::Sender<Result<usize>>,
    },
    /// §7.5's `SecretInput`, already normalised (§5.2).
    ///
    /// The writer calls `secret.with_bytes(|b| …)` and then drops the
    /// `SecretBytes`, so the zeroing happens in the writer after the PTY
    /// has the bytes.
    Secret {
        secret: SecretBytes,
        ack: tokio::sync::oneshot::Sender<Result<usize>>,
    },
    /// §9.6's autofill credential, written **only if** the child is still
    /// at the echo-off read it was resolved for.
    ///
    /// ## Why the decision is here and not at the call site
    ///
    /// The autofill decides to write, then goes away for as long as
    /// `keychain_provider_timeout_secs` while a credential store answers.
    /// A check taken before that — or even immediately before the enqueue
    /// — is separated from the write by **this queue**, and two
    /// interleavings get through it:
    ///
    /// 1. **A stale predicate.** `Session::is_awaiting_secret` is a cache
    ///    the reader thread refreshes only when the child produces output,
    ///    so a child that restores echo and then prints nothing leaves it
    ///    reading `true` indefinitely. Driven: `stty -echo; read x;
    ///    stty echo; read y` leaked the credential into the second,
    ///    echoing read — and therefore into the ring buffer `read_output`
    ///    serves to the agent — with the flag still `true`.
    /// 2. **Bytes already in flight.** `Input` and `Secret` share this one
    ///    FIFO. A `send_input` queued ahead of the credential satisfies
    ///    the echo-off read, and the credential lands in the next one. The
    ///    predicate was *correct when evaluated* and the write still
    ///    leaked, because the state changed on account of bytes in the
    ///    very queue the credential was about to join.
    ///
    /// Evaluating in the writer closes the first by construction — the
    /// decision happens at the moment of writing — and `expect_writes`
    /// closes the second by naming the state the decision was taken
    /// against, in the same shape `SlotSnapshot` uses for the secret slot.
    SecretIfUnread {
        secret: SecretBytes,
        /// [`Session::writes_performed`] as it stood when the caller
        /// decided to resolve — **before** the provider ran, not before
        /// the enqueue. Anything written to this child in between may have
        /// satisfied the read the credential was resolved for.
        expect_writes: u64,
        ack: tokio::sync::oneshot::Sender<Result<SecretWrite>>,
    },
}

/// What the writer did with a [`WriteRequest::SecretIfUnread`].
///
/// **A named answer rather than `Result<usize>` with a sentinel**: the
/// caller renders "written" and "declined" as two different outcomes —
/// one closes a request `fulfilled` and the other falls through to a human
/// — and a `0` that means "declined" is one careless normalisation away
/// from meaning "wrote an empty line".
#[derive(Debug, PartialEq, Eq)]
pub enum SecretWrite {
    Written(usize),
    /// Nothing was written and the value was dropped, which zeroes it.
    Declined(DeclineReason),
}

/// Which of [`WriteRequest::SecretIfUnread`]'s two conditions refused.
///
/// Two, and they are **not** the same condition seen twice: a child that
/// abandons its own read moves no counter, and bytes written ahead of the
/// credential can satisfy the read long before the child gets far enough
/// to restore echo. Each has its own row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclineReason {
    /// The child is no longer at an echo-off read — or the backend cannot
    /// say, which is refused for the same reason.
    NotEchoOff,
    /// Something else was written to this child between the decision and
    /// this write.
    OtherWriteIntervened,
}

impl WriteRequest {
    /// An `Input` request and the handle its result arrives on.
    pub fn input(bytes: Vec<u8>) -> (Self, tokio::sync::oneshot::Receiver<Result<usize>>) {
        let (ack, rx) = tokio::sync::oneshot::channel();
        (Self::Input { bytes, ack }, rx)
    }

    /// A `Secret` request. Takes ownership of the `SecretBytes`, which is
    /// the point: there is no way to build one of these from a `Vec<u8>`
    /// that escaped the type.
    pub fn secret(secret: SecretBytes) -> (Self, tokio::sync::oneshot::Receiver<Result<usize>>) {
        let (ack, rx) = tokio::sync::oneshot::channel();
        (Self::Secret { secret, ack }, rx)
    }

    /// A conditional secret write — see [`WriteRequest::SecretIfUnread`].
    ///
    /// **Not the default spelling, deliberately.** `attach::conn`'s
    /// `SecretInput` arm carries a value a human typed *at* the prompt
    /// they are looking at, with no provider round trip in between, so it
    /// has nothing to be stale about. This one is for §9.6's autofill,
    /// which does.
    pub fn secret_if_unread(
        secret: SecretBytes,
        expect_writes: u64,
    ) -> (Self, tokio::sync::oneshot::Receiver<Result<SecretWrite>>) {
        let (ack, rx) = tokio::sync::oneshot::channel();
        (
            Self::SecretIfUnread {
                secret,
                expect_writes,
                ack,
            },
            rx,
        )
    }
}

/// [`WriteRequest::SecretIfUnread`]'s two conditions and the write they
/// guard, on the writer thread.
///
/// **Order matters, and it is the cheap-and-certain one first.**
/// `expect_writes` is a load of an atomic; the echo test is a syscall.
/// Both refuse, so the order is not a correctness question — but the
/// counter is also the condition that can be true while the child is
/// *still* at its prompt (bytes ahead of the credential have not been
/// consumed yet), which is the case a termios read cannot see at all.
///
/// **`echo != Some(false)` and not `echo == Some(true)`.** A backend that
/// cannot sample the line discipline reports `None`, and "we cannot
/// confirm the child is at an echo-off read" is refused for the same
/// reason "it is not" is. §8.3's own classification requires
/// `echo == Some(false)`, so a caller that got this far on such a backend
/// is already impossible; this is the belt to that braces.
///
/// The value is dropped — and therefore zeroed — on both refusals,
/// before returning.
///
/// ## What neither condition can see, and why (GH #43)
///
/// **Bytes written *before* the decision that the child has not yet
/// consumed.** Both tests then pass, correctly and on their own terms:
/// nothing has been written *since* the sample, so the counter matches,
/// and the child really is still at an echo-off read, so the tty says
/// `Some(false)`. The queued byte satisfies that read, and the credential
/// lands in the child's **next** one — which usually echoes, and therefore
/// reaches the ring buffer `read_output` serves to the agent. Driven: a
/// child that drops echo, prints nothing, then prompts, with one byte
/// already queued, gives `Password: next=[hunter2]`.
///
/// The missing quantity is *"how many bytes are already queued and
/// unread"*, which neither a write counter nor a termios read can supply.
///
/// **The obstacle is not a missing API, and recording that wrongly is
/// worse than recording nothing.** `TIOCINQ` answers exactly this, the fd
/// is already reachable (`in_process.rs`'s `as_raw_fd`, which this very
/// function's echo test ioctls), and measured on a real pty it returns the
/// wanted count — **on the slave**; the master answers 0. The obstacle is
/// that `InProcessPty::spawn` **drops the slave on purpose so the master
/// sees EOF when the child exits**, and that EOF is what the reader loop
/// ends on. So this is a design tension between observing the input queue
/// and detecting child exit, and any repair resolves that tension in the
/// PTY backend rather than here.
fn write_secret_if_unread(
    session: &Arc<Session>,
    secret: SecretBytes,
    expect_writes: u64,
) -> Result<SecretWrite> {
    if session.writes_performed() != expect_writes {
        drop(secret);
        return Ok(SecretWrite::Declined(DeclineReason::OtherWriteIntervened));
    }
    if session.line_discipline().echo != Some(false) {
        drop(secret);
        return Ok(SecretWrite::Declined(DeclineReason::NotEchoOff));
    }
    let result = secret.with_bytes(|b| session.write_input(b));
    drop(secret);
    result.map(SecretWrite::Written)
}

/// What a session tells its attached clients beyond raw output (§7.5).
///
/// **Not `ServerFrame`.** `Session` knows nothing about the attach
/// protocol and must not: the frames are a §23.3 wire surface that the
/// web UI mirrors in 0.0.10, and a session that built them would be the
/// second place they are constructed. What travels here is the *event*;
/// `attach::conn` turns it into a frame, which is the same shape
/// `OutputFrame` already has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The child's line discipline dropped `ECHO` and the detector
    /// classified the session as `AwaitingSecret` (REQ-SEC-010). Carries
    /// the redacted prompt line the child had just drawn, which may
    /// legitimately be empty (REQ-O-013).
    AwaitingSecretEntered { prompt_text: String },
    /// Echo came back without a submission — §5.2's supersede case.
    AwaitingSecretLeft,
    /// The child ended. **The only place in the tree where a session's
    /// exit is an *event* rather than a poll.**
    ///
    /// Everything else observes death by asking — `Session::state()`
    /// latches `Exited(code)` lazily when somebody looks, the idle reaper
    /// sweeps every 30 s, `daemon/status` compares a set on its own tick.
    /// §7.5's `SessionExited { code }` is not a poll: it is one frame,
    /// once, before the `Detached { reason: "session_exit" }` that tears
    /// the view down, and REQ-D-009 fixes that order because it is what
    /// lets a renderer show the exit code before the pane closes.
    ///
    /// Raised from the reader thread, which is the one place that finds
    /// out promptly: it is parked in a blocking `read` on the master, and
    /// the master reports the child's end by failing that read.
    Exited { code: i32 },
}

/// How many session events a slow attach connection may fall behind
/// before it loses the oldest. Small on purpose: these are edges, not a
/// stream, and a connection that has missed 16 of them has bigger
/// problems than the one it lost.
pub const SESSION_EVENT_FRAMES: usize = 16;

/// What a write reports back: how much went, and where the buffer stood
/// the instant before it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAck {
    pub bytes_written: usize,
    /// `buffer.head` sampled immediately before `backend.write`.
    pub pre_write_head: u64,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The idle deadline for an activity stamp, or **0 when reaping is
/// disabled**.
///
/// The zero is the whole of REQ-S-004's disable value and it is spelled
/// here once, because a disabled session must be *skipped* rather than
/// given a far-future sentinel — a sentinel eventually arrives.
fn deadline_from(activity_ms: i64, idle_timeout_ms: i64) -> i64 {
    if idle_timeout_ms <= 0 {
        0
    } else {
        activity_ms.saturating_add(idle_timeout_ms)
    }
}

/// `(cols, rows)` in one `u32`, so a reader can never observe a half-applied
/// resize (a width from after the call beside a height from before it).
fn pack_size(cols: u16, rows: u16) -> u32 {
    (u32::from(cols) << 16) | u32::from(rows)
}

fn unpack_size(packed: u32) -> (u16, u16) {
    ((packed >> 16) as u16, (packed & 0xffff) as u16)
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
        let clock = config.clock.clone();
        let started_ms = clock.now_ms();
        let last_activity_ms = Arc::new(AtomicI64::new(started_ms));
        // Saturating, so a caller who asks for a century of idleness gets
        // "effectively never" rather than a wrapped deadline in the past.
        let idle_timeout_ms = (config.idle_timeout_secs as i64).saturating_mul(1000);
        let idle_deadline_ms = Arc::new(AtomicI64::new(deadline_from(started_ms, idle_timeout_ms)));
        let (output_tx, _) = broadcast::channel(OUTPUT_BROADCAST_FRAMES);
        let (events_tx, _) = broadcast::channel(SESSION_EVENT_FRAMES);
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel(WRITE_QUEUE_FRAMES);
        let awaiting_secret = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writes_performed = Arc::new(AtomicU64::new(0));

        // Geometry and mode are applied by `set_screen_config` right
        // after construction; the default matches `PtySpawnConfig::new`
        // so a session created without one still seeds a correct grid.
        let rules = crate::output::rules::builtin_shared();
        let screen = Arc::new(Mutex::new(ScreenTracker::new(
            ScreenConfig::default(),
            Arc::clone(&rules),
            Instant::now(),
        )));

        let session = Arc::new(Self {
            id,
            name,
            command,
            args,
            profile: config.profile.clone(),
            backend: Arc::clone(&backend),
            buffer: Arc::clone(&buffer),
            screen: Arc::clone(&screen),
            // Matches `ScreenConfig::default()` above, which matches
            // `PtySpawnConfig::new`. `set_screen_config` replaces both with
            // the geometry the child was actually spawned at.
            // **Zero means "no agent has asked"**, and it must not be
            // seeded from the start size: seeded, the session's opening
            // 80x24 would cap every attached client, so a 200-column
            // terminal would be clamped to 80 for no reason anybody chose.
            // A desired size only participates once something asks for one.
            desired_size: AtomicU32::new(0),
            size: AtomicU32::new(pack_size(
                ScreenConfig::default().cols,
                ScreenConfig::default().rows,
            )),
            rules,
            detector: Arc::clone(&detector),
            history: Arc::clone(&history),
            shell_integration: config.shell_integration,
            state: Mutex::new(SessionState::Running),
            redaction_stats: Mutex::new(BTreeMap::new()),
            binding_uses: Mutex::new(BTreeMap::new()),
            output_tx: output_tx.clone(),
            events_tx: events_tx.clone(),
            awaiting_secret: Arc::clone(&awaiting_secret),
            writes_performed: Arc::clone(&writes_performed),
            write_tx,
            last_activity_ms: Arc::clone(&last_activity_ms),
            exited_at_secs: Arc::new(AtomicI64::new(0)),
            idle_deadline_ms: Arc::clone(&idle_deadline_ms),
            idle_timeout_ms,
            clock: clock.clone(),
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
        let weak_screen = Arc::downgrade(&screen);
        let weak_detector = Arc::downgrade(&detector);
        let weak_history = Arc::downgrade(&history);
        let activity = Arc::clone(&last_activity_ms);
        let deadline = Arc::clone(&idle_deadline_ms);
        let reader_clock = clock.clone();
        let reader_backend = Arc::clone(&backend);
        let reader_rules = Arc::clone(&session.rules);
        // §4.5.1's responder is used from the reader thread alone, so it
        // needs no `Mutex` and no `Weak` — it is moved into the closure
        // and owned there for the life of the session.
        let mut responder = QueryResponder::new(
            config.terminal_queries,
            config.terminal_query_replies_per_min,
        );
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
                let (Some(buffer), Some(screen), Some(detector), Some(history)) = (
                    weak_buffer.upgrade(),
                    weak_screen.upgrade(),
                    weak_detector.upgrade(),
                    weak_history.upgrade(),
                ) else {
                    break;
                };
                // The chunk's absolute offset is what lets both consumers
                // line up with agent-visible cursors: the detector maps
                // OSC 133 spans onto it (0.0.2) and Tier B uses it to skip
                // bytes a re-seed already absorbed (spec §4.5). Computed
                // once, under one lock acquisition — reading `head()` a
                // second time would race the push.
                let base = {
                    let mut b = buffer.lock();
                    let base = b.head();
                    b.push(&buf[..n]);
                    base
                };

                // Published outside the buffer lock, and the error is
                // dropped on purpose: `send` fails only when nobody is
                // subscribed, which is the ordinary case.
                let _ = output_tx.send(OutputFrame {
                    start: base,
                    end: base + n as u64,
                    bytes: Arc::from(&buf[..n]),
                });

                // Push first, feed second: the seed comes from the ring
                // buffer, so this chunk must already be in it. `buffer` is
                // still alive here on purpose — it is the `SeedSource`,
                // which is why the `drop` below it moved down from where
                // 0.0.2 left it. Lock order `screen -> buffer`, never the
                // reverse.
                //
                // Sited *after* the fan-out rather than before it: this is
                // a VT100 parse on every chunk once Tier B is on, and ahead
                // of the `send` it would sit in `wait_for_pattern`'s
                // latency path for nothing.
                screen
                    .lock()
                    .feed(base, &buf[..n], Instant::now(), &*buffer);
                drop(buffer);

                // §4.5.1: answer Primary DA and nothing else. Written
                // through the backend directly and **never** through
                // `Session::write_input` — that is the agent's path and
                // it stamps `last_activity`, which would make a session a
                // child is querying in a loop immortal (REQ-TS-009). It
                // is also not a `send_input` audit event and never a
                // command-history entry, both of which follow from the
                // write never reaching `mcp::tools`: this block holds no
                // `AuditLog`, no `HoldfastServer` and no `Session`.
                //
                // The placement is not free. After the buffer push and
                // the fan-out, so the query's own bytes are in the ring
                // and published to `wait_for_pattern` subscribers before
                // the reply is written; before the detector feed, so a
                // reply cannot be reordered behind a classification that
                // the reply's own echo might change.
                for reply in responder.feed(&buf[..n], Instant::now()) {
                    // A closed master is the ordinary end of a session,
                    // not an error worth logging: the loop's own read
                    // will end it on the next pass.
                    let _ = reader_backend.write(reply);
                }

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
                // Sampled **before** the detector lock, exactly as
                // `Session::detection()` does. The cursor signal is not
                // sampled here at all, and that is not an economy: it
                // takes `screen` then `buffer`, so reading it under the
                // detector guard would be `detector → screen → buffer`
                // against the reader's own `screen → buffer` … `detector`
                // order. It is also unnecessary — the `AwaitingSecret`
                // rung is `echo == Some(false) && canonical != Some(false)
                // && !bracketed_paste`, and no cursor score can move it.
                let alive_now = reader_backend.is_alive();

                let mut detector_guard = detector.lock();
                let foreground = reader_backend.foreground_group();
                let events = detector_guard.feed(&buf[..n], base, foreground);

                // **REQ-SEC-010's edge, computed where the previous mode
                // can be held.** 0.0.2 ships a *sample* — `PromptDetector`
                // holds no previous mode and `detection()` is a pull-only
                // poll — so the transition is not computable from the
                // detector's state and the detector must stay a pure
                // classifier rather than grow one.
                //
                // The `ECHO` read is inside this critical section because
                // REQ-PD-019 requires it: sampling it outside is what
                // produced 267 spurious `AwaitingSecret` classifications
                // at 0.95 under load, by pairing a fresh echo-off with a
                // stale bracketed-paste-off. `line_discipline()` is one
                // `tcgetattr` yielding both flags.
                //
                // **Budgeted:** this adds **two** `WNOHANG` waits, one
                // `tcgetattr` and one classification per read chunk,
                // where there were none. Two and not one: `is_alive()` is
                // called directly above, and `line_discipline()` calls it
                // again internally (`pty/in_process.rs`). Harmless — the
                // only site that takes `child.lock()` holds it across
                // `try_wait()` and nothing else — but the budget is the
                // claim, so it says the number it costs. It does not add
                // a cursor read. The classification is pure —
                // `snapshot_at` reads the scanner and writes nothing — so
                // running it here cannot perturb what `detection()`
                // answers.
                //
                // **The residual of putting the edge here, measured:** a
                // child that drops `ECHO` and writes *nothing* raises no
                // request until its next byte of output, because this
                // loop only runs when a chunk arrives.
                // `sh -c 'stty -echo; read x'` is exactly that case and
                // produces no output at all. Every real secret prompt
                // draws one — which is what makes this the right place
                // for the edge rather than a poll — but a fixture that
                // does not print will look like a broken detector.
                let line = reader_backend.line_discipline();
                let snap = detector_guard.snapshot(alive_now, line, foreground, None);
                let now_awaiting = snap.interaction_mode == InteractionMode::AwaitingSecret;
                let prompt_line = snap.last_line.clone();
                drop(detector_guard);

                if awaiting_secret.swap(now_awaiting, Ordering::Relaxed) != now_awaiting {
                    // Fired **after** the guard is released: a subscriber
                    // that reacted by calling back into the session would
                    // otherwise re-enter the detector lock from inside it.
                    let _ = events_tx.send(if now_awaiting {
                        // Redacted on the way out, like every other string
                        // that leaves this process (§9.2). The prompt line
                        // is the child's own bytes and a password prompt
                        // is not the only thing that turns echo off.
                        SessionEvent::AwaitingSecretEntered {
                            // `redact_for_display` and not `redact_str`:
                            // this line becomes `AwaitingSecret.prompt_text`
                            // on every attached client, and `holdfast
                            // attach` writes that field to the terminal
                            // **unmodified** (GH #45).
                            //
                            // **Load-bearing, and an earlier revision of
                            // this comment said the opposite.** It said
                            // `prompt_line` was "already free of control
                            // characters" and called the strip defence in
                            // depth. That was a real measurement of
                            // `WRONG\x08…\rPassword: ` — which does reach
                            // the detector as exactly `Password: ` —
                            // generalised to a claim the measurement did
                            // not support.
                            //
                            // What actually reaches here: `detect::
                            // scanner`'s `ground` drops `0x00..=0x1f |
                            // 0x7f` and routes `0x1b` into the escape
                            // machine, so C0 and DEL are gone. But every
                            // byte `>= 0x80` falls to `text()`, and
                            // `TailLine::as_string`'s `from_utf8_lossy`
                            // reassembles `\xc2\x9b` as U+009B — so **all
                            // 32 C1 controls arrive intact**, as do U+202E
                            // and U+200B. `char::is_control` is true of
                            // every one of the 32, and this call is what
                            // removes them before `holdfast attach` writes
                            // the field to a terminal.
                            //
                            // There is also no strip **in the reader**:
                            // `detector_guard.feed(&buf[..n], …)` above is
                            // given the raw chunk. It is the scanner's own
                            // state machine that keeps escape *sequences*
                            // out of the tail, and it does that for `\x1b`
                            // introducers only.
                            //
                            // Pinned by `secret::binding`'s
                            // `a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act`,
                            // which drives U+009B out of a real child and
                            // asserts it is gone from the frame. The
                            // agent-supplied half of this field is the
                            // `prompt_text` argument, stripped in
                            // `mcp::tools` and pinned by that row's
                            // sibling.
                            prompt_text: crate::output::redact::redact_for_display(
                                &reader_rules,
                                &prompt_line,
                            ),
                        }
                    } else {
                        SessionEvent::AwaitingSecretLeft
                    });
                }
                if !events.is_empty() {
                    let at = now_ms();
                    let mut h = history.lock();
                    for ev in &events {
                        h.apply(ev, at);
                    }
                }
                drop(detector);
                drop(history);
                let at = reader_clock.now_ms();
                activity.store(at, Ordering::Relaxed);
                // The deadline moves with the stamp it is derived from,
                // at every site that bumps one (REQ-S-005/REQ-S-007).
                // Two atomics rather than one derived read, because the
                // reaper's sweep must not have to hold anything.
                deadline.store(deadline_from(at, idle_timeout_ms), Ordering::Relaxed);
            }

            // **§7.5's `SessionExited { code }`, at the one place a
            // session's end is observed rather than asked about.**
            //
            // The loop above leaves for three reasons and only one of
            // them is an exit: the `Session` was dropped while we idled,
            // a `Weak` failed to upgrade for the same reason, or the
            // child ended. A reader that stopped because the session went
            // away has no exit to announce and nobody left to hear it, so
            // that case is separated out first and costs nothing.
            //
            // **The loop ending is not the same event as the child being
            // reaped, and the difference is the whole of this block.** On
            // Linux the master reports the slave's last close as `EIO`,
            // which ends the `while let Ok(n)` immediately — while
            // `exit_code` comes from a `WNOHANG` wait that may not have
            // seen the child yet. Emitting on the read failure alone
            // would report `-1` for a child that exited `7`, and a client
            // believes an exit code. So the wait is given a bounded
            // moment, the same concession `mcp::tools`'s terminate path
            // already makes for the same reason. Bounded, because a
            // `read` that failed for some other cause must not park this
            // thread for the life of a live session.
            if weak_buffer.strong_count() > 0 {
                let reap_by = std::time::Instant::now() + EXIT_REAP_GRACE;
                while reader_backend.is_alive() && std::time::Instant::now() < reap_by {
                    std::thread::sleep(READER_IDLE_POLL);
                }
                if !reader_backend.is_alive() {
                    // **The same derivation `Session::state()` uses**, in
                    // the same order: `backend.exit_code()`, else `-1`.
                    // Two surfaces report this child's end — this frame
                    // and `Attached.exit_code` — and a second expression
                    // here is how they would come to disagree about the
                    // same child. `-1` is reachable only when the OS
                    // could not give a status at all, and it is what
                    // `SessionState::Exited` already carries in that case.
                    let code = reader_backend.exit_code().unwrap_or(-1);
                    // A `broadcast::Sender` with no live receivers returns
                    // `Err`, which here means "nobody was attached" and is
                    // not a failure.
                    let _ = events_tx.send(SessionEvent::Exited { code });
                }
            }
        });

        // §4.3's writer: **one `std::thread` per session, draining the
        // queue in arrival order.** Decided, not defaulted, for three
        // reasons that all point the same way:
        //
        // 1. `Session::new` is synchronous and has no runtime handle in
        //    scope. A `tokio::spawn` here panics with *"must be called
        //    from the context of a Tokio 1.x runtime"* in every `#[test]`
        //    in this file, all of which build a session through
        //    `mock_session()`.
        // 2. **A blocking PTY write must not sit on a tokio worker.** The
        //    master is a blocking fd; if a child stopped reading its
        //    terminal the write parks in the kernel, and Linux does not
        //    wake it when the child dies. On a runtime worker that parks
        //    the worker forever. `send_input` hands its write to the
        //    blocking pool for exactly this reason.
        // 3. The reader half beside it is already a `std::thread`, so
        //    both halves of §4.3's fan-out sit on the same kind of
        //    thread rather than split across two execution models.
        //
        // §4.3's pseudocode says `writer_task (one tokio task per
        // session)` and this does not contradict it: the pseudocode names
        // the *concurrency* — one serialising writer per session, FIFO —
        // not the executor. `tokio::sync::mpsc` is still the channel, and
        // `blocking_recv` is the documented way to drain one from outside
        // the runtime.
        //
        // **`Weak`, not `Arc`.** A strong reference would be a cycle: the
        // `Session` owns the `Sender` whose drop is this thread's exit
        // condition. Two exits, both correct — the channel closing
        // (`None`), and a `Session` that is already gone (`upgrade`
        // fails), which is what stops a `Sender` clone outliving its
        // session from parking this thread forever.
        let weak_session = Arc::downgrade(&session);
        std::thread::spawn(move || {
            while let Some(req) = write_rx.blocking_recv() {
                let Some(session) = weak_session.upgrade() else {
                    break;
                };
                match req {
                    WriteRequest::Input { bytes, ack } => {
                        // `write_input`, not a second write path. The
                        // liveness check, the `pre_write_head` sample and
                        // the activity stamp are all one statement away
                        // from the backend call there, and a queue that
                        // re-implemented them would be a second answer to
                        // each. The ack send fails when the caller
                        // dropped its receiver, which is the ordinary
                        // fire-and-forget case.
                        let _ = ack.send(session.write_input(&bytes));
                    }
                    // **The zeroing runs here, in the writer, after the
                    // PTY has the bytes.** `secret` is owned by this arm
                    // and dropped at its end, so no unzeroed copy of the
                    // value exists at any point: `with_bytes` lends the
                    // slice for the duration of the write and nothing
                    // else ever holds it.
                    WriteRequest::Secret { secret, ack } => {
                        let result = secret.with_bytes(|b| session.write_input(b));
                        drop(secret);
                        let _ = ack.send(result);
                    }
                    // §9.6's autofill. Both conditions are evaluated
                    // **here**, on the writer thread, one statement before
                    // the write — which is the only place where "the child
                    // is at an echo-off read" and "this value is the next
                    // thing it will receive" are still true together.
                    WriteRequest::SecretIfUnread {
                        secret,
                        expect_writes,
                        ack,
                    } => {
                        let _ = ack.send(write_secret_if_unread(&session, secret, expect_writes));
                    }
                }
            }
        });

        // Typed, not exported: rc files run after the environment is read
        // and would clobber an inherited PS1 (§8.5). A write failure here
        // is not fatal — the session simply degrades to tier 2.
        if let Some(shell) = config.shell_integration {
            let snippet = shell.integration_snippet();
            // §8.5.1 rule 5 (REQ-DM-009): the ring needs to know which line
            // Holdfast typed, because "it emits no `C`" stops being true the
            // moment a foreign emitter is already installed — the user's
            // `PS0` marks the snippet's own command line and the snippet
            // becomes the session's first history entry.
            //
            // **Before the write, not after.** The reader thread is already
            // running; a snippet whose `C` arrived before `set_injection_line`
            // landed would be recorded.
            session
                .history
                .lock()
                .set_injection_line(snippet.to_string());
            let mut line = snippet.as_bytes().to_vec();
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
        // Sampled *before* `detector.lock()` — the opposite of the two
        // samples below, and for a reason that does not apply to them.
        //
        // Mechanically it has to be: this takes `screen` and then
        // `buffer` (a re-seed reads the ring buffer), so holding
        // `detector` across it would make this path
        // `detector -> screen -> buffer` while the reader thread runs
        // `screen -> buffer` and then `detector`. Neither holds two at
        // once today; nesting them here is the change that would make a
        // cycle possible.
        //
        // And unlike the line discipline it is safe outside: a chunk
        // arriving between this sample and the classification can only
        // make the cursor score *stale*, never contradictory. `echo` had
        // to move inside because a stale `echo == false` pairs with a
        // fresh bracketed-paste-off to satisfy a *deterministic* rung
        // outright. `cursor_score` reaches only the T3 branch, through
        // `quiescent_score * max(pattern, cursor)` — and that same
        // arriving chunk resets quiescence under this very lock, so it
        // drives confidence down. A stale cursor cannot manufacture a
        // high one.
        let cursor = self.cursor_signal().map(|c| c.score);
        let mut detector = self.detector.lock();
        let line = self.backend.line_discipline();
        let foreground = self.backend.foreground_group();
        detector.snapshot(alive, line, foreground, cursor)
    }

    /// Whose OSC 133 markers this session is **using** (§18.2a, §8.5.1).
    ///
    /// Not the same question as `shell_integration`, which records only
    /// what Holdfast injected and is fixed at spawn: a session can report
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

    /// This session's configured quiescence window (§4.2), forwarded from
    /// the detector so a caller does not have to re-derive it from config.
    pub fn settle_threshold_ms(&self) -> u64 {
        self.detector.lock().settle_threshold_ms()
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
            self.latch_exit_time();
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

    /// Stamp the exit time, once, the first time anything observes the
    /// child gone.
    ///
    /// `compare_exchange`, not a store: this runs on every response and
    /// several responses run concurrently, so a plain store would move
    /// the reported instant forward on every call. A timestamp that
    /// drifts is worse than none, and a single-read test cannot see it.
    fn latch_exit_time(&self) {
        let _ = self.exited_at_secs.compare_exchange(
            0,
            now_secs(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Unix seconds at which this session's exit was first observed
    /// (§5.2's `exited_at_unix_secs`), or `None` while it is alive.
    ///
    /// **Observation time, and every observer counts** — not just
    /// `state()`. `terminate`'s idempotent path reports the exit without
    /// ever calling `state()`, so a latch armed only there answered
    /// `null` on the one response whose whole subject is that the session
    /// has exited. Caught by `every_emitted_unix_field_is_a_number`,
    /// which requires the field to be seen as a real number somewhere.
    pub fn exited_at_secs(&self) -> Option<u64> {
        if self.exited_at_secs.load(Ordering::Relaxed) == 0 && !self.backend.is_alive() {
            self.latch_exit_time();
        }
        match self.exited_at_secs.load(Ordering::Relaxed) {
            0 => None,
            secs => Some(secs as u64),
        }
    }

    pub fn last_activity_ms(&self) -> i64 {
        self.last_activity_ms.load(Ordering::Relaxed)
    }

    /// §7.5's non-output edges. Each attach connection takes one, exactly
    /// as it takes an output receiver.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SessionEvent> {
        self.events_tx.subscribe()
    }

    /// Whether the reader's most recent classification was
    /// `AwaitingSecret`.
    ///
    /// **This is the state, not the edge**, and it exists for the one
    /// case the edge cannot serve: a client that attaches while a secret
    /// prompt is already up missed the transition, and §7.5 requires it
    /// to be told anyway.
    pub fn is_awaiting_secret(&self) -> bool {
        self.awaiting_secret.load(Ordering::Relaxed)
    }

    /// The child's line discipline, sampled **now** — one `tcgetattr`.
    ///
    /// **Live, unlike [`is_awaiting_secret`](Self::is_awaiting_secret),
    /// which is a cache.** That flag's only writer is the reader thread,
    /// and that loop runs only when a chunk arrives from the child — the
    /// same statement this file already makes about the *entry* edge
    /// (*"a child that drops `ECHO` and writes nothing raises no request
    /// until its next byte of output"*) is true of the *exit* edge too.
    /// So a child that restores echo and then prints nothing leaves the
    /// flag reading `true` for an unbounded time, and anything that has to
    /// know whether the child is *still* at an echo-off read must ask
    /// here instead.
    pub fn line_discipline(&self) -> crate::pty::LineDiscipline {
        self.backend.line_discipline()
    }

    /// How many writes this session's PTY has taken — see the field.
    pub fn writes_performed(&self) -> u64 {
        self.writes_performed.load(Ordering::Relaxed)
    }

    /// The prompt line the child has drawn, redacted (§9.2).
    ///
    /// Used by the replay path, which needs the text at *attach* time
    /// rather than at the edge. May legitimately be empty (REQ-O-013).
    pub fn prompt_last_line_redacted(&self) -> String {
        // Redacted **and** reduced to one line of plain text: every
        // caller hands this to a human — `AwaitingSecret.prompt_text`,
        // which `holdfast attach` writes to the terminal unmodified, and
        // the approval prompt (GH #45). See `redact_for_display` for why
        // the strip runs before the redaction.
        //
        // **The strip is load-bearing here**, and an earlier revision of
        // this comment said it was not. It claimed the line "carries no
        // control characters to begin with" because it had "been through
        // the reader's ANSI stripper" — neither half holds. There is no
        // stripper in the reader (the detector is fed the raw chunk), and
        // `detect::scanner`'s `ground` drops only `0x00..=0x1f | 0x7f`:
        // every byte `>= 0x80` reaches the tail, so a child emitting
        // `\xc2\x9b` puts U+009B — a C1 control — in `last_line`, along
        // with the other 31, U+202E and U+200B.
        //
        // That matters because both callers render raw:
        // `AwaitingSecret.prompt_text`, which `holdfast attach` writes to
        // the terminal unmodified, and the approval prompt (GH #45). See
        // `redact_for_display` for why the strip runs before the
        // redaction, and `secret::binding`'s
        // `a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act`
        // for the row that fails if this becomes `redact_str`.
        crate::output::redact::redact_for_display(&self.rules, &self.detection().last_line)
    }

    pub fn buffer_head(&self) -> u64 {
        self.buffer.lock().head()
    }

    pub fn buffer_tail(&self) -> u64 {
        self.buffer.lock().tail()
    }

    /// `(tail, head)` from **one** lock acquisition, so the pair describes
    /// a single instant. Two separate accessor calls can straddle a push
    /// and produce an extent that never existed.
    pub fn buffer_extent(&self) -> (u64, u64) {
        let buffer = self.buffer.lock();
        (buffer.tail(), buffer.head())
    }

    /// Copy the absolute range `[start, end)`, clamped to what the buffer
    /// still holds.
    pub fn buffer_slice(&self, start: u64, end: u64) -> Vec<u8> {
        self.buffer.lock().slice(start, end)
    }

    /// Put Holdfast's **own** bytes into this session's output buffer and
    /// on the wire — §9.5's buffer notice, and nothing else so far.
    ///
    /// **Three things this deliberately does not do**, each of which is a
    /// plausible implementation and each of which is a defect:
    ///
    /// 1. **It is not written to the PTY.** §9.5 says the *output buffer*.
    ///    Writing it to the child's stdin submits
    ///    `[holdfast] awaiting secret input…` as the **secret**, to a
    ///    program that is at that moment reading one.
    /// 2. **It does not feed the detector.** The notice would become the
    ///    session's last logical line, replacing `prompt.last_line` — the
    ///    text a keychain binding's `match_prompt` matches against, the
    ///    text `status` reports, and the text a later `AwaitingSecret`
    ///    broadcasts. A notice that changes what a binding matches is a
    ///    notice that silently disables an operator's configuration.
    /// 3. **It does not bump `last_activity`.** This is Holdfast's own
    ///    text, not an input or output event from a ReadWrite path
    ///    (REQ-S-006). A session that keeps itself alive by announcing
    ///    that it is stuck is a session that never reaps.
    ///
    /// **It is the second producer into two structures that have had
    /// exactly one, so it derives its offsets exactly the way the reader
    /// thread does**: `head()` sampled *inside* the buffer lock that
    /// pushes, and the frame published *outside* it. `OutputFrame`'s
    /// `start`/`end` are buffer offsets, so sampling the head outside the
    /// lock — or broadcasting without pushing — makes the frames and the
    /// buffer disagree about where byte 0 is.
    ///
    /// Synchronous, and that is not a style preference: this module
    /// carries 37 `#[test]`s and no `#[tokio::test]`, and an `async`
    /// signature drags a runtime into every one of them.
    pub fn inject_notice(&self, bytes: &[u8]) {
        let base = {
            let mut b = self.buffer.lock();
            let base = b.head();
            b.push(bytes);
            base
        };
        // The error is dropped on purpose: `send` fails only when nobody
        // is subscribed, which for a session with no client attached —
        // the only situation that writes a notice — is the ordinary case.
        let _ = self.output_tx.send(OutputFrame {
            start: base,
            end: base + bytes.len() as u64,
            bytes: Arc::from(bytes),
        });
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

    /// Subscribe to this session's live output frames.
    ///
    /// Subscribing is lock-free and takes effect immediately, so a caller
    /// that subscribes *before* snapshotting the buffer sees every byte
    /// written after the snapshot — the ordering §5.2's two-phase scan
    /// requires.
    pub fn subscribe(&self) -> broadcast::Receiver<OutputFrame> {
        self.output_tx.subscribe()
    }

    /// A handle on §4.3's write queue.
    ///
    /// Cloned per producer, so every attach connection on a session
    /// pushes into the same FIFO and the writer thread is the only thing
    /// that touches the PTY's input side. A full queue backs the
    /// *producer* up — `send().await` on a bounded `mpsc` — and never the
    /// reader.
    pub fn write_queue(&self) -> tokio::sync::mpsc::Sender<WriteRequest> {
        self.write_tx.clone()
    }

    /// Where a read of this session must stop right now (§4.1):
    /// `buffer.head` unless a secret is still arriving in the trailing
    /// region.
    ///
    /// **The identical predicate `read_processed` applies** (REQ-O-004) —
    /// it is the same `OutputProcessor::holdback_boundary` call, over a
    /// snapshot of the same trailing region. `wait_for_pattern` needs the
    /// boundary as a *value* rather than as a flag, to decide whether a
    /// match intersects the withheld region; that is the only reason this
    /// is exposed separately, and it must never become a second rule.
    pub fn holdback_boundary(&self, processor: &OutputProcessor) -> u64 {
        self.holdback_snapshot(processor).0
    }

    /// The §4.1 boundary as an **open** value: `Some(b)` only when bytes
    /// really are withheld, `None` when nothing is.
    ///
    /// **`holdback_boundary` answers "nothing withheld" with a *value* —
    /// `w.head` — and that value is only distinguishable from a real
    /// boundary against the head sampled in the same snapshot.** Every
    /// consumer that re-reads `buffer.head()` afterwards is comparing a
    /// head from `T2` against a boundary from `T1`, so any byte that
    /// arrives in between reads as "a secret is still arriving" when
    /// nothing is. The pairing is done *here*, inside the one lock that
    /// saw both numbers, so no caller can get it wrong.
    ///
    /// `boundary == head` is unambiguous: `earliest_partial` returns the
    /// start of a match of at least one byte, so a real partial always
    /// begins strictly before `head`.
    pub fn open_holdback(&self, processor: &OutputProcessor) -> Option<u64> {
        let (boundary, head) = self.holdback_snapshot(processor);
        (boundary < head).then_some(boundary)
    }

    /// The §4.1 boundary **and** the head it was measured against, from
    /// one `buffer.lock()`. The pair is the unit of truth; see
    /// [`open_holdback`](Self::open_holdback) for why splitting it is a
    /// defect rather than a style choice.
    fn holdback_snapshot(&self, processor: &OutputProcessor) -> (u64, u64) {
        let limits = processor.limits;
        let (tail_region, scan_start, head) = {
            let buffer = self.buffer.lock();
            let head = buffer.head();
            let tail = buffer.tail();
            let scan_start = head
                .saturating_sub(limits.partial_secret_scan_bytes as u64)
                .max(tail);
            (buffer.slice(scan_start, head), scan_start, head)
        };
        let snapshot = WindowSnapshot {
            window: &[],
            window_start: head,
            tail_region: &tail_region,
            tail_region_start: scan_start,
            req_start: head,
            head,
            cap_end: head,
            child_alive: self.backend.is_alive(),
            bypass_holdback: false,
            front_clipped: false,
            truncated_at_tail: false,
        };
        (
            processor.holdback_boundary(&snapshot, &ReadOptions::default()),
            head,
        )
    }

    /// A snapshot of the cumulative per-session redaction tally.
    ///
    /// Empty (`{}`), never absent, when nothing has been redacted — the
    /// caller serialises it as an empty map so `status` reports a
    /// truthful zero rather than omitting the key (REQ-O-012).
    pub fn redaction_stats(&self) -> BTreeMap<String, u64> {
        self.redaction_stats.lock().clone()
    }

    /// A snapshot of this session's §9.6 `max_uses` tally, keyed by
    /// binding name. Read-only; see [`Session::claim_binding_use`].
    pub fn binding_uses(&self) -> crate::secret::binding::BindingUses {
        self.binding_uses.lock().clone()
    }

    /// Reserve one use of `binding` against this session's budget.
    ///
    /// `Some(n)` is a granted claim and `n` is the use count **including
    /// this one** — `1` on the first resolution, which is what
    /// `binding_resolved.use_count` carries. `None` means the budget is
    /// spent and the caller falls through to the prompt path (Decision 18).
    ///
    /// **`None` and `Some(0)` both mean unlimited.** §9.6 documents
    /// `0 = unlimited` and says nothing at all about an omitted knob; an
    /// omitted knob and an explicitly-zero one must not differ, and
    /// unlimited is the only reading under which omitting `max_uses`
    /// leaves a binding usable.
    ///
    /// **The test and the increment are one critical section**, which is
    /// what makes "the third resolution in this session falls through" a
    /// fact rather than a race between two calls that both read the count
    /// and then both incremented it. A caller that reserved and then
    /// failed gives the claim back with
    /// [`release_binding_use`](Session::release_binding_use).
    pub fn claim_binding_use(&self, binding: &str, max_uses: Option<u32>) -> Option<u32> {
        let mut uses = self.binding_uses.lock();
        // Read rather than `entry(..).or_insert(0)`: a refused claim must
        // not leave a zero behind, or `binding_uses()` reports a binding
        // as having been used when it never was.
        let count = uses.get(binding).copied().unwrap_or(0);
        if max_uses.is_some_and(|max| max > 0 && count >= max) {
            return None;
        }
        uses.insert(binding.to_string(), count + 1);
        Some(count + 1)
    }

    /// Give back a claim [`claim_binding_use`](Session::claim_binding_use)
    /// granted, for a resolution that then did not happen.
    ///
    /// Keeps `max_uses` a bound on **resolutions** rather than on
    /// attempts: an operator who wrote `max_uses = 2` against a keyring
    /// that happens to be locked must not find the budget gone with no
    /// credential ever resolved. Saturating, so a stray release cannot
    /// wrap the counter into an enormous remaining budget.
    pub fn release_binding_use(&self, binding: &str) {
        let mut uses = self.binding_uses.lock();
        if let Some(count) = uses.get_mut(binding) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                uses.remove(binding);
            }
        }
    }

    /// Fold one processed read's per-response counts into the session
    /// tally. Called from `read_processed` and nowhere else.
    fn note_redactions(&self, counts: &BTreeMap<String, usize>) {
        if counts.is_empty() {
            return;
        }
        let mut stats = self.redaction_stats.lock();
        for (kind, n) in counts {
            *stats.entry(kind.clone()).or_insert(0) += *n as u64;
        }
    }

    /// Read through the output processor: ANSI strip, redaction, the
    /// targeted holdback, and text encoding (spec §4.1).
    ///
    /// The buffer lock is held only to copy the expanded window and the
    /// partial-secret scan region; every regex runs outside it, honouring
    /// the §4.3 "no work under the buffer lock" invariant.
    pub fn read_processed(&self, req: &ReadRequest, processor: &OutputProcessor) -> ProcessedRead {
        // Liveness decides whether an unfinished escape can still be
        // completed; read it before taking the lock (§4.1).
        let child_alive = self.backend.is_alive();
        let limits = processor.limits;

        let (
            window,
            window_start,
            tail_region,
            scan_start,
            req_start,
            head,
            tail,
            cap_end,
            front_clipped,
        ) = {
            let buffer = self.buffer.lock();
            let head = buffer.head();
            let tail = buffer.tail();
            let requested_start = match req.start {
                ReadStart::Cursor(c) => c.clamp(tail, head),
                ReadStart::TailBytes(n) => buffer.tail_bytes_start(n),
                ReadStart::TailLines(n) => buffer.tail_lines_start(n),
            };
            // A `tail_*` read asks for the *newest* bytes, so when its
            // extent exceeds `max_bytes` the OLDEST bytes are dropped and
            // the cursor still lands past `buffer.head`. Capping forward
            // instead would return the oldest slice and hand back a cursor
            // far behind `head`, which re-delivers the same bytes on every
            // subsequent cursor read (0.0.1's documented contract, REQ-T-006).
            let (req_start, front_clipped) = if req.start.bypasses_holdback() {
                let clipped = head
                    .saturating_sub(req.max_bytes as u64)
                    .max(requested_start);
                (clipped, clipped > requested_start)
            } else {
                (requested_start, false)
            };
            let cap_end = req_start.saturating_add(req.max_bytes as u64).min(head);
            let window_start = req_start
                .saturating_sub(limits.lookbehind_bytes as u64)
                .max(tail);
            let window_end = cap_end
                .saturating_add(limits.lookahead_bytes as u64)
                .min(head);
            let scan_start = head
                .saturating_sub(limits.partial_secret_scan_bytes as u64)
                .max(tail);
            (
                buffer.slice(window_start, window_end),
                window_start,
                buffer.slice(scan_start, head),
                scan_start,
                req_start,
                head,
                tail,
                cap_end,
                front_clipped,
            )
        };

        let truncated_at_tail = matches!(req.start, ReadStart::Cursor(c) if c < tail);
        let snapshot = WindowSnapshot {
            window: &window,
            window_start,
            tail_region: &tail_region,
            tail_region_start: scan_start,
            req_start,
            head,
            cap_end,
            child_alive,
            bypass_holdback: req.start.bypasses_holdback(),
            front_clipped,
            truncated_at_tail,
        };
        let read = processor.process(&snapshot, &req.options);

        // Fold this response's counts into the session tally that
        // `status.redaction_stats` reports (§5.2, REQ-O-012). It is fed
        // from `read.redactions` but is a *different* quantity: two
        // overlapping reads of one secret leave each response reporting 1
        // while this reaches 2. Never serve one of the two from the other.
        self.note_redactions(&read.redactions);

        // Both of these are audit obligations of the *read*, so they live
        // here rather than in each transport that calls it (§9.2, §9.4).
        if !req.options.redact {
            processor
                .audit
                .record_redaction_disabled(Some(&self.id), req.tool, req.client_kind);
        }
        if truncated_at_tail {
            if let ReadStart::Cursor(c) = req.start {
                processor
                    .audit
                    .record_truncated_at_tail(&self.id, req.tool, c, tail);
            }
        }
        read
    }

    /// Apply the session's real geometry and `screen_tracking` mode.
    ///
    /// **Call this exactly once, immediately after construction and
    /// before the session is registered** (`start_session` does). It
    /// replaces the whole tracker, and the reader thread is already
    /// running by then: bytes the child emitted in between are still in
    /// the ring buffer, so a later seed recovers them for the *grid*, but
    /// the new tracker's Tier-A probe starts blank, so a bracketed-paste
    /// or OSC 133 sequence that landed in that window is not latched and
    /// the §4.5 three-second no-signal trigger can fire on a session that
    /// did emit one. The window is microseconds before any shell has
    /// printed a prompt; calling this later widens it for no gain.
    /// It is also where the session learns the geometry it was spawned at
    /// — `Session::new` is handed a `SessionConfig`, which carries none —
    /// so `size()` answers from the same numbers the Tier-B grid is built
    /// against rather than from a second copy that could disagree with it.
    pub fn set_screen_config(&self, cfg: ScreenConfig) {
        self.size
            .store(pack_size(cfg.cols, cfg.rows), Ordering::Relaxed);
        *self.screen.lock() = ScreenTracker::new(cfg, Arc::clone(&self.rules), Instant::now());
    }

    /// The PTY's current dimensions as `(cols, rows)` — what `resize`
    /// reports back, read after the backend call rather than echoed from
    /// the request.
    pub fn size(&self) -> (u16, u16) {
        unpack_size(self.size.load(Ordering::Relaxed))
    }

    /// The geometry an agent asked for, independent of what any attached
    /// terminal can display, or `None` if none has (GH #75).
    ///
    /// `None` is not the same as "the size it started at": an unasked-for
    /// geometry must not cap an attached client, or a session would clamp
    /// every terminal to its opening 80x24.
    pub fn desired_size(&self) -> Option<(u16, u16)> {
        match self.desired_size.load(Ordering::Relaxed) {
            0 => None,
            packed => Some(unpack_size(packed)),
        }
    }

    /// Record a new desired geometry. **Does not resize anything** — the
    /// caller folds this with the attached writers and applies the result,
    /// because only the attach hub knows who is looking.
    pub fn set_desired_size(&self, cols: u16, rows: u16) {
        self.desired_size
            .store(pack_size(cols, rows), Ordering::Relaxed);
    }

    /// Resize the terminal (spec §5.2 `resize`, REQ-T-009): `SIGWINCH` to
    /// the child, then the two pieces of Holdfast-side state that describe the
    /// same geometry.
    ///
    /// **Backend first, and the ordering is the contract.** The stored size
    /// is what `size()` reports, so writing it before the `ioctl` would
    /// have `resize` answering with dimensions the terminal never reached
    /// when the call fails.
    ///
    /// The tracker is told too, because this milestone introduces the one
    /// thing in the tree whose correctness depends on the dimensions: a
    /// `vt100::Parser` constructed from `ScreenConfig` and otherwise never
    /// told the size changed would leave `get_screen_state` rendering a
    /// 132×43 session through an 80×24 grid, silently and with no error
    /// anywhere.
    ///
    /// **The clamp is here because this is the funnel.** `resize` the tool
    /// reaches it, and so does every internal caller; `start_session`
    /// cannot (it has no session yet when it spawns the child), so it
    /// applies the same [`clamp_geometry`] to its `PtySpawnConfig` before
    /// the spawn. Clamping *before* the backend call is what keeps the
    /// child's `winsize`, the stored size and the tracker's grid one
    /// number rather than three — and since `size()` is what the tool
    /// reports, the agent is told the geometry it got rather than the one
    /// it asked for.
    ///
    /// **The ring buffer goes with it, because a width shrink re-seeds the
    /// tracker rather than resizing its parser** — see
    /// [`ScreenTracker::resize`] for why `vt100::set_size` is unsafe in
    /// that direction. The locks are taken `screen → buffer`, which is the
    /// order the tracker documents and the one `capture` already uses.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let (cols, rows) = clamp_geometry(cols, rows);
        self.backend.resize(cols, rows)?;
        self.size.store(pack_size(cols, rows), Ordering::Relaxed);
        self.screen.lock().resize(cols, rows, &*self.buffer);
        Ok(())
    }

    /// `screen_tracking` for the agent-facing responses: `"off"` or
    /// `"on"` per spec §18.2a — whether Tier B is *running*, not which
    /// mode was configured.
    ///
    /// The two-valued wire enum is derived from the policy's `enabled`
    /// flag inside the tracker, never from `ScreenTracking::as_str()`,
    /// which has a third spelling (`"adaptive"`) that no response schema
    /// accepts. A response builder calls **this**.
    pub fn screen_tracking(&self) -> &'static str {
        self.screen.lock().tracking_state()
    }

    /// Serve `get_screen_state`. Enables Tier B if it is off and the
    /// session's mode allows it, at the cost of one buffer re-seed.
    ///
    /// `redact` is §5.2's argument, already defaulted by the caller — the
    /// tool layer resolves `None` to `true` and writes §9.4's
    /// `redaction_disabled` entry when it is false, because that is where
    /// the caller is known. A `bool` here rather than an `Option` so the
    /// default cannot be re-decided in two places.
    ///
    /// **The `processor` is here for §4.1's boundary, and taking it as an
    /// argument is what keeps the grid on the same rule as every other
    /// read.** `get_screen_state` has no `tail_lines`/`tail_bytes` to opt
    /// out with, so it is inside the holdback (REQ-O-003) and the tracker
    /// masks the cells the withheld bytes wrote. The boundary is computed
    /// **before** the screen lock is taken: a re-seed reaches into the
    /// ring buffer, so the lock order is `screen → buffer` and this call
    /// must not hold the screen while it takes the buffer.
    pub fn screen_state(
        &self,
        diff_from: Option<u64>,
        redact: bool,
        processor: &OutputProcessor,
    ) -> ScreenCapture {
        // **`open_holdback`, not `Some(holdback_boundary(..))`.** The
        // tracker re-samples its own `consumed_head` when it seeds, so a
        // `Some(head)` handed down from here is a `T1` boundary judged
        // against a `T2` head: bytes that arrive in between make the
        // tracker mask cells for a secret nobody is withholding. The
        // pairing has to happen where both numbers were read.
        let holdback = self.open_holdback(processor);
        self.screen
            .lock()
            .capture(diff_from, redact, Instant::now(), &*self.buffer, holdback)
    }

    /// The §8.6 T3c cursor sub-signal, or `None` when Tier B is off.
    /// Also advances the adaptive policy clock, so a session that has
    /// gone quiet still reaches its enable and disable deadlines.
    pub fn cursor_signal(&self) -> Option<CursorSignal> {
        self.screen
            .lock()
            .cursor_signal(Instant::now(), &*self.buffer)
    }

    /// Bytes this session has handed to a `vt100::Parser`. Zero for a
    /// session that never enabled Tier B; the §11.4 write-path guard
    /// asserts exactly that.
    pub fn vt100_bytes_parsed(&self) -> u64 {
        self.screen.lock().parsed_bytes()
    }

    pub fn write_input(&self, data: &[u8]) -> Result<usize> {
        self.write_input_acked(data).map(|ack| ack.bytes_written)
    }

    /// `write_input`, plus the `buffer.head` sampled **immediately before**
    /// the write reached the backend.
    ///
    /// That cursor is what `send_input(wait_for=)` uses as the start of
    /// `output_since_start` (§5.2). Sampling it in the handler instead
    /// races the child's echo: a fast command's first bytes land between
    /// the handler's snapshot and the write, and then disappear from the
    /// context the agent is shown. Taking it here means it is sampled on
    /// the same thread as the write, one statement before it.
    pub fn write_input_acked(&self, data: &[u8]) -> Result<WriteAck> {
        // A real PTY fails a write to a dead child with EIO, but a
        // non-blocking test backend does not. Checking here means the
        // behaviour is the same on both.
        if !self.backend.is_alive() {
            return Err(HoldfastError::SessionDied);
        }
        let pre_write_head = self.buffer.lock().head();
        self.backend.write(data)?;
        // **After the backend took it**, so the count is of writes the
        // child can have seen. A failed write must not move it: §9.6's
        // autofill refuses a credential when this changed under it, and a
        // write that never reached the PTY satisfied no read.
        self.writes_performed.fetch_add(1, Ordering::Relaxed);
        self.touch();
        Ok(WriteAck {
            bytes_written: data.len(),
            pre_write_head,
        })
    }

    /// Signals are *not* liveness-guarded: terminating an
    /// already-exited session is a no-op, not an error, so `terminate`
    /// stays idempotent.
    ///
    /// **This bumps activity, which the reaper must account for.** A
    /// SIGTERM refreshes `last_activity_ms`, so an escalation that
    /// re-derived "still idle" from the stamp after signalling would
    /// never escalate. `session::reaper` tracks its own
    /// SIGTERM-then-SIGKILL state for exactly that reason.
    pub fn signal(&self, sig: Signal) -> Result<()> {
        self.backend.signal(sig)?;
        self.touch();
        Ok(())
    }

    /// Stamp activity for an event that mutated the session without
    /// going through `write_input` or `signal` (§4.1, REQ-S-006).
    ///
    /// **The one such event in 0.0.6 is an attach `Resize` from a
    /// ReadWrite client**, and this exists rather than a `touch()` inside
    /// `Session::resize` because the two callers of `resize` are not the
    /// same kind of event. §4.1 enumerates what bumps `last_activity` and
    /// lists *"attach `Input`/`SecretInput`/`Resize`/`Signal` frames from
    /// ReadWrite clients"*; it does not list the `resize` **tool**, which
    /// is an agent adjusting its own view. Putting the stamp inside
    /// `resize` would silently make an agent's geometry poke keep a
    /// session alive, which is the class of thing REQ-C-005 exists to
    /// stop — and it would do so with no test able to see it, because
    /// nothing asserts what the tool does *not* do.
    pub fn note_activity(&self) {
        self.touch();
    }

    /// Stamp activity now and move the idle deadline with it.
    ///
    /// One function rather than two stores at each site: the deadline is
    /// derived from the stamp, and a site that updated one without the
    /// other would leave a session reapable while it was busy — or
    /// immortal while it was idle — with nothing that fails.
    fn touch(&self) {
        let at = self.clock.now_ms();
        self.last_activity_ms.store(at, Ordering::Relaxed);
        self.idle_deadline_ms
            .store(deadline_from(at, self.idle_timeout_ms), Ordering::Relaxed);
    }

    /// The absolute instant this session becomes reapable, in Unix
    /// epoch milliseconds. `None` when `idle_timeout_secs` is `0` and
    /// reaping is disabled for it (REQ-S-004).
    pub fn idle_deadline_ms(&self) -> Option<i64> {
        match self.idle_deadline_ms.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    /// The resolved per-session idle timeout in seconds, `0` when
    /// reaping is disabled.
    pub fn idle_timeout_secs(&self) -> u64 {
        (self.idle_timeout_ms / 1000).max(0) as u64
    }

    /// Whether this session is past its idle deadline on `now_ms`.
    ///
    /// A session with reaping disabled is **skipped**, not compared: the
    /// naive `now - last >= 0` a zero timeout produces reaps immediately,
    /// which is the opposite of what `0` means.
    pub fn is_past_idle_deadline(&self, now_ms: i64) -> bool {
        match self.idle_deadline_ms() {
            None => false,
            Some(deadline) => now_ms >= deadline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{DetectionTier, InteractionMode, PatternSet, PromptPattern};
    use crate::pty::{MockPty, MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS};
    use crate::screen::{ScreenCapture, ScreenGrid, ScreenTracking};
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
            Err(HoldfastError::SessionDied)
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

    // ------------------------------------------------ 0.0.3 read path

    // `Session`, `SessionConfig`, `new_session_id`, `PtyBackend`, `Arc`
    // and `OutputProcessor` all arrive through the block's existing
    // `use super::*;` (they live in this module or are imported by it).
    // Re-importing any of them is `error[E0252]`.
    use crate::audit::AuditLog;
    use crate::output::rules::RuleSet;
    use crate::output::{ProcessingLimits, ReadRequest, ReadStart};

    const GITHUB: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    /// A processor writing to a real audit file, so the audit assertions
    /// exercise the same path production uses.
    fn processor_with_audit(dir: &std::path::Path) -> OutputProcessor {
        let rules = Arc::new(RuleSet::builtin().unwrap());
        let audit = Arc::new(AuditLog::to_path(dir.join("audit.log"), Arc::clone(&rules)).unwrap());
        OutputProcessor::new(rules, audit, ProcessingLimits::default())
    }

    fn audit_kinds(p: &OutputProcessor) -> Vec<String> {
        let text = std::fs::read_to_string(p.audit.path().unwrap()).unwrap();
        text.lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn read_processed_redacts_and_keeps_the_surrounding_output() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        let line = format!("export TOKEN={GITHUB}\nnext\n");
        pty.queue_output(line.as_bytes());
        wait_for_bytes(&s, line.len() as u64);

        let r = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        assert!(!r.output.contains(GITHUB), "secret leaked: {}", r.output);
        // Asserting absence alone would pass against a read that returned
        // nothing, so pin the surviving text as well.
        assert_eq!(r.output, "export TOKEN=[REDACTED:github]\nnext\n");
        assert_eq!(r.cursor, line.len() as u64);
        assert!(!r.held_back);
    }

    /// C-1 on the real read path (§4.1: *"a secret that was partially in
    /// the previous chunk is fully redacted again in the next chunk, with
    /// no leak"*).
    ///
    /// The unit test in `output` pins the same invariant against a
    /// hand-built snapshot; the geometry that actually decides whether a
    /// continuation read can still see `-----BEGIN` is *this* function's
    /// (`window_start = req_start − lookbehind_bytes`), so it is pinned
    /// here as well. A 1.6 KB key is three times the 512-byte lookbehind:
    /// a cursor left inside it can never be recovered from, and the leak
    /// carries `redactions: {}` and no audit entry, so nothing downstream
    /// can tell it happened.
    #[test]
    fn paging_a_capped_read_over_a_private_key_leaks_nothing_through_the_session() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();

        let mut lines: Vec<String> = Vec::new();
        for i in 0..24u32 {
            let mut line = String::new();
            while line.len() < 64 {
                line.push_str(&format!("MIIEow{i:02}IBAAKCAQEAy8Dbv8prpJ"));
            }
            line.truncate(64);
            lines.push(line);
        }
        let body = lines.join("\n");
        let stream = format!(
            "cat id_rsa\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n\
             -----END RSA PRIVATE KEY-----\ndone\n"
        );
        pty.queue_output(stream.as_bytes());
        wait_for_bytes(&s, stream.len() as u64);

        // `max_bytes: 1024` is an ordinary agent choice made to save
        // tokens, and against this key it splits deterministically.
        let mut joined = String::new();
        let mut cursor = 0u64;
        let mut reads = 0usize;
        loop {
            reads += 1;
            // Bounded, so a cursor that stops advancing fails here rather
            // than hanging CI.
            assert!(reads <= 16, "paging did not terminate (cursor {cursor})");
            let r = s.read_processed(&ReadRequest::since(cursor, 1024), &p);
            joined.push_str(&r.output);
            match r.next_cursor {
                Some(next) => {
                    assert!(next > cursor, "the cursor stalled at {cursor}");
                    cursor = next;
                }
                None => break,
            }
        }
        assert!(reads >= 2, "the cap must actually have split the read");
        for start in 0..=body.len() - 32 {
            assert!(
                !joined.contains(&body[start..start + 32]),
                "key material leaked at body offset {start}: {joined}"
            );
        }
        assert_eq!(joined, "cat id_rsa\n[REDACTED:private-key]\ndone\n");
    }

    #[test]
    fn read_processed_holds_an_in_flight_token_and_releases_it_on_completion() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"line one\nghp_abcdef");
        wait_for_bytes(&s, 18);

        let first = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        assert!(first.held_back, "an in-flight token must stop the read");
        assert_eq!(first.output, "line one\n");
        assert_eq!(first.cursor, 9);
        assert_eq!(first.next_cursor, Some(9));

        pty.queue_output(b"ghijABCDEFGHIJ0123450123456789abcd\n");
        wait_for_bytes(&s, 53);
        let second = s.read_processed(&ReadRequest::since(first.cursor, 32 * 1024), &p);
        assert!(!second.held_back, "the token completed");
        assert!(!second.output.contains("ghp_abcdef"), "{}", second.output);
        assert_eq!(second.output, "[REDACTED:github]\n");
    }

    #[test]
    fn tail_reads_bypass_the_holdback_through_the_session() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"line one\nghp_abcdef");
        wait_for_bytes(&s, 18);

        let r = s.read_processed(
            &ReadRequest {
                start: ReadStart::TailBytes(10),
                max_bytes: 32 * 1024,
                options: ReadOptions::default(),
                tool: "read_output",
                client_kind: "in_process",
            },
            &p,
        );
        assert!(!r.held_back);
        assert_eq!(r.output, "ghp_abcdef", "recency was explicitly requested");
    }

    #[test]
    fn disabling_redaction_returns_raw_bytes_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let p = processor_with_audit(dir.path());
        let (s, pty) = mock_session();
        let line = format!("t={GITHUB}\n");
        pty.queue_output(line.as_bytes());
        wait_for_bytes(&s, line.len() as u64);

        let r = s.read_processed(
            &ReadRequest {
                start: ReadStart::Cursor(0),
                max_bytes: 32 * 1024,
                options: ReadOptions {
                    redact: false,
                    ..Default::default()
                },
                tool: "read_output",
                client_kind: "in_process",
            },
            &p,
        );
        assert_eq!(r.output, line, "the escape hatch returns the raw bytes");
        assert_eq!(
            audit_kinds(&p),
            vec!["redaction_disabled"],
            "the escape hatch is audited, exactly once"
        );

        // …and the default read is *not* audited, so the trail stays a
        // record of exceptions rather than of every read.
        let _ = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        assert_eq!(audit_kinds(&p).len(), 1);
    }

    #[test]
    fn a_stale_cursor_sets_the_flag_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let p = processor_with_audit(dir.path());
        let pty = Arc::new(MockPty::new());
        // A 16-byte buffer so a second chunk evicts the first.
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(16),
        );
        pty.queue_output(b"0123456789abcdef");
        wait_for_bytes(&s, 16);
        pty.queue_output(b"GHIJKLMNOPQRSTUV");
        wait_for_bytes(&s, 32);

        let r = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        assert!(r.truncated_at_tail, "cursor 0 is below the live tail");
        assert_eq!(r.output, "GHIJKLMNOPQRSTUV");
        assert_eq!(audit_kinds(&p), vec!["truncated_at_tail"]);
    }

    /// The negative half of the row above: a cursor that is still inside
    /// the buffer sets no flag and writes nothing. Without it, a
    /// `truncated_at_tail` hardcoded to `true` — or an audit write with no
    /// condition on it — passes the test above and is caught by nothing.
    #[test]
    fn a_live_cursor_sets_no_truncation_flag_and_is_not_audited() {
        let dir = tempfile::tempdir().unwrap();
        let p = processor_with_audit(dir.path());
        let (s, pty) = mock_session();
        pty.queue_output(b"0123456789abcdef");
        wait_for_bytes(&s, 16);

        let r = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        assert!(!r.truncated_at_tail, "cursor 0 is still in the buffer");
        assert_eq!(r.output, "0123456789abcdef");
        assert!(
            audit_kinds(&p).is_empty(),
            "an ordinary read is not an audit event: {:?}",
            audit_kinds(&p)
        );
    }

    /// 0.0.1's `read_output` clipped an oversized `tail_lines` read from
    /// the FRONT so the newest bytes survive and the cursor still points
    /// past `buffer.head`. Capping forward from the tail-lines start
    /// instead would return the oldest slice and hand back a cursor far
    /// behind `head` — which re-delivers those same bytes on every
    /// follow-up cursor read, an infinite loop for a polling agent.
    #[test]
    fn an_oversized_tail_read_drops_the_oldest_bytes_not_the_newest() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"one\ntwo\nthree\nfour\n");
        wait_for_bytes(&s, 19);

        let r = s.read_processed(
            &ReadRequest {
                start: ReadStart::TailLines(100),
                max_bytes: 5,
                options: ReadOptions::default(),
                tool: "read_output",
                client_kind: "in_process",
            },
            &p,
        );
        assert_eq!(r.output, "four\n", "the newest bytes are the ones kept");
        assert_eq!(r.cursor, 19, "the cursor still points past the newest byte");
        assert!(r.truncated_for_size, "bytes were lost to the size budget");
        assert!(!r.held_back);
    }

    /// The negative half: a `tail_*` read that *fits* was not clipped, so
    /// it must not claim it was. `front_clipped` is the one input the
    /// processor cannot compute itself, and a version that sets it
    /// unconditionally satisfies the row above.
    #[test]
    fn a_tail_read_that_fits_reports_no_truncation() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"one\ntwo\nthree\nfour\n");
        wait_for_bytes(&s, 19);

        let r = s.read_processed(
            &ReadRequest {
                start: ReadStart::TailLines(2),
                max_bytes: 32 * 1024,
                options: ReadOptions::default(),
                tool: "read_output",
                client_kind: "in_process",
            },
            &p,
        );
        assert_eq!(r.output, "three\nfour\n");
        assert!(!r.truncated_for_size, "every requested byte was returned");
        assert_eq!(r.next_cursor, None);
    }

    #[test]
    fn a_size_cap_is_reported_as_truncation_not_holdback() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"0123456789abcdefghij");
        wait_for_bytes(&s, 20);

        let r = s.read_processed(&ReadRequest::since(0, 8), &p);
        assert_eq!(r.output, "01234567");
        assert!(r.truncated_for_size);
        assert!(!r.held_back, "more bytes are available now, not withheld");
        assert_eq!(r.next_cursor, Some(8));
    }

    /// REQ-O-008's liveness input comes from the backend, and
    /// `read_processed` is the only place that samples it. Every
    /// processor unit test builds its own snapshot and passes
    /// `child_alive` by hand, so hardcoding it here leaves all of them
    /// green while a real exited session withholds its last bytes for
    /// ever.
    #[test]
    fn the_liveness_the_escape_rule_needs_comes_from_the_backend() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"done\x1b[3");
        wait_for_bytes(&s, 7);

        // Alive: the child may still finish the sequence, so the tail
        // waits at the introducer.
        let live = s.read_processed(&ReadRequest::since(0, 4096), &p);
        assert!(live.held_back);
        assert_eq!(live.output, "done");
        assert_eq!(live.cursor, 4);
        assert!(!live.dropped_incomplete_escape);

        // Exited: it never will, so the read completes and reports it.
        pty.exit(0);
        let dead = s.read_processed(&ReadRequest::since(0, 4096), &p);
        assert!(!dead.held_back, "a dead child will never finish it");
        assert_eq!(dead.output, "done");
        assert_eq!(dead.cursor, 7);
        assert!(dead.dropped_incomplete_escape);
    }

    /// A cursor *past* `buffer.head` — a stale handle from a previous,
    /// longer session — clamps down to `head` and returns nothing.
    /// Unclamped, `read_end - req_start` underflows and the read panics;
    /// the below-tail half of the same clamp is pinned by
    /// `a_stale_cursor_sets_the_flag_and_is_audited` and cannot see this.
    #[test]
    fn a_cursor_past_the_head_returns_nothing_rather_than_underflowing() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();
        pty.queue_output(b"abc");
        wait_for_bytes(&s, 3);

        let r = s.read_processed(&ReadRequest::since(99, 4096), &p);
        assert_eq!(r.output, "");
        assert_eq!(r.bytes_returned, 0);
        assert_eq!(
            r.cursor, 3,
            "the cursor regresses to head, per 0.0.1's documented contract"
        );
        assert!(!r.truncated_at_tail);
    }

    /// REQ-O-012, session half: the tally is cumulative and is a
    /// different number from the per-response map.
    ///
    /// Kills both collapses at once — "alias `redaction_stats` to the
    /// last response's `redactions`" and "serve `redactions` from the
    /// session tally". Either makes the two numbers equal, and after two
    /// *overlapping* reads of one secret they must differ (1 and 2).
    /// A single-read test cannot tell any of these apart.
    ///
    /// The empty-tally assertion is the paired negative: an
    /// implementation that never counts anything reports 0 and 0 — equal,
    /// so `assert_ne!` catches it — and it also pins that a session which
    /// has redacted nothing reports an empty map rather than never
    /// having a map at all.
    #[test]
    fn the_session_tally_is_cumulative_and_is_not_the_per_response_map() {
        let (s, pty) = mock_session();
        let p = OutputProcessor::builtin().unwrap();

        assert!(
            s.redaction_stats().is_empty(),
            "a session that has redacted nothing reports an empty tally, \
             not an absent one"
        );

        let line = format!("t={GITHUB}\n");
        pty.queue_output(line.as_bytes());
        wait_for_bytes(&s, line.len() as u64);

        // Two OVERLAPPING reads: both start at cursor 0, so both return
        // the same secret and each redacts it exactly once.
        let first = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        let second = s.read_processed(&ReadRequest::since(0, 32 * 1024), &p);
        assert_eq!(first.redactions.get("github"), Some(&1));
        assert_eq!(
            second.redactions.get("github"),
            Some(&1),
            "the per-response map describes only this response"
        );
        assert_eq!(
            s.redaction_stats().get("github"),
            Some(&2),
            "the session tally accumulates across reads, double-counting \
             the overlap on purpose"
        );
        let per_response = second.redactions["github"] as u64;
        assert_ne!(
            per_response,
            s.redaction_stats()["github"],
            "the two surfaces must report different numbers here; equal \
             means one is being served from the other"
        );

        // A `redact: false` read redacts nothing, so it must not move the
        // tally — otherwise the escape hatch would inflate the one
        // statistic that says whether secrets were withheld.
        let _ = s.read_processed(
            &ReadRequest {
                start: ReadStart::Cursor(0),
                max_bytes: 32 * 1024,
                options: ReadOptions {
                    redact: false,
                    ..Default::default()
                },
                tool: "read_output",
                client_kind: "in_process",
            },
            &p,
        );
        assert_eq!(s.redaction_stats()["github"], 2, "no redaction, no count");
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
        // **A one-shot latch, and not `command_count() > 0`.** The guard
        // this replaces was written when `Session::detection` was the
        // only caller of `line_discipline`. 0.0.6's reader loop samples
        // it once per chunk too (`:662`), *strictly before* the reader
        // applies its history events a few lines below — so at the
        // reader's firing site `command_count()` is guaranteed still 0
        // and the payload was queued a second time in **every** run.
        // Whether the row failed was only whether the reader had
        // consumed the duplicate before the final assertion, which is
        // where the ~18% flake came from (164 pass / 36 fail in 200
        // isolated runs; `hook_queued=2` in 57 of 57 instrumented runs).
        //
        // The race was the hook's, not the product's: `feed()` runs once
        // per chunk, `PromptDetector::snapshot_at` writes nothing to
        // `self`, and `history.apply` runs once per event, so the
        // history can neither lose nor double-count a chunk that arrives
        // from the PTY. Only an injecting hook can put the same bytes in
        // twice. A latch is the whole fix: it is not a timeout, and the
        // defect this row exists to catch still kills it (measured —
        // sampling `line_discipline` outside the detector lock in
        // `Session::detection` gives 0 passes in 10 with the latch in
        // place).
        let queued_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let latch = Arc::clone(&queued_once);
        pty.on_line_discipline_sample(move || {
            let Some(s) = weak.upgrade() else { return };
            if latch.swap(true, Ordering::SeqCst) {
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
        // **Both directions, because the message used to name only one
        // of them and it was the one that never happened.** This row's
        // every observed failure was `left: 2, right: 1` — a duplicate
        // injected by the hook, not a chunk lost by the reader — while
        // the message said "the chunk never reached the history". A
        // failure message that describes the opposite of the failure
        // sends the next reader to look at the reader thread, which is
        // exactly where the time went.
        assert_eq!(
            s.command_count(),
            1,
            "the hook queues one `\\x1b]133;C` and the history must hold \
             exactly one command for it: 0 means the deferred chunk never \
             reached the history, and more than 1 means this test's own \
             hook fired twice — a defect in the hook, not in the reader"
        );
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
        // Two DA1 queries, first so nothing below them can disturb the
        // "last logical line" the pattern assertion reads. The reply
        // budget is 1, so exactly one of them is answered.
        bytes.extend_from_slice(b"\x1b[0c\x1b[0c");
        for i in 0..3u8 {
            bytes.extend_from_slice(b"\x1b]133;B\x07cmd");
            bytes.push(b'0' + i);
            bytes.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
        }
        // A tail that the bundled table scores 0.0 on, so a session-supplied
        // pattern is the only thing that can produce a non-zero score.
        bytes.extend_from_slice(b"holdfast~ ");

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
                            regex: r"holdfast~\s*$".into(),
                            score: 0.9,
                        }],
                        false,
                    )
                    .unwrap(),
                    ..DetectionConfig::default()
                },
                shell_integration: None,
                // §4.5.1's two knobs, exhaustively named here for the
                // reason the whole test exists: `terminal_queries: bool`
                // sits beside `shell_integration: Option<Shell>` and
                // `terminal_query_replies_per_min: u32` beside
                // `history_max_entries: usize`, and same-typed neighbours
                // transpose silently. The `\x1b[0c` in `bytes` above is
                // what makes the first one reachable, and the limit is
                // set to 1 so that a value that never arrived (the
                // default is 60) answers both queries instead of one.
                terminal_queries: true,
                terminal_query_replies_per_min: 1,
                idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
                clock: Clock::system(),
                // Named for the same reason: `Option<String>` beside
                // `Option<Shell>` is another same-shaped neighbour, and
                // `None` here is the ordinary `command`/`args` session.
                profile: None,
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
        // Both §4.5.1 knobs, and each one fails differently: a defaulted
        // `terminal_queries` is still `true` so the count would be right
        // for the wrong reason — which is why the *limit* is what is
        // asserted. Two queries and a budget of one gives exactly one
        // reply; a defaulted budget of 60 gives two, and a
        // `terminal_queries` that never reached the responder gives none.
        assert_eq!(
            pty.written(),
            b"\x1b[?6c",
            "terminal_queries / terminal_query_replies_per_min did not \
             reach the responder"
        );
    }

    /// §4.5.1's reply, byte for byte.
    const DA1_REPLY: &[u8] = b"\x1b[?6c";

    /// A session over `pty` with the §4.5.1 knobs set explicitly.
    fn query_session(pty: &Arc<MockPty>, terminal_queries: bool) -> Arc<Session> {
        Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                terminal_queries,
                ..SessionConfig::with_buffer_capacity(4096)
            },
        )
    }

    /// §4.5.1's reply reaches the child, and it is the only thing written.
    ///
    /// `SessionConfig::default()` sets `shell_integration: None`, so
    /// `written()` is empty until the reply lands — anything else in it is
    /// a second writer nobody declared.
    #[test]
    fn a_da1_query_from_the_child_is_answered_on_the_pty() {
        let pty = Arc::new(MockPty::new());
        let s = query_session(&pty, true);
        pty.queue_output(b"\x1b[0c");
        wait_until("the reply to reach the child", || {
            pty.written() == DA1_REPLY
        });
        drop(s);
    }

    /// The negative half, at the session level: a declined query travels
    /// the same reader path and must produce **no write at all**. Without
    /// it the test above passes identically against a session that answers
    /// everything, which is the outcome §4.5.1's admission rule exists to
    /// prevent.
    #[test]
    fn a_declined_query_from_the_child_is_answered_with_silence() {
        let pty = Arc::new(MockPty::new());
        let s = query_session(&pty, true);
        // CPR — §4.5.1's worked example of the rule saying no — followed
        // by a DA1 the reader must still answer, which is what proves the
        // silence above was a decision and not a dead reply path.
        pty.queue_output(b"\x1b[6n\x1b]11;?\x07\x1b[>0q");
        wait_for_bytes(&s, 15);
        assert!(
            pty.written().is_empty(),
            "a declined query was answered: {:?}",
            pty.written()
        );
        pty.queue_output(b"\x1b[0c");
        wait_until("DA1 to still be answered", || pty.written() == DA1_REPLY);
    }

    /// §4.2's `terminal_queries` knob, both arms in one test: `false` must
    /// be indistinguishable from a build with no reply path, and the
    /// positive arm is what stops that from passing against exactly such a
    /// build.
    #[test]
    fn terminal_queries_false_writes_nothing_into_the_child() {
        let off = Arc::new(MockPty::new());
        let s_off = query_session(&off, false);
        off.queue_output(b"\x1b[0c");
        wait_for_bytes(&s_off, 4);
        // The reader stamps activity at the end of the chunk's iteration,
        // strictly after the point the reply would have been written, so
        // waiting for the stamp is waiting past the write site.
        wait_until("the chunk's iteration to complete", || {
            s_off.last_activity_ms() > 0
        });
        assert!(
            off.written().is_empty(),
            "terminal_queries: false wrote {:?} into the child",
            off.written()
        );

        let on = Arc::new(MockPty::new());
        let s_on = query_session(&on, true);
        on.queue_output(b"\x1b[0c");
        wait_until("the same bytes to be answered when the knob is on", || {
            on.written() == DA1_REPLY
        });
        drop((s_off, s_on));
    }

    /// A backend that samples the session's activity stamp **at the moment
    /// each write reaches the child**, which is the one instant at which
    /// the reply's write path is distinguishable from the reader's own
    /// end-of-chunk stamp.
    struct ActivityProbe {
        inner: Arc<MockPty>,
        session: Mutex<Option<std::sync::Weak<Session>>>,
        samples: Mutex<Vec<i64>>,
    }

    impl ActivityProbe {
        fn new(inner: Arc<MockPty>) -> Self {
            Self {
                inner,
                session: Mutex::new(None),
                samples: Mutex::new(Vec::new()),
            }
        }

        /// `Weak`, not `Arc`: the probe outlives nothing and must not keep
        /// the session alive, or `the_reader_thread_exits_when_the_session_is_dropped`
        /// becomes a lie for every test that uses this.
        fn watch(&self, s: &Arc<Session>) {
            *self.session.lock() = Some(Arc::downgrade(s));
        }

        fn samples(&self) -> Vec<i64> {
            self.samples.lock().clone()
        }
    }

    impl PtyBackend for ActivityProbe {
        fn write(&self, data: &[u8]) -> Result<()> {
            // `now_ms()` has millisecond resolution, so two writes in the
            // same iteration would otherwise tie and a stamp taken between
            // them would be invisible.
            std::thread::sleep(Duration::from_millis(2));
            let stamp = self
                .session
                .lock()
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|s| s.last_activity_ms());
            if let Some(stamp) = stamp {
                self.samples.lock().push(stamp);
            }
            self.inner.write(data)
        }
        fn read(&self, buf: &mut [u8]) -> Result<usize> {
            self.inner.read(buf)
        }
        fn signal(&self, sig: Signal) -> Result<()> {
            self.inner.signal(sig)
        }
        fn resize(&self, cols: u16, rows: u16) -> Result<()> {
            self.inner.resize(cols, rows)
        }
        fn is_alive(&self) -> bool {
            self.inner.is_alive()
        }
        fn exit_code(&self) -> Option<i32> {
            self.inner.exit_code()
        }
        fn pid(&self) -> Option<u32> {
            self.inner.pid()
        }
    }

    /// REQ-TS-009: a reply is Holdfast's own answer, not agent input, and it
    /// stamps nothing.
    ///
    /// **Why the probe rather than a stamp read after the fact.** The
    /// reader already stamps `last_activity` once per chunk — the child's
    /// own output is activity, which §4.5.1 says in as many words — and
    /// that stamp lands *after* the reply write, so a reply routed through
    /// `Session::write_input` is invisible to any reading taken once the
    /// iteration has finished. It is visible between two replies in the
    /// same chunk: `write_input` stamps after each write returns, so the
    /// second write sees a stamp the correct path never produces. Two
    /// queries in one chunk is therefore the arrangement, and one is not.
    #[test]
    fn answering_a_query_does_not_bump_last_activity() {
        let mock = Arc::new(MockPty::new());
        let probe = Arc::new(ActivityProbe::new(Arc::clone(&mock)));
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&probe) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(4096),
        );
        probe.watch(&s);
        let before = s.last_activity_ms();

        mock.queue_output(b"\x1b[0c\x1b[0c");
        wait_until("both replies to reach the child", || {
            probe.samples().len() == 2
        });
        for (i, stamp) in probe.samples().into_iter().enumerate() {
            assert_eq!(
                stamp, before,
                "reply {i} was written by a path that stamped last_activity"
            );
        }

        // The negative arm, in the same test: without it this passes
        // against a session whose clock never moves at all.
        let seen = probe.samples().len();
        std::thread::sleep(Duration::from_millis(2));
        s.write_input(b"x").expect("write_input");
        assert!(
            s.last_activity_ms() > before,
            "agent input did not advance the stamp either, so the \
             assertion above proves nothing"
        );
        assert_eq!(
            probe.samples().len(),
            seen + 1,
            "the probe stopped observing writes"
        );
    }

    /// REQ-TS-009's immortality clause, on the reaper's terms.
    ///
    /// There is no reaper in the tree yet, so "past its deadline" is the
    /// arithmetic one will use: `now - last_activity >= idle`. The clause
    /// this pins is that the deadline runs from the **child's own output**
    /// and the replies add nothing after it — a reply path that stamped
    /// would leave a queried session's deadline running from whenever
    /// Holdfast last answered rather than from when the child last spoke.
    #[test]
    fn a_session_whose_only_traffic_is_queries_still_reaps_on_schedule() {
        const IDLE_MS: i64 = 60;
        let past_deadline = |s: &Session| now_ms() - s.last_activity_ms() >= IDLE_MS;

        // Queried, then quiet.
        let queried_pty = Arc::new(MockPty::new());
        let queried = query_session(&queried_pty, true);
        for _ in 0..8 {
            queried_pty.queue_output(b"\x1b[0c");
        }
        wait_until("every query to be answered", || {
            queried_pty.written().len() == 8 * DA1_REPLY.len()
        });

        // Ordinary output on a schedule, which is the control: a session
        // still being spoken to is *not* past its deadline, so an
        // implementation whose stamp never advances cannot pass both arms.
        let busy_pty = Arc::new(MockPty::new());
        let busy = query_session(&busy_pty, true);

        let deadline = Instant::now() + Duration::from_secs(2);
        while !past_deadline(&queried) && Instant::now() < deadline {
            busy_pty.queue_output(b".");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            past_deadline(&queried),
            "a session whose only traffic was queries never went idle: \
             answering is extending its deadline"
        );
        assert!(
            !past_deadline(&busy),
            "the control session went idle while it was still being \
             written to, so the arm above proves nothing"
        );
    }

    /// REQ-TS-009: a reply is never a command-history entry.
    #[test]
    fn a_query_reply_is_not_a_command_history_entry() {
        let pty = Arc::new(MockPty::new());
        let s = query_session(&pty, true);
        for _ in 0..5 {
            pty.queue_output(b"\x1b[0c");
        }
        wait_until("all five replies to reach the child", || {
            pty.written().len() == 5 * DA1_REPLY.len()
        });
        assert_eq!(s.command_count(), 0, "a reply was folded into a command");
        assert!(s.command_history(0, 10).is_empty());

        // The negative, on the same session: one real OSC 133 cycle
        // records exactly one entry, so an always-empty ring cannot pass
        // the arm above.
        pty.queue_output(
            b"\x1b]133;A\x07\x1b]133;B\x07echo hi\r\n\x1b]133;C\x07hi\r\n\x1b]133;D;0\x07",
        );
        wait_until("the OSC 133 cycle to be folded", || s.command_count() == 1);
        assert_eq!(s.command_history(0, 10).len(), 1);
    }

    fn grid(capture: ScreenCapture) -> ScreenGrid {
        match capture {
            ScreenCapture::Full(g) => g,
            ScreenCapture::Delta(d) => panic!("expected a full grid, got {d:?}"),
        }
    }

    #[test]
    fn tier_b_stays_off_for_line_oriented_output() {
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        let out = b"\x1b[?2004h$ make\r\nCompiling everything\r\n";
        pty.queue_output(out);
        wait_for_bytes(&s, out.len() as u64);

        assert_eq!(s.screen_tracking(), "off");
        assert_eq!(
            s.vt100_bytes_parsed(),
            0,
            "the reader thread ran the VT100 parser without a trigger"
        );
        assert!(s.cursor_signal().is_none());
    }

    #[test]
    fn get_screen_state_enables_tier_b_and_seeds_from_the_ring_buffer() {
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        // Painted while Tier B is off: only a re-seed can recover it.
        let out = b"\x1b[?2004h\x1b[H\x1b[2JSEEDED FROM BUFFER\r\n";
        pty.queue_output(out);
        wait_for_bytes(&s, out.len() as u64);
        assert_eq!(s.vt100_bytes_parsed(), 0);

        let g = grid(s.screen_state(None, true, &OutputProcessor::builtin().unwrap()));
        assert_eq!(s.screen_tracking(), "on");
        assert_eq!(g.rows, 24);
        assert_eq!(g.cols, 80);
        assert_eq!(g.lines[0].trim_end(), "SEEDED FROM BUFFER");
        assert!(s.vt100_bytes_parsed() > 0);
    }

    #[test]
    fn alt_screen_output_enables_tier_b_without_an_agent_call() {
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        let first = b"\x1b[?2004h$ less notes\r\n";
        pty.queue_output(first);
        wait_for_bytes(&s, first.len() as u64);
        assert_eq!(s.screen_tracking(), "off");

        let second = b"\x1b[?1049h\x1b[H\x1b[2JPAGER";
        pty.queue_output(second);
        wait_for_bytes(&s, (first.len() + second.len()) as u64);
        let deadline = Instant::now() + Duration::from_secs(2);
        while s.screen_tracking() == "off" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(s.screen_tracking(), "on");

        let g = grid(s.screen_state(None, true, &OutputProcessor::builtin().unwrap()));
        assert!(g.alt_screen);
        assert_eq!(g.lines[0].trim_end(), "PAGER");
    }

    #[test]
    fn screen_tracking_off_never_parses_on_the_write_path() {
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            mode: ScreenTracking::Off,
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        let out = b"\x1b[?1049h\x1b[H\x1b[2JTUI";
        pty.queue_output(out);
        wait_for_bytes(&s, out.len() as u64);

        assert_eq!(
            s.vt100_bytes_parsed(),
            0,
            "`off` ran the parser on the write path anyway"
        );
        // The call still answers — §5.2 says it succeeds either way.
        let g = grid(s.screen_state(None, true, &OutputProcessor::builtin().unwrap()));
        assert_eq!(g.lines[0].trim_end(), "TUI");
        assert_eq!(s.screen_tracking(), "off");
    }

    /// REQ-PD-008's wiring, which is a `Session` fact and not a detector
    /// one: `detection()` has to *hand* the detector §8.6's third term.
    ///
    /// Without this the only thing that notices `detection()` passing
    /// `None` is the live-`dash` row in `tests/detection.rs`, which
    /// notices it by polling for twenty seconds and timing out. The
    /// detector's own combiner test cannot see it at all — it calls
    /// `snapshot_at` directly.
    ///
    /// `mode: On` rather than a three-second wait: the §4.5 trigger is
    /// tested where it lives, and a unit test should not sleep past it.
    #[test]
    fn detection_carries_the_cursor_sub_signal_once_tier_b_is_running() {
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            mode: ScreenTracking::On,
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        let out = b"$ ";
        pty.queue_output(out);
        wait_for_bytes(&s, out.len() as u64);

        // Each `detection()` samples the cursor once, and
        // `cursor_stable_samples` is 3.
        wait_until("the cursor position to be stable", || {
            s.detection().cursor_score > 0.0
        });
        let d = s.detection();
        assert_eq!(
            d.cursor_score, 0.9,
            "the cursor is parked after `$ `, which is §8.6's 0.9 row"
        );
        // …and the combiner used it: `$ ` scores 0.6 on the pattern rung,
        // so a confidence built from the pattern alone would be lower.
        assert!(
            (d.confidence - d.quiescent_score * 0.9).abs() < 1e-6,
            "max(pattern {}, cursor {}) did not carry: {d:?}",
            d.pattern_score,
            d.cursor_score
        );
        assert!(d.pattern_score < d.cursor_score);
    }

    #[test]
    fn the_reader_thread_does_not_double_apply_the_triggering_chunk() {
        // The chunk that turns Tier B on is already in the ring buffer
        // when the seed is taken. If the reader then fed it to the parser
        // as well, the grid would show it twice.
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            mode: ScreenTracking::On,
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        // No `\x1b[2J`: a clear inside the same chunk would erase the first
        // paint, and the doubled output would be invisible.
        let out = b"ONCE";
        pty.queue_output(out);
        wait_for_bytes(&s, out.len() as u64);

        let g = grid(s.screen_state(None, true, &OutputProcessor::builtin().unwrap()));
        assert_eq!(g.lines[0].trim_end(), "ONCE");
        assert_eq!((g.cursor_row, g.cursor_col), (0, 4));
    }

    // ---------------------------------------------- geometry bounds (C3)

    fn capture(s: &Session) -> ScreenGrid {
        grid(s.screen_state(None, true, &OutputProcessor::builtin().unwrap()))
    }

    /// A live-parser session, painted, with Tier B already running — so a
    /// `resize` reaches `vt100::Screen::set_size` rather than only
    /// `ScreenConfig`.
    fn painted_session(mode: ScreenTracking) -> (Arc<Session>, Arc<MockPty>) {
        let (s, pty) = mock_session();
        s.set_screen_config(ScreenConfig {
            mode,
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        let out = b"PAINTED";
        pty.queue_output(out);
        wait_for_bytes(&s, out.len() as u64);
        (s, pty)
    }

    /// A terminal with zero rows or columns is not a terminal, and
    /// `TIOCSWINSZ` is perfectly happy to make one — so the value arrives
    /// at the tracker verbatim and `Grid::set_size` computes
    /// `size.rows - 1` on a `u16`. Under the `overflow-checks` a test
    /// build has on, that panics *inside the screen lock*; `parking_lot`
    /// does not poison, so the session would carry on with a parser the
    /// reader thread hits next.
    #[test]
    fn a_zero_geometry_resize_is_clamped_before_it_reaches_the_grid() {
        let (s, _pty) = painted_session(ScreenTracking::On);
        let before = capture(&s);
        assert_eq!(
            (before.cols, before.rows),
            (80, 24),
            "the parser has to exist before the resize, or `set_size` is \
             never called and this test exercises nothing"
        );

        s.resize(0, 0).expect("a clamped resize is not an error");
        assert_eq!(s.size(), (MIN_COLS, MIN_ROWS));
        let g = capture(&s);
        assert_eq!(
            (g.cols, g.rows),
            (MIN_COLS, MIN_ROWS),
            "the grid and the session disagree about the clamped geometry"
        );

        // The control, and it is what separates "clamped" from "refuses
        // every resize": an in-range pair still passes through untouched.
        s.resize(132, 43).expect("resize");
        assert_eq!(s.size(), (132, 43));
        let wide = capture(&s);
        assert_eq!((wide.cols, wide.rows), (132, 43));
    }

    /// The other end. `Row::new(cols)` allocates every cell eagerly and
    /// `vt100::Cell` is statically asserted at 32 bytes, so an unclamped
    /// `resize(65535, 65535)` asks for ~137 GB in one allocation loop —
    /// which in hybrid mode takes the daemon, and every other session
    /// with it.
    #[test]
    fn a_resize_past_the_supported_maximum_is_clamped_rather_than_allocated() {
        // The bound is spelled out as a literal here rather than read
        // back from the constant: a test that only compares
        // `size() == MAX_COLS` cannot tell a clamp from a ceiling that
        // has been raised out from under it, and this bound is a
        // deliberate choice (32 MB per grid) rather than an incidental
        // one.
        assert_eq!(
            (MIN_COLS, MIN_ROWS, MAX_COLS, MAX_ROWS),
            (2, 2, 1000, 1000),
            "the geometry bounds moved; the measurement in `pty`'s \
             `MIN_COLS`/`MAX_ROWS` doc comments is what justifies them"
        );

        let (s, _pty) = painted_session(ScreenTracking::On);
        let _ = capture(&s);

        s.resize(u16::MAX, u16::MAX)
            .expect("a clamped resize is not an error");
        assert_eq!(s.size(), (1000, 1000));
        let g = capture(&s);
        assert_eq!((g.cols, g.rows), (1000, 1000));
        assert_eq!(
            g.lines.len(),
            1000,
            "the rendered grid is a different shape from the one the \
             session reports"
        );

        // The control: an in-range pair is not clamped.
        s.resize(132, 43).expect("resize");
        assert_eq!(s.size(), (132, 43));
        assert_eq!((capture(&s).cols, capture(&s).rows), (132, 43));
    }

    /// Tier B *off* is a second path to the same subtraction, and it does
    /// not go through `set_size` at all: `ScreenTracker::resize` on a
    /// parserless tracker updates only `cfg`, and the next read builds
    /// `vt100::Parser::new(rows, cols, 0)` from it — where `Grid::new`
    /// has the identical `size.rows - 1`.
    #[test]
    fn the_tier_b_off_render_never_sees_an_unclamped_geometry() {
        let (s, _pty) = painted_session(ScreenTracking::Off);
        s.resize(0, 0).expect("a clamped resize is not an error");
        assert_eq!(
            s.screen_tracking(),
            "off",
            "the arm under test is the one with no live parser; with Tier \
             B running this would exercise `set_size` instead"
        );
        assert_eq!(s.size(), (MIN_COLS, MIN_ROWS));

        let g = capture(&s);
        assert_eq!((g.cols, g.rows), (MIN_COLS, MIN_ROWS));
        assert_eq!(
            s.screen_tracking(),
            "off",
            "the one-shot render must not have turned Tier B on"
        );

        // The control, and it also shows the one-shot still renders the
        // buffer rather than merely surviving: at the minimum there is
        // nowhere to put `PAINTED`.
        s.resize(80, 24).expect("resize");
        let back = capture(&s);
        assert_eq!((back.cols, back.rows), (80, 24));
        assert_eq!(back.lines[0].trim_end(), "PAINTED");
    }

    // ------------------------------------- §4.1's boundary, as a pair

    /// **`holdback_boundary` says "nothing is withheld" by returning
    /// `w.head`** — so that answer is a *value*, and it means nothing
    /// except beside the head it was measured against. `screen_state`
    /// used to hand the tracker `Some(that value)`; the tracker
    /// re-samples its own head when it seeds, so every byte that landed
    /// in between left a `T1` boundary sitting strictly behind a `T2`
    /// head, and the grid came back masked — `held_back: true`, cells
    /// replaced — for a secret nobody anywhere was withholding.
    ///
    /// Nothing in this stream is secret-shaped, so a correct
    /// implementation can never fail this; the reader thread supplies the
    /// race for free, because it drains the `MockPty` on its own schedule
    /// and the test does not have to find the window by hand.
    #[test]
    fn a_capture_racing_the_reader_masks_nothing_when_nothing_is_withheld() {
        let (s, pty) = painted_session(ScreenTracking::On);
        let processor = OutputProcessor::builtin().expect("builtin rules");
        for i in 0..300u32 {
            pty.queue_output(format!("build output line {i}\r\n").as_bytes());
            let g = grid(s.screen_state(None, true, &processor));
            assert!(
                !g.held_back,
                "iteration {i}: the grid was masked for a secret nobody is \
                 withholding — a boundary sampled before the reader ran, \
                 judged against a head sampled after it"
            );
        }
    }

    /// The pairing, and it is not optional: without it the row above is
    /// satisfied by an `open_holdback` that answers `None` to everything,
    /// which would hand the agent the withheld bytes it exists to keep.
    #[test]
    fn a_real_partial_still_masks_the_grid_through_screen_state() {
        let (s, pty) = painted_session(ScreenTracking::On);
        let processor = OutputProcessor::builtin().expect("builtin rules");
        let body = "PjLkMnBvCxZaSdFgHjKlQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJk";
        pty.queue_output(format!("\r\n-----BEGIN RSA PRIVATE KEY-----\r\n{body}").as_bytes());
        wait_until("the key body to reach the buffer", || {
            s.open_holdback(&processor).is_some()
        });
        assert!(
            s.open_holdback(&processor).expect("open") < s.buffer_head(),
            "an open boundary is strictly behind the head by construction — \
             `earliest_partial` returns the start of a match of at least one \
             byte"
        );
        assert!(
            grid(s.screen_state(None, true, &processor)).held_back,
            "the bytes §4.1 is withholding reached the grid unmasked"
        );
    }

    /// **Why the floor is two and not one.** Measured against
    /// `vt100` 0.16.2, each of these streams panics at one row or one
    /// column and survives at two:
    ///
    /// - one row — `Grid::col_wrap`'s `prev_pos.row -= scrolled`, on any
    ///   wrap, scroll region, reverse index or off-screen cursor move;
    /// - one column — `Grid::col_wrap`'s `self.size.cols - width`, on any
    ///   wide character.
    ///
    /// So this is the test that *chooses* the constant rather than
    /// restating it: set `MIN_COLS` or `MIN_ROWS` to 1 and it panics —
    /// inside the screen lock, which is where the shipped defect was.
    /// Raising them cannot make it pass by accident either, because the
    /// grid it asserts on is read back from the session.
    #[test]
    fn the_minimum_geometry_survives_the_streams_that_underflow_below_it() {
        // One session per stream: escape state left by one payload would
        // otherwise decide what the next one does.
        for (name, stream) in [
            ("narrow wrap", "abcdefghijklmnopqrstuvwxyz".as_bytes()),
            (
                "wide characters",
                "\u{4f60}\u{597d}\u{4e16}\u{754c}".as_bytes(),
            ),
            ("newlines", b"a\r\nb\r\nc\r\nd\r\n"),
            ("tabs", b"a\tb\tc\td\t"),
            (
                "one-row scroll region",
                b"\x1b[1;1r\x1b[2Jabc\r\ndef\r\nghi",
            ),
            ("reverse index", b"\x1bMabc\x1bM\x1bDdef\x1bE\x1bE"),
            (
                "off-screen cursor moves",
                b"\x1b[99;99H\x1b[2Jx\x1b[9A\x1b[9B\x1b[9C\x1b[9D\x1b[H\x1b[K",
            ),
            (
                "insert and delete",
                b"\x1b[2Jabc\x1b[9L\x1b[9M\x1b[9P\x1b[9@",
            ),
            ("alt screen", b"\x1b[?1049habcdef\r\nghi\x1b[?1049ljkl"),
        ] {
            let (s, pty) = painted_session(ScreenTracking::On);
            let _ = capture(&s);
            s.resize(MIN_COLS, MIN_ROWS).expect("resize");

            let head = s.buffer_head();
            pty.queue_output(stream);
            wait_for_bytes(&s, head + stream.len() as u64);

            let g = capture(&s);
            assert_eq!(
                (g.cols, g.rows),
                (MIN_COLS, MIN_ROWS),
                "{name} left the grid a different shape from the session's"
            );
            assert_eq!(
                g.lines.len(),
                usize::from(MIN_ROWS),
                "{name} rendered the wrong number of rows"
            );
        }
    }

    // ------------------------------------------ 0.0.6 §4.3 write queue

    /// A backend that hands the reader **one byte per `read`**.
    ///
    /// `MockPty::read` drains its whole queue into a single call, so a
    /// hundred `queue_output(b"x")` calls can arrive as one
    /// `OutputFrame`. That is fine for every test that cares about
    /// *bytes*, and useless for the one test that cares about *frames*:
    /// the broadcast's bound is 256 **frames**, so a burst that has to
    /// overrun it needs the frame count to be something the test
    /// controls rather than something the scheduler decides.
    ///
    /// 0.0.3 measured the alternative and recorded it: flooding a slow
    /// consumer through `MockPty` never produced a `Lagged` at all,
    /// proven by planting a `panic!` in the `Lagged` arm and watching it
    /// never fire.
    #[derive(Debug)]
    struct DribblePty {
        inner: Arc<MockPty>,
    }

    impl crate::pty::PtyBackend for DribblePty {
        fn write(&self, data: &[u8]) -> Result<()> {
            self.inner.write(data)
        }
        fn read(&self, buf: &mut [u8]) -> Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
        fn signal(&self, sig: crate::pty::Signal) -> Result<()> {
            self.inner.signal(sig)
        }
        fn resize(&self, cols: u16, rows: u16) -> Result<()> {
            self.inner.resize(cols, rows)
        }
        fn is_alive(&self) -> bool {
            self.inner.is_alive()
        }
        fn exit_code(&self) -> Option<i32> {
            self.inner.exit_code()
        }
        fn pid(&self) -> Option<u32> {
            self.inner.pid()
        }
    }

    /// A backend whose writes come back as output, the way a PTY in echo
    /// mode does.
    ///
    /// The write-queue tests need to see input **arrive at the child** by
    /// the same route a real session would show it — through the ring
    /// buffer and through the broadcast — and `MockPty` swallows writes
    /// into `written()` without echoing. Wrapping rather than changing
    /// `MockPty`, because every other test in the tree depends on writes
    /// *not* appearing in the output stream.
    #[derive(Debug)]
    struct EchoPty {
        inner: Arc<MockPty>,
    }

    impl crate::pty::PtyBackend for EchoPty {
        fn write(&self, data: &[u8]) -> Result<()> {
            self.inner.write(data)?;
            self.inner.queue_output(data);
            Ok(())
        }
        fn read(&self, buf: &mut [u8]) -> Result<usize> {
            self.inner.read(buf)
        }
        fn signal(&self, sig: crate::pty::Signal) -> Result<()> {
            self.inner.signal(sig)
        }
        fn resize(&self, cols: u16, rows: u16) -> Result<()> {
            self.inner.resize(cols, rows)
        }
        fn is_alive(&self) -> bool {
            self.inner.is_alive()
        }
        fn exit_code(&self) -> Option<i32> {
            self.inner.exit_code()
        }
        fn pid(&self) -> Option<u32> {
            self.inner.pid()
        }
    }

    fn session_on(backend: Arc<dyn PtyBackend>) -> Arc<Session> {
        Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            backend,
            SessionConfig::with_buffer_capacity(64 * 1024),
        )
    }

    /// `recv` with a deadline, so a stalled fan-out fails the test
    /// instead of hanging the run.
    ///
    /// `broadcast::Receiver` has no timeout of its own and there is no
    /// runtime here to borrow one from. A bare `blocking_recv()` against
    /// a reader that has stopped publishing waits forever, and an
    /// unbounded wait in CI is a hung job rather than a red row — which
    /// is the failure this whole section is most exposed to.
    fn recv_within(
        rx: &mut broadcast::Receiver<OutputFrame>,
        what: &str,
    ) -> std::result::Result<OutputFrame, broadcast::error::TryRecvError> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match rx.try_recv() {
                Err(broadcast::error::TryRecvError::Empty) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                other => {
                    if matches!(other, Err(broadcast::error::TryRecvError::Empty)) {
                        panic!("timed out waiting for {what}");
                    }
                    return other;
                }
            }
        }
    }

    fn drain_bytes_within(rx: &mut broadcast::Receiver<OutputFrame>, needle: &[u8], what: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut seen: Vec<u8> = Vec::new();
        while Instant::now() < deadline {
            match rx.try_recv() {
                Ok(f) => {
                    seen.extend_from_slice(&f.bytes);
                    if seen.windows(needle.len()).any(|w| w == needle) {
                        return;
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => panic!("{what}: {e:?}"),
            }
        }
        panic!(
            "timed out waiting for {what}; saw {:?}",
            String::from_utf8_lossy(&seen)
        );
    }

    #[test]
    fn two_subscribers_both_receive_the_same_chunk() {
        // The fan-out property, which nothing shipped pins:
        // `wait::for_pattern` is the only caller of `subscribe()` at HEAD
        // and it creates exactly one receiver, so "two receivers both see
        // one chunk" has never been asserted. 0.0.6 is the first
        // milestone with more than one subscriber alive at once — the
        // waiter plus every attach client — so this is the milestone that
        // has to pin it.
        let (s, pty) = mock_session();
        let mut a = s.subscribe();
        let mut b = s.subscribe();

        pty.queue_output(b"MARK");
        wait_for_bytes(&s, 4);

        let fa = recv_within(&mut a, "subscriber A's frame").expect("A received nothing");
        let fb = recv_within(&mut b, "subscriber B's frame").expect("B received nothing");
        assert_eq!(&*fa.bytes, b"MARK");
        assert_eq!(
            &*fb.bytes, b"MARK",
            "the second subscriber missed the chunk"
        );
        assert_eq!(
            (fa.start, fa.end),
            (fb.start, fb.end),
            "the two subscribers were told different offsets for one chunk"
        );
    }

    #[test]
    fn a_never_polled_subscriber_does_not_stall_the_reader() {
        // REQ-C-003's *reader never blocks* clause.
        //
        // **Not asserted as `Err(Lagged(n))`**, which is the shape 0.0.3
        // measured as unfalsifiable here. This asserts what the
        // requirement actually names: the reader kept running with a
        // full, unread channel, and a subscriber that arrives afterwards
        // still sees current output.
        let inner = Arc::new(MockPty::new());
        let s = session_on(Arc::new(DribblePty {
            inner: Arc::clone(&inner),
        }) as Arc<dyn PtyBackend>);

        // Held and never polled, for the whole test.
        let _never_polled = s.subscribe();

        // One frame per byte, so the count is the test's and not the
        // scheduler's. Comfortably past OUTPUT_BROADCAST_FRAMES.
        let burst = OUTPUT_BROADCAST_FRAMES * 2;
        inner.queue_output(&vec![b'x'; burst]);

        // (a) The reader kept going. A bounded channel that blocked its
        // sender parks the reader thread at frame 256 and the head stops
        // there — `wait_for_bytes` then fails on its own deadline rather
        // than hanging the run.
        wait_for_bytes(&s, burst as u64);

        // (b) A subscriber that arrives after the burst still sees
        // current output — the channel is usable, not merely unblocked.
        let mut fresh = s.subscribe();
        inner.queue_output(b"Z");
        drain_bytes_within(&mut fresh, b"Z", "a fresh subscriber's first frame");
    }

    #[test]
    fn input_queued_on_write_tx_reaches_the_pty() {
        let inner = Arc::new(MockPty::new());
        let s = session_on(Arc::new(EchoPty {
            inner: Arc::clone(&inner),
        }) as Arc<dyn PtyBackend>);
        let mut sub = s.subscribe();

        let (req, ack) = WriteRequest::input(b"echo QQ\n".to_vec());
        s.write_queue().blocking_send(req).expect("queue accepted");

        let wrote = ack
            .blocking_recv()
            .expect("the writer thread answered")
            .expect("the write succeeded");
        assert_eq!(wrote, 8);

        // Both routes, because a queue that is drained and discarded
        // fails neither on its own: `written()` alone would pass against
        // a writer that never let the bytes reach the session's own
        // record of them.
        wait_for_bytes(&s, 8);
        let read = s.read_from(0, 4096);
        assert!(
            String::from_utf8_lossy(&read.bytes).contains("QQ"),
            "queued input never reached the buffer: {:?}",
            String::from_utf8_lossy(&read.bytes)
        );
        drain_bytes_within(&mut sub, b"QQ", "the queued input on the broadcast");
        assert_eq!(inner.written(), b"echo QQ\n");
    }

    #[test]
    fn two_queued_writes_arrive_in_order() {
        // §7.5's last-writer-wins is FIFO through this channel and
        // nothing more. The mutation is a drain that spawns per message,
        // which reorders under load and is the bug that claim depends on
        // not existing.
        let inner = Arc::new(MockPty::new());
        let s = session_on(Arc::new(EchoPty {
            inner: Arc::clone(&inner),
        }) as Arc<dyn PtyBackend>);
        let q = s.write_queue();

        let (first, ack_a) = WriteRequest::input(b"AAAA".to_vec());
        let (second, ack_b) = WriteRequest::input(b"BBBB".to_vec());
        q.blocking_send(first).expect("queued A");
        q.blocking_send(second).expect("queued B");
        ack_a.blocking_recv().expect("A answered").expect("A wrote");
        ack_b.blocking_recv().expect("B answered").expect("B wrote");

        wait_for_bytes(&s, 8);
        let read = s.read_from(0, 4096);
        assert_eq!(
            String::from_utf8_lossy(&read.bytes),
            "AAAABBBB",
            "the queue did not preserve arrival order"
        );
        assert_eq!(inner.written(), b"AAAABBBB");
    }
}
