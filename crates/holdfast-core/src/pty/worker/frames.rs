//! The worker link's frame catalogue.
//!
//! Two closed enums, one per direction, over
//! [`crate::protocol::frame`]'s codec. The module header at
//! [`super`](crate::pty::worker) carries the decision this file
//! implements — control's codec and correlation id, attach's frame
//! shape, no new framing — and §23.4's reason it is not a §23.3 gate.
//!
//! **No `deny_unknown_fields` anywhere in this file**, for the same
//! reason `attach::frames` gives and for one more. Attach's reason is
//! §12.3 minor-compatibility, which does not apply here (§23.4: no skew
//! to survive). The reason that does apply is the failure mode: this
//! link is duplex and carries unsolicited [`WorkerFrame::Output`], so a
//! decode that errors on an unrecognised field kills the link and takes
//! the session's remaining output with it. A frame the daemon cannot
//! read is skipped ([`WorkerFrame::Unknown`]); it is not a reason to
//! stop reading.
//!
//! The strictness that does exist is **asymmetric, in the same direction
//! attach's is**: the side that must *act* on a frame refuses one it
//! does not understand, and the side that merely *observes* skips it.
//!
//! * A [`DaemonFrame`] with an unrecognised `type` is a decode **error**
//!   at the worker. The worker cannot act on an instruction it does not
//!   understand, and silently discarding a `Write` or a `Signal` is
//!   worse than refusing the link.
//! * A [`WorkerFrame`] with an unrecognised `type` decodes to
//!   [`WorkerFrame::Unknown`] at the daemon, which skips it and keeps
//!   reading.
//!
//! Both peers are the same build, so neither case can arise from a
//! correct install — `Hello`/`Ready` assert exactly that. Both are
//! implemented anyway, because "cannot arise" is a claim about a
//! deployment and this is a claim about a decoder.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;

use crate::protocol::frame::{self, FrameError};
use crate::pty::{LineDiscipline, PtySpawnConfig, Signal};

/// The build identity both peers assert on the link, carried by
/// [`DaemonFrame::Hello`] and echoed by [`WorkerFrame::Ready`].
///
/// **An identity assertion, not a version negotiation**, and the
/// difference is the whole of §23.4's argument. There is no skew to
/// survive between a daemon and a worker it spawned from its own
/// `current_exe`, so a mismatch is not an older peer to be accommodated
/// — it is evidence that the two processes are not the same build, which
/// is a bug. The link is refused, never downgraded, and this constant
/// exists so the refusal has one spelling rather than two.
///
/// The package version alone today. §12.2 gives this tree no build hash
/// to append — there is no `build.rs` and no `vergen`, and every other
/// identity string in the tree (`daemon_version`, `client_version`, the
/// pidfile's second field) is this same `env!`. If one is ever added,
/// it is appended **here**, so the two peers cannot come to disagree
/// about what they are comparing.
pub const WORKER_PROTOCOL_TAG: &str = env!("CARGO_PKG_VERSION");

/// The two questions the daemon can no longer answer for itself.
///
/// Both are reads of the PTY **master**, and after 0.0.10a the daemon
/// does not hold one: `line_discipline()` is a `tcgetattr` on the master
/// and `foreground_group()` is a `tcgetpgrp` on it. The rest of the
/// trait either travels one way (`write`, `resize`), is answered by the
/// daemon's own mirror (`is_alive`, `exit_code`, `pid`), or is
/// correlated separately because it is not a read at all
/// ([`DaemonFrame::Signal`]).
///
/// A closed set with no `Other` arm: a query the worker does not
/// implement must be a compile error at the daemon, not a `Reply` that
/// never comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryKind {
    /// `PtyBackend::line_discipline` — **one** `tcgetattr`, both flags,
    /// for the reason §8.3 and the trait's own doc comment give: two
    /// samples can straddle the child's `tcsetattr` and describe two
    /// different instants.
    LineDiscipline,
    /// `PtyBackend::foreground_group` — `tcgetpgrp(master)`, the
    /// terminal's own notion of which program holds it.
    ForegroundGroup,
}

/// Whether a correlated [`DaemonFrame::Signal`] was delivered.
///
/// **This is `Result<(), String>` in every sense except its
/// representation, and the representation is not a choice.** The plan
/// for this milestone specifies `Result<(), String>` literally, and
/// ciborium 0.2.2 cannot carry it: `Ok(())` serialises as `{"Ok":
/// null}`, and decoding that back fails with `invalid type: Option
/// value, expected unit` — the codec maps a CBOR `null` onto `Option`
/// and never onto unit, so the success arm of any `Result<(), E>` is
/// write-only. Measured, not inferred; it is what
/// `every_daemon_frame_and_worker_frame_round_trips` reddened on before
/// this type existed, and it would not have been caught by a fixture
/// that only exercised the error arm.
///
/// The `From` impls below keep `Result<(), String>` as the shape both
/// ends actually handle, so the substitution stops at the wire. No error
/// *type* crosses this link: `HoldfastError` is not on it and does not
/// need to be, because the daemon's only use for the message is to
/// rebuild `HoldfastError::Pty(message)` — which is exactly what the
/// in-process backend returns for the same failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalOutcome {
    Delivered,
    Failed(String),
}

impl From<Result<(), String>> for SignalOutcome {
    fn from(r: Result<(), String>) -> Self {
        match r {
            Ok(()) => Self::Delivered,
            Err(message) => Self::Failed(message),
        }
    }
}

impl From<SignalOutcome> for Result<(), String> {
    fn from(o: SignalOutcome) -> Self {
        match o {
            SignalOutcome::Delivered => Ok(()),
            SignalOutcome::Failed(message) => Err(message),
        }
    }
}

/// What a [`WorkerFrame::Reply`] carries.
///
/// **Named for queries but wider than [`QueryKind`], deliberately.**
/// [`Signalled`](Self::Signalled) answers [`DaemonFrame::Signal`], which
/// is not a query — it is here because `PtyBackend::signal` returns
/// `Result<()>` and a fire-and-forget send cannot produce one. One reply
/// frame and one correlation space is simpler than two of each, and the
/// alternative is a second `Reply`-shaped frame whose only difference is
/// which requests it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryResult {
    Discipline(LineDiscipline),
    ForegroundGroup(Option<i32>),
    Signalled(SignalOutcome),
}

/// Daemon → worker.
///
/// The order is this catalogue's order and it is the order of the link's
/// own life: identity, spawn, the steady state, then stop. §18's
/// preamble makes a catalogued position normative rather than
/// decorative, and the same rule is worth keeping here even though §23.4
/// exempts this wire from the gate — `serde`'s variant list comes back
/// in declaration order, so an appended variant reads differently from
/// an inserted one in every diff of this file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonFrame {
    /// The first frame on the link, always.
    ///
    /// `build` is [`WORKER_PROTOCOL_TAG`]; `session_id` is the session
    /// whose socket this is, and is carried so the worker can refuse a
    /// connection that reached the wrong socket rather than trusting the
    /// path it was handed on its argv.
    Hello { build: String, session_id: String },
    /// Sent once, immediately after [`Hello`](Self::Hello). **The worker
    /// spawns nothing until it arrives** — the child is created by this
    /// frame and not by the worker's own argv, so a worker that never
    /// gets one has forked nothing to leak.
    Spawn { cfg: PtySpawnConfig },
    /// Bytes for the child's stdin.
    ///
    /// Bounded far below the codec's cap by `send_input`'s existing
    /// 64 KiB limit, which is upstream of this frame and stays there.
    Write {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// Deliver a signal to the child's process group.
    ///
    /// Correlated, unlike [`Write`](Self::Write): `PtyBackend::signal`
    /// returns `Result<()>` and the daemon has no other way to learn
    /// whether delivery succeeded once the process group is not its own.
    Signal { id: u64, sig: Signal },
    /// Resize the terminal.
    ///
    /// Already clamped daemon-side by `clamp_geometry` — every caller
    /// applies it *before* the backend call, because the response
    /// reports the size the terminal reached. **The worker clamps
    /// again**, because a worker must not trust its peer even when its
    /// peer is itself, and because `vt100` underflows below
    /// `MIN_COLS`/`MIN_ROWS` rather than erroring.
    Resize { cols: u16, rows: u16 },
    /// Ask the worker something only a master-fd holder can answer.
    Query { id: u64, what: QueryKind },
    /// Stop gracefully: sweep the child's groups, then exit.
    ///
    /// The socket closing is the **un**graceful path and is a different
    /// mechanism, not a shorthand for this one.
    Shutdown,
}

/// Worker → daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkerFrame {
    /// The echo of [`DaemonFrame::Hello`]'s identity assertion, sent
    /// before [`DaemonFrame::Spawn`] is accepted.
    Ready { build: String },
    /// The child exists.
    ///
    /// **`pgid` and `sid` are load-bearing and are not diagnostics.**
    /// The daemon's fallback sweep — the one that runs when the worker
    /// dies without retiring the child's groups — has nothing else to
    /// aim at, because the worker held the master fd and the daemon
    /// never did. `None` on Windows, where a job object retires the tree
    /// instead and there is no session id to report.
    Started {
        child_pid: u32,
        pgid: Option<i32>,
        sid: Option<i32>,
    },
    /// The child could not be created; maps to the existing
    /// `spawn_failed` status and adds none.
    ///
    /// `message` is trimmed the same way the in-process path trims it,
    /// because the underlying `portable-pty` message embeds the whole
    /// `$PATH` and §18.1 already requires that not to reach a response.
    SpawnFailed { message: String },
    /// One PTY read.
    ///
    /// **Raw, and staying raw** (REQ-SPTY-004). Redaction is the
    /// daemon's, on read, downstream of the buffer; a redactor in the
    /// worker is the thing that requirement forbids.
    Output {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// The child exited. In-band, and **after** the last
    /// [`Output`](Self::Output) frame.
    ///
    /// That ordering is the whole of Task 5 and it re-creates a defect
    /// 0.0.6 already shipped once: a liveness check that returned before
    /// the loop that drains the queue threw away everything already
    /// queued. Acting on this frame before draining the frames ahead of
    /// it loses the child's last line.
    ///
    /// `signal` reaches the audit log and **no response**. Widening the
    /// trait to carry how a child died is REQ-P-007's fix and belongs to
    /// the milestone that revisits the backend seam; REQ-SPTY-001 rules
    /// it out of this one.
    Exited {
        code: Option<i32>,
        signal: Option<String>,
    },
    /// The answer to a correlated [`DaemonFrame::Signal`] or
    /// [`DaemonFrame::Query`].
    Reply { id: u64, result: QueryResult },
    /// The worker has hit an unrecoverable internal error and is about
    /// to exit.
    ///
    /// **Contains no PTY bytes.** This is the one frame whose payload is
    /// *composed* rather than copied, which makes it the one place a
    /// `{:?}` of a read buffer would put raw child output into a string
    /// the daemon logs — a leak the output-path redactor cannot see,
    /// because this is not the output path.
    Fault { message: String },
    /// A `type` this build does not know. **Never constructed by the
    /// worker and never encoded** — produced only by
    /// [`WorkerFrame::decode_body`] so the daemon can skip forward
    /// instead of dropping the link.
    ///
    /// `#[serde(skip)]` on a variant of an internally-tagged enum is a
    /// **runtime** error and not a compile-time one — measured on
    /// ciborium 0.2.2, serialising it yields `Err(Value("the enum
    /// variant … cannot be serialized"))` — so "never encoded" is a
    /// claim nothing enforces on its own. Here the enforcement is
    /// [`encode_frame`]'s `debug_assert!`, which is reachable because
    /// this link has exactly one encode helper; `attach::frames` has to
    /// put the same assertion at each send site.
    #[serde(skip)]
    Unknown { type_name: String },
}

/// Every `type` string the daemon sends, in [`DaemonFrame`]'s order.
///
/// Pinned by [`DaemonFrame::tag`]'s exhaustive match rather than kept by
/// hand: §7.6.3 held a second, hand-copied enumeration of a frame set
/// and it drifted three ways before anything was built.
pub const KNOWN_DAEMON_TYPES: &[&str] = &[
    "Hello", "Spawn", "Write", "Signal", "Resize", "Query", "Shutdown",
];

/// Every `type` string the worker sends, in [`WorkerFrame`]'s order.
///
/// `Unknown` is **not** here and must never be: it is what this array's
/// absence of a name *means*, so listing it would make every unknown
/// frame decode as a genuine error instead.
pub const KNOWN_WORKER_TYPES: &[&str] = &[
    "Ready",
    "Started",
    "SpawnFailed",
    "Output",
    "Exited",
    "Reply",
    "Fault",
];

/// One direction of the worker link.
///
/// Implemented for exactly [`DaemonFrame`] and [`WorkerFrame`] and not
/// an extension point: it exists so [`encode_frame`] and [`read_frame`]
/// can be one function each instead of two, while the *asymmetry*
/// between the directions — strict inbound at the worker, forgiving
/// inbound at the daemon — stays visible in each impl rather than
/// hiding behind a boolean parameter.
pub trait LinkFrame: Serialize + DeserializeOwned + Sized {
    /// This value's wire `type`, or `None` for a decode-only variant.
    ///
    /// Exhaustive on purpose in both impls — **no `_` arm** — so a
    /// variant added without a `KNOWN_*_TYPES` entry is a compile error
    /// rather than a silently short list.
    fn tag(&self) -> Option<&'static str>;

    /// Decode one CBOR body, applying this direction's strictness rule.
    fn decode_body(body: &[u8]) -> Result<Self, FrameError>;
}

impl LinkFrame for DaemonFrame {
    fn tag(&self) -> Option<&'static str> {
        Some(match self {
            Self::Hello { .. } => "Hello",
            Self::Spawn { .. } => "Spawn",
            Self::Write { .. } => "Write",
            Self::Signal { .. } => "Signal",
            Self::Resize { .. } => "Resize",
            Self::Query { .. } => "Query",
            Self::Shutdown => "Shutdown",
        })
    }

    /// Strict: an unrecognised `type` is an error.
    ///
    /// The worker is the side that *acts*, and it has no safe answer to
    /// an instruction it cannot read.
    fn decode_body(body: &[u8]) -> Result<Self, FrameError> {
        frame::decode(body)
    }
}

impl LinkFrame for WorkerFrame {
    fn tag(&self) -> Option<&'static str> {
        Some(match self {
            Self::Ready { .. } => "Ready",
            Self::Started { .. } => "Started",
            Self::SpawnFailed { .. } => "SpawnFailed",
            Self::Output { .. } => "Output",
            Self::Exited { .. } => "Exited",
            Self::Reply { .. } => "Reply",
            Self::Fault { .. } => "Fault",
            Self::Unknown { .. } => return None,
        })
    }

    /// Forgiving: an unrecognised `type` becomes
    /// [`WorkerFrame::Unknown`], while genuinely corrupt bytes stay an
    /// error.
    ///
    /// Telling the two apart needs the second decode — re-reading the
    /// map's `type` key — and that is the whole reason it is here. A
    /// decoder that answered `Unknown` for every failure would satisfy
    /// "an unknown type does not kill the link" while also swallowing a
    /// truncated frame, which is the degenerate case
    /// `attach::frames::decode_server_frame` already pairs its own test
    /// against.
    fn decode_body(body: &[u8]) -> Result<Self, FrameError> {
        let err = match frame::decode::<Self>(body) {
            Ok(f) => return Ok(f),
            Err(e) => e,
        };
        let Ok(ciborium::value::Value::Map(entries)) =
            frame::decode::<ciborium::value::Value>(body)
        else {
            return Err(err);
        };
        for (k, v) in &entries {
            if k.as_text() != Some("type") {
                continue;
            }
            match v.as_text() {
                Some(name) if !KNOWN_WORKER_TYPES.contains(&name) => {
                    return Ok(Self::Unknown {
                        type_name: name.to_string(),
                    })
                }
                _ => {}
            }
        }
        Err(err)
    }
}

/// Serialise one frame into a complete wire frame (prefix + CBOR body).
///
/// **A call into [`frame::encode`] and nothing else.** No length
/// handling, no size constant, no truncating path: the 16 MiB cap and
/// its reject-rather-than-truncate answer are the codec's, measured
/// post-redaction, and re-implementing either here would be a second
/// place for them to disagree.
///
/// The `debug_assert!` is the only thing this adds, and it is the
/// enforcement behind [`WorkerFrame::Unknown`]'s "never encoded": in
/// release ciborium returns an error the caller might log and skip; in a
/// debug or test build this fails at the line that made the mistake.
pub fn encode_frame<F: LinkFrame>(frame: &F) -> Result<Vec<u8>, FrameError> {
    debug_assert!(
        frame.tag().is_some(),
        "a decode-only frame reached the encoder"
    );
    frame::encode(frame)
}

/// Read one frame from the link.
///
/// **[`frame::read_frame_body`] plus this module's decode, not a second
/// reader.** The prefix, the cap and the EOF mapping stay in exactly one
/// place; what varies by direction is only which body-decode runs, which
/// is [`LinkFrame::decode_body`].
pub async fn read_frame<R, F>(r: &mut R) -> Result<F, FrameError>
where
    R: AsyncRead + Unpin,
    F: LinkFrame,
{
    F::decode_body(&frame::read_frame_body(r).await?)
}
