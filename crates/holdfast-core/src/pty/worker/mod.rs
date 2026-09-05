//! The daemon ↔ `holdfast pty-worker` link (§4.1, milestone 0.0.10a).
//!
//! **This tree already has two wire formats and §23.3 gates both. This
//! is a third, and it is deliberately not a gate.** §23.4 rules on it by
//! name: the per-session daemon ↔ worker socket *is* a wire format,
//! which is the shape §23.3 gates, but both of its peers are the **same
//! build of the same binary** and one of them spawns the other. There is
//! no installed client on the far end and no version skew to survive —
//! the property every §23.3 boundary has and this one lacks. What
//! 0.0.10a must not change is the *observable behaviour* of
//! [`PtyBackend`](crate::pty::PtyBackend), and REQ-SPTY-001 says so
//! directly rather than through a gate.
//!
//! **That ruling is a licence to keep the protocol small. It is not a
//! licence to invent framing**, and a reader who finds a third protocol
//! here would otherwise be right to assume nobody thought about it. So,
//! stated once, in the file, where the next hand will look:
//!
//! * The **codec is [`crate::protocol::frame`], reused verbatim** — a
//!   4-byte big-endian length prefix, a CBOR body, a 16 MiB
//!   [`MAX_FRAME_BYTES`](crate::protocol::frame::MAX_FRAME_BYTES) that
//!   **rejects rather than truncates**. [`frames`] adds no length
//!   handling, no second constant and no second reader.
//! * The **message shape is [`crate::attach::frames`]'s** — a
//!   `#[serde(tag = "type")]` tagged union, byte payloads through
//!   `serde_bytes` so PTY output stays a CBOR byte string, and a
//!   decode-only `Unknown` variant so an unrecognised `type` cannot kill
//!   the link.
//! * The **`u64` correlation id is the control protocol's**, and it is
//!   the only thing borrowed from there. Three of the trait's methods
//!   are synchronous and need an answer back — `signal` returns
//!   `Result<()>`, `line_discipline` and `foreground_group` are reads of
//!   the master fd the daemon no longer holds — and a duplex stream
//!   carrying unsolicited `Output` cannot answer any of them without
//!   correlation.
//!
//! What is deliberately **not** reused is control's `Request { id,
//! method, params }` envelope. That envelope exists to carry an *open*
//! method namespace between independently-versioned peers. This link has
//! a closed catalogue of fourteen messages between two copies of one
//! binary — an open namespace is precisely the property §23.4 says this
//! boundary does not have, and adopting the envelope would be paying its
//! cost for none of its benefit.
//!
//! # Invariants this module is responsible for
//!
//! 1. **The worker never redacts.** REQ-SPTY-004 keeps the §9.2 pipeline
//!    in the daemon rather than duplicating it in the worker: the
//!    [`Output`](frames::WorkerFrame::Output) frame carries **raw** PTY
//!    bytes, the daemon's buffer stores raw, and `OutputProcessor`
//!    redacts on read exactly as it does today. The new hop sits
//!    upstream of the buffer and therefore upstream of the redactor, so
//!    nothing about redaction siting moves.
//! 2. **The 16 MiB cap is unreachable rather than load-bearing.** An
//!    [`Output`](frames::WorkerFrame::Output) frame is bounded by the
//!    worker's PTY read buffer, which is orders of magnitude below the
//!    cap. When there is a worker to drive, that must be asserted
//!    against *observed* frame sizes and never against the buffer
//!    constant, which would be a tautology.
//! 3. **[`Fault`](frames::WorkerFrame::Fault) carries no PTY bytes.** It
//!    is the one frame whose message is composed from an error rather
//!    than copied from the wire, which makes it the one place a `{:?}`
//!    of a read buffer could put raw output into a message the daemon
//!    logs — a leak on no output path, and therefore invisible to every
//!    guard that watches one.
//!
//! Invariants 2 and 3 are properties of a **running** worker, so nothing
//! here can assert them yet; `tests/worker_protocol.rs` names the two
//! rows that owe them and the task they are owed by.

pub mod frames;
