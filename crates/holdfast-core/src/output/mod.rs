//! The output processor: ANSI stripping, secret redaction, the targeted
//! holdback, and text encoding (spec §4.1, §9.2).
//!
//! The ring buffer stores **raw** bytes. Everything in this module runs on
//! *read*, over an expanded window `[req_start − lookbehind,
//! req_end + lookahead]`, so a secret that straddles a cursor boundary is
//! still redacted from both sides.
//!
//! **Matching runs over the bytes the caller will receive, not the bytes
//! the buffer holds** — see [`normalise`]. Redaction used to run on the
//! raw window while ANSI stripping ran afterwards in [`render`], so an
//! escape planted inside a credential broke the rule's anchor at match
//! time and was removed before the payload went out: the read
//! *reassembled* the token and reported `redactions: {}` (GH #125). Every
//! offset in this module is still a raw buffer offset — spans, the
//! holdback, the cursors a caller pages through — because the buffer is
//! the only thing two reads can agree about. `normalise` is what lets
//! the two coexist: it matches on the emitted stream and maps back.
//!
//! [`render`]: OutputProcessor::render

pub mod ansi;
pub mod encoding;
pub mod normalise;
pub mod pem;
pub mod prefix_index;
pub mod redact;
pub mod rules;

use crate::audit::AuditLog;
use ansi::{AnsiMode, AnsiStripper};
use encoding::TextEncoding;
use prefix_index::{PrefixIndex, DEFAULT_PREFIX_EXPANSION_LIMIT};
use redact::Span;
use rules::{RuleError, RuleSet};
use std::collections::BTreeMap;
use std::sync::Arc;

/// How much evidence a candidate the window could not judge is believed
/// on — and therefore how far one `[REDACTED:unresolved]` may reach past
/// its anchor, and how far back of `buffer.head` the at-`head` scan looks
/// for one (GH #14, GH #195, REQ-O-011a).
///
/// **Not a tunable, and not in the §4.2 limits table.** It is a bound on
/// a *disclosure* decision: below it a real key body is released raw,
/// above it ordinary output is masked, and both ends are the kind of
/// thing an operator should not be able to move by editing a TOML key
/// with no warning that it is a disclosure boundary — which is precisely
/// the complaint GH #14 makes about `redaction_lookahead_bytes`.
///
/// **The number is `2 × STREAM_CARRY_BYTES`, and the second derivation
/// is the load-bearing one.**
///
/// * *The one unbounded rule in the shipped set.* `private-key-block` is
///   `-----BEGIN…PRIVATE KEY-----[\s\S]*?-----END…PRIVATE KEY-----`, and
///   the lazy quantifier means one match is one key rather than a bundle.
///   A 16,384-bit RSA key — the largest anyone generates — is 12,464
///   bytes in PEM, so 16,384 covers it with room and 8,192 does not.
///   `STREAM_CARRY_BYTES`'s own doc makes the matching argument against
///   shrinking toward 512, where *"the smallest real PEM is ~1.7 KiB"*.
///   `_RSA_16384_PEM_FITS_INSIDE_THE_CARRY` holds this at compile time.
/// * *The same order as the stream, and deliberately not more.*
///   `attach/redact_stream.rs` withholds an unjudgeable candidate over a
///   sliding window of exactly this size. **It is not the same number as
///   the stream's coverage, and an earlier draft of this comment said it
///   was.** `feed_while_withholding` leaves withholding only on a feed
///   with no partial open and then sets `split = buf.len()`, so the whole
///   exit chunk is dropped as well: the stream covers
///   `2 × STREAM_CARRY_BYTES + r`, with `r` up to the feed size — 8,192
///   for the in-process pty reader, 65,536 for the subprocess worker.
///   Measured on one fixture through both surfaces, the read releases at
///   anchor + 16,400 and the stream at anchor + 24,560.
///
///   **The read is therefore the weaker of the two, and that is the
///   direction REQ-O-011a asks for**, whose words are that a *stream* is
///   *"never weaker than the tool it renders"*. What must not happen is
///   the inversion — a read covering more than the live view of the same
///   bytes would put the leak on `holdfast watch` while the tool looked
///   safe. `the_stream_is_never_weaker_than_the_read_it_renders` measures
///   both surfaces rather than comparing two constants, which is what the
///   row it replaced did and why this was not caught earlier.
///
/// What the cap buys, measured on this repository's own contents as the
/// share of a corpus covered by `unresolved` markers (the CHANGELOG entry
/// for GH #195 carries the full table). On 5.79 MB of this repository's
/// Rust the cap costs 2.90% at `max_bytes` 32,768 and **0.28%** at 4 MiB —
/// it *falls*, because a wider window resolves more candidates outright —
/// where masking `[u, window_end)` uncapped costs 3.91% and **38.65%**.
/// Uncapped, the damage scales with a number the caller chooses.
///
/// **Those shares were measured before GH #242, and GH #242 is why they
/// no longer describe this repository.** Every candidate they counted was
/// a `-----BEGIN` in prose or test source, believed for the whole carry
/// because `private-key-block`'s `[\s\S]*?` never dies. A `-----BEGIN`
/// candidate is now believed only while what follows can be PEM text
/// (`pem.rs`), so a prose mention costs nothing:
/// `the_documented_read_loop_drains_this_repositorys_own_changelog`
/// asserts the CHANGELOG's share is zero. The cap still bounds what a
/// candidate that *is* PEM text can cost, which is what it is for.
pub const UNVOUCHED_CARRY_BYTES: usize = 16 * 1024;

/// The second half of [`UNVOUCHED_CARRY_BYTES`]'s derivation, asserted at
/// compile time because it is a relation between two literals: a
/// 16,384-bit RSA private key is 12,464 bytes in PEM, and
/// `private-key-block` is the one unbounded rule in the shipped set. The
/// first half — parity with `attach/redact_stream.rs` — needs the other
/// module and is
/// `the_unvouched_carry_matches_the_stream_it_is_derived_from`.
const _RSA_16384_PEM_FITS_INSIDE_THE_CARRY: () = assert!(UNVOUCHED_CARRY_BYTES > 12_464);

/// Which of `held_back`'s rules stopped *this* read (§4.1, REQ-O-008).
///
/// **`held_back` is a disjunction and the caller was told it was one
/// thing.** `process` computes it as `safety_end < w.cap_end`, and two
/// independent rules lower `safety_end`. There were three: GH #14's
/// window bound was the third, it moved with neither `buffer.head` nor
/// anything else, and a caller following §4.1's *"retry at
/// `next_cursor`"* against it never advanced (GH #195). **It is not a
/// value here because it is no longer a holdback** — the read makes full
/// progress and the region carries a marker instead. That is the whole
/// of the change, and the enum shrinking is how it is visible from the
/// wire.
///
/// So every value here names a boundary that **moves with
/// `buffer.head`**, and §4.1's instruction is right for both. The one
/// qualification is REQ-O-005's, stated on the variant it belongs to: a
/// session that has stopped producing output produces no new bytes to
/// move the boundary with, and `state` and `interaction_mode` in the same
/// response are how a caller tells that apart from a boundary that is
/// about to move.
///
/// **An exact statement about the read that just happened, not a guess.**
/// `process` already knows which term produced the final `safety_end`,
/// because it computed it; reporting it costs a `match` and introduces no
/// inference, so there is no false-fire rate to measure.
///
/// The value is a fact about the boundary, never an instruction: it does
/// not touch `next_cursor`, `held_back` or the bytes returned, so an
/// agent that ignores it sees exactly the response it saw before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldBackCause {
    /// §4.1's targeted holdback: a known secret *prefix* is still
    /// arriving inside the trailing `partial_secret_scan_bytes` region.
    ///
    /// **The bound is a function of `buffer.head`**, so new output moves
    /// it and the same read makes progress. The exception is stated in
    /// the same breath by REQ-O-005: quiescence does not release it, so a
    /// session that stopped mid-token stays withheld — `state` and
    /// `interaction_mode` in the same response are how a caller tells the
    /// two apart, and `redact: false` is the audited hatch.
    InFlightSecret,
    /// REQ-O-008: the read would have ended inside an unfinished ANSI
    /// escape sequence and the child is still alive, so the tail is held
    /// until the sequence completes.
    ///
    /// **Transient at every `max_bytes`, which it was not before 0.0.8.**
    /// The withhold is transient because the next read starts at the
    /// introducer and scans `max_bytes` past it, so the sequence exceeds
    /// `ansi_incomplete_max_bytes` and is dropped. That argument needed
    /// `max_bytes > ansi_incomplete_max_bytes`, and at or below it the
    /// read returned zero bytes with the cursor frozen for ever — a
    /// second GH #195 through a different rule. `process` now declines to
    /// withhold at a boundary that would return the caller nothing, so
    /// this value never names a wedge. Pinned by
    /// `an_escape_under_the_incomplete_cap_no_longer_wedges`.
    IncompleteEscape,
}

impl HeldBackCause {
    /// The wire spelling. Mirrored by `mcp::schema::HeldBackCause`, which
    /// is what the agent is handed as a closed vocabulary; the two are
    /// asserted equal in both directions in `tests/schema.rs`.
    pub fn as_str(self) -> &'static str {
        match self {
            HeldBackCause::InFlightSecret => "in_flight_secret",
            HeldBackCause::IncompleteEscape => "incomplete_escape",
        }
    }

    /// Parse the wire spelling — the inverse of [`Self::as_str`], so a
    /// process on the other side of the daemon socket (`holdfast logs`)
    /// branches on the enum rather than on string literals it would have
    /// to keep in step by hand.
    ///
    /// `None` for anything else, which is what a **newer** daemon's third
    /// cause looks like to an older CLI. That falls back to the wording a
    /// daemon too old to send the field at all gets.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "in_flight_secret" => Some(HeldBackCause::InFlightSecret),
            "incomplete_escape" => Some(HeldBackCause::IncompleteEscape),
            _ => None,
        }
    }

    /// Every variant, for the tests and the vocabulary walk. Adding a
    /// variant without adding it here fails
    /// `the_held_back_causes_are_all_enumerated`.
    pub const ALL: &'static [HeldBackCause] = &[
        HeldBackCause::InFlightSecret,
        HeldBackCause::IncompleteEscape,
    ];
}

/// Tunables from the §4.2 limits table.
#[derive(Debug, Clone, Copy)]
pub struct ProcessingLimits {
    /// `redaction_lookbehind_bytes` — how far back of the requested range
    /// the redactor looks for context prefixes.
    pub lookbehind_bytes: usize,
    /// `redaction_lookahead_bytes` — how far past it, so a value that
    /// continues beyond the cursor is still matched.
    pub lookahead_bytes: usize,
    /// `partial_secret_scan_bytes` — size of the trailing region scanned
    /// for a secret that is still arriving.
    pub partial_secret_scan_bytes: usize,
    /// `ansi_incomplete_max_bytes` — how long an unfinished trailing
    /// escape may withhold the tail before it is treated as malformed.
    pub ansi_incomplete_max_bytes: usize,
}

impl Default for ProcessingLimits {
    fn default() -> Self {
        Self {
            lookbehind_bytes: 512,
            lookahead_bytes: 8192,
            partial_secret_scan_bytes: 512,
            ansi_incomplete_max_bytes: 64,
        }
    }
}

/// The three independent output knobs of `read_output` (§5.2).
#[derive(Debug, Clone, Copy)]
pub struct ReadOptions {
    pub ansi: AnsiMode,
    pub text_encoding: TextEncoding,
    /// `false` is the audited escape hatch, never a default. It disables
    /// redaction *and* the targeted holdback — that is the whole point of
    /// the hatch (§4.1: the way to obtain a withheld partial).
    pub redact: bool,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            ansi: AnsiMode::Strip,
            text_encoding: TextEncoding::Utf8,
            redact: true,
        }
    }
}

/// Which bytes the caller wants.
///
/// **Shape only.** This says where a read starts and therefore which end
/// `max_bytes` clips. It says nothing about §4.1's holdback: that is
/// [`Holdback`], on the request, because the licence is the per-call
/// opt-in and not the tail shape (GH #169).
#[derive(Debug, Clone, Copy)]
pub enum ReadStart {
    /// Forward from an absolute offset.
    Cursor(u64),
    /// The last N bytes.
    TailBytes(usize),
    /// The last N lines.
    TailLines(usize),
}

impl ReadStart {
    /// Whether the read is anchored at `buffer.head` rather than at an
    /// absolute offset. An oversized tail read drops its **oldest** bytes,
    /// so this is what decides which end `max_bytes` clips.
    ///
    /// It is deliberately *not* the holdback predicate. It used to be —
    /// `bypasses_holdback()` — and `holdfast logs --tail N` inherited the
    /// bypass by having the same shape, on a surface §4.1 names as a
    /// non-member (GH #169).
    pub fn is_tail(&self) -> bool {
        matches!(self, Self::TailBytes(_) | Self::TailLines(_))
    }
}

/// Whether §4.1's targeted secret holdback applies to a read.
///
/// **It is a field on [`ReadRequest`] and not a property of
/// [`ReadStart`], and that is the whole of the fix for GH #169.** §4.1:
///
/// > **What licenses the bypass is the per-call opt-in, not the tail
/// > shape** — so the exemption covers exactly those two arguments on the
/// > one tool that takes them, and **nothing else**.
///
/// Encoding the bypass in the *shape* said the opposite, and every
/// tail-shaped read inherited it. §4.1 names three tail-shaped
/// non-members; two of them (`get_screen_state`, the `observer` stream)
/// never reached this type, and the third — `holdfast logs <session>
/// --tail N` — did, because it is served by `read_output`. §4.1 on that
/// one: *"`--raw` is that surface's opt-in and it is audited; `--tail`
/// is not an opt-in to anything."*
///
/// There is no `Default`, here or on [`ReadRequest`]. A new read surface
/// has to name its answer, and the compiler asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holdback {
    /// The read stops at `holdback_boundary`. Every surface, unless it
    /// carried the opt-in below.
    Applies,
    /// The caller named `read_output`'s `tail_lines`/`tail_bytes`
    /// argument, so it asked for the freshest bytes and accepted the
    /// trade-off. Documented residual risk on those two arguments only
    /// (§4.1, REQ-O-003).
    BypassedByCallerOptIn,
}

/// A read request as the session sees it.
#[derive(Debug, Clone, Copy)]
pub struct ReadRequest {
    pub start: ReadStart,
    /// Whether §4.1's holdback applies. See [`Holdback`]: it is here
    /// rather than on `start` because the licence is the per-call opt-in,
    /// not the tail shape.
    pub holdback: Holdback,
    /// Raw-byte budget (§5.1): caps bytes read *from the ring buffer*,
    /// not the size of the encoded payload.
    ///
    /// It has two documented overshoots. When the cap would fall inside a
    /// secret, the read consumes to the end of that secret so the
    /// continuation cursor lands past it and not inside it (see
    /// [`OutputProcessor::process`]); those extra raw bytes are wholly
    /// inside the one marker the response already carries, so the returned
    /// payload is unchanged — only `bytes_returned` and `cursor` move. And
    /// when a page smaller than one UTF-8 character would otherwise end
    /// inside it, the read finishes the character — at most three bytes,
    /// and only where stopping short would return nothing (GH #241).
    pub max_bytes: usize,
    pub options: ReadOptions,
    /// Which mechanism is reading — `read_output` or, from 0.0.5,
    /// `resource_read`. Recorded in the audit trail when `redact` is
    /// false (§9.4 `redaction_disabled.tool`).
    pub tool: &'static str,
    /// Who asked, for §9.4's `redaction_disabled.client_kind`.
    ///
    /// **0.0.5 owns this value and this field is the seam it fills.**
    /// It derives the caller server-side from the authenticated control
    /// connection — `crate::mcp::caller::audit_surface("read_output")`
    /// returns both this and `tool` — precisely so that an agent cannot
    /// label its own unredacted read as a human's. There is deliberately
    /// no path from a tool argument to this field; do not add one.
    ///
    /// Before the daemon exists there is no connection to derive a
    /// caller from, so every read in this milestone is genuinely
    /// in-process and passes `"in_process"` — the same value 0.0.5's
    /// `Caller::InProcess` records for `--no-daemon`. §9.4's other
    /// values are the handshake tokens verbatim: `"shim"`, `"cli"`,
    /// `"ui-bridge"`.
    ///
    /// **Audit attribution only; never a redaction input.** No read
    /// path may branch on this field to decide whether to redact
    /// (REQ-SEC-018); §7.5's `Attach.role` is the only field that
    /// selects raw versus redacted output, and REQ-SEC-008a already
    /// forbids deriving *that* from `client_kind`.
    pub client_kind: &'static str,
}

impl ReadRequest {
    /// A cursor read with default options.
    pub fn since(cursor: u64, max_bytes: usize) -> Self {
        Self {
            start: ReadStart::Cursor(cursor),
            holdback: Holdback::Applies,
            max_bytes,
            options: ReadOptions::default(),
            tool: "read_output",
            client_kind: "in_process",
        }
    }
}

/// A snapshot of the buffer taken under its lock, plus everything the
/// processor needs to decide where the read may end. Constructed by
/// `Session::read_processed`; processing then happens outside the lock.
#[derive(Debug)]
pub struct WindowSnapshot<'a> {
    /// The expanded raw window.
    pub window: &'a [u8],
    /// Absolute offset of `window[0]`.
    pub window_start: u64,
    /// The trailing region scanned for an in-flight secret prefix.
    pub tail_region: &'a [u8],
    /// Absolute offset of `tail_region[0]`.
    pub tail_region_start: u64,
    /// The region the **unvouched** scan reads: `window`, plus up to
    /// [`UNVOUCHED_CARRY_BYTES`] of extra lookbehind in front of it.
    /// Empty for a snapshot built only to ask a boundary.
    ///
    /// **A third region, and the reason it is not the window is a
    /// continuation read** (GH #195). When a read masks `[u, e)` the
    /// cursor lands somewhere in `[u, u + UNVOUCHED_CARRY_BYTES)`, and
    /// the *next* read has to reach the same verdict about the same
    /// candidate or it releases the rest of it raw — the exact GH #14
    /// leak, re-entered from the other side. `lookbehind_bytes` is 512
    /// and a believed candidate reaches 16 KiB back, so the window cannot
    /// answer it: the anchor is simply not in the bytes `process` holds.
    ///
    /// It is not folded into `window` because `window` is what
    /// [`OutputProcessor::all_spans`] and
    /// [`OutputProcessor::render`] run over, and widening *those* is a
    /// different change with a different blast radius — more matched
    /// spans, more markers, a longer stripper walk on every read. This
    /// region is read by one scan and nothing else.
    ///
    /// [`OutputProcessor::render`]: OutputProcessor::process
    pub carry_region: &'a [u8],
    /// Absolute offset of `carry_region[0]`. Never later than
    /// `window_start`, and equal to it when the buffer's tail is nearer.
    pub carry_region_start: u64,
    /// First byte the caller asked for.
    pub req_start: u64,
    /// `buffer.head` at snapshot time.
    pub head: u64,
    /// `min(req_start + max_bytes, head)` — where the size cap bites.
    pub cap_end: u64,
    pub child_alive: bool,
    pub bypass_holdback: bool,
    /// A `tail_*` read whose requested extent exceeded `max_bytes`: the
    /// *oldest* bytes were dropped so the newest survive and the cursor
    /// still lands past `buffer.head`. Reported as `truncated_for_size`,
    /// because bytes really were lost to the size budget.
    pub front_clipped: bool,
    pub truncated_at_tail: bool,
}

/// The result of one processed read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedRead {
    /// Encoded per `text_encoding`.
    pub output: String,
    /// **Raw** bytes consumed, so it stays consistent with the cursor
    /// arithmetic; the encoded `output` may be longer or shorter (§5.1).
    /// It may also exceed the request's `max_bytes` — by the tail of a
    /// secret the cap landed inside, or by the at most three remaining
    /// bytes of a character a page smaller than it would otherwise split
    /// (GH #241), and only then.
    pub bytes_returned: usize,
    /// Absolute offset just past the bytes consumed.
    pub cursor: u64,
    pub truncated_at_tail: bool,
    pub truncated_for_size: bool,
    pub held_back: bool,
    /// Which rule produced the boundary — `Some` exactly when
    /// `held_back`, and `None` otherwise.
    ///
    /// **Why it is not a `truncated_for_size` variant.** A size cap is not
    /// a holdback: `mcp/resources.rs` calls collapsing the two into one
    /// flag "the fault to avoid", and `a_size_cap_is_not_a_holdback` pins
    /// it. A size-capped read reports `held_back: false`,
    /// `held_back_cause: None`, `truncated_for_size: true`. The two flags
    /// can also both be true at once (`front_clipped`), which one merged
    /// field could not express.
    ///
    /// **Why an unvouched region is not a value.** It is not a holdback
    /// either, since 0.0.8: the read completes and the region carries a
    /// `[REDACTED:unresolved]` marker, which `redactions` counts like any
    /// other. See [`HeldBackCause`].
    pub held_back_cause: Option<HeldBackCause>,
    pub next_cursor: Option<u64>,
    /// `kind -> count` for the redactions inside the returned range.
    ///
    /// Keyed by the rule's `kind`, except for [`redact::UNRESOLVED_KIND`],
    /// which names no rule and counts the regions this window could not
    /// vouch for (REQ-O-011a, GH #195).
    pub redactions: BTreeMap<String, usize>,
    /// An unfinished escape was dropped rather than withheld, because the
    /// child has exited or it exceeded `ansi_incomplete_max_bytes`. The
    /// daemon logs this, rate-limited, in 0.0.5.
    pub dropped_incomplete_escape: bool,
}

/// Owns the rule set, the prefix index, and the audit log. One per
/// daemon; shared by every read path.
#[derive(Debug)]
pub struct OutputProcessor {
    pub rules: Arc<RuleSet>,
    pub index: PrefixIndex,
    pub limits: ProcessingLimits,
    pub audit: Arc<AuditLog>,
}

impl OutputProcessor {
    pub fn new(rules: Arc<RuleSet>, audit: Arc<AuditLog>, limits: ProcessingLimits) -> Self {
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        Self {
            rules,
            index,
            limits,
            audit,
        }
    }

    /// The default set-up: built-in rules, no audit file.
    pub fn builtin() -> Result<Self, RuleError> {
        let rules = Arc::new(RuleSet::builtin()?);
        let audit = Arc::new(AuditLog::disabled(Arc::clone(&rules)));
        Ok(Self::new(rules, audit, ProcessingLimits::default()))
    }

    /// Where a read must stop (spec §4.1). `buffer.head` unless a secret
    /// is still arriving in the trailing region.
    ///
    /// **Asked of the raw region only, and [`normalise`] deliberately
    /// does not reach here (GH #142).** A revision of the GH #125 fix did
    /// ask the views, on the reasoning that a token arriving with a
    /// colour reset inside it is not in flight by the raw region's
    /// account and would be released half-emitted. That reasoning is
    /// right and the change was still wrong, because
    /// [`PrefixIndex::earliest_partial`]'s continuation test — *every
    /// byte from the prefix to the end of the region could still belong
    /// to the value* — is **load-bearing on control bytes**, and every
    /// view exists precisely to delete them.
    ///
    /// Measured, default read path, against this method's own answer:
    ///
    /// ```text
    /// added 210 packages\r\nnpm WARN deprecated \x1b[33m@acme/key-manager@1.2.3\x1b[0m\x1b[K
    ///   raw          boundary 75 = head, released
    ///   stripped     boundary 51, held_back, and it never releases
    /// ```
    ///
    /// `key-` is `mailgun-api-key`'s indexed prefix and the rest is
    /// ordinary text; the trailing `\x1b[K` used to end the run and
    /// disarm the holdback, and in the stripped view it is not there. A
    /// progress line that ends in an escape with no newline after it —
    /// which is most of them — strands the caller's own output behind a
    /// `held_back` that nothing will clear. The same shape takes
    /// `prompt.last_line` to `""` on every `status` and `list_sessions`,
    /// and turns a `wait_for_pattern` that answered instantly into one
    /// that burns its whole `timeout_secs`.
    ///
    /// **The rule that came out of it**, and the reason the two halves of
    /// the GH #125 fix are not symmetric: *a view may add a **marker**,
    /// because a marker is safe in every stream and costs the caller
    /// nothing it was entitled to; a view may not add a **withhold**,
    /// because a withhold denies the caller bytes, and the predicate that
    /// decides withholds reads exactly the bytes a view removes.*
    /// [`OutputProcessor::all_spans`] is the first half; this method is
    /// the second.
    ///
    /// The cost of stopping here is stated rather than elided: a
    /// credential that straddles a read boundary **with an escape inside
    /// it** is still released half-emitted on *this* surface, exactly as
    /// before that fix. That is GH #142. What closes it for a surface
    /// that **masks** instead of shortening is
    /// [`OutputProcessor::unvouched_boundary`]; `read_output` keeps this
    /// boundary and keeps the residual, because a shortened read cannot
    /// be revised — the byte that would revise it has been deleted from
    /// the only stream consulted.
    ///
    /// [`PrefixIndex::earliest_partial`]: prefix_index::PrefixIndex::earliest_partial
    pub fn holdback_boundary(&self, w: &WindowSnapshot<'_>, opts: &ReadOptions) -> u64 {
        if !opts.redact || w.bypass_holdback {
            return w.head;
        }
        self.index
            .earliest_partial(&self.rules, w.tail_region, w.tail_region_start)
            .unwrap_or(w.head)
    }

    /// The earliest offset in the trailing region the redactor cannot
    /// **vouch for** — §4.1's boundary asked of every stream a consumer
    /// can derive from these bytes, not only of the raw region (GH #142).
    ///
    /// **This is a second boundary, not a replacement, and exactly one
    /// kind of surface may consume it.**
    /// [`holdback_boundary`](Self::holdback_boundary) explains why a view
    /// may not drive a *withhold*: `earliest_partial`'s continuation test
    /// is load-bearing on the control bytes every view deletes, so a view
    /// that says "still arriving" about ordinary output says it for ever.
    /// That argument is about **shortening**. A read that has been
    /// shortened cannot be revised, because the byte that would revise it
    /// — the space, the newline, the `\x1b` — is the byte the view
    /// removed, and `read_output` consults no other stream. The denial is
    /// therefore permanent, and the two cases are provably
    /// indistinguishable: `use crate::re_exports\x1b[0m` in a stripped
    /// view genuinely *is* `\bre_[A-Za-z0-9_]{24,}` with seven of its
    /// twenty-four value bytes arrived.
    ///
    /// **A mask is not a shortening and the argument does not carry over
    /// to it.** §18.2 gives `held_back` two spellings and says which
    /// surface gets which: *"On a cursor read the response is
    /// **shortened**: the read end is capped at `holdback_boundary` and
    /// `next_cursor` stops there. On `get_screen_state` the grid is
    /// **masked**, not shortened — a screen has no tail to cut, so the
    /// withheld cells carry `[REDACTED:unresolved]` and the geometry is
    /// unchanged."* The stated reason is geometry, never principle. A
    /// masked grid denies no range, moves no cursor, and is
    /// **re-rendered from the live parser on every call** (REQ-O-011a:
    /// the mask is the cells where the live render differs from the
    /// render at the boundary), so the next call simply produces a
    /// different answer. Nothing is destroyed, and the answer is revised
    /// the moment the buffer says something different.
    ///
    /// **The reach is bounded by the scan window, structurally.** Every
    /// view is built from `[head - partial_secret_scan_bytes, head)` and
    /// [`normalise::NormalView::raw_offset`] maps back into that same range, so no
    /// amount of deletion moves this boundary behind it. That bound is
    /// what keeps a *consuming* view — `C1::Strip` on an unterminated
    /// `0x9d`, which swallows everything after it — from being an
    /// unbounded denial primitive on the grid. It is still a denial: one
    /// such byte masks the cells written since the nearest indexed prefix,
    /// and what ends it is the prefix leaving the window rather than any
    /// terminator, because the view swallows terminators too. Pinned by
    /// `a_consuming_view_can_mask_back_to_the_scan_window_and_no_further`.
    ///
    /// **It is not free, and the cost is a rate rather than a strand.**
    /// A mask that never clears still covers the cells the unvouched
    /// bytes wrote, for as long as nothing else arrives, and the grid
    /// carries a residual of its own — see
    /// [`ScreenTracker::boundary_screen`] on an evicted replay front,
    /// which this boundary reaches more often than the raw one does.
    /// Measured rates and the eviction interaction are in the CHANGELOG
    /// entry for this change and pinned by the tests named there.
    ///
    /// Never later than [`holdback_boundary`](Self::holdback_boundary):
    /// a raw in-flight prefix is still in flight whatever a view thinks,
    /// so the two compose by `min`. `!opts.redact` and a `tail_*` bypass
    /// short-circuit for the reason §4.1 gives — the audited opt-out is
    /// the agent's recourse *from* the holdback, and a mask that survived
    /// it would be a hole in that recourse rather than a second layer.
    ///
    /// [`ScreenTracker::boundary_screen`]: crate::screen::ScreenTracker
    pub fn unvouched_boundary(&self, w: &WindowSnapshot<'_>, opts: &ReadOptions) -> u64 {
        let raw = self.holdback_boundary(w, opts);
        if !opts.redact || w.bypass_holdback {
            return raw;
        }
        let mut earliest = raw;
        for view in normalise::emitted_views(w.tail_region, w.tail_region_start) {
            // `region_start` is 0 because the offset wanted here is an
            // index *into the view*, which `NormalView::raw_offset` then
            // maps back to the raw stream. Handing the view the raw
            // `tail_region_start` would produce a number that is neither.
            if let Some(at) = self.index.earliest_partial(&self.rules, view.bytes(), 0) {
                earliest = earliest.min(view.raw_offset(at as usize));
            }
        }
        earliest
    }

    /// Every secret span in `region`, judged over **each byte stream a
    /// read of it could emit** and reported in raw buffer offsets
    /// (GH #125).
    ///
    /// The union, not a choice: a view can hide a match as well as
    /// create one. A credential inside an OSC title (`\x1b]0;ghp_…\x07`)
    /// is present in the raw bytes and absent from the stripped view,
    /// because the stripper consumes a sequence's payload — and `ansi:
    /// raw` emits those bytes. Scanning both costs one extra pass and
    /// owes nothing to which view found what.
    ///
    /// **`pub(crate)` for `attach::redact_stream`, which is the second
    /// surface that hands bytes to somebody (GH #135).** That module's
    /// own header says it is built on this module's primitives *"so the
    /// rule set cannot drift between the two surfaces"*, and it reached
    /// for `find_spans` because that was the primitive at the time. The
    /// union is the primitive now; a second hand-written one there would
    /// be exactly the drift that argument forbids.
    pub(crate) fn all_spans(&self, region: &[u8], region_start: u64) -> Vec<Span> {
        let mut spans = redact::find_spans(&self.rules, region, region_start);
        for view in normalise::emitted_views(region, region_start) {
            spans.extend(
                redact::find_spans(&self.rules, view.bytes(), 0)
                    .into_iter()
                    .map(|s| view.map_span(s)),
            );
        }
        // `find_spans` merges what it found; the union of several passes
        // has to be merged again, and for the same reason (REQ-O-009):
        // a raw span and a mapped one covering the same credential must
        // read as one marker, not two.
        redact::merge_spans(spans)
    }

    /// Every complete `binary`-rule match in `region`, over each stream a
    /// read of it could emit — [`Self::all_spans`] restricted to the rules
    /// whose one match can outrun a lookbehind.
    pub(crate) fn binary_spans(&self, region: &[u8], region_start: u64) -> Vec<Span> {
        let mut spans = redact::find_binary_spans(&self.rules, region, region_start);
        for view in normalise::emitted_views(region, region_start) {
            spans.extend(
                redact::find_binary_spans(&self.rules, view.bytes(), 0)
                    .into_iter()
                    .map(|s| view.map_span(s)),
            );
        }
        redact::merge_spans(spans)
    }

    /// Redact one string a surface reports whole — a window title — as
    /// [`redact::redact_str`] does, and also mask a private-key candidate
    /// in it that nothing closes (GH #224).
    ///
    /// `redact_str` replaces complete matches and nothing else, so
    /// `printf '\033]0;%s\007' "$(head -n 8 id_rsa)"` put eight lines of
    /// key into `get_screen_state`'s `title` and `status`'s, joined by the
    /// emulator into one line, while `read_output` masked the same bytes.
    /// The candidate walk is the one every other surface runs, over the
    /// string as the surface reports it; a title is final rather than
    /// arriving, so a candidate still believed at its end is masked too.
    pub fn redact_standalone(&self, text: &str) -> String {
        let redacted = redact::redact_str(&self.rules, text);
        let spans: Vec<Span> = self
            .index
            .unterminated_candidates(&self.rules, redacted.as_bytes(), 0, pem::RegionEnd::Final)
            .into_iter()
            .map(|c| Span::unresolved(c.start, c.end))
            .collect();
        if spans.is_empty() {
            return redacted;
        }
        let bytes = redacted.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut at = 0usize;
        for span in redact::merge_spans(spans) {
            out.extend_from_slice(&bytes[at..span.start as usize]);
            out.extend_from_slice(redact::marker(redact::UNRESOLVED_KIND).as_bytes());
            at = span.end as usize;
        }
        out.extend_from_slice(&bytes[at..]);
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The byte ranges of `region` that are a private key as far as this
    /// processor can tell — for a surface that masks by *what bytes wrote
    /// a cell* rather than by a read range (GH #224, `get_screen_state`).
    ///
    /// Four kinds, and they are the four `process` masks: a complete
    /// `binary` match; a `-----BEGIN` candidate still believed at the
    /// region's end; one that died with key material behind it; and the
    /// key-body lines after one that stopped short (`pem::body_lines`) —
    /// the next screenful of a pager is the case the grid shows most. The
    /// last three are capped at [`UNVOUCHED_CARRY_BYTES`] past their
    /// anchor, as a read caps them, and a candidate a complete match
    /// covers is that match's. Sorted and disjoint.
    ///
    /// The region ends at `buffer.head`, so a last line still arriving is
    /// masked as far as a read masks it; a line only a live stream would
    /// hold is not, because a grid has nothing to hold it for.
    pub fn key_regions(&self, region: &[u8], region_start: u64) -> Vec<(u64, u64)> {
        let mut spans = self.binary_spans(region, region_start);
        let complete = spans.clone();
        for c in self.index.unterminated_candidates(
            &self.rules,
            region,
            region_start,
            pem::RegionEnd::Arriving,
        ) {
            if c.resumed && c.in_flight {
                continue;
            }
            if !complete
                .iter()
                .any(|s| s.start <= c.start && s.end > c.start)
            {
                let end = c.end.min(c.start + UNVOUCHED_CARRY_BYTES as u64);
                spans.push(Span::unresolved(c.start, end));
            }
        }
        redact::merge_spans(spans)
            .into_iter()
            .map(|s| (s.start, s.end))
            .collect()
    }

    /// The complete `binary` matches that open **behind** the window and
    /// reach the page (GH #243) — the ones `all_spans` over the window
    /// cannot see, because their anchor is not in it.
    ///
    /// Over `carry_region` rather than a wider window, and for the
    /// `binary` rules alone, for one reason: every other rule's match fits
    /// inside `lookbehind_bytes` and is already found from the window, so
    /// asking them again about sixteen more kilobytes costs a scan and
    /// finds nothing. A match wholly behind `req_start` is dropped, since
    /// the caller receives none of it; one that starts inside the window
    /// is `all_spans`'s already.
    ///
    /// **Scanned to `window_start + UNVOUCHED_CARRY_BYTES` and no
    /// further**, which bounds the cost on a read of any size — without
    /// it a 256 KiB read would re-judge its whole window for one rule, and
    /// the views over it are most of what a read costs on colourised
    /// output. A match found this way is therefore at most
    /// `UNVOUCHED_CARRY_BYTES` long, the same bound a candidate is
    /// believed over and the one `_RSA_16384_PEM_FITS_INSIDE_THE_CARRY`
    /// holds against the largest key the rule can match. A key painted
    /// with a colour change on every character can exceed it in raw
    /// bytes; that is outside this reach — and the likeliest way to paint
    /// one is not `lolcat` but `grep -n . id_rsa` under the common
    /// `grep --color=auto` alias, which wraps every matched character in
    /// its own colour change and makes a 3 KB key about 64 KB. Its header
    /// is not in the raw bytes either, so no candidate is found for it
    /// and nothing follows its body lines.
    fn carry_spans(&self, w: &WindowSnapshot<'_>) -> Vec<Span> {
        if w.carry_region_start >= w.window_start || w.carry_region.is_empty() {
            return Vec::new();
        }
        let region_end = w.carry_region_start + w.carry_region.len() as u64;
        let scan_end = (w.window_start + UNVOUCHED_CARRY_BYTES as u64).min(region_end);
        let region = &w.carry_region[..(scan_end - w.carry_region_start) as usize];
        self.binary_spans(region, w.carry_region_start)
            .into_iter()
            .filter(|s| s.start < w.window_start && s.end > w.req_start)
            .collect()
    }

    /// The unterminated candidates in `carry_region` that died with key
    /// material behind them, and the key-body lines after one that stopped
    /// short (`pem::body_lines`), that no span in `spans` covers — each one
    /// capped at [`UNVOUCHED_CARRY_BYTES`] past its anchor and the window's
    /// end. See [`PrefixIndex::unterminated_candidates`].
    ///
    /// [`PrefixIndex::unterminated_candidates`]: prefix_index::PrefixIndex::unterminated_candidates
    fn dead_candidates(
        &self,
        w: &WindowSnapshot<'_>,
        spans: &[Span],
    ) -> Vec<prefix_index::Unterminated> {
        let window_end = w.window_start + w.window.len() as u64;
        self.index
            .unterminated_candidates(
                &self.rules,
                w.carry_region,
                w.carry_region_start,
                pem::RegionEnd::Arriving,
            )
            .into_iter()
            .filter(|c| !c.in_flight)
            .filter(|c| {
                !spans
                    .iter()
                    .any(|s| !s.is_unresolved() && s.start <= c.start && s.end > c.start)
            })
            .map(|c| prefix_index::Unterminated {
                end: c
                    .end
                    .min(c.start + UNVOUCHED_CARRY_BYTES as u64)
                    .min(window_end),
                ..c
            })
            .filter(|c| c.end > w.req_start && c.start < c.end)
            .collect()
    }

    /// The earliest anchor in `[head − `[`UNVOUCHED_CARRY_BYTES`]`, head −
    /// partial_secret_scan_bytes)` that is still alive at the end of the
    /// window — the at-`buffer.head` half of GH #14, which no window size
    /// reaches.
    ///
    /// **This is the hole `read_output` had at `head` and `resources/read`
    /// has always had.** GH #14's declination was gated on `window_end <
    /// w.head`, so a window that *reached* `head` cleared the bound by not
    /// running the check rather than by resolving anything. A candidate
    /// still unterminated at `head` matches no rule, so `find_spans`
    /// reports nothing and the body goes out raw with `redactions: {}` and
    /// no audit entry — and `resources/read`, a `tail_*` read and any
    /// `max_bytes` large enough to reach `head` are **one mechanism with
    /// three names**, all three doing it. Measured: a 12,350-byte buffer
    /// holding an unterminated `-----BEGIN RSA PRIVATE KEY-----` gives 17
    /// bytes with `held_back: true` at `max_bytes` 4,096 and the whole key
    /// body, raw, at 8,192 and at every larger value.
    ///
    /// **Two bounds, and both of them are the point.**
    ///
    /// * The region **starts** at `head − UNVOUCHED_CARRY_BYTES`. A
    ///   candidate anchored further back has had more evidence than the
    ///   constant licenses and is not believed — the sliding window
    ///   `attach/redact_stream.rs` already keeps. It is also what keeps
    ///   this scan off the whole-buffer cost: `resources/read` judges up
    ///   to 4 MiB, and `earliest_partial` walks a liveness automaton from
    ///   every anchor it finds.
    /// * The region **ends** at `head − partial_secret_scan_bytes`, where
    ///   [`holdback_boundary`](Self::holdback_boundary)'s region begins.
    ///   The two must not overlap: that one *shortens* and `tail_bytes`
    ///   opts out of it (REQ-O-003), this one *masks* and nothing opts
    ///   out of it but `redact: false`. An overlap would mask the
    ///   in-flight partial REQ-O-003's paired fixture requires a
    ///   `tail_bytes` read to return.
    ///
    /// `earliest_partial` and not `unresolved_from`: the trailing
    /// value-run detector is a fact about a **window** edge, and at `head`
    /// there is no window edge — there is the end of what has arrived,
    /// which is §4.1's question and is answered *targeted*. Running it
    /// here would stamp a marker over the last partial word of every read.
    ///
    /// **The scan reads to `window_end` and the *answer* is filtered, and
    /// the two are not interchangeable.** `earliest_partial`'s third
    /// condition is *the rule's own anchored regex does not match yet* —
    /// asked of `region[i..]`, so a region cut at `head −
    /// partial_secret_scan_bytes` cannot see a terminator that lands after
    /// it. Scanning the cut region directly called a **completely
    /// terminated** `-----BEGIN…-----END` block in flight, and because it
    /// overlapped the real `private-key` span, `merge_spans` weakened the
    /// whole match to `unresolved`: a correct, rule-named redaction turned
    /// into an anonymous one, and `status.redaction_stats` lost the kind.
    /// Reading to `window_end` and discarding an answer at or after
    /// `carry_end` gives the same region ownership with the whole
    /// terminator in evidence, and it is exact rather than conservative
    /// because the scan returns the **earliest** qualifying anchor: if
    /// that one is at or after `carry_end`, there is none before it.
    /// Pinned by `a_terminated_key_block_keeps_its_own_kind_at_head`.
    fn unvouched_carry(&self, w: &WindowSnapshot<'_>, window_end: u64) -> Option<u64> {
        let region_start = w.carry_region_start;
        let carry_end = w
            .head
            .saturating_sub(self.limits.partial_secret_scan_bytes as u64)
            .clamp(region_start, window_end);
        let carry_start = w
            .head
            .saturating_sub(UNVOUCHED_CARRY_BYTES as u64)
            .clamp(region_start, carry_end);
        if carry_start >= carry_end {
            return None;
        }
        let at = |off: u64| (off - region_start) as usize;
        self.index
            .earliest_partial(
                &self.rules,
                &w.carry_region[at(carry_start)..at(window_end)],
                carry_start,
            )
            .filter(|u| *u < carry_end)
    }

    /// Run the pipeline over a snapshot. Pure: no locks, no I/O.
    ///
    /// With no terminal width, so a redraw is never collapsed (GH #247):
    /// whether a line wrapped is a question about the width, and a caller
    /// that cannot answer it gets every byte. `Session::read_processed`
    /// knows the session's width and calls [`Self::process_at_width`].
    pub fn process(&self, w: &WindowSnapshot<'_>, opts: &ReadOptions) -> ProcessedRead {
        self.process_at_width(w, opts, None)
    }

    /// [`Self::process`] for a session `cols` wide, which is what lets
    /// `ansi: "strip"` drop a redraw a terminal erased (GH #247) — only a
    /// line that cannot have wrapped at that width; see `erased_redraws`.
    pub fn process_at_width(
        &self,
        w: &WindowSnapshot<'_>,
        opts: &ReadOptions,
        cols: Option<u16>,
    ) -> ProcessedRead {
        let window_end = w.window_start + w.window.len() as u64;
        let holdback = self.holdback_boundary(w, opts);
        // The size cap and the holdback both bound the read; whichever
        // bites first decides which flag the agent sees.
        let bound = w.cap_end.min(holdback);

        // Pre-pass: walk the window up to `bound` to find out whether the
        // read would end inside an unfinished escape sequence.
        let mut dropped_incomplete_escape = false;
        let mut safety_end = bound;
        // Which term is currently *binding*, so the response can say which
        // of `held_back`'s rules stopped it. Recomputed rather than
        // inferred: `process` already knows, because it computed it.
        let mut cause = (holdback < w.cap_end).then_some(HeldBackCause::InFlightSecret);
        if opts.ansi == AnsiMode::Strip {
            let scan_end = bound.clamp(w.window_start, window_end);
            let mut probe = AnsiStripper::new();
            for (i, byte) in w.window[..(scan_end - w.window_start) as usize]
                .iter()
                .enumerate()
            {
                probe.feed(w.window_start + i as u64, *byte);
            }
            if let Some(seq_start) = probe.pending_start() {
                let seq_len = scan_end.saturating_sub(seq_start);
                // **`seq_start > w.req_start` is the third condition, and
                // without it REQ-O-008's withhold is a permanent wedge**
                // (GH #195, found by PR #215). The withhold is transient
                // *because* the next read starts at the introducer and
                // scans `max_bytes` past it, so the sequence exceeds
                // `ansi_incomplete_max_bytes` and is dropped instead. That
                // argument needs `max_bytes > ansi_incomplete_max_bytes`:
                // below it, `cap_end` is `req_start + max_bytes`, it stops
                // tracking `buffer.head`, and the pending sequence is the
                // same length on every retry for ever. Measured at
                // `max_bytes` 1/8/32/64 — zero bytes, cursor frozen, 300 KB
                // of later output not moving it — and clearing at 65.
                //
                // Pulling the read end back to `req_start` returns nothing,
                // so the withhold buys the caller no bytes and costs it
                // every byte. Dropping is what the two existing arms
                // already do when waiting cannot pay, and the stripper
                // emits nothing for those bytes either way;
                // `dropped_incomplete_escape` says so.
                if w.child_alive
                    && seq_len <= self.limits.ansi_incomplete_max_bytes as u64
                    && seq_start > w.req_start
                {
                    // The child may still finish it: withhold the tail.
                    safety_end = seq_start;
                    cause = Some(HeldBackCause::IncompleteEscape);
                } else {
                    // A dead child never will, and neither will one that
                    // has already exceeded the cap — nor one where waiting
                    // would return the caller nothing at all.
                    dropped_incomplete_escape = true;
                }
            }
        }

        let mut spans = if opts.redact {
            let mut spans = self.all_spans(w.window, w.window_start);
            // **A match that opened behind the window still covers the
            // page (GH #243).** The window reaches `lookbehind_bytes` —
            // 512 — behind `req_start`, and a private key is kilobytes, so
            // a read that starts inside a *complete* key never saw its
            // `-----BEGIN` and `find_spans` matched nothing: `tail_lines`,
            // `tail_bytes` and a cursor partway in all returned the rest
            // of the body raw with `redactions: {}`. The carry region
            // reaches `UNVOUCHED_CARRY_BYTES` back, which covers the
            // largest key the rule can match, and only the `binary` rules
            // can need it — every other rule's match fits the lookbehind.
            spans.extend(self.carry_spans(w));
            redact::merge_spans(spans)
        } else {
            Vec::new()
        };

        // **The window is evidence, and a match can run off the end of it
        // (GH #14).**
        //
        // `find_spans` sees `[window_start, window_end)` and nothing more.
        // When `redaction_lookahead_bytes` cut that window short of
        // `buffer.head`, a rule whose match begins inside it and ends
        // outside it matches *nothing at all* — not partially, not
        // approximately — and the read hands back the secret's body raw
        // with `redactions: {}` and no audit entry. `private-key-block`
        // reaches that on a concatenated `.pem` bundle at `read_output`'s
        // own default `max_bytes`, on the first read, with no paging
        // involved.
        //
        // Raising the constant is not the fix: any bound is exceeded by
        // one more byte, and it does not reach a rule with **no indexed
        // prefix**, which gets no holdback at any window size. What closes
        // the class is noticing that the evidence ran out mid-candidate —
        // `unresolved_from` reports the earliest offset this window cannot
        // vouch for.
        //
        // **What the read then does with that offset is one
        // `[REDACTED:unresolved]` over the region, and not a withhold
        // (GH #195).** Until 0.0.8 it was a withhold, and the withhold had
        // two ends and both of them were wrong:
        //
        // * **It never released.** The bound is a function of
        //   `since_cursor`, `max_bytes` and bytes already in the buffer —
        //   not of `buffer.head` — so the identical read returns the
        //   identical boundary for ever. Measured on this repository's own
        //   `CHANGELOG.md`, which contains `-----BEGIN RSA PRIVATE
        //   KEY-----` as **prose**: `buffer.head` 136,206, read 1 returns
        //   32,768 B, read 2 returns 9,990 B and pins at 42,758, and reads
        //   3 through 9 return **zero bytes with the cursor frozen**.
        //   §4.1's `held_back` + `next_cursor` say *retry*, and retrying is
        //   what does not work.
        // * **It was selected by the shape of a regex rather than by
        //   risk.** The old condition 3 — "no span already covers it to the
        //   window's edge" — exempted an unbounded *greedy* rule, because
        //   such a rule matches to the last byte of the window and `render`
        //   already emits one marker over the whole unjudgeable region with
        //   full progress. That is the right answer, and a **lazy** rule
        //   never reaches the window edge, so `private-key-block`'s
        //   `[\s\S]*?` got the withhold instead. Identical risk, opposite
        //   handling, decided by how somebody wrote the quantifier.
        //
        // So the greedy arm's answer is now every arm's answer, and it
        // is the one the `attach`/`watch` stream already gives: one
        // `[REDACTED:unresolved]` over the region it cannot judge,
        // bounded by its carry window. REQ-O-011a names the marker as
        // the one a bounded window emits for *"a match the window cannot
        // judge"*; this is a bounded window.
        //
        // **`get_screen_state` was not a third example until GH #224,
        // and an earlier draft of this comment listed it as one.** Its
        // mask covered the trailing `partial_secret_scan_bytes` only, so
        // `read_output` returned one marker where the grid returned 39 raw
        // body lines. It now asks this processor which bytes behind the
        // screen are a key (`key_regions`) and masks the cells those
        // bytes wrote — the same regions this read masks, by a different
        // unit — which is `ScreenTracker::capture_judged`'s business.
        //
        // **A mask is legal here where a view-driven *withhold* is not.**
        // `holdback_boundary` explains the asymmetry: a shortened read
        // cannot be revised, so a wrong withhold is permanent. A mask
        // denies no range and moves no cursor backwards — the read
        // completes, the caller may read the same cursor again, and
        // `redact: false` is the audited hatch that was always the
        // recourse. Nothing is destroyed that a withhold was not already
        // destroying, and the caller gets the rest of its page.
        //
        // Three conditions survive, each still load-bearing:
        //
        // 1. **`opts.redact`** — the audited hatch disables redaction, and
        //    a marker is redaction (§4.1).
        // 2. **which detector answers**, which turns on whether the window
        //    reaches `buffer.head`:
        //    * *Truncated* (`window_end < w.head`) — `unresolved_from`,
        //      both its detectors. The window was cut by
        //      `redaction_lookahead_bytes` and everything past it is
        //      already in the buffer, so a trailing run of value bytes is
        //      evidence of a match running off a **window** edge.
        //    * *At `head`* — the anchored detector only, over
        //      [`UNVOUCHED_CARRY_BYTES`] and stopping where
        //      `holdback_boundary`'s region begins. At `head` what follows
        //      has not arrived rather than been cut, which is §4.1's
        //      question and REQ-O-003 answers it *targeted*: an indexed
        //      prefix inside `partial_secret_scan_bytes`. Running the
        //      trailing-run detector here instead would stamp a marker over
        //      the last partial word of every read — `buffer.head` lands
        //      mid-word constantly — which is the rev. 10–14 failure
        //      wearing a marker instead of a flag.
        //
        //      **The two regions are disjoint on purpose.**
        //      `holdback_boundary` owns `[head − partial_secret_scan_bytes,
        //      head)` and *shortens*, and `tail_lines`/`tail_bytes` opt out
        //      of it (REQ-O-003). This scan owns `[head −
        //      UNVOUCHED_CARRY_BYTES, head − partial_secret_scan_bytes)`
        //      and *masks*, and nothing opts out of it but `redact: false`,
        //      because a mask is redaction and the `tail_*` licence is a
        //      licence to bypass the holdback and nothing else. Overlapping
        //      them would mask the in-flight partial REQ-O-003's paired
        //      fixture requires a `tail_bytes` read to return.
        //
        //      **This bounds the at-`head` half at the front, and that
        //      narrows GH #14's residual there rather than closing it.**
        //      An anchor further back than `UNVOUCHED_CARRY_BYTES` is not
        //      found, so nothing is masked and the body is released
        //      exactly as `v0.0.7` released it. The bound is not symmetry:
        //      `earliest_partial` carries no GH #163 ceiling and walks a
        //      liveness automaton from every anchor to the end of its
        //      region, so an uncapped scan over a 1 MiB `resources/read`
        //      window is quadratic in a buffer an agent controls. The
        //      truncated branch can afford the whole window because
        //      `unresolved_from` *is* ceilinged. The visible consequence
        //      is that protection is **non-monotonic in `max_bytes`** on
        //      one buffer at one cursor — a smaller read truncates its
        //      window, takes the other branch, and finds an anchor the
        //      larger read does not. Pinned, in both directions, by
        //      `at_head_an_anchor_beyond_the_carry_is_released_and_one_inside_it_is_not`.
        // 3. **no span already covers it to the window's edge** — the
        //    greedy case above. A correct, rule-named marker is strictly
        //    better than an `unresolved` one over the same bytes, and
        //    `merge_spans` would otherwise weaken the name.
        //
        // The recourse for a caller who wants the masked bytes is
        // unchanged and is the only one that ever worked: the audited
        // `redact: false`. "A larger `max_bytes`" is **not** a general
        // recourse and never was — measured on a 338,264 B buffer bound at
        // 25,644, every one of 32,768 / 65,536 / 131,072 / 262,144 and the
        // clamped 262,145 returned zero bytes with the cursor frozen.
        if opts.redact {
            let unresolved = if window_end < w.head {
                // `carry_region` and not `window`: see the field's own
                // doc. A read that starts inside a region a *previous*
                // read masked has to reach the same verdict, and the
                // anchor that produced it is up to
                // `UNVOUCHED_CARRY_BYTES` behind `req_start` — six times
                // further back than `lookbehind_bytes` reaches.
                self.index
                    .unresolved_from(&self.rules, w.carry_region, w.carry_region_start)
            } else {
                self.unvouched_carry(w, window_end)
            }
            // `<` and not `<=`: at a tie the read stops in the same place
            // either way, and a span that begins exactly where the read
            // already ends covers no byte the caller receives.
            .filter(|u| *u < safety_end)
            .filter(|u| !spans.iter().any(|s| s.start <= *u && s.end >= window_end));
            if let Some(u) = unresolved {
                // **The marker reaches [`UNVOUCHED_CARRY_BYTES`] past the
                // anchor and no further, and that cap is the whole of what
                // this change costs.** The region `[u, window_end)` is
                // genuinely unjudgeable in full — if the match ended inside
                // the window `find_spans` would have found it, so a real
                // match covers every byte of it — but masking all of it
                // scales the damage with `max_bytes`, which the caller
                // chooses: measured over 5.79 MB of this repository's
                // Rust, uncapped masking costs 38.65% at a 4 MiB read
                // where the cap costs 0.28%.
                //
                // Past the cap the candidate is not believed. That is the
                // same trade `attach/redact_stream.rs` already makes at the
                // same number — its `2 × STREAM_CARRY_BYTES` sliding window
                // forgets an opening prefix and resumes mid-body, stated as
                // §9.2's residual (a) — so a cursor read is now neither
                // weaker nor stronger than the live stream rendering the
                // same bytes, which is what REQ-O-011a asks of a stream
                // ("never weaker than the tool it renders") read the other
                // way round.
                let end = (u + UNVOUCHED_CARRY_BYTES as u64).min(window_end);
                spans.push(redact::Span::unresolved(u, end));
                spans = redact::merge_spans(spans);
            }

            // **A candidate that died with key material behind it is
            // masked, not released (GH #242).** The two detectors above
            // own the candidates still believed at the window's edge.
            // Since a `-----BEGIN` candidate can stop at the first byte
            // that is not PEM text, there is a second kind — `head -n 15
            // id_rsa` and then a prompt — that is neither believed nor
            // matched, and nothing above sees it. Its extent is where
            // `pem::extent` stopped believing it, capped at the same
            // `UNVOUCHED_CARRY_BYTES` for the same reason, and one that a
            // complete match covers is left to that match's own marker.
            //
            // **And the key body that goes on after it** (the independent
            // review of GH #242): the next screenful of `less`, the middle
            // of a key `sed` prints in chunks, every line of a key printed
            // under a timestamp or a gutter that a pager cut off. Each was
            // masked while `[\s\S]*?` kept the candidate believed, and
            // each was released raw by the narrowing — `less` and a space
            // returned 23 body lines with `redactions: {}`. The lines that
            // carry key body are masked for the same carry past the
            // anchor, and the prompt and command between them are not.
            for c in self.dead_candidates(w, &spans) {
                spans.push(redact::Span::unresolved(c.start, c.end));
            }
            spans = redact::merge_spans(spans);
        }

        let mut read_end = safety_end.max(w.req_start).min(w.cap_end);
        // **A read never ends inside a UTF-8 character (GH #241).** The
        // cap is a raw byte count, and `encode` decodes each page on its
        // own, so a character split across two pages came back as two
        // U+FFFD — on both sides, silently, in text an agent then quotes
        // back into a `sed`. See `utf8_read_end` for the three arms.
        read_end = utf8_read_end(w, read_end);
        let held_back = safety_end < w.cap_end;
        let truncated_for_size = w.front_clipped || (w.cap_end < w.head && w.cap_end <= safety_end);
        // `held_back` and its cause answer the same question and must
        // never disagree. `then_some(..).flatten()` rather than `cause`:
        // the escape arm can set a cause at a `seq_start` that `cap_end`
        // then equals, which is a boundary nobody is held back at.
        let held_back_cause = held_back.then_some(cause).flatten();
        debug_assert_eq!(
            held_back,
            held_back_cause.is_some(),
            "held_back and its cause answer the same question and must never disagree"
        );

        // **The continuation cursor must never land inside a secret.**
        //
        // `render` already replaces a span that straddles `read_end` with
        // one whole marker, so *this* read is safe whatever `read_end` is.
        // The danger is the next one: a cursor left mid-secret starts a
        // window whose lookbehind cannot reach the value's anchor — a
        // 1.7 KB PEM is far past the 512-byte lookbehind — so `find_spans`
        // sees nothing, the raw key body is emitted with `redactions: {}`,
        // and no audit entry marks it. A leak with no symptom. §4.1 states
        // the opposite as normative: a secret partially in the previous
        // chunk is fully redacted again in the next one, with no leak.
        //
        // Widening the lookbehind cannot fix this — any bound is exceeded
        // by one more byte. Moving the cursor *past* the span closes the
        // class.
        //
        // This may push `read_end` beyond `cap_end`, i.e. past the caller's
        // `max_bytes`. That is deliberate, and it costs the caller nothing
        // it can observe in the payload: every byte in `[cap_end, span.end)`
        // is inside the span, and `render` emits exactly one marker for that
        // span either way, so `output` and `redactions` are byte-identical
        // to what the un-advanced `read_end` would have produced. Only
        // `bytes_returned` (raw bytes consumed) and the cursor move, and the
        // overshoot is bounded by the window, hence by `lookahead_bytes`.
        //
        // The alternative — pulling `read_end` back to `span.start` — was
        // rejected: when the request *begins* inside a secret (REQ-O-002,
        // the documented split-read case) `span.start <= req_start`, so the
        // read would return zero bytes and hand back the cursor it was
        // given. That is a paging loop that never terminates, and a hang is
        // worse than the leak being fixed here. Advancing is monotone:
        // `read_end` only ever grows, so no read makes less progress than
        // it did before.
        //
        // Spans arrive sorted and non-overlapping from `merge_spans`, so
        // one forward pass suffices: after an advance every later span
        // starts at or after the new `read_end`.
        advance_past_straddled(&mut read_end, &spans);

        // **The window is judged; the page is what goes out (GH #138).**
        //
        // `all_spans` above asked about `[window_start, window_end)`.
        // `render` below emits `[req_start, read_end)`, which is a
        // *subsequence* of it — and a subsequence can match a rule its
        // superstring does not. A leading `\b` is the everyday case: the
        // lookbehind supplies a word character in front of the token, the
        // window therefore holds `…xxxghp_…` and matches nothing, and the
        // page the caller receives begins at the `g`. GH #125 enumerated
        // the *filter* dimension of "the bytes the caller gets"; this is
        // its *range* dimension, and it needs no planted payload at all —
        // 51 of the rule set's own 61 positive fixtures leak through it,
        // measured by `tests/redaction_sweep.rs` against `v0.0.7`'s
        // pipeline (2886 of its rows, every one of them in the `paged`
        // geometry).
        //
        // **It is legal under this module's marker/withhold rule because
        // it is cursor-neutral.** The advance above fires on
        // `span.start < read_end && read_end < span.end`; every span
        // found here has `span.end <= read_end` by construction, since
        // `find_spans` cannot report past its region's end and
        // `NormalView::map_span` reaches at most the last byte of one. So
        // this pass can only add markers *inside* the page — never a
        // withhold, and never a cursor move of its own.
        //
        // The second `advance_past_straddled` is not that, and is not
        // redundant: `merge_spans` joins spans that merely **touch**
        // (REQ-O-009), so a page span ending exactly at `read_end` and a
        // window span starting exactly there become one span that does
        // straddle. The bytes that advance consumes are all inside that
        // span, so `render` covers them with the one marker it was
        // already going to emit and the payload is unchanged; only the
        // cursor moves, in the direction it was always allowed to move.
        //
        // Skipped when the page *is* the window, which is the common
        // single-read case and the one where this would be a second scan
        // of the same bytes for nothing. What it costs where it is not
        // skipped, measured rather than asserted:
        // `streaming_ordinary_output_is_never_held_back` — 1 MiB of
        // colourised build output paged 33 times at 32 KiB, every page a
        // strict subset of its window — runs in **0.12 s before and
        // 0.15 s after**, release, six runs each, same machine. It is a
        // second pass over the page and not over the window, so it is
        // bounded by `max_bytes` rather than by the lookahead.
        if opts.redact && (w.req_start > w.window_start || read_end < window_end) {
            let page_end = read_end.clamp(w.req_start, window_end);
            if w.req_start < page_end {
                let at = |off: u64| (off - w.window_start) as usize;
                let page_spans =
                    self.all_spans(&w.window[at(w.req_start)..at(page_end)], w.req_start);
                debug_assert!(
                    page_spans.iter().all(|s| s.end <= page_end),
                    "a span found in the page cannot reach past it"
                );
                if !page_spans.is_empty() {
                    spans.extend(page_spans);
                    spans = redact::merge_spans(spans);
                    advance_past_straddled(&mut read_end, &spans);
                }
            }
        }

        // **A redraw a terminal erased is not text the caller is shown
        // (GH #247).** See `erased_redraws`; the ranges it returns are
        // skipped by `render` exactly as a span is, minus the marker.
        let erased = match (opts.ansi, cols) {
            (AnsiMode::Strip, Some(cols)) => erased_redraws(w, &spans, read_end, cols),
            _ => Vec::new(),
        };
        let (mut bytes, mut redactions) = self.render(w, &spans, &erased, read_end, opts);
        if !erased.is_empty() {
            self.judge_collapsed(&mut bytes, &mut redactions);
        }

        ProcessedRead {
            output: encoding::encode(&bytes, opts.text_encoding),
            bytes_returned: (read_end - w.req_start) as usize,
            cursor: read_end,
            truncated_at_tail: w.truncated_at_tail,
            truncated_for_size,
            held_back,
            held_back_cause,
            next_cursor: (held_back || truncated_for_size).then_some(read_end),
            redactions,
            dropped_incomplete_escape,
        }
    }

    /// Walk the window once, emitting only bytes at or after `req_start`.
    ///
    /// A secret span is replaced by a single marker even when it starts in
    /// the lookbehind portion — that is what makes a secret split across
    /// two reads redact from both sides (§4.1). Its bytes are still fed to
    /// the stripper so escape state stays accurate.
    ///
    /// Bytes inside an `erased` range are fed to the stripper and emitted
    /// nowhere (GH #247).
    fn render(
        &self,
        w: &WindowSnapshot<'_>,
        spans: &[Span],
        erased: &[(u64, u64)],
        read_end: u64,
        opts: &ReadOptions,
    ) -> (Vec<u8>, BTreeMap<String, usize>) {
        let window_end = w.window_start + w.window.len() as u64;
        let mut out: Vec<u8> = Vec::new();
        let mut redactions: BTreeMap<String, usize> = BTreeMap::new();
        let mut stripper = AnsiStripper::new();
        let mut off = w.window_start;
        let mut next_span = 0usize;
        let mut next_erased = 0usize;

        while off < read_end {
            while next_span < spans.len() && spans[next_span].end <= off {
                next_span += 1;
            }
            if let Some(span) = spans.get(next_span) {
                if span.start <= off {
                    let feed_end = span.end.min(window_end);
                    for o in off..feed_end {
                        stripper.feed(o, w.window[(o - w.window_start) as usize]);
                    }
                    if span.end > w.req_start && span.start < read_end {
                        // `span_kind` and not `rules.rules[span.rule]`: a
                        // span may be the synthetic `unresolved` one,
                        // whose `rule` names no rule by construction.
                        let kind = redact::span_kind(&self.rules, span);
                        out.extend_from_slice(redact::marker(kind).as_bytes());
                        *redactions.entry(kind.to_string()).or_insert(0) += 1;
                    }
                    off = span.end;
                    continue;
                }
            }
            let byte = w.window[(off - w.window_start) as usize];
            let emitted = match opts.ansi {
                AnsiMode::Strip => stripper.feed(off, byte),
                AnsiMode::Raw => Some(byte),
            };
            while next_erased < erased.len() && erased[next_erased].1 <= off {
                next_erased += 1;
            }
            let is_erased = erased.get(next_erased).is_some_and(|e| e.0 <= off);
            if off >= w.req_start && !is_erased {
                if let Some(b) = emitted {
                    out.push(b);
                }
            }
            off += 1;
        }
        (out, redactions)
    }

    /// Judge a page `erased_redraws` shortened, **as the caller receives
    /// it**, and marker whatever it newly carries (GH #247).
    ///
    /// Dropping a redraw joins the text in front of its line to the text
    /// that replaced it — a stream no view in `normalise` enumerates,
    /// because none of them deletes a range. A rule that reaches across a
    /// line break (`\s` in a label rule's separator does) can match there
    /// and nowhere else: `PASSWORD:\n` then an erased ` x` then the value
    /// matches only once ` x` is gone. So the payload itself is matched —
    /// by `all_spans`, whose views are what `encode`'s filters can derive
    /// from it — and a match is replaced exactly as `render` replaces one.
    /// A match over a marker's own text replaces it with another marker,
    /// which shows nothing either did not.
    ///
    /// Only reached when something was erased, so an ordinary page pays
    /// nothing for it.
    fn judge_collapsed(&self, out: &mut Vec<u8>, redactions: &mut BTreeMap<String, usize>) {
        let spans = self.all_spans(out, 0);
        if spans.is_empty() {
            return;
        }
        let mut judged = Vec::with_capacity(out.len());
        let mut at = 0usize;
        for span in spans {
            let kind = redact::span_kind(&self.rules, &span);
            judged.extend_from_slice(&out[at..span.start as usize]);
            judged.extend_from_slice(redact::marker(kind).as_bytes());
            *redactions.entry(kind.to_string()).or_insert(0) += 1;
            at = span.end as usize;
        }
        judged.extend_from_slice(&out[at..]);
        *out = judged;
    }
}

/// The length a UTF-8 sequence opening with `lead` claims, or `None` for
/// a byte that opens nothing — ASCII, a continuation byte, or one of the
/// bytes no well-formed sequence starts with (`0xc0`, `0xc1`, `0xf5..`).
fn utf8_sequence_len(lead: u8) -> Option<u64> {
    match lead {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// Where a read that would end at `read_end` may end without splitting a
/// UTF-8 character (GH #241). Returns `read_end` unchanged unless the
/// bytes in front of it are the first part of a sequence whose remaining
/// bytes lie at or past it.
///
/// **Three arms, and the reason there are three is that the obvious one
/// wedges.**
///
/// * *Pull back to the lead byte* when that still returns the caller
///   something (`lead > req_start`). The rest of the character is the
///   first thing the next read returns, so both pages decode whole. At
///   most three bytes, and only ever of a character the page could not
///   finish — the same move REQ-O-008 makes for an unfinished escape.
/// * *Push forward to the character's end* when pulling back would return
///   nothing — a `max_bytes` smaller than one character, or a read whose
///   whole page is the front of one. Pulling back there hands the caller
///   its own cursor on every retry, which is GH #195's wedge through a
///   third rule; the overshoot is at most three bytes past `max_bytes`,
///   and only when the character's remaining bytes are already in the
///   window. `ProcessedRead::bytes_returned` documents it beside the
///   secret overshoot, which is the only other one.
/// * *Leave it* at `buffer.head` when the child has exited, or when the
///   remaining bytes have not arrived and pulling back would return
///   nothing. A dead child will never finish the character, so holding it
///   back would strand it; and a read that is *only* an unfinished
///   character is exactly the case the escape rule already declines to
///   withhold. What is left is at most three bytes that decode as
///   U+FFFD, which is what they are.
///
/// **Not a holdback.** It sets no flag and names no cause: it moves the
/// read end by less than one character and costs the caller no byte it
/// is not handed on the next read, which is why `held_back_cause`'s
/// closed vocabulary does not grow for it. A read cut short of `head` by
/// it still reports `cursor` at the lead byte, which is where the next
/// read must start, and a read that was already truncated for size hands
/// back that same offset as `next_cursor`.
fn utf8_read_end(w: &WindowSnapshot<'_>, read_end: u64) -> u64 {
    let window_end = w.window_start + w.window.len() as u64;
    if read_end <= w.req_start || read_end > window_end {
        return read_end;
    }
    let byte = |off: u64| w.window[(off - w.window_start) as usize];
    // Walk back to the byte that opened the character `read_end` might be
    // inside. At most three of a character's bytes can sit in front of a
    // split — a four-byte one cut after its third — so at most two of
    // them are continuation bytes, and the lead is at most three back.
    let floor = w.req_start.max(w.window_start);
    let mut lead = read_end - 1;
    while lead > floor && read_end - lead < 3 && (0x80..=0xbf).contains(&byte(lead)) {
        lead -= 1;
    }
    let Some(len) = utf8_sequence_len(byte(lead)) else {
        return read_end;
    };
    let char_end = lead + len;
    if char_end <= read_end {
        // The character closes at or before the read end: no split.
        return read_end;
    }
    if lead > w.req_start && (read_end < w.head || w.child_alive) {
        return lead;
    }
    // Pulling back would return nothing. Finish the character instead,
    // if the whole of it is here and really is one.
    if char_end <= window_end && (read_end..char_end).all(|off| (0x80..=0xbf).contains(&byte(off)))
    {
        return char_end;
    }
    read_end
}

/// The ranges of `[req_start, read_end)` holding a redraw a terminal has
/// already erased (GH #247) — what a progress bar leaves behind in the
/// byte stream: every frame of `Building [==>  ] 12/400`, each one
/// returned to column 0 by `\r` and wiped by the next.
///
/// **Only a line the stream itself erases, and only in two spellings a
/// terminal cannot read any other way.** Both start at a `\r` that is not
/// the first half of `\r\n`, and both drop everything on that line in
/// front of it:
///
/// * `\r`, then SGR only, then **erase-in-line** —
///   `\x1b[K`, `\x1b[0K` or `\x1b[2K`. From column 0 all three clear the
///   whole row, so nothing written on it before survives. This is how
///   cargo clears its bar before printing a `Compiling` line, and how
///   most progress bars redraw.
/// * `\r`, then a redraw of printable text and SGR only, **ending in
///   `\x1b[K`** before the next `\r` or `\n`. It overwrote the row from
///   column 0 and erased the rest, so again nothing older survives —
///   whatever the widths, wide characters included.
///
/// Anything else is left exactly as it was: a `\r` followed by a shorter
/// line with no erase (the old tail is still on screen), a redraw with a
/// tab, a backspace or a cursor movement in it, a redraw that has not
/// finished inside this page, and every byte under `ansi: raw`, which
/// promises the bytes.
///
/// **And a line that may have wrapped** (the independent review of
/// GH #247). `\r` returns to column 0 of the row the cursor is on, and an
/// erase clears that row — so a line wider than the terminal leaves every
/// row above its last one on screen, and dropping the whole line dropped
/// text a terminal still shows: 150 `W`s and a `\r\x1b[K` in an 80-column
/// session read back as nothing where the grid showed two rows of them.
/// So the line is dropped only if its start column is known and it never
/// reached past `cols`, counted the conservative way: every character
/// that is not ASCII as two columns, a column that is unknown after any
/// escape that can move the cursor, and a page whose first line began
/// before anything this window can see as unknown too. `cols` is the
/// session's width when the read is taken; a session widened *after* a
/// wrapped line was painted is the residual, since the rows it wrapped
/// onto are still on screen and this counts against the wider width.
/// **Nothing that a terminal still shows is dropped.**
///
/// **It never touches what redaction sees.** Spans are found on the whole
/// window before this runs and a range overlapping any of them is not
/// dropped, so no marker disappears; the cursor, `bytes_returned` and
/// every flag are unchanged, because the bytes were read — they are only
/// not shown. And a line with nothing printable in front of its `\r` —
/// bash's `\x1b[?2004l\r` before every command's output — is not
/// "collapsed" into a page that differs only by that `\r`.
fn erased_redraws(
    w: &WindowSnapshot<'_>,
    spans: &[Span],
    read_end: u64,
    cols: u16,
) -> Vec<(u64, u64)> {
    let window_end = w.window_start + w.window.len() as u64;
    let end = read_end.min(window_end);
    if end <= w.req_start {
        return Vec::new();
    }
    let cols = u32::from(cols);
    let at = |off: u64| w.window[(off - w.window_start) as usize];
    // A CSI sequence at `off`: where it ends and its final byte.
    let csi = |off: u64| -> Option<(u64, u8)> {
        if off + 1 >= end || at(off) != 0x1b || at(off + 1) != b'[' {
            return None;
        }
        let mut i = off + 2;
        while i < end {
            match at(i) {
                0x20..=0x3f => i += 1,
                f @ 0x40..=0x7e => return Some((i + 1, f)),
                _ => return None,
            }
        }
        None
    };
    // Where a non-CSI escape at `off` ends: a string sequence (OSC, DCS,
    // SOS, PM, APC) at its BEL or ST, anything else after its
    // intermediates and one final byte — the grammar `AnsiStripper`
    // consumes, so no byte of the sequence is mistaken for text.
    let escape_end = |off: u64| -> u64 {
        let mut i = off + 1;
        if i >= end {
            return end;
        }
        if matches!(at(i), b']' | b'P' | b'X' | b'^' | b'_') {
            i += 1;
            while i < end {
                match at(i) {
                    0x07 => return i + 1,
                    0x1b if i + 1 < end && at(i + 1) == b'\\' => return i + 2,
                    _ => i += 1,
                }
            }
            return end;
        }
        while i < end && (0x20..=0x2f).contains(&at(i)) {
            i += 1;
        }
        (i + 1).min(end)
    };
    // Erase-in-line from the cursor or of the whole line: `\x1b[K`,
    // `\x1b[0K`, `\x1b[2K`. Returns the byte after it and whether it was
    // the whole-line form.
    let erase = |off: u64| -> Option<(u64, bool)> {
        let (next, fin) = csi(off)?;
        let params =
            &w.window[(off + 2 - w.window_start) as usize..(next - 1 - w.window_start) as usize];
        (fin == b'K' && matches!(params, b"" | b"0" | b"2")).then_some((next, params == b"2"))
    };
    let mut out: Vec<(u64, u64)> = Vec::new();
    // The walk starts at the window, not the page, so the column the
    // page's first line began at can be known: from the stream's first
    // byte, or from the first `\r` the lookbehind holds. Before either it
    // is unknown, and so is every line that began then.
    let mut col: Option<u32> = (w.window_start == 0).then_some(0);
    let mut line_start = w.window_start;
    let mut printable = false;
    // The current line began at a known column and has not wrapped.
    let mut fits = col.is_some();
    let mut off = w.window_start;
    while off < end {
        let b = at(off);
        // A line feed — or the two other bytes that move the cursor down,
        // VT and FF — starts a new line, at the column it left.
        if matches!(b, b'\n' | 0x0b | 0x0c) {
            line_start = off + 1;
            printable = false;
            fits = col.is_some();
            off += 1;
            continue;
        }
        if b == 0x1b {
            // SGR changes no position. Every other sequence might: a
            // cursor move, a screen switch, a save and restore, a scroll —
            // after which a `\r` and an erase may land on a different row
            // or a different screen from the text written before it. So
            // anything but SGR ends the line as far as this rule is
            // concerned, and the text in front of it is never dropped.
            // Found by an independent review, on `\x1b[?1049h`. An erase
            // moves no cursor either, so the column survives it; after
            // anything else it is unknown until the next `\r`.
            match csi(off) {
                Some((next, b'm')) => off = next,
                Some((next, fin)) => {
                    off = next;
                    line_start = off;
                    printable = false;
                    if !matches!(fin, b'K' | b'J') {
                        col = None;
                    }
                    fits = col.is_some();
                }
                None => {
                    off = escape_end(off);
                    line_start = off;
                    printable = false;
                    col = None;
                    fits = false;
                }
            }
            continue;
        }
        if b != b'\r' {
            printable |= b >= 0x20 && b != 0x7f;
            // Where the cursor goes, counted so that a line that might
            // have wrapped is taken to have. A character is written at the
            // column after a full row only by wrapping to the next one.
            if let Some(c) = col.as_mut() {
                let width = match b {
                    0x20..=0x7e => 1,
                    0xc0..=0xff => 2,
                    _ => 0,
                };
                match b {
                    b'\t' => *c = ((*c / 8 + 1) * 8).min(cols.saturating_sub(1)),
                    0x08 => *c = c.saturating_sub(1),
                    _ if width > 0 => {
                        if *c + width > cols {
                            fits = false;
                            *c = 0;
                        }
                        *c += width;
                    }
                    _ => {}
                }
            }
            off += 1;
            continue;
        }
        // The first half of `\r\n` needs no arm of its own: the `\n` after
        // it is neither an erase nor a redraw ending in one, so both
        // spellings below decline it.
        let cr = off;
        // Spelling 1: SGR only, then an erase. **Not mode changes**, and
        // an earlier draft allowed them: `\x1b[?1049h` switches to the
        // alternate screen, so an erase after it clears *that* screen and
        // the line in front of the `\r` is still on the main one, shown
        // again the moment the program leaves — dropping it would drop
        // text a terminal still shows. Found by an independent review.
        let mut i = cr + 1;
        let mut erased = false;
        while let Some((next, fin)) = csi(i) {
            if erase(i).is_some() {
                erased = true;
                break;
            }
            if fin != b'm' {
                break;
            }
            i = next;
        }
        // Spelling 2: a redraw of text and SGR from column 0, ending in an
        // erase-to-end before the next `\r` or `\n` — both inside this
        // page, or it has not finished and nothing is decided.
        if !erased {
            let mut j = cr + 1;
            let mut last_was_erase = false;
            while j < end {
                let c = at(j);
                if c == b'\r' || c == b'\n' {
                    erased = last_was_erase;
                    break;
                }
                if c == 0x1b {
                    match (csi(j), erase(j)) {
                        (_, Some((next, false))) => {
                            last_was_erase = true;
                            j = next;
                        }
                        (Some((next, b'm')), _) => j = next,
                        _ => break,
                    }
                    continue;
                }
                if c < 0x20 || c == 0x7f {
                    break;
                }
                last_was_erase = false;
                j += 1;
            }
        }
        let drop = (line_start, cr + 1);
        let overlaps_span = spans.iter().any(|s| s.start < drop.1 && drop.0 < s.end);
        if erased && printable && fits && !overlaps_span && drop.1 > w.req_start {
            out.push(drop);
        }
        if erased {
            line_start = cr + 1;
            printable = false;
        }
        // `\r` is column 0 on whatever row the cursor is, and a line that
        // did not end here goes on from there without having wrapped.
        col = Some(0);
        fits |= erased;
        off = cr + 1;
    }
    out
}

/// Move `read_end` past any span it would otherwise end *inside*, so the
/// continuation cursor never lands mid-secret. See the long comment at
/// its first call site in [`OutputProcessor::process`] for why advancing
/// rather than retreating is the only option that terminates.
///
/// Monotone by construction, and called twice for that reason: a second
/// pass over a larger span set can only move `read_end` further forward.
fn advance_past_straddled(read_end: &mut u64, spans: &[Span]) {
    for span in spans {
        if span.start < *read_end && *read_end < span.end {
            *read_end = span.end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GITHUB: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    fn processor() -> OutputProcessor {
        OutputProcessor::builtin().unwrap()
    }

    /// Build a snapshot over a whole in-memory buffer, as a session with
    /// `head == buffer.len()` and nothing evicted would produce.
    fn snapshot<'a>(
        proc: &OutputProcessor,
        buffer: &'a [u8],
        req_start: u64,
        max_bytes: usize,
        child_alive: bool,
        bypass_holdback: bool,
    ) -> WindowSnapshot<'a> {
        let head = buffer.len() as u64;
        let cap_end = (req_start + max_bytes as u64).min(head);
        let window_start = req_start.saturating_sub(proc.limits.lookbehind_bytes as u64);
        let window_end = (cap_end + proc.limits.lookahead_bytes as u64).min(head);
        let scan_start = head.saturating_sub(proc.limits.partial_secret_scan_bytes as u64);
        let carry_start = req_start
            .saturating_sub(UNVOUCHED_CARRY_BYTES as u64)
            .min(window_start);
        WindowSnapshot {
            window: &buffer[window_start as usize..window_end as usize],
            window_start,
            carry_region: &buffer[carry_start as usize..window_end as usize],
            carry_region_start: carry_start,
            tail_region: &buffer[scan_start as usize..head as usize],
            tail_region_start: scan_start,
            req_start,
            head,
            cap_end,
            child_alive,
            bypass_holdback,
            front_clipped: false,
            truncated_at_tail: false,
        }
    }

    fn read(buffer: &[u8], req_start: u64, max_bytes: usize) -> ProcessedRead {
        let p = processor();
        let w = snapshot(&p, buffer, req_start, max_bytes, true, false);
        p.process(&w, &ReadOptions::default())
    }

    /// **The two boundaries compose by `min`, and `read_output` keeps the
    /// raw one (GH #142).** Three properties, each of which a plausible
    /// implementation gets wrong on its own:
    ///
    /// 1. the unvouched boundary is never *later* than §4.1's — a raw
    ///    in-flight prefix is still in flight whatever a view thinks;
    /// 2. it is strictly earlier on the fixture this issue is about, so
    ///    the row is not passing vacuously;
    /// 3. `process` — the read path — is byte-identical either way,
    ///    because it never asks this question. Handing it the unvouched
    ///    boundary is the change PR #162 measured at 2,570 zero-byte
    ///    second reads.
    #[test]
    fn the_unvouched_boundary_is_never_later_than_the_holdback_and_never_reaches_a_read() {
        let p = processor();
        let o = ReadOptions::default();
        let spliced = b"line one\nghp_0123456789a\x1b[0mbcdefghijABCDEFGHIJ01234";
        let arriving = format!("export TOKEN={}", &GITHUB[..20]).into_bytes();
        let ordinary = b"   Compiling holdfast-core v0.0.1\n".to_vec();

        for buf in [spliced.to_vec(), arriving, ordinary] {
            let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
            assert!(
                p.unvouched_boundary(&w, &o) <= p.holdback_boundary(&w, &o),
                "the unvouched boundary released bytes §4.1 is withholding"
            );
        }

        // Strictly earlier on the fixture, and §4.1 finds nothing at all.
        let w = snapshot(&p, spliced, 0, 32 * 1024, true, false);
        assert_eq!(p.holdback_boundary(&w, &o), w.head);
        assert!(p.unvouched_boundary(&w, &o) < w.head);

        // And the read is untouched: full payload, no flag, no cursor.
        let r = read(spliced, 0, 32 * 1024);
        assert!(!r.held_back);
        assert_eq!(r.bytes_returned, spliced.len());
        assert_eq!(r.next_cursor, None);
    }

    /// The audited opt-out and the `tail_*` bypass reach the new boundary
    /// on exactly the terms §4.1 gives them: both answer `head`, so a mask
    /// cannot survive a recourse that exists to get *past* the holdback.
    #[test]
    fn the_unvouched_boundary_honours_both_of_section_four_ones_bypasses() {
        let p = processor();
        let spliced = b"line one\nghp_0123456789a\x1b[0mbcdefghijABCDEFGHIJ01234";

        let w = snapshot(&p, spliced, 0, 32 * 1024, true, false);
        let no_redact = ReadOptions {
            redact: false,
            ..ReadOptions::default()
        };
        assert_eq!(p.unvouched_boundary(&w, &no_redact), w.head);

        let bypass = snapshot(&p, spliced, 0, 32 * 1024, true, true);
        assert_eq!(
            p.unvouched_boundary(&bypass, &ReadOptions::default()),
            bypass.head
        );
    }

    #[test]
    fn a_clean_read_returns_everything_and_sets_no_flags() {
        let buf = b"   Compiling holdfast-core v0.0.1\n    Finished in 13.72s\n";
        let r = read(buf, 0, 32 * 1024);
        assert_eq!(r.output, String::from_utf8_lossy(buf));
        assert_eq!(r.cursor, buf.len() as u64);
        assert_eq!(r.bytes_returned, buf.len());
        assert!(!r.held_back, "ordinary output must never be held back");
        assert!(!r.truncated_for_size);
        assert_eq!(r.next_cursor, None);
        assert!(r.redactions.is_empty());
    }

    #[test]
    fn a_secret_is_replaced_and_its_surroundings_survive() {
        let buf = format!("export TOKEN={GITHUB}\nnext line\n").into_bytes();
        let r = read(&buf, 0, 32 * 1024);
        assert!(!r.output.contains(GITHUB), "secret leaked: {}", r.output);
        // The absence check alone passes against an implementation that
        // returns nothing, so pin the exact surviving text too.
        assert_eq!(r.output, "export TOKEN=[REDACTED:github]\nnext line\n");
        assert_eq!(r.redactions.get("github"), Some(&1));
        assert_eq!(
            r.cursor,
            buf.len() as u64,
            "the cursor advances by raw bytes, not by marker length"
        );
    }

    #[test]
    fn ansi_escapes_are_stripped_by_default_and_kept_on_request() {
        let buf = b"\x1b[32mok\x1b[0m done";
        assert_eq!(read(buf, 0, 4096).output, "ok done");

        let p = processor();
        let w = snapshot(&p, buf, 0, 4096, true, false);
        let raw = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..Default::default()
            },
        );
        assert_eq!(raw.output, String::from_utf8_lossy(buf));
    }

    /// REQ-O-002 / §11.4 split-secret: a request that begins inside a
    /// secret still redacts, because the lookbehind sees its start.
    #[test]
    fn a_request_starting_inside_a_secret_still_redacts() {
        let buf = format!("prefix {GITHUB} suffix").into_bytes();
        let secret_start = 7u64;
        let r = read(&buf, secret_start + 10, 32 * 1024);
        assert!(!r.output.contains("abcdefghij"), "leaked: {}", r.output);
        assert_eq!(r.output, "[REDACTED:github] suffix");
        assert_eq!(r.redactions.get("github"), Some(&1));
    }

    /// The other half of REQ-O-002: a request that *ends* inside a secret.
    ///
    /// The cap at 20 lands 13 bytes into the token, so the read consumes
    /// to the token's end (47) instead: the marker is emitted either way,
    /// but a cursor of 20 would hand the *continuation* an offset inside
    /// the secret. `bytes_returned` therefore exceeds `max_bytes` — the
    /// one documented overshoot, and the payload is not one byte larger
    /// for it.
    #[test]
    fn a_request_ending_inside_a_secret_still_redacts() {
        let buf = format!("prefix {GITHUB} suffix").into_bytes();
        let r = read(&buf, 0, 20);
        assert!(!r.output.contains("ghp_012345"), "leaked: {}", r.output);
        assert_eq!(r.output, "prefix [REDACTED:github]");
        assert!(r.truncated_for_size, "more bytes are available now");
        assert!(!r.held_back, "a size cap is not a holdback");
        assert_eq!(
            r.next_cursor,
            Some((7 + GITHUB.len()) as u64),
            "the continuation must resume past the token, never inside it"
        );
        assert_eq!(r.bytes_returned, 7 + GITHUB.len());
    }

    /// Sequencing two reads over the same secret must leak in neither.
    #[test]
    fn neither_half_of_a_split_read_leaks() {
        let buf = format!("prefix {GITHUB} suffix").into_bytes();
        let first = read(&buf, 0, 12);
        let second = read(&buf, first.cursor, 32 * 1024);
        for part in [&first.output, &second.output] {
            assert!(!part.contains("ghp_0123"), "leaked: {part}");
            assert!(!part.contains("HIJ012345"), "leaked: {part}");
        }
        assert_eq!(first.output, "prefix [REDACTED:github]");
        // The first read consumed the whole token, so the second starts
        // exactly at its end and reports it no second time — `render`'s
        // `span.end > req_start` gate. The pair shows the secret once.
        assert_eq!(first.cursor, (7 + GITHUB.len()) as u64);
        assert_eq!(second.output, " suffix");
        assert!(second.redactions.is_empty());
    }

    /// A ~1.6 KB PEM: header, 24 base64 body lines, footer. Its body
    /// alone is three times `lookbehind_bytes`, which is the whole point
    /// — once a cursor sits more than 512 bytes past `-----BEGIN`, no
    /// later window can see the anchor and the rule cannot fire at all.
    fn pem_private_key() -> (String, String) {
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
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
        (pem, body)
    }

    /// §4.1, normative: *"a secret that was partially in the previous
    /// chunk is fully redacted again in the next chunk, with no leak."*
    ///
    /// The failure this pins had no symptom. `render` replaces a straddling
    /// span with a whole marker, so the *capped* read looked right; the
    /// cursor it returned pointed into the middle of the key, and the
    /// continuation read — the documented `next_cursor` paging loop — had
    /// no `-----BEGIN` within its 512-byte lookbehind, matched nothing,
    /// and returned raw key bytes with `redactions: {}` and no audit
    /// entry: indistinguishable from output that never held a secret.
    ///
    /// `max_bytes: 1024` is an ordinary agent choice made to save tokens,
    /// and against a 1.7 KB key it splits *deterministically*.
    #[test]
    fn paging_a_capped_read_over_a_private_key_leaks_no_key_material() {
        let (pem, body) = pem_private_key();
        let prologue = "cat id_rsa\n";
        let buf = format!("{prologue}{pem}\ndone\n").into_bytes();
        let key_start = prologue.len() as u64;
        let key_end = key_start + pem.len() as u64;

        // Control: read whole, the rule fires and nothing is withheld. If
        // this fails the fixture is wrong, not the cursor.
        let whole = read(&buf, 0, 64 * 1024);
        assert_eq!(whole.output, "cat id_rsa\n[REDACTED:private-key]\ndone\n");
        assert!(
            !whole.held_back,
            "the key is complete; nothing is in flight"
        );

        const CAP: usize = 1024;
        assert!(
            (CAP as u64) < key_end && (CAP as u64) > key_start,
            "the fixture must actually straddle the cap"
        );

        let mut chunks: Vec<String> = Vec::new();
        let mut cursor = 0u64;
        let mut reads = 0usize;
        loop {
            reads += 1;
            // Bounded so a cursor that stops advancing fails the test
            // instead of hanging CI.
            assert!(reads <= 16, "paging did not terminate (cursor {cursor})");
            let r = read(&buf, cursor, CAP);
            assert!(
                !(key_start < r.cursor && r.cursor < key_end),
                "read {reads} returned cursor {} inside the key [{key_start}, {key_end})",
                r.cursor
            );
            chunks.push(r.output);
            match r.next_cursor {
                Some(next) => {
                    assert!(next > cursor, "cursor stalled at {cursor}");
                    cursor = next;
                }
                None => break,
            }
        }
        assert!(reads >= 2, "the cap must actually have split the read");

        // No run of key material survives anywhere. 32 bytes is far past
        // anything that could collide by chance, and sweeping every offset
        // catches a partial line as well as a whole one.
        for (i, chunk) in chunks.iter().enumerate() {
            for start in 0..=body.len() - 32 {
                let needle = &body[start..start + 32];
                assert!(
                    !chunk.contains(needle),
                    "chunk {i} leaked key material from body offset {start}: {chunk}"
                );
            }
        }
        // And the paged reads say exactly what the single read said —
        // which also rules out a chunk that leaked nothing by returning
        // nothing.
        assert_eq!(chunks.concat(), whole.output);
    }

    /// The lookbehind exists so a secret that *straddles* the cursor is
    /// redacted from both sides — not so one the previous read already
    /// replaced is reported again. A span ending at or before `req_start`
    /// emits no marker and is counted in no response.
    ///
    /// Without this, `render`'s `span.end > w.req_start` gate is unpinned:
    /// dropping it leaves every other test in this module green, because
    /// every one of them requests a range the secret reaches into.
    #[test]
    fn a_secret_wholly_behind_the_cursor_is_not_re_reported() {
        let buf = format!("t={GITHUB}\nnext line\n").into_bytes();
        // Just past the newline that ends the token's line.
        let req_start = (2 + GITHUB.len() + 1) as u64;
        let r = read(&buf, req_start, 4096);
        assert_eq!(r.output, "next line\n");
        assert!(
            r.redactions.is_empty(),
            "a substitution the caller was never shown must not be counted: {:?}",
            r.redactions
        );
    }

    /// REQ-O-002, context rules: the label is in the lookbehind only.
    #[test]
    fn a_context_prefix_in_the_lookbehind_still_redacts_the_value() {
        let value = "0123456789abcdef0123456789abcdef";
        let buf = format!("DD_API_KEY={value} tail").into_bytes();
        let r = read(&buf, 11, 4096);
        assert!(!r.output.contains(value), "leaked: {}", r.output);
        assert_eq!(r.output, "[REDACTED:datadog] tail");
    }

    /// The documented limit in §4.1: past the lookbehind window a rule
    /// can no longer see the anchor that names its value.
    ///
    /// The limit is not peculiar to context rules — a prefix-anchored
    /// rule is bounded the same way, and `-----BEGIN` sits far more than
    /// 512 bytes ahead of a PEM's last line. Widening the lookbehind
    /// cannot repair that; the reason no *paged* read is exposed to it is
    /// that `process` never leaves a cursor inside a span, which
    /// `paging_a_capped_read_over_a_private_key_leaks_no_key_material`
    /// pins. This test is the reason that invariant has to exist.
    #[test]
    fn a_context_prefix_beyond_the_lookbehind_can_no_longer_protect_the_value() {
        let value = "0123456789abcdef0123456789abcdef";
        let filler = "x".repeat(1024);
        let buf = format!("DD_API_KEY={filler}\n{value} tail").into_bytes();
        let req_start = (11 + filler.len() + 1) as u64;
        let r = read(&buf, req_start, 4096);
        assert!(
            r.output.starts_with(value),
            "the label is 1 KB back, outside the lookbehind, so nothing \
             marks this value as a secret: {}",
            r.output
        );
    }

    // ---------------------------------------------------------- holdback

    #[test]
    fn a_partial_secret_stops_the_read_at_its_start() {
        let buf = b"line one\nghp_abcdef".to_vec();
        let r = read(&buf, 0, 32 * 1024);
        assert!(r.held_back, "an in-flight token must stop the read");
        assert_eq!(r.output, "line one\n");
        assert_eq!(r.cursor, 9, "the boundary is the partial's first byte");
        assert_eq!(r.next_cursor, Some(9));
        assert!(!r.truncated_for_size, "this is a holdback, not a size cap");
    }

    #[test]
    fn the_boundary_advances_once_the_token_completes() {
        let mut buf = b"line one\nghp_abcdef".to_vec();
        let first = read(&buf, 0, 32 * 1024);
        assert!(first.held_back);
        // The rest of the token plus a delimiter arrive.
        buf.extend_from_slice(b"ghijABCDEFGHIJ0123450123456789abcd\n");
        let second = read(&buf, first.cursor, 32 * 1024);
        assert!(
            !second.held_back,
            "the token completed; nothing is withheld"
        );
        assert!(!second.output.contains("ghp_abcdef"), "{}", second.output);
        assert_eq!(second.output, "[REDACTED:github]\n");
    }

    #[test]
    fn a_request_entirely_inside_the_withheld_region_returns_empty() {
        let buf = b"line one\nghp_abcdef".to_vec();
        let r = read(&buf, 12, 32 * 1024);
        assert!(r.held_back);
        assert_eq!(r.output, "");
        assert_eq!(r.bytes_returned, 0);
        assert_eq!(
            r.next_cursor,
            Some(12),
            "the agent retries from where it asked"
        );
    }

    /// §4.1's flag algebra, first order: the boundary sits *before* the
    /// size cap, so the read stopped for safety and not for budget.
    ///
    /// Paired with the test below, this is what pins the
    /// `cap_end <= safety_end` clause of `truncated_for_size`. Every other
    /// holdback test in this module reads with a cap so large that
    /// `cap_end == head`, where the clause cannot be observed at all.
    #[test]
    fn a_holdback_before_the_size_cap_is_not_reported_as_truncation() {
        // 24 bytes of token: a partial the rule cannot complete, with the
        // buffer continuing well past the cap.
        let mut buf = b"line one\n".to_vec();
        buf.extend_from_slice(b"ghp_01234567890123456789");
        let r = read(&buf, 0, 20);
        assert!(r.held_back, "the boundary at 9 stopped the read");
        assert_eq!(r.cursor, 9);
        assert_eq!(r.output, "line one\n");
        assert!(
            !r.truncated_for_size,
            "the cap at 20 never bit; the boundary at 9 came first"
        );
        assert_eq!(r.next_cursor, Some(9));
    }

    /// The other order, which §4.1 names in terms: a size cap hit before
    /// the holdback boundary is a standard continuation, no safety delay.
    #[test]
    fn a_size_cap_before_the_holdback_is_truncation_and_not_a_holdback() {
        let mut buf = b"line one\n".to_vec();
        buf.extend_from_slice(b"ghp_01234567890123456789");
        let r = read(&buf, 0, 5);
        assert!(!r.held_back, "the read stopped on budget, not on safety");
        assert!(r.truncated_for_size);
        assert_eq!(r.output, "line ");
        assert_eq!(r.next_cursor, Some(5));
    }

    /// REQ-O-005: quiescence does not release the holdback, and
    /// `redact: false` is the audited way out.
    #[test]
    fn a_quiescent_partial_stays_withheld_until_redaction_is_disabled() {
        let buf = b"line one\nghp_abcdef".to_vec();
        let p = processor();

        // Child has exited: still withheld. Quiescence is not a release.
        let w = snapshot(&p, &buf, 0, 32 * 1024, false, false);
        let r = p.process(&w, &ReadOptions::default());
        assert!(r.held_back);
        assert_eq!(r.output, "line one\n");

        // The escape hatch returns it.
        let w = snapshot(&p, &buf, 0, 32 * 1024, false, false);
        let raw = p.process(
            &w,
            &ReadOptions {
                redact: false,
                ..Default::default()
            },
        );
        assert!(!raw.held_back);
        assert_eq!(raw.output, "line one\nghp_abcdef");
    }

    /// REQ-O-003: `tail_bytes`/`tail_lines` opt out of the holdback.
    #[test]
    fn tail_reads_bypass_the_holdback() {
        let buf = b"line one\nghp_abcdef".to_vec();
        let p = processor();
        let w = snapshot(&p, &buf, 9, 32 * 1024, true, true);
        let r = p.process(&w, &ReadOptions::default());
        assert!(!r.held_back);
        assert_eq!(
            r.output, "ghp_abcdef",
            "the agent asked for the freshest bytes and accepts the trade"
        );
    }

    /// The regression guard for the rev. 10–14 blanket holdback.
    #[test]
    fn streaming_ordinary_output_is_never_held_back() {
        let p = processor();
        let mut buf: Vec<u8> = Vec::new();
        let mut cursor = 0u64;
        let mut reads = 0usize;
        let lines = [
            "   Compiling holdfast-core v0.0.1 (/home/user/src/holdfast)\n",
            "\x1b[32m    Finished\x1b[0m `dev` profile in 13.72s\n",
            "test output::redact::tests::merge ... ok\n",
            "warning: unused variable `n` --> src/lib.rs:42:9\n",
        ];
        // ~1 MiB of realistic build output, read continuously.
        while buf.len() < 1024 * 1024 {
            for line in lines {
                buf.extend_from_slice(line.as_bytes());
            }
            let w = snapshot(&p, &buf, cursor, 32 * 1024, true, false);
            let r = p.process(&w, &ReadOptions::default());
            assert!(
                !r.held_back,
                "ordinary output was held back at cursor {cursor}"
            );
            assert!(
                r.cursor == r.next_cursor.unwrap_or(buf.len() as u64),
                "cursor/next_cursor disagree at {cursor}"
            );
            cursor = r.cursor;
            reads += 1;
        }
        assert_eq!(
            cursor,
            buf.len() as u64,
            "the reads must have consumed the whole buffer"
        );
        assert!(reads > 30, "expected many reads, got {reads}");
    }

    // ------------------------------------ the window as evidence (GH #14)

    /// A PEM whose base64 body is at least `body_bytes` long, in 64-column
    /// lines, each line naming itself so a leak of any single line is
    /// detectable by name. Returned with its body separately.
    ///
    /// `pem_private_key` above is ~1.6 KB and deliberately so: it is sized
    /// against `lookbehind_bytes` (512). This one is sized against
    /// `lookahead_bytes` (8192), sixteen times larger, so it is a separate
    /// fixture rather than a parameter on that one — a `pem_private_key`
    /// grown to 64 KB would silently change what the cursor tests above
    /// are measuring.
    fn pem_longer_than(body_bytes: usize) -> (String, String) {
        let mut lines: Vec<String> = Vec::new();
        while lines.len() * 65 < body_bytes {
            let i = lines.len();
            let mut line = format!("KEYBODY{i:06}");
            while line.len() < 64 {
                line.push_str("MIIEowIBAAKCAQEAy8Dbv8prpJ");
            }
            line.truncate(64);
            lines.push(line);
        }
        let body = lines.join("\n");
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
        (pem, body)
    }

    /// A processor over the built-in rules plus `extra`, for the one case
    /// that needs a rule shape the shipped set does not contain.
    fn processor_with(extra: &str) -> OutputProcessor {
        let rules = Arc::new(RuleSet::builtin_with_extra(extra).unwrap());
        let audit = Arc::new(AuditLog::disabled(Arc::clone(&rules)));
        OutputProcessor::new(rules, audit, ProcessingLimits::default())
    }

    /// GH #14 — **`redaction_lookahead_bytes` bounds the redactor's
    /// evidence, and a match can run off the end of it.**
    ///
    /// `find_spans` is handed `[req_start − lookbehind, cap_end +
    /// lookahead)` and nothing more. `private-key-block` is anchored at
    /// both ends with `[\s\S]*?` between them, so its match is as long as
    /// the key: a concatenated `.pem` bundle pushes `-----END` past the
    /// window, the rule matches **nothing at all**, and the read returns
    /// the key body raw with `redactions: {}` and no audit entry — the
    /// same no-symptom shape as the cursor defect above, reached on the
    /// *first* read at `read_output`'s own default `max_bytes`.
    ///
    /// Widening the window is not the fix and is not what this pins: any
    /// bound is exceeded by one more byte, and the next size of key is one
    /// `cat` away. What the read owes its caller is to notice that its
    /// evidence ran out mid-candidate — which is what
    /// `PrefixIndex::unresolved_from` reports — and to **say so in the
    /// payload**: one `[REDACTED:unresolved]` over the region, and the
    /// read completes.
    ///
    /// **This row asserted a withhold until GH #195, and the withhold was
    /// a wedge.** The fixture below is an *unterminated* key rather than
    /// the terminated one the row used to carry, and the difference is the
    /// whole subject: a terminated block matches `private-key-block` the
    /// moment the window reaches its footer and was never the leak.
    ///
    /// **The guarantee is now stated with its bound, and both halves are
    /// asserted.** A candidate is believed for [`UNVOUCHED_CARRY_BYTES`]
    /// past its anchor. Within that, **no raw byte on any surface** — and
    /// measured against `origin/main`, that is a strict gain rather than a
    /// concession: an 8 KB unterminated key, which is an ordinary
    /// RSA-8192 one, came back **entirely raw with `redactions: {}` on
    /// every surface including the default cursor read**, because the
    /// window reached `buffer.head` and the declination was gated on its
    /// not doing so. Past the bound the candidate is not believed and the
    /// remainder is released, which is `attach/redact_stream.rs`'s
    /// shipped residual (a) at the same number.
    ///
    /// The residual is asserted rather than described, because a residual
    /// nobody measures is a residual that quietly grows.
    #[test]
    fn a_private_key_longer_than_the_lookahead_window_is_never_emitted_raw() {
        let p = processor();
        let carry = UNVOUCHED_CARRY_BYTES as u64;
        let prologue = "$ cat chain.pem\n";

        // ---- arm 1: a key that fits inside the carry. Every surface.
        let (short_pem, short_body) = pem_longer_than(8 * 1024);
        let short = format!("{prologue}{}\n", &short_pem[..short_pem.len() - 30]).into_bytes();
        assert!(
            !String::from_utf8_lossy(&short).contains("-----END"),
            "the fixture must be unterminated, which is the shape that leaks"
        );
        assert!(
            (short.len() as u64) < carry,
            "arm 1 must fit inside the carry or it is arm 2"
        );
        // **Probed by line name, not by byte window.** Every body line is
        // `KEYBODY<n>` then the same 26-character filler, so a 48-byte
        // window that starts past column 13 is identical in every line and
        // a `contains` on one proves nothing about where it came from. The
        // names are unique and each one names its own line.
        let lines = short_body.len() / 65 + 1;
        for cap in [4096usize, 32 * 1024, 256 * 1024, 4 * 1024 * 1024] {
            let w = snapshot(&p, &short, 0, cap, true, false);
            let r = p.process(&w, &ReadOptions::default());
            for i in 0..lines {
                assert!(
                    !r.output.contains(&format!("KEYBODY{i:06}")),
                    "max_bytes {cap}: key body line {i} leaked"
                );
            }
            assert!(
                !r.output.contains(&short_body[..48]),
                "max_bytes {cap}: the body's own first bytes leaked"
            );
            assert_eq!(
                r.output,
                format!("{prologue}[REDACTED:unresolved]"),
                "max_bytes {cap}: one marker over the whole unjudgeable region"
            );
            assert_eq!(r.redactions.get(redact::UNRESOLVED_KIND), Some(&1));
            assert!(!r.held_back, "max_bytes {cap}: masked, not withheld");
            assert_eq!(
                r.cursor,
                short.len() as u64,
                "max_bytes {cap}: the read made full progress"
            );
        }

        // ---- arm 2: a key longer than the carry, read at the default.
        let (pem, body) = pem_longer_than(64 * 1024);
        let buf = format!("{prologue}{}\n", &pem[..pem.len() - 30]).into_bytes();
        const CAP: usize = 32 * 1024;
        assert!(
            CAP as u64 + p.limits.lookahead_bytes as u64 + 1 < buf.len() as u64,
            "the fixture must actually truncate the window, or it pins nothing"
        );

        let w = snapshot(&p, &buf, 0, CAP, true, false);
        let r = p.process(&w, &ReadOptions::default());

        // THE GUARANTEE: no line of key body inside the carry, by name.
        // The anchor is the `-----BEGIN` at `prologue.len()`; the header
        // and its newline are 32 bytes, so body line `i` begins at
        // `anchor + 32 + 65 i`.
        let anchor = prologue.len() as u64;
        let line_at = |i: usize| anchor + 32 + 65 * i as u64;
        let last_masked = (0..body.len() / 65)
            .take_while(|i| line_at(*i) + 65 <= anchor + carry)
            .last()
            .expect("the carry covers whole lines");
        assert!(last_masked > 200, "the masked run must be substantial");
        for i in 0..=last_masked {
            assert!(
                !r.output.contains(&format!("KEYBODY{i:06}")),
                "key body line {i} is inside the carry and leaked"
            );
        }
        assert_eq!(r.redactions.get(redact::UNRESOLVED_KIND), Some(&1));
        assert!(r
            .output
            .starts_with(&format!("{prologue}[REDACTED:unresolved]")));
        assert!(!r.held_back, "the read is masked, not withheld");
        assert_eq!(r.bytes_returned, CAP, "…and it made its full progress");
        // The extent, arithmetically. Probing by line name pins the
        // residual only at 65-byte granularity, so a mask one byte short
        // or one byte long survives it; this does not.
        let marker = redact::marker(redact::UNRESOLVED_KIND);
        assert_eq!(
            r.output.len(),
            (anchor as usize) + marker.len() + (CAP - anchor as usize - carry as usize),
            "prologue, one marker, and exactly the bytes past the carry"
        );

        // THE RESIDUAL, asserted in the same breath: past the carry the
        // candidate is not believed and its bytes are released. Without
        // this arm the row above passes against an implementation that
        // masks unboundedly, which is a different and much more expensive
        // trade than the one that was taken — measured at 38.65% of
        // this repository's Rust against this bound's 0.28%, on a 4 MiB
        // read.
        assert!(
            r.output.contains(&format!("KEYBODY{:06}", last_masked + 2)),
            "the residual moved: a candidate past {carry} bytes of evidence \
             is no longer believed, and this row is what makes that a \
             measurement rather than a footnote"
        );
    }

    /// The paired direction, and the reason the withhold above is not a
    /// dead end: the same buffer read with a window that *does* reach the
    /// closing anchor resolves to the rule that actually matched, names
    /// the real kind, and consumes the whole key in one read.
    ///
    /// This is the documented recourse — `read_output` clamps `max_bytes`
    /// to `MAX_READ_MAX_BYTES` (256 KiB), which puts `buffer.head` back
    /// inside the window for any key a 1 MiB ring buffer can hold most of.
    /// It is also the control that separates *detecting the truncation*
    /// from *withholding whenever the window is short*: the cheap wrong
    /// fix passes the test above and fails this one.
    #[test]
    fn the_same_key_resolves_once_the_window_reaches_its_closing_anchor() {
        let (pem, body) = pem_longer_than(64 * 1024);
        let prologue = "$ cat chain.pem\n";
        let buf = format!("{prologue}{pem}\n$ echo done\n").into_bytes();

        let r = read(&buf, 0, 256 * 1024);
        assert!(!r.held_back, "the window saw the whole key");
        assert_eq!(
            r.output,
            format!("{prologue}[REDACTED:private-key]\n$ echo done\n")
        );
        assert_eq!(r.redactions.get("private-key"), Some(&1));
        assert!(!r.output.contains(&body[..48]));
        assert_eq!(r.cursor, buf.len() as u64, "the read made full progress");
    }

    // ------------------------------------------- GH #195: the paging wedge

    /// **GH #195's reproduction, on the corpus the issue was filed
    /// against: this repository's own documentation.**
    ///
    /// `CHANGELOG.md` contains `-----BEGIN RSA PRIVATE KEY-----` as
    /// **prose**, in the paragraph describing this very holdback rule.
    /// `private-key-block` is anchored at both ends, the opening anchor is
    /// found, `-----END` never arrives, and before 0.0.8 the read stopped
    /// at that anchor on every retry for ever: measured at `buffer.head`
    /// 136,206 — read 1 returning 32,768 B, read 2 returning 9,990 B and
    /// pinning at 42,758, and reads 3 through 9 returning **zero bytes
    /// with the cursor frozen**.
    ///
    /// The file is read from disk rather than synthesised, and that is
    /// the point: a fixture spelling the anchor out is a fixture that
    /// passes when somebody reverts the fix and edits the fixture. This
    /// one goes red if the corpus stops containing the shape *or* if the
    /// shape stops being handled, and the first assertion tells the two
    /// apart.
    ///
    /// **Since GH #242 the prose anchors are not masked at all**, and the
    /// row asserts that as well as the drain. #195's fix made the loop
    /// progress by masking each unterminated anchor for
    /// `UNVOUCHED_CARRY_BYTES`; on this corpus that was a quarter of the
    /// text. A `-----BEGIN` candidate is now believed only while what
    /// follows can be PEM text, and a closing backtick is not, so every
    /// prose mention comes back verbatim with no marker. The paired half
    /// — that the check was *narrowed* and not deleted — is the same
    /// corpus with a truncated key planted in it, which must come back
    /// masked on the same loop.
    #[test]
    fn the_documented_read_loop_drains_this_repositorys_own_changelog() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        let mut buf = Vec::new();
        for name in ["CHANGELOG.md", "README.md", "ROADMAP.md"] {
            buf.extend_from_slice(
                &std::fs::read(root.join(name)).expect("the repository's own docs"),
            );
        }
        // The row is about a corpus that contains the shape. If it stops
        // containing one, this row proves nothing and must say so rather
        // than pass.
        assert!(
            buf.windows(31)
                .any(|w| w == b"-----BEGIN RSA PRIVATE KEY-----"),
            "the corpus no longer contains GH #195's shape, so this row \
             would pass against the wedge it exists to forbid"
        );

        let p = processor();
        let o = ReadOptions::default();
        // One pass of the documented loop, returning the joined payload,
        // the read count and the `unresolved` markers it reported.
        let drain = |buf: &[u8]| {
            let mut cursor = 0u64;
            let mut reads = 0usize;
            let mut unresolved = 0usize;
            let mut joined = String::new();
            while cursor < buf.len() as u64 {
                reads += 1;
                assert!(reads <= 32, "the read loop did not terminate");
                let w = snapshot(&p, buf, cursor, 32 * 1024, true, false);
                let r = p.process(&w, &o);
                assert!(
                    r.cursor > cursor,
                    "read {reads} returned {} bytes and left the cursor at \
                     {cursor}: that is GH #195",
                    r.bytes_returned
                );
                unresolved += r
                    .redactions
                    .get(redact::UNRESOLVED_KIND)
                    .copied()
                    .unwrap_or(0);
                joined.push_str(&r.output);
                cursor = r.cursor;
            }
            assert_eq!(
                cursor,
                buf.len() as u64,
                "the loop must consume the corpus, not merely terminate"
            );
            (joined, reads, unresolved)
        };
        let (joined, reads, unresolved) = drain(&buf);
        // **Relative to the corpus, not an absolute.** These three files
        // grow, and an absolute bound goes red from documentation growth
        // alone — which would be misdiagnosed as the wedge returning. The
        // property is "one read per `max_bytes`, plus one for the mask's
        // overshoot", and that is what a regression would break.
        let floor = buf.len().div_ceil(32 * 1024);
        assert!(
            reads <= floor + 2,
            "the default loop drains {} B in {reads} reads against a floor \
             of {floor}; a count that has grown is the wedge coming back by \
             degrees",
            buf.len()
        );
        // GH #242: every prose anchor comes back verbatim, and nothing is
        // masked on their account.
        let anchors = |t: &[u8]| {
            t.windows(31)
                .filter(|w| *w == b"-----BEGIN RSA PRIVATE KEY-----")
                .count()
        };
        assert_eq!(
            unresolved, 0,
            "a prose `-----BEGIN` is not a candidate past its closing \
             backtick, so nothing in this corpus is unresolved"
        );
        assert_eq!(
            anchors(joined.as_bytes()),
            anchors(&buf),
            "every prose anchor must reach the caller"
        );

        // The paired half: the check was narrowed, not deleted. A key cut
        // short in the middle of the same corpus is still masked, whole.
        let key = pem::fixtures::KEYS[0].pem();
        let truncated: String = key.lines().take(12).map(|l| format!("{l}\n")).collect();
        let mid = buf.len() / 2;
        let mut planted = buf[..mid].to_vec();
        planted.extend_from_slice(b"\n$ head -n 12 id_rsa\n");
        planted.extend_from_slice(truncated.as_bytes());
        planted.extend_from_slice(b"$ ");
        planted.extend_from_slice(&buf[mid..]);
        let (joined, _, unresolved) = drain(&planted);
        assert!(unresolved >= 1, "the planted key must be masked");
        for line in truncated.lines().skip(1) {
            assert!(
                !joined.contains(line),
                "a line of the planted key reached the caller: {line}"
            );
        }
    }

    /// **The gap between surfaces, closed and asserted in both
    /// directions** (GH #14 at `buffer.head`, GH #195).
    ///
    /// GH #14's declination was gated on `window_end < w.head`, so a
    /// window that *reached* `head` cleared the bound by not running the
    /// check. `resources/read`, a `tail_*` read and any `max_bytes` large
    /// enough are **one mechanism with three names**, and all three
    /// returned an unterminated candidate's body raw with
    /// `redactions: {}`.
    ///
    /// Measured against `origin/main` on this fixture: **every** row of
    /// the loop below returned the whole key body raw, including the
    /// plain default cursor read, because an 8 KB key fits inside the
    /// window. That is the ordinary case — `cat id_rsa` on a fresh
    /// session — and it is the one the old gate never protected.
    ///
    /// **Paired with the two things that must still work**, or the row
    /// passes against an implementation that masks everything: the
    /// audited `redact: false` still returns the bytes, and a `tail_*`
    /// read still returns §4.1's in-flight partial, which REQ-O-003
    /// requires and which an overlap between this scan's region and
    /// `holdback_boundary`'s would have destroyed.
    #[test]
    fn an_unterminated_key_is_masked_on_every_surface_that_reaches_head() {
        let p = processor();
        let (pem, body) = pem_longer_than(8 * 1024);
        let prologue = "$ cat id_rsa\n";
        let unterminated = &pem[..pem.len() - 30];
        assert!(!unterminated.contains("-----END"));
        let buf = format!("{prologue}{unterminated}\n").into_bytes();
        assert!(
            (buf.len() as u64) < UNVOUCHED_CARRY_BYTES as u64,
            "arm 1 is about a key inside the carry"
        );
        let lines = body.len() / 65 + 1;

        // `4096` is smaller than the buffer and `32 KiB` larger, so the
        // loop crosses the truncated/at-head boundary; 256 KiB is
        // `read_output`'s ceiling and 4 MiB is `resources/read`'s.
        for cap in [4096usize, 32 * 1024, 256 * 1024, 4 * 1024 * 1024] {
            let w = snapshot(&p, &buf, 0, cap, true, false);
            let r = p.process(&w, &ReadOptions::default());
            for i in 0..lines {
                assert!(
                    !r.output.contains(&format!("KEYBODY{i:06}")),
                    "max_bytes {cap}: body line {i} raw — the surfaces disagree"
                );
            }
            assert_eq!(
                r.output,
                format!("{prologue}[REDACTED:unresolved]"),
                "max_bytes {cap}"
            );
            assert_eq!(r.redactions.get(redact::UNRESOLVED_KIND), Some(&1));
            assert!(!r.held_back, "max_bytes {cap}: masked, not withheld");
            assert_eq!(r.cursor, buf.len() as u64, "max_bytes {cap}");
        }

        // The audited hatch is unchanged: it is the recourse, and a mask
        // that survived it would be a hole in the recourse.
        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        let raw = p.process(
            &w,
            &ReadOptions {
                redact: false,
                ..Default::default()
            },
        );
        assert!(
            raw.output.contains("KEYBODY000000"),
            "`redact: false` is the audited way past every marker"
        );

        // And §4.1's in-flight partial still reaches a `tail_*` read: the
        // carry scan stops where `holdback_boundary`'s region begins.
        let arriving = b"line one\nghp_abcdef".to_vec();
        let w = snapshot(&p, &arriving, 9, 32 * 1024, true, true);
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(
            r.output, "ghp_abcdef",
            "REQ-O-003's opt-in must still return the in-flight partial; \
             an unvouched scan overlapping the trailing region masks it"
        );
    }

    /// **A continuation read that begins *inside* a masked region reaches
    /// the same verdict, and that is what `carry_region` is for.**
    ///
    /// When a read masks `[u, u + UNVOUCHED_CARRY_BYTES)` the cursor lands
    /// somewhere inside that range, and the *next* read has to find the
    /// same anchor or it releases the rest of the candidate raw — GH #14
    /// re-entered from the other side, and strictly worse than the wedge
    /// it replaced. `lookbehind_bytes` is 512 and a believed candidate
    /// reaches 16 KiB back, so the window cannot answer it: the anchor is
    /// not among the bytes `process` holds. `WindowSnapshot::carry_region`
    /// is the extra lookbehind that makes it visible.
    ///
    /// Two mutations survived every other row in this file before this
    /// one existed — `carry_region` swapped back to `window` here, and
    /// `session/mod.rs` handing `window_start` as `carry_region_start` —
    /// and both of them are a private key body on the wire.
    ///
    /// The paging step is deliberately small (512 B), because the
    /// property is about a cursor landing *strictly between* the anchor
    /// and the end of the carry, and a default-sized read consumes the
    /// whole carry in one step and never produces one. The row asserts
    /// that such a read happened before it asserts anything about it.
    #[test]
    fn a_continuation_read_inside_a_masked_region_still_masks() {
        let carry = UNVOUCHED_CARRY_BYTES as u64;
        let (pem, _) = pem_longer_than(64 * 1024);
        let prologue = "$ cat id_rsa\n";
        let buf = format!("{prologue}{}\n", &pem[..pem.len() - 30]).into_bytes();
        let anchor = prologue.len() as u64;
        // Body line `i` begins at `anchor + 32 + 65 i`; the header and its
        // newline are 32 bytes. A line wholly inside the carry must never
        // appear raw.
        let line_at = |i: usize| anchor + 32 + 65 * i as u64;
        let last_in_carry = (0..1000)
            .take_while(|i| line_at(*i) + 65 <= anchor + carry)
            .last()
            .expect("the carry covers whole body lines");
        assert!(last_in_carry > 200);

        let mut cursor = 0u64;
        let mut markers = 0usize;
        let mut reads = 0usize;
        let mut resumed_inside = false;
        while cursor < anchor + carry {
            reads += 1;
            assert!(reads <= 64, "the paging loop did not terminate");
            if cursor > anchor && cursor < anchor + carry {
                resumed_inside = true;
            }
            let r = read(&buf, cursor, 512);
            assert!(r.cursor > cursor, "read {reads} made no progress");
            for i in 0..=last_in_carry {
                assert!(
                    !r.output.contains(&format!("KEYBODY{i:06}")),
                    "read {reads} from cursor {cursor} released body line {i}, \
                     which is inside the carry"
                );
            }
            markers += r
                .redactions
                .get(redact::UNRESOLVED_KIND)
                .copied()
                .unwrap_or(0);
            cursor = r.cursor;
        }
        assert!(
            resumed_inside,
            "no read began strictly inside the masked region, so this row \
             asserted nothing about a continuation"
        );
        assert!(
            markers >= 2,
            "only {markers} read masked; the continuation must mask too, \
             not merely decline to leak by returning nothing"
        );

        // Paired: past the carry the candidate is not believed, so the row
        // above cannot pass against an implementation that masks for ever.
        let after = read(&buf, anchor + carry, 512);
        assert!(after.redactions.is_empty(), "{:?}", after.redactions);
        assert!(after.output.contains("KEYBODY"));
    }

    /// **`held_back` and `held_back_cause` never disagree, swept rather
    /// than argued.**
    ///
    /// `process` clamps the cause with `held_back.then_some(cause)
    /// .flatten()`. Mutating that to a bare `cause` **survives** every
    /// row here, and the reason is that it is an equivalent mutant on the
    /// two causes that exist: each one lowers `safety_end` below
    /// `cap_end` in the same statement that sets it. The clamp is kept
    /// because a third cause need not, and this sweep is what would go
    /// red if one were added that did not — which is the thing worth
    /// catching, and is not the mutation.
    #[test]
    fn a_cause_is_reported_exactly_when_something_was_held_back() {
        let p = processor();
        let o = ReadOptions::default();
        let bodies: [&[u8]; 6] = [
            b"ordinary output\n",
            b"line one\nghp_abcdef",
            b"done\x1b[0",
            b"done\x1b[0m and more\n",
            b"export TOKEN=ghp_0123456789abcdefghij",
            b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKC",
        ];
        let mut swept = 0usize;
        let mut held = 0usize;
        for body in bodies {
            for pad in [0usize, 1, 7, 64, 513, 8193] {
                let mut buf = vec![b'.'; pad];
                buf.extend_from_slice(body);
                for req_start in [0u64, 1, pad as u64, buf.len() as u64] {
                    if req_start > buf.len() as u64 {
                        continue;
                    }
                    for max_bytes in [1usize, 8, 64, 65, 512, 8192, 32 * 1024] {
                        for alive in [true, false] {
                            for bypass in [true, false] {
                                let w = snapshot(&p, &buf, req_start, max_bytes, alive, bypass);
                                let r = p.process(&w, &o);
                                swept += 1;
                                held += r.held_back as usize;
                                assert_eq!(
                                    r.held_back,
                                    r.held_back_cause.is_some(),
                                    "held_back {} but cause {:?} — body {:?} pad {pad} \
                                     req_start {req_start} max_bytes {max_bytes} \
                                     alive {alive} bypass {bypass}",
                                    r.held_back,
                                    r.held_back_cause,
                                    String::from_utf8_lossy(body),
                                );
                                if let Some(c) = r.held_back_cause {
                                    assert!(HeldBackCause::ALL.contains(&c));
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(swept > 2_000, "the sweep shrank to {swept} combinations");
        assert!(
            held > 0,
            "no combination in the sweep was held back, so the agreement \
             it asserts is vacuous"
        );
    }

    /// **The two regions are disjoint, asserted against each other**
    /// (REQ-O-007's shape, one bound further out).
    ///
    /// `holdback_boundary` owns `[head − partial_secret_scan_bytes, head)`
    /// and *shortens*; the unvouched carry owns
    /// `[head − UNVOUCHED_CARRY_BYTES, head − partial_secret_scan_bytes)`
    /// and *masks*. Asserting the sizes alone is green against an
    /// implementation that overlaps them, which is the one that breaks
    /// REQ-O-003 — so the property asserted is the *adjacency*, driven
    /// through a real read.
    #[test]
    fn the_unvouched_carry_stops_where_the_trailing_holdback_begins() {
        let p = processor();
        let scan = p.limits.partial_secret_scan_bytes as u64;
        assert!(
            (UNVOUCHED_CARRY_BYTES as u64) > scan,
            "a carry inside the trailing region would be the same scan twice"
        );

        // **The anchor has to be *live* at the end of the region, and the
        // first draft of this row got that wrong.** It planted
        // `ghp_abcdef` followed by newlines, so the candidate was **dead**
        // by the time the scan reached the region's end:
        // `earliest_partial` answered `None` before `carry_end` was ever
        // consulted, and the row was green against an implementation with
        // no `carry_end` at all. Instrumented across all of this module's
        // tests, the `u < carry_end` filter discarded an answer **zero**
        // times — the line it exists to hold was dead in the whole suite.
        //
        // A live partial is the only fixture that reaches the question: no
        // delimiter after it, so it is still arriving at `buffer.head`,
        // and short enough that no rule has matched it yet.
        let mut buf = vec![b'.'; 4096];
        buf.extend_from_slice(b"\n");
        let live_anchor = buf.len() as u64;
        buf.extend_from_slice(b"ghp_0123456789abcdef");
        let head = buf.len() as u64;
        assert!(
            head - live_anchor <= scan,
            "the anchor must sit inside `holdback_boundary`'s region"
        );

        let w = snapshot(&p, &buf, 0, 32 * 1024, true, true);
        let window_end = w.window_start + w.window.len() as u64;
        // The scan really does find it — without this the assertion below
        // is satisfied by an answer of `None` for any reason at all, which
        // is exactly how the first draft passed.
        assert_eq!(
            p.index.earliest_partial(
                &p.rules,
                &w.carry_region[..(window_end - w.carry_region_start) as usize],
                w.carry_region_start,
            ),
            Some(live_anchor),
            "the fixture must present a *live* partial, or `carry_end` is \
             never the reason the answer is `None`"
        );
        assert_eq!(
            p.unvouched_carry(&w, window_end),
            None,
            "an anchor at or after `head - partial_secret_scan_bytes` is \
             `holdback_boundary`'s and must not be masked here: the two \
             regions are adjacent, not overlapping"
        );

        let r = p.process(&w, &ReadOptions::default());
        assert!(
            !r.redactions.contains_key(redact::UNRESOLVED_KIND),
            "an anchor inside the trailing region is `holdback_boundary`'s, \
             and a `tail_*` read opts out of it"
        );
        assert!(
            r.output.ends_with("ghp_0123456789abcdef"),
            "…and the bytes really are the ones REQ-O-003 promises a \
             `tail_*` read: {:?}",
            &r.output[r.output.len().saturating_sub(40)..]
        );
    }

    /// **The synthetic span meets a real one, driven through `process`.**
    ///
    /// Two lines exist only for this shape — `merge_spans`'s rule that a
    /// merge swallowing an unresolved span *is* unresolved, and the
    /// `spans = merge_spans(spans)` that follows the `spans.push` — and
    /// until this row neither had a test that went through the read path.
    /// The only coverage was `redact::tests::a_merge_that_swallows_an_
    /// unresolved_span_is_unresolved`, which hands `merge_spans` two
    /// literals. **Measured: deleting the re-merge left every test in this
    /// workspace green.**
    ///
    /// Two arrangements, because they fail differently and each is blind
    /// to the other's fault:
    ///
    /// * **The mask starts first.** Without the re-merge `spans` is left
    ///   *unsorted*, and `render` walks it monotonically —
    ///   `while spans[next_span].end <= off { next_span += 1 }` never
    ///   looks back — so it steps past the synthetic span and emits the
    ///   bytes before the real match **raw**. That is GH #14 re-entered
    ///   through its own fix, not a mislabel.
    /// * **The real match starts first and the anchor lands on its end.**
    ///   Without the rule assignment the merged span carries the rule's
    ///   name over sixteen kilobytes no rule matched, and
    ///   `status.redaction_stats` counts a `github` the session never
    ///   caught — the report `merge_spans`'s own doc says an agent is
    ///   entitled to disbelieve. The mask-first arrangement cannot see
    ///   this, because there the merge folds into an already-`UNRESOLVED`
    ///   head.
    #[test]
    fn an_unresolved_mask_that_meets_a_real_match_is_one_marker_and_the_weaker_kind() {
        let p = processor();

        // ---- arm 1: the mask starts first and swallows the real match.
        //
        // **The real match is an AWS key id, and it was a GitHub token
        // until GH #242.** A `-----BEGIN` candidate is now believed only
        // while what follows can be PEM text, and `ghp_`'s underscore is
        // not — the candidate ended in front of the token, and the row was
        // no longer about a mask meeting a match. `AKIA…` is sixteen
        // base64 characters behind a base64 prefix, so it sits inside text
        // the candidate still believes, which is the arrangement this row
        // needs.
        const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
        let prologue = "$ cat bundle\n";
        let mut buf = format!("{prologue}-----BEGIN RSA PRIVATE KEY-----\n").into_bytes();
        buf.extend(std::iter::repeat_n(b'A', 1024));
        buf.extend_from_slice(b"\ntoken ");
        buf.extend_from_slice(AWS.as_bytes());
        buf.extend_from_slice(b"\n");
        buf.extend(std::iter::repeat_n(b'B', 1024));
        buf.extend_from_slice(b"\n");
        assert!(
            !String::from_utf8_lossy(&buf).contains("-----END"),
            "the anchor must stay unterminated, which is what makes it a mask"
        );

        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        assert_eq!(
            p.all_spans(w.window, w.window_start).len(),
            1,
            "the fixture must contain exactly one real match for the mask \
             to swallow, or the merge never happens"
        );
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(
            r.output,
            format!("{prologue}[REDACTED:unresolved]"),
            "one marker over the merged region — not a raw run followed by \
             two markers"
        );
        assert_eq!(
            r.redactions,
            std::iter::once((redact::UNRESOLVED_KIND.to_string(), 1)).collect(),
            "…and one redaction, of the weaker kind: {:?}",
            r.redactions
        );
        assert!(
            !r.output.contains("-----BEGIN") && !r.output.contains("AAAA"),
            "the bytes between the anchor and the real match came back raw"
        );

        // ---- arm 2: the real match starts first and the anchor lands on
        // its end, which is the merge `merge_spans`'s doc is about.
        let mut buf =
            format!("$ env\nTOKEN={GITHUB}-----BEGIN RSA PRIVATE KEY-----\n").into_bytes();
        // Padded past `partial_secret_scan_bytes`, or the whole buffer is
        // `holdback_boundary`'s region, `carry_start >= carry_end`
        // short-circuits, and no mask is ever built — which is how a
        // shorter draft of this arm passed for the wrong reason.
        buf.extend(std::iter::repeat_n(
            b'A',
            4 * p.limits.partial_secret_scan_bytes,
        ));
        buf.extend_from_slice(b"\n");
        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        let real = p.all_spans(w.window, w.window_start);
        assert_eq!(real.len(), 1, "one real match: {real:?}");
        assert_eq!(
            redact::span_kind(&p.rules, &real[0]),
            "github",
            "the fixture's real match must name a rule, or the weakening \
             has nothing to weaken"
        );
        let r = p.process(&w, &ReadOptions::default());
        assert!(
            !r.redactions.contains_key("github"),
            "a merged span may not claim `github` matched bytes no rule \
             matched: {:?}",
            r.redactions
        );
        assert_eq!(
            r.redactions.get(redact::UNRESOLVED_KIND),
            Some(&1),
            "…and the merge is counted as `unresolved`: {:?}",
            r.redactions
        );
        assert!(!r.output.contains(GITHUB));
        assert!(!r.output.contains("-----BEGIN"));
    }

    /// **An anchor past the read end is not the read's business, and the
    /// `u < safety_end` filter is what keeps it that way.**
    ///
    /// The filter looked like a cheap short-circuit and survived every
    /// other row here, including a sweep that showed it discarding an
    /// answer 34 times with `spans` empty each time — where the would-be
    /// span starts past `read_end`, `render` skips it, and removing the
    /// filter changes nothing. That is most of its firings and none of
    /// its purpose.
    ///
    /// What it defends is the one arrangement where the late span does
    /// **not** stay out of the way: a rule's match that straddles
    /// `read_end`, with the anchor landing on its end.
    /// `merge_spans` joins spans that merely *touch* (REQ-O-009), so the
    /// two become one span — which this module's own rule then weakens to
    /// `unresolved`, and which `advance_past_straddled` then follows to
    /// `u + UNVOUCHED_CARRY_BYTES`. Without the filter the read consumes
    /// sixteen kilobytes past its own `max_bytes`, and a correctly
    /// identified `github` token is reported as an anonymous unjudgeable
    /// region — in `redactions` and, through it, in
    /// `status.redaction_stats`.
    #[test]
    fn an_anchor_past_the_read_end_does_not_rename_or_extend_a_real_match() {
        let p = processor();
        const CAP: usize = 4096;

        // The token straddles `cap_end`; the anchor sits exactly on its
        // end, which is what makes the two touch.
        let mut buf = vec![b'.'; CAP - 20];
        let token_start = buf.len() as u64;
        buf.extend_from_slice(GITHUB.as_bytes());
        let anchor = buf.len() as u64;
        buf.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
        buf.extend(std::iter::repeat_n(b'A', 40 * 1024));
        buf.extend_from_slice(b"\n");

        let w = snapshot(&p, &buf, 0, CAP, true, false);
        // The arrangement really is the one described, or the row is a
        // restatement of the ordinary case.
        assert!(
            token_start < w.cap_end && anchor > w.cap_end,
            "the match must straddle the read end: {token_start} / {} / {anchor}",
            w.cap_end
        );
        let window_end = w.window_start + w.window.len() as u64;
        assert_eq!(
            p.index
                .unresolved_from(&p.rules, w.carry_region, w.carry_region_start),
            Some(anchor),
            "the scan must find an anchor *past* `cap_end`, which is the \
             answer the filter discards"
        );
        assert!(window_end < w.head, "the truncated branch is the subject");

        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(
            r.redactions.get("github"),
            Some(&1),
            "the match keeps its own kind: {:?}",
            r.redactions
        );
        assert!(
            !r.redactions.contains_key(redact::UNRESOLVED_KIND),
            "an anchor the read never reaches must not rename it: {:?}",
            r.redactions
        );
        assert_eq!(
            r.bytes_returned,
            (anchor - w.req_start) as usize,
            "the read consumes to the end of the straddled span and no \
             further; following the merged span would take it \
             `UNVOUCHED_CARRY_BYTES` past its own `max_bytes`"
        );
        assert!(!r.output.contains(GITHUB));

        // ---- the tie, `u == safety_end` exactly, which `<` declines and
        // `<=` would take. **It is reachable**, and a previous attempt at
        // this rule resolved the tie by an argument that had the safety
        // direction backwards. Put the match so it *ends* on the read end
        // and the anchor begins there: nothing straddles, so the span
        // would be invisible on its own — but the merge makes it straddle,
        // and then the read follows it sixteen kilobytes past `max_bytes`.
        let mut buf = vec![b'.'; CAP - GITHUB.len()];
        let token_start = buf.len() as u64;
        buf.extend_from_slice(GITHUB.as_bytes());
        let anchor = buf.len() as u64;
        buf.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
        buf.extend(std::iter::repeat_n(b'A', 40 * 1024));
        buf.extend_from_slice(b"\n");

        let w = snapshot(&p, &buf, 0, CAP, true, false);
        assert_eq!(anchor, w.cap_end, "the fixture must sit exactly on the tie");
        assert_eq!(
            p.index
                .unresolved_from(&p.rules, w.carry_region, w.carry_region_start),
            Some(anchor),
            "the scan must answer exactly `safety_end`, or the tie is never \
             reached and this arm asserts nothing"
        );
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(
            r.bytes_returned, CAP,
            "at the tie the read stops where it was going to stop"
        );
        assert_eq!(
            r.redactions.get("github"),
            Some(&1),
            "…and the match that ends there keeps its kind: {:?}",
            r.redactions
        );
        assert!(!r.redactions.contains_key(redact::UNRESOLVED_KIND));
        assert!(!r.output.contains(GITHUB));
        let _ = token_start;
    }

    /// **The read path and the `observer` stream, measured against each
    /// other on one fixture.**
    ///
    /// This row used to be `assert_eq!(UNVOUCHED_CARRY_BYTES, 2 *
    /// STREAM_CARRY_BYTES)` — a constant identity, which proves nothing
    /// about either surface's behaviour and which hid the thing it was
    /// written to guard. `WITHHOLD_WINDOW_BYTES` is the stream's sliding
    /// *window*, not its coverage: `feed_while_withholding` leaves
    /// withholding only on a feed with no partial open, and then sets
    /// `split = buf.len()`, so the **whole exit chunk is dropped too**.
    /// The stream's coverage is therefore `2 × STREAM_CARRY_BYTES + r`
    /// with `r` up to the feed size — 8,192 for the in-process pty
    /// reader and 65,536 for the subprocess worker — where this module's
    /// is exactly `UNVOUCHED_CARRY_BYTES`.
    ///
    /// **So the read is the weaker of the two, and that is the direction
    /// REQ-O-011a requires.** Its words are that a *stream* is *"never
    /// weaker than the tool it renders"*; a stream that covers more is a
    /// stream satisfying it. What this row forbids is the inversion — a
    /// read that covers more than the live view of the same bytes, which
    /// would put the leak on `holdfast watch` and leave the tool looking
    /// safe.
    #[test]
    fn the_stream_is_never_weaker_than_the_read_it_renders() {
        let p = Arc::new(OutputProcessor::builtin().unwrap());
        let (pem, _) = pem_longer_than(120 * 1024);
        let prologue = "$ cat chain.pem\n";
        let buf = format!("{prologue}{}\n", &pem[..pem.len() - 30]).into_bytes();
        let anchor = prologue.len() as u64;

        // The read path: page it and find the first body line that comes
        // back raw. Probed by line name — the filler repeats, so a byte
        // window is not locatable to a line.
        let first_raw_line = |text: &str| -> Option<usize> {
            (0..2000).find(|i| text.contains(&format!("KEYBODY{i:06}")))
        };
        let mut joined = String::new();
        let mut cursor = 0u64;
        let mut reads = 0;
        while cursor < buf.len() as u64 && reads < 500 {
            reads += 1;
            let r = read(&buf, cursor, 32 * 1024);
            assert!(r.cursor > cursor);
            joined.push_str(&r.output);
            cursor = r.cursor;
        }
        let read_first_raw = first_raw_line(&joined).expect(
            "the read must release *something* past the carry, or this row              is comparing a bound against an absence",
        );

        // The stream, fed at the production pty chunk size. Anything
        // smaller flatters it: the dropped exit chunk is the difference.
        let mut stream = crate::attach::redact_stream::StreamRedactor::new(Arc::clone(&p));
        let mut out: Vec<u8> = Vec::new();
        for chunk in buf.chunks(8192) {
            out.extend_from_slice(&stream.feed(chunk));
        }
        let stream_text = String::from_utf8_lossy(&out).into_owned();
        let stream_first_raw = first_raw_line(&stream_text)
            .expect("the stream must release something past its window too");

        assert!(
            stream_first_raw >= read_first_raw,
            "the read covered more of an unjudgeable candidate than the              stream rendering the same bytes: read released line              {read_first_raw}, stream released line {stream_first_raw}.              REQ-O-011a requires the stream to be no weaker than the tool"
        );
        // …and the two are the same order of magnitude, or "no weaker"
        // is being satisfied by a stream that withholds everything.
        assert!(
            stream_first_raw < read_first_raw * 4,
            "the stream withheld {stream_first_raw} lines against the              read's {read_first_raw}; they are no longer the same mechanism"
        );

        // The read's own bound, stated as a line index so a change to
        // `UNVOUCHED_CARRY_BYTES` moves it here rather than silently.
        let line_at = |i: usize| anchor + 32 + 65 * i as u64;
        assert!(
            line_at(read_first_raw) >= anchor + UNVOUCHED_CARRY_BYTES as u64,
            "the read released a line inside its own carry"
        );
        assert!(
            line_at(read_first_raw) < anchor + UNVOUCHED_CARRY_BYTES as u64 + 65,
            "the read covered more than its carry; the bound moved"
        );

        // …and the carry covers the largest key the one unbounded
        // shipped rule can match: a 16,384-bit RSA private key is 12,464
        // bytes in PEM. That relation is between two literals, so it is
        // held by `_RSA_16384_PEM_FITS_INSIDE_THE_CARRY` beside the
        // constant and the compiler checks it; naming it here is how a
        // reader of this row finds it.
    }

    /// **At `buffer.head` the scan reaches `UNVOUCHED_CARRY_BYTES` back
    /// and no further, and an anchor beyond that is released — measured
    /// here rather than described.**
    ///
    /// The at-`head` scan is `[head − UNVOUCHED_CARRY_BYTES, head −
    /// partial_secret_scan_bytes)`, and it is bounded **at the front**
    /// for a reason that is not symmetry: `earliest_partial` has no
    /// GH #163 ceiling and walks a liveness automaton from every anchor
    /// it finds to the end of its region, so an uncapped scan over a
    /// 1 MiB `resources/read` window is quadratic in a buffer an agent
    /// controls. `unresolved_from`, which the truncated branch uses, is
    /// capped by that ceiling and can afford the whole window.
    ///
    /// **The consequences, both of them asserted:** an anchor inside the
    /// carry is masked on every surface, and one beyond it is released
    /// exactly as `v0.0.7` released it — `held_back: false`,
    /// `redactions: {}`, no audit entry. GH #14's at-`head` residual is
    /// therefore *narrowed*, not closed, and the narrowing is the
    /// carry's width.
    ///
    /// **It also makes the protection non-monotonic in `max_bytes`, on
    /// one buffer at one cursor**, because `max_bytes` is what decides
    /// whether the window reaches `head` and therefore which scan runs.
    /// A smaller read takes the truncated branch, whose region reaches
    /// `since_cursor − UNVOUCHED_CARRY_BYTES` and finds the anchor; a
    /// larger one reaches `head` and does not. Pinned below, because it
    /// is surprising enough that a future reader will otherwise assume
    /// it is a bug and "fix" it by uncapping the scan.
    #[test]
    fn at_head_an_anchor_beyond_the_carry_is_released_and_one_inside_it_is_not() {
        let carry = UNVOUCHED_CARRY_BYTES as u64;
        let prologue = "$ cat chain.pem\n";

        // `body_bytes` sized so the key body runs from just after the
        // anchor to `head`; `head - anchor` is what decides the arm.
        let case = |body_bytes: usize| {
            let (pem, _) = pem_longer_than(body_bytes);
            let buf = format!("{prologue}{}\n", &pem[..pem.len() - 30]).into_bytes();
            let r = read(&buf, 0, 4 * 1024 * 1024);
            let span = buf.len() as u64 - prologue.len() as u64;
            (span, r)
        };

        // Inside the carry: masked, on the widest read there is.
        let (span, r) = case(4 * 1024);
        assert!(
            span < carry,
            "arm 1 must sit inside the carry (span {span})"
        );
        assert_eq!(r.redactions.get(redact::UNRESOLVED_KIND), Some(&1));
        assert!(!r.output.contains("KEYBODY000000"));

        // Beyond it: released, and the row says so rather than implying
        // the gap is closed.
        let (span, r) = case(48 * 1024);
        assert!(span > carry, "arm 2 must exceed the carry (span {span})");
        assert!(
            r.redactions.is_empty(),
            "the at-`head` scan reaches {carry} bytes back; an anchor \
             beyond that is not found, and this row is what keeps that a \
             measurement: {:?}",
            r.redactions
        );
        assert!(
            r.output.contains("KEYBODY000000"),
            "…and the body is released, exactly as v0.0.7 released it"
        );

        // **Non-monotonic in `max_bytes`, same buffer, same cursor.** The
        // smaller read truncates its window, takes the other branch, and
        // finds the anchor its own carry lookbehind reaches.
        let (pem, _) = pem_longer_than(48 * 1024);
        let buf = format!("{prologue}{}\n", &pem[..pem.len() - 30]).into_bytes();
        let small = read(&buf, 0, 4096);
        assert_eq!(
            small.redactions.get(redact::UNRESOLVED_KIND),
            Some(&1),
            "a truncated window scans `[since_cursor - carry, window_end)` \
             and must still find it"
        );
        let large = read(&buf, 0, 4 * 1024 * 1024);
        assert!(
            large.redactions.is_empty(),
            "the pair is what makes the non-monotonicity a pinned fact \
             rather than a surprise: {:?}",
            large.redactions
        );
    }

    /// **A terminated block keeps its own kind, at `buffer.head`.**
    ///
    /// The carry scan asks `earliest_partial`, whose third condition is
    /// *the rule's own anchored regex does not match yet* — asked of
    /// `region[i..]`. A region cut at `head − partial_secret_scan_bytes`
    /// cannot see a terminator landing after the cut, so a **completely
    /// terminated** key read as in flight, the synthetic span overlapped
    /// the real `private-key` one, and `merge_spans` weakened the whole
    /// match to `unresolved`: a correct, rule-named redaction turned
    /// anonymous and `status.redaction_stats` lost the kind.
    ///
    /// Found by measurement while building GH #195's fix, not by review.
    #[test]
    fn a_terminated_key_block_keeps_its_own_kind_at_head() {
        let p = processor();
        let (pem, body) = pem_longer_than(8 * 1024);
        let buf = format!("$ cat id_rsa\n{pem}\n").into_bytes();
        // The terminator must land inside the trailing region, which is
        // the arrangement that cut it out of the old scan.
        let end_at = String::from_utf8_lossy(&buf)
            .rfind("-----END")
            .expect("the fixture is a terminated block");
        assert!(
            buf.len() - end_at < p.limits.partial_secret_scan_bytes,
            "the fixture must put `-----END` inside the trailing region, \
             which is the arrangement that cut it out of the old scan"
        );

        let r = read(&buf, 0, 32 * 1024);
        assert_eq!(
            r.redactions.get("private-key"),
            Some(&1),
            "a terminated block names its own rule: {:?}",
            r.redactions
        );
        assert!(
            !r.redactions.contains_key(redact::UNRESOLVED_KIND),
            "…and is not weakened to the anonymous kind: {:?}",
            r.redactions
        );
        assert!(!r.output.contains(&body[..48]));
    }

    /// **REQ-O-008's withhold no longer wedges** (found by PR #215,
    /// measured, and fixed here rather than documented).
    ///
    /// The withhold is transient *because* the next read starts at the
    /// introducer and scans `max_bytes` past it, so the sequence exceeds
    /// `ansi_incomplete_max_bytes` and is dropped. That argument needs
    /// `max_bytes > ansi_incomplete_max_bytes`; at or below it, `cap_end`
    /// is `req_start + max_bytes`, it stops tracking `buffer.head`, and
    /// the pending sequence is the same length on every retry. Measured
    /// on `origin/main`: zero bytes with the cursor frozen at `max_bytes`
    /// 1, 8, 32 and 64 after a further 300 KB of output, clearing at 65.
    ///
    /// **Paired**, or the row passes against an implementation that never
    /// withholds an escape at all: one byte *above* the introducer the
    /// withhold still happens and still sets its cause.
    #[test]
    fn an_escape_under_the_incomplete_cap_no_longer_wedges() {
        let p = processor();
        let cap = p.limits.ansi_incomplete_max_bytes;
        let mut buf = b"done\x1b[".to_vec();
        buf.extend(std::iter::repeat_n(b'0', 4000));
        // A caller that followed `next_cursor` lands exactly on the ESC.
        const ESC_AT: u64 = 4;

        for max_bytes in [1usize, 8, 32, cap, cap + 1] {
            let r = read(&buf, ESC_AT, max_bytes);
            assert!(
                r.cursor > ESC_AT,
                "max_bytes {max_bytes}: {} bytes and a frozen cursor",
                r.bytes_returned
            );
            assert!(r.dropped_incomplete_escape || max_bytes > cap);
            assert_eq!(r.held_back_cause, None, "max_bytes {max_bytes}");
        }

        // The paired arm: a read that starts *before* the introducer has
        // bytes to return, so withholding costs it nothing and REQ-O-008
        // still applies. The sequence must also be under the cap — the
        // 4,000-byte one above is dropped on its length, which is the arm
        // `an_over_long_incomplete_escape_is_dropped_rather_than_stalling_reads`
        // already owns.
        let short = b"done\x1b[0".to_vec();
        let r = read(&short, 0, 32 * 1024);
        assert!(r.held_back, "REQ-O-008's withhold must survive the fix");
        assert_eq!(r.held_back_cause, Some(HeldBackCause::IncompleteEscape));
        assert_eq!(r.output, "done");
        assert_eq!(r.next_cursor, Some(4));
        assert!(!r.dropped_incomplete_escape);
    }

    /// **`held_back` is transient-only, and this is the property rather
    /// than a comment about it** (GH #195).
    ///
    /// Before 0.0.8 a third rule lowered `safety_end` at an offset that
    /// depended on the *request* and not on `buffer.head`, so the
    /// documented "retry at `next_cursor`" loop never advanced. Every
    /// remaining cause moves with `buffer.head`: the row drives each one
    /// and then shows the same read advancing once more output arrives.
    #[test]
    fn every_held_back_cause_is_released_by_more_output() {
        let mut seen: Vec<HeldBackCause> = Vec::new();

        // `in_flight_secret`: a token arriving with no delimiter yet.
        let arriving = b"line one\nexport TOKEN=ghp_0123456789abcdefghij".to_vec();
        let r = read(&arriving, 0, 32 * 1024);
        assert_eq!(r.held_back_cause, Some(HeldBackCause::InFlightSecret));
        seen.push(HeldBackCause::InFlightSecret);
        let mut finished = arriving.clone();
        finished.extend_from_slice(b"ABCDEFGHIJ012345\n$ ");
        let after = read(&finished, r.cursor, 32 * 1024);
        assert!(after.cursor > r.cursor, "more output released the boundary");

        // `incomplete_escape`: an unfinished sequence the child may end.
        let mut esc = b"done\x1b[".to_vec();
        esc.extend(std::iter::repeat_n(b'0', 8));
        let r = read(&esc, 0, 32 * 1024);
        assert_eq!(r.held_back_cause, Some(HeldBackCause::IncompleteEscape));
        seen.push(HeldBackCause::IncompleteEscape);
        let mut finished = esc.clone();
        finished.extend_from_slice(b"m and more\n");
        let after = read(&finished, r.cursor, 32 * 1024);
        assert!(after.cursor > r.cursor, "more output released the boundary");

        // Every declared cause was driven, so the row cannot go green by
        // covering one of them and calling it the set.
        seen.sort_by_key(|c| c.as_str());
        let mut all = HeldBackCause::ALL.to_vec();
        all.sort_by_key(|c| c.as_str());
        assert_eq!(seen, all, "a cause exists that this row never drove");
    }

    /// `HeldBackCause::ALL` really is all of them, and the wire spellings
    /// round-trip. The `match` is what the compiler makes fail when a
    /// variant is added and this list is not.
    #[test]
    fn the_held_back_causes_are_all_enumerated() {
        fn exhaustive(c: HeldBackCause) -> &'static str {
            match c {
                HeldBackCause::InFlightSecret => "in_flight_secret",
                HeldBackCause::IncompleteEscape => "incomplete_escape",
            }
        }
        assert_eq!(HeldBackCause::ALL.len(), 2);
        for c in HeldBackCause::ALL {
            assert_eq!(c.as_str(), exhaustive(*c));
            assert_eq!(HeldBackCause::from_wire(c.as_str()), Some(*c));
        }
        assert_eq!(HeldBackCause::from_wire("unvouched_window"), None);
        assert_eq!(HeldBackCause::from_wire(""), None);
    }

    /// GH #14, **the half no lookahead constant reaches.**
    ///
    /// A rule whose pattern opens with a character *range* derives no
    /// literal prefix, and if it declares none it gets no entry in the
    /// prefix index at all. `earliest_partial` is then structurally blind
    /// to it — at the buffer head and at the window's edge alike — so it
    /// has no holdback at any window size, and raising
    /// `redaction_lookahead_bytes` buys a larger number for the same bug.
    /// The bound that reaches it needs no prefix: a match running off the
    /// end of the window covers every byte from its start to that end, so
    /// for a non-`binary` rule it cannot begin before the maximal trailing
    /// run of value bytes.
    ///
    /// The shipped rule with this shape is `telegram-bot-token`
    /// (`\b[0-9]{8,10}:AA…{33}`), whose match is capped at 46 bytes and so
    /// cannot outrun any plausible window. REQ-O-006 puts **user** rules
    /// in the same index, so the fixture supplies one that can.
    ///
    /// **The fixture is envelope-shaped for a measured reason.** An
    /// unbounded *greedy* rule — `…[A-Za-z0-9]{16,}` with no closing
    /// anchor — does not leak at a truncated window at all: it simply
    /// matches to the window's last byte and `render` markers the lot.
    /// Measured, against this very buffer, before the fix existed. A match
    /// only escapes when it **cannot satisfy itself inside the window**,
    /// which means a closing anchor (`private-key-block`'s `-----END`) or
    /// a fixed length larger than the window. A prefixless rule that only
    /// exercised the greedy case would be green at BASE and prove nothing.
    #[test]
    fn a_prefixless_rules_over_long_match_is_not_emitted_raw_either() {
        let p = processor_with(
            r#"
            [[rule]]
            name = "gh14-prefixless"
            kind = "acme-envelope"
            pattern = '''\b[0-9]{4}-ACMEBOX-[A-Za-z0-9+/=]{16,}-ENDACMEBOX'''
            positive = ["1234-ACMEBOX-abcdefghijklmnop-ENDACMEBOX"]
            negative = ["1234-ACMEBOX-short-ENDACMEBOX"]
            "#,
        );
        assert!(
            p.index.prefixes_for(&p.rules, "gh14-prefixless").is_empty(),
            "the fixture rule must have NO index entry, or this test \
             exercises the prefix-anchored half of the fix instead of the \
             half nothing indexes"
        );

        let prologue = "$ dump-blob\n";
        let mut blob = String::from("1234-ACMEBOX-");
        while blob.len() < 60 * 1024 {
            blob.push_str("NOPREFIXSECRETBODY0123456789abcdefghij");
        }
        blob.push_str("-ENDACMEBOX");
        // The trailing newline is not decoration: without it the buffer's
        // last 512 bytes are an unbroken run of value bytes, and §4.1's
        // ordinary tail holdback — nothing to do with this fix — fires on
        // whatever indexed prefix the filler happens to contain.
        let buf = format!("{prologue}{blob}\n").into_bytes();

        const CAP: usize = 32 * 1024;
        assert!(
            CAP as u64 + p.limits.lookahead_bytes as u64 + 1 < buf.len() as u64,
            "the fixture must actually truncate the window, or it pins nothing"
        );

        let w = snapshot(&p, &buf, 0, CAP, true, false);
        let r = p.process(&w, &ReadOptions::default());
        // THE HARM: the value's bytes, in a response §4.1 says is
        // redacted. Since GH #195 the region is **masked** rather than
        // withheld, so the guarantee is stated with its bound: the first
        // `UNVOUCHED_CARRY_BYTES` after the candidate's start carry one
        // marker and no raw byte, and the residual past it is asserted
        // below rather than left to a comment.
        //
        // The blob is uniform filler, so *where* a released byte came
        // from cannot be read off its content. The assertion is therefore
        // arithmetic: the payload is the prologue, one marker, and exactly
        // the bytes between the end of the carry and `cap_end`. An
        // implementation that masked one byte fewer or one byte more
        // fails it, and so does one that masked nothing.
        let marker = redact::marker(redact::UNRESOLVED_KIND);
        let candidate_start = prologue.len();
        let released = CAP - candidate_start - UNVOUCHED_CARRY_BYTES;
        assert_eq!(
            r.output.len(),
            prologue.len() + marker.len() + released,
            "prologue, one marker, and exactly the bytes past the carry"
        );
        assert!(r.output.starts_with(&format!("{prologue}{marker}")));
        // **The harm is asserted over the whole payload, and a draft of
        // this row asserted it over a slice that could not contain it.**
        // Given the line above, `output[..prologue.len() + marker.len()]`
        // *is* `"$ dump-blob\n[REDACTED:unresolved]"` — so the `contains`
        // was satisfied by every input it was meant to reject. Swapping
        // the needle for `"unresolved"` made it fail, which is how the
        // no-op was demonstrated rather than argued.
        let carry_end_in_output = prologue.len() + marker.len() + released;
        assert_eq!(
            r.output.len(),
            carry_end_in_output,
            "the payload is the prologue, one marker, and exactly the bytes \
             past the carry"
        );
        // The strongest form available, and it cannot be off by one: the
        // payload past the marker is **byte-identical** to the buffer from
        // the end of the carry to `cap_end`. A mask one byte short leaks a
        // byte here; one byte long eats one.
        assert_eq!(
            &r.output.as_bytes()[prologue.len() + marker.len()..],
            &buf[candidate_start + UNVOUCHED_CARRY_BYTES..CAP],
            "the released tail must be exactly the bytes past the carry"
        );
        assert!(
            r.output[prologue.len() + marker.len()..].contains("NOPREFIXSECRETBODY"),
            "the residual moved: past the carry the candidate is not \
             believed and its bytes are released"
        );
        assert_eq!(r.redactions.get(redact::UNRESOLVED_KIND), Some(&1));
        assert!(!r.held_back, "masked, not withheld — GH #195");
        assert_eq!(r.bytes_returned, CAP, "and full progress");

        // Paired, as above: a window reaching the end of the blob resolves
        // it to the rule that matched and names that rule's kind, so the
        // withhold is a consequence of the missing evidence and not of the
        // rule being unindexed.
        let w = snapshot(&p, &buf, 0, 256 * 1024, true, false);
        let r = p.process(&w, &ReadOptions::default());
        assert!(!r.held_back);
        assert_eq!(r.output, format!("{prologue}[REDACTED:acme-envelope]\n"));
        assert_eq!(r.redactions.get("acme-envelope"), Some(&1));
        assert_eq!(r.cursor, buf.len() as u64, "the read made full progress");
    }

    /// The measurement from the note above, kept as a test: an unbounded
    /// **greedy** rule is self-covering at a truncated window, and must
    /// keep making progress.
    ///
    /// `…[A-Za-z0-9]{16,}` with no closing anchor matches right up to the
    /// window's last byte, so `find_spans` returns a span reaching
    /// `window_end`, `render` emits one marker over the whole unjudgeable
    /// region, and no raw byte escapes without any help from the
    /// truncation bound. Declining here as well would trade a correct
    /// marker and a cursor that advances for a withhold that buys nothing
    /// — so the bound stands down when a span already covers the region to
    /// the window's edge.
    #[test]
    fn a_greedy_match_reaching_the_window_edge_is_markered_and_not_declined() {
        let p = processor_with(
            r#"
            [[rule]]
            name = "gh14-greedy"
            kind = "acme-blob"
            pattern = '''\b[0-9]{4}:ZZ[A-Za-z0-9]{16,}'''
            positive = ["1234:ZZabcdefghijklmnop"]
            negative = ["1234:ZZshort"]
            "#,
        );
        let prologue = "$ dump-blob\n";
        let mut blob = String::from("1234:ZZ");
        while blob.len() < 60 * 1024 {
            blob.push_str("GREEDYSECRETBODY0123456789abcdefghij");
        }
        let buf = format!("{prologue}{blob}\n").into_bytes();

        const CAP: usize = 32 * 1024;
        let w = snapshot(&p, &buf, 0, CAP, true, false);
        let r = p.process(&w, &ReadOptions::default());
        assert!(!r.output.contains("GREEDYSECRETBODY"), "the value leaked");
        assert_eq!(r.output, format!("{prologue}[REDACTED:acme-blob]"));
        assert_eq!(r.redactions.get("acme-blob"), Some(&1));
        assert!(
            !r.held_back,
            "the span covers every byte the window could not judge; there \
             is nothing left to decline"
        );
        assert!(
            r.cursor > CAP as u64,
            "the cursor must clear the straddling span, not stop at the cap"
        );
    }

    /// The control that keeps the new bound **targeted**, and the one that
    /// dies if its truncation gate is dropped.
    ///
    /// Ordinary output ends mid-word constantly — `buffer.head` lands
    /// wherever the child's last write did — and a read whose window
    /// reaches `head` has already seen every byte there is. Declining the
    /// trailing partial word *there* would make `held_back` routine, which
    /// §4.1 names as the rev. 10–14 failure the targeted holdback exists
    /// to avoid. `streaming_ordinary_output_is_never_held_back` above
    /// cannot catch that: it reads a 1 MiB buffer whose every line ends in
    /// a newline, so its trailing run is empty at exactly the read where
    /// the window stops being truncated.
    #[test]
    fn a_window_that_reaches_the_buffer_head_never_declines_a_trailing_word() {
        let mut buf: Vec<u8> = Vec::new();
        while buf.len() < 40 * 1024 {
            buf.extend_from_slice(b"   Compiling holdfast-core v0.0.1 (/home/user/src)\n");
        }
        // The child's last write stopped mid-word, as writes do.
        buf.extend_from_slice(b"   Compil");
        // A cap large enough that `window_end == head`: there is no
        // unseen byte for the read to be cautious about.
        let r = read(&buf, 0, 256 * 1024);
        assert!(
            !r.held_back,
            "the window saw everything there is to see; nothing is unresolved"
        );
        assert_eq!(r.cursor, buf.len() as u64);
        assert!(r.output.ends_with("   Compil"), "the tail must survive");
    }

    // ------------------------------------------------- ANSI boundary rule

    /// REQ-O-008: while the child is alive an unfinished trailing escape
    /// pulls the read back to its introducer.
    #[test]
    fn an_unfinished_trailing_escape_withholds_its_tail_while_the_child_lives() {
        let buf = b"done\x1b[3".to_vec();
        let r = read(&buf, 0, 4096);
        assert!(r.held_back);
        assert_eq!(r.output, "done");
        assert_eq!(r.cursor, 4, "pulled back to the ESC at offset 4");
        assert!(!r.dropped_incomplete_escape);
    }

    #[test]
    fn an_unfinished_trailing_escape_is_dropped_once_the_child_has_exited() {
        let buf = b"done\x1b[3".to_vec();
        let p = processor();
        let w = snapshot(&p, &buf, 0, 4096, false, false);
        let r = p.process(&w, &ReadOptions::default());
        assert!(!r.held_back, "a dead child will never finish it");
        assert_eq!(r.output, "done");
        assert_eq!(r.cursor, buf.len() as u64, "the read completes");
        assert!(r.dropped_incomplete_escape, "and it is reported");
    }

    #[test]
    fn an_over_long_incomplete_escape_is_dropped_rather_than_stalling_reads() {
        // A program that emitted `\x1b[` and then kept writing parameter
        // bytes forever must not withhold the tail of every later read.
        let mut buf = b"done\x1b[".to_vec();
        buf.extend(std::iter::repeat_n(b'0', 200));
        let r = read(&buf, 0, 4096);
        assert!(!r.held_back);
        assert!(r.dropped_incomplete_escape);
        assert_eq!(r.output, "done");
        assert_eq!(r.cursor, buf.len() as u64);
    }

    #[test]
    fn raw_mode_bypasses_the_escape_boundary_rule() {
        let buf = b"done\x1b[3".to_vec();
        let p = processor();
        let w = snapshot(&p, &buf, 0, 4096, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..Default::default()
            },
        );
        assert!(!r.held_back);
        assert_eq!(r.output, "done\u{1b}[3");
    }

    // -------------------------------------------------------- encodings

    #[test]
    fn base64_with_redaction_encodes_the_redacted_stream() {
        use base64::Engine as _;
        let buf = format!("t={GITHUB}\n").into_bytes();
        let p = processor();
        let w = snapshot(&p, &buf, 0, 4096, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                text_encoding: TextEncoding::Base64,
                ..Default::default()
            },
        );
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(r.output.as_bytes())
            .unwrap();
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "t=[REDACTED:github]\n");
        assert!(!text.contains(GITHUB));
        assert_eq!(
            r.bytes_returned,
            buf.len(),
            "bytes_returned counts raw bytes, not encoded ones"
        );
    }

    #[test]
    fn base64_without_redaction_is_byte_exact() {
        use base64::Engine as _;
        let buf: Vec<u8> = vec![0xff, 0x00, 0x80, b'h', b'i'];
        let p = processor();
        let w = snapshot(&p, &buf, 0, 4096, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                text_encoding: TextEncoding::Base64,
                redact: false,
            },
        );
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(r.output.as_bytes())
            .unwrap();
        assert_eq!(decoded, buf);
    }

    #[test]
    fn redaction_and_ansi_are_independent_knobs() {
        // ansi: raw must not disable redaction (§5.2).
        let buf = format!("\x1b[31mt={GITHUB}\x1b[0m").into_bytes();
        let p = processor();
        let w = snapshot(&p, &buf, 0, 4096, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..Default::default()
            },
        );
        assert!(!r.output.contains(GITHUB), "raw mode must still redact");
        assert_eq!(r.output, "\u{1b}[31mt=[REDACTED:github]\u{1b}[0m");
    }

    #[test]
    fn disabling_redaction_returns_the_secret_verbatim() {
        let buf = format!("t={GITHUB}\n").into_bytes();
        let p = processor();
        let w = snapshot(&p, &buf, 0, 4096, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                redact: false,
                ..Default::default()
            },
        );
        assert_eq!(r.output, format!("t={GITHUB}\n"));
        assert!(r.redactions.is_empty());
    }

    // ------------------------------------------ GH #138: window vs. page

    /// **The window matches nothing and the page matches a credential.**
    /// The lookbehind ends in a word character, so `\bghp_` has no word
    /// boundary to open on anywhere in `[window_start, window_end)` —
    /// and the caller's page begins at the `g`, where it does.
    ///
    /// The `all_spans` call is the control: without it this row passes
    /// against a build that never had the defect, because "the token is
    /// absent from the output" is also what a correctly-redacting window
    /// scan produces. 51 of the 61 shipped positive fixtures reach this
    /// shape (`tests/redaction_sweep.rs`).
    #[test]
    fn a_token_whose_word_break_is_supplied_by_the_lookbehind_is_still_redacted() {
        let mut buf = b"x".repeat(600);
        let req_start = buf.len() as u64;
        buf.extend_from_slice(GITHUB.as_bytes());
        buf.extend_from_slice(b"\nbuild finished\n");

        let p = processor();
        let w = snapshot(&p, &buf, req_start, 4096, true, false);
        assert!(
            p.all_spans(w.window, w.window_start).is_empty(),
            "control: the window itself must match nothing, or the page \
             pass is not what this row is testing"
        );

        let r = p.process(&w, &ReadOptions::default());
        assert!(
            !r.output.contains(GITHUB),
            "the page the caller receives must not carry the token: {:?}",
            r.output
        );
        assert_eq!(r.redactions.get("github"), Some(&1));
    }

    /// The page pass adds **markers only**. A span found inside
    /// `[req_start, read_end)` ends at or before `read_end` by
    /// construction, so it can never move the cursor — which is what
    /// keeps `bytes_returned` and the continuation cursor the same for
    /// every caller, whatever display knobs they set (see `normalise`'s
    /// third invariant).
    #[test]
    fn the_page_pass_moves_no_cursor() {
        let mut buf = b"x".repeat(600);
        let req_start = buf.len() as u64;
        buf.extend_from_slice(GITHUB.as_bytes());
        buf.extend_from_slice(b"\nbuild finished\n");

        let p = processor();
        let w = snapshot(&p, &buf, req_start, 4096, true, false);
        let redacted = p.process(&w, &ReadOptions::default());
        // `redact: false` takes the same path with no span set at all,
        // so any cursor difference is the page pass and nothing else.
        let raw = p.process(
            &w,
            &ReadOptions {
                redact: false,
                ..Default::default()
            },
        );
        assert!(
            raw.output.contains(GITHUB),
            "control: the audited hatch still returns the token, so the \
             two reads really did see the same bytes"
        );
        assert_eq!(
            redacted.cursor, raw.cursor,
            "the page pass may add a marker; it may not move the cursor"
        );
        assert_eq!(redacted.bytes_returned, raw.bytes_returned);
    }

    // ------------------------------------- GH #125: the normalisation seam

    /// The token as the issue plants it: a colour reset 15 characters in,
    /// which is what any program that highlights part of a line emits.
    fn painted(token: &str, tail: &str) -> Vec<u8> {
        format!("{}\x1b[0m{}{tail}", &token[..15], &token[15..]).into_bytes()
    }

    /// **The premise every row below rests on, asserted once rather than
    /// assumed eight times.** The defect is not that the rule is weak: it
    /// is that the bytes redaction was shown are not the bytes the caller
    /// receives. So the raw form really must not match, and the
    /// normalised form really must — otherwise the rows that follow are
    /// about something else and would pass against a fix that does
    /// nothing.
    #[test]
    fn the_raw_bytes_do_not_match_and_the_bytes_the_caller_gets_do() {
        let p = processor();
        let buf = painted(GITHUB, "\n");
        assert!(
            redact::find_spans(&p.rules, &buf, 0).is_empty(),
            "the planted escape must break the rule's anchor in the raw window"
        );
        assert_eq!(
            String::from_utf8_lossy(&ansi::strip(&buf)),
            format!("{GITHUB}\n"),
            "and stripping must put the credential back together"
        );
    }

    /// **GH #125, the issue's unit-level reproduction, as a permanent
    /// row.** Redaction searched `w.window` — the raw buffer — while
    /// `AnsiStripper` ran later inside `render`, so the escape defeated
    /// the match and was then removed on the way out: a complete, valid
    /// 40-character credential, on the default read path, reported as
    /// `redactions: {}`.
    #[test]
    fn an_escape_inside_a_token_is_redacted_rather_than_stripped_back_together() {
        let r = read(&painted(GITHUB, "\n"), 0, 32 * 1024);
        assert!(!r.output.contains(GITHUB), "reassembled: {}", r.output);
        assert_eq!(r.output, "[REDACTED:github]\n");
        assert_eq!(
            r.redactions.get("github"),
            Some(&1),
            "and the caller is told, which `redactions: {{}}` did not"
        );
    }

    /// **Two credentials in one read, found by two different passes.**
    /// The painted one matches only in a view; the clean one only ever
    /// needed the raw bytes — and the raw pass runs first, so the union
    /// arrives with a later span in front of an earlier one.
    ///
    /// `render` and the `read_end` advance are both **single forward
    /// passes** over spans they are promised are sorted and
    /// non-overlapping. That promise used to come free, because
    /// `find_spans` sorts what it finds and there was one call; a union of
    /// several calls has to be merged again to keep it. Dropping that
    /// merge does not fail loudly — it walks past the out-of-order span
    /// and emits the credential it covers byte for byte, which is the
    /// original defect wearing a different hat. No other row here has
    /// both shapes of secret in one window, so no other row notices, and
    /// removing `merge_spans` from `all_spans` passed the whole 932-test
    /// suite before this was written.
    #[test]
    fn two_secrets_found_by_different_passes_are_both_replaced() {
        const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
        let mut buf = painted(GITHUB, " then ");
        buf.extend_from_slice(format!("{AWS}\n").as_bytes());
        let p = processor();
        // The premise: one is invisible to the raw pass and the other is
        // all the raw pass ever needed, so the union really is assembled
        // out of order.
        let raw_spans = redact::find_spans(&p.rules, &buf, 0);
        assert_eq!(raw_spans.len(), 1, "only the clean token matches raw");
        assert!(raw_spans[0].start > 0, "and it is the *later* of the two");

        let r = read(&buf, 0, 32 * 1024);
        assert!(!r.output.contains(&GITHUB[..15]), "leaked: {}", r.output);
        assert!(!r.output.contains(AWS), "leaked: {}", r.output);
        assert_eq!(r.output, "[REDACTED:github] then [REDACTED:aws]\n");
        assert_eq!(r.redactions.get("github"), Some(&1));
        assert_eq!(r.redactions.get("aws"), Some(&1));
    }

    /// The same planted escape under each `text_encoding`. Encoding runs
    /// *after* redaction, so a fix that matched only the stripped stream
    /// would pass `utf8` and `base64` and still hand the credential to a
    /// `lossy_printable` caller — these are the same bytes reached by
    /// three different last steps, and the seam is in every one of them.
    #[test]
    fn every_text_encoding_redacts_through_a_planted_escape() {
        use base64::Engine as _;
        let buf = painted(GITHUB, "\n");
        let p = processor();
        for encoding in [
            TextEncoding::Utf8,
            TextEncoding::Base64,
            TextEncoding::LossyPrintable,
        ] {
            let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
            let r = p.process(
                &w,
                &ReadOptions {
                    text_encoding: encoding,
                    ..Default::default()
                },
            );
            let text = match encoding {
                TextEncoding::Base64 => String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(r.output.as_bytes())
                        .expect("base64 round-trips"),
                )
                .expect("the redacted stream is UTF-8"),
                _ => r.output.clone(),
            };
            assert!(
                !text.contains(GITHUB),
                "{} reassembled the credential: {text}",
                encoding.as_str()
            );
            assert_eq!(text, "[REDACTED:github]\n", "{}", encoding.as_str());
            assert_eq!(
                r.redactions.get("github"),
                Some(&1),
                "{}",
                encoding.as_str()
            );
        }
    }

    /// `ansi: raw` is the other half of the same seam, and the assertion
    /// has to be written differently to mean anything.
    ///
    /// A raw payload still carries the escape, so `contains(GITHUB)` is
    /// **false against the unfixed code** — the credential is all there,
    /// split by four bytes that vanish the moment the agent pipes the
    /// stream to anything that renders it. The halves are therefore what
    /// this asserts on. `ansi: raw` is a display knob, not an audited
    /// escape hatch; `redact: false` is the hatch, and it is the row
    /// below.
    #[test]
    fn raw_mode_redacts_the_credential_a_terminal_would_reassemble() {
        let buf = painted(GITHUB, "\n");
        let p = processor();
        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..Default::default()
            },
        );
        assert!(
            !r.output.contains(&GITHUB[..15]),
            "the first half survived: {:?}",
            r.output
        );
        assert!(
            !r.output.contains(&GITHUB[15..]),
            "the second half survived: {:?}",
            r.output
        );
        assert_eq!(
            r.output, "[REDACTED:github]\n",
            "one marker covers the token and the escape planted inside it"
        );
        assert_eq!(r.redactions.get("github"), Some(&1));
    }

    /// The sibling one step further down the pipeline: two C0 bytes the
    /// **stripper keeps** and `lossy_printable` drops. Nothing about the
    /// mechanism is specific to `\x1b`, so a fix aimed at escape
    /// sequences alone would leave `read_output(text_encoding:
    /// "lossy_printable")` reassembling credentials exactly as before.
    #[test]
    fn a_control_byte_only_the_encoder_drops_cannot_reassemble_a_token_either() {
        let p = processor();
        for planted in ['\u{8}', '\u{7f}'] {
            let buf = format!("{}{planted}{}\n", &GITHUB[..15], &GITHUB[15..]).into_bytes();
            // Both halves of the premise, per byte: the raw form does not
            // match, and stripping alone does not repair it either — so
            // this row cannot pass for the reason the row above does.
            assert!(
                redact::find_spans(&p.rules, &buf, 0).is_empty(),
                "{planted:?} must break the anchor"
            );
            assert_eq!(
                ansi::strip(&buf),
                buf,
                "{planted:?} survives the stripper; only the encoder drops it"
            );

            let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
            let r = p.process(
                &w,
                &ReadOptions {
                    text_encoding: TextEncoding::LossyPrintable,
                    ..Default::default()
                },
            );
            assert!(
                !r.output.contains(GITHUB),
                "{planted:?} was dropped around an intact credential: {}",
                r.output
            );
            assert_eq!(r.output, "[REDACTED:github]\n", "{planted:?}");
        }
    }

    /// **The boundary row: a planted escape *and* a read boundary inside
    /// the token.** Redaction, stripping and pagination are each tested
    /// alone above and elsewhere; this is the seam.
    ///
    /// The cap at 12 lands inside the token, so `process` must advance
    /// the continuation cursor past the *whole* span — which now includes
    /// the four bytes of the escape — or the next read starts inside the
    /// credential with a lookbehind that cannot reach its anchor.
    #[test]
    fn neither_half_of_a_split_read_leaks_through_a_planted_escape() {
        let mut buf = b"prefix ".to_vec();
        buf.extend_from_slice(&painted(GITHUB, " suffix"));
        let first = read(&buf, 0, 12);
        let second = read(&buf, first.cursor, 32 * 1024);
        for part in [&first.output, &second.output] {
            assert!(!part.contains(&GITHUB[..15]), "leaked: {part}");
            assert!(!part.contains(&GITHUB[15..]), "leaked: {part}");
        }
        assert_eq!(first.output, "prefix [REDACTED:github]");
        assert_eq!(
            first.cursor,
            (7 + GITHUB.len() + 4) as u64,
            "the cursor must clear the token *and* the escape inside it"
        );
        assert_eq!(second.output, " suffix");
        assert!(second.redactions.is_empty());
    }

    /// Paging the same buffer in 8-byte requests: every cursor is a raw
    /// buffer offset, the pages tile the buffer exactly, and the
    /// concatenation carries one marker and no half-credential.
    ///
    /// The tiling is the half that pins the mapping. A fix that reported
    /// spans in *normalised* offsets would still redact — and would then
    /// hand back a cursor short of, or past, the bytes it consumed, so
    /// paging would repeat or skip output with nothing to show for it.
    #[test]
    fn paging_over_a_planted_escape_keeps_every_cursor_on_the_raw_stream() {
        let mut buf = b"head ".to_vec();
        buf.extend_from_slice(&painted(GITHUB, " tail\n"));
        let mut cursor = 0u64;
        let mut seen = String::new();
        let mut pages = 0usize;
        while cursor < buf.len() as u64 {
            let r = read(&buf, cursor, 8);
            assert!(r.cursor > cursor, "page {pages} made no progress");
            assert_eq!(
                r.bytes_returned as u64,
                r.cursor - cursor,
                "bytes_returned counts raw bytes consumed, page {pages}"
            );
            seen.push_str(&r.output);
            cursor = r.cursor;
            pages += 1;
            assert!(pages < 64, "paging did not terminate");
        }
        assert_eq!(
            cursor,
            buf.len() as u64,
            "the final cursor lands exactly on head"
        );
        assert_eq!(seen, "head [REDACTED:github] tail\n");
    }

    /// **A window that does not start at zero, which is the only thing
    /// that tests the map's base.**
    ///
    /// Every other row here fits inside `lookbehind_bytes`, so
    /// `window_start` is 0 and a view offset and an absolute offset are
    /// the same number — a mapping that never added the window's own
    /// start would land on exactly the right byte in all of them and
    /// leak here. The padding is the whole fixture: it puts the painted
    /// token past the lookbehind so a read of it opens a window several
    /// hundred bytes into the buffer.
    #[test]
    fn a_painted_token_far_into_the_buffer_maps_back_to_absolute_offsets() {
        let p = processor();
        let mut buf = "filler line\n".repeat(200).into_bytes();
        let at = buf.len() as u64;
        assert!(
            at > p.limits.lookbehind_bytes as u64,
            "the arrangement must really start its window past zero"
        );
        buf.extend_from_slice(&painted(GITHUB, " tail\n"));

        let r = read(&buf, at, 32 * 1024);
        assert!(!r.output.contains(&GITHUB[..15]), "leaked: {}", r.output);
        assert_eq!(r.output, "[REDACTED:github] tail\n");
        assert_eq!(r.cursor, buf.len() as u64);
        assert_eq!(
            r.bytes_returned as u64,
            buf.len() as u64 - at,
            "bytes_returned still counts raw bytes from the request's start"
        );
    }

    /// **The other direction, which the first version of this fix got
    /// wrong.** A *terminated* window title carrying an indexed secret
    /// prefix must not stop the read.
    ///
    /// Asking the `Printable` view whether a secret is in flight does
    /// stop it: that view deletes the `\x1b` and the BEL and keeps
    /// `]0;SECRET_DONE`, which to a continuation test whose whole rule is
    /// *printable and not a space* reads as a value still accumulating.
    /// Nothing here is contrived — it is `screen.rs`'s own fixture, and
    /// the read stopped four bytes into the sequence.
    #[test]
    fn a_terminated_window_title_is_not_a_credential_still_arriving() {
        let p = processor();
        assert!(
            p.index
                .prefixes_for(&p.rules, "generic-secret-assignment")
                .contains(&b"secret".to_vec()),
            "the premise: `secret` is an indexed prefix, so the title really \
             does offer the scanner a candidate"
        );
        let buf = b"harmless header line\x1b[2;1Hdone\x1b]0;SECRET_DONE\x07".to_vec();
        let r = read(&buf, 0, 32 * 1024);
        assert!(!r.held_back, "a finished title is not a secret in flight");
        assert_eq!(r.cursor, buf.len() as u64, "and the read reaches head");
        assert_eq!(r.output, "harmless header linedone");
    }

    /// A colourised blob with no space or newline in it, longer than
    /// `max_bytes + lookahead`, paged at the default size.
    ///
    /// **The GH #14 path (`window_end < w.head`) is the only branch this
    /// reaches, and it had no row.** `unresolved_from`'s trailing
    /// value-run test finds the first byte the window cannot vouch for;
    /// escapes break that run in the raw bytes and do not break it in a
    /// stripped view, so asking the views moved the run start back to at
    /// or before `req_start`, `read_end` came out equal to the cursor it
    /// was given, and the read returned **zero bytes for ever**. `jq -C
    /// -c` on a medium document is that shape.
    ///
    /// The stall *class* pre-exists this fix — the same probe with the
    /// escapes removed stalls on the parent commit too, and closing that
    /// is not this change's job. What is this change's job is not moving
    /// colourised output, which streamed before, into it.
    #[test]
    fn a_colourised_blob_with_no_delimiter_still_pages_to_the_end() {
        let mut buf = b"starting up\n".to_vec();
        for i in 0..2000u32 {
            buf.extend_from_slice(b"\x1b[32m");
            buf.extend_from_slice(format!("{:016x}", i).as_bytes());
        }
        buf.extend_from_slice(b"\ndone\n");

        let mut cursor = 0u64;
        let mut pages = 0usize;
        let mut seen = 0usize;
        while cursor < buf.len() as u64 {
            let r = read(&buf, cursor, 1024);
            assert!(
                r.cursor > cursor,
                "page {pages} returned {} bytes and left the cursor at {cursor}: \
                 a read that never completes",
                r.bytes_returned
            );
            seen += r.bytes_returned;
            cursor = r.cursor;
            pages += 1;
            assert!(pages < 200, "paging did not terminate");
        }
        assert_eq!(seen, buf.len(), "the pages must tile the buffer exactly");
    }

    /// **The row that ties the enumeration to the pipeline, so the module
    /// header's claim is checked rather than asserted in prose.**
    ///
    /// `normalise`'s table says the emittable streams are the raw window
    /// and its three views. Nothing proved that: the views were pinned
    /// against hand-written literals, so a *fourth* filter appearing
    /// anywhere in `render` or `encode` would go unnoticed and reopen
    /// GH #125 for whatever stream it produced. Driven, by adding a CRLF
    /// normalisation to `encode`'s `Utf8` arm: `deploy ghp_…\r…` came
    /// back as a whole credential with `redactions: {}`, and the suite's
    /// entire reaction was three `assert_eq!`s differing by `\r\n` versus
    /// `\n` — exactly the failures somebody fixes by editing the
    /// literals.
    ///
    /// So this asserts the relationship instead: with redaction off, the
    /// bytes a read emits under **every** `ansi` × `text_encoding`
    /// combination must be the raw window or one of the streams
    /// `emitted_views` names. A new filter fails it on the next run.
    ///
    /// `redact: false` is deliberate — it is the only way to see the
    /// pipeline's own output with no markers substituted into it — and
    /// the fixture is ASCII so a lossy UTF-8 decode is the identity and
    /// the comparison stays on bytes.
    #[test]
    fn every_option_combination_emits_a_stream_this_module_enumerates() {
        use base64::Engine as _;
        // One of everything the filters react to: a CSI, an OSC with a
        // payload, a bare `\x08`, a `\x7f`, and a CRLF.
        let buf = b"a\x1b[31mb\x08c\x7fd\x1b]0;title\x07e\r\nf\n".to_vec();
        let p = processor();

        let mut streams: Vec<Vec<u8>> = vec![buf.clone()];
        for v in normalise::emitted_views(&buf, 0) {
            streams.push(v.bytes().to_vec());
        }

        for ansi in [AnsiMode::Strip, AnsiMode::Raw] {
            for text_encoding in [
                TextEncoding::Utf8,
                TextEncoding::Base64,
                TextEncoding::LossyPrintable,
            ] {
                let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
                let r = p.process(
                    &w,
                    &ReadOptions {
                        ansi,
                        text_encoding,
                        redact: false,
                    },
                );
                let emitted = match text_encoding {
                    TextEncoding::Base64 => base64::engine::general_purpose::STANDARD
                        .decode(r.output.as_bytes())
                        .expect("base64 round-trips"),
                    _ => r.output.clone().into_bytes(),
                };
                assert!(
                    streams.contains(&emitted),
                    "{ansi:?}/{} emitted a stream `emitted_views` does not \
                     enumerate, so redaction never judged it: {emitted:?}",
                    text_encoding.as_str()
                );
            }
        }
    }

    /// `View::Printable`'s own case — `ansi: "raw"` with
    /// `lossy_printable`, the one combination no other view covers —
    /// asserted on an outcome rather than on the view taxonomy.
    ///
    /// The stripper keeps `\x08`, so the raw and stripped streams both
    /// carry the planted byte and neither reassembles anything; only this
    /// combination drops it and joins the halves.
    #[test]
    fn the_raw_lossy_printable_stream_is_redacted_on_its_own_account() {
        let buf = format!("deploy {}\u{8}{}\n", &GITHUB[..15], &GITHUB[15..]).into_bytes();
        let p = processor();
        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                text_encoding: TextEncoding::LossyPrintable,
                ..Default::default()
            },
        );
        assert!(!r.output.contains(GITHUB), "reassembled: {}", r.output);
        assert_eq!(r.output, "deploy [REDACTED:github]\n");
        assert_eq!(r.redactions.get("github"), Some(&1));
    }

    /// **Ordinary output that ends in an escape sequence must still be
    /// released (GH #142).**
    ///
    /// `earliest_partial` used to ask whether every byte from an indexed
    /// prefix to the end of the region was printable and not a space; the
    /// control byte that ends a sequence is what ended that run. Asking a
    /// *stripped* view under that test removed the terminator, the run
    /// reached the end of the region, and the read stopped — permanently,
    /// because the line is finished and nothing more is coming.
    ///
    /// **It asks the rule now, so no run is formed on this line at all
    /// (GH #142).** `mailgun-api-key` is `\bkey-[a-f0-9]{32}`, which
    /// cannot reach the `m` of `manager` — the release comes from the
    /// predicate rather than from the terminator, and would survive a
    /// stream that deleted the terminator. No such stream is asked here:
    /// `holdback_boundary` reads the raw bytes only.
    ///
    /// `key-` is `mailgun-api-key`'s indexed prefix and the rest of this
    /// line is an npm deprecation warning. A progress line ending in
    /// `\x1b[K` with no newline after it is the ordinary shape, not an
    /// exotic one, which is why this is a row and not a footnote: it
    /// strands the caller's own output, takes `prompt.last_line` to `""`
    /// on every `status` and `list_sessions`, and turns a
    /// `wait_for_pattern` that answered instantly into one that burns its
    /// whole `timeout_secs`.
    #[test]
    fn ordinary_output_ending_in_an_escape_sequence_is_not_held_back() {
        let buf = b"added 210 packages\r\nnpm WARN deprecated \x1b[33m@acme/key-manager@1.2.3\x1b[0m\x1b[K".to_vec();
        let p = processor();
        // The premise: there really is an indexed prefix in the tail, so
        // the row exercises the detector rather than skipping past it.
        assert!(
            p.index
                .prefixes_for(&p.rules, "mailgun-api-key")
                .iter()
                .any(|x| x == b"key-"),
            "`key-` must be indexed, or this line offers the scanner nothing"
        );
        let r = read(&buf, 0, 32 * 1024);
        assert!(
            !r.held_back,
            "an ordinary warning line was withheld: {:?}",
            r.output
        );
        assert_eq!(r.cursor, buf.len() as u64, "the read must reach head");
        assert_eq!(
            r.output,
            "added 210 packages\r\nnpm WARN deprecated @acme/key-manager@1.2.3"
        );
    }

    /// The audited opt-out is unchanged: `redact: false` disables the
    /// redaction *and* the holdback, and returns the planted bytes
    /// exactly as the child wrote them (§4.1).
    #[test]
    fn the_audited_opt_out_still_returns_the_planted_bytes_verbatim() {
        let buf = painted(GITHUB, "\n");
        let p = processor();
        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                redact: false,
                ..Default::default()
            },
        );
        assert_eq!(r.output, String::from_utf8_lossy(&buf));
        assert!(r.redactions.is_empty());
        assert!(!r.held_back);
        assert_eq!(r.cursor, buf.len() as u64);
    }

    /// A credential inside an OSC title is **absent from the stripped
    /// view**, because the stripper consumes a sequence's payload whole —
    /// and `ansi: raw` puts those bytes on the wire regardless. So the
    /// span set is a *union* over the streams a read can emit, never a
    /// move from the raw bytes to the normalised ones: a fix that
    /// replaced `find_spans(window)` with `find_spans(stripped)` would
    /// have traded this case for the one the issue reports, and this row
    /// is what fails when it does.
    ///
    /// **What it does *not* pin, said plainly.** Deleting the raw pass
    /// alone leaves this one green, because the `lossy_printable` view
    /// keeps an escape sequence's body and carries the token too. That
    /// deletion is caught many times over by the rows that predate this
    /// work — for a buffer of plain text there is no view at all and
    /// nothing is redacted — so it needs no row of its own here.
    #[test]
    fn a_secret_only_the_raw_stream_carries_is_still_redacted() {
        let buf = format!("\x1b]0;deploy {GITHUB}\x07$ ").into_bytes();
        let p = processor();
        assert!(
            !ansi::strip(&buf).windows(4).any(|w| w == b"ghp_"),
            "the stripped view really does not carry it"
        );
        let w = snapshot(&p, &buf, 0, 32 * 1024, true, false);
        let r = p.process(
            &w,
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..Default::default()
            },
        );
        assert!(!r.output.contains(GITHUB), "leaked: {}", r.output);
        assert_eq!(r.output, "\u{1b}]0;deploy [REDACTED:github]\u{7}$ ");
    }

    // ------------------------------------------ GH #241: UTF-8 boundaries

    /// Mixed-width text in which every page boundary a small `max_bytes`
    /// produces lands inside a character sooner or later: two-, three-
    /// and four-byte sequences, ASCII between them, and newlines.
    fn multibyte_corpus(lines: usize) -> String {
        "한ü日語 — “quoted” 🦀 é 🎉 abc\n".repeat(lines)
    }

    /// **The documented paging loop returns the text it was given, at
    /// every `max_bytes`, including the ones smaller than a character**
    /// (GH #241).
    ///
    /// The window end was a raw byte count and `encode` decodes each page
    /// on its own, so a character split across two pages came back as
    /// U+FFFD on both sides. Measured on `main` at `a81b02d` with this
    /// corpus: every `max_bytes` below swaps characters for U+FFFD, and
    /// `max_bytes: 1` returns nothing *but* U+FFFD for the non-ASCII part.
    ///
    /// Two properties, and each one catches a different wrong fix:
    /// *byte-identical concatenation* catches the split, and *every read
    /// makes progress* catches the pull-back that returns nothing — which
    /// at `max_bytes` 1, 2 and 3 is every read that starts on a lead
    /// byte, and would be GH #195's wedge through a third rule.
    #[test]
    fn paging_never_splits_a_utf8_character_at_any_max_bytes() {
        let p = processor();
        for max_bytes in [1usize, 2, 3, 5, 7, 64, 1000, 4096] {
            // Every read of a tiny page re-judges a whole lookahead
            // window, so the corpus is sized to the page: enough pages to
            // meet every alignment, few enough to stay fast.
            let text = multibyte_corpus(if max_bytes < 64 { 3 } else { 200 });
            let buf = text.as_bytes();
            // The fixture has to contain the shapes this is about, or it
            // proves nothing about them.
            assert!(text.chars().any(|c| c.len_utf8() == 2));
            assert!(text.chars().any(|c| c.len_utf8() == 3));
            assert!(text.chars().any(|c| c.len_utf8() == 4));
            let mut joined = String::new();
            let mut cursor = 0u64;
            let mut reads = 0usize;
            let mut split_seen = false;
            while cursor < buf.len() as u64 {
                reads += 1;
                assert!(
                    reads <= buf.len() + 1,
                    "max_bytes {max_bytes}: no termination"
                );
                let w = snapshot(&p, buf, cursor, max_bytes, true, false);
                // The fixture really does put a raw page end inside a
                // character at this size, or the row is vacuous for it.
                let cap = w.cap_end;
                if cap < buf.len() as u64 && (0x80..=0xbf).contains(&buf[cap as usize]) {
                    split_seen = true;
                }
                let r = p.process(&w, &ReadOptions::default());
                assert!(
                    r.cursor > cursor,
                    "max_bytes {max_bytes}: read {reads} from {cursor} made no progress"
                );
                assert!(
                    !r.output.contains('\u{fffd}'),
                    "max_bytes {max_bytes}: read {reads} from {cursor} split a character: {:?}",
                    r.output
                );
                joined.push_str(&r.output);
                cursor = r.cursor;
            }
            assert!(
                split_seen,
                "max_bytes {max_bytes}: no page end fell inside a character"
            );
            assert_eq!(
                joined, text,
                "max_bytes {max_bytes}: the pages do not rejoin"
            );
        }
    }

    /// The three arms of `utf8_read_end`, each pinned on its own, because
    /// the paging row above is satisfied by more than one of them at a
    /// time and a mutant that deletes one arm can hide behind another.
    #[test]
    fn a_split_character_is_pulled_back_pushed_forward_or_left_by_rule() {
        let p = processor();
        // "ab" then 日 (e6 97 a5), then "c".
        let buf = "ab日c".as_bytes();

        // Pulled back: a page ending one byte into the character stops
        // before it and returns what it can.
        let w = snapshot(&p, buf, 0, 3, true, false);
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(r.output, "ab");
        assert_eq!(r.cursor, 2, "the next read starts on the lead byte");
        assert_eq!(r.next_cursor, Some(2));
        assert!(r.truncated_for_size && !r.held_back);

        // Pushed forward: a page that *is* the front of the character
        // would return nothing if pulled back, so it finishes it.
        let w = snapshot(&p, buf, 2, 1, true, false);
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(r.output, "日");
        assert_eq!(r.bytes_returned, 3, "at most three bytes past max_bytes");
        assert_eq!(r.cursor, 5);

        // At `head`, with the child alive: the rest has not arrived, so
        // the page stops before it and `cursor` says where to resume.
        let partial = &buf[..4];
        let w = snapshot(&p, partial, 0, 4096, true, false);
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(r.output, "ab");
        assert_eq!(r.cursor, 2);
        assert!(!r.held_back, "less than one character is not a holdback");

        // …and with the child gone it never will arrive, so the bytes go
        // out as what they are rather than being stranded.
        let w = snapshot(&p, partial, 0, 4096, false, false);
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(r.cursor, 4, "a dead child's partial character is not held");
        assert!(r.output.starts_with("ab") && r.output.contains('\u{fffd}'));

        // A read that is *only* an unfinished character at `head` is left
        // alone even while the child lives, for the reason the escape
        // rule gives: withholding it would return the caller nothing.
        let w = snapshot(&p, partial, 2, 4096, true, false);
        let r = p.process(&w, &ReadOptions::default());
        assert_eq!(r.cursor, 4, "no zero-byte read at head");
    }

    // ------------------------------------ GH #243 / #242: every read shape

    /// A PTY's rendering of `cat <key>` in the middle of a session: the
    /// command, the key with `\r\n` line ends, and a later command.
    fn catted(pem: &str) -> String {
        format!(
            "$ cat id_key\r\n{}$ echo done\r\ndone\r\n$ ",
            pem.replace('\n', "\r\n")
        )
    }

    /// The offsets a `tail_lines` read of each size would start at — the
    /// byte after each `\n`, newest first — plus the buffer's start.
    fn line_starts(buf: &[u8]) -> Vec<u64> {
        let mut starts: Vec<u64> = std::iter::once(0)
            .chain(
                buf.iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'\n')
                    .map(|(i, _)| i as u64 + 1),
            )
            .filter(|s| (*s as usize) < buf.len())
            .collect();
        starts.reverse();
        starts
    }

    /// **No read shape returns key material, for any key format, whether
    /// the key is complete or cut short** (GH #243, GH #242).
    ///
    /// #223 masked a key for a read that starts *before* its header. A
    /// read that starts *inside* it never saw the header, so nothing
    /// marked the body: on `main` at `a81b02d` a `tail_lines` read of a
    /// complete 4096-bit key returned most of its body raw with
    /// `redactions: {}`, and so did `tail_bytes` and a cursor partway in.
    /// Every such shape is driven here, at every line and at a spread of
    /// byte offsets, against every fixture format:
    ///
    /// * `tail_lines` of every size, which is a read starting after each
    ///   `\n`;
    /// * `tail_bytes` at every size up to the whole buffer, in steps;
    /// * a cursor read starting at every such offset, at the default
    ///   `max_bytes` and at a small one, so both the at-`head` branch and
    ///   the truncated one run.
    ///
    /// The shapes are `pem::fixtures::Key::shapes`. `head -n 9` followed
    /// by a prompt is the case that is neither closed nor in flight, and
    /// that GH #242's narrowing would release if dying released. The five
    /// after it are the independent review's: key body arriving *after*
    /// the candidate stopped — a pager's next screenful, `sed` in chunks,
    /// and three decorated keys a pager cut off — each of which the
    /// narrowing released raw and `a81b02d` masked.
    ///
    /// **Paired** with what must survive, on the whole-buffer read: the
    /// commands around every shape, which is what GH #242 was for.
    #[test]
    fn no_read_shape_returns_key_material_for_any_key_format() {
        let p = processor();
        let o = ReadOptions::default();
        let mut reads = 0usize;
        for key in pem::fixtures::KEYS {
            for shape in key.shapes() {
                let (name, buf) = (shape.name, shape.text.as_bytes());
                let head = buf.len() as u64;
                // Control: the whole-buffer read masks it, so a leak below
                // is the read shape's and not the fixture's.
                let whole = p.process(&snapshot(&p, buf, 0, 1 << 20, true, false), &o);
                assert_eq!(key.leaked_in(&whole.output), None, "{} {name}", key.name);
                for kept in &shape.kept {
                    assert!(
                        whole.output.contains(kept.as_str()),
                        "{} {name}: {kept:?} was masked with the key: {:?}",
                        key.name,
                        whole.output
                    );
                }

                let mut starts = line_starts(buf);
                starts.extend((0..head).step_by(53));
                for start in starts {
                    for (max_bytes, bypass) in [(32 * 1024, true), (32 * 1024, false), (256, false)]
                    {
                        reads += 1;
                        let w = snapshot(&p, buf, start, max_bytes, true, bypass);
                        let r = p.process(&w, &o);
                        assert_eq!(
                            key.leaked_in(&r.output),
                            None,
                            "{} ({name}): a read from {start} of {head} at max_bytes \
                             {max_bytes} returned key material: {:?} redactions {:?}",
                            key.name,
                            r.output,
                            r.redactions
                        );
                        // A complete key the rule matched keeps the rule's
                        // name from inside it too — `unresolved` is for a
                        // region nothing matched, and this one did.
                        if shape.complete && r.output.contains("[REDACTED:") {
                            assert!(
                                r.redactions.contains_key("private-key"),
                                "{} ({name}) from {start}: {:?}",
                                key.name,
                                r.redactions
                            );
                        }
                    }
                }
            }
        }
        assert!(reads > 1000, "the sweep shrank to {reads} reads");
    }

    /// **A PEM block that is not a private key is never masked**, from
    /// any read position — a certificate, a public key, EC parameters, a
    /// CSR. Each opens `-----BEGIN` and carries a base64 body the PEM walk
    /// believes; what keeps them out is the rule's own automaton dying on
    /// the label, and without that the walk would mask every certificate
    /// chain a TLS tool prints as "a key that died with material".
    #[test]
    fn a_pem_block_that_is_not_a_private_key_is_never_masked() {
        let p = processor();
        let o = ReadOptions::default();
        let body: String = pem::fixtures::KEYS[1]
            .material_lines()
            .iter()
            .map(|l| format!("{l}\r\n"))
            .collect();
        for label in [
            "CERTIFICATE",
            "PUBLIC KEY",
            "RSA PUBLIC KEY",
            "EC PARAMETERS",
            "CERTIFICATE REQUEST",
        ] {
            let text = format!(
                "$ cat f.pem\r\n-----BEGIN {label}-----\r\n{body}-----END {label}-----\r\n$ "
            );
            let cut = format!(
                "$ head f.pem\r\n-----BEGIN {label}-----\r\n{}$ ",
                &body[..700]
            );
            for text in [text, cut] {
                let buf = text.as_bytes();
                for start in (0..buf.len() as u64).step_by(97) {
                    let r = p.process(&snapshot(&p, buf, start, 32 * 1024, true, false), &o);
                    assert!(
                        r.redactions.is_empty(),
                        "{label} from {start}: {:?}",
                        r.redactions
                    );
                    assert_eq!(
                        r.output.as_bytes(),
                        &buf[start as usize..],
                        "{label} from {start}"
                    );
                }
            }
        }
    }

    /// **A candidate that died is believed over the carry and no further**,
    /// the same bound a candidate still arriving gets (GH #242). Without
    /// the cap a PEM-shaped blob of any length followed by a prompt would
    /// be masked whole by a read that starts before it, while a read that
    /// starts past the carry — which cannot see the anchor — releases the
    /// same bytes; the two reads would disagree about one region by a
    /// distance the child chooses. The residual is asserted, as the
    /// in-flight one is in
    /// `a_private_key_longer_than_the_lookahead_window_is_never_emitted_raw`.
    #[test]
    fn a_dead_candidate_is_believed_for_the_carry_and_no_further() {
        let carry = UNVOUCHED_CARRY_BYTES as u64;
        let (pem, _) = pem_longer_than(40 * 1024);
        let prologue = "$ cat blob\n";
        let buf = format!("{prologue}{}\n$ echo done\n", &pem[..pem.len() - 30]).into_bytes();
        let anchor = prologue.len() as u64;
        let line_at = |i: usize| anchor + 32 + 65 * i as u64;
        let r = read(&buf, 0, 256 * 1024);
        for i in (0..600).take_while(|i| line_at(*i) + 65 <= anchor + carry) {
            assert!(
                !r.output.contains(&format!("KEYBODY{i:06}")),
                "line {i} is inside the carry"
            );
        }
        let past = (0..600).find(|i| line_at(*i) > anchor + carry).unwrap();
        assert!(
            r.output.contains(&format!("KEYBODY{past:06}")),
            "the residual moved: a dead candidate past {carry} bytes is not believed"
        );
        assert!(r.output.ends_with("$ echo done\n"));
    }

    /// The paired direction for the row above: the reads that must *not*
    /// be masked still are not. Without this the sweep passes against a
    /// processor that masks every read carrying a `-----BEGIN` in its
    /// carry region, which would be GH #242 back at full size.
    #[test]
    fn output_after_a_key_is_not_masked_on_its_account() {
        let p = processor();
        let o = ReadOptions::default();
        for key in pem::fixtures::KEYS {
            let pem = key.pem();
            let cut: String = pem.lines().take(9).map(|l| format!("{l}\n")).collect();
            for (shape, text) in [("complete", catted(&pem)), ("head -n 9", catted(&cut))] {
                let buf = text.as_bytes();
                let done = text.rfind("$ echo done").unwrap() as u64;
                // A read that starts at the next command sees it verbatim,
                // though the key is well inside its carry region.
                let r = p.process(&snapshot(&p, buf, done, 32 * 1024, true, false), &o);
                assert_eq!(
                    r.output, "$ echo done\r\ndone\r\n$ ",
                    "{} {shape}",
                    key.name
                );
                assert!(
                    r.redactions.is_empty(),
                    "{} {shape}: {:?}",
                    key.name,
                    r.redactions
                );
                // And the whole-buffer read masks the key and nothing else.
                let r = p.process(&snapshot(&p, buf, 0, 1 << 20, true, false), &o);
                assert!(
                    r.output.starts_with("$ cat id_key\r\n[REDACTED:"),
                    "{}",
                    r.output
                );
                assert!(
                    r.output.ends_with("$ echo done\r\ndone\r\n$ "),
                    "{} {shape}: {:?}",
                    key.name,
                    r.output
                );
            }
        }
    }

    /// **After a key header, what is masked is key body and nothing else**
    /// — the cost side of following a stopped candidate's body lines
    /// (`pem::body_lines`), measured on the lines likeliest to follow one.
    ///
    /// * After a **complete** key nothing is followed: its candidate
    ///   closed, and the rule's own match is the whole of its mask. A
    ///   SHA-256 digest on the next line comes back.
    /// * After a key **cut short**, or a header in **prose**, a git object
    ///   id (40 hex) and ordinary output come back; a line carrying a run
    ///   of [`pem::KEY_LINE_RUN`] — here a SHA-256 digest — is masked,
    ///   which is the stated cost; and past `UNVOUCHED_CARRY_BYTES` from
    ///   the header even that comes back.
    #[test]
    fn after_a_key_header_only_key_body_lines_are_masked() {
        let p = processor();
        let o = ReadOptions::default();
        let key = &pem::fixtures::KEYS[0];
        let pem = key.pem();
        let cut: String = pem.lines().take(9).map(|l| format!("{l}\n")).collect();
        let sha1 = "a81b02d3c4e5f60718293a4b5c6d7e8f90a1b2c3";
        let sha256 = "66786b9abe23920d022a182d1416b1bbc8130dd4872a9553d76985a1708dcd1e";
        let after =
            format!("$ git log -1 --format=%H\r\n{sha1}\r\n$ sha256sum f\r\n{sha256}  f\r\n$ ");
        for (shape, text, digest_masked) in [
            ("complete", catted(&pem), false),
            ("head -n 9", catted(&cut), true),
            (
                "prose",
                "$ grep -n BEGIN CHANGELOG.md\r\n12: `-----BEGIN RSA PRIVATE KEY-----` as prose\r\n$ "
                    .to_string(),
                true,
            ),
        ] {
            let buf = format!("{text}{after}");
            let r = p.process(&snapshot(&p, buf.as_bytes(), 0, 1 << 20, true, false), &o);
            assert_eq!(key.leaked_in(&r.output), None, "{shape}");
            assert!(r.output.contains(sha1), "{shape}: {:?}", r.output);
            assert!(r.output.contains("$ sha256sum f"), "{shape}: {:?}", r.output);
            assert_eq!(
                !r.output.contains(sha256),
                digest_masked,
                "{shape}: {:?}",
                r.output
            );
        }

        // Past the carry, the prose header's reach has ended.
        let pad: String = (0..UNVOUCHED_CARRY_BYTES / 40)
            .map(|i| format!("ordinary line {i:024}\r\n"))
            .collect();
        let buf = format!("12: `-----BEGIN RSA PRIVATE KEY-----` as prose\r\n{pad}{after}");
        let r = p.process(&snapshot(&p, buf.as_bytes(), 0, 1 << 20, true, false), &o);
        assert!(r.output.contains(sha256), "the reach is the carry");
        assert!(r.redactions.is_empty(), "{:?}", r.redactions);
    }

    // ---------------------------------------- GH #247: erased redraws

    /// A terminal wide enough for every fixture line below: the width the
    /// dogfood pass's cargo measurement was taken at.
    const WIDE: u16 = 120;

    /// The bytes `cargo build` writes through a pty, in the shape measured
    /// on cargo 1.97 at 120 columns: each `Building` frame padded to the
    /// width and ended by `\r`, followed either by the next frame or by
    /// `\r\x1b[K` and a `Compiling` line, and the last frame erased before
    /// `Finished`.
    fn cargo_progress(crates: &[&str]) -> (String, Vec<String>) {
        const BOLD_GREEN: &str = "\x1b[1m\x1b[92m";
        const BOLD_CYAN: &str = "\x1b[1m\x1b[96m";
        const RESET: &str = "\x1b[0m";
        let total = crates.len() * 2;
        let frame = |n: usize, what: &str| {
            let bar = format!("[{:<28}]", "=".repeat(n * 28 / total) + ">");
            let text = format!(" {bar} {n}/{total}: {what}");
            format!("{BOLD_CYAN}    Building{RESET}{text:<100}\r")
        };
        let mut out = String::new();
        let mut shown = Vec::new();
        for (i, name) in crates.iter().enumerate() {
            let line = format!("   Compiling {name} v1.0.{i}");
            out.push_str(&format!(
                "{BOLD_GREEN}   Compiling{RESET} {name} v1.0.{i}\r\n"
            ));
            shown.push(line);
            out.push_str(&frame(2 * i, name));
            out.push_str(&frame(2 * i + 1, name));
            out.push_str("\x1b[K");
        }
        out.push_str(&frame(total - 1, "demo(bin)"));
        out.push_str(&format!(
            "\x1b[K{BOLD_GREEN}    Finished{RESET} `dev` profile in 8.47s\r\n"
        ));
        shown.push("    Finished `dev` profile in 8.47s".to_string());
        (out, shown)
    }

    /// **A build's progress bar costs the caller its last frame, not
    /// every frame** (GH #247).
    ///
    /// Measured on `main` at `a81b02d`: a nine-second `cargo build` read
    /// back as mostly `Building [...]` redraws, and a synthetic 400-step
    /// bar returned 32 KB of progress to a `tail_lines: 3` read because
    /// the redraws are one "line". A terminal shows none of those frames
    /// — each is returned to column 0 and wiped — so the stripped page
    /// now carries exactly what a terminal shows: every `Compiling` line,
    /// `Finished`, and nothing of the bar.
    ///
    /// **The cursor does not move for it.** The frames were read; they
    /// are only not shown. So `bytes_returned` and `cursor` are asserted
    /// to be the whole buffer, exactly as before.
    #[test]
    fn a_build_progress_bar_reads_back_as_what_a_terminal_shows() {
        let p = processor();
        let (text, shown) = cargo_progress(&["proc-macro2", "quote", "syn", "serde", "regex"]);
        let buf = text.as_bytes();
        let r = p.process_at_width(
            &snapshot(&p, buf, 0, 1 << 20, true, false),
            &ReadOptions::default(),
            Some(WIDE),
        );
        let expected: String = shown.iter().map(|l| format!("{l}\r\n")).collect();
        assert_eq!(r.output, expected);
        assert_eq!(r.cursor, buf.len() as u64);
        assert_eq!(r.bytes_returned, buf.len());
        assert!(!r.output.contains("Building"));

        // The synthetic one from the issue: 400 frames of `\r\x1b[K`
        // then text, and nothing after the last.
        let mut bar = String::new();
        for n in 1..=400 {
            bar.push_str(&format!(
                "\r\x1b[K Building [{}] {n}/400",
                "#".repeat(n / 10)
            ));
        }
        let r = p.process_at_width(
            &snapshot(&p, bar.as_bytes(), 0, 1 << 20, true, false),
            &ReadOptions::default(),
            Some(WIDE),
        );
        // The first `\r` stays: nothing printable is in front of it, so it
        // erased nothing, and the rule drops only what was erased.
        assert_eq!(
            r.output,
            format!("\r Building [{}] 400/400", "#".repeat(40))
        );

        // The second spelling: a redraw from column 0 that ends in an
        // erase-to-end, with no erase in front of it.
        let r = p.process_at_width(
            &snapshot(
                &p,
                b"a much longer old line\rnew\x1b[K\r\n",
                0,
                4096,
                true,
                false,
            ),
            &ReadOptions::default(),
            Some(WIDE),
        );
        assert_eq!(r.output, "new\r\n");

        // `ansi: raw` promises the bytes, and gets them.
        let raw = p.process_at_width(
            &snapshot(&p, buf, 0, 1 << 20, true, false),
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..ReadOptions::default()
            },
            Some(WIDE),
        );
        assert_eq!(raw.output, text);
    }

    /// **Nothing a terminal still shows is dropped** — the half that makes
    /// the row above safe to have. Each case is a `\r` that does *not*
    /// erase its line, and each comes back byte for byte.
    #[test]
    fn a_redraw_that_leaves_text_on_screen_is_not_collapsed() {
        let p = processor();
        for text in [
            // Shorter, no erase: the old tail is still visible.
            "downloading 100%\rdone\n",
            // A tab moves the cursor without writing; the old text under
            // the gap survives.
            "old text here\r\tnew\x1b[K\n",
            // Cursor movement inside the redraw.
            "0123456789\rab\x1b[3Ccd\x1b[K\n",
            // A screen switch between the `\r` and the erase: the erase
            // clears the alternate screen, and the main one keeps its line.
            "main screen text\r\x1b[?1049h\x1b[K\x1b[?1049l\n",
            // …or in front of the `\r`, which is the same thing earlier.
            "main screen text\x1b[?1049h\r\x1b[K\x1b[?1049l\n",
            // A cursor move in front of the `\r`: the erase clears the row
            // above, and this one keeps its text.
            "this row stays\x1b[A\r\x1b[Kthe row above\n",
            // Save and restore are escapes too.
            "kept\x1b7\r\x1b[K\x1b8\n",
            // A vertical tab moves down a row as a line feed does.
            "this row stays\x0b\r\x1b[Kthe row below\n",
            // Not finished inside the page: nothing is decided.
            "frame one\rframe two",
            // A `\r\n` is a line end and erases nothing.
            "line one\r\nline two\x1b[K\r\n",
            // bash's `\x1b[?2004l\r` before a command's output: nothing
            // printable precedes it, so there is nothing to erase.
            "$ ls\r\n\x1b[?2004l\rCargo.toml\r\n",
        ] {
            let r = p.process_at_width(
                &snapshot(&p, text.as_bytes(), 0, 1 << 20, true, false),
                &ReadOptions::default(),
                Some(WIDE),
            );
            assert_eq!(
                r.output,
                ansi::strip(text.as_bytes())
                    .iter()
                    .map(|b| *b as char)
                    .collect::<String>(),
                "{text:?}"
            );
        }
    }

    /// **A line that may have wrapped is not collapsed** (the independent
    /// review of GH #247). `\r` returns to column 0 of the *last* row a
    /// wrapped line reached and the erase clears that row alone, so the
    /// rows above it are still on screen. Each case is paired with the
    /// width at which the same bytes do collapse, so the rule is shown to
    /// turn on the width and not on the shape.
    #[test]
    fn a_line_that_may_have_wrapped_is_not_collapsed() {
        let p = processor();
        let read = |text: &str, cols: u16| {
            p.process_at_width(
                &snapshot(&p, text.as_bytes(), 0, 1 << 20, true, false),
                &ReadOptions::default(),
                Some(cols),
            )
            .output
        };
        let strip = |text: &str| String::from_utf8(ansi::strip(text.as_bytes())).unwrap();

        // The review's repro: 164 columns of text.
        let wide = format!("{}IMPORTANT-TAIL\r\x1b[Kdone-51\r\n", "W".repeat(150));
        assert_eq!(read(&wide, 80), strip(&wide));
        assert_eq!(read(&wide, 163), strip(&wide), "one column short");
        assert_eq!(read(&wide, 164), "done-51\r\n", "exactly the width");

        // Wide characters are counted as two columns: 30 of them are 60.
        let cjk = format!("{}\r\x1b[Kdone\r\n", "日本".repeat(15));
        assert_eq!(read(&cjk, 59), strip(&cjk));
        assert_eq!(read(&cjk, 60), "done\r\n");

        // A tab is a jump, not a wrap, and it is counted.
        let tabbed = "\t\t\tVISIBLE\r\x1b[Kdone\r\n";
        assert_eq!(read(tabbed, 30), strip(tabbed));
        assert_eq!(read(tabbed, 31), "done\r\n");

        // A line whose start column is not known — it began in front of
        // anything the window holds — is never collapsed, at any width.
        let mut long = "x".repeat(4000);
        long.push_str("\r\x1b[Kdone\r\n");
        let r = p.process_at_width(
            &snapshot(&p, long.as_bytes(), 2000, 1 << 20, true, false),
            &ReadOptions::default(),
            Some(u16::MAX),
        );
        assert!(r.output.starts_with("xxxx"), "{:?}", &r.output[..16]);
        // …and one whose start the window does hold is.
        let mut known = "x".repeat(4000);
        known.push_str("\r\nbar 1/9\r\x1b[Kdone\r\n");
        let at = known.find("bar").unwrap() as u64;
        let r = p.process_at_width(
            &snapshot(&p, known.as_bytes(), at, 1 << 20, true, false),
            &ReadOptions::default(),
            Some(80),
        );
        assert_eq!(r.output, "done\r\n");

        // No width, no collapse: `process` is the spelling for a caller
        // that cannot say.
        let bar = "bar 1/9\r\x1b[Kdone\r\n";
        let r = p.process(
            &snapshot(&p, bar.as_bytes(), 0, 1 << 20, true, false),
            &ReadOptions::default(),
        );
        assert_eq!(r.output, strip(bar));
    }

    /// **Every range the collapse drops wrote nothing a terminal still
    /// shows** — the property GH #247 is allowed on, checked against a
    /// terminal rather than argued.
    ///
    /// The oracle is the one `get_screen_state` masks keys with: replay the
    /// stream through `vt100` twice, once as written and once with every
    /// printable byte of the dropped ranges swapped for another, and
    /// compare the final screens. If a dropped byte is still visible the
    /// two differ. Streams are drawn at random from the pieces redraws are
    /// made of — text, `\r`, erase-in-line in all three spellings, SGR,
    /// line feeds, and the sequences that move the cursor or switch the
    /// screen, which is where both of this rule's review findings lived
    /// (`\x1b[?1049h`, `\x1b[A`). The screen is tall enough that nothing
    /// scrolls, so "still visible" means exactly that.
    ///
    /// **At two widths, and the narrow one is the third finding.** A
    /// 120-column terminal never wraps a line these pieces make, so a rule
    /// that ignored the width passed here while dropping the rows of a
    /// wrapped line a terminal still shows (150 `W`s and `\r\x1b[K` in an
    /// 80-column session). At 20 columns most lines wrap, and every one
    /// that does must be kept.
    ///
    /// **Paired**: the sweep must also have collapsed something at each
    /// width, and a stream the rule is for must collapse, or the property
    /// holds of a rule that drops nothing.
    #[test]
    fn nothing_a_collapse_drops_is_still_on_a_terminal() {
        struct Rng(u64);
        impl Rng {
            fn below(&mut self, n: usize) -> usize {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                (self.0 % n as u64) as usize
            }
        }
        // The ordinary pieces are repeated so that most streams contain
        // a collapsible redraw; the rest are the ones that break it.
        const PIECES: &[&str] = &[
            "alpha",
            "beta gamma",
            "x",
            "Building [==>  ] 3/9",
            "alpha",
            "beta gamma",
            "\r",
            "\r",
            "\r",
            "\r",
            "\r\x1b[K",
            "\r\x1b[K",
            "\x1b[K",
            "\x1b[K",
            "\x1b[0K",
            "\x1b[2K",
            "\x1b[1K",
            "\x1b[32m",
            "\x1b[0m",
            "\n",
            "\r\n",
            "\x1b[?1049h",
            "\x1b[?1049l",
            "\x1b[A",
            "\x1b[B",
            "\x1b[3C",
            "\x1b[2D",
            "\x1b[5G",
            "\x1b7",
            "\x1b8",
            "\x1bM",
            "\t",
            "\x08",
            "\x0b",
            "\x1b]0;title\x07",
            "\x1b[?25l",
            "日本",
        ];
        // Leaving the alternate screen at the end, so a line the stream
        // left on the main screen is on the screen compared.
        let screen = |bytes: &[u8], cols: u16| {
            let mut t = vt100::Parser::new(200, cols, 0);
            t.process(bytes);
            t.process(b"\x1b[?1049l");
            t.screen().clone()
        };
        // The arrangements the reviews found, first, because a random walk
        // reaches each of them too rarely to be the thing that pins it.
        let wrapped = format!("{}IMPORTANT-TAIL\r\x1b[Kdone\r\n", "W".repeat(150));
        let found: Vec<&str> = vec![
            "VISIBLE\r\x1b[?1049h\x1b[K",
            "VISIBLE\x1b[?1049h\r\x1b[K",
            "VISIBLE\x1b[A\r\x1b[K",
            "VISIBLE\x1b7\r\x1b[K\x1b8",
            "VISIBLE\x0b\r\x1b[K",
            &wrapped,
            "a line of twenty-five chars\r\x1b[K",
            "\t\t\tVISIBLE\r\x1b[K",
        ];
        let p = processor();
        for cols in [120u16, 20] {
            let mut rng = Rng(0x2545_f491_4f6c_dd1d);
            let mut collapsed = 0usize;
            for iter in 0..3000 + found.len() {
                let text: String = match found.get(iter) {
                    Some(found) => found.to_string(),
                    None => {
                        let n = 1 + rng.below(24);
                        (0..n).map(|_| PIECES[rng.below(PIECES.len())]).collect()
                    }
                };
                let buf = text.as_bytes();
                let w = snapshot(&p, buf, 0, 1 << 20, true, false);
                let erased = erased_redraws(&w, &[], buf.len() as u64, cols);
                if erased.is_empty() {
                    continue;
                }
                collapsed += 1;
                let mut swapped = buf.to_vec();
                let mut stripper = AnsiStripper::new();
                for (i, byte) in swapped.iter_mut().enumerate() {
                    let printed = stripper.feed(i as u64, *byte).is_some();
                    let inside = erased
                        .iter()
                        .any(|(s, e)| *s <= i as u64 && (i as u64) < *e);
                    if inside && printed && (0x20..=0x7e).contains(byte) {
                        *byte = if *byte == b'#' { b'%' } else { b'#' };
                    }
                }
                assert_eq!(
                    screen(buf, cols).contents(),
                    screen(&swapped, cols).contents(),
                    "iter {iter} at {cols} columns: a dropped range is still on screen: \
                 {text:?} dropped {erased:?}"
                );
            }
            assert!(
                collapsed > 100,
                "only {collapsed} streams collapsed anything at {cols} columns"
            );
        }
    }

    /// **Dropping a redraw never removes a marker, and never lets the text
    /// it joins carry a credential out** (GH #247's "must not change what
    /// redaction sees").
    ///
    /// Two arrangements. A secret *inside* an erased frame keeps its
    /// marker, because a frame a span touches is not dropped — the agent
    /// is told something was redacted there, which is what REQ-O-012's
    /// count says. And a value that only becomes a match *once* the frame
    /// is gone — a label on one line, an erased frame, the value on the
    /// next — is judged on the page the caller receives and replaced.
    #[test]
    fn collapsing_a_redraw_keeps_every_marker_and_hides_every_join() {
        let p = processor();
        let text = format!("progress {GITHUB}\r\x1b[Kdone\n");
        let r = p.process_at_width(
            &snapshot(&p, text.as_bytes(), 0, 1 << 20, true, false),
            &ReadOptions::default(),
            Some(WIDE),
        );
        assert_eq!(r.redactions.get("github"), Some(&1));
        assert_eq!(
            r.output, "progress [REDACTED:github]\rdone\n",
            "a frame a redaction touches is kept whole, text and marker"
        );

        // `PASSWORD=` then a frame of ` x` then the value, indented.
        // Uncollapsed, the value rule sees ` x` and nothing it can use;
        // collapsed, the value is on the line after the `=`, indented —
        // the one line break a label-keyed rule still crosses (GH #245:
        // how rustfmt and prettier wrap a long assignment).
        //
        // **Not `PASSWORD:`, which is what this arm used until GH #245.**
        // A `:` no longer crosses a line at all, so `PASSWORD:\n<value>`
        // is not a match collapsed or not (a documented limitation of the
        // rule, pinned in `tests/redaction_prose.rs`), and the arm was
        // asserting a join that could no longer form.
        let value = "hunter2hunter2hunter2";
        let text = format!("PASSWORD=\n x\r\x1b[K    {value}\n");
        let uncollapsed = p.process_at_width(
            &snapshot(&p, text.as_bytes(), 0, 1 << 20, true, false),
            &ReadOptions {
                ansi: AnsiMode::Raw,
                ..ReadOptions::default()
            },
            Some(WIDE),
        );
        assert!(
            uncollapsed.redactions.is_empty(),
            "the premise: no stream the old pipeline judged matches here: {:?}",
            uncollapsed.redactions
        );
        let r = p.process_at_width(
            &snapshot(&p, text.as_bytes(), 0, 1 << 20, true, false),
            &ReadOptions::default(),
            Some(WIDE),
        );
        assert!(
            !r.output.contains(value),
            "the join carried the value out: {:?}",
            r.output
        );
        assert!(!r.redactions.is_empty(), "{:?}", r.redactions);
    }
}
