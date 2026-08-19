//! Carry-buffer redaction for the `observer` role (§9.2, REQ-O-011a).
//!
//! **Why 0.0.3's `OutputProcessor::process` is not used.** That pipeline
//! takes a `WindowSnapshot` with absolute offsets, a `cap_end` and a
//! holdback boundary — a *cursor read* shape, where the bytes it declines
//! stay in the ring buffer and the caller comes back for them with a
//! `next_cursor`. A live stream arrives in chunks the daemon does not
//! choose, has no cursor, and a secret can straddle any two of them. The
//! straddle problem is solved a third time here because the shape
//! genuinely differs, and it is solved **on 0.0.3's own `pub`
//! primitives** — `find_spans`, `marker`, `PrefixIndex::earliest_partial`
//! — so the rule set cannot drift between the two surfaces.

use std::sync::Arc;

use crate::output::redact::{find_spans, marker};
use crate::output::{OutputProcessor, ProcessingLimits};

/// The pseudo-kind emitted for a match the window could not judge:
/// `[REDACTED:unresolved]` (§9.2, REQ-O-011a). **Reserved — no redaction
/// rule may take this name.** Every other marker names a rule that
/// *matched*; this one means the opposite, so the two facts need two
/// strings and the collision must be impossible rather than merely
/// unlikely.
///
/// **Imported, not declared here.** The constant is owned by
/// `crate::output`, where it backs `RuleError::ReservedKind` — the guard
/// in `RuleSet::compile` that rejects any rule declaring
/// `kind = "unresolved"`. It belongs with the loader that enforces the
/// reservation; this file is that constant's second consumer, not its
/// owner.
pub use crate::output::rules::UNRESOLVED_KIND;

/// The stream's unit (§9.2 *Subject 3*, REQ-O-011a). **Derived, not
/// chosen:** it is `ProcessingLimits::lookahead_bytes` (8192), which is
/// the window `read_output` already judges over, so `holdfast watch` is
/// never weaker than the tool it renders.
///
/// **A floor, not a proof.** `private-key-block` is unbounded by
/// construction (`[\s\S]*?` between two anchors), so no finite window is
/// provably sufficient and a larger number would not close the question.
/// What makes the residual acceptable *here* is that a stream's declined
/// bytes stay in the ring buffer and stay reachable through `read_output`
/// — which, by REQ-O-005, may withhold forever because the agent holds a
/// `next_cursor`. A stream has no `next_cursor` and cannot. So the stream
/// degrades to **less information** and never to **raw**.
///
/// Do not shrink this toward `partial_secret_scan_bytes` (512): that
/// bound was measured wrong against the shipped rule set, where the
/// smallest real PEM is ~1.7 KiB, so a 512-byte carry flushes the key
/// **body** and only then keeps looking. And do not delete the
/// withholding state it feeds on the grounds that 8 KiB covers every real
/// PEM — that is a proposal to flush a key body the moment somebody
/// prints one that does not.
pub const STREAM_CARRY_BYTES: usize = 8192;

/// How much of an unjudgeable region is kept in front of the sliding
/// window while withholding — and therefore how long the withholding
/// lasts before the opening prefix scrolls out and the stream resumes.
///
/// **`2 × STREAM_CARRY_BYTES`, and the factor is measured rather than
/// decorative.** §9.2's residual (a) is stated as *"up to
/// `2 × STREAM_CARRY_BYTES` of dropped output before the stream
/// recovers"*, and a window of exactly `STREAM_CARRY_BYTES` does not
/// produce that number: withholding begins when the carry has already
/// passed `STREAM_CARRY_BYTES`, so the opening prefix is a full window
/// behind the tail at that instant and the *next* feed drops it. The loss
/// would be ~1× and an unterminated `-----BEGIN RSA PRIVATE KEY-----`
/// would resume streaming its body after 8 KiB rather than 16 KiB.
///
/// The cost of the larger window is 16 KiB per `observer` connection and
/// nothing else; the benefit is that the residual matches the number the
/// requirement states. It cannot be made unbounded: a window that never
/// forgot its prefix would blacken an observer's stream for the rest of
/// the session on `-----BEGIN CERTIFICATE-----`, which matches the
/// prefix and can never match the pattern.
const WITHHOLD_WINDOW_BYTES: usize = 2 * STREAM_CARRY_BYTES;

/// Redacts a live byte stream for the `observer` role (§9.2).
///
/// Two carried regions, both bounded, both derived from
/// `ProcessingLimits`:
///
/// * **Lookbehind** — the last `lookbehind_bytes` (512) already emitted,
///   retained so a context-based rule (`DD_API_KEY=` then a hex value)
///   still matches when the identifier and the value land in different
///   chunks. Retained, not re-emitted.
/// * **Carry** — the trailing region that must not be emitted yet,
///   because `PrefixIndex::earliest_partial` says a secret is still
///   arriving in it. Bounded by [`STREAM_CARRY_BYTES`], and what happens
///   when it fills is *withholding*, not flushing.
///
/// **The unit is the carry window, and its size is part of this type's
/// contract.** A byte this redactor could not judge inside that window is
/// never emitted raw.
///
/// **Nothing is held back when nothing is arriving.** That is 0.0.3's
/// *targeted* holdback property (REQ-O-003) and it is the reason a watch
/// stream is not perceptibly laggy: `earliest_partial` returns `None` for
/// ordinary build output, so every byte is emitted immediately.
///
/// **One handle to the processor, not two to its parts.** REQ-O-006 makes
/// the prefix index "a function of the rule set, not a startup step", and
/// REQ-RTD-002 requires a future `holdfast redaction-rules update` to
/// replace rules and index "together or not at all, with no instant at
/// which one is new and the other stale". Two independent `Arc`s held for
/// a connection's lifetime are exactly a pair that can be swapped one at
/// a time; borrowing the daemon's `Arc<OutputProcessor>` makes the
/// invariant structural. Nothing changes in v0.1.0 — the rule set only
/// changes at startup — which is precisely why holding them apart would
/// never be noticed. (`OutputProcessor.index` is a **bare** `PrefixIndex`
/// and could not be cloned out of one anyway.)
///
/// **Two residuals, documented and not closed.** (a) A match longer than
/// roughly `2 × STREAM_CARRY_BYTES` scrolls its opening prefix out of the
/// sliding window, after which streaming resumes mid-body — the same
/// shape as REQ-O-011a's own *"a secret continuing above row 0 … is
/// outside the window"*. (b) `-----BEGIN CERTIFICATE-----` matches
/// `private-key-block`'s **prefix** and never its pattern, so a
/// certificate dump costs one `[REDACTED:unresolved]` and up to
/// `2 × STREAM_CARRY_BYTES` of dropped output before the stream recovers.
/// Neither licenses going back to flushing raw.
///
/// **A third residual belongs to the rule set rather than to this type,
/// and it is inherited rather than introduced.** A rule whose pattern
/// carries no literal prefix of at least `MIN_PREFIX_LEN` bytes gets no
/// entry in the prefix index, so `earliest_partial` never reports it as
/// in flight and nothing is ever held back for it. If such a rule's match
/// is longer than the window, it is emitted raw — the same hole a cursor
/// read has when a match runs past `lookahead_bytes`. This type does not
/// widen it and cannot close it; the fix is in the index.
pub struct StreamRedactor {
    /// `crate::output::OutputProcessor`. Its `rules` is an
    /// `Arc<RuleSet>`; its `index` is a **bare** `PrefixIndex`, so both
    /// are read through this one handle and neither is cloned out.
    processor: Arc<OutputProcessor>,
    limits: ProcessingLimits,
    /// Lookbehind and carry in one allocation: `buf[..split]` is the
    /// lookbehind (already emitted, retained for context) and
    /// `buf[split..]` is the carry (not emitted yet). Keeping them
    /// contiguous is what lets a single `find_spans` see a rule whose
    /// anchor landed in one chunk and whose value landed in the next.
    buf: Vec<u8>,
    split: usize,
    /// Absolute stream offset of `buf[0]`. The offsets 0.0.3's
    /// primitives speak are absolute, so the stream keeps a counter
    /// rather than translating at every call site.
    base: u64,
    /// True while the carry overflowed with a partial still open. In this
    /// state incoming bytes are dropped — not emitted, and not
    /// accumulated past [`STREAM_CARRY_BYTES`].
    withholding: bool,
}

impl std::fmt::Debug for StreamRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // **Never the buffer.** A `#[derive(Debug)]` here would put
        // carried, unjudged bytes — which is to say the candidate secret
        // itself — into the first `tracing` line anybody adds.
        f.debug_struct("StreamRedactor")
            .field("carried", &(self.buf.len() - self.split))
            .field("withholding", &self.withholding)
            .finish()
    }
}

impl StreamRedactor {
    pub fn new(processor: Arc<OutputProcessor>) -> Self {
        let limits = processor.limits;
        Self {
            processor,
            limits,
            buf: Vec::new(),
            split: 0,
            base: 0,
            withholding: false,
        }
    }

    /// Feed a chunk; return the bytes that may be emitted now, redacted.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.withholding {
            return self.feed_while_withholding(chunk);
        }
        self.buf.extend_from_slice(chunk);

        // `earliest_partial` requires its region's last byte to be the
        // last byte in the buffer, which is exactly what a stream's carry
        // is. The region is lookbehind **plus** carry rather than the
        // carry alone: a prefix that arrived with no value byte behind it
        // was released (a bare `ghp_` carries no secret material), and if
        // the value then arrives in the next chunk, only a region that
        // still contains the prefix can see the token in flight.
        let stream_end = self.base + self.buf.len() as u64;
        let carry_start = self.base + self.split as u64;
        let stop = self
            .processor
            .index
            .earliest_partial(&self.processor.rules, &self.buf, self.base)
            .unwrap_or(stream_end);
        // Clamped below by `carry_start`: a partial that opened inside
        // the already-emitted lookbehind cannot be un-emitted, and the
        // best that is left is to withhold its value bytes.
        let emit_end = stop.clamp(carry_start, stream_end);

        let spans = find_spans(&self.processor.rules, &self.buf, self.base);
        let mut out = self.render(&spans, emit_end);
        self.retire(emit_end);

        if self.buf.len() - self.split > STREAM_CARRY_BYTES {
            // §9.2's terminating rule: the marker **once**, the carried
            // bytes discarded, and withholding from here.
            out.extend_from_slice(marker(UNRESOLVED_KIND).as_bytes());
            self.enter_withholding();
        }
        out
    }

    /// Emit everything still carried, redacted as far as possible.
    ///
    /// Called when the session's stream ends — a session that dies
    /// mid-token must not silently swallow its last line.
    ///
    /// **While withholding this emits nothing, and in particular never
    /// the withheld bytes**: the `[REDACTED:unresolved]` marker was
    /// emitted at the instant the decision was taken, so the stream
    /// already says what happened. Treating the withholding state as an
    /// ordinary carry here is the same leak arriving through the exit
    /// path.
    ///
    /// The other direction is a stated residual: an *unfinished* partial
    /// that never overflowed the carry is emitted raw, because at end of
    /// stream it will never be judged and `ghp_abc` — a prefix that is
    /// not a secret — is the common case. What bounds it is
    /// [`STREAM_CARRY_BYTES`].
    pub fn flush(&mut self) -> Vec<u8> {
        if self.withholding {
            self.reset();
            return Vec::new();
        }
        let stream_end = self.base + self.buf.len() as u64;
        let spans = find_spans(&self.processor.rules, &self.buf, self.base);
        let out = self.render(&spans, stream_end);
        self.retire(stream_end);
        out
    }

    /// Bytes carried but not yet emitted. The allocation this type is
    /// allowed to hold is bounded by this plus the lookbehind.
    pub fn carried(&self) -> usize {
        self.buf.len() - self.split
    }

    pub fn is_withholding(&self) -> bool {
        self.withholding
    }

    fn feed_while_withholding(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        if self.buf.len() > WITHHOLD_WINDOW_BYTES {
            let cut = self.buf.len() - WITHHOLD_WINDOW_BYTES;
            self.buf.drain(..cut);
            self.base += cut as u64;
        }
        // **Withholding ends at the first feed with no partial open over
        // the sliding window** — either the match completed (and its
        // bytes are dropped, never emitted) or the opening prefix scrolled
        // out and nothing new is in flight. Without this clause
        // `-----BEGIN CERTIFICATE-----` blackens an observer's stream for
        // the rest of the session, which is safe and useless.
        if self
            .processor
            .index
            .earliest_partial(&self.processor.rules, &self.buf, self.base)
            .is_none()
        {
            self.withholding = false;
            // The withheld bytes become lookbehind rather than output, so
            // a rule spanning the boundary can still match what comes
            // next. They are never emitted: `render` only ever emits from
            // `split` onwards.
            self.split = self.buf.len();
            self.trim_lookbehind();
        }
        Vec::new()
    }

    /// Copy `buf[split..emit_end]` out, substituting a marker for every
    /// span that overlaps it.
    fn render(&self, spans: &[crate::output::redact::Span], emit_end: u64) -> Vec<u8> {
        let region_start = self.base + self.split as u64;
        if emit_end <= region_start {
            return Vec::new();
        }
        let at = |off: u64| (off - self.base) as usize;
        let mut out = Vec::with_capacity(at(emit_end) - at(region_start));
        let mut pos = region_start;
        // `merge_spans` hands these back sorted and non-overlapping, so
        // one forward pass suffices.
        for span in spans {
            if span.end <= region_start || span.start >= emit_end {
                continue;
            }
            let start = span.start.max(region_start);
            if start > pos {
                out.extend_from_slice(&self.buf[at(pos)..at(start)]);
            }
            // A span that opened inside the already-emitted lookbehind
            // gets **no** marker and still loses its bytes: the marker
            // would claim a substitution the reader never saw begin, and
            // emitting the tail raw would hand over the value half of a
            // token whose prefix already went out.
            if span.start >= region_start {
                let kind = &self.processor.rules.rules[span.rule].kind;
                out.extend_from_slice(marker(kind).as_bytes());
            }
            pos = pos.max(span.end.min(emit_end));
        }
        if pos < emit_end {
            out.extend_from_slice(&self.buf[at(pos)..at(emit_end)]);
        }
        out
    }

    /// Move the split forward to `emit_end` and drop everything that has
    /// fallen out of the lookbehind window.
    fn retire(&mut self, emit_end: u64) {
        self.split = ((emit_end - self.base) as usize).min(self.buf.len());
        self.trim_lookbehind();
    }

    fn trim_lookbehind(&mut self) {
        if self.split > self.limits.lookbehind_bytes {
            let cut = self.split - self.limits.lookbehind_bytes;
            self.buf.drain(..cut);
            self.base += cut as u64;
            self.split -= cut;
        }
    }

    fn enter_withholding(&mut self) {
        self.withholding = true;
        // The carry becomes a sliding window of the last
        // `STREAM_CARRY_BYTES`, and the lookbehind goes with it: what is
        // in front of the withheld region is no longer context for
        // anything that will be emitted.
        let keep = self.buf.len().min(WITHHOLD_WINDOW_BYTES);
        let cut = self.buf.len() - keep;
        self.buf.drain(..cut);
        self.base += cut as u64;
        self.split = 0;
    }

    fn reset(&mut self) {
        self.base += self.buf.len() as u64;
        self.buf.clear();
        self.split = 0;
        self.withholding = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Named **here** rather than at the top of the file: the type reads
    // `processor.rules` and `processor.index` through its one handle and
    // names neither as a type, so a file-level import would be an
    // `unused_imports` warning and `-D warnings` makes that fatal.
    use crate::audit::AuditLog;
    use crate::output::rules::{builtin_shared, RuleSet};

    fn redactor() -> StreamRedactor {
        let rules = builtin_shared();
        let audit = Arc::new(AuditLog::disabled(Arc::clone(&rules)));
        StreamRedactor::new(Arc::new(OutputProcessor::new(
            rules,
            audit,
            ProcessingLimits::default(),
        )))
    }

    const GH: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    fn pem(body_bytes: usize) -> Vec<u8> {
        let mut v = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        while v.len() < body_bytes {
            v.extend_from_slice(
                b"MIIEpAIBAAKCAQEA7uJ8xk3nQ2s5vT1wY0zL9pR4bN6cH8dF2gJ5kM7nP0qS3tU\n",
            );
        }
        v.extend_from_slice(b"-----END RSA PRIVATE KEY-----\n");
        v
    }

    #[test]
    fn unresolved_is_a_reserved_kind_that_no_rule_takes() {
        // §9.2(b): *"a rule named `unresolved` would collide with the one
        // string that must not name a rule."* Every other marker names a
        // rule that **matched**; this one means the opposite.
        let rs = RuleSet::builtin().expect("builtin rule set");
        // The guard against a vacuous `all()`. An empty rule set satisfies
        // the reservation without it holding.
        assert!(!rs.is_empty(), "the builtin rule set is empty");
        assert!(
            rs.rules.iter().all(|r| r.kind != UNRESOLVED_KIND),
            "a shipped rule took the reserved kind"
        );

        // The pairing that makes the string mean something. The real kind
        // is taken off the shipped set rather than hard-coded, so this
        // cannot drift away from it.
        assert_eq!(marker(UNRESOLVED_KIND), "[REDACTED:unresolved]");
        let real = &rs.rules[0].kind;
        assert_ne!(
            marker(real),
            marker(UNRESOLVED_KIND),
            "a real kind and the pseudo-kind produced the same marker"
        );
    }

    #[test]
    fn ordinary_output_is_never_held_back() {
        // REQ-O-003's *targeted* holdback, restated for the stream: a
        // blanket carry would make `holdfast watch` lag by a chunk.
        let mut r = redactor();
        let mut got = Vec::new();
        for line in 0..64 {
            got.extend(r.feed(format!("   Compiling widget v0.{line}.0\n").as_bytes()));
        }
        assert_eq!(
            r.carried(),
            0,
            "nothing is arriving, so nothing may be held"
        );
        assert!(got.ends_with(b"   Compiling widget v0.63.0\n"));
        assert!(!got.is_empty());
    }

    #[test]
    fn a_secret_split_across_two_chunks_is_still_redacted() {
        // The straddled-token bug, invisible to any single-chunk test.
        let mut r = redactor();
        let (head, tail) = GH.split_at(10);
        let first = r.feed(head.as_bytes());
        assert!(
            first.is_empty(),
            "a token in flight was emitted before it could be judged: {:?}",
            String::from_utf8_lossy(&first)
        );
        let second = r.feed(format!("{tail}\n").as_bytes());
        let whole = String::from_utf8_lossy(&second).to_string();
        assert!(whole.contains("[REDACTED:github]"), "got {whole:?}");
        assert!(!whole.contains("ghp_"), "the token reached the stream");
    }

    #[test]
    fn a_bare_prefix_is_released_and_its_value_is_still_redacted() {
        // The nastier straddle: `ghp_` alone carries no secret material,
        // so `earliest_partial` releases it — and the value then arrives
        // in a region that no longer contains its own prefix. Scanning
        // the carry **alone** loses the token here and streams the value
        // raw. The prefix has already gone out and cannot be recalled;
        // what must not go out is the value.
        // **Three chunks, and the middle one is the whole point.** With
        // two, the token is complete by the second feed and `find_spans`
        // over lookbehind+carry covers the value whatever region the
        // partial scan used — so a two-chunk fixture passes against the
        // carry-only bug and proves nothing. The middle chunk is value
        // bytes with the token still *incomplete*: only a region that
        // still contains the prefix can see anything in flight there.
        let mut r = redactor();
        assert_eq!(r.feed(b"ghp_"), b"ghp_");

        let mid = &GH[4..24];
        let held = r.feed(mid.as_bytes());
        assert!(
            held.is_empty(),
            "value bytes of an incomplete token were streamed raw: {:?}",
            String::from_utf8_lossy(&held)
        );

        let out =
            String::from_utf8_lossy(&r.feed(format!("{}\n", &GH[24..]).as_bytes())).to_string();
        assert!(
            !out.contains(mid),
            "the value half of a straddled token was streamed raw: {out:?}"
        );
    }

    #[test]
    fn a_private_key_longer_than_the_old_carry_is_redacted_not_streamed() {
        // The size fixture a 512-byte carry could not judge: it flushes
        // the body at byte 512 and redacts nothing after it.
        // **Fed in pieces, and that is what makes the bound load-bearing.**
        // A whole PEM in one `feed` completes its match inside a single
        // window, so `earliest_partial` never reports a partial, nothing
        // is ever carried, and the size of the carry bound cannot matter:
        // measured, shrinking `STREAM_CARRY_BYTES` to 512 leaves a
        // single-chunk version of this row **green**. In pieces the
        // partial stays open across chunks and the carry has to hold ~1.7
        // KiB, which a 512-byte bound cannot.
        let mut r = redactor();
        let key = pem(1700);
        let mut out = Vec::new();
        for piece in key.chunks(256) {
            out.extend(r.feed(piece));
        }
        let out = String::from_utf8_lossy(&out).to_string();
        assert!(out.contains("[REDACTED:private-key]"), "got {out:?}");
        let body = &key[40..key.len() - 40];
        for w in body.windows(16).step_by(37) {
            assert!(
                !out.contains(&String::from_utf8_lossy(w).to_string()),
                "16 bytes of the key body reached the stream"
            );
        }
    }

    #[test]
    fn an_unterminated_key_block_is_withheld_not_flushed_raw() {
        // `-----BEGIN` opens a partial that `[\s\S]*?` can never close on
        // its own, so this is the case the carry bound exists for. The
        // inverted form of this row — asserting that the emitted count
        // tracks the written count — pinned a key body reaching an
        // observer as *correct*.
        //
        // **The plan's row asserts "no 32-byte run of the body" over a
        // whole megabyte, and that is not achievable beside its own
        // residual (a).** The two are the same input shape: after the
        // opening prefix scrolls out of the sliding window, an
        // unterminated `-----BEGIN RSA PRIVATE KEY-----` and a
        // `-----BEGIN CERTIFICATE-----` are indistinguishable — the regex
        // crate has no partial match, so nothing can tell "this will
        // complete" from "this never can". A rule that withheld the
        // megabyte would be the "withhold forever" that
        // `the_stream_recovers_after_a_withheld_block` exists to refuse.
        // So what is asserted here is the guarantee the design actually
        // makes — nothing raw while the window can judge — and the
        // residual is asserted below it as a *known limitation*, in the
        // shape §9.2 states it.
        let mut r = redactor();
        let mut out = r.feed(b"-----BEGIN RSA PRIVATE KEY-----\n");
        let body = b"MIIEpAIBAAKCAQEA7uJ8xk3nQ2s5vT1wY0zL9pR4bN6cH8dF2gJ5kM7nP0qS3tU\n";
        let mut written = 0usize;
        while written < WITHHOLD_WINDOW_BYTES {
            out.extend(r.feed(body));
            written += body.len();
        }
        let text = String::from_utf8_lossy(&out).to_string();

        assert_eq!(
            text.matches("[REDACTED:unresolved]").count(),
            1,
            "the marker is emitted once, not once per chunk"
        );
        assert!(
            !out.windows(32).any(|w| w == &body[..32]),
            "32 bytes of the withheld body reached the stream inside the \
             window that could judge it"
        );
        // **The overflow transition releases nothing, and this is the
        // assertion that says so rather than implying it.** The competing
        // diagnosis of this row's original failure was that `feed` let
        // the carry go out *before* setting `withholding` — a control
        // whose repair path runs before its assertion. That would put
        // body bytes ahead of the marker in the stream. It does not: the
        // marker is the whole of the output, so the carried region was
        // discarded and not emitted. The real cause was the withholding
        // state's **exit** condition, asserted as a residual below.
        assert_eq!(
            text, "[REDACTED:unresolved]",
            "the marker must be the only thing emitted while the window \
             can still judge the region"
        );
        // The allocation stays bounded: the body does not become carry.
        assert!(
            r.carried() <= WITHHOLD_WINDOW_BYTES,
            "carried {} bytes",
            r.carried()
        );

        // **The documented limitation, asserted rather than assumed.**
        // §9.2's residual (a): a match longer than roughly
        // `2 × STREAM_CARRY_BYTES` scrolls its opening prefix out of the
        // sliding window, after which streaming resumes mid-body. If this
        // assertion ever changes, §9.2's residual (a) and
        // `WITHHOLD_WINDOW_BYTES` change with it.
        let mut later = Vec::new();
        for _ in 0..512 {
            later.extend(r.feed(body));
        }
        assert!(
            later.windows(32).any(|w| w == &body[..32]),
            "the stream never recovered — which is safer, but then \
             `the_stream_recovers_after_a_withheld_block` is unreachable \
             and §9.2's residual (a) is wrong"
        );
    }

    #[test]
    fn the_stream_recovers_after_a_withheld_block() {
        // The negative that stops "withhold forever" passing the row
        // above. `-----BEGIN CERTIFICATE-----` matches `private-key-block`'s
        // **prefix** and never its pattern, so it can never complete.
        //
        // **The plan's fixture for this row is 2 KiB of body, and that is
        // measured wrong against its own residual (a):** recovery happens
        // when the opening prefix scrolls out of a sliding window of
        // `STREAM_CARRY_BYTES`, which needs more than 8192 bytes behind
        // it, not 2048. The assertion is therefore the residual's own
        // bound — within `2 × STREAM_CARRY_BYTES` — rather than a smaller
        // number the design cannot meet.
        let mut r = redactor();
        let mut out = r.feed(b"-----BEGIN CERTIFICATE-----\n");
        let chunk = vec![b'Q'; 256];
        let mut written = 0usize;
        while written < WITHHOLD_WINDOW_BYTES + STREAM_CARRY_BYTES {
            out.extend(r.feed(&chunk));
            written += chunk.len();
        }
        out.extend(r.feed(b"RECOVERED\n"));
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(
            text.contains("RECOVERED"),
            "the withholding state had no exit condition"
        );
        assert!(
            !r.is_withholding(),
            "still withholding after the prefix scrolled out"
        );
    }

    #[test]
    fn the_carry_is_flushed_at_end_of_stream() {
        // A partial that never completes, and is not a secret. A `flush`
        // that never runs leaves the client on a truncated last line
        // forever.
        let mut r = redactor();
        assert!(r.feed(b"ghp_abc").is_empty(), "an open partial is held");
        assert_eq!(r.flush(), b"ghp_abc");
        assert_eq!(r.carried(), 0);
    }

    #[test]
    fn flushing_while_withholding_emits_no_withheld_bytes() {
        // The pairing for the row above, and the leak it stops is the
        // same one arriving through the exit path: a `flush` that treats
        // the withholding state as an ordinary carry dumps the key body.
        let mut r = redactor();
        let mut out = r.feed(b"-----BEGIN RSA PRIVATE KEY-----\n");
        let body = vec![b'K'; STREAM_CARRY_BYTES * 2];
        out.extend(r.feed(&body));
        assert!(r.is_withholding(), "the fixture must reach the carry bound");
        let tail = r.flush();
        assert!(
            tail.is_empty(),
            "flush dumped {} withheld bytes",
            tail.len()
        );
        assert_eq!(
            String::from_utf8_lossy(&out)
                .matches("[REDACTED:unresolved]")
                .count(),
            1
        );
        assert!(!out.windows(64).any(|w| w.iter().all(|b| *b == b'K')));
    }
}
