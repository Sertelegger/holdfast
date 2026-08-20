//! The output processor: ANSI stripping, secret redaction, the targeted
//! holdback, and text encoding (spec §4.1, §9.2).
//!
//! The ring buffer stores **raw** bytes. Everything in this module runs on
//! *read*, over an expanded window `[req_start − lookbehind,
//! req_end + lookahead]`, so a secret that straddles a cursor boundary is
//! still redacted from both sides.

pub mod ansi;
pub mod encoding;
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
#[derive(Debug, Clone, Copy)]
pub enum ReadStart {
    /// Forward from an absolute offset.
    Cursor(u64),
    /// The last N bytes. Bypasses the holdback (§4.1).
    TailBytes(usize),
    /// The last N lines. Bypasses the holdback (§4.1).
    TailLines(usize),
}

impl ReadStart {
    /// Explicit recency requests trade the holdback for freshness.
    pub fn bypasses_holdback(&self) -> bool {
        matches!(self, Self::TailBytes(_) | Self::TailLines(_))
    }
}

/// A read request as the session sees it.
#[derive(Debug, Clone, Copy)]
pub struct ReadRequest {
    pub start: ReadStart,
    /// Raw-byte budget (§5.1): caps bytes read *from the ring buffer*,
    /// not the size of the encoded payload.
    ///
    /// It has exactly one documented overshoot: when the cap would fall
    /// inside a secret, the read consumes to the end of that secret so the
    /// continuation cursor lands past it and not inside it (see
    /// [`OutputProcessor::process`]). Those extra raw bytes are wholly
    /// inside the one marker the response already carries, so the returned
    /// payload is unchanged — only `bytes_returned` and `cursor` move.
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
    /// secret the cap landed inside, and only then.
    pub bytes_returned: usize,
    /// Absolute offset just past the bytes consumed.
    pub cursor: u64,
    pub truncated_at_tail: bool,
    pub truncated_for_size: bool,
    pub held_back: bool,
    pub next_cursor: Option<u64>,
    /// `kind -> count` for the redactions inside the returned range.
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
    pub fn holdback_boundary(&self, w: &WindowSnapshot<'_>, opts: &ReadOptions) -> u64 {
        if !opts.redact || w.bypass_holdback {
            return w.head;
        }
        self.index
            .earliest_partial(&self.rules, w.tail_region, w.tail_region_start)
            .unwrap_or(w.head)
    }

    /// Run the pipeline over a snapshot. Pure: no locks, no I/O.
    pub fn process(&self, w: &WindowSnapshot<'_>, opts: &ReadOptions) -> ProcessedRead {
        let window_end = w.window_start + w.window.len() as u64;
        let holdback = self.holdback_boundary(w, opts);
        // The size cap and the holdback both bound the read; whichever
        // bites first decides which flag the agent sees.
        let bound = w.cap_end.min(holdback);

        // Pre-pass: walk the window up to `bound` to find out whether the
        // read would end inside an unfinished escape sequence.
        let mut dropped_incomplete_escape = false;
        let mut safety_end = bound;
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
                if w.child_alive && seq_len <= self.limits.ansi_incomplete_max_bytes as u64 {
                    // The child may still finish it: withhold the tail.
                    safety_end = seq_start;
                } else {
                    // A dead child never will, and neither will one that
                    // has already exceeded the cap. Drop it; the stripper
                    // emits nothing for those bytes anyway.
                    dropped_incomplete_escape = true;
                }
            }
        }

        let spans = if opts.redact {
            redact::find_spans(&self.rules, w.window, w.window_start)
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
        // the class is noticing that the evidence ran out mid-candidate
        // and declining — `unresolved_from` reports the earliest offset
        // this window cannot vouch for, and the read stops there.
        //
        // Three conditions, each load-bearing:
        //
        // 1. **`opts.redact`** — the audited hatch disables the holdback
        //    with the redaction, and this is a holdback (§4.1).
        // 2. **`window_end < w.head`** — the window really was truncated.
        //    When it reaches `head` the redactor has seen every byte that
        //    exists, and the only in-flight question left is the one
        //    `holdback_boundary` already answers over the tail region.
        //    Applying this bound there too would decline the trailing
        //    partial word of every read — `buffer.head` lands mid-word
        //    constantly — and make `held_back` routine, which is the rev.
        //    10–14 failure the *targeted* holdback exists to avoid.
        // 3. **no span already covers it to the window's edge** — an
        //    unbounded *greedy* rule matches right up to the last byte of
        //    the window, so `render` emits one marker over the whole
        //    unjudgeable region and no raw byte escapes. Declining as well
        //    would trade a correct marker and full progress for a withhold
        //    that buys nothing.
        //
        // No marker is emitted, because nothing is consumed and there is
        // nothing to substitute; §4.1's `held_back` + `next_cursor` are
        // how the caller is told, exactly as for an in-flight secret. The
        // recourse is a larger `max_bytes` — `read_output` clamps to
        // `MAX_READ_MAX_BYTES`, which puts `head` back inside the window —
        // or a `tail_*` read, or the audited `redact: false`. The residual
        // is a secret longer than that ceiling plus the lookahead: it
        // stays withheld from cursor reads, which is the safe direction
        // and is what REQ-O-005 already licenses.
        if opts.redact && window_end < w.head {
            let unresolved = self
                .index
                .unresolved_from(&self.rules, w.window, w.window_start)
                .filter(|u| !spans.iter().any(|s| s.start <= *u && s.end >= window_end));
            if let Some(u) = unresolved {
                safety_end = safety_end.min(u);
            }
        }

        let mut read_end = safety_end.max(w.req_start).min(w.cap_end);
        let held_back = safety_end < w.cap_end;
        let truncated_for_size = w.front_clipped || (w.cap_end < w.head && w.cap_end <= safety_end);

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
        for span in &spans {
            if span.start < read_end && read_end < span.end {
                read_end = span.end;
            }
        }

        let (bytes, redactions) = self.render(w, &spans, read_end, opts);

        ProcessedRead {
            output: encoding::encode(&bytes, opts.text_encoding),
            bytes_returned: (read_end - w.req_start) as usize,
            cursor: read_end,
            truncated_at_tail: w.truncated_at_tail,
            truncated_for_size,
            held_back,
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
    fn render(
        &self,
        w: &WindowSnapshot<'_>,
        spans: &[Span],
        read_end: u64,
        opts: &ReadOptions,
    ) -> (Vec<u8>, BTreeMap<String, usize>) {
        let window_end = w.window_start + w.window.len() as u64;
        let mut out: Vec<u8> = Vec::new();
        let mut redactions: BTreeMap<String, usize> = BTreeMap::new();
        let mut stripper = AnsiStripper::new();
        let mut off = w.window_start;
        let mut next_span = 0usize;

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
                        let kind = &self.rules.rules[span.rule].kind;
                        out.extend_from_slice(redact::marker(kind).as_bytes());
                        *redactions.entry(kind.clone()).or_insert(0) += 1;
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
            if off >= w.req_start {
                if let Some(b) = emitted {
                    out.push(b);
                }
            }
            off += 1;
        }
        (out, redactions)
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
        WindowSnapshot {
            window: &buffer[window_start as usize..window_end as usize],
            window_start,
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
    /// evidence ran out mid-candidate and decline — which is what
    /// `PrefixIndex::unresolved_from` reports and what §4.1 promises
    /// everywhere else.
    #[test]
    fn a_private_key_longer_than_the_lookahead_window_is_never_emitted_raw() {
        let p = processor();
        let (pem, body) = pem_longer_than(64 * 1024);
        let prologue = "$ cat chain.pem\n";
        let buf = format!("{prologue}{pem}\n$ echo done\n").into_bytes();

        // `read_output`'s own default (`DEFAULT_READ_MAX_BYTES`), so this
        // is an ordinary call and not a cap contrived to split anything.
        const CAP: usize = 32 * 1024;
        assert!(
            CAP as u64 + p.limits.lookahead_bytes as u64 + 1 < buf.len() as u64,
            "the fixture must actually truncate the window, or it pins nothing"
        );

        let w = snapshot(&p, &buf, 0, CAP, true, false);
        let r = p.process(&w, &ReadOptions::default());

        // THE HARM, stated as bytes: no run of key body may appear in a
        // response §4.1 says is redacted. Sampled rather than swept —
        // the body is 64 KB and every 48-byte window of it is unique.
        for start in (0..body.len() - 48).step_by(251) {
            assert!(
                !r.output.contains(&body[start..start + 48]),
                "key body from offset {start} leaked"
            );
        }
        // …and the exact payload, because the absence check alone passes
        // against an implementation that returns nothing at all.
        assert_eq!(r.output, prologue);
        assert!(r.held_back, "the read stopped because it could not vouch");
        assert_eq!(r.next_cursor, Some(prologue.len() as u64));
        assert_eq!(r.bytes_returned, prologue.len());
        assert!(
            r.redactions.is_empty(),
            "nothing was substituted — the bytes were declined, not replaced: {:?}",
            r.redactions
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
        // THE HARM: the value's bytes, in a response §4.1 says is redacted.
        assert!(
            !r.output.contains("NOPREFIXSECRETBODY"),
            "a rule with no index entry leaked its value"
        );
        assert_eq!(r.output, prologue);
        assert!(r.held_back);
        assert_eq!(r.next_cursor, Some(prologue.len() as u64));

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
}
