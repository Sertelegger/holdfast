//! The byte streams a read can actually emit, each carrying the map back
//! to the raw buffer offsets it came from (GH #125).
//!
//! **The defect this module exists to close.** Redaction ran over
//! [`WindowSnapshot::window`] — the *raw* bytes — and [`AnsiStripper`] ran
//! afterwards, inside `render`. An escape sequence planted inside a
//! credential therefore broke the rule's literal anchor at match time and
//! was then *removed* before the bytes went out, so the read reassembled
//! the token and handed back a complete, valid credential with
//! `redactions: {}` and no audit entry. The same shape repeats one step
//! later at [`TextEncoding::LossyPrintable`], which drops the C0 controls
//! the stripper keeps (`\x08`, `\x7f`) after redaction has already run.
//!
//! **The property, stated as narrowly as it was actually proved.** Every
//! byte stream that `render` and [`encode`] can *derive from the matched
//! window* is matched before it is emitted. That is a closure over the
//! **filters this pipeline applies**; it is not a closure over "what the
//! caller ends up seeing". Two axes were open when this module landed and
//! are now closed; each closure is stated here because the *shape* of it is
//! what a later reader needs, not the fact of it.
//!
//! * **The window is not the payload (GH #138, closed).** Spans are found
//!   over `[window_start, window_end)` while `render` emits
//!   `[req_start, read_end)`, so a `\b` could be decided by a lookbehind
//!   byte the caller never receives. `OutputProcessor::process` now judges
//!   the emitted page as well as the window. The page pass adds **markers
//!   only** — `advance_past_straddled` runs a second time *after*
//!   `merge_spans`, because `merge_spans` joins spans that merely touch
//!   (`span.start <= last.end`), so a page span ending at `read_end` and a
//!   window span starting there become one span that does straddle. One
//!   call is not enough and the reason is not visible from the call site.
//! * **The enumeration is 7-bit (GH #139, closed).** These views come from
//!   [`AnsiStripper`]'s grammar, which opens a sequence only on `0x1b`, so
//!   an 8-bit C1 introducer used to survive every view and no view
//!   reassembled the token: `get_screen_state` could redact a line
//!   `read_output` returned whole. [`View`] now carries a C1 axis, and it
//!   carries **two** filters rather than one — [`C1::Drop`] and
//!   [`C1::Strip`] — for the reason below.
//!
//!   **The emulator does NOT interpret C1, and the difference decides the
//!   fix.** An earlier revision of this paragraph said it did, GH #139 says
//!   it does, and both are wrong. `vte` 0.15.0 documents *"Only supports
//!   7-bit codes"*; it routes
//!   `'\u{80}'..='\u{9f}'` to `Perform::execute` rather than to CSI entry,
//!   and `vt100` 0.16.2's `execute` falls through to `unhandled_control`,
//!   whose body is empty. So the emulator **drops** the byte — and dropping
//!   it is precisely what splices the token back together in the grid.
//!   A reader who takes the old sentence at face value writes only a
//!   `c1_strip` filter that consumes the introducer *as a sequence*, which
//!   models a real 8-bit terminal but not this emulator, and so misses the
//!   very stream `get_screen_state` redacts — the oracle the issue
//!   proposes. Both filters are wanted; only one of them was implied, which
//!   is why [`C1`] has two variants and the view table has four rows per
//!   pipeline filter rather than two.
//!
//! **What is still open is deliberately not listed here**, because a list
//! of open axes in a module header is what went stale twice already. Each
//! residual is documented where it is measured: GH #135's split-stream
//! residual in `StreamRedactor`'s header, the tail-anchor cost at
//! `TAIL_ANCHOR` in `tests/redaction_sweep.rs`, and what the withholding
//! side still leaves open for twelve rules — a credential still arriving
//! with an escape inside it — in `OutputProcessor::holdback_boundary`
//! and GH #160.
//!
//! An earlier revision of this module claimed the unqualified form —
//! *every byte stream a read can emit is matched before it is emitted* —
//! and review falsified it twice. The claim is worth stating only at the
//! width it is true: the next reader will check the sentence rather than
//! re-derive the class, which is how both of those were found.
//!
//! **Which view may decide what.** The two halves of the GH #125 fix are
//! deliberately not symmetric:
//!
//! * A view may add a **marker**. A marker is safe in every stream and
//!   costs the caller nothing it was entitled to, so
//!   [`OutputProcessor::all_spans`] reads every view.
//! * A view may add a **withhold** only for a rule whose holdback is
//!   provably bounded (GH #142). A withhold denies the caller bytes, and
//!   a raw one is safe because it is self-healing — the byte that kills a
//!   candidate that will never complete is the same byte the caller was
//!   waiting for. A view deletes exactly those bytes, so for a rule whose
//!   alive-and-unmatched continuations are infinite there may be no byte
//!   left that can ever end the withhold, and `\x1b]0;SECRET_DONE\x07`
//!   strands the caller for good. `PrefixIndex::build` decides which
//!   rules those are; twelve of the shipped fifty-one fail it and keep
//!   GH #142's residual, which GH #160 is about making audible.
//!
//! The pipeline is `render` (strip or pass through) then [`encode`], and
//! only two of its knobs drop bytes, so the set of derivable streams is
//! small and enumerable:
//!
//! | `ansi` | `text_encoding` | stream |
//! |--------|-----------------|--------|
//! | `Raw`  | `utf8`/`base64` | the raw window itself |
//! | `Raw`  | `lossy_printable` | [`View::Printable`] |
//! | `Strip`| `utf8`/`base64` | [`View::Stripped`] |
//! | `Strip`| `lossy_printable` | [`View::StrippedPrintable`] |
//!
//! `utf8` and `base64` share a row because neither removes a byte:
//! base64 re-encodes the stream reversibly and lossy UTF-8 substitutes
//! U+FFFD for an invalid byte, one replacement per byte, never joining
//! its neighbours.
//!
//! **The span set is deliberately option-independent.** A read scans
//! every view above, not the one its own `ansi`/`text_encoding` selects,
//! and three things fall out of that which are worth more than the
//! handful of passes it costs:
//!
//! 1. An agent cannot pick the mode that leaks. If the span set varied
//!    with the display knobs, `ansi: "raw"` would be a documented way to
//!    ask for the one representation in which a given token does not
//!    match.
//! 2. `ansi: "raw"` is not a raw-*display* escape hatch — `redact: false`
//!    is, and it is the audited one. Raw bytes carrying
//!    `ghp_…\x1b[0m…` still *render* as an intact credential in any
//!    terminal the agent pipes them to, so the escape being visible in
//!    the payload protects nobody.
//! 3. Cursor arithmetic stays the same for every caller. `process`
//!    advances `read_end` past a span the read would otherwise end
//!    inside, so an option-dependent span set would make
//!    `bytes_returned` and the continuation cursor depend on the display
//!    knobs, and two clients paging the same session with different
//!    encodings would disagree about where a page ends.
//!
//! **What the passes cost, measured rather than asserted.** Ordinary text
//! costs one scan of the region and no allocation — the guard at the top
//! of [`emitted_views`] returns nothing when no filter in the pipeline
//! would drop a byte, which is every read that carries no escape and no
//! bare control. Colourised output is the worst case, and
//! `streaming_ordinary_output_is_never_held_back` is a fair sample of it:
//! 1 MiB of build output with a `\x1b[32m` on every fourth line, read in
//! 33 pages of 32 KiB. Release, same machine, three runs each: **0.10 s
//! before, 0.11 s after**. It buys three regex passes where there was
//! one, and it is paid once per `read_output` call rather than once per
//! byte the child writes.
//!
//! An earlier revision of this fix read **0.15 s** on the same row,
//! because it also fed the in-flight detectors and so built every view
//! twice on each of the pages where `window_end < head` — which is every
//! page but the last. The views are built once now, by
//! [`OutputProcessor::all_spans`] and nowhere else, which is a
//! consequence of the marker/withhold rule above rather than an
//! optimisation in its own right.
//!
//! If it ever matters again, the saving to reach for first is deriving
//! [`View::StrippedPrintable`] by filtering [`View::Stripped`] instead of
//! walking the region through the stripper a second time, and skipping it
//! outright when that filter would drop nothing — which is the common
//! case, since a bare `\x08` in real output is rare.
//!
//! **What it costs, measured rather than waved at.** Redaction increases
//! on colourised output, and that is a user-visible payload change:
//!
//! ```text
//! \x1b[36mpassword\x1b[0m = \x1b[33mnot-set-yet\x1b[0m
//!   before   password = not-set-yet
//!   after    password = [REDACTED:generic]
//! ```
//!
//! The plain form was always redacted — `generic-secret-assignment`'s
//! value class is `[^\s"';,)]{8,}` and does not care what the value looks
//! like — so this is that rule reaching the stream it was always meant to
//! judge. It still means `grep --color` over a config returns markers
//! where it returned placeholders, which is a bread-and-butter agent
//! action and belongs in the changelog rather than in a reviewer's diff.
//!
//! One case adds a match no stream had *as plain bytes*: `ESC =` (DECKPAM)
//! is dropped by the printable filter and supplies the `[:=]` that
//! `generic-secret-assignment` needs, so `password\x1b=hunter2hunter2`
//! matches in [`View::Printable`] and nowhere else. A sweep of 16 escape
//! and C0 shapes against 5 labels and 2 value shapes found it to be the
//! only one. It stays: it is a real adjacency in a stream `ansi: "raw"`
//! plus `lossy_printable` really does emit, and under the rule above a
//! marker is the safe answer.
//!
//! **What a view is not.** It is a *subsequence* of the raw region: every
//! byte in it is a byte of the region, unchanged, in order. That is what
//! makes the offset map exact, and it is a property of the two filters
//! rather than an accident — [`AnsiStripper::feed`] returns the byte it
//! was given or nothing, and the `lossy_printable` filter keeps or drops.
//! Nothing here transcodes, so no view can invent a byte that a caller
//! could be handed and this module could not point at.
//!
//! [`WindowSnapshot::window`]: super::WindowSnapshot::window
//! [`AnsiStripper`]: super::ansi::AnsiStripper
//! [`AnsiStripper::feed`]: super::ansi::AnsiStripper::feed
//! [`TextEncoding::LossyPrintable`]: super::encoding::TextEncoding::LossyPrintable
//! [`encode`]: super::encoding::encode

use super::ansi::AnsiStripper;
use super::encoding::lossy_printable_keeps;
use super::redact::Span;

/// Which non-raw stream a [`NormalView`] holds. Named so a test can say
/// *which* view it means and a debug dump is readable.
///
/// The first three are the pipeline's own filters. The eight `C1` rows
/// are each of those (and the otherwise-unfiltered stream) composed with
/// a **consumer's** treatment of an 8-bit control — see [`C1`] and
/// [`c1_mask`] for why there are two such treatments and not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// `ansi: strip`, encoding that drops nothing.
    Stripped,
    /// `ansi: raw`, `text_encoding: lossy_printable`.
    Printable,
    /// `ansi: strip`, `text_encoding: lossy_printable`.
    StrippedPrintable,
    /// The bytes as emitted, read by something that drops C1.
    C1Dropped,
    /// The bytes as emitted, read by something that consumes C1
    /// sequences.
    C1Stripped,
    StrippedC1Dropped,
    StrippedC1Stripped,
    PrintableC1Dropped,
    PrintableC1Stripped,
    StrippedPrintableC1Dropped,
    StrippedPrintableC1Stripped,
}

/// What a consumer of the bytes we hand out does with an 8-bit C1
/// control, `0x80..=0x9f` (GH #139).
///
/// **Two answers, both real, and the difference decides whether a token
/// is reassembled.** `vte` 0.15.0 documents *"Only supports 7-bit
/// codes"*: it routes `'\u{80}'..='\u{9f}'` to `Perform::execute` rather
/// than to CSI entry, and `vt100` 0.16.2's `execute` falls through to
/// `unhandled_control`, whose body is empty. Holdfast's own emulator —
/// the one behind `get_screen_state` — therefore **drops** the byte,
/// which splices the bytes either side of it together in the grid. A
/// real 8-bit terminal instead **consumes** `0x9b` as CSI and `0x9d` as
/// OSC, taking the sequence's payload with it.
///
/// The two reach different streams from the same bytes —
/// `ghp_…\x9b…345` re-joins under [`C1::Drop`] and loses a character
/// under [`C1::Strip`], while `ghp_…\x9b0m…345` re-joins under
/// [`C1::Strip`] and keeps a visible `0m` under [`C1::Drop`] — so a
/// closure over "what a consumer can derive" needs both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C1 {
    /// Left in place: the 7-bit enumeration this module shipped with.
    Keep,
    /// Deleted one control at a time — Holdfast's own emulator.
    Drop,
    /// Consumed as a sequence introducer — a real 8-bit terminal.
    Strip,
}

/// `0x80..=0x9f`, the C1 range, whichever way it is spelled.
fn is_c1(b: u8) -> bool {
    (0x80..=0x9f).contains(&b)
}

/// One emitted byte stream, plus the raw offset each of its bytes came
/// from.
///
/// `offsets` is parallel to `bytes` and strictly increasing. It is
/// `u32` *relative to* `base` rather than absolute `u64`: a window is
/// bounded by `max_bytes` (256 KiB at `read_output`'s ceiling) plus the
/// lookahead, so four bytes per raw byte is never short, and eight would
/// double the only allocation on this path that scales with the window.
#[derive(Debug)]
pub struct NormalView {
    pub view: View,
    bytes: Vec<u8>,
    offsets: Vec<u32>,
    base: u64,
}

impl NormalView {
    /// The stream as a caller would receive it.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Absolute offset of the raw byte that produced `bytes()[i]`.
    pub fn raw_offset(&self, i: usize) -> u64 {
        self.base + self.offsets[i] as u64
    }

    /// Translate a span found *in this view* into raw buffer offsets.
    ///
    /// **The end is `raw_offset(end - 1) + 1`, not `raw_offset(end)`**,
    /// and the difference is the whole point of the map. The raw range
    /// between the match's first and last surviving bytes contains every
    /// byte the view dropped *inside* the match — the planted escape, the
    /// backspace — so one marker covers the credential and its
    /// obfuscation together. Reaching forward to the next surviving byte
    /// instead would swallow whatever separates the match from the text
    /// after it, and there may be no next byte at all when the match ends
    /// the view.
    ///
    /// Anything dropped *before* the first surviving byte or *after* the
    /// last one is outside the match in the view too, so it stays
    /// visible: a colour sequence that merely abuts a token is not part
    /// of it.
    ///
    /// # Panics
    ///
    /// On an empty or out-of-range span. Callers pass spans that
    /// [`find_spans`] produced from `bytes()`, which are non-empty and
    /// in range by construction.
    ///
    /// [`find_spans`]: super::redact::find_spans
    pub fn map_span(&self, span: Span) -> Span {
        let (start, end) = (span.start as usize, span.end as usize);
        assert!(
            start < end && end <= self.bytes.len(),
            "span {start}..{end} is not a match in a view of {} bytes",
            self.bytes.len()
        );
        Span {
            start: self.raw_offset(start),
            end: self.raw_offset(end - 1) + 1,
            rule: span.rule,
        }
    }
}

/// Every emittable stream of `region` that is **not** the raw bytes
/// themselves, with duplicates removed.
///
/// Ordinary output — text, `\n`, `\r`, `\t` — returns an empty vector and
/// costs one pass over the region, because no filter in the pipeline
/// would remove any of it and all four rows of the table collapse onto
/// the raw bytes. Colourised output returns between one and eleven,
/// depending on how many of the `VIEWS` rows reach distinct bytes.
///
/// **The stripper starts in `Ground` at `region[0]`**, exactly as
/// `render` does at `window_start`, so a view is byte-for-byte what that
/// same region would emit rather than an approximation of it. When the
/// region opens mid-sequence both make the same wrong guess and reach the
/// same bytes, which is the only property span mapping needs.
pub fn emitted_views(region: &[u8], region_start: u64) -> Vec<NormalView> {
    // The cheap question first: does any filter remove anything at all
    // here? `lossy_printable` drops a superset of what the stripper drops
    // as bare bytes — every C0 control except the three layout bytes,
    // plus DEL — so that half is a `no` for all three 7-bit views, and it
    // is the answer for almost every read.
    //
    // **The C1 clause is not redundant and its absence was GH #139.**
    // `lossy_printable_keeps(0x9b)` is `true` — it is above `0x20` and it
    // is not DEL — so a region whose only oddity is an 8-bit introducer
    // short-circuited here and no view was built at all, which is to say
    // the one region that most needs the new views was the one that
    // skipped them.
    let has_c1 = region.iter().any(|b| is_c1(*b));
    if !has_c1 && !region.iter().any(|b| !lossy_printable_keeps(*b)) {
        return Vec::new();
    }
    // One mask per C1 treatment, shared by the four filter pairs above
    // it, and allocated only when the region carries a C1 byte at all.
    let masks = has_c1.then(|| [c1_mask(region, C1::Drop), c1_mask(region, C1::Strip)]);
    let mut views = Vec::with_capacity(VIEWS.len());
    // Views can coincide — a region with a bare `\x08` and no escape
    // sequence reaches the same bytes under `Printable` and
    // `StrippedPrintable` — and the duplicate is dropped, so whichever is
    // built first survives. The one caller reads every view it is given
    // and cares only that the set of *streams* is right, not which name
    // carries one.
    for (view, strip, printable, c1) in VIEWS {
        let mask = match c1 {
            C1::Keep => None,
            C1::Drop => match &masks {
                Some([dropped, _]) => Some(dropped.as_slice()),
                None => continue,
            },
            C1::Strip => match &masks {
                Some([_, stripped]) => Some(stripped.as_slice()),
                None => continue,
            },
        };
        let built = build(*view, region, region_start, *strip, *printable, mask);
        // A view that dropped nothing *is* the raw region, which the
        // caller scans anyway; two views that dropped the same bytes are
        // the same stream, since a view is a subsequence and its offsets
        // therefore determine its bytes.
        if built.offsets.len() == region.len()
            || views
                .iter()
                .any(|prior: &NormalView| prior.offsets == built.offsets)
        {
            continue;
        }
        views.push(built);
    }
    views
}

/// The enumeration itself: every stream that is a *pipeline* filter
/// composed with a *consumer* filter, minus the raw region.
///
/// Ordered so the three 7-bit views are built first and therefore keep
/// their names when a C1 view reaches the same bytes, which is what makes
/// `views_that_reach_the_same_bytes_are_returned_once` stable.
#[allow(clippy::type_complexity)]
const VIEWS: &[(View, bool, bool, C1)] = &[
    (View::Stripped, true, false, C1::Keep),
    (View::StrippedPrintable, true, true, C1::Keep),
    (View::Printable, false, true, C1::Keep),
    (View::C1Dropped, false, false, C1::Drop),
    (View::StrippedC1Dropped, true, false, C1::Drop),
    (View::StrippedPrintableC1Dropped, true, true, C1::Drop),
    (View::PrintableC1Dropped, false, true, C1::Drop),
    (View::C1Stripped, false, false, C1::Strip),
    (View::StrippedC1Stripped, true, false, C1::Strip),
    (View::StrippedPrintableC1Stripped, true, true, C1::Strip),
    (View::PrintableC1Stripped, false, true, C1::Strip),
];

/// Which bytes of `region` survive a consumer's C1 treatment: `true`
/// keeps.
///
/// A mask rather than a filter in the byte loop because the two-byte
/// UTF-8 spelling of a C1 control — `0xc2` then `0x80..=0x9f`, which is
/// what a UTF-8 terminal actually decodes into one — is only recognised
/// at its *second* byte, and a one-in-one-out filter cannot un-emit the
/// first. Both spellings die together here, in one pass, so the rest of
/// `build` stays a subsequence walk.
///
/// [`C1::Strip`] consumes `0x9b` (CSI) through its final byte and the
/// string introducers `0x90`/`0x9d`/`0x9e`/`0x9f` (DCS, OSC, PM, APC)
/// through BEL, ST or `ESC \`. An unterminated sequence consumes the
/// rest of the region, which is the same guess `AnsiStripper` makes for
/// an unterminated 7-bit one.
fn c1_mask(region: &[u8], mode: C1) -> Vec<bool> {
    let mut keep = vec![true; region.len()];
    let mut i = 0;
    while i < region.len() {
        let (control, width) = match (region[i], region.get(i + 1)) {
            (0xc2, Some(&next)) if is_c1(next) => (next, 2),
            (b, _) if is_c1(b) => (b, 1),
            _ => {
                i += 1;
                continue;
            }
        };
        keep[i..i + width].fill(false);
        i += width;
        if mode == C1::Drop {
            continue;
        }
        match control {
            // CSI: parameters and intermediates, then one final byte.
            0x9b => {
                while i < region.len() {
                    let byte = region[i];
                    keep[i] = false;
                    i += 1;
                    if (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
            }
            // The string sequences, terminated by BEL, ST or `ESC \`.
            0x90 | 0x9d | 0x9e | 0x9f => {
                while i < region.len() {
                    let byte = region[i];
                    keep[i] = false;
                    i += 1;
                    if byte == 0x07 || byte == 0x9c {
                        break;
                    }
                    if byte == 0x1b && region.get(i) == Some(&b'\\') {
                        keep[i] = false;
                        i += 1;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    keep
}

fn build(
    view: View,
    region: &[u8],
    region_start: u64,
    strip: bool,
    printable: bool,
    c1_keeps: Option<&[bool]>,
) -> NormalView {
    let mut bytes = Vec::with_capacity(region.len());
    let mut offsets = Vec::with_capacity(region.len());
    let mut stripper = AnsiStripper::new();
    for (i, raw) in region.iter().enumerate() {
        // The consumer's filter runs first: an 8-bit introducer is a
        // control to the machine that removes it, and that machine sees
        // the bytes before any 7-bit stripper downstream of us does.
        if c1_keeps.is_some_and(|keeps| !keeps[i]) {
            continue;
        }
        let kept = if strip {
            stripper.feed(region_start + i as u64, *raw)
        } else {
            Some(*raw)
        };
        let Some(byte) = kept else { continue };
        if printable && !lossy_printable_keeps(byte) {
            continue;
        }
        bytes.push(byte);
        offsets.push(i as u32);
    }
    NormalView {
        view,
        bytes,
        offsets,
        base: region_start,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 40-character GitHub token, matched by the `github-token` rule.
    const GITHUB: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    fn view_bytes(region: &[u8], which: View) -> Option<String> {
        emitted_views(region, 0)
            .into_iter()
            .find(|v| v.view == which)
            .map(|v| String::from_utf8_lossy(v.bytes()).into_owned())
    }

    /// The common case, and the one the guard at the top of
    /// [`emitted_views`] exists for: plain text with layout bytes offers
    /// no view but the raw one, so a read pays one pass and no
    /// allocation.
    #[test]
    fn ordinary_output_has_no_view_but_the_raw_bytes() {
        assert!(emitted_views(b"one\r\n\ttwo\n", 0).is_empty());
        assert!(emitted_views(b"", 0).is_empty());
    }

    /// Each row of the module table, in a region that exercises all
    /// three filters at once: an escape sequence (stripper only), a
    /// backspace (`lossy_printable` only), and a DEL (likewise).
    #[test]
    fn the_three_views_drop_exactly_what_their_pipelines_drop() {
        let region = b"a\x1b[0mb\x08c\x7fd";
        assert_eq!(
            view_bytes(region, View::Stripped).as_deref(),
            Some("ab\x08c\x7fd"),
            "the stripper removes the sequence and keeps both C0 bytes"
        );
        assert_eq!(
            view_bytes(region, View::Printable).as_deref(),
            Some("a[0mbcd"),
            "without stripping the ESC goes but its parameters stay behind"
        );
        assert_eq!(
            view_bytes(region, View::StrippedPrintable).as_deref(),
            Some("abcd")
        );
    }

    /// Two views that drop the same bytes are one stream, and the raw
    /// region is never returned as a view. A region whose only oddity is
    /// a backspace collapses `Stripped` onto the raw bytes (the stripper
    /// keeps `\x08`) and `StrippedPrintable` onto `Printable`.
    #[test]
    fn views_that_reach_the_same_bytes_are_returned_once() {
        let views = emitted_views(b"a\x08b", 0);
        assert_eq!(
            views.iter().map(|v| v.view).collect::<Vec<_>>(),
            vec![View::StrippedPrintable],
            "one distinct non-raw stream exists here, not three"
        );
    }

    /// The map's contract: a span found in a view names the raw range
    /// from its first surviving byte through its last, which is what puts
    /// the planted escape *inside* the marker.
    #[test]
    fn a_mapped_span_covers_the_bytes_the_view_dropped_inside_it() {
        let region = format!("xx{}\x1b[0m{}yy", &GITHUB[..10], &GITHUB[10..]).into_bytes();
        let views = emitted_views(&region, 1000);
        let stripped = views.iter().find(|v| v.view == View::Stripped).unwrap();
        let text = stripped.bytes();
        let at = text
            .windows(GITHUB.len())
            .position(|w| w == GITHUB.as_bytes())
            .expect("the stripped view reassembles the token; that is the defect");
        let mapped = stripped.map_span(Span {
            start: at as u64,
            end: (at + GITHUB.len()) as u64,
            rule: 0,
        });
        assert_eq!(mapped.start, 1002, "two bytes of `xx` precede the token");
        assert_eq!(
            mapped.end,
            1000 + region.len() as u64 - 2,
            "the marker reaches the last token byte, and no further"
        );
        let covered = &region[(mapped.start - 1000) as usize..(mapped.end - 1000) as usize];
        assert!(
            covered.starts_with(b"ghp_") && covered.ends_with(b"012345"),
            "the raw range is the token and the escape between its halves"
        );
        assert!(
            covered.windows(2).any(|w| w == b"\x1b["),
            "the planted escape must be inside the span, not beside it"
        );
    }

    /// A sequence that merely *abuts* a token is not swallowed by its
    /// span — the map reaches the last surviving byte of the match and
    /// stops, so the colour reset after the token still reaches a raw
    /// reader.
    #[test]
    fn a_sequence_beside_a_match_stays_outside_its_span() {
        let region = format!("{GITHUB}\x1b[0m.").into_bytes();
        let views = emitted_views(&region, 0);
        let stripped = views.iter().find(|v| v.view == View::Stripped).unwrap();
        let mapped = stripped.map_span(Span {
            start: 0,
            end: GITHUB.len() as u64,
            rule: 0,
        });
        assert_eq!(mapped.end, GITHUB.len() as u64);
    }

    /// The **start** side of the map, which needs a dropped byte
    /// *immediately before* the match to mean anything.
    ///
    /// The row above has `xx` in front of its token, so a `map_span` that
    /// walked its start back over dropped bytes lands on the same offset
    /// and passes. Here the byte before the match is an OSC terminator
    /// the printable filter removes, so walking back swallows the whole
    /// window title — output loss rather than a leak, and invisible to
    /// every other row in the workspace.
    #[test]
    fn a_mapped_span_starts_at_its_first_surviving_byte_and_no_earlier() {
        let title = "\x1b]0;my window title\x07";
        let region = format!("{title}{GITHUB}\n").into_bytes();
        let printable = emitted_views(&region, 0)
            .into_iter()
            .find(|v| v.view == View::Printable)
            .expect("the printable view drops the ESC and the BEL");
        let text = printable.bytes();
        let at = text
            .windows(GITHUB.len())
            .position(|w| w == GITHUB.as_bytes())
            .expect("the token is intact in this view");
        let mapped = printable.map_span(Span {
            start: at as u64,
            end: (at + GITHUB.len()) as u64,
            rule: 0,
        });
        assert_eq!(
            mapped.start,
            title.len() as u64,
            "the span must begin at the token, not at the terminator before it"
        );
        assert_eq!(mapped.end, mapped.start + GITHUB.len() as u64);
    }

    /// **The whole of GH #139's correctness detail.**
    /// `lossy_printable_keeps(0x9b)` is `true`, so a region whose only
    /// oddity is an 8-bit introducer used to satisfy the cheap guard at
    /// the top of [`emitted_views`] and return *no views at all* — the
    /// region that most needs the C1 views was the one that skipped them.
    ///
    /// Asserted on the guard's own input shape (no ESC, no C0, no DEL)
    /// so it fails if the extra clause is dropped, whatever else changes.
    #[test]
    fn a_c1_introducer_does_not_short_circuit_the_guard() {
        // Built byte-wise: `\u{9b}` in a `str` literal is the *two-byte*
        // spelling, and the bare introducer is the shape the guard missed.
        let mut region = GITHUB.as_bytes()[..20].to_vec();
        region.push(0x9b);
        region.extend_from_slice(&GITHUB.as_bytes()[20..]);
        assert!(
            region.iter().all(|b| lossy_printable_keeps(*b)),
            "the fixture must contain nothing the 7-bit guard would catch"
        );
        let views = emitted_views(&region, 0);
        assert!(
            !views.is_empty(),
            "a region carrying a C1 byte offers views; the guard must not skip it"
        );
        assert!(
            views.iter().any(|v| v
                .bytes()
                .windows(GITHUB.len())
                .any(|w| w == GITHUB.as_bytes())),
            "one of those views reassembles the token; that is the defect"
        );
    }

    /// The two C1 treatments reach **different** streams from the same
    /// bytes, which is why both exist. `\x9b` alone is deleted by the
    /// emulator and rejoins the text; `\x9b0m` is a whole sequence to an
    /// 8-bit terminal and rejoins it there instead, while the emulator
    /// leaves its `0m` behind.
    #[test]
    fn the_two_c1_filters_reach_different_streams() {
        assert_eq!(
            view_bytes(b"a\x9b0mb", View::C1Dropped).as_deref(),
            Some("a0mb")
        );
        assert_eq!(
            view_bytes(b"a\x9b0mb", View::C1Stripped).as_deref(),
            Some("ab")
        );
        // The two-byte UTF-8 spelling is the same control, and both of
        // its bytes go.
        assert_eq!(
            view_bytes(b"a\xc2\x9b0mb", View::C1Dropped).as_deref(),
            Some("a0mb")
        );
        assert_eq!(
            view_bytes(b"a\xc2\x9b0mb", View::C1Stripped).as_deref(),
            Some("ab")
        );
        // An 8-bit OSC runs to its string terminator, not to a CSI final
        // byte.
        assert_eq!(
            view_bytes(b"a\x9d0;title\x07b", View::C1Stripped).as_deref(),
            Some("ab")
        );
    }

    /// A C1 view composes with the pipeline's own filters rather than
    /// replacing them: the region below needs the stripper *and* the
    /// emulator's C1 drop before the token is whole, and neither alone
    /// reaches it.
    #[test]
    fn a_c1_view_composes_with_the_pipelines_own_filters() {
        let mut region = format!("{}\x1b[0m{}", &GITHUB[..10], &GITHUB[10..20]).into_bytes();
        region.push(0x9b);
        region.extend_from_slice(&GITHUB.as_bytes()[20..]);
        let views = emitted_views(&region, 0);
        let whole: Vec<View> = views
            .iter()
            .filter(|v| {
                v.bytes()
                    .windows(GITHUB.len())
                    .any(|w| w == GITHUB.as_bytes())
            })
            .map(|v| v.view)
            .collect();
        assert!(
            whole.contains(&View::StrippedC1Dropped),
            "only the composed view reassembles this token, got {whole:?}"
        );
        assert!(
            !views
                .iter()
                .filter(|v| matches!(v.view, View::Stripped | View::C1Dropped))
                .any(|v| v
                    .bytes()
                    .windows(GITHUB.len())
                    .any(|w| w == GITHUB.as_bytes())),
            "neither filter alone should reach it, or the row proves nothing"
        );
    }

    /// The view is a subsequence: every byte it holds is the raw byte at
    /// the offset it reports, unchanged. `map_span` is only exact because
    /// of it, so it is asserted rather than assumed.
    #[test]
    fn every_view_byte_is_the_raw_byte_at_the_offset_it_reports() {
        let region = b"\x1b]0;title\x07plain\x08\x7f\x1b[1mbold\x1b[0m\x9b1K\xc2\x9dx\x07\ttail\n";
        for view in emitted_views(region, 7) {
            assert!(!view.bytes().is_empty(), "{:?} is empty", view.view);
            let mut previous: Option<u64> = None;
            for (i, byte) in view.bytes().iter().enumerate() {
                let off = view.raw_offset(i);
                assert_eq!(*byte, region[(off - 7) as usize], "{:?} at {i}", view.view);
                assert!(
                    previous.is_none_or(|p| p < off),
                    "{:?} offsets must strictly increase",
                    view.view
                );
                previous = Some(off);
            }
        }
    }
}
