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
//! caller ends up seeing", and two axes are known to remain open:
//!
//! * **The window is not the payload (GH #138).** Spans are found over
//!   `[window_start, window_end)` while `render` emits
//!   `[req_start, read_end)`, so a `\b` can be decided by a lookbehind
//!   byte the caller never receives.
//! * **The enumeration is 7-bit (GH #139).** These views come from
//!   [`AnsiStripper`]'s grammar, which opens a sequence only on `0x1b`, so
//!   an 8-bit C1 introducer survives every view and no view reassembles the
//!   token. `get_screen_state` can therefore redact a line `read_output`
//!   returns whole.
//!
//!   **The emulator does NOT interpret C1, and the difference decides the
//!   fix.** This paragraph said it did, GH #139 says it does, and both are
//!   wrong. `vte` 0.15.0 documents *"Only supports 7-bit codes"*; it routes
//!   `'\u{80}'..='\u{9f}'` to `Perform::execute` rather than to CSI entry,
//!   and `vt100` 0.16.2's `execute` falls through to `unhandled_control`,
//!   whose body is empty. So the emulator **drops** the byte — and dropping
//!   it is precisely what splices the token back together in the grid.
//!   A reader who takes the old sentence at face value writes a `c1_strip`
//!   filter that consumes the introducer *as a sequence*, which models a
//!   real 8-bit terminal but not this emulator, and so misses the very
//!   stream `get_screen_state` redacts — the oracle the issue proposes.
//!   Both filters are wanted; only one of them was implied.
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
//! * A view may **not** add a **withhold**. A withhold denies the caller
//!   bytes, and [`PrefixIndex::earliest_partial`] — the predicate behind
//!   every withhold — is load-bearing on exactly the control bytes a view
//!   deletes. Asked about a stripped view it strands ordinary output
//!   behind a `held_back` that never clears, so
//!   `OutputProcessor::holdback_boundary` reads the raw region alone.
//!   GH #142 carries the measurement and the residual that leaves open.
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

/// Which of the three non-raw streams a [`NormalView`] holds. Named so a
/// test can say *which* view it means and a debug dump is readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// `ansi: strip`, encoding that drops nothing.
    Stripped,
    /// `ansi: raw`, `text_encoding: lossy_printable`.
    Printable,
    /// `ansi: strip`, `text_encoding: lossy_printable`.
    StrippedPrintable,
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
/// the raw bytes. Colourised output returns one to three views.
///
/// **The stripper starts in `Ground` at `region[0]`**, exactly as
/// `render` does at `window_start`, so a view is byte-for-byte what that
/// same region would emit rather than an approximation of it. When the
/// region opens mid-sequence both make the same wrong guess and reach the
/// same bytes, which is the only property span mapping needs.
pub fn emitted_views(region: &[u8], region_start: u64) -> Vec<NormalView> {
    // The cheap question first: does any filter in the pipeline remove
    // anything at all here? `lossy_printable` drops a superset of what
    // the stripper drops as bare bytes — every C0 control except the
    // three layout bytes, plus DEL — so a `no` here is a `no` for all
    // three views, and it is the answer for almost every read.
    if !region.iter().any(|b| !lossy_printable_keeps(*b)) {
        return Vec::new();
    }
    let mut views = Vec::with_capacity(3);
    // Two of these can coincide — a region with a bare `\x08` and no
    // escape sequence reaches the same bytes under `Printable` and
    // `StrippedPrintable` — and the duplicate is dropped, so whichever is
    // built first survives. The one caller reads every view it is given
    // and cares only that the set of *streams* is right, not which name
    // carries one.
    for view in [View::Stripped, View::StrippedPrintable, View::Printable] {
        let built = build(view, region, region_start);
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

fn build(view: View, region: &[u8], region_start: u64) -> NormalView {
    let (strip, printable) = match view {
        View::Stripped => (true, false),
        View::Printable => (false, true),
        View::StrippedPrintable => (true, true),
    };
    let mut bytes = Vec::with_capacity(region.len());
    let mut offsets = Vec::with_capacity(region.len());
    let mut stripper = AnsiStripper::new();
    for (i, raw) in region.iter().enumerate() {
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

    /// The view is a subsequence: every byte it holds is the raw byte at
    /// the offset it reports, unchanged. `map_span` is only exact because
    /// of it, so it is asserted rather than assumed.
    #[test]
    fn every_view_byte_is_the_raw_byte_at_the_offset_it_reports() {
        let region = b"\x1b]0;title\x07plain\x08\x7f\x1b[1mbold\x1b[0m\ttail\n";
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
