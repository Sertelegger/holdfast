//! Every shipped rule's own fixtures, driven **through** the pipeline
//! rather than past it (GH #135, #138, #139).
//!
//! **The gap this target exists to close.** `rule.positive` is consumed
//! in exactly one place in the workspace — `output::rules`'s
//! `every_rule_matches_its_positives_and_rejects_its_negatives`, which
//! hands each fixture verbatim to `rule.regex.is_match`. That is a
//! *pattern* check: it proves the regex is the regex its author meant.
//! It never reaches `find_spans`, `all_spans`, `emitted_views`, `render`
//! or `process`, so it cannot see a fixture that the pattern matches and
//! the pipeline still hands out. Every leak in the #125 family had that
//! shape. This target is the *pipeline* check over the same fixtures.
//!
//! **The oracle, stated as the property and not as a list of cases:**
//! *no byte stream any consumer can derive from the bytes we handed out
//! matches a redaction rule.* A caller receives bytes; what it does with
//! them next is not ours to choose, so the check enumerates the
//! derivations a real consumer performs — a terminal (7-bit **and** 8-bit
//! grammar), Holdfast's own `vt100` emulator, and a printable filter —
//! and asks the rule set about each one. A match is only excused when it
//! lands inside a `[REDACTED:…]` marker this pipeline itself emitted,
//! because `secret_key = [REDACTED:generic]` really is a
//! `generic-secret-assignment` match and really is not a leak.
//!
//! **Why the assertions here are not vacuous.** Three controls, and a
//! change that deletes any of them has silently deleted the sweep:
//!
//! 1. [`the_sweep_detects_a_leak_when_redaction_is_off`] runs the same
//!    rows with `redact: false` and requires the oracle to report a leak
//!    for **every** one. An oracle that cannot see the unredacted
//!    pipeline cannot see a regression in the redacted one.
//! 2. Every row asserts the read actually **reached** its fixture
//!    (`cursor` past the planted payload). A read held back short of the
//!    secret emits nothing and would pass by absence.
//! 3. The negative fixtures run the same path as a measured-zero
//!    false-positive arm, so "redact everything" does not pass either.
//!
//! **Three axes, one table.** Fixtures × payloads × geometries ×
//! surfaces, with the payload planted **at the fixture's own matched
//! span** — computed with `find_spans`, so a value-group rule
//! (`DD_API_KEY=…`) gets it inside the value rather than in the label.
//!
//! * **payload** — the #125 filter axis (`\x1b[…m`, `\x08`, `\x7f`) and
//!   the #139 grammar axis (`\x9b`, `\x9b0m`, `\xc2\x9b`).
//! * **geometry** — the #138 range axis: `paged` puts the fixture behind
//!   a word-character prefix that lands in the lookbehind and not in the
//!   page, so a `\b` is decided by a byte the caller never receives.
//! * **surface** — `read_output` through `OutputProcessor::process` under
//!   four `ansi`/`text_encoding` pairs, and the `observer` stream through
//!   `StreamRedactor`.
//!
//! **What this target deliberately does not assert.** A credential split
//! across two *stream chunks* with an escape inside it is released up to
//! the escape — GH #142 at the `StreamRedactor` boundary, recorded in
//! that type's header. [`the_stream_residual_at_a_chunk_split_is_bounded`]
//! measures it rather than asserting it away, so the number moves when
//! somebody closes it instead of the test quietly encoding it as correct.

use std::sync::Arc;

use base64::Engine as _;
use holdfast_core::attach::StreamRedactor;
use holdfast_core::output::ansi::AnsiMode;
use holdfast_core::output::encoding::TextEncoding;
use holdfast_core::output::redact::find_spans;
use holdfast_core::output::rules::RuleSet;
use holdfast_core::output::{OutputProcessor, ProcessedRead, ReadOptions, WindowSnapshot};

// ---------------------------------------------------------------- fixtures

/// One shipped positive example, with the offset a payload is planted at:
/// the midpoint of the span `find_spans` reports for it, which is the
/// *value* for a rule with a `value` capture group.
struct Fixture {
    /// `rule-name#n`, so two positives of one rule count as two fixtures
    /// — the sweep's headline number is *fixtures*, and 51 rules ship 61
    /// of them.
    id: String,
    rule: String,
    text: String,
    plant_at: usize,
}

fn fixtures(rules: &RuleSet) -> Vec<Fixture> {
    let mut out = Vec::new();
    for rule in &rules.rules {
        for (n, positive) in rule.positive.iter().enumerate() {
            let spans = find_spans(rules, positive.as_bytes(), 0);
            let span = spans.first().unwrap_or_else(|| {
                panic!(
                    "rule `{}` positive {positive:?} matches `regex.is_match` but \
                     `find_spans` reports no span for it",
                    rule.name
                )
            });
            let (start, end) = (span.start as usize, span.end as usize);
            let mut plant_at = start + (end - start) / 2;
            while !positive.is_char_boundary(plant_at) {
                plant_at += 1;
            }
            assert!(
                plant_at > start && plant_at < end,
                "rule `{}`: nothing to split in span {start}..{end}",
                rule.name
            );
            out.push(Fixture {
                id: format!("{}#{n}", rule.name),
                rule: rule.name.clone(),
                text: positive.clone(),
                plant_at,
            });
        }
    }
    out
}

/// The obfuscations planted inside a fixture, one per filter a consumer
/// applies. Each is a byte string this pipeline or a downstream reader
/// **deletes**, which is what re-joins the two halves of the token.
const PAYLOADS: &[(&str, &[u8])] = &[
    // No payload at all. The #138 row: a `paged` read needs nothing
    // planted, because the byte that suppresses the leading `\b` is
    // supplied by the lookbehind.
    ("none", b""),
    // GH #125's own axis, kept as a regression arm.
    ("esc-csi", b"\x1b[0m"),
    ("bs", b"\x08"),
    ("del", b"\x7f"),
    // GH #139. `c1-csi` is dropped by the emulator (`vt100` routes
    // 0x80..=0x9f to `execute`, whose `unhandled_control` is empty) and
    // so re-joins the token in the grid; `c1-csi-seq` is *consumed as a
    // sequence* by a real 8-bit terminal, which is the other filter and
    // a different stream. `c1-utf8` is the two-byte spelling of the same
    // introducer.
    ("c1-csi", b"\x9b"),
    ("c1-csi-seq", b"\x9b0m"),
    ("c1-utf8", b"\xc2\x9b"),
];

/// `ansi` × `text_encoding` pairs. `Base64` is present twice because it
/// is the only encoding that hands back the **exact** bytes, so it is the
/// one that shows a leak the `Utf8` decode would paper over with U+FFFD.
const OPTION_PAIRS: &[(&str, AnsiMode, TextEncoding)] = &[
    ("strip/utf8", AnsiMode::Strip, TextEncoding::Utf8),
    ("strip/base64", AnsiMode::Strip, TextEncoding::Base64),
    ("raw/base64", AnsiMode::Raw, TextEncoding::Base64),
    (
        "raw/lossy_printable",
        AnsiMode::Raw,
        TextEncoding::LossyPrintable,
    ),
];

/// Bytes after the fixture, so the trailing partial-secret scan sees the
/// value end and the read is not held back short of it (control 2).
const TAIL: &str = "\nbuild finished in 13.72s\n";

/// The part of [`TAIL`] a marker cannot reach, and the anchor control 2
/// uses on the stream surface.
///
/// A marker **can** reach into the first few bytes of the tail, and that
/// is not a defect: an 8-bit CSI planted inside a value runs to its final
/// byte, which is the `b` of `build`, so the view joins the value to
/// `uild` and `NormalView::map_span` covers the raw bytes between. One
/// marker eating a word is the documented shape of
/// `a_mapped_span_covers_the_bytes_the_view_dropped_inside_it`; a
/// terminal reading those raw bytes would have shown the same join.
const TAIL_ANCHOR: &str = " finished in 13.72s\n";

/// A word-character run long enough to reach past `lookbehind_bytes`'s
/// own start, so the page really is a strict subset of the window.
fn paged_prefix() -> String {
    "x".repeat(600)
}

// ------------------------------------------------------------- the surfaces

fn snapshot<'a>(
    processor: &OutputProcessor,
    buffer: &'a [u8],
    req_start: u64,
    max_bytes: usize,
) -> WindowSnapshot<'a> {
    let head = buffer.len() as u64;
    let cap_end = (req_start + max_bytes as u64).min(head);
    let window_start = req_start.saturating_sub(processor.limits.lookbehind_bytes as u64);
    let window_end = (cap_end + processor.limits.lookahead_bytes as u64).min(head);
    let scan_start = head.saturating_sub(processor.limits.partial_secret_scan_bytes as u64);
    WindowSnapshot {
        window: &buffer[window_start as usize..window_end as usize],
        window_start,
        tail_region: &buffer[scan_start as usize..head as usize],
        tail_region_start: scan_start,
        req_start,
        head,
        cap_end,
        child_alive: true,
        bypass_holdback: false,
        front_clipped: false,
        truncated_at_tail: false,
    }
}

fn read(
    processor: &OutputProcessor,
    buffer: &[u8],
    req_start: u64,
    opts: &ReadOptions,
) -> ProcessedRead {
    let w = snapshot(processor, buffer, req_start, 64 * 1024);
    processor.process(&w, opts)
}

/// The bytes the caller ends up holding, after undoing the transport
/// encoding a client undoes for itself.
fn handed_out(read: &ProcessedRead, encoding: TextEncoding) -> Vec<u8> {
    match encoding {
        TextEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(read.output.as_bytes())
            .expect("base64 output must decode"),
        _ => read.output.clone().into_bytes(),
    }
}

// -------------------------------------------------- the consumer's filters
//
// Written out here rather than imported from `output::normalise`: this is
// the oracle, and an oracle that shares an implementation with the thing
// it judges cannot see a bug in it.

fn printable_keeps(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\r') || (b >= 0x20 && b != 0x7f)
}

fn printable(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|b| printable_keeps(*b))
        .collect()
}

/// What a real terminal does: ESC-introduced sequences **and** their
/// 8-bit C1 equivalents are consumed whole.
fn terminal(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // The two-byte UTF-8 spelling of a C1 introducer is the same
        // control to a terminal that decodes UTF-8.
        let (c1, width) = match (b, bytes.get(i + 1)) {
            (0xc2, Some(&n)) if (0x80..=0x9f).contains(&n) => (Some(n), 2),
            (0x80..=0x9f, _) => (Some(b), 1),
            _ => (None, 0),
        };
        match (b, bytes.get(i + 1), c1) {
            (0x1b, Some(b'['), _) => i = csi_end(bytes, i + 2),
            (0x1b, Some(b']'), _) => i = string_end(bytes, i + 2),
            (0x1b, Some(_), _) => i += 2,
            (0x1b, None, _) => i += 1,
            // CSI, and OSC / DCS / APC / PM as string sequences.
            (_, _, Some(0x9b)) => i = csi_end(bytes, i + width),
            (_, _, Some(0x9d | 0x90 | 0x9e | 0x9f)) => i = string_end(bytes, i + width),
            // Every other C1 is a single control the terminal executes
            // and does not print.
            (_, _, Some(_)) => i += width,
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// What **Holdfast's** emulator does: `vte` 0.15 documents *"Only
/// supports 7-bit codes"*, routes `0x80..=0x9f` to `Perform::execute`,
/// and `vt100` 0.16's `execute` falls through to an empty
/// `unhandled_control` — so the byte is *dropped*, not consumed as a
/// sequence, and the two halves of the token abut in the grid.
fn emulator(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1)) {
            (0x1b, Some(b'[')) => i = csi_end(bytes, i + 2),
            (0x1b, Some(b']')) => i = string_end(bytes, i + 2),
            (0x1b, Some(_)) => i += 2,
            (0x1b, None) => i += 1,
            (0xc2, Some(&n)) if (0x80..=0x9f).contains(&n) => i += 2,
            (0x80..=0x9f, _) => i += 1,
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn csi_end(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
        i += 1;
    }
    i + usize::from(i < bytes.len())
}

fn string_end(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            0x07 | 0x9c => return i + 1,
            0x1b if bytes.get(i + 1) == Some(&b'\\') => return i + 2,
            _ => i += 1,
        }
    }
    i
}

/// The real emulator, not a model of it: `get_screen_state`'s own
/// `vt100::Parser`. Wide enough that no token wraps, tall enough that
/// nothing scrolls off.
fn vt100_grid(bytes: &[u8]) -> Vec<u8> {
    let mut parser = vt100::Parser::new(64, 300, 0);
    parser.process(bytes);
    parser.screen().contents().into_bytes()
}

/// Every stream a consumer can derive from `bytes`, **deduplicated**.
///
/// The duplicates are the common case rather than a corner: a row with no
/// payload derives the same bytes seven times, and the rule set is the
/// expensive part of this target.
fn consumer_streams(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let printed = printable(bytes);
    let all = [
        ("as-handed-out", bytes.to_vec()),
        ("terminal", terminal(bytes)),
        ("emulator", emulator(bytes)),
        ("printable", printed.clone()),
        ("printable+terminal", terminal(&printed)),
        ("printable+emulator", emulator(&printed)),
        ("vt100-grid", vt100_grid(bytes)),
    ];
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::with_capacity(all.len());
    for (name, stream) in all {
        if !out.iter().any(|(_, prior)| *prior == stream) {
            out.push((name, stream));
        }
    }
    out
}

// ------------------------------------------------------------- the oracle

/// Ranges of `bytes` occupied by a `[REDACTED:…]` marker this pipeline
/// emitted. A rule matching *inside* one is the marker doing its job.
fn marker_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    const OPEN: &[u8] = b"[REDACTED:";
    let mut out = Vec::new();
    let mut i = 0;
    while i + OPEN.len() <= bytes.len() {
        if &bytes[i..i + OPEN.len()] == OPEN {
            match bytes[i..].iter().position(|b| *b == b']') {
                Some(close) => {
                    out.push((i, i + close + 1));
                    i += close + 1;
                }
                None => break,
            }
        } else {
            i += 1;
        }
    }
    out
}

/// The names of the derived streams in which a rule matches bytes that
/// are not part of a marker.
fn leaking_streams(rules: &RuleSet, handed_out: &[u8]) -> Vec<String> {
    let mut leaks = Vec::new();
    for (name, stream) in consumer_streams(handed_out) {
        let markers = marker_ranges(&stream);
        let escaped = |s: &holdfast_core::output::redact::Span| {
            markers
                .iter()
                .any(|(m0, m1)| s.start < *m1 as u64 && (*m0 as u64) < s.end)
        };
        if let Some(span) = find_spans(rules, &stream, 0).iter().find(|s| !escaped(s)) {
            let bytes = &stream[span.start as usize..span.end as usize];
            leaks.push(format!(
                "{name}: `{}` matched {:?}",
                rules.rules[span.rule].name,
                String::from_utf8_lossy(bytes)
            ));
        }
    }
    leaks
}

// --------------------------------------------------------------- the sweep

/// The longest run of `needle`'s own bytes that survives anywhere in
/// `haystack` — "34 of 40 characters", measured rather than eyeballed.
fn longest_shared_run(needle: &[u8], haystack: &[u8]) -> usize {
    (1..=needle.len())
        .rev()
        .find(|n| {
            needle
                .windows(*n)
                .any(|w| haystack.windows(*n).any(|h| h == w))
        })
        .unwrap_or(0)
}

/// One handed-out stream a consumer could turn back into a credential.
/// Carries the axis coordinates rather than a prose label, because the
/// number this task is judged on is *distinct fixtures per axis* and a
/// row count answers a different question.
struct Row {
    payload: &'static str,
    geometry: &'static str,
    fixture: String,
    what: String,
    detail: String,
}

/// What a sweep saw, so that "no leaks" can be told apart from "nothing
/// was looked at".
#[derive(Default)]
struct Tally {
    leaks: Vec<Row>,
    /// Rows whose read reached past the planted fixture.
    reached: usize,
    /// Rows the holdback declined to hand out at all. Safe, and real:
    /// a payload planted inside a `private-key-block` breaks the pattern
    /// permanently, so its indexed prefix reads as in flight for as long
    /// as it stays in the window — §9.2's own
    /// `-----BEGIN CERTIFICATE-----` shape.
    withheld: usize,
}

/// Run every fixture × payload × geometry × option pair through
/// `read_output`, and every one through the `observer` stream, returning
/// the rows whose handed-out bytes a consumer can turn back into a
/// credential.
fn sweep(processor: &OutputProcessor, redact: bool) -> Tally {
    let rules = &processor.rules;
    let mut tally = Tally::default();
    for fixture in fixtures(rules) {
        for (payload_name, payload) in PAYLOADS {
            let mut planted = fixture.text.as_bytes()[..fixture.plant_at].to_vec();
            planted.extend_from_slice(payload);
            planted.extend_from_slice(&fixture.text.as_bytes()[fixture.plant_at..]);

            for geometry in ["whole", "paged"] {
                let mut buffer = Vec::new();
                if geometry == "paged" {
                    buffer.extend_from_slice(paged_prefix().as_bytes());
                }
                let req_start = buffer.len() as u64;
                let fixture_end = req_start + planted.len() as u64;
                buffer.extend_from_slice(&planted);
                buffer.extend_from_slice(TAIL.as_bytes());

                for (opts_name, ansi, encoding) in OPTION_PAIRS {
                    let opts = ReadOptions {
                        ansi: *ansi,
                        text_encoding: *encoding,
                        redact,
                    };
                    let r = read(processor, &buffer, req_start, &opts);
                    // Control 2: a read that stopped short of the fixture
                    // proves nothing about the fixture — unless it says
                    // so, which is the holdback doing its job (§4.1).
                    // Counted either way, because "no leaks" over a sweep
                    // that handed out nothing is not a result.
                    if r.cursor >= fixture_end {
                        tally.reached += 1;
                    } else {
                        assert!(
                            r.held_back,
                            "`{}` / {payload_name} / {geometry} / {opts_name}: read stopped at \
                             {} before the fixture ended at {fixture_end} and did not say so",
                            fixture.rule, r.cursor
                        );
                        tally.withheld += 1;
                    }
                    for detail in leaking_streams(rules, &handed_out(&r, *encoding)) {
                        tally.leaks.push(Row {
                            payload: payload_name,
                            geometry,
                            fixture: fixture.id.clone(),
                            what: format!(
                                "read_output `{}` / {payload_name} / {geometry} / {opts_name}",
                                fixture.rule
                            ),
                            detail,
                        });
                    }
                }
            }

            // The `observer` stream: one chunk, so the whole credential is
            // in the carry when it is judged. A chunk *split* inside the
            // token is GH #142 at this boundary and is measured by
            // `the_stream_residual_at_a_chunk_split_is_bounded` instead.
            let mut redactor = StreamRedactor::new(Arc::new(OutputProcessor::builtin().unwrap()));
            let mut out = redactor.feed(&planted);
            out.extend_from_slice(&redactor.feed(TAIL.as_bytes()));
            out.extend_from_slice(&redactor.flush());
            // Control 2 again, in the stream's own terms: either the
            // fixture went past, or §9.2's terminating rule fired and the
            // stream is withholding — which emits nothing and is safe.
            if out.ends_with(TAIL_ANCHOR.as_bytes()) {
                tally.reached += 1;
            } else {
                assert!(
                    redactor.is_withholding(),
                    "`{}` / {payload_name}: the stream swallowed the fixture's tail                      without withholding",
                    fixture.rule
                );
                tally.withheld += 1;
            }
            if redact {
                for detail in leaking_streams(rules, &out) {
                    tally.leaks.push(Row {
                        payload: payload_name,
                        geometry: "stream",
                        fixture: fixture.id.clone(),
                        what: format!("stream `{}` / {payload_name}", fixture.rule),
                        detail,
                    });
                }
            }
        }
    }
    tally
}

/// The count this task is judged on: **distinct fixtures** that leak, per
/// payload (the grammar axis) and per geometry (the range axis), with a
/// row count beside it so a change that narrows one without the other is
/// visible.
fn summarise(tally: &Tally, fixture_count: usize) -> String {
    let mut report = format!(
        "{} read rows reached their fixture, {} were held back; {} leaking rows\n\
         payload      geometry  fixtures/{fixture_count}  rows   example\n",
        tally.reached,
        tally.withheld,
        tally.leaks.len()
    );
    for (payload, _) in PAYLOADS {
        for geometry in ["whole", "paged", "stream"] {
            let rows: Vec<&Row> = tally
                .leaks
                .iter()
                .filter(|r| r.payload == *payload && r.geometry == geometry)
                .collect();
            if rows.is_empty() {
                continue;
            }
            let mut names: Vec<&str> = rows.iter().map(|r| r.fixture.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            report.push_str(&format!(
                "{payload:<12} {geometry:<9} {:<13} {:<6} {} -> {}\n",
                names.len(),
                rows.len(),
                rows[0].what,
                rows[0].detail
            ));
        }
    }
    report
}

/// **The pipeline check.** `output::rules`'s
/// `every_rule_matches_its_positives_and_rejects_its_negatives` is the
/// *pattern* check over the same fixtures; this is the one that runs them
/// through `process` and `StreamRedactor` and asks what a consumer can
/// reconstruct.
#[test]
fn no_consumer_can_derive_a_credential_from_a_redacted_read() {
    let processor = OutputProcessor::builtin().unwrap();
    let fixture_count = fixtures(&processor.rules).len();
    let tally = sweep(&processor, true);
    eprintln!("{}", summarise(&tally, fixture_count));
    assert!(
        tally.leaks.is_empty(),
        "{} rows handed out bytes a consumer can turn back into a credential:\n{}",
        tally.leaks.len(),
        summarise(&tally, fixture_count)
    );
    // Control 2's floor: a change that put most of this sweep behind the
    // holdback would empty it without failing a single row above.
    assert!(
        tally.reached * 10 >= (tally.reached + tally.withheld) * 9,
        "only {} of {} read rows reached their fixture; the sweep is mostly withheld",
        tally.reached,
        tally.reached + tally.withheld
    );
}

/// **Control 1**, and the reason the row above is not vacuous: the same
/// sweep with the audited `redact: false` hatch must leak on *every*
/// fixture. An oracle that cannot see the unredacted pipeline cannot see
/// a regression in the redacted one.
#[test]
fn the_sweep_detects_a_leak_when_redaction_is_off() {
    let processor = OutputProcessor::builtin().unwrap();
    let fixture_count = fixtures(&processor.rules).len();
    let tally = sweep(&processor, false);
    eprintln!("redaction off: {}", summarise(&tally, fixture_count));
    assert!(
        tally.leaks.len() >= fixture_count,
        "the oracle found only {} leaks with redaction disabled, fewer than the {} \
         fixtures; it is not looking at the bytes it claims to",
        tally.leaks.len(),
        fixture_count
    );
}

/// **Control 3**: the false-positive arm. Every shipped negative example
/// goes through the same read path, and the count of redactions it
/// provokes is measured rather than assumed — "redact everything" passes
/// the sweep above and fails here.
#[test]
fn no_negative_fixture_is_redacted_by_the_pipeline() {
    let processor = OutputProcessor::builtin().unwrap();
    let mut hits = Vec::new();
    for rule in &processor.rules.rules {
        for negative in &rule.negative {
            let buffer = format!("{negative}{TAIL}").into_bytes();
            let r = read(&processor, &buffer, 0, &ReadOptions::default());
            if !r.redactions.is_empty() {
                hits.push(format!(
                    "`{}` negative {negative:?} -> {:?}",
                    rule.name, r.redactions
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "{} negative fixtures were redacted:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// GH #142 at the `StreamRedactor` boundary, **measured and not
/// asserted away**: a credential whose escape-broken halves arrive in
/// different chunks is released up to the escape, because the union of
/// views can only judge bytes that have arrived. The number is recorded
/// here so that closing the issue moves it, rather than the sweep
/// quietly encoding the residual as correct.
#[test]
fn the_stream_residual_at_a_chunk_split_is_bounded() {
    let processor = Arc::new(OutputProcessor::builtin().unwrap());
    let token = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    let planted = format!("{}\x1b[0m{}", &token[..20], &token[20..]);
    let mut residuals = Vec::new();
    for split in [8, 16, 24, 32] {
        let mut redactor = StreamRedactor::new(Arc::clone(&processor));
        let bytes = planted.as_bytes();
        let mut out = redactor.feed(&bytes[..split]);
        out.extend_from_slice(&redactor.feed(&bytes[split..]));
        out.extend_from_slice(&redactor.feed(TAIL.as_bytes()));
        out.extend_from_slice(&redactor.flush());
        // The stream as a terminal renders it — the escape is gone by
        // then, which is the whole shape of the defect.
        let rendered = terminal(&out);
        let residual = longest_shared_run(token.as_bytes(), &rendered);
        assert!(
            residual < token.len(),
            "split {split}: the whole token was released intact: {:?}",
            String::from_utf8_lossy(&rendered)
        );
        residuals.push((split, residual));
    }
    // The control the residuals are measured against: **unsplit**, the
    // same bytes are judged by `all_spans` over a carry that holds the
    // whole token, and nothing of it is released. Without this row the
    // assertions above pass against a redactor that never matched
    // anything, because "not the whole token" is most of the outputs a
    // broken one produces.
    let mut redactor = StreamRedactor::new(Arc::clone(&processor));
    let mut whole = redactor.feed(planted.as_bytes());
    whole.extend_from_slice(&redactor.feed(TAIL.as_bytes()));
    whole.extend_from_slice(&redactor.flush());
    let rendered = terminal(&whole);
    assert_eq!(
        marker_ranges(&rendered).len(),
        1,
        "unsplit, the escape-broken token is one marker: {:?}",
        String::from_utf8_lossy(&rendered)
    );
    assert!(
        longest_shared_run(token.as_bytes(), &rendered) < 8,
        "unsplit, nothing of the token is released: {:?}",
        String::from_utf8_lossy(&rendered)
    );
    eprintln!("GH #142 at the stream boundary — (chunk split, longest run of the 40-character token still released): {residuals:?}");
}
