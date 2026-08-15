//! The session-state block carried by every prompt-bearing response
//! (spec §5.4, §18.2a).
//!
//! One helper rather than one copy per tool: `read_output`, `send_input`,
//! `status`, and `list_sessions` all report the same fields, and a tool
//! that quietly stopped reporting them would be a silent regression.

use crate::detect::Detection;
use crate::output::redact::redact_str;
use crate::output::OutputProcessor;
use crate::session::Session;
use serde_json::{json, Value};

/// Tier-B VT100 tracking arrives in 0.0.4. Until then the answer is always
/// `"off"`; the field exists now so the response shape does not change
/// when tracking becomes real (§4.5).
pub const SCREEN_TRACKING: &str = "off";

/// f32 scores serialise through f64 and pick up representation noise
/// (`0.95f32` prints as `0.949999988079071`, which an agent thresholding
/// on 0.95 would never match). Three decimals is more precision than any
/// of these signals carries.
fn round3(x: f32) -> f64 {
    ((x as f64) * 1000.0).round() / 1000.0
}

/// `last_line` as an agent may see it — **vouched-for text, or nothing**
/// (§9.2's `prompt.last_line` rule).
///
/// The field is a *diagnostic*: it exists so an agent can read the prompt
/// it is about to answer. It is not a data channel, and the recourse when
/// it is empty is `read_output`, which redacts over the whole buffer with
/// §4.1's lookbehind and its multi-line rules and reports `held_back` when
/// it is withholding. That asymmetry is what licenses a rule that reports
/// nothing whenever the line cannot be judged: the value of a line that
/// shows a prompt is high, the value of one that shows key material is
/// negative, and everything the agent *acts* on — `interaction_mode`,
/// `confidence`, `quiescent_score`, `pattern_score` — is still computed
/// from the full line and still reported.
///
/// Three conditions make a line unjudgeable. Each is a separate failure of
/// the same mechanism, and none subsumes another:
///
/// **1. An in-flight candidate is visible in the rendered line — clip at
/// it.** `redact_str` replaces *complete* matches; a token one character
/// short of its rule's minimum matches nothing by construction, so a
/// 39-character `ghp_…` came back verbatim on a response that was
/// simultaneously withholding those very bytes from `output`. The clip
/// runs over `last_line` itself rather than over the buffer's
/// `holdback_boundary`, and that is deliberate: `ghp_\x1b[0m0123…` **has
/// no holdback boundary**, because `ESC` is not a value byte, so the
/// buffer-side scanner correctly declines to call it a token in flight
/// while the stripped line the agent is handed reads as a contiguous
/// 39-character partial. §9.2's screen-state rule is the one that applies
/// — "the redactor must run on the rendered rows, not on the bytes that
/// produced them" — because `last_line` is a *reconstruction*, the
/// scanner's post-strip tail (§4.1's last paragraph), not a slice of the
/// byte stream.
///
/// **2. The session's holdback is active — report nothing.** Rule 1 is a
/// per-line predicate and cannot see an anchor on an earlier line. `cat
/// id_rsa` on a key still streaming is the case: the `-----BEGIN` that
/// licenses the withholding sits lines above, the rendered last line is
/// 64 characters of base64 with no anchor anywhere in it, and every
/// per-line mechanism reports it clean. Meanwhile `read_output` on the
/// *same response* answered `held_back: true` with the boundary at the
/// `-----BEGIN`. The rule is `holdback_boundary < buffer.head`, and it
/// closes that by construction rather than by pattern: the withheld
/// region always ends at `head`, and the tail line is always built from
/// bytes ending at `head`, so an active holdback means the reconstruction
/// necessarily overlaps the bytes the session is refusing to hand over.
/// No byte-to-rendered-position arithmetic is attempted, because none is
/// possible — a `\r` redraw, a multi-byte character, or a withheld region
/// spanning lines each break it in a different direction — so the flag is
/// used at the coarsest granularity it is sound at: the whole line.
///
/// **3. The line was front-truncated — report nothing.** Both mechanisms
/// above are *anchored*: `redact_str` finds a rule's leading literal and
/// `earliest_partial` finds an indexed prefix. `TailLine::push` evicts
/// from the front at `TAIL_LINE_MAX`, so a 643-character JWT loses its
/// `eyJ` and hands back 512 characters — signature included — that no rule
/// can recognise. That is not a race; it persists until the next line
/// arrives. Widening what the redactor may see was the alternative and it
/// is not a fix: any bound can be exceeded by one more byte, and the field
/// would trade a bounded reconstruction for an unbounded scan while still
/// leaving case 2 open.
///
/// **Detection is unaffected by all three.** `pattern_score` is computed
/// inside the detector from the full line (`detect::detector`), before any
/// response exists. These decide what is *reported* and never what is
/// *decided* — the property `suppressing_the_report_does_not_move_the_
/// pattern_score` asserts directly.
fn safe_last_line(processor: &OutputProcessor, session: &Session, d: &Detection) -> String {
    // Case 3 first, and case 2 before any per-line work: both answer for
    // the whole line, so there is nothing for the clip to improve on.
    if d.last_line_truncated {
        return String::new();
    }
    if session.holdback_boundary(processor) < session.buffer_head() {
        return String::new();
    }
    let line = d.last_line.as_str();
    let visible = match processor
        .index
        .earliest_partial(&processor.rules, line.as_bytes(), 0)
    {
        // Prefixes are ASCII, so the offset is already a char boundary;
        // the walk is there so a future non-ASCII prefix truncates *more*
        // rather than panicking on a split code point.
        Some(cut) => {
            let mut cut = cut as usize;
            while cut > 0 && !line.is_char_boundary(cut) {
                cut -= 1;
            }
            &line[..cut]
        }
        None => line,
    };
    redact_str(&processor.rules, visible)
}

/// Insert the session-state block into a tool's `data` object.
///
/// The enums are siblings of `prompt`, not nested inside it: they describe
/// the session, not the heuristic (§5.4).
///
/// **`last_line` is redacted here, at the one builder, and that is what
/// makes REQ-T-011 hold everywhere at once.** This helper serves every
/// prompt-bearing response, so redacting at a call site instead would
/// leave the other four leaking — and the last line of output is where a
/// secret the child just echoed lands.
///
/// `reason` is deliberately **not** redacted: it is CLASP's own
/// branch-name vocabulary from §8.3's ladder (`"bracketed paste off"` and
/// friends), never child output, so it cannot carry a secret. Running the
/// redactor over a fixed vocabulary only creates a way for a rule change
/// to corrupt an enum.
///
/// **`title` is redacted here too, and the comment this replaces is why it
/// was not.** It read: *"a scope statement rather than an oversight: §9.2
/// lists it, but it arrives from OSC 0/2 in 0.0.4's `ScreenTracker` and is
/// `None` on every response this milestone can produce. 0.0.4 owns that
/// call site."* Every clause of that is true except the load-bearing one.
/// `d.title` comes from **0.0.2's `ModeScanner`**, which has parsed OSC 0/2
/// since it was written — `every_documented_field_is_present`, three
/// screens up this file, feeds `\x1b]0;build\x07` and asserts `"build"`
/// comes back. So the field was non-`None` on ordinary responses and went
/// out verbatim, and `printf '\033]0;%s\007' "$GH_TOKEN"` put a live token
/// on `status` and `list_sessions` — both of which §5.2 says redact it.
///
/// It is recorded at this length because the *shape* of the mistake
/// outlives it: a premise about which milestone owns a field, written
/// beside the code, with nothing asserting the premise. The redaction is
/// unconditional now, so there is no premise left to go stale, and
/// `a_secret_in_the_window_title_does_not_reach_any_tool` fails if it is
/// removed.
///
/// This is **not** an instance of §9.2's bounded-reconstruction class that
/// `safe_last_line` above exists for. A title is a single contiguous OSC
/// payload with nothing evicted from it, and an over-long one is discarded
/// wholesale by the scanner rather than truncated — so the redactor sees
/// the whole of whatever it sees. It was simply not being run.
pub fn with_detection(mut data: Value, session: &Session, processor: &OutputProcessor) -> Value {
    let d = session.detection();
    let Some(map) = data.as_object_mut() else {
        return data;
    };
    map.insert(
        "interaction_mode".into(),
        json!(d.interaction_mode.as_str()),
    );
    map.insert("detection_tier".into(), json!(d.detection_tier.as_str()));
    map.insert("screen_tracking".into(), json!(SCREEN_TRACKING));
    map.insert(
        "title".into(),
        json!(d.title.as_deref().map(|t| redact_str(&processor.rules, t))),
    );
    map.insert(
        "prompt".into(),
        json!({
            "confidence": round3(d.confidence),
            "quiescent_score": round3(d.quiescent_score),
            "pattern_score": round3(d.pattern_score),
            "cursor_score": round3(d.cursor_score),
            "reason": d.reason,
            "last_line": safe_last_line(processor, session, &d),
        }),
    );
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::{MockPty, PtyBackend};
    use crate::session::{new_session_id, Session, SessionConfig};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A session that has already *classified* `bytes`, where `last_line`
    /// is what the detector reports once it has caught up.
    ///
    /// The wait is on the detector's own state, not on `buffer_head()`.
    /// The reader appends to the buffer before it feeds the detector, so a
    /// byte count can be satisfied while the detector has seen nothing —
    /// and every assertion in this module is about the detector. Measured:
    /// the window never opened naturally here (0 failures in 600 runs,
    /// because `queue_output` runs before `Session::new` and the reader
    /// therefore never reaches its idle sleep), but injecting 50 ms
    /// between the push and the feed fails
    /// `every_documented_field_is_present` and
    /// `scores_serialise_without_float_noise` every time. Uncorrelated is
    /// not the same as closed.
    fn session_with_output(bytes: &[u8], last_line: &str) -> (Arc<Session>, Arc<MockPty>) {
        session_until(bytes, "the detector to consume the queued output", |d| {
            d.last_line == last_line
        })
    }

    /// The same arrangement, waiting on an arbitrary property of the
    /// detection rather than on `last_line`'s exact text.
    ///
    /// **The reason it exists is diagnostic quality, not flexibility.** A
    /// test whose fixture waits for `last_line == <the exact string>`
    /// reports every mutation that blanks that field as *"timed out
    /// waiting for the detector"* — including the one mutation it is the
    /// only test able to catch, an implementation of §9.2's rule sited in
    /// the scanner or the detector instead of at the response boundary.
    /// Waiting on the property under test and asserting the string
    /// afterwards makes that failure land on the assertion that names it.
    fn session_until(
        bytes: &[u8],
        what: &str,
        mut pred: impl FnMut(&crate::detect::Detection) -> bool,
    ) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        pty.queue_output(bytes);
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(4096),
        );
        wait_until(what, || pred(&s.detection()));
        (s, pty)
    }

    /// The exact set of keys an object carries.
    fn key_set(v: &Value) -> BTreeSet<&str> {
        v.as_object()
            .unwrap_or_else(|| panic!("expected an object, got {v}"))
            .keys()
            .map(String::as_str)
            .collect()
    }

    /// The built-in processor, which is what production passes.
    fn rules() -> OutputProcessor {
        OutputProcessor::builtin().expect("the built-in rules must compile")
    }

    fn set<'a>(names: &[&'a str]) -> BTreeSet<&'a str> {
        names.iter().copied().collect()
    }

    /// Poll the *detector's* state, not the buffer's.
    ///
    /// The reader appends to the buffer before it feeds the detector, so a
    /// byte count says nothing about what the detector has seen (the same
    /// caveat `session::tests::wait_until` documents).
    fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pred() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(pred(), "timed out waiting for {what}");
    }

    #[test]
    fn every_documented_field_is_present() {
        let (s, _pty) = session_with_output(b"\x1b[?2004h\x1b]0;build\x07bash-5.3$ ", "bash-5.3$ ");
        let v = with_detection(json!({ "output": "" }), &s, &rules());

        assert_eq!(v["output"], "");
        assert_eq!(v["interaction_mode"], "AtPrompt");
        assert_eq!(v["detection_tier"], "terminal_mode");
        assert_eq!(v["screen_tracking"], "off");
        assert_eq!(v["title"], "build");
        for key in [
            "confidence",
            "quiescent_score",
            "pattern_score",
            "cursor_score",
            "reason",
            "last_line",
        ] {
            assert!(v["prompt"].get(key).is_some(), "prompt.{key} is missing");
        }
        assert_eq!(v["prompt"]["last_line"], "bash-5.3$ ");
    }

    /// REQ-T-011 at the builder. Its paired negative is
    /// `every_documented_field_is_present`, which pins an ordinary
    /// `last_line` byte-identical — without that, a `last_line` replaced
    /// by a constant marker would satisfy this test.
    #[test]
    fn a_secret_on_the_last_line_is_redacted_before_any_tool_sees_it() {
        let secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let line = format!("TOKEN={secret}");
        let (s, _pty) = session_with_output(line.as_bytes(), &line);
        let v = with_detection(json!({}), &s, &rules());
        assert_eq!(v["prompt"]["last_line"], "TOKEN=[REDACTED:github]");
        assert!(
            !v.to_string().contains(secret),
            "the token survived somewhere in the block: {v}"
        );
    }

    /// C1. `redact_str` replaces *complete* matches, so a token one
    /// character short of its rule's minimum matches nothing — and the
    /// holdback, which exists for exactly that case, was applied to
    /// `output` and not to this field. The same response withheld these
    /// bytes from `read_output.output` and handed them back here.
    ///
    /// Its paired negative is `a_secret_on_the_last_line_is_redacted_
    /// before_any_tool_sees_it` (a *completed* token still comes back as
    /// a marker, not as nothing) and `a_prefix_that_is_no_longer_in_
    /// flight_is_left_alone` below.
    ///
    /// **Its answer is over-determined since the holdback case landed**:
    /// this fixture has a real byte-stream boundary as well as a rendered
    /// candidate, so either mechanism alone produces `""`. That is fine
    /// for what it pins — the field must not carry the partial — and it is
    /// why the clip keeps a fixture of its own below, where no boundary
    /// exists at all.
    #[test]
    fn an_in_flight_partial_secret_is_dropped_from_the_last_line() {
        let partial = format!("ghp_{}", "0123456789abcdefghijABCDEFGHIJ01234");
        assert_eq!(partial.len(), 39, "one short of the rule's 40-char minimum");
        let (s, _pty) = session_with_output(format!("building\n{partial}").as_bytes(), &partial);

        let v = with_detection(json!({}), &s, &rules());
        assert_eq!(
            v["prompt"]["last_line"], "",
            "the candidate tail is the whole line, so nothing is left of it"
        );
        assert!(
            !v.to_string().contains(&partial),
            "the in-flight token survived somewhere in the block: {v}"
        );
    }

    /// The discriminating fixture: **the input never contains the secret**
    /// (§9.2's reconstruction rule). `ghp_\x1b[0m…` is a token in flight
    /// only in the *rendered* line; in the byte stream an `ESC` sits in
    /// the middle of it, which is not a value byte, so the buffer-side
    /// holdback correctly declines to fire — asserted here, because that
    /// is what makes this test separate the implementation that clips at
    /// `Session::holdback_boundary` from the one that runs the same
    /// predicate over the rendered text. The first returns this line in
    /// full.
    #[test]
    fn a_partial_contiguous_only_in_the_rendering_is_dropped_too() {
        let tail = "0123456789abcdefghijABCDEFGHIJ01234";
        let rendered = format!("ghp_{tail}");
        let bytes = format!("building\nghp_\x1b[0m{tail}");
        assert!(
            !bytes.contains(&rendered),
            "the fixture must not contain the partial contiguously, or it \
             tests the wrong layer"
        );
        let (s, _pty) = session_with_output(bytes.as_bytes(), &rendered);

        let processor = rules();
        assert_eq!(
            s.holdback_boundary(&processor),
            s.buffer_head(),
            "no byte-stream boundary exists here; a clip at the boundary \
             would return the line in full"
        );
        let v = with_detection(json!({}), &s, &processor);
        assert_eq!(v["prompt"]["last_line"], "");
        assert!(!v.to_string().contains(&rendered), "{v}");
    }

    /// The separator between "drop the in-flight candidate" and "delete
    /// everything after a known prefix". A space after `ghp_abc` means the
    /// token can never complete, so nothing is in flight and the line is
    /// returned byte-identical.
    ///
    /// It is also the paired negative for the **holdback** case: the
    /// boundary is asserted inactive, so a rule that suppressed on
    /// `holdback_boundary <= buffer.head` rather than `<` — or on nothing
    /// at all — fails here rather than passing everywhere.
    #[test]
    fn a_prefix_that_is_no_longer_in_flight_is_left_alone() {
        let line = "TOKEN=ghp_abc ready";
        let (s, _pty) = session_with_output(line.as_bytes(), line);
        let processor = rules();
        assert_eq!(
            s.holdback_boundary(&processor),
            s.buffer_head(),
            "nothing is in flight, so nothing is withheld"
        );
        assert_eq!(
            with_detection(json!({}), &s, &processor)["prompt"]["last_line"],
            line
        );
    }

    // -------------------------------------- §9.2's other two cases
    //
    // The clip above is a **per-line** predicate over a **whole** line, and
    // both of those words carry a failure. F2 breaks the first: a rule
    // whose anchor is on an earlier line is invisible to anything that
    // looks only at the last one. F1 breaks the second: the front of a long
    // line is evicted at `TAIL_LINE_MAX`, and the front is where an anchor
    // lives. Neither is reachable from the other, so each gets a fixture
    // that the other mechanism provably cannot answer.

    /// F2 — `cat id_rsa` with the key still streaming.
    ///
    /// **The discriminating property is that every per-line mechanism is
    /// blind here, and it is asserted rather than described**: the rendered
    /// last line is 64 characters of base64 with no rule anchor anywhere in
    /// it, so `redact_str` returns it verbatim and `earliest_partial` finds
    /// nothing. An implementation carrying only the clip hands the agent a
    /// private-key body on a `readOnlyHint: true` tool, on the same
    /// response whose `read_output` is withholding those bytes.
    #[test]
    fn a_last_line_the_holdback_is_withholding_is_not_reported() {
        let body = "PjLkMnBvCxZaSdFgHjKlQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJk";
        let stream = format!("$ cat id_rsa\n-----BEGIN RSA PRIVATE KEY-----\n{body}");
        let (s, _pty) = session_with_output(stream.as_bytes(), body);
        let processor = rules();

        // The clip cannot see this line, and neither can the redactor.
        assert_eq!(
            redact_str(&processor.rules, body),
            body,
            "no complete match on this line — the `-----END` has not arrived"
        );
        assert_eq!(
            processor
                .index
                .earliest_partial(&processor.rules, body.as_bytes(), 0),
            None,
            "no in-flight candidate on this line either; the anchor is two \
             lines above it"
        );
        // What *can* see it, and does.
        assert!(
            s.holdback_boundary(&processor) < s.buffer_head(),
            "the byte stream is withholding from the `-----BEGIN` onward"
        );

        let v = with_detection(json!({}), &s, &processor);
        assert_eq!(v["prompt"]["last_line"], "");
        assert!(!v.to_string().contains(body), "the key body survived: {v}");
    }

    /// F1 — a secret longer than the tail bound, so its anchor is evicted.
    ///
    /// **The holdback is asserted inactive**, which is what makes this a
    /// separate case rather than a second spelling of the one above: the
    /// JWT is *complete*, `read_output` redacts it correctly to
    /// `[REDACTED:jwt]`, nothing is in flight, and the only thing wrong is
    /// that `last_line` is the final 512 characters of a 643-character
    /// line. It is not a race; it persists until the next line arrives.
    #[test]
    fn a_last_line_too_long_to_carry_its_own_anchor_is_not_reported() {
        // header.payload.signature, 643 characters. The `\beyJ` both the
        // rule and the index anchor on is 131 characters past eviction.
        let jwt = format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ{}.{}",
            "A".repeat(400),
            "S".repeat(202)
        );
        assert_eq!(jwt.len(), 643);
        let reported = &jwt[jwt.len() - 512..];
        // Waits on the eviction, then asserts the text — so a §9.2 rule
        // wrongly sited upstream of the response boundary fails on the
        // assertion below rather than in this fixture's timeout.
        let (s, _pty) = session_until(
            format!("$ echo $T\n{jwt}").as_bytes(),
            "the detector to record a front-truncated tail line",
            |d| d.last_line_truncated,
        );
        assert_eq!(
            s.detection().last_line,
            reported,
            "the detector must still hold the 512-byte tail: suppression \
             belongs at the response boundary, not upstream of every score"
        );
        let processor = rules();

        // The evidence is gone, and both mechanisms say so.
        assert_eq!(
            redact_str(&processor.rules, reported),
            reported,
            "the `eyJ` anchor was evicted, so the jwt rule cannot fire"
        );
        assert_eq!(
            processor
                .index
                .earliest_partial(&processor.rules, reported.as_bytes(), 0),
            None
        );
        assert_eq!(
            s.holdback_boundary(&processor),
            s.buffer_head(),
            "the token is complete, so nothing is in flight — the holdback \
             case cannot be what answers this one"
        );
        assert!(
            s.detection().last_line_truncated,
            "the scanner must have recorded the eviction"
        );

        let v = with_detection(json!({}), &s, &processor);
        assert_eq!(v["prompt"]["last_line"], "");
        assert!(
            !v.to_string().contains(&jwt[jwt.len() - 202..]),
            "the signature segment survived: {v}"
        );
    }

    /// The paired negative for the truncation case, at the boundary: a line
    /// of **exactly** `TAIL_LINE_MAX` bytes lost nothing and is reported in
    /// full. Without it, "suppress a line of 512 characters" passes as
    /// "suppress a line that was truncated", and every long-but-ordinary
    /// line — a `ls -l` of a deep path, a wrapped compiler diagnostic —
    /// disappears from the field.
    #[test]
    fn a_long_line_that_lost_nothing_is_reported_in_full() {
        let line = format!("{}$ ", "x".repeat(510));
        assert_eq!(line.len(), 512, "exactly the bound, so nothing is evicted");
        let (s, _pty) = session_with_output(line.as_bytes(), &line);
        assert!(!s.detection().last_line_truncated);
        assert_eq!(
            with_detection(json!({}), &s, &rules())["prompt"]["last_line"],
            json!(line)
        );
    }

    /// The property the whole §9.2 rule is written to preserve, asserted
    /// directly on the case the review named: `user@host:~$ ghp_<39>`.
    ///
    /// `pattern_score` is computed inside the detector from the **full**
    /// line, before any response exists, so suppression changes what is
    /// *reported* and never what is *decided*. This is the assertion that
    /// would fail if the rule were ever implemented by blanking
    /// `Detection::last_line` in the scanner or the detector — which is the
    /// obvious place to put it and the wrong one, because every score, tier
    /// and `interaction_mode` downstream reads that field.
    #[test]
    fn suppressing_the_report_does_not_move_the_pattern_score() {
        use crate::detect::PatternSet;
        let line = format!("user@host:~$ ghp_{}", "0123456789abcdefghijABCDEFGHIJ01234");
        let (s, _pty) = session_with_output(format!("building\n{line}").as_bytes(), &line);
        let processor = rules();

        let d = s.detection();
        assert_eq!(d.last_line, line, "the detector still holds the whole line");
        assert_eq!(
            d.pattern_score,
            PatternSet::defaults().score(&line),
            "the score is the full line's, unchanged by anything below"
        );

        let v = with_detection(json!({}), &s, &processor);
        assert_eq!(
            v["prompt"]["last_line"], "",
            "and the reported line is suppressed, so this really is a case \
             where reporting and deciding disagree"
        );
        assert_eq!(v["prompt"]["pattern_score"], round3(d.pattern_score));
    }

    #[test]
    fn scores_serialise_without_float_noise() {
        let (s, _pty) = session_with_output(b"\x1b[?2004h$ ", "$ ");
        let v = with_detection(json!({}), &s, &rules());
        assert_eq!(v["prompt"]["confidence"], 0.95);
        assert_eq!(
            serde_json::to_string(&v["prompt"]["confidence"]).unwrap(),
            "0.95"
        );
    }

    #[test]
    fn a_session_with_no_title_reports_null() {
        let (s, _pty) = session_with_output(b"$ ", "$ ");
        assert_eq!(
            with_detection(json!({}), &s, &rules())["title"],
            Value::Null
        );
    }

    /// §5.2 says `title` is redacted at `status` and `list_sessions`; it was
    /// not, at any of the seven call sites, because this builder emitted
    /// `d.title` raw under a comment asserting the field was always `None`
    /// this milestone. Any child can set it: `printf '\033]0;%s\007' "$T"`.
    ///
    /// Its paired negative is `an_ordinary_window_title_is_reported_byte_
    /// identical` below — without it, dropping the field or emitting a
    /// constant marker passes this.
    #[test]
    fn a_secret_in_the_window_title_does_not_reach_any_tool() {
        let secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let (s, _pty) =
            session_with_output(format!("\x1b]0;deploy {secret}\x07$ ").as_bytes(), "$ ");
        assert_eq!(
            s.detection().title.as_deref(),
            Some(format!("deploy {secret}").as_str()),
            "the premise the old comment rested on: the scanner really does \
             produce a title this milestone"
        );

        let v = with_detection(json!({}), &s, &rules());
        assert_eq!(v["title"], "deploy [REDACTED:github]");
        assert!(
            !v.to_string().contains(secret),
            "the token survived somewhere in the block: {v}"
        );
    }

    #[test]
    fn an_ordinary_window_title_is_reported_byte_identical() {
        let (s, _pty) = session_with_output(b"\x1b]0;~/src/clasp\x07$ ", "$ ");
        assert_eq!(
            with_detection(json!({}), &s, &rules())["title"],
            "~/src/clasp"
        );
    }

    #[test]
    fn a_non_object_payload_is_returned_unchanged() {
        let (s, _pty) = session_with_output(b"$ ", "$ ");
        assert_eq!(with_detection(json!("plain"), &s, &rules()), json!("plain"));
    }

    #[test]
    fn each_field_carries_the_value_it_names() {
        // The block is a pile of same-typed fields — four `f64` scores,
        // several strings. Two of them transposed still compiles, still
        // serialises, and still passes any test that checks only the set
        // of keys. So this session is chosen to make every field of a
        // given type hold a *different* value: 0.95 / 1.0 / 0.9 / 0.0 for
        // the scores, six distinct strings for the rest. A session where
        // two of them happened to agree would prove nothing about either.
        let (s, _pty) = session_with_output(b"\x1b[?2004h\x1b]0;py\x07>>> ", ">>> ");
        // `quiescent_score` climbs with idle time, so wait for it to
        // saturate at a fixed 1.0. The `last_line` half of the predicate
        // is what proves the detector actually consumed the bytes — an
        // unfed detector's quiescence saturates too.
        wait_until("the detector to consume the prompt and settle", || {
            let d = s.detection();
            d.last_line == ">>> " && d.quiescent_score >= 1.0
        });

        let v = with_detection(json!({}), &s, &rules());

        assert_eq!(v["interaction_mode"], "AtPrompt");
        assert_eq!(v["detection_tier"], "terminal_mode");
        assert_eq!(v["screen_tracking"], "off");
        assert_eq!(v["title"], "py");
        assert_eq!(v["prompt"]["confidence"], 0.95);
        assert_eq!(v["prompt"]["quiescent_score"], 1.0);
        assert_eq!(v["prompt"]["pattern_score"], 0.9);
        // Zero because this session's Tier B is off, not because the
        // field is a constant — since 0.0.4 it carries the §8.6 T3c score
        // whenever the tracker is running, so what this pins is the off
        // case. Deterministically off, and by the fixture rather than by
        // luck: the `\x1b[?2004h` above is a §4.5 deterministic signal, so
        // the three-second no-signal trigger never arms. A fixture without
        // one would answer 0.0 for under three seconds and 0.9 after.
        assert_eq!(v["prompt"]["cursor_score"], 0.0);
        assert_eq!(v["prompt"]["reason"], "bracketed paste is enabled");
        assert_eq!(v["prompt"]["last_line"], ">>> ");
    }

    #[test]
    fn an_absent_title_is_still_a_key() {
        // The separator for `a_session_with_no_title_reports_null`:
        // indexing a *missing* key also yields `Value::Null`, so that
        // test passes just as well if the field is never inserted. §5.4
        // wants the key present and null, and 0.0.2's `outputSchema` work
        // makes the difference load-bearing.
        let (s, _pty) = session_with_output(b"$ ", "$ ");
        let v = with_detection(json!({}), &s, &rules());
        let map = v.as_object().expect("payload stays an object");
        assert!(
            map.contains_key("title"),
            "title must be emitted, not omitted"
        );
        assert_eq!(map["title"], Value::Null);
    }

    #[test]
    fn the_block_inserts_exactly_the_keys_5_4_names_and_no_others() {
        // Every other test in this module asserts *presence* and values:
        // `every_documented_field_is_present` walks a list of keys it
        // expects and `each_field_carries_the_value_it_names` indexes them
        // by name. Neither can see an *extra* key. Adding
        // `map.insert("debug".into(), json!(1))` next to the real inserts
        // survives all seven of them.
        //
        // That is not cosmetic. §23.3 freezes this surface, and every
        // schema declaring it is `deny_unknown_fields`, so a stray key here
        // is `additionalProperties` rejection on a live response — a
        // failure the agent sees and no test in this crate does. Pinning
        // the exact key set is what turns that into a local failure.
        //
        // The payload starts non-empty so the assertion also proves the
        // block is *added to* the caller's data rather than replacing it.
        let (s, _pty) = session_with_output(b"\x1b[?2004h\x1b]0;t\x07$ ", "$ ");
        let v = with_detection(json!({ "output": "", "cursor": 0 }), &s, &rules());

        assert_eq!(
            key_set(&v),
            set(&[
                // The caller's own fields, which the block must not eat…
                "output",
                "cursor",
                // …and the five §5.4 siblings.
                "interaction_mode",
                "detection_tier",
                "screen_tracking",
                "title",
                "prompt",
            ]),
            "the §5.4 block gained or lost a field"
        );
        assert_eq!(
            key_set(&v["prompt"]),
            set(&[
                "confidence",
                "quiescent_score",
                "pattern_score",
                "cursor_score",
                "reason",
                "last_line",
            ]),
            "the §5.4 prompt object gained or lost a field"
        );
    }

    #[test]
    fn round3_rounds_rather_than_truncating_at_three_decimals() {
        // `scores_serialise_without_float_noise` pins 0.95, which survives
        // rounding at *two* decimals just as well — it cannot tell 1000.0
        // from 100.0, nor rounding from truncation. These can.
        assert_eq!(round3(0.4567), 0.457, "must round up at 3 decimals");
        assert_eq!(round3(0.1234), 0.123, "must round down at 3 decimals");
        assert_eq!(round3(0.9999), 1.0);
        assert_eq!(round3(0.0), 0.0);
        assert_eq!(round3(1.0), 1.0);
    }
}
