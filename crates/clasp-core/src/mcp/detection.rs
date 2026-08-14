//! The session-state block carried by every prompt-bearing response
//! (spec §5.4, §18.2a).
//!
//! One helper rather than one copy per tool: `read_output`, `send_input`,
//! `status`, and `list_sessions` all report the same fields, and a tool
//! that quietly stopped reporting them would be a silent regression.

use crate::output::redact::redact_str;
use crate::output::rules::RuleSet;
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
/// `title` is not redacted here either, and that is a scope statement
/// rather than an oversight: §9.2 lists it, but it arrives from OSC 0/2
/// in 0.0.4's `ScreenTracker` and is `None` on every response this
/// milestone can produce. 0.0.4 owns that call site.
pub fn with_detection(mut data: Value, session: &Session, rules: &RuleSet) -> Value {
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
    map.insert("title".into(), json!(d.title));
    map.insert(
        "prompt".into(),
        json!({
            "confidence": round3(d.confidence),
            "quiescent_score": round3(d.quiescent_score),
            "pattern_score": round3(d.pattern_score),
            "cursor_score": round3(d.cursor_score),
            "reason": d.reason,
            "last_line": redact_str(rules, &d.last_line),
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
        wait_until("the detector to consume the queued output", || {
            s.detection().last_line == last_line
        });
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

    /// The built-in rule set, which is what production passes.
    fn rules() -> Arc<crate::output::rules::RuleSet> {
        crate::output::rules::builtin_shared()
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
        // Constant until the Tier-B cursor heuristic lands in 0.0.4: the
        // field is reported now so that milestone changes a value rather
        // than the response shape.
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
