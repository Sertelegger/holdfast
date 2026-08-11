//! The session-state block carried by every prompt-bearing response
//! (spec §5.4, §18.2a).
//!
//! One helper rather than one copy per tool: `read_output`, `send_input`,
//! `status`, and `list_sessions` all report the same fields, and a tool
//! that quietly stopped reporting them would be a silent regression.

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
pub fn with_detection(mut data: Value, session: &Session) -> Value {
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
            "last_line": d.last_line,
        }),
    );
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::{MockPty, PtyBackend};
    use crate::session::{new_session_id, Session, SessionConfig};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn session_with_output(bytes: &[u8]) -> (Arc<Session>, Arc<MockPty>) {
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
        let deadline = Instant::now() + Duration::from_secs(2);
        while s.buffer_head() < bytes.len() as u64 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            s.buffer_head(),
            bytes.len() as u64,
            "reader never caught up"
        );
        (s, pty)
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
        let (s, _pty) = session_with_output(b"\x1b[?2004h\x1b]0;build\x07bash-5.3$ ");
        let v = with_detection(json!({ "output": "" }), &s);

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

    #[test]
    fn scores_serialise_without_float_noise() {
        let (s, _pty) = session_with_output(b"\x1b[?2004h$ ");
        let v = with_detection(json!({}), &s);
        assert_eq!(v["prompt"]["confidence"], 0.95);
        assert_eq!(
            serde_json::to_string(&v["prompt"]["confidence"]).unwrap(),
            "0.95"
        );
    }

    #[test]
    fn a_session_with_no_title_reports_null() {
        let (s, _pty) = session_with_output(b"$ ");
        assert_eq!(with_detection(json!({}), &s)["title"], Value::Null);
    }

    #[test]
    fn a_non_object_payload_is_returned_unchanged() {
        let (s, _pty) = session_with_output(b"$ ");
        assert_eq!(with_detection(json!("plain"), &s), json!("plain"));
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
        let (s, _pty) = session_with_output(b"\x1b[?2004h\x1b]0;py\x07>>> ");
        // `quiescent_score` climbs with idle time, so wait for it to
        // saturate at a fixed 1.0. The `last_line` half of the predicate
        // is what proves the detector actually consumed the bytes — an
        // unfed detector's quiescence saturates too.
        wait_until("the detector to consume the prompt and settle", || {
            let d = s.detection();
            d.last_line == ">>> " && d.quiescent_score >= 1.0
        });

        let v = with_detection(json!({}), &s);

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
        let (s, _pty) = session_with_output(b"$ ");
        let v = with_detection(json!({}), &s);
        let map = v.as_object().expect("payload stays an object");
        assert!(
            map.contains_key("title"),
            "title must be emitted, not omitted"
        );
        assert_eq!(map["title"], Value::Null);
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
