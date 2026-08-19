//! The `{status, data, details}` response envelope (spec §5.1).

use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::ErrorData;
use serde_json::{json, Value};

/// Statuses used by the 0.0.1 tool set. The full taxonomy is spec §18.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Timeout,
    SessionDied,
    SessionNotFound,
    NameTaken,
    LimitReached,
    SpawnFailed,
    Unavailable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::SessionDied => "session_died",
            Self::SessionNotFound => "session_not_found",
            Self::NameTaken => "name_taken",
            Self::LimitReached => "limit_reached",
            Self::SpawnFailed => "spawn_failed",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether this status should surface as an MCP tool error.
    ///
    /// `Timeout` is deliberately absent: §18.1 lists it with
    /// `isError: false` because a deadline elapsing is an outcome the
    /// agent is expected to handle (retry, read output, terminate), not a
    /// failure that should halt its plan.
    pub fn is_error(self) -> bool {
        matches!(
            self,
            Self::SessionNotFound | Self::NameTaken | Self::LimitReached | Self::SpawnFailed
        )
    }
}

/// Build a `CallToolResult` carrying the envelope.
///
/// `content[0]` is the serialised envelope so clients that ignore
/// `structuredContent` still receive the data.
pub fn envelope(status: Status, data: Value, details: impl Into<String>) -> CallToolResult {
    let body = json!({
        "status": status.as_str(),
        "data": data,
        "details": details.into(),
    });
    let text = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
    let mut result = if status.is_error() {
        CallToolResult::structured_error(body)
    } else {
        CallToolResult::structured(body)
    };
    // `content` is `Vec<ContentBlock>`, not `Option<Vec<_>>`.
    result.content = vec![ContentBlock::text(text)];
    result
}

pub fn ok(data: Value, details: impl Into<String>) -> CallToolResult {
    envelope(Status::Ok, data, details)
}

/// Spec §18.1's `isError` column, keyed by the wire status string.
///
/// The control protocol carries `status` but not `isError` (§7.4.1), so
/// the shim re-derives the flag here. The table covers every §18.1 row,
/// not just the statuses this build can produce, so a status introduced
/// by a later milestone crosses the wire correctly without a protocol
/// change. An unrecognised status is treated as an error: a shim that is
/// older than its daemon must not downgrade an unknown failure into a
/// success the agent will act on.
pub fn status_is_error(status: &str) -> bool {
    !matches!(
        status,
        "ok" | "timeout"
            | "session_died"
            | "requires_confirmation"
            | "secret_provided"
            | "secret_cancelled"
            | "unavailable"
    )
}

/// Rebuild a `CallToolResult` from the `{status, data, details}` triple
/// that crossed the control protocol.
///
/// Unlike [`envelope`], the status is an opaque string rather than the
/// [`Status`] enum: the daemon is the authority on which statuses exist,
/// and a shim that only knew this build's variants would corrupt a newer
/// daemon's response into an enum variant it happened to match.
pub fn result_from_wire(status: &str, data: Value, details: impl Into<String>) -> CallToolResult {
    let body = json!({
        "status": status,
        "data": data,
        "details": details.into(),
    });
    let text = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
    let mut result = if status_is_error(status) {
        CallToolResult::structured_error(body)
    } else {
        CallToolResult::structured(body)
    };
    result.content = vec![ContentBlock::text(text)];
    result
}

/// Map a `ClaspError` onto the envelope.
///
/// Only the variants that have a catalogued `status` in spec §18.1 become
/// envelopes. `Pty` and `Io` have none: they mean the server failed to do
/// its job, which §5.1 routes to the *protocol* channel, not to
/// `isError: true`. Folding them into `session_died` (as an earlier draft
/// did) would tell the agent a lie it cannot detect — a failed write and
/// an exited child are different problems.
///
/// **Do not use this for `SessionDied` when you hold the session.** §18.1
/// requires `session_died` to carry `data.exit_code`, and `ClaspError::
/// SessionDied` is a unit variant with no code to extract, so the arm
/// below can only emit `data: {}`. A caller that has the `Session` must
/// build the envelope directly:
///
/// ```ignore
/// envelope(Status::SessionDied, json!({ "exit_code": session.exit_code() }), "…")
/// ```
///
/// The arm is kept only for callers that genuinely have no session in
/// hand. Routing a tool response through it produces a §18.1-noncompliant
/// payload that nothing will catch at compile time.
pub fn from_error(e: &crate::ClaspError) -> Result<CallToolResult, ErrorData> {
    use crate::ClaspError as E;
    let status = match e {
        E::SessionNotFound(_) => Status::SessionNotFound,
        E::NameTaken(_) => Status::NameTaken,
        E::LimitReached(_) => Status::LimitReached,
        E::SessionDied => Status::SessionDied,
        // Same caveat as `SessionDied` above: a caller that holds the
        // session should build the envelope directly so it can attach the
        // deadline it actually applied. §18.1 mandates no `data` fields
        // for `timeout`, so `data: {}` is at least not a lie.
        E::WriteTimeout => Status::Timeout,
        // A bad `prompt_patterns` regex is the caller's mistake, not
        // the server's, so it is an input-schema violation (§5.1)
        // rather than an envelope status.
        //
        // `brief` rather than `to_string`: this message is built from a
        // string the *caller* supplied, which is the one case where the
        // hazard `brief` documents is not hypothetical. The pattern is
        // already clipped where the error is constructed; this is the
        // guarantee at the boundary, so no future producer of this variant
        // can put an unbounded string into the transcript.
        E::InvalidPattern(_) => {
            return Err(ErrorData::invalid_params(brief(e), None));
        }
        E::Pty(_) | E::Io(_) => {
            return Err(ErrorData::internal_error(e.to_string(), None));
        }
    };
    Ok(envelope(status, json!({}), e.to_string()))
}

/// Trim a third-party error string before it enters the MCP transcript.
///
/// `portable-pty` embeds the entire `$PATH` in its "no viable candidates"
/// message; that is both noise and a small information leak into the
/// agent's conversation history.
pub fn brief(e: &dyn std::fmt::Display) -> String {
    const MAX: usize = 200;
    let s = e.to_string();
    let first = s.lines().next().unwrap_or("").trim().to_string();
    if first.chars().count() <= MAX {
        return first;
    }
    let truncated: String = first.chars().take(MAX).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(r: &CallToolResult) -> Value {
        r.structured_content.clone().expect("structured content")
    }

    #[test]
    fn ok_envelope_has_all_three_fields() {
        let r = ok(json!({"session_id": "sess_x"}), "started");
        let b = body_of(&r);
        assert_eq!(b["status"], "ok");
        assert_eq!(b["data"]["session_id"], "sess_x");
        assert_eq!(b["details"], "started");
        assert_ne!(r.is_error, Some(true));
    }

    #[test]
    fn content_zero_mirrors_structured_content() {
        let r = ok(json!({"n": 1}), "d");
        let raw = r.content[0].as_text().expect("text").text.clone();
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, body_of(&r));
    }

    #[test]
    fn hard_errors_set_is_error() {
        let r = envelope(Status::SessionNotFound, json!({}), "nope");
        assert_eq!(r.is_error, Some(true));
        assert_eq!(body_of(&r)["status"], "session_not_found");
    }

    #[test]
    fn spawn_failed_is_an_error() {
        let r = envelope(Status::SpawnFailed, json!({}), "no such program");
        assert_eq!(r.is_error, Some(true));
        assert_eq!(body_of(&r)["status"], "spawn_failed");
    }

    #[test]
    fn session_died_is_not_an_error() {
        let r = envelope(Status::SessionDied, json!({}), "exited");
        assert_ne!(r.is_error, Some(true));
    }

    #[test]
    fn timeout_is_not_an_error() {
        // §18.1 lists `timeout` with isError: false — a deadline elapsing
        // is something the agent handles, not something that should halt
        // its plan.
        let r = envelope(Status::Timeout, json!({}), "deadline elapsed");
        assert_eq!(body_of(&r)["status"], "timeout");
        assert_ne!(r.is_error, Some(true));
    }

    #[test]
    fn unavailable_is_not_an_error() {
        // §18.1 lists `unavailable` with isError: false. It is the answer
        // `get_command_history` gives a session with no OSC 133 markers,
        // and "this session has no shell integration" is an ordinary
        // outcome the agent handles, not a failure that should halt it.
        // Both halves are asserted: the wire spelling (nothing else pins
        // the `as_str` arm) and the error classification.
        let r = envelope(Status::Unavailable, json!({}), "no shell integration");
        assert_eq!(body_of(&r)["status"], "unavailable");
        assert_ne!(r.is_error, Some(true));
    }

    #[test]
    fn error_mapping_covers_the_registry_errors() {
        let cases = [
            (
                crate::ClaspError::SessionNotFound("a".into()),
                "session_not_found",
            ),
            (crate::ClaspError::NameTaken("b".into()), "name_taken"),
            (crate::ClaspError::LimitReached(8), "limit_reached"),
            (crate::ClaspError::SessionDied, "session_died"),
            (crate::ClaspError::WriteTimeout, "timeout"),
        ];
        for (err, expected) in cases {
            let r = from_error(&err).expect("catalogued status must be an envelope");
            assert_eq!(body_of(&r)["status"], expected);
        }
    }

    #[test]
    fn infrastructure_errors_are_protocol_errors_not_session_died() {
        for err in [
            crate::ClaspError::Pty("openpty failed".into()),
            crate::ClaspError::Io(std::io::Error::other("boom")),
        ] {
            assert!(
                from_error(&err).is_err(),
                "{err:?} must not be reported as a tool status"
            );
        }
    }

    #[test]
    fn an_invalid_pattern_is_a_bounded_invalid_params_error() {
        // Three separate things, none of which any other test pins.
        //
        // It must be a *protocol* error, not an envelope status: an agent
        // reads a status as a normal outcome and a protocol error as "I
        // sent something malformed", and a bad regex is the latter (§5.1).
        // It must be `invalid_params` rather than `internal_error`, which
        // would blame the server for the caller's mistake. And it must be
        // bounded — this message is built from a string the caller supplied,
        // and it lands in the MCP transcript for the rest of the session.
        let e = crate::ClaspError::InvalidPattern("x".repeat(5000));
        let err = from_error(&e).expect_err("a caller's bad regex is a protocol error");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.chars().count() <= 201,
            "{} chars reached the transcript",
            err.message.chars().count()
        );
    }

    #[test]
    fn brief_keeps_the_first_line_and_bounds_the_length() {
        let e = std::io::Error::other("spawn: no candidates\nPATH=\"/a/very/long/path\"");
        let s = brief(&e);
        assert_eq!(s, "spawn: no candidates");

        let long = std::io::Error::other("x".repeat(500));
        assert!(brief(&long).chars().count() <= 201, "bounded");
    }

    #[test]
    fn the_wire_status_table_agrees_with_the_status_enum() {
        // Two representations of §18.1's isError column: the enum, used
        // in-process, and the string table, used after a control-protocol
        // hop. If they disagree, the same tool call is an error on one
        // transport and a success on the other.
        //
        // `Timeout` is in this list deliberately. It is the newest status
        // (`send_input`'s write deadline, §5.2/§18.1), it is
        // `isError: false`, and it is exactly the kind of row a wire
        // table maintained by hand forgets — leaving the agent told that
        // a recoverable timeout was a hard failure.
        //
        // `Unavailable` is 0.0.2's and is live, not hypothetical
        // (`get_command_history` returns it), and it is the second
        // `isError: false` row — so it is exactly as easy to lose as
        // `Timeout` and belongs in this loop for the same reason.
        for s in [
            Status::Ok,
            Status::Timeout,
            Status::SessionDied,
            Status::SessionNotFound,
            Status::NameTaken,
            Status::LimitReached,
            Status::SpawnFailed,
            Status::Unavailable,
        ] {
            assert_eq!(
                status_is_error(s.as_str()),
                s.is_error(),
                "{} disagrees between the enum and the wire table",
                s.as_str()
            );
        }
    }

    #[test]
    fn an_unrecognised_status_is_treated_as_an_error() {
        // A shim older than its daemon must fail loudly, not quietly
        // hand the agent a failure dressed as a success.
        assert!(status_is_error("transfer_failed"));
        assert!(status_is_error("some_status_from_the_future"));
        assert!(!status_is_error("ok"));
    }

    #[test]
    fn result_from_wire_reproduces_the_in_process_envelope() {
        for (status, data, details) in [
            ("name_taken", json!({"n": 1}), "taken"),
            // The `timeout` row twice over: it must rebuild identically
            // *and* keep `isError` false across a transport that never
            // carries the flag.
            (
                "timeout",
                json!({"bytes_written": Value::Null, "timeout_ms": 5000}),
                "the child did not accept the input",
            ),
        ] {
            let enum_status = match status {
                "name_taken" => Status::NameTaken,
                "timeout" => Status::Timeout,
                other => panic!("unmapped status {other}"),
            };
            let direct = envelope(enum_status, data.clone(), details);
            let rebuilt = result_from_wire(status, data, details);
            assert_eq!(rebuilt.structured_content, direct.structured_content);
            assert_eq!(rebuilt.is_error, direct.is_error, "{status}");
            assert_eq!(
                rebuilt.content[0].as_text().unwrap().text,
                direct.content[0].as_text().unwrap().text
            );
        }
        assert_ne!(
            result_from_wire("timeout", json!({}), "").is_error,
            Some(true),
            "§18.1 lists timeout with isError:false; the wire must not upgrade it"
        );
    }
}
