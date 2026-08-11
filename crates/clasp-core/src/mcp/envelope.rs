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
}
