//! Control-protocol request/response types, the method-name constants
//! from spec §7.4.1, and the error-code catalog from §18.3.

use super::frame::FrameError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// CBOR is the wire encoding, so `params` and `data` are CBOR values —
/// not `serde_json::Value`, which cannot represent a byte string.
pub type CborValue = ciborium::Value;

/// Namespace prefix for MCP-tool-passthrough methods (§7.4.1).
pub const TOOL_METHOD_PREFIX: &str = "tool/";

/// The connect handshake. Must be the first method on every connection.
pub const METHOD_HANDSHAKE: &str = "clasp/handshake";
/// Daemon introspection, behind `clasp daemon status`.
pub const METHOD_DAEMON_STATUS: &str = "daemon/status";
/// Graceful daemon shutdown, behind `clasp daemon stop`.
pub const METHOD_DAEMON_STOP: &str = "daemon/stop";

/// `{ id, method, params }` — spec §7.4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    pub params: CborValue,
}

/// `{ id, status, data, details }` — spec §7.4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub status: String,
    pub data: CborValue,
    pub details: String,
}

/// The `data` payload of an error response (§7.4.1, "Common error
/// response shape").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlError {
    pub code: String,
    pub message: String,
    pub retriable: bool,
}

/// Spec §18.3, complete, and **in §18.3's row order**. Producers select
/// from this enum rather than inventing strings; adding a variant is a
/// spec change.
///
/// The order is normative, not stylistic: §18's preamble states that a
/// table there fixes its enum's order as well as its membership, so a
/// value is **inserted at its catalogued position and never appended**.
/// That sentence is in §18's preamble rather than inside §18.1, and it
/// says *"where an implementation mirrors a table in this section as an
/// enum"* — so it reaches this enum. `LimitReached` is sixth of seven —
/// between `ProtocolViolation` and `DaemonShuttingDown` — because that
/// is where §18.3 puts `limit_reached`.
///
/// **This build declares `LimitReached` and produces it nowhere.** §18.3
/// gives it exactly one v0.1.0 producer, `bridge/register` refused
/// against `max_bridge_sessions` (§4.2, §7.6.1), and `bridge/*` is
/// 0.0.10's. It is declared here anyway, for the same reason
/// `envelope::status_is_error` covers every §18.1 row rather than only
/// the statuses this build can emit: a new error code is additive and
/// does **not** move `PROTOCOL_MAJOR` (§23.3), so a client built at this
/// milestone can meet `limit_reached` from a later daemon on the same
/// major. `from_wire` answering `None` there would leave that client
/// guessing at `closes_connection()` — the one thing `from_wire`'s own
/// doc comment says it must not do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnknownMethod,
    BadParams,
    FrameTooLarge,
    NoHandshake,
    ProtocolViolation,
    LimitReached,
    DaemonShuttingDown,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownMethod => "unknown_method",
            Self::BadParams => "bad_params",
            Self::FrameTooLarge => "frame_too_large",
            Self::NoHandshake => "no_handshake",
            Self::ProtocolViolation => "protocol_violation",
            Self::LimitReached => "limit_reached",
            Self::DaemonShuttingDown => "daemon_shutting_down",
        }
    }

    /// Only `daemon_shutting_down` is worth retrying (§18.3).
    ///
    /// `limit_reached` is **not** retriable and §18.3 says why in as many
    /// words: *"nothing the caller can do makes room; the operator
    /// revokes or waits for a TTL"*. A caller that retried it would spin.
    pub fn retriable(self) -> bool {
        matches!(self, Self::DaemonShuttingDown)
    }

    /// Whether the connection must be closed after emitting this code.
    /// `unknown_method`, `bad_params` and `limit_reached` are per-request
    /// faults and leave the connection usable; the other three mean the
    /// peer is mis-framing or unwelcome (§7.4, §18.3).
    ///
    /// `limit_reached` is in the *first* group deliberately. §18.3 marks
    /// only `frame_too_large` as closing, and the caller that meets
    /// `limit_reached` is a `bridge/register` (0.0.10) on a connection it
    /// still needs for every other method — tearing it down would turn a
    /// full table into a dropped client.
    pub fn closes_connection(self) -> bool {
        matches!(
            self,
            Self::FrameTooLarge | Self::NoHandshake | Self::ProtocolViolation
        )
    }

    /// Every code in §18.3, **in §18.3's row order**. The single list the
    /// dispatcher, the tests and [`ErrorCode::from_wire`] all read from.
    /// The order is asserted as a sequence below, not as a set — see
    /// `error_codes_are_the_spec_18_3_table_in_catalog_order`.
    pub const ALL: [Self; 7] = [
        Self::UnknownMethod,
        Self::BadParams,
        Self::FrameTooLarge,
        Self::NoHandshake,
        Self::ProtocolViolation,
        Self::LimitReached,
        Self::DaemonShuttingDown,
    ];

    /// Recover a code from its wire string. `None` for anything not in
    /// §18.3 — a newer daemon's code, which this build must not guess at.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// Serialise any `Serialize` value into a CBOR value.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<CborValue, FrameError> {
    CborValue::serialized(value).map_err(|e| FrameError::Cbor(e.to_string()))
}

/// Deserialise a CBOR value into any `DeserializeOwned` type.
pub fn from_cbor<T: DeserializeOwned>(value: &CborValue) -> Result<T, FrameError> {
    value
        .deserialized()
        .map_err(|e| FrameError::Cbor(e.to_string()))
}

impl Request {
    pub fn new<P: Serialize>(
        id: u64,
        method: impl Into<String>,
        params: &P,
    ) -> Result<Self, FrameError> {
        Ok(Self {
            id,
            method: method.into(),
            params: to_cbor(params)?,
        })
    }

    pub fn params_as<T: DeserializeOwned>(&self) -> Result<T, FrameError> {
        from_cbor(&self.params)
    }

    /// The tool name behind a `tool/<name>` method, if this is one.
    pub fn tool_name(&self) -> Option<&str> {
        self.method.strip_prefix(TOOL_METHOD_PREFIX)
    }
}

impl Response {
    pub fn ok<D: Serialize>(
        id: u64,
        data: &D,
        details: impl Into<String>,
    ) -> Result<Self, FrameError> {
        Ok(Self {
            id,
            status: "ok".into(),
            data: to_cbor(data)?,
            details: details.into(),
        })
    }

    /// Build the §7.4.1 error response.
    ///
    /// Infallible on purpose: `ControlError` is three owned primitives,
    /// so its CBOR encoding cannot fail, and a fallible constructor here
    /// would give every error path an error path of its own.
    pub fn error(id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        let payload = ControlError {
            code: code.as_str().into(),
            message: message.clone(),
            retriable: code.retriable(),
        };
        Self {
            id,
            status: "error".into(),
            data: to_cbor(&payload).unwrap_or(CborValue::Null),
            details: message,
        }
    }

    pub fn is_error(&self) -> bool {
        self.status == "error"
    }

    pub fn data_as<T: DeserializeOwned>(&self) -> Result<T, FrameError> {
        from_cbor(&self.data)
    }

    /// The `ControlError` payload, if this is an error response.
    pub fn control_error(&self) -> Option<ControlError> {
        if !self.is_error() {
            return None;
        }
        self.data_as().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::super::frame;
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Probe {
        session: String,
        cursor: u64,
    }

    fn probe() -> Probe {
        Probe {
            session: "sess_abc".into(),
            cursor: 4096,
        }
    }

    #[tokio::test]
    async fn request_survives_a_frame_round_trip_with_typed_params() {
        let req = Request::new(7, "tool/read_output", &probe()).unwrap();
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &req).await.unwrap();
        let back: Request = frame::read_frame(&mut buf.as_slice()).await.unwrap();

        assert_eq!(back.id, 7);
        assert_eq!(back.method, "tool/read_output");
        assert_eq!(back.tool_name(), Some("read_output"));
        assert_eq!(back.params_as::<Probe>().unwrap(), probe());
    }

    #[tokio::test]
    async fn response_survives_a_frame_round_trip() {
        let resp = Response::ok(9, &probe(), "done").unwrap();
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &resp).await.unwrap();
        let back: Response = frame::read_frame(&mut buf.as_slice()).await.unwrap();
        assert_eq!(back, resp);
        assert!(!back.is_error());
        assert_eq!(back.details, "done");
        assert_eq!(back.data_as::<Probe>().unwrap(), probe());
    }

    #[test]
    fn error_response_carries_the_catalogued_code_and_retriability() {
        let r = Response::error(3, ErrorCode::DaemonShuttingDown, "stopping");
        let e = r.control_error().expect("error payload");
        assert_eq!(e.code, "daemon_shutting_down");
        assert_eq!(e.message, "stopping");
        assert!(e.retriable, "§18.3 marks this code retriable");
        assert_eq!(r.details, "stopping");

        let r = Response::error(4, ErrorCode::BadParams, "nope");
        assert!(!r.control_error().unwrap().retriable);
    }

    #[test]
    fn ok_responses_have_no_control_error_payload() {
        let r = Response::ok(1, &probe(), "").unwrap();
        assert!(r.control_error().is_none());
    }

    #[test]
    fn error_codes_are_the_spec_18_3_table_in_catalog_order() {
        // A **sequence** assertion, not a set one — and this one is
        // the plan's choice rather than a requirement's. §18's preamble
        // binds this enum's *order*; REQ-T-017 is the row that turns
        // that rule into an asserted one, and its asserted set is
        // §18.1's `$defs.Status.enum` plus §18.2a's arrays. §18.3 is
        // not in it. So the rule binds here with nothing checking it,
        // and this test is what closes that gap: a sorted comparison
        // cannot detect the one violation the rule names. The version
        // this replaces sorted both sides, so it stayed green against
        // `limit_reached` appended seventh instead of inserted sixth,
        // which is precisely the edit §18.3 took at rev. 47.
        let seen: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            seen,
            vec![
                "unknown_method",
                "bad_params",
                "frame_too_large",
                "no_handshake",
                "protocol_violation",
                "limit_reached",
                "daemon_shutting_down",
            ],
            "§18.3's rows, in §18.3's order"
        );

        // The negative that separates "in order" from "the right set".
        // If §18.3 happened to be alphabetical the assertion above could
        // not tell one from the other; it is not, and this row is what
        // says so out loud rather than leaving it to be noticed.
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        assert_ne!(
            sorted, seen,
            "§18.3 is not in alphabetical order, so the assertion above \
             is a sequence check and not a disguised set comparison"
        );

        // §18.3's "Retriable" column: exactly one row is true, and it is
        // `daemon_shutting_down`. Naming both ends stops a mutation that
        // moves which row is true from passing the count.
        assert_eq!(ErrorCode::ALL.iter().filter(|c| c.retriable()).count(), 1);
        assert!(ErrorCode::DaemonShuttingDown.retriable());
        assert!(!ErrorCode::LimitReached.retriable());

        // §18.3's closing column: exactly three codes close, and
        // `limit_reached` is not one of them. Without this arm the new
        // variant could join `closes_connection`'s `matches!` unnoticed,
        // and a full bridge table would drop a control connection the
        // caller still needs for every other method.
        let closing: Vec<&str> = ErrorCode::ALL
            .iter()
            .filter(|c| c.closes_connection())
            .map(|c| c.as_str())
            .collect();
        assert_eq!(
            closing,
            vec!["frame_too_large", "no_handshake", "protocol_violation"],
            "§7.4/§18.3: these three close the connection and nothing else does"
        );
    }

    #[test]
    fn from_wire_round_trips_every_code_and_rejects_the_unknown() {
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_wire(code.as_str()), Some(code));
        }
        // A code this build has never heard of must not be coerced into
        // one it has — `closes_connection` would then be a guess.
        assert_eq!(ErrorCode::from_wire("a_code_from_the_future"), None);
    }

    #[tokio::test]
    async fn params_carry_raw_bytes_intact() {
        // The reason §7.4 chose CBOR. A JSON transport would have to
        // base64 this, and the equality below would fail.
        let raw = vec![0x00, 0x1b, 0x5b, 0xff, 0x7f];
        let req = Request {
            id: 1,
            method: "tool/send_input".into(),
            params: CborValue::Bytes(raw.clone()),
        };
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &req).await.unwrap();
        let back: Request = frame::read_frame(&mut buf.as_slice()).await.unwrap();
        assert_eq!(back.params, CborValue::Bytes(raw));
    }
}
