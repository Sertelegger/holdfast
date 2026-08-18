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
    ///
    /// §18.3 writes the retriable cell as *"true (after restart)"*, and
    /// the qualifier is lost here because §7.4.1 makes the wire field a
    /// bare `bool` — there is nowhere to put it. It is recorded instead:
    /// the retry must follow a **reconnect**, since the connection this
    /// code arrived on is being torn down. A client that retries
    /// immediately on the same socket spins.
    pub fn retriable(self) -> bool {
        matches!(self, Self::DaemonShuttingDown)
    }

    /// Whether the connection must be closed after emitting this code.
    /// `unknown_method`, `bad_params` and `limit_reached` are per-request
    /// faults and leave the connection usable; `frame_too_large`,
    /// `no_handshake` and `protocol_violation` mean the peer is
    /// mis-framing or unwelcome (§7.4, §18.3). `daemon_shutting_down` is
    /// in neither group and answers `false` deliberately: the daemon
    /// does close that connection, but on its own schedule and not on
    /// this code's account, so a peer must not read the code as the
    /// instruction.
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

    /// Whether this is a §7.4.1 **transport**-level error response.
    ///
    /// Scope matters: this answers the control protocol's two-valued
    /// `status` (`"ok"` / `"error"`), not §18.1's tool-status vocabulary.
    /// A tool-passthrough response carrying `status: "session_not_found"`
    /// is a *successful* control exchange and answers `false` here;
    /// `envelope::status_is_error` is the §18.1 question.
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

    #[test]
    fn method_names_are_the_7_4_1_catalogue_strings() {
        // Both peers are built from this crate, so every other use in
        // this milestone and the ones after it is `method::METHOD_*`
        // against `method::METHOD_*`. A typo in a const round-trips
        // against itself perfectly and fails only against a peer built
        // from §7.4.1 — verbatim the argument `frame.rs` makes for the
        // big-endian length prefix, one layer up. The **literals** are
        // the pinning; replacing them with the constants deletes the
        // test while leaving it green.
        assert_eq!(METHOD_HANDSHAKE, "clasp/handshake");
        assert_eq!(METHOD_DAEMON_STATUS, "daemon/status");
        assert_eq!(METHOD_DAEMON_STOP, "daemon/stop");
        assert_eq!(TOOL_METHOD_PREFIX, "tool/");
    }

    #[test]
    fn frame_bodies_are_cbor_maps_keyed_by_the_7_4_1_field_names() {
        // §7.4 is normative on the body — `{ id, method, params }` and
        // `{ id, status, data, details }` — and §7.4.1 adds that "the
        // wire form is CBOR with the same field names".
        //
        // The round-trip tests below cannot see this: they encode and
        // decode through the *same* derived serde impls, so they stay
        // green against integer keys, a `#[serde(rename_all)]`, or a
        // ciborium change to how it represents structs. Decoding the
        // body as a raw CBOR map is the only formulation that fails
        // against a peer built from §7.4.1. A **set** comparison is
        // right here: §7.4 fixes the field names, not a map order.
        fn field_names<T: Serialize>(value: &T) -> Vec<String> {
            let framed = frame::encode(value).unwrap();
            let body: CborValue = frame::decode(&framed[frame::LENGTH_PREFIX_BYTES..]).unwrap();
            let CborValue::Map(entries) = body else {
                panic!("§7.4's body is a map, got {body:?}")
            };
            let mut keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| {
                    k.as_text()
                        .expect("text keys — an integer-keyed map is a different wire format")
                        .to_owned()
                })
                .collect();
            keys.sort_unstable();
            keys
        }

        assert_eq!(
            field_names(&Request::new(1, "tool/read_output", &probe()).unwrap()),
            ["id", "method", "params"]
        );
        assert_eq!(
            field_names(&Response::ok(1, &probe(), "done").unwrap()),
            ["data", "details", "id", "status"]
        );
    }

    #[test]
    fn tool_name_strips_the_prefix_and_answers_none_for_every_other_method() {
        // The positive case alone is passed by a mutant returning
        // `self.method.rsplit('/').next()`, which would then report
        // `daemon/status` as tool `status` — and 0.0.2 ships a `status`
        // MCP tool, so that mutant routes a daemon-internal method into
        // the tool dispatcher. The negatives are what separate a prefix
        // strip from a last-segment split.
        let tool = Request::new(1, "tool/read_output", &()).unwrap();
        assert_eq!(tool.tool_name(), Some("read_output"));

        for method in [METHOD_HANDSHAKE, METHOD_DAEMON_STATUS, METHOD_DAEMON_STOP] {
            let req = Request::new(2, method, &()).unwrap();
            assert_eq!(req.tool_name(), None, "{method} is not a tool method");
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

    #[tokio::test]
    async fn error_response_carries_the_catalogued_code_and_retriability() {
        // Round-tripped through the frame codec rather than inspected in
        // memory: this payload is what every failure path on the wire
        // sends, and only the `ok` response was proven to survive it.
        let sent = Response::error(3, ErrorCode::DaemonShuttingDown, "stopping");
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &sent).await.unwrap();
        let r: Response = frame::read_frame(&mut buf.as_slice()).await.unwrap();
        assert_eq!(r, sent);

        let e = r.control_error().expect("error payload");
        assert_eq!(e.code, "daemon_shutting_down");
        assert_eq!(e.message, "stopping");
        assert!(e.retriable, "§18.3 marks this code retriable");
        assert_eq!(r.details, "stopping");
        assert!(r.is_error());

        let r = Response::error(4, ErrorCode::BadParams, "nope");
        assert!(!r.control_error().unwrap().retriable);
    }

    #[test]
    fn an_ok_response_has_no_control_error_even_when_its_data_is_shaped_like_one() {
        // The fixture is adversarial on purpose. With `probe()` as the
        // data this test is green even with `control_error`'s
        // `if !self.is_error()` guard **deleted** — a `Probe` fails to
        // deserialise as a `ControlError` anyway, so `.ok()` yields
        // `None` either way, and the test would be asserting that a
        // `Probe` is not shaped like a `ControlError` rather than that
        // the *status* decides. A payload that decodes cleanly leaves
        // the status as the only thing that can answer.
        let payload = ControlError {
            code: ErrorCode::BadParams.as_str().into(),
            message: "m".into(),
            retriable: false,
        };
        let r = Response::ok(1, &payload, "").unwrap();
        assert!(
            r.data_as::<ControlError>().is_ok(),
            "the fixture must decode as a ControlError, or the assertion below is vacuous"
        );
        assert!(r.control_error().is_none(), "status decides, not shape");
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

        // The literal above is deliberately not in alphabetical order,
        // which is what makes it a *sequence* check rather than a
        // disguised set comparison. An earlier draft said so with
        // `assert_ne!(sorted, seen)` — a line that cannot fail, because
        // the `assert_eq!` above already pins `seen` to a literal that
        // is not sorted, so any mutation reaching it has panicked one
        // assertion earlier. Its only reachable future was a red on
        // correct code if §18.3 were ever reordered alphabetically.
        // Demoted to this comment rather than left as dead ceremony.
    }

    // §18.3's "Retriable" and closing columns are separate tests, not
    // more assertions on the sequence test above: they are independent
    // properties, and the plan's own step asks for two of them to go red
    // under one mutation — which the first panic would hide if they
    // shared a test.

    #[test]
    fn exactly_daemon_shutting_down_is_the_retriable_row() {
        // Naming both ends — the count and the two named rows — stops a
        // mutation that *moves* which row is true from passing on the
        // count alone.
        assert_eq!(ErrorCode::ALL.iter().filter(|c| c.retriable()).count(), 1);
        assert!(ErrorCode::DaemonShuttingDown.retriable());
        assert!(!ErrorCode::LimitReached.retriable());
    }

    #[test]
    fn exactly_three_codes_close_the_connection() {
        // §18.3's closing column, and `limit_reached` is not in it.
        // Without this the new variant could join `closes_connection`'s
        // `matches!` unnoticed, and a full bridge table would drop a
        // control connection the caller still needs for every other
        // method. A sequence assertion again, for the same reason.
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
        //
        // The bstr is wrapped in a one-entry map because §7.4 declares
        // `params: object`; a top-level `CborValue::Bytes` is a shape
        // the wire format does not permit, and the next reader would
        // copy it.
        let raw = vec![0x00, 0x1b, 0x5b, 0xff, 0x7f];
        let params = CborValue::Map(vec![(
            CborValue::Text("data".into()),
            CborValue::Bytes(raw.clone()),
        )]);
        let req = Request {
            id: 1,
            method: "tool/send_input".into(),
            params: params.clone(),
        };
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &req).await.unwrap();
        let back: Request = frame::read_frame(&mut buf.as_slice()).await.unwrap();
        let CborValue::Map(entries) = &back.params else {
            panic!("§7.4's params is an object, got {:?}", back.params)
        };
        assert_eq!(
            entries[0].1,
            CborValue::Bytes(raw),
            "still a bstr, not an array of integers"
        );
        assert_eq!(back.params, params);
    }
}
