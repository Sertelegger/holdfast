//! The hybrid-mode MCP server (spec §3.3): an MCP server whose tool
//! handlers are thin RPC calls into a daemon.
//!
//! `ShimServer` declares no tools of its own: `call_tool` forwards by
//! name, so no tool *behaviour* lives outside `holdfast-core`, which is
//! what §3.5 means in practice.
//!
//! **`list_tools` is answered locally, not fetched.** This said the
//! opposite — that the manifest came from the daemon "verbatim" — and it
//! did not: [`passthrough::tool_manifest`] is
//! `HoldfastServer::tool_router().list_all()`, a static call **in the
//! shim's own process**, and §7.4.1 defines no `tool/list` method by
//! which one could be fetched. `is_passthrough_tool`, the guard on
//! `call_tool`, reads the same local set.
//!
//! It matters because §7.4.1 **explicitly permits** shim/daemon minor
//! skew (*"Same-major different-minor is forwards/backwards
//! compatible"*). Under that skew: a tool a daemon minor added is
//! invisible to an older shim, and a tool this shim knows and the daemon
//! lacks is advertised and then answered `unknown_method` — which
//! [`rebuild_tool_error`] now reports as `invalid_params`, matching what
//! an unknown tool gets in-process, rather than as a server fault.
//!
//! `every_router_tool_is_dispatchable` builds both sides from one
//! process and cannot see any of this. Closing it properly needs a
//! manifest method on the control protocol, which is a protocol addition
//! for a later milestone; what is fixed here is the description and the
//! one code the skew makes reachable.

use super::passthrough;
use crate::protocol::client::{ClientError, ControlClient};
use crate::protocol::method::{self, TOOL_METHOD_PREFIX};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub struct ShimServer {
    client: Arc<ControlClient>,
}

impl ShimServer {
    pub fn new(client: Arc<ControlClient>) -> Self {
        Self { client }
    }

    /// Forward one tool call to the daemon and rebuild the MCP result.
    ///
    /// §7.4.1 fixes the mapping this implements, and the whole of it:
    /// the method is `tool/<tool_name>`, `params` **is** the MCP
    /// `arguments` — not a wrapper around them — and the response's
    /// `data`, `status` and `details` map onto the envelope's three
    /// fields. `the_shim_puts_7_4_1s_own_field_names_on_the_wire`
    /// asserts each of those against a hand-built CBOR map rather than
    /// against a round-trip through these same types.
    async fn forward(
        &self,
        tool: &str,
        arguments: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = Value::Object(arguments.unwrap_or_default());
        let params =
            method::to_cbor(&args).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let resp = self
            .client
            .call_raw(&format!("{TOOL_METHOD_PREFIX}{tool}"), params)
            .await
            .map_err(map_client_error)?;

        if let Some(e) = resp.control_error() {
            return Err(rebuild_tool_error(e));
        }

        let data: Value = method::from_cbor(&resp.data)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(passthrough::outcome_to_result(passthrough::ToolOutcome {
            status: resp.status,
            data,
            details: resp.details,
        }))
    }

    /// One `resource/*` round trip, returning the response `data`.
    ///
    /// The error path goes through [`rebuild_resource_error`] rather than
    /// [`rebuild_error`], because §5.5.2 requires a *structured*
    /// `data.code` that the control protocol has nowhere to carry and the
    /// daemon therefore encodes into the error message.
    async fn forward_resource(&self, method: &str, params: Value) -> Result<Value, ErrorData> {
        let params =
            method::to_cbor(&params).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let resp = self
            .client
            .call_raw(method, params)
            .await
            .map_err(map_client_error)?;
        if let Some(e) = resp.control_error() {
            return Err(rebuild_resource_error(e));
        }
        method::from_cbor(&resp.data).map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }
}

/// Rebuild the MCP error the agent would have seen in-process from
/// §7.4.1's error payload.
///
/// **`rpc_code` wins outright when the daemon sent one.** The control
/// protocol has no room for the JSON-RPC codes an MCP handler raises, so
/// the daemon flattens every `Err(ErrorData)` onto §18.3's nearest row,
/// `bad_params`. Rebuilding from `code` alone therefore reported every
/// *internal* fault as the agent's own bad argument: `openpty failed`
/// arrived as `invalid_params` here and as `internal_error` under
/// `--no-daemon`, so the two transports disagreed about whose fault it
/// was. `rpc_code` is the daemon's record of what the handler really
/// raised, and it is the whole of the answer when it is present.
///
/// Without it — a daemon one minor behind, or any control-protocol fault
/// that never came from a tool — the original mapping stands.
/// `bad_params` is `invalid_params`, which is right for §5.5.2's
/// validation faults; everything else is a server fault and says which
/// §18.3 code it was.
fn rebuild_error(e: method::ControlError) -> ErrorData {
    if let Some(code) = e.rpc_code {
        return ErrorData::new(rmcp::model::ErrorCode(code), e.message, None);
    }
    if e.code == method::ErrorCode::BadParams.as_str() {
        ErrorData::invalid_params(e.message, None)
    } else {
        ErrorData::internal_error(format!("[{}] {}", e.code, e.message), None)
    }
}

/// [`rebuild_error`], plus the one §18.3 code whose meaning is
/// transport-specific on a `tool/*` call.
///
/// **`unknown_method` on a tool call means "no such tool", and an
/// unknown tool is `-32602` on the MCP wire.** rmcp's router answers
/// `invalid_params("tool not found")` in-process, and `call_tool`'s own
/// guard two functions down answers `invalid_params` for a name outside
/// the manifest. Falling through to [`rebuild_error`] made the daemon's
/// answer `internal_error` instead — the same call, two diagnoses,
/// decided by which transport was in use.
///
/// Not hypothetical: §7.4.1 permits shim/daemon minor skew, and a tool
/// this shim advertises and an older daemon does not have lands exactly
/// here. `internal_error` tells the agent to give up on a server bug
/// where `invalid_params` tells it the tool does not exist, which is
/// both true and actionable.
///
/// `rpc_code` still wins when the daemon sent one, for
/// [`rebuild_error`]'s reason: it is the handler's own code, and this
/// arm is a guess made in its absence.
fn rebuild_tool_error(e: method::ControlError) -> ErrorData {
    if e.rpc_code.is_none() && e.code == method::ErrorCode::UnknownMethod.as_str() {
        return ErrorData::invalid_params(e.message, None);
    }
    rebuild_error(e)
}

/// [`rebuild_error`], plus the `{message, data}` envelope the daemon
/// writes for a `resource/read` fault.
///
/// **§5.5.2's four codes are structured `data`, not prose.** The
/// in-process transport answers a bad URI with
/// `ErrorData::invalid_params(message, Some({"code": "invalid_enum",
/// "param": "ansi", "value": "purple", "allowed": [...]}))` and an agent
/// branches on `data.code` to know whether to fix a name, a value or a
/// range. `ControlError` has nowhere to put that object, so
/// `daemon::server::dispatch_resource` JSON-encodes `{message, data}`
/// into the error *message* — and the rebuild here never decoded it. The
/// agent got a raw JSON blob where prose belongs and `data: null` where
/// the four codes belong, on the transport that is the default.
///
/// This is the decode for that encode. Nothing new crosses the wire: the
/// same bytes already travelled, in the wrong field.
///
/// Conservative about what it will unwrap — exactly the two keys, a
/// string `message` — because a §5.5.2 message is prose and any other
/// producer's message must be left alone. A message that is not this
/// envelope falls through unchanged.
fn rebuild_resource_error(e: method::ControlError) -> ErrorData {
    let mut out = rebuild_error(e);
    if let Some((message, data)) = decode_resource_envelope(&out.message) {
        out.message = message.into();
        out.data = data;
    }
    out
}

/// The `{message, data}` object `dispatch_resource` encodes, parsed back
/// out. `None` for anything else, including plain prose.
///
/// `data: null` becomes `None` rather than `Some(Value::Null)`: the
/// daemon writes `null` there for an `ErrorData` that carried no
/// structured payload — `resource_not_found`, for one — and
/// `Some(Value::Null)` would put a literal `"data": null` on the MCP wire
/// where the in-process transport omits the field.
fn decode_resource_envelope(message: &str) -> Option<(String, Option<Value>)> {
    let parsed: Value = serde_json::from_str(message).ok()?;
    let obj = parsed.as_object()?;
    // Both keys and only those two. A message that merely *happens* to
    // be a JSON object is not this envelope.
    if obj.len() != 2 || !obj.contains_key("data") {
        return None;
    }
    let message = obj.get("message")?.as_str()?.to_string();
    let data = match obj.get("data") {
        Some(Value::Null) | None => None,
        Some(d) => Some(d.clone()),
    };
    Some((message, data))
}

/// The daemon-backed server's `instructions`, **derived** from the
/// in-process text rather than copied from it.
///
/// Both transports build `list_tools` from the same in-process
/// `HoldfastServer::tool_router()`, so every tool description, output
/// schema and annotation already has exactly one definition — *derived*
/// on both sides rather than forwarded, which this comment used to
/// claim. That leaves `instructions` as the one agent-visible string
/// with no shared derivation of its own, so it is built from
/// [`super::INSTRUCTIONS`] and differs by exactly one appended sentence
/// — the single fact that is genuinely transport-specific.
///
/// A second hand-written copy would have been stale the day it was
/// written. 0.0.2 rewrote that string because it still described a
/// four-tool 0.0.1 surface, and 0.0.3 rewrote its closing sentence from
/// "returned raw and unredacted" to the redaction contract — neither
/// edit would have reached a copy living here, and hybrid mode is the
/// *default* transport, so the copy is the text most agents would read.
fn instructions() -> String {
    format!(
        "{} Sessions live in a background daemon and survive this connection.",
        super::INSTRUCTIONS
    )
}

fn map_client_error(e: ClientError) -> ErrorData {
    // §3.2: an unreachable daemon is a JSON-RPC internal error carrying
    // `data.reason = "daemon_unreachable"`, not a tool status.
    ErrorData::internal_error(
        "Internal error".to_string(),
        Some(serde_json::json!({
            "reason": "daemon_unreachable",
            "detail": e.to_string(),
        })),
    )
}

impl ServerHandler for ShimServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        // **`shim_capabilities`, not `server_capabilities`.** The
        // difference is `resources.listChanged`, which this transport
        // cannot deliver: the forwarder that turns a pulse into an MCP
        // notification is `HoldfastServer::on_initialized`, and in hybrid
        // mode that object runs inside the daemon with no MCP peer to
        // notify. See `super::shim_capabilities` for the deferral.
        info.capabilities = super::shim_capabilities();
        info.server_info = Implementation::new("clasp", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(instructions());
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(passthrough::tool_manifest()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        // The guard reads the daemon-side manifest, so it needs no
        // updating when a milestone adds a tool.
        if !passthrough::is_passthrough_tool(&name) {
            return Err(ErrorData::invalid_params(format!("no tool {name}"), None));
        }
        Ok(self.forward(&name, request.arguments).await?.into())
    }

    // §5.5's three methods, forwarded to §7.4.1's three control methods.
    // **The spellings differ on the two wires** — MCP says
    // `resources/templates/list`, the control protocol says
    // `resource/templates_list` — and the constants below are the only
    // place that mapping is written down.
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let data = self
            .forward_resource(method::METHOD_RESOURCE_LIST, json!({}))
            .await?;
        let resources = serde_json::from_value(data.get("resources").cloned().unwrap_or(json!([])))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let data = self
            .forward_resource(method::METHOD_RESOURCE_TEMPLATES_LIST, json!({}))
            .await?;
        let templates =
            serde_json::from_value(data.get("resourceTemplates").cloned().unwrap_or(json!([])))
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(ListResourceTemplatesResult::with_all_items(templates))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let data = self
            .forward_resource(method::METHOD_RESOURCE_READ, json!({ "uri": request.uri }))
            .await?;
        let result: ReadResourceResult = serde_json::from_value(data)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(result.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame;
    use crate::protocol::handshake::{self, ClientKind, HandshakeData};
    use crate::protocol::method::{CborValue, Request, Response};
    use serde_json::json;
    use std::path::PathBuf;

    /// Kills the mutation of hand-writing a second `instructions`
    /// literal here instead of deriving one. That copy cannot be kept in
    /// step by review: it says nothing wrong on the day it lands and
    /// goes stale the next time anyone edits the in-process string.
    ///
    /// `instructions()` is a free function precisely so this test can
    /// run without a `ControlClient` and therefore without a socket.
    #[test]
    fn the_shim_derives_its_instructions_from_the_in_process_ones() {
        let text = instructions();
        let shared = crate::mcp::INSTRUCTIONS;
        // The positive: everything the in-process server tells an agent
        // — the tool names `scripts/mcp-smoke.sh` asserts on, and the
        // output-handling sentence — is present here verbatim.
        assert!(
            text.starts_with(shared),
            "the shim's instructions must be the shared text plus a suffix, not a second copy"
        );
        let suffix = &text[shared.len()..];
        // The negative that separates that from the degenerate case:
        // `starts_with` is equally satisfied by an empty suffix, and the
        // one fact this transport must add for itself is that a session
        // outlives the connection that created it.
        assert!(
            suffix.contains("daemon"),
            "hybrid mode must still say sessions live in a daemon; suffix was {suffix:?}"
        );
        // And the suffix must not re-describe what the shared text
        // already covers: output handling has exactly one home, so a
        // stale "raw and unredacted" claim cannot be reintroduced here
        // after 0.0.3 removes it there.
        assert!(
            !suffix.contains("unredacted"),
            "output handling is described once, in the shared text; suffix was {suffix:?}"
        );
    }

    /// REQ-R-006 has no delivery path on this transport, so the
    /// handshake must not claim one.
    ///
    /// `HoldfastServer::on_initialized` is the only thing in the tree that
    /// turns a `resource_list_changed` pulse into an MCP notification,
    /// and it needs the MCP peer. In hybrid mode the `HoldfastServer` lives
    /// in the daemon, where there is no peer: the pulse goes into a
    /// broadcast channel with zero receivers, and §7.4.1's streaming
    /// frames are reserved and unused in v0.1.0, so nothing carries it
    /// across. An agent told `listChanged: true` holds a stale
    /// `resources/list` for the life of the connection.
    ///
    /// **Read through `get_info`, not off the free function.** A test
    /// that compared `shim_capabilities()` with `server_capabilities()`
    /// would be green while `get_info` went on returning the wrong one
    /// — which is the defect, exactly.
    ///
    /// The last assertion is the pairing: without it a build that
    /// dropped the notification from *both* transports passes, and that
    /// would be a regression on the transport that can deliver it.
    #[tokio::test]
    async fn the_shim_does_not_advertise_the_notification_it_cannot_deliver() {
        let dir = scratch_dir("caps");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");
        // No request is issued, so the reply template is never used; the
        // stand-in is here only to complete the handshake `connect`
        // needs.
        let _captured = stand_in_daemon(sock.clone(), CborValue::Map(vec![]));
        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let caps = shim.get_info().capabilities;
        let resources = caps
            .resources
            .expect("§5.5's resources capability is served on both transports");
        assert_eq!(
            resources.list_changed, None,
            "hybrid mode has no path from the daemon's pulse to the MCP peer, \
             so advertising `listChanged` promises a notification that is dropped"
        );
        // The rest of the surface is unchanged: this is one capability
        // withdrawn, not the resources surface retreating.
        assert!(
            caps.tools.is_some(),
            "the shim still serves tools/list and tools/call"
        );

        let in_process = crate::mcp::HoldfastServer::new()
            .get_info()
            .capabilities
            .resources
            .expect("§5.5's resources capability in-process");
        assert_eq!(
            in_process.list_changed,
            Some(true),
            "`--no-daemon` holds the MCP peer in `on_initialized` and does \
             deliver the notification; withdrawing it there too would be a \
             regression, and would satisfy the assertion above"
        );
    }

    /// A `/tmp` path short enough for `sockaddr_un.sun_path`.
    fn scratch_dir(tag: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        PathBuf::from(format!("/tmp/clasp-t-shim-{tag}-{}", &unique[..8]))
    }

    struct Scoped(PathBuf);
    impl Drop for Scoped {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The value at `key` in a CBOR map, read as a **raw map** rather
    /// than through a derived `Deserialize`.
    ///
    /// This is the whole point of the test below. `Request`/`Response`
    /// decode through the same impls the shim encoded with, so they
    /// agree with themselves whatever the field names are — a
    /// `#[serde(rename_all = "camelCase")]` on either type is invisible
    /// to every round-trip assertion and fatal on the wire. Only a
    /// literal key lookup can see it.
    fn field<'a>(value: &'a CborValue, key: &str) -> &'a CborValue {
        let CborValue::Map(entries) = value else {
            panic!("§7.4's frames are maps, got {value:?}")
        };
        entries
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| {
                let keys: Vec<_> = entries.iter().filter_map(|(k, _)| k.as_text()).collect();
                panic!("no `{key}` on the wire; the frame carried {keys:?}")
            })
    }

    /// A stand-in daemon that completes the handshake, then captures the
    /// **raw** CBOR of the next request and answers it with a
    /// hand-built map.
    ///
    /// Hand-built in both directions on purpose. A stand-in that replied
    /// with `Response::ok(..)` would serialise through the same derive
    /// the shim deserialises with, which proves the shim agrees with
    /// this crate rather than with §7.4.1.
    fn stand_in_daemon(
        sock: PathBuf,
        reply: CborValue,
    ) -> tokio::sync::oneshot::Receiver<CborValue> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&sock).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            // The handshake is Task 4's contract and is already pinned
            // on the wire by `tests/control_protocol.rs`; here it is
            // just the price of admission, so it goes through the typed
            // helpers.
            let hs: Request = frame::read_frame(&mut stream).await.unwrap();
            let data = HandshakeData {
                protocol_major: handshake::PROTOCOL_MAJOR,
                protocol_minor: handshake::PROTOCOL_MINOR,
                daemon_version: "99.0.0".into(),
                build: "stand-in".into(),
                accepted: true,
                reject_reason: None,
            };
            let resp = Response::ok(hs.id, &data, "handshake accepted").unwrap();
            frame::write_frame(&mut stream, &resp).await.unwrap();

            // Everything after this point is raw.
            let req: CborValue = frame::read_frame(&mut stream).await.unwrap();
            let id = field(&req, "id")
                .as_integer()
                .expect("§7.4's id is an integer");
            let id = u64::try_from(id).expect("a request id fits u64");

            let mut entries = vec![(CborValue::Text("id".into()), CborValue::Integer(id.into()))];
            let CborValue::Map(rest) = reply else {
                panic!("the reply template is a map")
            };
            entries.extend(rest);
            frame::write_frame(&mut stream, &CborValue::Map(entries))
                .await
                .unwrap();

            let _ = tx.send(req);
            // Hold the connection open: an EOF here would race the
            // shim's read and turn a wire mismatch into a framing error,
            // which is a different failure wearing the same colour.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        rx
    }

    /// **The wire test.** Everything else in this file is built from the
    /// same types on both sides and is therefore blind to a rename; this
    /// one hand-builds the daemon's reply from literal CBOR keys and
    /// reads the shim's request back as a literal CBOR map.
    ///
    /// §7.4.1, verbatim: the shim *"forwards each MCP `tools/call` to the
    /// daemon as a control-protocol request with method
    /// `tool/<tool_name>` and `params` set to the MCP `arguments`"*, and
    /// *"the daemon's `data` field corresponds to the MCP
    /// `structuredContent.data`; `status` and `details` likewise map."*
    /// Both halves are asserted here against literals.
    #[tokio::test]
    async fn the_shim_puts_7_4_1s_own_field_names_on_the_wire() {
        let dir = scratch_dir("wire");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        // The daemon's answer, built from §7.4's four literal keys. A
        // `Response::ok(..)` here would agree with the shim by
        // construction and prove nothing about either.
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("ok".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("output".into()),
                        CborValue::Text("hello\n".into()),
                    ),
                    (
                        CborValue::Text("cursor".into()),
                        CborValue::Integer(6u64.into()),
                    ),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("read 6 bytes".into()),
            ),
        ]);
        let captured = stand_in_daemon(sock.clone(), reply);

        // Give the listener a moment to bind before connecting.
        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let mut arguments = serde_json::Map::new();
        arguments.insert("session".into(), json!("sess_abc"));
        arguments.insert("since_cursor".into(), json!(0));
        let result = shim
            .forward("read_output", Some(arguments))
            .await
            .expect("the stand-in answered ok");

        // --- the request direction ---
        let req = captured.await.expect("the stand-in captured a request");

        // The method is the literal `tool/` prefix plus the tool name.
        // A shim that sent `tools/read_output`, or `read_output` bare,
        // or `{"tool": "read_output"}` round-trips against itself and
        // is refused by the daemon's `req.tool_name()`.
        assert_eq!(
            field(&req, "method").as_text(),
            Some("tool/read_output"),
            "§7.4.1: the method is `tool/<tool_name>`"
        );

        // `params` **is** the arguments map — not a wrapper carrying
        // them under `arguments`, which is the shape an MCP-shaped
        // forward would produce and which no round-trip test can see.
        let params = field(&req, "params");
        assert_eq!(
            field(params, "session").as_text(),
            Some("sess_abc"),
            "§7.4.1: `params` is set to the MCP `arguments`, verbatim"
        );
        assert_eq!(
            field(params, "since_cursor").as_integer(),
            Some(0u64.into()),
            "an argument that is not a string must survive the JSON→CBOR hop"
        );
        let CborValue::Map(param_entries) = params else {
            panic!("params is a map")
        };
        assert_eq!(
            param_entries.len(),
            2,
            "`params` must carry the arguments and nothing else; got {params:?}"
        );

        // --- the response direction ---
        // §7.4.1's three fields land on the envelope's three fields.
        // Reading `structured_content` as JSON is the right level here:
        // it is what the MCP client receives, and the assertion is that
        // the hand-built CBOR reached it intact.
        let body = result.structured_content.expect("§5.1's structured body");
        assert_eq!(
            body,
            json!({
                "status": "ok",
                "data": { "output": "hello\n", "cursor": 6 },
                "details": "read 6 bytes",
            }),
            "§7.4.1: data → structuredContent.data, status and details likewise"
        );
    }

    /// The negative for the mapping above: a control-protocol *error*
    /// response is not an envelope, and must not be rebuilt as one.
    ///
    /// Hand-built from §7.4.1's literal error shape for the same reason
    /// — `Response::error(..)` would agree with `control_error()` by
    /// construction.
    #[tokio::test]
    async fn a_daemon_side_bad_params_is_re_raised_as_an_mcp_protocol_error() {
        let dir = scratch_dir("err");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("bad_params".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text("missing field `session`".into()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("missing field `session`".into()),
            ),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let err = shim
            .forward("read_output", None)
            .await
            .expect_err("`bad_params` is a protocol fault, not a tool status");
        // §5.1 routes a schema violation to the protocol channel. The
        // code, not just the message: a shim that flattened every
        // daemon-side fault into `internal_error` would still carry the
        // text and would tell the agent it hit a server bug rather than
        // a fixable argument.
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "daemon `bad_params` re-raises as JSON-RPC invalid_params"
        );
        assert!(
            err.message.contains("missing field `session`"),
            "the daemon's own message must reach the agent: {}",
            err.message
        );
    }

    /// An internal fault must not read to the agent as its own bad
    /// input.
    ///
    /// The daemon flattens every `Err(ErrorData)` a tool raises onto
    /// §18.3's `bad_params`, because §18.3 has no JSON-RPC codes. While
    /// the rebuild read `code` alone, that flattening was lossy in the
    /// one direction that matters — `internal_error` came back as
    /// `invalid_params` — and the *same* fault under `--no-daemon` stayed
    /// `internal_error`, so the two transports disagreed about whose
    /// fault it was.
    ///
    /// Three distinct codes, not one: a rebuild that hardcoded
    /// `INVALID_PARAMS` passes any single-code row.
    #[test]
    fn rpc_code_decides_the_rebuilt_error_when_the_daemon_sent_one() {
        let with_rpc = |rpc: i32| method::ControlError {
            // Always `bad_params`, because that is what the daemon must
            // send for **every** tool fault. If the §18.3 code decided,
            // these three would be indistinguishable — which was the bug.
            code: method::ErrorCode::BadParams.as_str().into(),
            message: "openpty failed".into(),
            retriable: false,
            rpc_code: Some(rpc),
        };
        for code in [-32603, -32602, -32002] {
            let e = rebuild_error(with_rpc(code));
            assert_eq!(e.code, rmcp::model::ErrorCode(code));
            assert_eq!(e.message, "openpty failed");
        }
    }

    /// The fallback, which is what a daemon one minor behind sends: no
    /// `rpc_code`, and §18.3's code is all there is. §7.4.1 permits that
    /// skew explicitly, so this arm is a live path and not a leftover.
    #[test]
    fn without_an_rpc_code_the_18_3_code_still_decides() {
        let bare = |code: method::ErrorCode| method::ControlError {
            code: code.as_str().into(),
            message: "m".into(),
            retriable: false,
            rpc_code: None,
        };
        // §5.5.2's validation faults are `-32602` on the MCP wire, which
        // is why `bad_params` maps here and not to "internal error".
        assert_eq!(
            rebuild_error(bare(method::ErrorCode::BadParams)).code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
        // Everything else is a server fault, and says which §18.3 code
        // it was — the agent cannot act on it, but an operator can.
        let e = rebuild_error(bare(method::ErrorCode::ProtocolViolation));
        assert_eq!(e.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(
            e.message.contains("protocol_violation"),
            "the §18.3 code must survive into the message: {}",
            e.message
        );
    }

    /// A tool the daemon does not have must read as "no such tool", not
    /// as a server fault.
    ///
    /// `list_tools` is answered from the shim's **own** process —
    /// `passthrough::tool_manifest()` is
    /// `HoldfastServer::tool_router().list_all()`, and §7.4.1 defines no
    /// method by which a manifest could be fetched — while §7.4.1
    /// explicitly permits shim/daemon minor skew. So a tool this build
    /// advertises and an older daemon lacks is reachable, and it comes
    /// back `unknown_method`.
    ///
    /// In-process the identical call is `invalid_params("tool not
    /// found")`, from rmcp's router, and `call_tool`'s own guard answers
    /// `invalid_params` for a name outside the manifest. Reporting it as
    /// `internal_error` told the agent to give up on a server bug where
    /// the truth is that the tool does not exist.
    ///
    /// The paired row is the one that keeps this honest: a §18.3 code
    /// that really *is* a server fault must still arrive as one, or the
    /// fix is just a second flattening in the other direction.
    ///
    /// The first half goes over the socket, because `forward` *calling*
    /// the right rebuild is a separate claim from the rebuild being
    /// right — the same split that made the resource path's decode
    /// worth driving end to end.
    #[tokio::test]
    async fn an_unknown_tool_is_the_agents_bad_argument_and_not_a_server_fault() {
        let dir = scratch_dir("notool");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        // What a daemon one minor behind answers for `tool/<name>` when
        // it has no such tool: §18.3's `unknown_method`, and no
        // `rpc_code`, because no handler ever ran to raise one.
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("unknown_method".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text("no tool inspect_screen".into()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("no tool inspect_screen".into()),
            ),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));
        let err = shim
            .forward("inspect_screen", None)
            .await
            .expect_err("a tool the daemon lacks is not an outcome");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "an unknown tool is `-32602` in-process; the daemon transport must agree"
        );

        let bare = |code: method::ErrorCode| method::ControlError {
            code: code.as_str().into(),
            message: "no tool inspect_screen".into(),
            retriable: false,
            rpc_code: None,
        };
        assert_eq!(
            rebuild_tool_error(bare(method::ErrorCode::ProtocolViolation)).code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "a real server fault must not be relabelled the agent's bad argument"
        );
        // And an `rpc_code` still wins: this arm is a guess made only in
        // its absence.
        assert_eq!(
            rebuild_tool_error(method::ControlError {
                code: method::ErrorCode::UnknownMethod.as_str().into(),
                message: "m".into(),
                retriable: false,
                rpc_code: Some(-32603),
            })
            .code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
        );
    }

    /// §5.5.2's structured `data.code` must survive the hybrid hop.
    ///
    /// The in-process transport answers a bad query parameter with
    /// `invalid_params(prose, Some({"code": "invalid_enum", …}))`, and an
    /// agent branches on `data.code` to know whether to fix a name, a
    /// value or a range. `ControlError` has nowhere to carry that object,
    /// so the daemon JSON-encodes `{message, data}` into the error
    /// *message* — and nothing decoded it: the agent received the raw
    /// blob as its prose and `data: null` where the four codes belong.
    ///
    /// **Driven through `forward_resource`, not through the free
    /// function.** The decode existing and the resource path *calling*
    /// it are two different claims, and only the second is the fix.
    #[tokio::test]
    async fn a_resource_fault_keeps_the_structured_code_5_5_2_requires() {
        let dir = scratch_dir("resdata");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        // The daemon's encoding, hand-built from §5.5.2's literal shape
        // rather than by calling the encoder — a round trip through one
        // expression would agree with itself whatever that shape is.
        let envelope = json!({
            "message": "ansi=purple is not one of strip, raw",
            "data": {
                "code": "invalid_enum",
                "param": "ansi",
                "value": "purple",
                "allowed": ["strip", "raw"],
            },
        })
        .to_string();
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("bad_params".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text(envelope.clone()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                    (
                        CborValue::Text("rpc_code".into()),
                        CborValue::Integer((-32602i64).into()),
                    ),
                ]),
            ),
            (CborValue::Text("details".into()), CborValue::Text(envelope)),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let err = shim
            .forward_resource(
                method::METHOD_RESOURCE_READ,
                json!({ "uri": "holdfast://session/s/buffer?ansi=purple" }),
            )
            .await
            .expect_err("§5.5.2 routes a bad parameter to the protocol channel");

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(
            err.data.as_ref().map(|d| &d["code"]),
            Some(&json!("invalid_enum")),
            "§5.5.2's four codes are structured `data`, not prose; got data {:?}",
            err.data
        );
        // The other half of the same defect: the prose field held the
        // JSON blob. An agent shows `message` to a human.
        assert_eq!(
            err.message.as_ref(),
            "ansi=purple is not one of strip, raw",
            "the message field must carry prose, not the envelope it arrived in"
        );
    }

    /// The decode is deliberately narrow, and these are the rows that
    /// say so. A control error whose message is ordinary prose — every
    /// producer that is not `dispatch_resource` — must pass through
    /// untouched, or the shim starts inventing `data` from any message
    /// that happens to parse.
    #[test]
    fn only_the_daemons_own_two_key_envelope_is_unwrapped() {
        assert_eq!(
            decode_resource_envelope("no session sess_x"),
            None,
            "prose is not an envelope"
        );
        assert_eq!(
            decode_resource_envelope(r#"{"message":"m","data":null,"extra":1}"#),
            None,
            "a third key means this came from somewhere else"
        );
        assert_eq!(
            decode_resource_envelope(r#"{"code":"invalid_enum","param":"ansi"}"#),
            None,
            "§5.5.2's `data` object on its own is not the envelope"
        );
        // `data: null` is what the daemon writes for an `ErrorData` that
        // carried none — `resource_not_found`, for one. It must become
        // an absent field, not a literal `"data": null` on the MCP wire
        // where the in-process transport omits it.
        assert_eq!(
            decode_resource_envelope(r#"{"message":"no session sess_x","data":null}"#),
            Some(("no session sess_x".to_string(), None))
        );
    }

    /// **The wire test for the new field.** Everything above decodes
    /// through the same derived impl the daemon encodes with, so a
    /// rename of `rpc_code` — or a daemon that spelt it `rpcCode` — is
    /// invisible to all of it and fatal in production. Only a literal
    /// CBOR key can see it.
    #[tokio::test]
    async fn the_shim_reads_rpc_code_under_its_own_wire_name() {
        let dir = scratch_dir("rpccode");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    // The §18.3 code the daemon is obliged to send for
                    // *every* tool fault. Read alone it says
                    // "invalid_params", which is the wrong answer here.
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("bad_params".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text("write task failed".into()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                    (
                        CborValue::Text("rpc_code".into()),
                        CborValue::Integer((-32603i64).into()),
                    ),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("write task failed".into()),
            ),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let err = shim
            .forward("send_input", None)
            .await
            .expect_err("a tool protocol fault is not a tool status");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "a CLASP bug must reach the agent as one, not as its own bad argument"
        );
        assert!(err.message.contains("write task failed"), "{}", err.message);
    }
}
