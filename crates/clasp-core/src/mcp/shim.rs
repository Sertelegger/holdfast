//! The hybrid-mode MCP server (spec §3.3): an MCP server whose tool
//! handlers are thin RPC calls into a daemon.
//!
//! `ShimServer` declares no tools of its own. `list_tools` returns the
//! *daemon-side* manifest ([`passthrough::tool_manifest`]) verbatim and
//! `call_tool` forwards by name, so the agent-visible surface is
//! identical whichever transport is in use — which is what §3.5's "there
//! is no business logic outside `clasp-core`" means in practice.

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
            // `bad_params` is how the daemon reports a tool's own
            // `ErrorData::invalid_params` (§5.1 protocol channel). Rebuild
            // it as such rather than flattening every daemon-side fault
            // into "internal error", so the agent sees the same class of
            // failure it would in-process.
            return Err(if e.code == method::ErrorCode::BadParams.as_str() {
                ErrorData::invalid_params(e.message, None)
            } else {
                ErrorData::internal_error(format!("[{}] {}", e.code, e.message), None)
            });
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
    /// `bad_params` becomes `ErrorData::invalid_params` for the same
    /// reason `forward` does it: §5.5.2's validation faults are
    /// `-32602 Invalid params` on the MCP wire, and flattening them into
    /// "internal error" would tell the agent its URI was fine and the
    /// server broke.
    async fn forward_resource(&self, method: &str, params: Value) -> Result<Value, ErrorData> {
        let params =
            method::to_cbor(&params).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let resp = self
            .client
            .call_raw(method, params)
            .await
            .map_err(map_client_error)?;
        if let Some(e) = resp.control_error() {
            return Err(if e.code == method::ErrorCode::BadParams.as_str() {
                ErrorData::invalid_params(e.message, None)
            } else {
                ErrorData::internal_error(format!("[{}] {}", e.code, e.message), None)
            });
        }
        method::from_cbor(&resp.data).map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }
}

/// The daemon-backed server's `instructions`, **derived** from the
/// in-process text rather than copied from it.
///
/// `list_tools` is forwarded verbatim, so every tool description, output
/// schema and annotation already has exactly one definition. That leaves
/// `instructions` as the one agent-visible string not covered by the
/// forwarding, so it is built from [`super::INSTRUCTIONS`] and differs
/// by exactly one appended sentence — the single fact that is genuinely
/// transport-specific.
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
        info.capabilities = super::server_capabilities();
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
}
