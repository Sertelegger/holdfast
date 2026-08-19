//! MCP-tool passthrough: the seam that lets the same tool handlers run
//! in-process (Windows, `--no-daemon`) or behind the control protocol
//! (§3.3, §3.5, §7.4.1).
//!
//! §7.4.1 fixes the mapping: the shim forwards an MCP `tools/call` as
//! `tool/<tool_name>` with `params` set to the MCP `arguments`; the
//! daemon's `status`/`data`/`details` map onto the tool envelope's
//! fields. Nothing about a tool's behaviour differs between the two
//! transports — only where it runs.

use super::envelope;
// **Ten names, one per arg-taking arm of `call_tool` below.** Six of
// them are 0.0.2's, 0.0.3's and 0.0.4's — Step 3's table names which —
// and `rustfmt` sorts the braces alphabetically, so the milestones are
// interleaved rather than trailing. Count these against the match: a
// list that is short by one is `E0412 cannot find type ... in this
// scope`, which is what an earlier revision of this block shipped.
//
// All ten exist by the time this milestone runs; if one does not, stop
// and check the milestone order rather than inventing a stand-in —
// `every_router_tool_is_dispatchable` names whichever tool is
// unreachable.
use super::tools::{
    GetCommandHistoryArgs, GetScreenStateArgs, InterruptArgs, ReadOutputArgs, ResizeArgs,
    SendInputArgs, StartSessionArgs, StatusArgs, TerminateArgs, WaitForPatternArgs,
};
use super::HoldfastServer;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Tool};
use rmcp::ErrorData;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The `{status, data, details}` triple as it crosses the control
/// protocol. Deliberately not `CallToolResult`: the wire carries the
/// envelope, and the MCP-specific packaging is rebuilt on the shim side.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub status: String,
    pub data: Value,
    pub details: String,
}

/// Every tool this build exposes — description, `inputSchema`,
/// `outputSchema` (REQ-T-013) and annotations (REQ-T-014) included.
///
/// The shim serves this list verbatim rather than declaring its own, so
/// the agent-visible surface cannot drift between the two transports.
/// `list_all()` returns whatever `#[tool(...)]` declared, so a tool that
/// gains a schema or an annotation in a later milestone gets it on both
/// transports with no edit here.
pub fn tool_manifest() -> Vec<Tool> {
    HoldfastServer::tool_router().list_all()
}

/// The names in [`tool_manifest`], which is the *only* definition of the
/// passthrough set.
///
/// Derived rather than hand-maintained on purpose. A parallel `const`
/// list would have to be edited by every milestone that adds a tool —
/// 0.0.2 adds three, 0.0.4 adds one — and the failure mode of forgetting
/// is a tool that the agent can see and the daemon refuses, which only
/// manifests in hybrid mode. Deriving makes that class of drift
/// unrepresentable; what remains hand-written is [`call_tool`]'s match,
/// and `every_router_tool_is_dispatchable` is what holds *it* to account.
pub fn passthrough_tools() -> Vec<String> {
    tool_manifest()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect()
}

/// Whether `name` is a tool the daemon will dispatch.
pub fn is_passthrough_tool(name: &str) -> bool {
    tool_manifest().iter().any(|t| t.name.as_ref() == name)
}

/// Daemon side: run a tool by name. `None` means "no such tool", which
/// the caller reports as `unknown_method`.
///
/// **Adding a tool means adding an arm here.** Milestones 0.0.2, 0.0.3
/// and 0.0.4 land before this one and bring seven more (`status`,
/// `list_sessions`, `get_command_history`, `wait_for_pattern`,
/// `get_screen_state`, `resize`, `interrupt`); each needs one line.
/// `every_router_tool_is_dispatchable` fails until they have it, and
/// names the tool that is missing.
pub async fn call_tool(
    server: &HoldfastServer,
    tool: &str,
    args: Value,
) -> Option<Result<CallToolResult, ErrorData>> {
    macro_rules! run {
        ($method:ident, $args:ty) => {{
            match serde_json::from_value::<$args>(args) {
                Ok(parsed) => Some(server.$method(Parameters(parsed)).await),
                Err(e) => Some(Err(ErrorData::invalid_params(e.to_string(), None))),
            }
        }};
    }
    match tool {
        "start_session" => run!(start_session, StartSessionArgs),
        "read_output" => run!(read_output, ReadOutputArgs),
        "send_input" => run!(send_input, SendInputArgs),
        "terminate" => run!(terminate, TerminateArgs),
        // --- tools introduced by 0.0.2, 0.0.3 and 0.0.4 ---
        "status" => run!(status, StatusArgs),
        "get_command_history" => run!(get_command_history, GetCommandHistoryArgs),
        "wait_for_pattern" => run!(wait_for_pattern, WaitForPatternArgs),
        "get_screen_state" => run!(get_screen_state, GetScreenStateArgs),
        "resize" => run!(resize, ResizeArgs),
        "interrupt" => run!(interrupt, InterruptArgs),
        // No arguments: the router still passes an (empty) object, and
        // the macro above is arg-shaped, so this arm is written out.
        "list_sessions" => Some(server.list_sessions().await),
        _ => None,
    }
}

/// Daemon side: flatten a tool result into the wire triple.
///
/// `structured_content` is always present — `envelope()` sets it on
/// every path — but the fallback keeps a future tool that forgets from
/// silently producing `status: ""`.
pub fn result_to_outcome(result: &CallToolResult) -> ToolOutcome {
    let body = result
        .structured_content
        .clone()
        .unwrap_or_else(|| json!({}));
    ToolOutcome {
        status: body
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("internal_error")
            .to_string(),
        data: body.get("data").cloned().unwrap_or_else(|| json!({})),
        details: body
            .get("details")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

/// Shim side: rebuild the MCP result from the wire triple.
///
/// `isError` is *not* on the wire — §7.4.1 carries only status, data and
/// details — so it is re-derived from §18.1's table. That keeps one
/// source of truth for the `isError` column instead of letting the
/// daemon assert it.
pub fn outcome_to_result(outcome: ToolOutcome) -> CallToolResult {
    envelope::result_from_wire(&outcome.status, outcome.data, outcome.details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_router_tool_is_dispatchable() {
        // The daemon dispatches by name. A tool in the router but not in
        // `call_tool` would be advertised to the agent and then fail with
        // `unknown_method` at the daemon — a bug visible *only* in hybrid
        // mode, which is the configuration hardest to notice.
        //
        // `Value::Null` cannot deserialise into any argument struct, so
        // an arg-taking tool answers `Some(Err(invalid_params))` without
        // running: the assertion is about reachability, not behaviour.
        let server = HoldfastServer::new();
        let names = passthrough_tools();
        // The vacuity guard. It was `>= 4` — 0.0.1's tool count — which
        // by the time this milestone runs is four milestones behind what
        // it guards and would stay green after seven tools vanished. The
        // exact set is pinned by name in
        // `tools::tests::the_router_advertises_exactly_the_0_0_4_tool_set`;
        // this floor only has to be non-vacuous, so it tracks that test's
        // count rather than restating its names.
        assert!(names.len() >= 11, "the router lost tools; got {names:?}");
        for name in names {
            assert!(
                call_tool(&server, &name, Value::Null).await.is_some(),
                "`{name}` is in the tool manifest but `call_tool` has no arm for it"
            );
        }
    }

    #[test]
    fn the_manifest_contains_the_tools_the_wire_contract_names() {
        // Guards the reverse direction: a manifest that shrank to
        // nothing would satisfy the loop above vacuously.
        for required in ["start_session", "read_output", "send_input", "terminate"] {
            assert!(
                is_passthrough_tool(required),
                "{required} is missing from the tool manifest"
            );
        }
        assert!(!is_passthrough_tool("no_such_tool"));
    }

    #[tokio::test]
    async fn unknown_tool_is_reported_as_such() {
        let server = HoldfastServer::new();
        assert!(call_tool(&server, "no_such_tool", json!({}))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn bad_params_become_an_mcp_protocol_error() {
        let server = HoldfastServer::new();
        // `session` is required and missing.
        let r = call_tool(&server, "read_output", json!({ "tail_lines": 1 }))
            .await
            .expect("known tool");
        assert!(r.is_err(), "a schema violation must not be a tool status");
    }

    #[tokio::test]
    async fn a_tool_envelope_survives_the_outcome_round_trip() {
        let server = HoldfastServer::new();
        let r = call_tool(
            &server,
            "read_output",
            json!({ "session": "sess_nope", "since_cursor": 0 }),
        )
        .await
        .expect("known tool")
        .expect("session_not_found is an envelope, not a protocol error");

        let outcome = result_to_outcome(&r);
        assert_eq!(outcome.status, "session_not_found");

        let rebuilt = outcome_to_result(outcome);
        assert_eq!(rebuilt.structured_content, r.structured_content);
        assert_eq!(
            rebuilt.is_error,
            Some(true),
            "§18.1 marks session_not_found isError:true; the flag must \
             survive a transport that never carries it"
        );
    }

    #[tokio::test]
    async fn a_timeout_envelope_survives_the_round_trip_without_becoming_an_error() {
        // `timeout` is `send_input`'s write-deadline outcome (§5.2,
        // §18.1) and is `isError: false`. It is the status most likely to
        // be mis-carried, because the wire has no `isError` field to
        // copy: a transport that defaulted unknown statuses to "error"
        // would turn a recoverable timeout into a halted plan.
        let outcome = ToolOutcome {
            status: "timeout".into(),
            data: json!({ "bytes_written": Value::Null, "timeout_ms": 5000 }),
            details: "the child did not accept the input".into(),
        };
        let rebuilt = outcome_to_result(outcome.clone());
        assert_ne!(rebuilt.is_error, Some(true), "timeout must not be an error");
        let body = rebuilt.structured_content.expect("structured content");
        assert_eq!(body["status"], "timeout");
        assert_eq!(body["data"]["timeout_ms"], 5000);
        assert!(body["data"]["bytes_written"].is_null());
        assert_eq!(body["details"], outcome.details);
    }
}
