//! GH #219: **every tool refuses an argument it does not declare**, on both
//! transports, and the refusal names the key and lists the valid ones.
//!
//! Before this, eleven of the twelve tools accepted an unknown key and
//! dropped it, so a typo was honoured as the default it was meant to
//! override: `wait_for_pattern { patern }` became a pattern-less wait and
//! answered `ok, session is AtPrompt`, and `send_input { apend_newline:
//! false }` wrote the newline. `request_secret_input` was the one tool
//! that refused, for REQ-SEC-010a's reason; `tools::ListSessionsArgs`
//! carries the rest of the argument, including why no MCP client breaks.
//!
//! **Every row here is paired.** A refusal row alone passes against a tool
//! that refuses everything, so each tool is first called with arguments
//! that reach its body — and that outcome is asserted as well — and only
//! then with the same arguments plus one key it does not declare.
//!
//! **The tool list is the router's, not a copy.** A tool added later is in
//! these loops the day it lands, and a tool whose reaching arguments are
//! wrong fails the pairing loudly rather than skipping.

use holdfast_core::mcp::passthrough;
use holdfast_core::mcp::HoldfastServer;
use rmcp::model::{CallToolResult, ErrorCode};
use serde_json::{json, Value};

/// A session id that names nothing, so every session-taking tool answers
/// `session_not_found` from its body — past the deserialiser, and without
/// a side effect.
const NOPE: &str = "sess_nope219";

/// The key no tool declares. Deliberately not a near-miss of any real
/// argument: this is the generic row, and the near-misses the issue
/// measured are rows of their own below.
const BOGUS: &str = "bogus_argument_219";

/// What a call with [`reaching`]'s arguments must produce, which is the
/// proof that it got past the deserialiser into the tool.
enum Reached {
    /// An envelope with this `status`.
    Status(&'static str),
    /// A protocol error the tool's *body* raises, containing this text.
    BodyRefusal(&'static str),
}

/// Arguments that deserialise for `tool` and reach its body.
///
/// The `_` arm is `session` alone, which is what the session-only tools
/// take. A new tool with another required field fails the pairing
/// assertion with `missing field`, which is the loud way to be told to add
/// an arm here.
fn reaching(tool: &str) -> (Value, Reached) {
    match tool {
        // Neither `command` nor `profile`: the body refuses it, and that
        // refusal is only reachable once the arguments have deserialised.
        // No child is spawned on either arm of this file.
        "start_session" => (
            json!({}),
            Reached::BodyRefusal("needs either `command` or `profile`"),
        ),
        "list_sessions" => (json!({}), Reached::Status("ok")),
        "read_output" => (
            json!({ "session": NOPE, "since_cursor": 0 }),
            Reached::Status("session_not_found"),
        ),
        "send_input" => (
            json!({ "session": NOPE, "data": "x" }),
            Reached::Status("session_not_found"),
        ),
        "resize" => (
            json!({ "session": NOPE, "cols": 80, "rows": 24 }),
            Reached::Status("session_not_found"),
        ),
        "request_secret_input" => (
            json!({ "session": NOPE, "prompt_text": "x" }),
            Reached::Status("session_not_found"),
        ),
        _ => (
            json!({ "session": NOPE }),
            Reached::Status("session_not_found"),
        ),
    }
}

fn status_of(r: &CallToolResult) -> String {
    r.structured_content
        .as_ref()
        .and_then(|b| b.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("<no status>")
        .to_string()
}

/// The property names `tools/list` advertises for `tool`.
fn advertised_properties(tool: &rmcp::model::Tool) -> Vec<String> {
    tool.input_schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default()
}

/// The vacuity guard for every loop below. The exact set is pinned by
/// name in `tools::tests::the_router_advertises_exactly_the_0_0_7_tool_set`
/// and by `scripts/mcp-smoke.sh`; this only has to stop an empty manifest
/// passing every loop.
fn manifest() -> Vec<rmcp::model::Tool> {
    let tools = passthrough::tool_manifest();
    assert!(
        tools.len() >= 12,
        "the router lost tools; these loops would pass over nothing: {:?}",
        tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>()
    );
    tools
}

/// **The advertised schema and the deserialiser say the same thing.**
///
/// Before GH #219 they agreed by both being open, on eleven tools; the
/// fix has to close both or it moves the disagreement rather than
/// removing it. Nested argument objects are held to it too —
/// `start_session.prompt_patterns[]` is `PromptPatternArg` — and the two
/// free-form maps (`env`, `vars`) are exempt by construction, because
/// their `additionalProperties` is a *schema* (`{"type": "string"}`)
/// rather than `false`, and a map whose keys are the caller's is not a
/// struct with a typo to catch.
#[test]
fn every_tool_advertises_a_closed_input_schema() {
    let mut nested = 0;
    for tool in manifest() {
        let name = tool.name.to_string();
        let schema = Value::Object((*tool.input_schema).clone());
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&json!(false)),
            "`{name}` advertises an open input schema, so a client may send it a key \
             it drops — or, if its deserialiser refuses, the schema promises what the \
             tool refuses: {schema}"
        );
        // A tool with no arguments still advertises `properties`, as it did
        // before it gained an argument type: some clients require the key.
        assert!(
            schema.get("properties").is_some_and(Value::is_object),
            "`{name}` advertises no `properties` object: {schema}"
        );
        if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
            for (def, body) in defs {
                if body.get("type") == Some(&json!("object")) {
                    nested += 1;
                    assert_eq!(
                        body.get("additionalProperties"),
                        Some(&json!(false)),
                        "`{name}`'s nested argument `{def}` is open: {body}"
                    );
                }
            }
        }
    }
    assert!(
        nested >= 1,
        "no nested argument object was reached, so the `$defs` half of this row \
         checked nothing (`start_session.prompt_patterns` should be one)"
    );
}

/// **The daemon's deserialiser** — `passthrough::call_tool` is what
/// `daemon::server::dispatch_tool` runs for `tool/<name>`, so this is the
/// default transport's path.
#[tokio::test]
async fn every_tool_refuses_an_unknown_argument_by_name_on_the_daemon_path() {
    let server = HoldfastServer::new();
    for tool in manifest() {
        let name = tool.name.to_string();
        let (args, reached) = reaching(&name);

        // ---- the pairing: the same call without the key reaches the tool.
        let base = passthrough::call_tool(&server, &name, args.clone())
            .await
            .unwrap_or_else(|| panic!("`{name}` is in the manifest and not dispatchable"));
        match (&reached, &base) {
            (Reached::Status(want), Ok(r)) => assert_eq!(
                status_of(r),
                *want,
                "`{name}` with {args} did not reach its body as expected"
            ),
            (Reached::BodyRefusal(want), Err(e)) => assert!(
                e.message.contains(want),
                "`{name}` with {args} was refused, but not by its body: {}",
                e.message
            ),
            (_, other) => {
                panic!("`{name}` with {args} did not reach its body — fix `reaching()`: {other:?}")
            }
        }

        // ---- and with one undeclared key, refused before the body runs.
        let mut with_bogus = args;
        with_bogus
            .as_object_mut()
            .expect("an argument object")
            .insert(BOGUS.into(), json!(1));
        let e = passthrough::call_tool(&server, &name, with_bogus)
            .await
            .expect("dispatchable")
            .expect_err(&format!(
                "`{name}` accepted `{BOGUS}` and ran — an agent's typo is honoured as the \
                 default it meant to override (GH #219)"
            ));
        assert_eq!(
            e.code,
            ErrorCode::INVALID_PARAMS,
            "`{name}`: an input-schema violation is `invalid_params` (§5.1): {e:?}"
        );
        assert!(
            e.message.contains(&format!("unknown field `{BOGUS}`")),
            "`{name}`'s refusal does not name the key the caller got wrong: {}",
            e.message
        );
        // "Lists the valid ones", derived from what the tool advertises
        // rather than restated: every property in `tools/list` is named in
        // the refusal, so the agent can correct the call from the error
        // alone.
        for prop in advertised_properties(&tool) {
            assert!(
                e.message.contains(&format!("`{prop}`")),
                "`{name}`'s refusal does not list the valid argument `{prop}`: {}",
                e.message
            );
        }
    }
}

/// **The near-misses the dogfood pass measured**, one per tool that was
/// measured, each paired with the spelling it missed.
///
/// The generic row above would pass against a deserialiser that refused
/// only keys matching some pattern; these are the actual keys an agent
/// sent, and before the fix each one answered as if it had not been sent.
#[tokio::test]
async fn the_measured_typos_are_refused_rather_than_honoured_as_defaults() {
    let server = HoldfastServer::new();
    for (tool, typo_args, typo) in [
        (
            "wait_for_pattern",
            json!({ "session": NOPE, "patern": "never", "timeout_secs": 2 }),
            "patern",
        ),
        (
            "wait_for_pattern",
            json!({ "session": NOPE, "pattern": "x", "timeout": 2 }),
            "timeout",
        ),
        (
            "send_input",
            json!({ "session": NOPE, "data": "echo B", "apend_newline": false }),
            "apend_newline",
        ),
        (
            "read_output",
            json!({ "session": NOPE, "tail_lines": 5, "sinc_cursor": 0 }),
            "sinc_cursor",
        ),
        (
            "read_output",
            json!({ "session": NOPE, "cursor": 0 }),
            "cursor",
        ),
        ("list_sessions", json!({ "session": "smoke" }), "session"),
        (
            "request_secret_input",
            json!({ "session": NOPE, "prompt": "x" }),
            "prompt",
        ),
    ] {
        let e = passthrough::call_tool(&server, tool, typo_args.clone())
            .await
            .expect("dispatchable")
            .expect_err(&format!("`{tool}` accepted {typo_args}"));
        assert!(
            e.message.contains(&format!("unknown field `{typo}`")),
            "`{tool}`'s refusal of {typo_args} does not name `{typo}`: {}",
            e.message
        );
    }
}

/// **The nested argument object refuses too.** `prompt_patterns[]` is a
/// struct of its own, and a key misspelt inside it would otherwise be
/// dropped while the outer call succeeded.
///
/// No `command`, so without the refusal this is the body's
/// "needs either" error rather than a spawned shell — the row cannot
/// leave a child behind whichever way it goes.
#[tokio::test]
async fn a_misspelt_key_inside_prompt_patterns_is_refused_by_name() {
    let server = HoldfastServer::new();
    let e = passthrough::call_tool(
        &server,
        "start_session",
        json!({ "prompt_patterns": [{ "regex": "x", "score": 0.5, "weight": 1 }] }),
    )
    .await
    .expect("dispatchable")
    .expect_err("a call with no command or profile is refused either way");
    assert!(
        e.message.contains("unknown field `weight`"),
        "the nested `PromptPatternArg` dropped `weight` and the body answered \
         instead: {}",
        e.message
    );
    // The pairing: the same pattern without the stray key gets past the
    // deserialiser and reaches the body's own refusal.
    let e = passthrough::call_tool(
        &server,
        "start_session",
        json!({ "prompt_patterns": [{ "regex": "x", "score": 0.5 }] }),
    )
    .await
    .expect("dispatchable")
    .expect_err("still no command or profile");
    assert!(
        e.message.contains("needs either `command` or `profile`"),
        "a well-formed `prompt_patterns` did not reach the body: {}",
        e.message
    );
}

/// **The in-process transport**, driven as a client drives it: real
/// JSON-RPC over an in-memory duplex into rmcp's router.
///
/// This is `--no-daemon` and Windows (§3.3), and it is the half the
/// daemon rows above cannot see — rmcp's `Parameters` extractor rather
/// than `passthrough::call_tool`'s. It is also where `list_sessions`
/// could not refuse at all before GH #219, because rmcp hands a tool with
/// no `Parameters` no `arguments`.
///
/// It carries the compatibility half as well: `_meta` is **protocol
/// metadata at the `params` level**, beside `arguments`, and a client that
/// sends it must still be served. An `arguments` object that is absent
/// altogether must be too.
#[tokio::test]
async fn the_in_process_transport_refuses_the_same_way_and_still_serves_meta() {
    use rmcp::service::ServiceExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        if let Ok(running) = HoldfastServer::new().serve(server_side).await {
            let _ = running.waiting().await;
        }
    });
    let (rx, mut tx) = tokio::io::split(client_side);
    let mut rx = BufReader::new(rx);

    // One request, one answer: every request here is answered promptly
    // (no session exists, so nothing waits), and ids are checked so an
    // out-of-order answer is a failure rather than a misread.
    let mut next_id = 0u64;
    let mut call = |params: Value| {
        next_id += 1;
        let id = next_id;
        let mut line = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params
        })
        .to_string();
        line.push('\n');
        (id, line)
    };
    async fn answer(
        rx: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        id: u64,
    ) -> Value {
        let mut line = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(10), rx.read_line(&mut line))
            .await
            .expect("the in-process server never answered")
            .expect("read");
        let v: Value = serde_json::from_str(&line).expect("a JSON-RPC line");
        assert_eq!(v["id"], json!(id), "answered out of order: {v}");
        v
    }

    let mut init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "gh219", "version": "0" }
        }
    })
    .to_string();
    init.push('\n');
    tx.write_all(init.as_bytes()).await.unwrap();
    let _ = answer(&mut rx, 0).await;
    tx.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();

    // ---- the issue's own repro, and the no-argument tool.
    for (params, typo) in [
        (
            json!({ "name": "wait_for_pattern",
                    "arguments": { "session": NOPE, "patern": "never", "timeout_secs": 2 } }),
            "patern",
        ),
        (
            json!({ "name": "list_sessions", "arguments": { "session": "smoke" } }),
            "session",
        ),
    ] {
        let (id, line) = call(params.clone());
        tx.write_all(line.as_bytes()).await.unwrap();
        let v = answer(&mut rx, id).await;
        // **Two shapes, one refusal, and the difference is rmcp's rather
        // than this issue's.** rmcp 3.x turns a failure of its own
        // `Parameters` extractor into a tool result with `isError: true`
        // (MCP's SEP-1303 reading, so a model can self-correct), where the
        // daemon path — `passthrough::call_tool` rebuilt by the shim —
        // answers a JSON-RPC `-32602`. That divergence predates GH #219:
        // at `a81b02d` `request_secret_input`'s refusal already took both
        // shapes, on rmcp 3.2.0. What this row pins is what the issue is about — the call
        // did not run, and the answer names the key — and it takes the
        // message from whichever channel carried it.
        let message = if v["error"]["code"] == json!(-32602) {
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        } else {
            assert_eq!(
                v["result"]["isError"],
                json!(true),
                "{params} was neither refused nor an error in-process — it ran: {v}"
            );
            assert!(
                v["result"].get("structuredContent").is_none(),
                "{params} produced a tool envelope in-process, so the tool body ran: {v}"
            );
            v["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };
        assert!(
            message.contains(&format!("unknown field `{typo}`")),
            "the in-process refusal of {params} does not name `{typo}`: {v}"
        );
    }

    // ---- the pairings, which are also the compatibility rows.
    for (params, want) in [
        // `_meta` beside `arguments` — where MCP puts it — is not an
        // argument, and must not be refused as one.
        (
            json!({ "name": "list_sessions", "arguments": {},
                    "_meta": { "progressToken": "gh219" } }),
            "ok",
        ),
        // No `arguments` key at all: rmcp hands the tool an empty object.
        (json!({ "name": "list_sessions" }), "ok"),
        (
            json!({ "name": "wait_for_pattern",
                    "arguments": { "session": NOPE, "pattern": "never", "timeout_secs": 2 },
                    "_meta": { "progressToken": "gh219-2" } }),
            "session_not_found",
        ),
    ] {
        let (id, line) = call(params.clone());
        tx.write_all(line.as_bytes()).await.unwrap();
        let v = answer(&mut rx, id).await;
        assert_eq!(
            v["result"]["structuredContent"]["status"],
            json!(want),
            "{params} did not reach the tool in-process: {v}"
        );
    }

    server.abort();
}
