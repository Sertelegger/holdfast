//! REQ-T-013 / REQ-T-014: every tool advertises an `outputSchema` and its
//! annotations, and the responses it actually produces validate against
//! the schema a client actually receives.
//!
//! **Why this file drives the tools instead of serialising the structs.**
//! `mcp::schema` declares the shapes, but nothing in the production path
//! ever constructs one of those structs — the tools build their `data`
//! with `json!`. A test that serialised `schema::ReadOutput` and validated
//! it against `ReadOutput`'s own schema would pass for as long as the file
//! compiles and would prove nothing about `read_output`. So every
//! assertion below starts from a real `CallToolResult` returned by a real
//! tool call, and validates it against `ClaspServer::*_tool_attr()` — the
//! very function `#[tool_router]` builds its routes from, so it is the
//! object an MCP client receives from `tools/list`, not a second copy of
//! the declaration.
//!
//! **Why the negative tests matter.** Every `data` field is optional
//! (§18.1 statuses carry different payloads), so a response that omitted
//! *every* field would validate. `additionalProperties: false` and the
//! required-key assertions are what stop these tests from being
//! unfalsifiable: `an_undeclared_field_is_rejected` and
//! `read_output_emits_every_field_5_4_promises` are the two halves.

use clasp_core::mcp::envelope;
use clasp_core::mcp::schema;
use clasp_core::mcp::tools::{ReadOutputArgs, SendInputArgs, StartSessionArgs, TerminateArgs};
use clasp_core::mcp::ClaspServer;
use clasp_core::pty::{MockPty, PtyBackend};
use clasp_core::session::{new_session_id, Session, SessionConfig};
use jsonschema::error::ValidationErrorKind;
use jsonschema::Validator;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Tool};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- helpers

/// The `Tool` the router advertises, by tool name.
fn advertised(name: &str) -> Tool {
    match name {
        "start_session" => ClaspServer::start_session_tool_attr(),
        "read_output" => ClaspServer::read_output_tool_attr(),
        "send_input" => ClaspServer::send_input_tool_attr(),
        "terminate" => ClaspServer::terminate_tool_attr(),
        other => panic!("no such tool: {other}"),
    }
}

const TOOLS: [&str; 4] = ["start_session", "read_output", "send_input", "terminate"];

fn output_schema(name: &str) -> Value {
    let tool = advertised(name);
    Value::Object(
        tool.output_schema
            .as_ref()
            .unwrap_or_else(|| panic!("{name} advertises no outputSchema (REQ-T-013)"))
            .as_ref()
            .clone(),
    )
}

fn validator(name: &str) -> Validator {
    jsonschema::validator_for(&output_schema(name))
        .unwrap_or_else(|e| panic!("{name}'s advertised outputSchema does not compile: {e}"))
}

fn body(r: &CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// Validate a real tool response against the schema the router advertises.
#[track_caller]
fn assert_matches_schema(name: &str, r: &CallToolResult) -> Value {
    let payload = body(r);
    let compiled = validator(name);
    let errors: Vec<String> = compiled
        .iter_errors(&payload)
        .map(|e| format!("at `{}`: {e}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{name} produced a response its own outputSchema rejects:\n  {}\nresponse: {payload}",
        errors.join("\n  ")
    );
    payload
}

/// Whether the schema rejects `instance` *for the stated reason*.
///
/// The reason matters: a test that only asserted "invalid" would pass for
/// any unrelated breakage, including a schema so wrong that nothing
/// validates.
#[track_caller]
fn assert_rejected_because(
    name: &str,
    instance: &Value,
    why: &str,
    pred: impl Fn(&ValidationErrorKind) -> bool,
) {
    let compiled = validator(name);
    let kinds: Vec<String> = compiled
        .iter_errors(instance)
        .map(|e| format!("{:?}", e.kind()))
        .collect();
    let matched = compiled.iter_errors(instance).any(|e| pred(e.kind()));
    assert!(
        matched,
        "{name}: expected a rejection because {why}; got {kinds:?}"
    );
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .unwrap_or_else(|| panic!("expected an object, got {v}"))
        .keys()
        .cloned()
        .collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

fn bash_args() -> Vec<String> {
    vec!["--norc".into(), "--noprofile".into()]
}

async fn start_bash(server: &ClaspServer) -> (String, CallToolResult) {
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            ..Default::default()
        }))
        .await
        .expect("start_session must not be a protocol error");
    let id = body(&r)["data"]["session_id"]
        .as_str()
        .expect("session_id")
        .to_string();
    (id, r)
}

async fn read_tail(server: &ClaspServer, session: &str) -> CallToolResult {
    server
        .read_output(Parameters(ReadOutputArgs {
            session: session.into(),
            tail_bytes: Some(4096),
            ..Default::default()
        }))
        .await
        .expect("read_output must not be a protocol error")
}

/// Poll until the session's buffer holds `needle`, so the detector has
/// seen a real prompt before the response is sampled.
async fn wait_for(server: &ClaspServer, session: &str, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = read_tail(server, session).await;
        let text = body(&r)["data"]["output"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if text.contains(needle) || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Poll until the session is at an OSC 133 prompt — `AtPrompt` reached
/// via the *semantic* tier, not the terminal-mode one.
///
/// Waiting for `AtPrompt` alone is not enough, and the difference is a
/// measured flake rather than a theoretical one. bash reaches its first
/// prompt (bracketed paste, `terminal_mode`) *before* CLASP has finished
/// typing the §8.5 integration snippet; the snippet then runs, and while
/// it does, readline has ECHO off with bracketed paste momentarily
/// disabled — which the §8.3 ladder classifies as `AwaitingSecret`. A
/// `send_input` landing in that window gets a `session_awaiting_secret`
/// warning, and the no-warning assertion below fails for a reason that
/// has nothing to do with what it is testing. The mutation run caught
/// this twice, under mutants that could not possibly affect `send_input`.
///
/// Once the snippet has run, `t1 && at_marker` answers first in the
/// ladder and echo is never consulted, so `semantic` + `AtPrompt` is a
/// state the session stays in until something is typed.
async fn wait_for_at_prompt(server: &ClaspServer, session: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let data = body(&read_tail(server, session).await)["data"].clone();
        let settled =
            data["interaction_mode"] == "AtPrompt" && data["detection_tier"] == "semantic";
        if settled {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session never reached an OSC 133 prompt; last state: {data}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn kill(server: &ClaspServer, session: &str) {
    let _ = server
        .terminate(Parameters(TerminateArgs {
            session: session.into(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await;
}

/// A registry-resident session backed by a mock, so states a real shell
/// will not reliably reach (echo-off) can be driven through the real tool.
fn mock_session(server: &ClaspServer, echo: Option<bool>) -> (String, Arc<MockPty>) {
    let pty = Arc::new(MockPty::new());
    pty.set_echo(echo);
    let session = Session::new(
        new_session_id(),
        None,
        "mock".into(),
        vec![],
        Arc::clone(&pty) as Arc<dyn PtyBackend>,
        SessionConfig::default(),
    );
    let id = session.id.clone();
    server.registry.insert(session).expect("registry insert");
    (id, pty)
}

// ------------------------------------------------- the advertised surface

#[test]
fn every_tool_advertises_a_compiling_output_schema() {
    for name in TOOLS {
        let schema = output_schema(name);
        assert_eq!(
            schema["type"], "object",
            "{name}: structuredContent is always the §5.1 envelope object"
        );
        assert_eq!(
            schema["required"],
            json!(["status", "data", "details"]),
            "{name}: §5.1 requires all three envelope fields on every response"
        );
        // Compiles under the draft it declares.
        let _ = validator(name);
    }
}

#[test]
fn every_declared_shape_forbids_undeclared_fields() {
    // The load-bearing detail. JSON Schema permits unknown properties by
    // default, so without `additionalProperties: false` a schema that
    // merely *omitted* a field would validate every response and every
    // positive test in this file would pass unconditionally. This asserts
    // the strictness itself, on the envelope and on each tool's `data`.
    for name in TOOLS {
        let schema = output_schema(name);
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{name}: the envelope must reject undeclared fields"
        );
        for (def, body) in schema["$defs"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: schema has no $defs"))
        {
            // Enums are `type: string`; only object shapes carry the flag.
            if body.get("type").is_some_and(|t| t == "object") {
                assert_eq!(
                    body["additionalProperties"],
                    json!(false),
                    "{name}: $defs/{def} must reject undeclared fields"
                );
            }
        }
    }
}

#[test]
fn the_shapes_task_10_will_use_are_declared_and_strict() {
    // `status`, `list_sessions` and `get_command_history` are Task 10's
    // tools, but their schemas are declared here so the surface freezes in
    // one place. Assert the same strictness now — a `deny_unknown_fields`
    // missing from one of these would otherwise only be noticed once the
    // tool that uses it shipped.
    for (label, schema) in [
        (
            "ListSessions",
            schema::envelope_schema::<schema::ListSessions>(),
        ),
        (
            "CommandHistory",
            schema::envelope_schema::<schema::CommandHistory>(),
        ),
        (
            "SessionRecord",
            schema::envelope_schema::<schema::SessionRecord>(),
        ),
    ] {
        let schema = Value::Object(schema.as_ref().clone());
        assert_eq!(schema["additionalProperties"], json!(false), "{label}");
        for (def, body) in schema["$defs"].as_object().expect("$defs") {
            if body.get("type").is_some_and(|t| t == "object") {
                assert_eq!(
                    body["additionalProperties"],
                    json!(false),
                    "{label}: $defs/{def}"
                );
            }
        }
    }
}

#[test]
fn every_tool_declares_the_annotations_5_3_assigns_it() {
    // Four same-typed booleans per tool: transposing two of them compiles,
    // serialises, and passes any test that only checks "annotations are
    // present". Each hint is asserted by name, and the four tools carry
    // four *different* combinations, so a transposition changes an
    // expected value rather than shuffling equal ones.
    //
    // `idempotent_hint` is deliberately absent on `read_output`: the MCP
    // spec says the hint is meaningless for a read-only tool.
    let expected = [
        (
            "start_session",
            "Start a PTY-backed shell session",
            Some(false),
            Some(true),
            Some(false),
            Some(true),
        ),
        (
            "read_output",
            "Read session output",
            Some(true),
            None,
            None,
            Some(false),
        ),
        (
            "send_input",
            "Send keystrokes to a session",
            Some(false),
            Some(true),
            Some(false),
            Some(true),
        ),
        (
            "terminate",
            "Terminate a session",
            Some(false),
            Some(true),
            Some(true),
            Some(false),
        ),
    ];
    for (name, title, read_only, destructive, idempotent, open_world) in expected {
        let a = advertised(name)
            .annotations
            .unwrap_or_else(|| panic!("{name} carries no annotations (REQ-T-014)"));
        assert_eq!(a.title.as_deref(), Some(title), "{name}: title");
        assert_eq!(a.read_only_hint, read_only, "{name}: readOnlyHint");
        assert_eq!(a.destructive_hint, destructive, "{name}: destructiveHint");
        assert_eq!(a.idempotent_hint, idempotent, "{name}: idempotentHint");
        assert_eq!(a.open_world_hint, open_world, "{name}: openWorldHint");
    }
}

#[test]
fn the_status_enum_declares_every_status_the_envelope_can_emit() {
    // `envelope::Status` is what the tools actually serialise;
    // `schema::Status` is what the agent is told to expect. A status added
    // to one and not the other is a response that fails its own schema the
    // first time that path runs, which no positive test here would reach.
    let declared = output_schema("read_output")["$defs"]["Status"]["enum"].clone();
    let declared: BTreeSet<String> = declared
        .as_array()
        .expect("Status is an enum")
        .iter()
        .map(|v| v.as_str().expect("string variant").to_string())
        .collect();

    let emitted: BTreeSet<String> = [
        envelope::Status::Ok,
        envelope::Status::Timeout,
        envelope::Status::SessionDied,
        envelope::Status::SessionNotFound,
        envelope::Status::NameTaken,
        envelope::Status::LimitReached,
        envelope::Status::SpawnFailed,
    ]
    .iter()
    .map(|s| s.as_str().to_string())
    .collect();

    let undeclared: Vec<_> = emitted.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "these statuses are emitted but not declared: {undeclared:?}"
    );
    // The reverse is allowed and intentional: `unavailable` is declared
    // for Task 10's `get_command_history` before the tool exists. Pin it,
    // so "declared but unemitted" cannot grow silently.
    assert_eq!(
        declared.difference(&emitted).collect::<Vec<_>>(),
        vec![&"unavailable".to_string()],
        "only `unavailable` may be declared ahead of its tool"
    );
}

// --------------------------------------------------- real tool responses

#[tokio::test]
async fn start_session_ok_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, r) = start_bash(&server).await;

    let payload = assert_matches_schema("start_session", &r);
    assert_eq!(payload["status"], "ok");
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "session_id",
            "name",
            "pid",
            "cwd",
            "shell_integration",
            "started_at_unix_secs",
        ]),
        "start_session's ok payload changed shape"
    );
    assert_eq!(
        payload["data"]["shell_integration"], "bash",
        "an interactive bash session is integrated (§8.5)"
    );

    kill(&server, &id).await;
}

#[tokio::test]
async fn start_session_spawn_failed_response_matches_its_schema() {
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "clasp-no-such-program-9f2a".into(),
            ..Default::default()
        }))
        .await
        .expect("a spawn failure is a status, not a protocol error");

    let payload = assert_matches_schema("start_session", &r);
    assert_eq!(payload["status"], "spawn_failed");
    // The `spawn_failed` payload is a *different* shape from the `ok` one,
    // which is exactly why every `data` field is optional.
    assert_eq!(keys(&payload["data"]), set(&["command"]));
}

#[tokio::test]
async fn read_output_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    let r = read_tail(&server, &id).await;
    let payload = assert_matches_schema("read_output", &r);
    assert_eq!(payload["status"], "ok");

    kill(&server, &id).await;
}

#[tokio::test]
async fn read_output_emits_every_field_5_4_promises() {
    // The separator that stops the schema tests from being vacuous. Every
    // `data` field is optional, so `read_output` could stop reporting the
    // whole §5.4 session-state block — enums, title, prompt — and still
    // validate. This pins the exact key set instead.
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    let payload = body(&read_tail(&server, &id).await);
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "output",
            "cursor",
            "bytes_returned",
            "truncated_at_tail",
            "truncated_for_size",
            "next_cursor",
            "state",
            "exit_code",
            // The §5.4 block. Dropping `with_detection` deletes these five
            // and leaves every other test in this file green.
            "interaction_mode",
            "detection_tier",
            "screen_tracking",
            "title",
            "prompt",
        ]),
    );
    assert_eq!(
        keys(&payload["data"]["prompt"]),
        set(&[
            "confidence",
            "quiescent_score",
            "pattern_score",
            "cursor_score",
            "reason",
            "last_line",
        ]),
    );

    kill(&server, &id).await;
}

#[tokio::test]
async fn read_output_session_not_found_response_matches_its_schema() {
    let server = ClaspServer::new();
    let r = server
        .read_output(Parameters(ReadOutputArgs {
            session: "sess_does_not_exist".into(),
            tail_bytes: Some(16),
            ..Default::default()
        }))
        .await
        .expect("a missing session is a status, not a protocol error");

    let payload = assert_matches_schema("read_output", &r);
    assert_eq!(payload["status"], "session_not_found");
    assert_eq!(payload["data"], json!({}));
}

#[tokio::test]
async fn send_input_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for_at_prompt(&server, &id).await;

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo SCHEMA''_OK".into(),
            append_newline: None,
        }))
        .await
        .expect("send_input must not be a protocol error");

    let payload = assert_matches_schema("send_input", &r);
    assert_eq!(payload["status"], "ok");
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "bytes_written",
            "warning",
            "interaction_mode",
            "detection_tier",
            "screen_tracking",
            "title",
            "prompt",
        ]),
    );
    // Present and null, not absent: `additionalProperties: false` cannot
    // tell those apart, and `payload["warning"] == Null` cannot either.
    assert!(
        payload["data"]
            .as_object()
            .expect("object")
            .contains_key("warning"),
        "the warning key is emitted on every write, null when there is none"
    );
    assert_eq!(payload["data"]["warning"], Value::Null);

    kill(&server, &id).await;
}

#[tokio::test]
async fn send_input_to_an_echo_off_session_warns_and_still_matches_its_schema() {
    // REQ-SEC-011. `warning` is the one `data` field whose *string* form
    // is only produced on this path; without it the field would only ever
    // be exercised as null, and its declared type would be untested.
    let server = ClaspServer::new();
    let (id, _pty) = mock_session(&server, Some(false));

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "hunter2".into(),
            append_newline: None,
        }))
        .await
        .expect("send_input must not be a protocol error");

    let payload = assert_matches_schema("send_input", &r);
    assert_eq!(payload["status"], "ok", "the write is not blocked");
    assert_eq!(payload["data"]["warning"], "session_awaiting_secret");
    assert_eq!(payload["data"]["interaction_mode"], "AwaitingSecret");
}

#[tokio::test]
async fn send_input_session_died_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, pty) = mock_session(&server, None);
    pty.exit(7);
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.registry.get(&id).expect("session").is_alive() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "x".into(),
            append_newline: None,
        }))
        .await
        .expect("a dead session is a status, not a protocol error");

    let payload = assert_matches_schema("send_input", &r);
    assert_eq!(payload["status"], "session_died");
    assert_eq!(keys(&payload["data"]), set(&["exit_code"]));
    assert_eq!(payload["data"]["exit_code"], 7);
}

#[tokio::test]
async fn terminate_responses_match_their_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;

    let first = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await
        .expect("terminate must not be a protocol error");
    let payload = assert_matches_schema("terminate", &first);
    assert_eq!(payload["status"], "ok");
    assert_eq!(
        keys(&payload["data"]),
        set(&["exit_code", "already_exited"])
    );
    assert_eq!(payload["data"]["already_exited"], false);

    // The idempotent second call is a different `data` population.
    let second = server
        .terminate(Parameters(TerminateArgs {
            session: id.clone(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await
        .expect("terminate must not be a protocol error");
    let payload = assert_matches_schema("terminate", &second);
    assert_eq!(payload["data"]["already_exited"], true);
}

/// A backend whose `write` parks until it is released.
///
/// `timeout` is the one §18.1 status the 0.0.2 tools emit whose `data`
/// shape (`{bytes_written: null, timeout_ms}`) no other test reaches, and
/// it is exactly the case the schema work is meant to catch: had
/// `timeout_ms` been left out of `schema::SendInput`, `additionalProperties:
/// false` would reject the response the first time a child stopped
/// draining its tty — in production, with nothing to have caught it.
/// `MockPty` accepts every write instantly, so this exists to park one.
struct GatedPty {
    gate: std::sync::Mutex<bool>,
    released: std::sync::Condvar,
}

impl GatedPty {
    fn new() -> Self {
        Self {
            gate: std::sync::Mutex::new(false),
            released: std::sync::Condvar::new(),
        }
    }

    /// Let the parked write finish, so the blocking pool drains and the
    /// runtime can shut down instead of hanging on drop.
    fn release(&self) {
        *self.gate.lock().expect("gate") = true;
        self.released.notify_all();
    }
}

impl PtyBackend for GatedPty {
    fn write(&self, _data: &[u8]) -> clasp_core::Result<()> {
        let mut open = self.gate.lock().expect("gate");
        while !*open {
            open = self.released.wait(open).expect("gate");
        }
        Ok(())
    }
    fn read(&self, _buf: &mut [u8]) -> clasp_core::Result<usize> {
        std::thread::sleep(Duration::from_millis(20));
        Ok(0)
    }
    fn signal(&self, _sig: clasp_core::pty::Signal) -> clasp_core::Result<()> {
        Ok(())
    }
    fn resize(&self, _cols: u16, _rows: u16) -> clasp_core::Result<()> {
        Ok(())
    }
    fn is_alive(&self) -> bool {
        true
    }
    fn exit_code(&self) -> Option<i32> {
        None
    }
    fn pid(&self) -> Option<u32> {
        None
    }
}

#[tokio::test]
async fn send_input_timeout_response_matches_its_schema() {
    let server = ClaspServer::new();
    let pty = Arc::new(GatedPty::new());
    let session = Session::new(
        new_session_id(),
        None,
        "gated".into(),
        vec![],
        Arc::clone(&pty) as Arc<dyn PtyBackend>,
        SessionConfig::default(),
    );
    let id = session.id.clone();
    server.registry.insert(session).expect("registry insert");

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id,
            data: "x".into(),
            append_newline: Some(false),
        }))
        .await
        .expect("a write deadline is a status, not a protocol error");
    pty.release();

    let payload = assert_matches_schema("send_input", &r);
    assert_eq!(payload["status"], "timeout");
    assert_eq!(
        keys(&payload["data"]),
        set(&["bytes_written", "timeout_ms"])
    );
    assert!(
        payload["data"]["bytes_written"].is_null(),
        "a partial write may have landed, so a count would be a guess"
    );
    assert!(
        payload["data"]["timeout_ms"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "the deadline actually applied must be reported: {payload}"
    );
}

// ------------------------------------------------------- falsification

#[tokio::test]
async fn an_undeclared_field_is_rejected() {
    // The proof that the positive tests above can fail. Take a response
    // that *does* validate, add one field nobody declared, and require the
    // validator to name it.
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;
    let mut payload = assert_matches_schema("read_output", &read_tail(&server, &id).await);
    kill(&server, &id).await;

    payload["data"]["undeclared_field"] = json!(1);
    assert_rejected_because(
        "read_output",
        &payload,
        "`undeclared_field` is not in the schema",
        |k| {
            matches!(
                k,
                ValidationErrorKind::AdditionalProperties { unexpected }
                    if unexpected.iter().any(|u| u == "undeclared_field")
            )
        },
    );
}

#[tokio::test]
async fn a_missing_envelope_field_is_rejected() {
    let server = ClaspServer::new();
    let (id, started) = start_bash(&server).await;
    let mut payload = assert_matches_schema("start_session", &started);
    kill(&server, &id).await;

    payload
        .as_object_mut()
        .expect("object")
        .remove("details")
        .expect("details was present");
    assert_rejected_because(
        "start_session",
        &payload,
        "§5.1 requires `details` on every response",
        |k| matches!(k, ValidationErrorKind::Required { property } if property == "details"),
    );
}

#[tokio::test]
async fn a_wrongly_typed_field_is_rejected() {
    // `cursor` and `bytes_returned` are both `uint64`; `output` and
    // `state` are both strings. A schema that merely listed the field
    // names would accept any of them holding any of the others' values.
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;
    let payload = assert_matches_schema("read_output", &read_tail(&server, &id).await);
    kill(&server, &id).await;

    for (field, bad) in [
        ("cursor", json!("not a number")),
        ("state", json!(3)),
        ("truncated_at_tail", json!("yes")),
        ("interaction_mode", json!("NotAMode")),
        ("detection_tier", json!("terminal-mode")),
        ("screen_tracking", json!("on")),
        ("prompt", json!({ "confidence": 1.0 })),
    ] {
        let mut broken = payload.clone();
        broken["data"][field] = bad.clone();
        assert!(
            !validator("read_output").is_valid(&broken),
            "read_output's schema accepted `{field}: {bad}`"
        );
    }
}

#[tokio::test]
async fn the_status_field_is_constrained_to_the_declared_enum() {
    let server = ClaspServer::new();
    let (id, started) = start_bash(&server).await;
    let mut payload = assert_matches_schema("start_session", &started);
    kill(&server, &id).await;

    payload["status"] = json!("everything_is_fine");
    assert_rejected_because(
        "start_session",
        &payload,
        "`everything_is_fine` is not one of the §18.1 statuses",
        |k| matches!(k, ValidationErrorKind::Enum { .. }),
    );
}
