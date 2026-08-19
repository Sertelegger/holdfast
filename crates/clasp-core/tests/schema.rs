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

use clasp_core::detect::Shell;
use clasp_core::mcp::envelope;
use clasp_core::mcp::tools::{
    GetCommandHistoryArgs, GetScreenStateArgs, InterruptArgs, ReadOutputArgs, ResizeArgs,
    SendInputArgs, StartSessionArgs, StatusArgs, TerminateArgs, WaitForPatternArgs,
};
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
        "status" => ClaspServer::status_tool_attr(),
        "list_sessions" => ClaspServer::list_sessions_tool_attr(),
        "get_command_history" => ClaspServer::get_command_history_tool_attr(),
        "wait_for_pattern" => ClaspServer::wait_for_pattern_tool_attr(),
        "get_screen_state" => ClaspServer::get_screen_state_tool_attr(),
        "resize" => ClaspServer::resize_tool_attr(),
        "interrupt" => ClaspServer::interrupt_tool_attr(),
        other => panic!("no such tool: {other}"),
    }
}

/// Every tool 0.0.4 ships. REQ-T-013 says "every tool", so this is
/// enumerated rather than spot-checked: a tool added later without a
/// schema, or without annotations, fails the loops below.
///
/// **This array cannot see a tool that is in the router and not here** —
/// `advertised()` panics on an unknown *name*, which is the other
/// direction. `mcp::tools::tests::the_router_advertises_exactly_the_0_0_4_
/// tool_set` is the link that closes it, because it reads `tool_router()`
/// and this file cannot (`tool_router` is `pub(crate)`).
const TOOLS: [&str; 11] = [
    "start_session",
    "read_output",
    "send_input",
    "terminate",
    "status",
    "list_sessions",
    "get_command_history",
    "wait_for_pattern",
    "get_screen_state",
    "resize",
    "interrupt",
];

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

/// The §5.4 `prompt` block's key set, enumerated once (REQ-T-019).
fn prompt_keys() -> BTreeSet<String> {
    set(&[
        "confidence",
        "quiescent_score",
        "pattern_score",
        "cursor_score",
        "reason",
        "last_line",
    ])
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
///
/// Asserts on the deadline rather than returning quietly. A silent return
/// is the shape that produced the flake `b04e4f2` fixed: every downstream
/// assertion still fails, but it fails describing a *response*, several
/// screens away from the fact that the session never got where the test
/// needed it. `wait_for_at_prompt` was hardened out of the same shape.
async fn wait_for(server: &ClaspServer, session: &str, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = read_tail(server, session).await;
        let text = body(&r)["data"]["output"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if text.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session never produced {needle:?}; last output: {text:?}"
        );
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
    let id = register(server, None, "mock", &[], SessionConfig::default(), &pty);
    (id, pty)
}

/// Register a mock-backed session with a chosen identity and config.
///
/// `status` and `list_sessions` report a dozen fields off the `Session`,
/// most of them same-typed; a real `bash` session cannot give them
/// distinguishable values (`command` and `shell_integration` are both
/// `"bash"`), so the value assertions drive a mock whose every field is
/// different from every other.
fn register(
    server: &ClaspServer,
    name: Option<&str>,
    command: &str,
    args: &[&str],
    config: SessionConfig,
    pty: &Arc<MockPty>,
) -> String {
    let session = Session::new(
        new_session_id(),
        name.map(str::to_string),
        command.to_string(),
        args.iter().map(|a| (*a).to_string()).collect(),
        Arc::clone(pty) as Arc<dyn PtyBackend>,
        config,
    );
    let id = session.id.clone();
    server.registry.insert(session).expect("registry insert");
    id
}

/// Milliseconds since the Unix epoch, for bounding a reported timestamp
/// from a reading taken in the test rather than from a constant.
fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}

/// Poll until `pred` holds, or fail with `what`.
async fn until(what: &str, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pred() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(pred(), "timed out waiting for {what}");
}

/// The §5.4 session-state block, which `status` and every `list_sessions`
/// entry carry as siblings of the record's own fields.
const DETECTION_FIELDS: [&str; 5] = [
    "interaction_mode",
    "detection_tier",
    "screen_tracking",
    "title",
    "prompt",
];

/// Every key a `SessionRecord` carries: §5.2's own fields plus §5.4's.
fn session_record_keys() -> BTreeSet<String> {
    let mut all = set(&[
        "id",
        "name",
        "command",
        "args",
        "state",
        "pid",
        "exit_code",
        "shell_integration",
        "osc133_source",
        "command_count",
        "started_at_unix_secs",
        "exited_at_unix_secs",
        "last_activity_unix_ms",
        // 0.0.5's reaper closes §5.2's declared-but-unemitted
        // `idle_deadline`. Emitted through the one shared
        // `session_record`, so `list_sessions` carries it too — a field
        // on only one of the two is REQ-T-015's fault.
        "idle_deadline_unix_secs",
        "buffer",
        // The session's cumulative redaction tally (§9.2, REQ-O-012).
        // Emitted by both tools through the one shared `session_record`,
        // which is why it belongs in this shared literal rather than in
        // `status`'s alone.
        "redaction_stats",
    ]);
    all.extend(set(&DETECTION_FIELDS));
    all
}

/// Two OSC 133 commands with distinct texts and distinct non-zero exit
/// codes, so no entry's field can be confused with another's.
const TWO_COMMANDS: &[u8] = b"\x1b]133;A\x07$ \x1b]133;B\x07echo one\r\n\x1b]133;C\x07one\r\n\
\x1b]133;D;3\x07\x1b]133;A\x07$ \x1b]133;B\x07echo two\r\n\x1b]133;C\x07two\r\n\x1b]133;D;4\x07";

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

/// Every object subschema reachable from `schema`, as `(path, subschema)`.
///
/// A recursive walk rather than a look at `$defs`: whether schemars hoists
/// a nested shape into `$defs` or inlines it under `properties` is its
/// choice, not the contract, and a shape that got inlined would silently
/// drop out of a `$defs`-only sweep.
fn object_subschemas<'a>(path: &str, schema: &'a Value, out: &mut Vec<(String, &'a Value)>) {
    let Some(map) = schema.as_object() else {
        return;
    };
    if map.get("type").is_some_and(|t| t == "object") {
        out.push((path.to_string(), schema));
    }
    for key in ["properties", "$defs", "definitions"] {
        if let Some(children) = map.get(key).and_then(Value::as_object) {
            for (name, child) in children {
                object_subschemas(&format!("{path}/{key}/{name}"), child, out);
            }
        }
    }
    for key in ["items", "additionalProperties", "not"] {
        if let Some(child) = map.get(key) {
            object_subschemas(&format!("{path}/{key}"), child, out);
        }
    }
    for key in ["anyOf", "oneOf", "allOf", "prefixItems"] {
        if let Some(children) = map.get(key).and_then(Value::as_array) {
            for (i, child) in children.iter().enumerate() {
                object_subschemas(&format!("{path}/{key}/{i}"), child, out);
            }
        }
    }
}

#[test]
fn every_declared_shape_forbids_undeclared_fields() {
    // The load-bearing detail. JSON Schema permits unknown properties by
    // default, so without `additionalProperties: false` a schema that
    // merely *omitted* a field would validate every response and every
    // positive test in this file would pass unconditionally. This asserts
    // the strictness itself, on the envelope and on every object shape
    // underneath it — `SessionRecord`, `Buffer`, `Prompt`, `CommandEntry`.
    for name in TOOLS {
        let schema = output_schema(name);
        let mut found = Vec::new();
        object_subschemas("#", &schema, &mut found);
        // The envelope, `data`, and at minimum one shape below it. A walk
        // that silently found nothing would make the loop vacuous.
        assert!(
            found.len() >= 2,
            "{name}: only {} object shape(s) reachable; the walk found nothing to check",
            found.len()
        );
        for (path, body) in found {
            assert_eq!(
                body["additionalProperties"],
                json!(false),
                "{name}: {path} must reject undeclared fields"
            );
        }

        // The generalisation of the `CommandHistory::entries` bug, asserted
        // at *declaration* time instead of two tasks later.
        //
        // `entries` was declared as a bare `Vec`, so schemars marked it
        // `required`, and `get_command_history` answers a missing session
        // through `envelope::from_error` — whose `data` is always `{}`. The
        // tool therefore produced a response its own advertised schema
        // rejected, in production, on a path no test reached. The loop above
        // checks `additionalProperties` and never `required`, so it could
        // not see it.
        //
        // This is the one payload every tool that takes a `session`
        // argument can emit, byte for byte, and it is the cheapest possible
        // statement of the module header's rule that every `data` field is
        // optional.
        let error_envelope = json!({
            "status": "session_not_found",
            "data": {},
            "details": "",
        });
        let accepted = validator(name).is_valid(&error_envelope);
        if name == "list_sessions" {
            // The one deliberate exception, and it is asserted as the
            // *negative* rather than skipped. `ListSessions::sessions` stays
            // required because this tool takes no arguments and emits only
            // `ok`, so it has no second `data` shape. That premise lives in
            // a comment in `schema.rs`; 0.0.5 puts the tool behind the
            // daemon control protocol, where an error envelope becomes
            // plausible. Pinning the rejection here makes the premise go red
            // the moment it stops holding, instead of shipping the bug above
            // a second time.
            assert!(
                !accepted,
                "list_sessions declares `sessions` required on the premise \
                 that it emits only `ok`; it now accepts an error envelope, \
                 so either the premise or the declaration has changed"
            );
        } else {
            assert!(
                accepted,
                "{name} advertises a schema that rejects the \
                 `session_not_found` envelope `envelope::from_error` builds \
                 for it — a `data` field is declared required"
            );
        }
    }
}

/// REQ-SEC-006's echo half, and the reason it is testable at all.
///
/// §9.2 requires `env` values to be redacted "in any echo back via
/// `status` etc.". v0.1.0 satisfies that the stronger way: **no tool
/// returns `env` on any Returns list**, so there is no echo to redact.
/// That is a decision, not an accident — the audit log is keys-only
/// (`session_start`, REQ-SEC-006) and a response field carrying the map
/// would reintroduce, on the MCP wire, exactly the exposure the log
/// avoids. Whoever adds an `env` field to `SessionRecord` for the
/// convenience of it gets this test, and the decision, in front of them.
///
/// The `start_session` assertion at the end is the pair. `env` is an
/// *input* — the whole point of the argument — and asserting its presence
/// there is what stops this test from passing because the walk found
/// nothing, or because `env` was spelled differently everywhere.
#[test]
fn no_tool_advertises_an_env_field_to_echo() {
    let mut shapes = 0usize;
    for name in TOOLS {
        let schema = output_schema(name);
        let mut found = Vec::new();
        object_subschemas("#", &schema, &mut found);
        assert!(found.len() >= 2, "{name}: the walk found nothing to check");
        for (path, body) in found {
            shapes += 1;
            if let Some(props) = body.get("properties").and_then(Value::as_object) {
                assert!(
                    !props.contains_key("env"),
                    "{name}: {path} declares an `env` field. v0.1.0's \
                     protection for env values is that no response carries \
                     them (REQ-SEC-006); adding one turns that structural \
                     guarantee into a redaction outcome, and the redactor \
                     only catches secret-*shaped* values"
                );
            }
        }
    }
    assert!(
        shapes >= 2 * TOOLS.len(),
        "only {shapes} object shape(s) across {} tools; the sweep is not \
         reaching the record shapes",
        TOOLS.len()
    );

    let input = advertised("start_session").input_schema;
    assert!(
        input
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|p| p.contains_key("env")),
        "`env` is not spelled `env` on the way *in* either, so the sweep \
         above is looking for a name nothing uses"
    );
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
        (
            "wait_for_pattern",
            "Wait for a regex to match output",
            Some(true),
            None,
            None,
            Some(false),
        ),
        // The read-only tools share one hint combination, so the
        // *title* is what distinguishes them: a `status` that advertised
        // `list_sessions`'s annotations would pass the boolean columns and
        // fail here.
        (
            "status",
            "Get detailed session status",
            Some(true),
            None,
            None,
            Some(false),
        ),
        // "List all sessions", not "List active sessions": the tool returns
        // every registry entry, exited ones included. The title is the
        // second agent-visible string that said otherwise — this row going
        // red when the description was corrected is the guard working.
        (
            "list_sessions",
            "List all sessions",
            Some(true),
            None,
            None,
            Some(false),
        ),
        (
            "get_command_history",
            "List commands run, with exit codes",
            Some(true),
            None,
            None,
            Some(false),
        ),
        // §5.3: read-only even though the call can enable Tier B, because
        // that changes CLASP's bookkeeping and not the session.
        (
            "get_screen_state",
            "Read the rendered terminal screen",
            Some(true),
            None,
            None,
            Some(false),
        ),
        // The one non-read-only tool that is `idempotentHint: true` and
        // `destructiveHint: false` — resizing to the size already in force
        // is a no-op, and no other row in this table carries that pair.
        (
            "resize",
            "Resize a session's terminal",
            Some(false),
            Some(false),
            Some(true),
            Some(false),
        ),
        // REQ-T-010's interrupt half: `interrupt` and `terminate` differ
        // exactly here. Copying `terminate`'s row by reflex gives
        // `idempotent: true, open_world: false`, and both are wrong.
        (
            "interrupt",
            "Send Ctrl+C to a session's process group",
            Some(false),
            Some(true),
            Some(false),
            Some(true),
        ),
    ];
    assert_eq!(
        expected.len(),
        TOOLS.len(),
        "every tool must have a row here, or REQ-T-014 is only spot-checked"
    );
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

/// Every variant of `envelope::Status`, enumerated so that **the compiler**
/// refuses to build until a newly added one is accounted for.
///
/// This used to be a hand-written array, and that is the whole reason this
/// function exists. A reviewer added a `Cancelled` variant with an `as_str`
/// arm returning a status `schema::Status` does not declare, and the entire
/// 252-test suite passed — the array simply did not mention it, so the
/// "emitted" set stayed at eight and both differences below stayed empty.
/// The test's own comment says it exists to catch exactly that drift.
///
/// The array was self-healing in one direction only: `declared − emitted`
/// forces a manual update when a variant is added to *`schema::Status`*, so
/// `unavailable` did make this go red. A variant added to the *emitting*
/// side was invisible.
///
/// `successor` is a walk over every variant rather than a `match` beside a
/// list, because a `match` beside a list can be satisfied by adding an arm
/// and forgetting the list — which is the same hole one level in. Here the
/// walk **is** the list: adding a variant to `envelope::Status` makes this
/// `match` non-exhaustive and this file stops compiling, and the arm the
/// compiler then demands can only be written by linking the new variant
/// into the chain.
///
/// Residual, stated so it is not mistaken for airtightness: a *deliberate*
/// dead-end arm (`Cancelled => None` while `Unavailable => None` stays) is
/// unreachable and would not be walked. Nothing short of reflection closes
/// that, and the `assert!(!seen.contains(..))` below at least makes a
/// mis-linked chain fail loudly rather than loop.
fn every_envelope_status() -> Vec<envelope::Status> {
    use envelope::Status as S;

    fn successor(s: S) -> Option<S> {
        match s {
            S::Ok => Some(S::Timeout),
            S::Timeout => Some(S::SessionDied),
            S::SessionDied => Some(S::SessionNotFound),
            S::SessionNotFound => Some(S::NameTaken),
            S::NameTaken => Some(S::LimitReached),
            S::LimitReached => Some(S::SpawnFailed),
            S::SpawnFailed => Some(S::Unavailable),
            S::Unavailable => None,
        }
    }

    let mut walk = vec![S::Ok];
    while let Some(next) = successor(*walk.last().expect("the walk starts non-empty")) {
        assert!(
            !walk.contains(&next),
            "the status walk revisits {:?}; the chain in `successor` is \
             mis-linked and is not enumerating every variant",
            next.as_str()
        );
        walk.push(next);
    }
    walk
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

    let emitted: BTreeSet<String> = every_envelope_status()
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    // The walk is the enumeration, so it cannot be short. Asserted anyway,
    // because a `successor` chain that somehow returned `None` on its first
    // step would make both differences below empty against an empty set.
    assert!(
        emitted.len() >= 8,
        "the status walk found only {} variant(s); it is not enumerating",
        emitted.len()
    );

    // Both directions, and both matter. A status emitted but not declared
    // is a response that fails its own schema the first time that path
    // runs. A status declared but not emitted is vocabulary the agent is
    // told to branch on and never sees — which is what `unavailable` was
    // until `get_command_history` shipped, and the reason this assertion
    // used to allow exactly that one exception. It no longer does.
    assert_eq!(
        emitted.difference(&declared).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "these statuses are emitted but not declared"
    );
    assert_eq!(
        declared.difference(&emitted).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "these statuses are declared but no tool can emit them"
    );
}

#[test]
fn the_closed_vocabularies_declare_exactly_what_the_session_emits() {
    // `state` and `shell_integration` were declared `Option<String>`, so
    // `state: "banana"` and `shell_integration: "not-a-shell"` validated
    // against the schema the agent is handed. Both mirror a closed
    // vocabulary that already exists in production — `SessionState::as_str`
    // and `Shell::as_str` — and both are fields the agent branches on, so
    // "any string" is the wrong declaration for the same reason it would be
    // for `interaction_mode`.
    //
    // Declaring them as enums creates the drift this whole file exists to
    // stop, one level down: a fifth `SessionState` is a value the agent is
    // told cannot occur. So both sides are enumerated by exhaustive `match`
    // — the same construction `every_envelope_status` uses, for the same
    // reason.
    let declared = |tool: &str, def: &str| -> BTreeSet<String> {
        output_schema(tool)["$defs"][def]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{tool}: $defs/{def} is not an enum"))
            .iter()
            .map(|v| v.as_str().expect("string variant").to_string())
            .collect()
    };

    // `SessionState` carries data in two of its four variants, so the walk
    // constructs them; the payload is irrelevant to `as_str` and the values
    // below are chosen only to be constructible.
    use clasp_core::session::SessionState as St;
    fn next_state(s: &St) -> Option<St> {
        match s {
            St::Starting => Some(St::Running),
            St::Running => Some(St::Exited(0)),
            St::Exited(_) => Some(St::Dead(String::new())),
            St::Dead(_) => None,
        }
    }
    let mut states = vec![St::Starting];
    while let Some(next) = next_state(states.last().expect("non-empty")) {
        assert!(
            !states.iter().any(|s| s.as_str() == next.as_str()),
            "the SessionState walk revisits {:?}",
            next.as_str()
        );
        states.push(next);
    }
    let emitted_states: BTreeSet<String> = states.iter().map(|s| s.as_str().to_string()).collect();

    fn next_shell(s: Shell) -> Option<Shell> {
        match s {
            Shell::Bash => Some(Shell::Zsh),
            Shell::Zsh => Some(Shell::Fish),
            Shell::Fish => None,
        }
    }
    let mut shells = vec![Shell::Bash];
    while let Some(next) = next_shell(*shells.last().expect("non-empty")) {
        assert!(
            !shells.contains(&next),
            "the Shell walk revisits {:?}",
            next.as_str()
        );
        shells.push(next);
    }
    let emitted_shells: BTreeSet<String> = shells.iter().map(|s| s.as_str().to_string()).collect();

    // §8.5.1's `osc133_source`, walked the same way. It is a *third*
    // vocabulary rather than a fourth `ShellIntegration` value because
    // §12.3's append-only rule is written over fields, not over enum value
    // sets — and because `mixed` is a state no answer to "which shell did
    // CLASP inject for" could carry.
    use clasp_core::detect::Osc133Source as Src;
    fn next_source(s: Src) -> Option<Src> {
        match s {
            Src::Clasp => Some(Src::External),
            Src::External => Some(Src::Mixed),
            Src::Mixed => None,
        }
    }
    let mut sources = vec![Src::Clasp];
    while let Some(next) = next_source(*sources.last().expect("non-empty")) {
        assert!(
            !sources.contains(&next),
            "the Osc133Source walk revisits {:?}",
            next.as_str()
        );
        sources.push(next);
    }
    let emitted_sources: BTreeSet<String> =
        sources.iter().map(|s| s.as_str().to_string()).collect();

    // Both directions. A value emitted but not declared is a response that
    // fails its own schema; a value declared but not emitted is vocabulary
    // the agent is told to branch on and never sees.
    assert_eq!(
        declared("status", "SessionState"),
        emitted_states,
        "schema::SessionState and session::SessionState::as_str disagree"
    );
    assert_eq!(
        declared("read_output", "SessionState"),
        emitted_states,
        "read_output declares a different `state` vocabulary than `status`"
    );
    assert_eq!(
        declared("status", "ShellIntegration"),
        emitted_shells,
        "schema::ShellIntegration and detect::Shell::as_str disagree"
    );
    assert_eq!(
        declared("status", "Osc133Source"),
        emitted_sources,
        "schema::Osc133Source and detect::Osc133Source::as_str disagree"
    );
    assert_eq!(emitted_states.len(), 4);
    assert_eq!(emitted_shells.len(), 3);
    assert_eq!(emitted_sources.len(), 3);
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

/// §18.1 `name_taken`, driven through the real tool.
///
/// Every §18.1 status any 0.0.2 tool can emit is driven for real
/// somewhere in this file, and these two `start_session` rows plus the two
/// `session_not_found` rows below are what makes that true rather than
/// nearly true. Nothing about them was broken — all four shapes accept
/// `data: {}`, which is what `envelope::from_error` always produces — but
/// an unexercised branch is a branch whose payload shape is asserted by
/// inspection, and inspection is what `CommandHistory`'s `required:
/// ["entries"]` survived for two tasks.
///
/// The occupying session is a **mock**: the name has to belong to a *live*
/// session (§4.1 releases a name when its session exits), and a mock is
/// alive on construction without a second PTY having to stay up for it.
#[tokio::test]
async fn start_session_name_taken_response_matches_its_schema() {
    let server = ClaspServer::new();
    let pty = Arc::new(MockPty::new());
    let _occupant = register(
        &server,
        Some("taken"),
        "mock",
        &[],
        SessionConfig::default(),
        &pty,
    );

    let before = server.registry.all().len();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            name: Some("taken".into()),
            ..Default::default()
        }))
        .await
        .expect("a taken name is a status, not a protocol error");

    let payload = assert_matches_schema("start_session", &r);
    assert_eq!(payload["status"], "name_taken");
    assert_eq!(payload["data"], json!({}));
    // The child is spawned before the registry is consulted, so the
    // rejection path has to kill it. A rejected `start_session` that left
    // a running shell behind would still pass every schema assertion
    // above, and the registry is the only place the leak would show.
    assert_eq!(
        server.registry.all().len(),
        before,
        "the rejected session was registered anyway"
    );
}

/// §18.1 `limit_reached`.
///
/// The limit counts *live* sessions, so the fill has to be live and the
/// separator has to be a session that would otherwise have been accepted:
/// `DEFAULT_MAX_SESSIONS` mocks in, one real `start_session` rejected.
#[tokio::test]
async fn start_session_limit_reached_response_matches_its_schema() {
    let server = ClaspServer::new();
    let mut ptys = Vec::new();
    for _ in 0..clasp_core::session::registry::DEFAULT_MAX_SESSIONS {
        let pty = Arc::new(MockPty::new());
        register(&server, None, "mock", &[], SessionConfig::default(), &pty);
        ptys.push(pty);
    }

    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: bash_args(),
            ..Default::default()
        }))
        .await
        .expect("a full registry is a status, not a protocol error");

    let payload = assert_matches_schema("start_session", &r);
    assert_eq!(payload["status"], "limit_reached");
    assert_eq!(payload["data"], json!({}));
    assert_eq!(
        server.registry.all().len(),
        clasp_core::session::registry::DEFAULT_MAX_SESSIONS,
        "the rejected session was registered anyway"
    );

    // The separator: with one slot freed the identical call succeeds, so
    // this pins the *limit* rather than "start_session rejects everything".
    ptys[0].exit(0);
    until("the freed slot to be observed", || {
        server.registry.live_count() < clasp_core::session::registry::DEFAULT_MAX_SESSIONS
    })
    .await;
    let (id, r) = start_bash(&server).await;
    assert_eq!(body(&r)["status"], "ok");
    kill(&server, &id).await;
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
            // 0.0.3's two: the read stopped at the holdback boundary
            // (§4.1), and what it replaced on the way out (§5.2,
            // REQ-O-012). Both are declared on `schema::ReadOutput`, so
            // this literal is what catches either half being skipped —
            // an undeclared emitted field fails `assert_matches_schema`
            // with `Additional properties are not allowed`, and a
            // declared unemitted one fails only here.
            "held_back",
            "redactions",
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

/// §18.1 `session_not_found` on the two tools that resolve a session and
/// then *write* to it.
///
/// `read_output`, `status` and `get_command_history` each drive this
/// already; `send_input` and `terminate` did not, and they are the two
/// where the status has to arrive without the side effect. The assertions
/// are therefore the same envelope plus the absence of any registry
/// change: a resolver that inserted, resurrected or otherwise materialised
/// the missing session would still return `session_not_found`.
#[tokio::test]
async fn send_input_and_terminate_session_not_found_responses_match_their_schema() {
    let server = ClaspServer::new();

    let r = server
        .send_input(Parameters(SendInputArgs {
            session: "sess_does_not_exist".into(),
            data: "echo nope".into(),
            append_newline: None,
            ..Default::default()
        }))
        .await
        .expect("a missing session is a status, not a protocol error");
    let payload = assert_matches_schema("send_input", &r);
    assert_eq!(payload["status"], "session_not_found");
    // Not `keys(...)` against a set: the point here is that the write path
    // emits the *empty* payload `envelope::from_error` builds, with none
    // of the §5.4 detection block a resolved `send_input` carries.
    assert_eq!(payload["data"], json!({}));

    let r = server
        .terminate(Parameters(TerminateArgs {
            session: "sess_does_not_exist".into(),
            force: Some(true),
            timeout_secs: None,
        }))
        .await
        .expect("a missing session is a status, not a protocol error");
    let payload = assert_matches_schema("terminate", &r);
    assert_eq!(payload["status"], "session_not_found");
    assert_eq!(payload["data"], json!({}));

    assert!(
        server.registry.all().is_empty(),
        "resolving a missing session created one"
    );
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        set(&["exit_code", "already_exited", "exited_at_unix_secs"])
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

// ------------------------------------- status / list_sessions / history

#[tokio::test]
async fn status_response_matches_its_schema() {
    // Against a *real* bash, so `pid` is a live process id and
    // `shell_integration` is the value `detect_shell` produced rather than
    // one the test handed in. The field *values* are pinned separately, on
    // a mock that can make every same-typed field differ.
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    let r = server
        .status(Parameters(StatusArgs {
            session: id.clone(),
        }))
        .await
        .expect("status must not be a protocol error");

    let payload = assert_matches_schema("status", &r);
    assert_eq!(payload["status"], "ok");
    assert_eq!(
        keys(&payload["data"]),
        session_record_keys(),
        "status's record changed shape"
    );
    assert_eq!(
        keys(&payload["data"]["buffer"]),
        set(&["head", "tail"]),
        "the buffer extent changed shape"
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
    assert!(
        payload["data"]["pid"].as_u64().is_some_and(|p| p > 0),
        "a live session reports its child's pid: {payload}"
    );
    assert_eq!(
        payload["data"]["shell_integration"], "bash",
        "an interactive bash session is integrated (§8.5)"
    );

    kill(&server, &id).await;
}

#[tokio::test]
async fn status_reports_each_field_from_the_session_it_names() {
    // Twelve fields, most of them same-typed: five strings (`id`, `name`,
    // `command`, `state`, `shell_integration`) and five numbers. Any two
    // transposed still compiles, still serialises, and still passes the
    // key-set assertion above. So this session is built so that no two
    // fields of a type can hold the same value — which a real `bash`
    // session cannot do, since its `command` and `shell_integration` are
    // both "bash".
    let server = ClaspServer::new();
    let pty = Arc::new(MockPty::new());
    pty.queue_output(TWO_COMMANDS);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let id = register(
        &server,
        Some("beta"),
        "mycmd",
        &["a1", "a2"],
        SessionConfig {
            shell_integration: Some(Shell::Fish),
            ..SessionConfig::with_buffer_capacity(4096)
        },
        &pty,
    );
    let session = server.registry.get(&id).expect("session");
    until("both commands to be recorded", || {
        session.command_count() == 2
    })
    .await;

    let payload = assert_matches_schema(
        "status",
        &server
            .status(Parameters(StatusArgs {
                session: id.clone(),
            }))
            .await
            .expect("status must not be a protocol error"),
    );
    let data = &payload["data"];

    assert_eq!(data["id"], id.as_str());
    assert_eq!(data["name"], "beta");
    assert_eq!(data["command"], "mycmd");
    assert_eq!(data["args"], json!(["a1", "a2"]));
    assert_eq!(data["state"], "Running");
    assert_eq!(data["shell_integration"], "fish");
    assert_eq!(data["pid"], 4242, "MockPty's pid, not some other number");
    assert_eq!(data["exit_code"], Value::Null, "the child is still running");
    assert_eq!(data["command_count"], 2);
    // `head` is the byte count the reader accumulated and `tail` is 0
    // because nothing was evicted from a 4 KiB buffer — two numbers that a
    // transposition would swap and neither of which equals `command_count`.
    assert_eq!(data["buffer"]["head"], TWO_COMMANDS.len() as u64);
    assert_eq!(data["buffer"]["tail"], 0);
    // Seconds and milliseconds differ by three orders of magnitude, so
    // each bound also proves the other field was not used.
    let started = data["started_at_unix_secs"].as_u64().expect("secs");
    assert!(
        started >= before && started <= before + 60,
        "started_at_unix_secs is {started}, not a clock reading in seconds"
    );
    let activity = data["last_activity_unix_ms"].as_i64().expect("ms");
    assert!(
        activity >= (before as i64) * 1000,
        "last_activity_unix_ms is {activity}, not a clock reading in milliseconds"
    );
    // `details` is §5.1 agent-visible text and is the `content[0]` block
    // that clients ignoring `structuredContent` read. Replacing this
    // `format!` with a constant survived the whole suite. It carries the
    // session id, so pinning it is also a second, independent statement
    // that `status` answered about the session it was asked about.
    assert_eq!(
        payload["details"],
        format!("status of {id}"),
        "status' details line is what a client that ignores structuredContent sees"
    );

    // `osc133_source` is what the session *observed*, and it answers a
    // different question from `shell_integration` two assertions up — which
    // reads `"fish"` here while no fish is involved at all. `TWO_COMMANDS`
    // carries **untagged** markers, so under §8.5.1 every letter is foreign
    // and every one of CLASP's would be discarded.
    assert_eq!(
        data["osc133_source"], "external",
        "untagged markers are a foreign emitter's"
    );

    // The other value, on a second mock fed a `clasp=1`-tagged copy of the
    // same stream — cheaper than a real shell and enough to keep both
    // values exercised, so a `session_record` that hardcoded either one
    // fails here. (`mixed` is measured on a verbatim fish 4.0.2 capture in
    // `detect::history`, where a real partial emitter produces it.)
    let tagged: Vec<u8> = String::from_utf8_lossy(TWO_COMMANDS)
        .replace("\u{1b}]133;A\u{7}", "\u{1b}]133;A;clasp=1\u{7}")
        .replace("\u{1b}]133;B\u{7}", "\u{1b}]133;B;clasp=1\u{7}")
        .replace("\u{1b}]133;C\u{7}", "\u{1b}]133;C;clasp=1\u{7}")
        .replace("\u{1b}]133;D;3\u{7}", "\u{1b}]133;D;3;clasp=1\u{7}")
        .replace("\u{1b}]133;D;4\u{7}", "\u{1b}]133;D;4;clasp=1\u{7}")
        .into_bytes();
    let pty2 = Arc::new(MockPty::new());
    pty2.queue_output(&tagged);
    let id2 = register(
        &server,
        Some("gamma"),
        "mycmd",
        &[],
        SessionConfig {
            shell_integration: Some(Shell::Bash),
            ..SessionConfig::with_buffer_capacity(4096)
        },
        &pty2,
    );
    let s2 = server.registry.get(&id2).expect("session");
    until("the tagged stream to be recorded", || {
        s2.command_count() == 2
    })
    .await;
    let d2 = body(
        &server
            .status(Parameters(StatusArgs {
                session: id2.clone(),
            }))
            .await
            .expect("status"),
    );
    assert_eq!(
        d2["data"]["osc133_source"], "clasp",
        "tagged markers are CLASP's own"
    );

    // A resolvable session that is nonetheless *not* this one must not
    // answer: without this, `status` returning the first session in the
    // registry would pass everything above.
    let other = mock_session(&server, None).0;
    let others = body(
        &server
            .status(Parameters(StatusArgs { session: other }))
            .await
            .expect("status"),
    );
    assert_eq!(others["data"]["command"], "mock");
    assert_ne!(others["data"]["id"], id.as_str());
}

#[tokio::test]
async fn status_session_not_found_response_matches_its_schema() {
    let server = ClaspServer::new();
    let r = server
        .status(Parameters(StatusArgs {
            session: "sess_does_not_exist".into(),
        }))
        .await
        .expect("a missing session is a status, not a protocol error");

    let payload = assert_matches_schema("status", &r);
    assert_eq!(payload["status"], "session_not_found");
    assert_eq!(payload["data"], json!({}));
}

#[tokio::test]
async fn list_sessions_returns_every_registered_session_and_only_those() {
    // Arity is not identity. A `list_sessions` that returned the *same*
    // session three times, or three sessions from somewhere else, passes
    // both "the session appears" and "there are three of them". So the
    // assertion is set equality on ids, plus the id→name mapping, which is
    // what separates "returned the right sessions" from "returned the
    // right ids attached to the wrong records".
    let server = ClaspServer::new();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    let mut names: Vec<(String, String)> = Vec::new();
    let mut ptys = Vec::new();
    for name in ["alpha", "beta", "gamma"] {
        let pty = Arc::new(MockPty::new());
        let id = register(
            &server,
            Some(name),
            name,
            &[],
            SessionConfig::default(),
            &pty,
        );
        expected.insert(id.clone());
        names.push((id, name.to_string()));
        ptys.push(pty);
    }
    // §4.1 keeps an exited session in the registry with its id, and
    // `state` is what tells the agent it has gone. Killing one here is the
    // separator that stops this passing against a `list_sessions` that
    // filtered to live sessions and happened to be handed only live ones.
    ptys[1].exit(9);
    let dead = names[1].0.clone();
    until("the exited session to be observed", || {
        !server.registry.get(&dead).expect("session").is_alive()
    })
    .await;

    let r = server
        .list_sessions()
        .await
        .expect("list_sessions must not be a protocol error");
    let payload = assert_matches_schema("list_sessions", &r);
    assert_eq!(payload["status"], "ok");
    assert_eq!(keys(&payload["data"]), set(&["sessions"]));

    let entries = payload["data"]["sessions"]
        .as_array()
        .expect("sessions is an array");
    let got: BTreeSet<String> = entries
        .iter()
        .map(|e| e["id"].as_str().expect("each entry has an id").to_string())
        .collect();
    assert_eq!(got, expected, "list_sessions returned the wrong sessions");
    assert_eq!(
        entries.len(),
        expected.len(),
        "an id appeared more than once"
    );
    // `details` is §5.1 agent-visible text and the `content[0]` block a
    // client ignoring `structuredContent` reads. `{n} session(s)` with
    // `n + 1` substituted survived the whole suite, so the count a client
    // reads could disagree with the array beside it and nothing noticed.
    assert_eq!(
        payload["details"],
        format!("{} session(s)", expected.len()),
        "the details line must report the same count as `sessions`"
    );

    for (id, name) in &names {
        let entry = entries
            .iter()
            .find(|e| e["id"] == id.as_str())
            .unwrap_or_else(|| panic!("{id} missing from {payload}"));
        assert_eq!(
            entry["name"],
            name.as_str(),
            "{id} was reported under another session's name"
        );
        // Each entry is a full §5.4-bearing record — 0.0.5's own notes say
        // its version of this tool deliberately does *not* run entries
        // through `with_detection`, so this is the assertion that keeps
        // 0.0.2's behaviour when that milestone adapts.
        assert_eq!(
            keys(entry),
            session_record_keys(),
            "{id}'s entry is not a full session record"
        );
    }

    let dead_entry = entries
        .iter()
        .find(|e| e["id"] == dead.as_str())
        .expect("the exited session is still listed");
    assert_eq!(dead_entry["state"], "Exited");
    assert_eq!(dead_entry["exit_code"], 9);
}

#[tokio::test]
async fn get_command_history_ok_response_matches_its_schema() {
    let server = ClaspServer::new();
    // Read the clock *before* anything runs, so `started_at_unix_ms` can be
    // bounded below by a real epoch reading rather than by a constant.
    let before = unix_ms_now();
    let pty = Arc::new(MockPty::new());
    pty.queue_output(TWO_COMMANDS);
    let id = register(
        &server,
        None,
        "mock",
        &[],
        SessionConfig::with_buffer_capacity(4096),
        &pty,
    );
    let session = server.registry.get(&id).expect("session");
    until("both commands to be recorded", || {
        session.command_count() == 2
    })
    .await;

    let r = server
        .get_command_history(Parameters(GetCommandHistoryArgs {
            session: id.clone(),
            limit: None,
            since_index: None,
        }))
        .await
        .expect("get_command_history must not be a protocol error");

    let payload = assert_matches_schema("get_command_history", &r);
    assert_eq!(payload["status"], "ok");
    assert_eq!(
        keys(&payload["data"]),
        set(&["entries", "truncated_at_tail", "total"]),
    );
    // The negative half of the truncation pair: two commands into a ring
    // of a thousand drops nothing, and a flag that is always true tells
    // the agent every history has holes.
    assert_eq!(payload["data"]["truncated_at_tail"], false);
    assert_eq!(payload["data"]["total"], 2);

    let entries = payload["data"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 2);
    for e in entries {
        assert_eq!(
            keys(e),
            set(&[
                "index",
                "command",
                "exit_code",
                "started_at_unix_ms",
                "duration_ms",
                "output_start_cursor",
                "output_end_cursor",
            ]),
        );
    }
    // Distinct texts and distinct non-zero exit codes, so a transposition
    // between the two entries — or between `index` and `exit_code` — is
    // visible. `\r\n` before `C` is part of the echo, hence the trim.
    assert_eq!(entries[0]["index"], 0);
    assert_eq!(entries[0]["command"], "echo one");
    assert_eq!(entries[0]["exit_code"], 3);
    assert_eq!(entries[1]["index"], 1);
    assert_eq!(entries[1]["command"], "echo two");
    assert_eq!(entries[1]["exit_code"], 4);
    // `started_at_unix_ms` and `duration_ms` are adjacent, same-typed and
    // numeric, and were pinned by nothing but their key names: transposing
    // the two in `get_command_history`'s `json!` map survived the whole
    // workspace suite (measured). Nothing else in the file reaches them.
    //
    // The separation is three orders of magnitude, which is what makes it
    // an assertion rather than a formality: an epoch reading is ~1.7e12 and
    // these commands are replayed from a `MockPty` in well under a second,
    // so the transposed pair fails both bounds at once. This is the same
    // shape `status_reports_each_field_from_the_session_it_names` uses for
    // `started_at_unix_secs` versus `last_activity_unix_ms`.
    let after = unix_ms_now();
    for (i, e) in entries.iter().enumerate() {
        let started = e["started_at_unix_ms"]
            .as_i64()
            .unwrap_or_else(|| panic!("entry {i}: started_at_unix_ms must be an integer"));
        assert!(
            (before..=after).contains(&started),
            "entry {i}: started_at_unix_ms {started} is not an epoch-ms \
             reading taken during this test ({before}..={after}) — a \
             duration is what lands here when the two fields transpose"
        );
        let duration = e["duration_ms"]
            .as_u64()
            .unwrap_or_else(|| panic!("entry {i}: duration_ms must be an integer"));
        assert!(
            duration < 60_000,
            "entry {i}: duration_ms {duration} is an epoch reading, not an \
             elapsed time; these commands are replayed from a mock"
        );
    }
    // The span must address the session's own buffer: reading it back
    // returns exactly that command's output and not its neighbour's.
    let start = entries[0]["output_start_cursor"].as_u64().expect("start");
    let end = entries[0]["output_end_cursor"].as_u64().expect("end");
    let read = session.read_from(start, (end - start) as usize);
    assert_eq!(String::from_utf8_lossy(&read.bytes), "one\r\n");
}

#[tokio::test]
async fn get_command_history_unavailable_response_matches_its_schema() {
    // Two ways to have no history, with *different* reasons, because the
    // reason is the only thing the agent can act on: an un-integrated
    // command is a `start_session` argument away from working, while a
    // recognised shell that emits nothing is not. A single case would pass
    // against an implementation that hardcoded either string.
    let server = ClaspServer::new();
    let cases = [
        (
            SessionConfig::default(),
            "shell integration was not injected for this command",
        ),
        (
            SessionConfig {
                shell_integration: Some(Shell::Bash),
                ..SessionConfig::default()
            },
            "this shell has emitted no OSC 133 markers",
        ),
    ];
    for (config, reason) in cases {
        let pty = Arc::new(MockPty::new());
        // Output with no OSC 133 markers in it: "nothing arrived" must be
        // decided by the marker stream, not by the session being idle.
        pty.queue_output(b"$ ls\r\nfile\r\n$ ");
        let id = register(&server, None, "mock", &[], config, &pty);
        let session = server.registry.get(&id).expect("session");
        // Wait on the *detector*, not on `buffer_head()`. The reader
        // appends to the buffer before it feeds the detector, so a byte
        // count is satisfied while the detector — and therefore the
        // history — has seen nothing, and "no markers have arrived" is
        // trivially true of a stream nobody has looked at yet. Waiting for
        // the classified last line is what makes this "these bytes were
        // scanned and contained no markers".
        until("the detector to consume the output", || {
            session.detection().last_line == "$ "
        })
        .await;

        let r = server
            .get_command_history(Parameters(GetCommandHistoryArgs {
                session: id.clone(),
                limit: None,
                since_index: None,
            }))
            .await
            .expect("no history is a status, not a protocol error");

        // §18.1 lists `unavailable` with isError: false — "this session has
        // no shell integration" is an ordinary outcome, not a failure.
        assert_ne!(r.is_error, Some(true), "{reason}");
        let payload = assert_matches_schema("get_command_history", &r);
        assert_eq!(payload["status"], "unavailable");
        assert_eq!(
            keys(&payload["data"]),
            set(&["reason", "entries", "truncated_at_tail"]),
        );
        assert_eq!(payload["data"]["reason"], reason);
        assert_eq!(payload["data"]["entries"], json!([]));
        assert_eq!(payload["data"]["truncated_at_tail"], false);
    }
}

#[tokio::test]
async fn get_command_history_session_not_found_response_matches_its_schema() {
    // The one error envelope whose `data: {}` is a different shape again.
    // `CommandHistory` declares `entries`, and a schema that required it
    // would reject CLASP's own `session_not_found` response — in
    // production, on a path no positive test above reaches.
    let server = ClaspServer::new();
    let r = server
        .get_command_history(Parameters(GetCommandHistoryArgs {
            session: "sess_does_not_exist".into(),
            limit: None,
            since_index: None,
        }))
        .await
        .expect("a missing session is a status, not a protocol error");

    let payload = assert_matches_schema("get_command_history", &r);
    assert_eq!(payload["status"], "session_not_found");
    assert_eq!(payload["data"], json!({}));
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
            ..Default::default()
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
        // The *vocabulary* violation, not just the type violation. `state`
        // and `shell_integration` were `Option<String>`, so `"banana"` and
        // `"not-a-shell"` both validated; the `json!(3)` row above is a type
        // violation and could not see that. Both fields mirror a closed
        // four- and three-word vocabulary the agent is expected to branch
        // on, exactly like `interaction_mode` below.
        ("state", json!("banana")),
        ("truncated_at_tail", json!("yes")),
        ("interaction_mode", json!("NotAMode")),
        ("detection_tier", json!("terminal-mode")),
        // `"adaptive"`, and it replaces `"on"`, which 0.0.4 made a legal
        // value. It is not an arbitrary replacement: `screen_tracking` is
        // a **three**-valued `start_session` argument and a **two**-valued
        // reported state, and `adaptive` is the default mode — so
        // `ScreenTracking::as_str()` on the policy's mode is the obvious
        // accessor, is wrong, and would emit exactly this on every
        // session's first response. This row is what makes that a
        // validation failure rather than a value an agent has to guess at.
        ("screen_tracking", json!("adaptive")),
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

// ----------------------------------------------------- wait_for_pattern

/// Driven for real, like every other tool: the response the router
/// produces is validated against the schema the router advertises.
#[tokio::test]
async fn wait_for_pattern_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    // `SCHEMA''_READY` echoes with the quotes and prints without them, so
    // the needle is producible only by running the command.
    server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo SCHEMA''_READY".into(),
            ..Default::default()
        }))
        .await
        .expect("send_input");

    let matched = server
        .wait_for_pattern(Parameters(WaitForPatternArgs {
            session: id.clone(),
            pattern: "SCHEMA_READY".into(),
            timeout_secs: Some(10),
            since_cursor: Some(0),
            max_bytes: None,
        }))
        .await
        .expect("wait_for_pattern must not be a protocol error");
    let payload = assert_matches_schema("wait_for_pattern", &matched);
    assert_eq!(payload["status"], "ok", "{payload}");
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "matched",
            "match",
            "output_since_start",
            "truncated_at_tail",
            "truncated_for_size",
            "held_back",
            "next_cursor",
            "interaction_mode",
            "detection_tier",
            "screen_tracking",
            "title",
            "prompt",
        ]),
        "wait_for_pattern's data key set drifted from §5.2's Returns list"
    );
    // REQ-T-016: the nested objects are pinned too, not just `data`.
    assert_eq!(keys(&payload["data"]["match"]), set(&["offset", "text"]));
    assert_eq!(keys(&payload["data"]["prompt"]), prompt_keys());

    // The `timeout` population is a different `data` shape, so it is
    // validated too. One second, not zero: `timeout_secs: 0` means "no
    // *caller* deadline" and clamps to the hour cap, so a zero here
    // against a pattern that never matches is an hour-long test. (It was
    // written that way first, and that is exactly what it did.)
    let timed_out = server
        .wait_for_pattern(Parameters(WaitForPatternArgs {
            session: id.clone(),
            pattern: "NEVER_EVER_MATCHES".into(),
            timeout_secs: Some(1),
            since_cursor: Some(0),
            max_bytes: None,
        }))
        .await
        .expect("wait_for_pattern must not be a protocol error");
    let payload = assert_matches_schema("wait_for_pattern", &timed_out);
    assert_eq!(payload["status"], "timeout");
    assert_eq!(payload["data"]["matched"], false);
    assert_eq!(payload["data"]["match"], Value::Null);
    assert!(
        payload["data"].get("clamped_timeout_secs").is_none(),
        "one second is inside the cap; nothing was clamped: {payload}"
    );

    // The third population: the clamp field, which appears only when a
    // clamp happened. Driven against a pattern that is already in the
    // buffer, so the hour-long deadline is never waited on.
    let clamped = server
        .wait_for_pattern(Parameters(WaitForPatternArgs {
            session: id.clone(),
            pattern: "SCHEMA_READY".into(),
            timeout_secs: Some(0),
            since_cursor: Some(0),
            max_bytes: None,
        }))
        .await
        .expect("wait_for_pattern must not be a protocol error");
    let payload = assert_matches_schema("wait_for_pattern", &clamped);
    assert_eq!(payload["data"]["clamped_timeout_secs"], 3600);

    kill(&server, &id).await;
}

// ------------------------------------------------------- 0.0.4's three tools

/// A session whose child has really exited, with a **distinctive** code.
///
/// `exit 7` rather than a kill: `0` is what a broken exit-status read
/// produces by default and a signalled child reports a code the caller did
/// not choose, so neither would prove the field was read.
async fn exited_session(server: &ClaspServer) -> String {
    let (id, _) = start_bash(server).await;
    wait_for(server, &id, "$").await;
    let session = server.registry.get(&id).expect("the session");
    session.write_input(b"exit 7\n").expect("write");
    let deadline = Instant::now() + Duration::from_secs(10);
    while session.is_alive() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!session.is_alive(), "bash never exited");
    id
}

/// `get_screen_state`'s full-grid shape, with its key set pinned exactly
/// (REQ-T-015).
///
/// **The fixture paints a screen, and that is the point of it.** A key-set
/// assertion sees a key that is present-and-`null` exactly the way it sees
/// one carrying a value, so a green run against a bare prompt would prove
/// nothing whatever about `title`, `alt_screen` or the cursor — which is
/// precisely how `title` shipped unredacted for three milestones
/// underneath a whole-response leak guard whose fixtures never set one. So
/// this session enters the alternate screen, sets an OSC 0 title, paints
/// text on row 3, and leaves the cursor off `(0, 0)`; every one of those
/// four fields is then asserted by value below the key set.
#[tokio::test]
async fn get_screen_state_full_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    // `GRID''_ROW` echoes with the quotes and prints without them, so the
    // wait below cannot be satisfied by the PTY's echo of the command.
    let session = server.registry.get(&id).expect("the session");
    session
        .write_input(
            b"printf '\\033[?1049h\\033[H\\033[2J\\033]0;clasp-grid\\007\\033[3;5HGRID''_ROW'\n",
        )
        .expect("write");
    wait_for(&server, &id, "GRID_ROW").await;

    let r = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: id.clone(),
            ..Default::default()
        }))
        .await
        .expect("get_screen_state must not be a protocol error");
    let payload = assert_matches_schema("get_screen_state", &r);
    assert_eq!(payload["status"], "ok", "{payload}");
    // REQ-T-015: exactly, not "contains". `screen_revision` proves this is
    // the full shape; the absence of `base_revision`/`diff` proves it is
    // not the diff shape; the absence of `exit_code` proves that field is
    // conditional rather than always emitted. A subset check would pass
    // against all three faults.
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "screen_revision",
            "rows",
            "cols",
            "cursor",
            "alt_screen",
            "title",
            "lines",
            "screen_tracking",
            "held_back",
        ]),
    );
    assert_eq!(
        keys(&payload["data"]["cursor"]),
        set(&["row", "col", "visible"]),
    );
    // This call is what enables Tier B, so it is also the first response
    // in the whole suite that can carry `screen_tracking: "on"` — which is
    // what proves the `ScreenTracking::On` variant landed. Without it this
    // line is where the suite goes red.
    assert_eq!(payload["data"]["screen_tracking"], "on");

    // The four fields the fixture exists to populate. Without these the
    // key set above is satisfied by a grid of nulls.
    let data = &payload["data"];
    assert_eq!(data["title"], "clasp-grid", "{data}");
    assert_eq!(data["alt_screen"], true, "{data}");
    assert_ne!(
        (
            data["cursor"]["row"].as_u64(),
            data["cursor"]["col"].as_u64()
        ),
        (Some(0), Some(0)),
        "the cursor was never moved, so `cursor` proves nothing: {data}"
    );
    let lines = data["lines"].as_array().expect("lines is an array");
    assert_eq!(lines.len(), 40, "the default geometry is 120x40");
    // `starts_with`, not equality: bash prints its prompt where the
    // `printf` left the cursor, so this row carries `PS1` after the text
    // and the prompt string differs between bash versions. The four
    // leading spaces are the load-bearing part — they are the `\033[3;5H`,
    // which is what makes this a rendered grid rather than a line of
    // output.
    assert!(
        lines[2].as_str().unwrap_or("").starts_with("    GRID_ROW"),
        "row 3, painted at column 5: {lines:?}"
    );

    kill(&server, &id).await;
}

/// The diff shape, and the separator from the full grid.
///
/// The key set has to be exact for a reason specific to this tool: every
/// field of `schema::GetScreenState` is optional, so a diff capture that
/// silently degraded to a full grid would still validate. The grid keys
/// must be *absent*, not merely unchecked.
#[tokio::test]
async fn get_screen_state_diff_response_matches_its_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    let first = assert_matches_schema(
        "get_screen_state",
        &server
            .get_screen_state(Parameters(GetScreenStateArgs {
                session: id.clone(),
                ..Default::default()
            }))
            .await
            .expect("get_screen_state"),
    );
    let rev = first["data"]["screen_revision"]
        .as_u64()
        .expect("a full capture carries a revision");

    let r = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: id.clone(),
            diff_from: Some(rev),
            ..Default::default()
        }))
        .await
        .expect("get_screen_state");
    let payload = assert_matches_schema("get_screen_state", &r);
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "screen_revision",
            "base_revision",
            "diff",
            "screen_tracking",
            "held_back"
        ]),
    );
    assert_eq!(payload["data"]["base_revision"], rev);
    assert!(payload["data"]["diff"].is_string());

    kill(&server, &id).await;
}

/// The only path that emits `get_screen_state.exit_code`, and therefore
/// the only response that can close the declared-but-never-emitted half of
/// REQ-T-015 for this tool. §5.1: `session_died` is a status, not an
/// error, and here it comes back with the final screen still in it.
#[tokio::test]
async fn get_screen_state_on_a_dead_session_matches_its_schema() {
    let server = ClaspServer::new();
    let id = exited_session(&server).await;

    let r = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: id.clone(),
            ..Default::default()
        }))
        .await
        .expect("get_screen_state");
    let payload = assert_matches_schema("get_screen_state", &r);
    assert_eq!(payload["status"], "session_died", "{payload}");
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "screen_revision",
            "rows",
            "cols",
            "cursor",
            "alt_screen",
            "title",
            "lines",
            "screen_tracking",
            "held_back",
            "exit_code",
        ]),
    );
    // The value, not just the key: `0` is what a broken exit-status read
    // produces by default, so a non-zero code is what proves it was read.
    assert_eq!(payload["data"]["exit_code"], 7);
    // And the grid survived the child, which is the behaviour §5.2
    // describes and the reason `session_died` carries data at all.
    assert!(payload["data"]["lines"].is_array());
    assert!(
        payload["data"]["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .any(|l| l.as_str().unwrap_or("").contains("exit 7")),
        "the final screen is empty, so `session_died carries data` is \
         untested here: {}",
        payload["data"]["lines"]
    );
}

/// `resize`'s two shapes. The `ok` one carries the dimensions the session
/// *reached*; the `session_died` one is the only path that emits
/// `exit_code`, which `schema::Resize` declares.
#[tokio::test]
async fn resize_responses_match_their_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    let r = server
        .resize(Parameters(ResizeArgs {
            session: id.clone(),
            cols: 132,
            rows: 43,
        }))
        .await
        .expect("resize must not be a protocol error");
    let payload = assert_matches_schema("resize", &r);
    assert_eq!(payload["status"], "ok", "{payload}");
    assert_eq!(keys(&payload["data"]), set(&["cols", "rows"]));
    // Unequal on purpose: a transposition is invisible on a square
    // terminal, and `cols`/`rows` are the same type.
    assert_eq!(payload["data"]["cols"], 132);
    assert_eq!(payload["data"]["rows"], 43);
    kill(&server, &id).await;

    let dead = exited_session(&server).await;
    let r = server
        .resize(Parameters(ResizeArgs {
            session: dead,
            cols: 132,
            rows: 43,
        }))
        .await
        .expect("resize must not be a protocol error");
    let payload = assert_matches_schema("resize", &r);
    assert_eq!(payload["status"], "session_died", "{payload}");
    assert_eq!(keys(&payload["data"]), set(&["exit_code"]));
    assert_eq!(payload["data"]["exit_code"], 7);
}

/// `interrupt`'s two shapes.
///
/// The `ok` one is **prompt-bearing** (§5.2, REQ-T-019), so its key set is
/// `delivered` plus the whole §5.4 block — and the nested `prompt` object
/// is pinned too, because REQ-T-016's equality obligation is recursive and
/// the top level cannot see a `prompt` that gained a field.
#[tokio::test]
async fn interrupt_responses_match_their_schema() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for_at_prompt(&server, &id).await;

    let r = server
        .interrupt(Parameters(InterruptArgs {
            session: id.clone(),
        }))
        .await
        .expect("interrupt must not be a protocol error");
    let payload = assert_matches_schema("interrupt", &r);
    assert_eq!(payload["status"], "ok", "{payload}");
    assert_eq!(
        keys(&payload["data"]),
        set(&[
            "delivered",
            "interaction_mode",
            "detection_tier",
            "screen_tracking",
            "title",
            "prompt",
        ]),
    );
    assert_eq!(payload["data"]["delivered"], true);
    assert_eq!(keys(&payload["data"]["prompt"]), prompt_keys());
    kill(&server, &id).await;

    let dead = exited_session(&server).await;
    let r = server
        .interrupt(Parameters(InterruptArgs { session: dead }))
        .await
        .expect("interrupt must not be a protocol error");
    let payload = assert_matches_schema("interrupt", &r);
    assert_eq!(payload["status"], "session_died", "{payload}");
    // No `delivered` at all, rather than `delivered: false`: nothing was
    // written, so there is no delivery to report on.
    assert_eq!(keys(&payload["data"]), set(&["exit_code"]));
    assert_eq!(payload["data"]["exit_code"], 7);
}

// ------------------------------------ the four §5.4 rules, asserted generally
//
// Steps 5a-5c pinned key sets tool by tool, by hand. These four assert
// the *rules* those literals are instances of, so the next three tools do
// not each get their own chance to copy one wrong.

/// §5.4, REQ-T-016: **one record, one key set.** `status` and
/// `list_sessions` render the same record from one builder, so the two
/// are asserted against **each other**, not each against its own literal.
/// The literal comparisons elsewhere in this file catch a field added to
/// one; this catches the edit that makes those stop working — forking
/// `session_record_keys()` into two helpers, which is one refactor away
/// and leaves both of them green.
#[tokio::test]
async fn status_and_a_list_sessions_entry_are_the_same_record() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;

    let status_payload = body(
        &server
            .status(Parameters(StatusArgs {
                session: id.clone(),
            }))
            .await
            .expect("status"),
    );
    let listed = body(&server.list_sessions().await.expect("list_sessions"));
    let entry = listed["data"]["sessions"]
        .as_array()
        .expect("sessions")
        .iter()
        .find(|s| s["id"] == json!(id))
        .expect("the session we started")
        .clone();

    assert_eq!(
        keys(&status_payload["data"]),
        keys(&entry),
        "status and list_sessions have diverged as key sets"
    );
    // Recursively, on the same terms — a nested divergence is the one
    // that has actually happened (§5.4: `list_sessions[].prompt` carried
    // a field its Returns list excluded for every revision on record,
    // with the entry's top-level key set pinned green throughout).
    for nested in ["prompt", "buffer", "redaction_stats"] {
        assert_eq!(
            keys(&status_payload["data"][nested]),
            keys(&entry[nested]),
            "{nested} differs between status and list_sessions"
        );
    }

    kill(&server, &id).await;
}

/// §5.4, REQ-T-016, the recursive half: every nested object §5.2 declares
/// carries its own exact key set. A per-tool assertion on `data` reaches
/// the top level only.
#[tokio::test]
async fn every_nested_object_a_tool_returns_has_its_key_set_pinned() {
    let server = ClaspServer::new();
    let (id, _) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;
    // A command, so `get_command_history` has an entry to enumerate.
    server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo NESTED''_OK".into(),
            ..Default::default()
        }))
        .await
        .expect("send_input");
    wait_for(&server, &id, "NESTED_OK").await;

    // `send_input.prompt` — the call above returned one, but a fresh one
    // keeps this test's own arrangement explicit.
    let sent = body(
        &server
            .send_input(Parameters(SendInputArgs {
                session: id.clone(),
                data: String::new(),
                append_newline: Some(false),
                ..Default::default()
            }))
            .await
            .expect("send_input"),
    );
    assert_eq!(keys(&sent["data"]["prompt"]), prompt_keys());

    // `list_sessions[].prompt` and `[].buffer` — the pair §5.4 names as
    // the drift that actually happened.
    let listed = body(&server.list_sessions().await.expect("list_sessions"));
    let entry = listed["data"]["sessions"]
        .as_array()
        .expect("sessions")
        .iter()
        .find(|s| s["id"] == json!(id))
        .expect("the session")
        .clone();
    assert_eq!(keys(&entry["prompt"]), prompt_keys());
    assert_eq!(keys(&entry["buffer"]), set(&["head", "tail"]));

    // `get_command_history.entries[]`.
    let history = body(
        &server
            .get_command_history(Parameters(GetCommandHistoryArgs {
                session: id.clone(),
                limit: None,
                since_index: None,
            }))
            .await
            .expect("get_command_history"),
    );
    let entries = history["data"]["entries"].as_array().expect("entries");
    assert!(!entries.is_empty(), "no command was recorded: {history}");
    for e in entries {
        assert_eq!(
            keys(e),
            set(&[
                "index",
                "command",
                "exit_code",
                "started_at_unix_ms",
                "duration_ms",
                "output_start_cursor",
                "output_end_cursor",
            ]),
            "a history entry's key set drifted from §5.2"
        );
    }

    kill(&server, &id).await;
}

/// §18.1, REQ-T-017: every status the agent is told to branch on is one
/// some tool actually returns.
///
/// `the_status_enum_declares_every_status_the_envelope_can_emit` compares
/// two *enumerations* — both can agree on a variant no response ever
/// carries, which is a permanently unreachable branch no reviewer can
/// tell from an unimplemented one. This drives a real `CallToolResult`
/// per declared variant.
#[tokio::test]
async fn every_declared_status_is_returned_by_a_real_response() {
    let declared: BTreeSet<String> = output_schema("read_output")["$defs"]["Status"]["enum"]
        .as_array()
        .expect("Status is an enum")
        .iter()
        .map(|v| v.as_str().expect("string variant").to_string())
        .collect();

    let mut produced: BTreeSet<String> = BTreeSet::new();
    let mut note = |payload: &Value| {
        produced.insert(payload["status"].as_str().expect("a status").to_string());
    };

    let server = ClaspServer::new();
    let (id, started) = start_bash(&server).await;
    note(&body(&started)); // ok

    note(&body(
        &server
            .status(Parameters(StatusArgs {
                session: "sess_nope".into(),
            }))
            .await
            .expect("status"),
    )); // session_not_found

    // name_taken: two starts with one name.
    for _ in 0..2 {
        let r = server
            .start_session(Parameters(StartSessionArgs {
                command: "bash".into(),
                args: bash_args(),
                name: Some("taken".into()),
                ..Default::default()
            }))
            .await
            .expect("start_session");
        note(&body(&r));
    }

    // spawn_failed: a command that does not exist.
    note(&body(
        &server
            .start_session(Parameters(StartSessionArgs {
                command: "clasp-no-such-binary-anywhere".into(),
                ..Default::default()
            }))
            .await
            .expect("start_session"),
    ));

    // limit_reached: a registry of one, already full.
    {
        let small = ClaspServer::new();
        // `with_capacity` is the registry's own knob; the server's
        // default registry is replaced rather than reconfigured.
        let one = clasp_core::session::SessionRegistry::new(1);
        let server_one = ClaspServer {
            registry: std::sync::Arc::new(one),
            processor: std::sync::Arc::clone(&small.processor),
            // 0.0.5 gave `ClaspServer` the operator config; this literal
            // keeps the default one rather than the registry it just
            // replaced, because the point here is the *registry* limit.
            config: std::sync::Arc::clone(&small.config),
        };
        let (_first, _) = start_bash(&server_one).await;
        note(&body(
            &server_one
                .start_session(Parameters(StartSessionArgs {
                    command: "bash".into(),
                    args: bash_args(),
                    ..Default::default()
                }))
                .await
                .expect("start_session"),
        ));
        for s in server_one.registry.all() {
            let _ = s.signal(clasp_core::pty::Signal::Kill);
        }
    }

    // unavailable: a session with no shell integration.
    {
        let r = server
            .start_session(Parameters(StartSessionArgs {
                command: "bash".into(),
                args: bash_args(),
                shell_integration: Some(false),
                ..Default::default()
            }))
            .await
            .expect("start_session");
        let plain = body(&r)["data"]["session_id"].as_str().unwrap().to_string();
        note(&body(
            &server
                .get_command_history(Parameters(GetCommandHistoryArgs {
                    session: plain.clone(),
                    limit: None,
                    since_index: None,
                }))
                .await
                .expect("get_command_history"),
        ));
        kill(&server, &plain).await;
    }

    // timeout: a one-second wait for something that never arrives. Before
    // `wait_for_pattern` the only producer was `send_input`'s write
    // deadline, which costs a parked PTY write and five seconds.
    note(&body(
        &server
            .wait_for_pattern(Parameters(WaitForPatternArgs {
                session: id.clone(),
                pattern: "NEVER_MATCHES_ANYTHING".into(),
                timeout_secs: Some(1),
                since_cursor: Some(0),
                max_bytes: None,
            }))
            .await
            .expect("wait_for_pattern"),
    ));

    // session_died: read after the child has gone.
    {
        let dead = start_bash(&server).await.0;
        let session = server.registry.get(&dead).unwrap();
        let _ = session.signal(clasp_core::pty::Signal::Kill);
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.is_alive() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        note(&body(
            &server
                .send_input(Parameters(SendInputArgs {
                    session: dead.clone(),
                    data: "x".into(),
                    ..Default::default()
                }))
                .await
                .expect("send_input"),
        ));
    }

    assert_eq!(
        declared.difference(&produced).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "these statuses are declared and no real response produced one"
    );
    assert!(
        !declared.contains("awaiting_secret"),
        "§18.1 catalogues awaiting_secret as notification-only: no tool \
         returns it, and an agent meets it as interaction_mode instead"
    );

    for s in server.registry.all() {
        let _ = s.signal(clasp_core::pty::Signal::Kill);
    }
}

/// §5.4, REQ-T-018. Non-circular on purpose: the rule is not "fields
/// named `_unix_*` are named `_unix_*`". It is that a **bare** temporal
/// name is a claim the value does not support, so the bare spellings are
/// banned outright and everything temporal must carry its unit.
const BARE_TEMPORAL_NAMES: [&str; 6] = [
    "started_at",
    "last_activity",
    "idle_deadline",
    "exited_at",
    "created_at",
    "timestamp",
];

#[test]
fn no_declared_timestamp_carries_a_bare_name() {
    for tool in TOOLS {
        let schema = output_schema(tool);
        let mut found = Vec::new();
        object_subschemas("#", &schema, &mut found);
        assert!(!found.is_empty(), "{tool}: the walk found no objects");
        for (path, object) in found {
            let Some(props) = object.get("properties").and_then(Value::as_object) else {
                continue;
            };
            for name in props.keys() {
                assert!(
                    !BARE_TEMPORAL_NAMES.contains(&name.as_str()),
                    "{tool} at {path} declares `{name}`: a bare temporal name is \
                     a claim the value does not support (REQ-T-018)"
                );
                // Temporal by *stem*, not by "contains `_at`": the plan's
                // wider rule flags `truncated_at_tail`, which is a
                // boolean and carries no unit because it names no
                // instant. A stem test says what the rule means — a
                // field describing one of these moments must carry the
                // unit of the number it holds.
                for stem in BARE_TEMPORAL_NAMES {
                    if name.starts_with(stem) {
                        assert!(
                            name.ends_with("_unix_secs") || name.ends_with("_unix_ms"),
                            "{tool} at {path} declares `{name}`, which is temporal \
                             and does not carry its unit (REQ-T-018)"
                        );
                    }
                }
            }
        }
    }
}

/// The emission half. The schema alone cannot catch an RFC-3339 string
/// under a correct name, which is why the value is asserted as well.
#[tokio::test]
async fn every_emitted_unix_field_is_a_number() {
    let server = ClaspServer::new();
    let (id, started) = start_bash(&server).await;
    wait_for(&server, &id, "$").await;
    server
        .send_input(Parameters(SendInputArgs {
            session: id.clone(),
            data: "echo UNIX''_OK".into(),
            ..Default::default()
        }))
        .await
        .expect("send_input");
    wait_for(&server, &id, "UNIX_OK").await;

    let mut payloads = vec![body(&started)];
    payloads.push(body(
        &server
            .status(Parameters(StatusArgs {
                session: id.clone(),
            }))
            .await
            .expect("status"),
    ));
    payloads.push(body(&server.list_sessions().await.expect("list_sessions")));
    payloads.push(body(
        &server
            .get_command_history(Parameters(GetCommandHistoryArgs {
                session: id.clone(),
                limit: None,
                since_index: None,
            }))
            .await
            .expect("get_command_history"),
    ));
    // An exited session, so `exited_at_unix_secs` is populated rather
    // than null — a null passes any "is not a string" check.
    let session = server.registry.get(&id).unwrap();
    let _ = session.signal(clasp_core::pty::Signal::Kill);
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.is_alive() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    payloads.push(body(
        &server
            .terminate(Parameters(TerminateArgs {
                session: id.clone(),
                force: Some(true),
                timeout_secs: None,
            }))
            .await
            .expect("terminate"),
    ));

    fn walk(path: &str, v: &Value, seen: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    if k.ends_with("_unix_secs") || k.ends_with("_unix_ms") {
                        // Null is legitimate — `exited_at_unix_secs` is
                        // absent while the session is alive — but a
                        // *string* never is, which is the RFC-3339
                        // regression this half exists to catch. Only
                        // numbers count as "seen", so the expectation
                        // list below cannot be satisfied by a field that
                        // is null everywhere.
                        assert!(
                            child.is_number() || child.is_null(),
                            "{path}/{k} is {child}, not a number — every epoch \
                             field on the MCP surface is an integer (REQ-T-018)"
                        );
                        if child.is_number() {
                            seen.push(k.clone());
                        }
                    }
                    walk(&format!("{path}/{k}"), child, seen);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(&format!("{path}/{i}"), child, seen);
                }
            }
            _ => {}
        }
    }

    let mut seen = Vec::new();
    for p in &payloads {
        walk("#", p, &mut seen);
    }
    for expected in [
        "started_at_unix_secs",
        "last_activity_unix_ms",
        "exited_at_unix_secs",
        "started_at_unix_ms",
    ] {
        assert!(
            seen.iter().any(|s| s == expected),
            "{expected} was never emitted, so the walk proves nothing about \
             it; seen: {seen:?}"
        );
    }

    for s in server.registry.all() {
        let _ = s.signal(clasp_core::pty::Signal::Kill);
    }
}

/// §5.4, REQ-T-019: one shape, one builder, referenced. The tools are
/// **discovered**, not listed — every tool whose `outputSchema` declares
/// `prompt` is in scope, so 0.0.4's `interrupt` and 0.0.7's
/// `request_secret_input` are covered the day they are added rather than
/// the day someone remembers this test.
#[test]
fn every_tool_that_declares_prompt_declares_the_same_block() {
    // The block's own shape, pinned once as a literal on the first tool
    // found, so agreement is agreement about the right thing.
    let block = [
        "confidence",
        "quiescent_score",
        "pattern_score",
        "cursor_score",
        "reason",
        "last_line",
    ];
    let siblings = [
        "interaction_mode",
        "detection_tier",
        "screen_tracking",
        "title",
    ];

    let mut found_in: Vec<String> = Vec::new();
    let mut first: Option<BTreeSet<String>> = None;

    for tool in TOOLS {
        let schema = output_schema(tool);
        let mut objects = Vec::new();
        object_subschemas("#", &schema, &mut objects);
        for (path, object) in objects {
            let Some(props) = object.get("properties").and_then(Value::as_object) else {
                continue;
            };
            if !props.contains_key("prompt") {
                continue;
            }
            // The `prompt` property is a `$ref` or an inline object; the
            // walk already visited whatever it resolves to, so the shape
            // is read from the `Prompt` definition the schema carries.
            let prompt_props = schema["$defs"]["Prompt"]["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{tool} declares prompt but no Prompt definition"));
            let names: BTreeSet<String> = prompt_props.keys().cloned().collect();
            match &first {
                None => {
                    assert_eq!(
                        names,
                        block.iter().map(|s| (*s).to_string()).collect(),
                        "{tool} at {path}: the §5.4 prompt block's shape changed"
                    );
                    first = Some(names);
                }
                Some(expected) => assert_eq!(
                    &names, expected,
                    "{tool} at {path} declares a different prompt block; the \
                     block comes from one builder, so a narrower variant means \
                     a second builder (REQ-T-019)"
                ),
            }
            // A tool that wants `prompt` is asking for the whole block.
            for sibling in siblings {
                assert!(
                    props.contains_key(sibling),
                    "{tool} at {path} declares `prompt` without `{sibling}`"
                );
            }
            found_in.push(format!("{tool}{path}"));
        }
    }

    assert!(
        found_in.len() >= 4,
        "only {} declaration(s) of the session-state block were found; the \
         walk is not walking: {found_in:?}",
        found_in.len()
    );
}
