//! Declared `outputSchema` for every tool (REQ-T-013, spec §5.1).
//!
//! §5.1: "Every tool ships an `outputSchema` (JSON Schema) describing the
//! `structuredContent` shape, so MCP clients can validate."
//! `structuredContent` is always the §5.1 envelope `{status, data,
//! details}`, so each tool's schema is `Envelope<T>` and only `T` varies.
//!
//! **These structs are schema declarations, not the serialisation path.**
//! The tools build their `data` with `json!` because the payload varies by
//! status. `tests/schema.rs` is what stops the two from drifting: it drives
//! every tool for real and validates the response it actually produced
//! against the schema the router actually advertises.
//!
//! **Why the `data` fields are optional.** One tool answers with several
//! §18.1 statuses and each carries a different `data` shape:
//! `read_output` returns the full read on `ok` and `{}` on
//! `session_not_found`; `start_session` returns `{command}` on
//! `spawn_failed`; `get_command_history` returns `{reason, entries,
//! truncated_at_tail}` on `unavailable`. Marking the `ok` fields
//! `required` would make CLASP's own error envelopes fail validation.
//! Optional-but-declared is the honest encoding: the agent learns every
//! field name and type the tool can produce, and every status validates.
//! `status` and `details` are present on every response and stay required.
//!
//! **Why `deny_unknown_fields` everywhere.** JSON Schema allows unknown
//! properties by default, so without it a schema that simply *omitted* a
//! field would validate every response and `tests/schema.rs` could never
//! go red. `additionalProperties: false` is what turns the test into a
//! guard — and it is also what catches the bug spec rev. 17 records, where
//! §5.4's enums were missing from tools' Returns lists.

use serde::Serialize;
use std::sync::Arc;

/// `rmcp::model::JsonObject` — the map type `Tool::output_schema` holds.
type SchemaObject = serde_json::Map<String, serde_json::Value>;

/// The §5.1 envelope. Every tool's `structuredContent` is one of these.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    /// Outcome status (spec §18.1). The agent branches on this.
    pub status: Status,
    pub data: T,
    /// Human-readable one-liner describing the outcome.
    pub details: String,
}

/// The statuses the 0.0.2 tool set can emit (a subset of §18.1).
///
/// Deliberately one shared enum rather than seven per-tool ones: §18.1 is
/// the canonical enumeration and each tool's `Possible statuses` list is a
/// subset of this. Narrowing per tool would be more precise and is a
/// candidate for the milestone that freezes the surface; it is not a
/// correctness gap, because a status this enum omits is one no tool emits.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
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

/// What the session is doing (§18.2a).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub enum InteractionMode {
    AtPrompt,
    Executing,
    AwaitingSecret,
    Fullscreen,
    Exited,
}

/// Which mechanism produced `interaction_mode` (§18.2a).
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTier {
    Semantic,
    TerminalMode,
    Heuristic,
}

/// Tier-B tracking state (§4.5). 0.0.2 only ever reports `off`; 0.0.4 adds
/// the other values. Declared as an enum so the agent sees the vocabulary.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreenTracking {
    Off,
}

/// The `prompt` object carried by every prompt-bearing response (§18.2a).
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prompt {
    /// Combined confidence in [0,1] (§8.4).
    pub confidence: f64,
    /// How settled the output stream is, in [0,1] (§8.6 T3a).
    pub quiescent_score: f64,
    /// Best tier-3 pattern match against the last line, in [0,1] (§8.6 T3b).
    pub pattern_score: f64,
    /// Cursor sub-signal (§8.6 T3c). Always 0.0 until 0.0.4.
    pub cursor_score: f64,
    /// Which branch of the §8.3 ladder answered, in words.
    pub reason: String,
    /// Last logical line of output, escape-free. Unredacted until 0.0.3.
    pub last_line: String,
}

/// `start_session`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartSession {
    pub session_id: Option<String>,
    pub name: Option<String>,
    pub pid: Option<u32>,
    /// The *effective* working directory the child was spawned in (§5.2).
    pub cwd: Option<String>,
    /// Which shell integration was injected, if any (§8.5).
    pub shell_integration: Option<String>,
    pub started_at_unix_secs: Option<u64>,
    /// Present on `spawn_failed`: the command that could not be spawned.
    pub command: Option<String>,
}

/// `read_output`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadOutput {
    pub output: Option<String>,
    /// Byte offset just past the bytes returned; feed back as `since_cursor`.
    pub cursor: Option<u64>,
    pub bytes_returned: Option<u64>,
    pub truncated_at_tail: Option<bool>,
    pub truncated_for_size: Option<bool>,
    pub next_cursor: Option<u64>,
    pub state: Option<String>,
    pub exit_code: Option<i32>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
}

/// `send_input`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendInput {
    /// Null on `timeout`: a partial write may have landed, so any number
    /// would be a guess (§5.2).
    pub bytes_written: Option<u64>,
    /// `"session_awaiting_secret"` when the write went to an echo-off
    /// session (REQ-SEC-011). The write still happened.
    pub warning: Option<String>,
    pub timeout_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
}

/// `terminate`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Terminate {
    pub exit_code: Option<i32>,
    pub already_exited: Option<bool>,
}

/// Ring-buffer extent for one session.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Buffer {
    pub head: u64,
    pub tail: u64,
}

/// One session record, shared by `status` and `list_sessions` entries.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub id: Option<String>,
    pub name: Option<String>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub state: Option<String>,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub shell_integration: Option<String>,
    pub command_count: Option<u64>,
    pub started_at_unix_secs: Option<u64>,
    pub last_activity_unix_ms: Option<i64>,
    pub buffer: Option<Buffer>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
}

/// `list_sessions`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSessions {
    pub sessions: Vec<SessionRecord>,
}

/// One OSC 133-derived command (§5.2 `get_command_history`).
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandEntry {
    /// Monotonic per session; survives ring eviction.
    pub index: u64,
    pub command: String,
    /// Null while the command is still running.
    pub exit_code: Option<i32>,
    pub started_at_unix_ms: i64,
    pub duration_ms: Option<u64>,
    /// Absolute offset of the command's first output byte.
    pub output_start_cursor: u64,
    /// Absolute offset just past its last output byte; null while running.
    pub output_end_cursor: Option<u64>,
}

/// `get_command_history`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandHistory {
    /// Optional for the reason the module header gives, and this is the
    /// field that proved it: `get_command_history` answers a missing
    /// session through `envelope::from_error`, whose `data` is `{}`.
    /// Declared as a bare `Vec` this was `required`, so CLASP's own
    /// `session_not_found` response failed its own advertised schema —
    /// caught by `get_command_history_session_not_found_response_matches_
    /// its_schema`, which is the only path that reaches it.
    ///
    /// `ListSessions::sessions` is deliberately *not* optional: that tool
    /// takes no arguments, emits only `ok`, and therefore has no second
    /// `data` shape.
    pub entries: Option<Vec<CommandEntry>>,
    pub truncated_at_tail: Option<bool>,
    pub total: Option<u64>,
    /// Present on `unavailable`: why no history is available.
    pub reason: Option<String>,
}

/// The `outputSchema` for a tool whose `data` is `T`.
///
/// `#[tool(output_schema = ...)]` wants an `Arc<JsonObject>`, which is what
/// rmcp's own generator returns; this is just the envelope wrapper applied
/// once per tool so no call site repeats it.
pub fn envelope_schema<T>() -> Arc<SchemaObject>
where
    T: schemars::JsonSchema + std::any::Any,
{
    rmcp::handler::server::tool::schema_for_output::<Envelope<T>>()
}
