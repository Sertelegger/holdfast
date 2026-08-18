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

/// Tier-B tracking state (§4.5, §18.2a): whether emulation is **running**,
/// not which mode was configured. Declared as an enum so the agent sees the
/// vocabulary.
///
/// **Two values, and `adaptive` is deliberately not one of them.**
/// `screen_tracking` is a three-valued *`start_session` argument* and a
/// two-valued *reported state*; §4.5 and §18.2a both enumerate only `off`
/// and `on` for the report. `Session::screen_tracking()` derives the wire
/// value from the policy's `enabled` flag rather than from
/// `screen::ScreenTracking::as_str()`, which has the third spelling — and
/// since the default mode is `adaptive`, the wrong accessor would fail this
/// closed schema on the *first* response of *every* session rather than on
/// a rare one.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreenTracking {
    Off,
    On,
}

/// Lifecycle state of a session (§5.2).
///
/// Mirrors `session::SessionState::as_str`, which is a closed vocabulary of
/// four words. Declared as an enum rather than a `String` for the same
/// reason `InteractionMode` and `DetectionTier` are: `state: "banana"`
/// validated against the old declaration, and `a_wrongly_typed_field_is_
/// rejected` substitutes `json!(3)` — a *type* violation — so the looseness
/// was invisible to it. The agent branches on this field; a schema that
/// admits any string tells it nothing about what to branch on.
///
/// PascalCase with no `rename_all`, because that is what `as_str` emits:
/// the point of the enum is to match the wire, not to tidy it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub enum SessionState {
    Starting,
    Running,
    Exited,
    Dead,
}

/// Which shell integration was injected (§8.5).
///
/// Mirrors `detect::Shell::as_str`. Same reasoning as `SessionState`:
/// `shell_integration: "not-a-shell"` validated against the old `String`
/// declaration. Null when no integration was injected, which is why the
/// fields that carry it stay `Option`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShellIntegration {
    Bash,
    Zsh,
    Fish,
}

/// Whose OSC 133 markers the session is **using** (§18.2a, §8.5.1).
///
/// Distinct from `shell_integration`, which records only what CLASP
/// *injected* and is fixed at spawn. `external` and `mixed` do **not** mean
/// CLASP declined to inject: the snippet is installed and firing, and its
/// markers are being dropped on arrival. Null until the first marker
/// arrives, which is genuinely all CLASP knows before the first prompt
/// cycle.
///
/// A new **field** rather than a fourth value on `ShellIntegration`, and
/// §12.3 is the reason: the append-only rule is written over fields —
/// "existing fields stay; new optional fields can be added" — and says
/// nothing that makes widening a closed enum's value set free. It is also
/// the more honest shape, since `mixed` is a state no value of "which shell
/// CLASP injected for" could express.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Osc133Source {
    Clasp,
    External,
    Mixed,
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
    /// Cursor sub-signal (§8.6 T3c). `0.0` whenever Tier B is off for
    /// the session, which is the ordinary line-oriented case, and
    /// whenever the cursor has not held position for
    /// `cursor_stable_samples`.
    pub cursor_score: f64,
    /// Which branch of the §8.3 ladder answered, in words.
    pub reason: String,
    /// Last logical line of output, escape-free, and **redacted**
    /// (§9.2, REQ-T-011) — it is the line a child that just echoed a
    /// secret puts it on.
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
    pub shell_integration: Option<ShellIntegration>,
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
    /// The read stopped short of `buffer.head` at the holdback boundary
    /// (§4.1), or an unfinished escape was pulled back (REQ-O-008).
    pub held_back: Option<bool>,
    /// `rule kind -> count` for the redactions inside the returned range.
    /// Empty on an unredacted read; absent only on an error envelope.
    pub redactions: Option<std::collections::BTreeMap<String, u64>>,
    pub next_cursor: Option<u64>,
    pub state: Option<SessionState>,
    pub exit_code: Option<i32>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
}

/// One regex match (§5.2 `wait_for_pattern`).
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// Raw byte offset of the match start. **Always** present on a match,
    /// redacted or not, truncated or not.
    pub offset: u64,
    /// The matched text, routed through the OutputProcessor. **Omitted**
    /// when the match intersects the withheld region (§4.1): an in-flight
    /// secret prefix sits at or before it.
    pub text: Option<String>,
}

/// `wait_for_pattern`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitForPattern {
    pub matched: Option<bool>,
    pub r#match: Option<Match>,
    /// Output from the scan start through the match, redacted through the
    /// same pipeline as `read_output`, and clipped before `match.offset`
    /// when the match is withheld — so withheld bytes cannot reach the
    /// agent through the surrounding context.
    pub output_since_start: Option<String>,
    pub truncated_at_tail: Option<bool>,
    pub truncated_for_size: Option<bool>,
    pub held_back: Option<bool>,
    pub next_cursor: Option<u64>,
    /// Set **only** when the daemon clamped the requested deadline
    /// (REQ-T-008). A field that is always present carries no information.
    pub clamped_timeout_secs: Option<u64>,
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
    // The `wait_for` fields (§5.2). Present only when `wait_for` was set,
    // and identical to `wait_for_pattern`'s — the same code path, not a
    // parallel one.
    pub matched: Option<bool>,
    pub r#match: Option<Match>,
    pub output_since_start: Option<String>,
    pub truncated_at_tail: Option<bool>,
    pub truncated_for_size: Option<bool>,
    pub held_back: Option<bool>,
    pub next_cursor: Option<u64>,
    pub clamped_timeout_secs: Option<u64>,
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
    /// Unix seconds at which the exit was first observed (§5.2).
    pub exited_at_unix_secs: Option<u64>,
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
    pub state: Option<SessionState>,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    /// Unix seconds at which the exit was first *observed*, absent while
    /// the session is alive (§5.2). Named for its unit per REQ-T-018.
    pub exited_at_unix_secs: Option<u64>,
    pub shell_integration: Option<ShellIntegration>,
    /// Whose markers the session is using (§8.5.1). Null until the first
    /// marker arrives.
    pub osc133_source: Option<Osc133Source>,
    pub command_count: Option<u64>,
    pub started_at_unix_secs: Option<u64>,
    pub last_activity_unix_ms: Option<i64>,
    pub buffer: Option<Buffer>,
    /// Cumulative `rule kind -> count` for the session (§9.2). Distinct
    /// from `read_output.redactions`, which is per response (REQ-O-012).
    pub redaction_stats: Option<std::collections::BTreeMap<String, u64>>,
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

/// Cursor position within the rendered grid.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub row: u16,
    pub col: u16,
    pub visible: bool,
}

/// `get_screen_state`.
///
/// One tool, two `data` shapes: a full capture carries the grid, a
/// `diff_from` capture carries `base_revision` + `diff` instead, and
/// either can come back as `session_died` with an `exit_code` beside a
/// still-populated screen. Optional-but-declared is 0.0.2's rule for
/// exactly this case.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetScreenState {
    pub screen_revision: Option<u64>,
    pub rows: Option<u16>,
    pub cols: Option<u16>,
    pub cursor: Option<Cursor>,
    pub alt_screen: Option<bool>,
    pub title: Option<String>,
    pub lines: Option<Vec<String>>,
    /// Diff captures only: the revision the diff applies to.
    pub base_revision: Option<u64>,
    /// Diff captures only: the changed regions, as the escape sequence
    /// that turns the base screen into this one.
    pub diff: Option<String>,
    pub screen_tracking: Option<ScreenTracking>,
    /// Both shapes: some cells carry `[REDACTED:unresolved]` because
    /// §4.1's holdback is withholding the bytes that wrote them. The grid
    /// is **masked, not truncated** — it is not covered by the tail-read
    /// bypass, which is licensed by a per-call opt-in this tool does not
    /// have (§5.2, REQ-O-003).
    pub held_back: Option<bool>,
    /// Present on `session_died`.
    pub exit_code: Option<i32>,
}

/// `resize`.
///
/// The dimensions are read back from the session **after** the backend
/// call, so a resize that did not take effect cannot report success — they
/// are not an echo of the request.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resize {
    pub cols: Option<u16>,
    pub rows: Option<u16>,
    /// Present on `session_died`.
    pub exit_code: Option<i32>,
}

/// `interrupt`.
///
/// A **prompt-bearing** response (§5.2, REQ-T-019): `delivered` says the
/// signal was written to the process group, and the session-state block
/// beside it is what tells the agent whether anything acted on it — a
/// session that was `Executing` and is now `AtPrompt` is an interrupt that
/// landed. Declaring `prompt` without the four siblings is what
/// `every_tool_that_declares_prompt_declares_the_same_block` refuses.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Interrupt {
    pub delivered: Option<bool>,
    /// Present on `session_died`.
    pub exit_code: Option<i32>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
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
