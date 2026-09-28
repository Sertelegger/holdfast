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
//! `required` would make Holdfast's own error envelopes fail validation.
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
    /// Outcome status. Branch on this.
    pub status: Status,
    pub data: T,
    /// Human-readable one-liner describing the outcome.
    pub details: String,
}

/// Every status a tool can answer with; each tool emits only some of them.
//
// The statuses the tool set can emit (a subset of §18.1).
//
// Deliberately one shared enum rather than seven per-tool ones: §18.1 is
// the canonical enumeration and each tool's `Possible statuses` list is a
// subset of this. Narrowing per tool would be more precise and is a
// candidate for the milestone that freezes the surface; it is not a
// correctness gap, because a status this enum omits is one no tool emits.
// **Declaration order is load-bearing** — `schemars` emits
// `$defs.Status.enum` in it and `scripts/mcp-smoke.sh` compares that
// array positionally. §18's preamble: a new value is *inserted at its
// catalogued position and never appended*. Keep this in lockstep with
// `crate::mcp::envelope::Status`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Timeout,
    SessionDied,
    SecretProvided,
    SecretCancelled,
    SessionNotFound,
    NameTaken,
    LimitReached,
    SpawnFailed,
    NotSupportedOnPlatform,
    Unavailable,
}

/// What the session is doing. `detection_tier` says how that was judged.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub enum InteractionMode {
    AtPrompt,
    Executing,
    AwaitingSecret,
    Fullscreen,
    Exited,
}

/// Which mechanism produced `interaction_mode`, and so how far to trust it.
///
/// `semantic` is read from OSC 133 shell-integration markers, and
/// `terminal_mode` from the terminal's own state: bracketed paste, echo,
/// or the alternate screen. Both are measurements. `heuristic` is a guess
/// from how long the output has been quiet and how much its last line
/// looks like a prompt. `prompt.reason` names the evidence behind any tier.
///
/// **A running command normally reads `heuristic`, even in an integrated
/// shell, and that is by design.** The markers and bracketed paste
/// describe the shell that produced them, not a program it started, so
/// once the shell hands the terminal to a program they vouch for nothing:
/// the answer is `Executing` at `heuristic`, with `prompt.reason` starting
/// `no deterministic signal`. That is not a lost integration, and the tier
/// is `semantic` again at the shell's next prompt.
//
// The variants carry no doc comments on purpose: one would turn this
// `enum` into a `oneOf` in the published schema. The by-design paragraph
// is `detect::detector`'s owner scoping (GH #240): a licence is withheld
// when the program that emitted a signal and the one holding the terminal
// are both known and differ, which moves every external command from the
// T1 and T2 executing rungs to T3. It is stated here because an agent that
// sees `heuristic` beside a working integration otherwise reads it as a
// broken one.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTier {
    Semantic,
    TerminalMode,
    Heuristic,
}

/// Whether screen tracking is **running** for the session now, not which
/// mode `start_session` asked for: an `adaptive` session reads `off` or
/// `on`.
//
// Tier-B tracking state (§4.5, §18.2a). Declared as an enum so the agent
// sees the vocabulary.
//
// **Two values, and `adaptive` is deliberately not one of them.**
// `screen_tracking` is a three-valued *`start_session` argument* and a
// two-valued *reported state*; §4.5 and §18.2a both enumerate only `off`
// and `on` for the report. `Session::screen_tracking()` derives the wire
// value from the policy's `enabled` flag rather than from
// `screen::ScreenTracking::as_str()`, which has the third spelling — and
// since the default mode is `adaptive`, the wrong accessor would fail this
// closed schema on the *first* response of *every* session rather than on
// a rare one.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreenTracking {
    Off,
    On,
}

/// Which of `held_back`'s two rules stopped this read.
///
/// **What a caller does with it.** `held_back` alone says only *"some of
/// what you asked for is being withheld"*, and the answer to that is
/// right for **both** of these values: each names a boundary that new
/// output moves, so the same read makes progress. **Retry at
/// `next_cursor`.**
///
/// * `in_flight_secret` — a known secret *prefix* is still arriving
///   inside the trailing scan region, so the read withholds from where it
///   starts. One qualification: a session that is quiescent or has
///   exited produces no further bytes to move the boundary with, so this
///   one will not clear on its own. `state` and `interaction_mode`, both
///   in this same response, are how a caller tells that apart from a
///   boundary that is about to move, and `redact: false` is the audited
///   hatch.
/// * `incomplete_escape` — the read would have ended inside an
///   unfinished ANSI escape sequence and the child is still alive, so
///   the tail is held until the sequence completes. The next read starts
///   at the introducer, so it clears either way — the sequence finishes,
///   or it over-runs the operator's `limits.ansi_incomplete_max_bytes`
///   and is dropped.
///
/// A region the read could not vouch for is not a value here: the read
/// makes full progress and the region comes back as
/// `[REDACTED:unresolved]`, counted in `redactions`. A size cap is not a
/// value either; `truncated_for_size` answers that, and the two can be
/// true at once.
//
// §4.1, REQ-O-008; the quiescent qualification is REQ-O-005's. Mirrors
// `output::HeldBackCause::as_str`, and the two are asserted equal in
// `tests/schema.rs` — same construction as `SessionState` below and for
// the same reason.
//
// **A window that could not judge a candidate inside it is not a value
// here, and that absence is GH #195.** It used to be a third one, and it
// was bounded by the *request* rather than by `buffer.head`, so a caller
// obeying "retry at `next_cursor`" retried the identical read for ever and
// never advanced. Every value left here is bounded by `buffer.head` and
// moves. The size cap is kept out for the reason
// `output::ProcessedRead::held_back_cause` gives.
//
// Carried by `read_output`, `wait_for_pattern`, `send_input`'s `wait_for`
// fields and `resources/read`'s `_meta.holdfast` — every surface §4.1
// calls identical. **`get_screen_state` is the one exclusion**, and it is
// not an omission: its `held_back` reports that the grid was *masked*, not
// that a read end was pulled back (REQ-O-011a), so neither of these values
// is an answer to it and there is no `next_cursor` for a caller to retry
// on.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeldBackCause {
    InFlightSecret,
    IncompleteEscape,
}

/// Lifecycle state of a session.
//
// §5.2. Mirrors `session::SessionState::as_str`, which is a closed
// vocabulary of four words. Declared as an enum rather than a `String` for
// the same reason `InteractionMode` and `DetectionTier` are: `state:
// "banana"` validated against the old declaration, and
// `a_wrongly_typed_field_is_rejected` substitutes `json!(3)` — a *type*
// violation — so the looseness was invisible to it. The agent branches on
// this field; a schema that admits any string tells it nothing about what
// to branch on.
//
// PascalCase with no `rename_all`, because that is what `as_str` emits:
// the point of the enum is to match the wire, not to tidy it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub enum SessionState {
    Starting,
    Running,
    Exited,
    Dead,
}

/// Which shell integration Holdfast injected. Null when none was.
//
// §8.5. Mirrors `detect::Shell::as_str`. Same reasoning as `SessionState`:
// `shell_integration: "not-a-shell"` validated against the old `String`
// declaration. Null when no integration was injected, which is why the
// fields that carry it stay `Option`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShellIntegration {
    Bash,
    Zsh,
    Fish,
}

/// Whose OSC 133 markers the session is **using**.
///
/// Distinct from `shell_integration`, which records only what Holdfast
/// *injected* and is fixed at spawn. `external` and `mixed` do **not** mean
/// Holdfast declined to inject: the snippet is installed and firing, and its
/// markers are being dropped on arrival. Null until the first marker
/// arrives, which is genuinely all Holdfast knows before the first prompt
/// cycle. Whether the markers in use still capture command text is
/// `command_capture`'s question, not this one's.
//
// Everything in `///` above is published as this type's `description` in
// `status`'s and `list_sessions`'s output schemas, so it says what the
// value means to an agent and nothing else; the design rationale, and the
// spec's §18.2a and §8.5.1, are here.
//
// A field of its own rather than a fourth value on `ShellIntegration`,
// because it answers a different question: "which shell Holdfast injected
// for" and "whose markers are in use" are two, and `mixed` is a state no
// value of the first could express. The same rule — one question per
// field — is why `CommandCapture` is not a value of this one.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Osc133Source {
    Holdfast,
    External,
    Mixed,
}

/// Whether the session's newest `get_command_history` entry has its
/// command text: `captured`, or `missing` when that entry's
/// OSC 133 `C` marker had no `B` marker in front of it, so its `command`
/// is null. Null until the first entry is recorded.
///
/// `missing` has two causes. A prompt whose `B` marker does not arrive —
/// one a prompt framework such as starship regenerates over the shell
/// integration's markers, one a hook added to `PROMPT_COMMAND` after the
/// session started rewrites, or a foreign integration that emits no `B` —
/// leaves the entry the command's own, with its exit code and output span
/// exact. A program that printed a `C` marker in its own output opens an
/// entry that is not a command: it takes the exit code and the rest of the
/// output of the command that printed it, whose own entry stays open.
///
/// It describes the last command recorded and cannot predict the next,
/// and it changes only when an entry is recorded. After a program has
/// printed a `C` marker, later commands can stop being recorded at all;
/// while `command_count` does not grow as commands run, this field is
/// stale.
//
// Everything in `///` above is published as this type's `description`,
// so it says what the value means to an agent; the design rationale is
// here (§18.2a). The freeze in its last paragraph is §8.5.1 rule 3's
// permanent yield, GH #265.
//
// Its own field, not a fourth `Osc133Source` value, because it is a
// second question with its own answer under every source: a prompt
// framework that regenerates the prompt over the `A`/`B` markers loses
// the text whether those markers are Holdfast's, a foreign integration's,
// or a mix, and one value could not say `external` and `missing` at once
// (GH #220). The variants carry no doc comments on purpose: one would
// turn this `enum` into a `oneOf` in the published schema.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommandCapture {
    Captured,
    Missing,
}

/// The evidence behind `interaction_mode` and `detection_tier`.
//
// Carried by every prompt-bearing response (§18.2a); the field docs below
// are published to agents, so they name config keys and not spec sections
// (§8.4 for `confidence`, §8.6 T3a-T3c for the three scores, §8.3's ladder
// for `reason`, §9.2 and REQ-T-011 for `last_line`).
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prompt {
    /// Combined confidence in [0,1]. At `heuristic` it is
    /// `quiescent_score` times the larger of `pattern_score` and
    /// `cursor_score`, and 0.5 or more reads as `AtPrompt`.
    pub confidence: f64,
    /// How settled the output stream is, in [0,1]: 1.0 once nothing has
    /// arrived for the operator's `prompts.settle_threshold_ms`.
    pub quiescent_score: f64,
    /// How well the last line matches a prompt pattern, built-in or the
    /// operator's `prompts.extra_patterns`, in [0,1].
    pub pattern_score: f64,
    /// How much the cursor's position looks like a prompt's, in [0,1].
    /// `0.0` whenever `screen_tracking` is off, which is the ordinary
    /// line-oriented case, and until the cursor has held its position for
    /// the operator's `prompts.cursor_stable_samples`.
    pub cursor_score: f64,
    /// Which rule produced the answer, in words. A running command
    /// normally reads `no deterministic signal`, followed by the scores.
    pub reason: String,
    /// Last logical line of output, escape-free, and **redacted** — it is
    /// the line a child that just echoed a secret puts it on.
    pub last_line: String,
}

/// `start_session`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartSession {
    pub session_id: Option<String>,
    pub name: Option<String>,
    pub pid: Option<u32>,
    /// The *effective* working directory the child was spawned in.
    pub cwd: Option<String>,
    /// Which shell integration was injected, if any.
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
    /// The read stopped short of the newest output at the secret
    /// holdback boundary, or an unfinished escape was pulled back.
    /// `held_back_cause` says which, and both of them clear as output
    /// arrives.
    // §4.1, REQ-O-008.
    pub held_back: Option<bool>,
    /// Which rule held this read back. **Non-null exactly when
    /// `held_back` is true; present and `null` otherwise**, so branch on
    /// the value and never on the key's existence.
    ///
    /// Both values name a boundary that new output moves — retry at
    /// `next_cursor` — with one qualification on `in_flight_secret`,
    /// stated in that value's own documentation.
    // The qualification is REQ-O-005's.
    pub held_back_cause: Option<HeldBackCause>,
    /// `kind -> count` for the redactions inside the returned range.
    /// Empty on an unredacted read; absent only on an error envelope.
    ///
    /// **Every key is a rule's `kind` except one.** `unresolved` names no
    /// rule: it counts `[REDACTED:unresolved]` markers, bytes the read
    /// window could not vouch for, which can include a real secret whose
    /// own kind is then not counted. It is a count of markers really
    /// present in `output`, like every other key, so a caller totalling
    /// this map gets substitutions rather than credentials.
    //
    // §9.2's reserved pseudo-kind (REQ-O-011a, GH #195). "Can include a
    // real secret" is `output::redact::merge_spans` folding a real match
    // that meets an unjudgeable region into the one marker; the server
    // instructions and `read_output`'s description carry the same caveat.
    pub redactions: Option<std::collections::BTreeMap<String, u64>>,
    pub next_cursor: Option<u64>,
    /// The `holdfast://` URI that fetches this session's whole buffer as an
    /// MCP resource.
    // §5.2, §5.5. Declared since rev. 2 and emitted only from 0.0.5,
    // because `resources/read` had to resolve it first — 0.0.3 was told
    // explicitly not to stub it.
    pub resource_uri: Option<String>,
    pub state: Option<SessionState>,
    pub exit_code: Option<i32>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
}

/// One regex match.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// Raw byte offset of the match start. **Always** present on a match,
    /// redacted or not, truncated or not.
    pub offset: u64,
    /// The matched text, routed through the OutputProcessor. **Omitted**
    /// when the match intersects the withheld region: an in-flight secret
    /// prefix sits at or before it.
    pub text: Option<String>,
}

/// `wait_for_pattern`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitForPattern {
    /// Present for a wait that was given a pattern; absent for one that
    /// was not.
    pub matched: Option<bool>,
    /// Present **only** for a pattern-less wait: the session left
    /// `Executing` before the deadline.
    ///
    /// Spelled differently from `matched` on purpose. The two answer
    /// different questions — "your regex appeared" and "the session
    /// stopped running a command" — and a single field would let a caller
    /// read one as the other. Neither is the whole answer on its own:
    /// `interaction_mode` beside it says *what* the session reached, and
    /// `Fullscreen`, `AwaitingSecret` and `Exited` all satisfy this while
    /// meaning something the caller must act on differently.
    pub reached: Option<bool>,
    pub r#match: Option<Match>,
    /// Output from the scan start through the match, redacted through the
    /// same pipeline as `read_output`, and clipped before `match.offset`
    /// when the match is withheld — so withheld bytes cannot reach the
    /// agent through the surrounding context.
    pub output_since_start: Option<String>,
    pub truncated_at_tail: Option<bool>,
    pub truncated_for_size: Option<bool>,
    pub held_back: Option<bool>,
    /// Which rule held this wait's read back. **Non-null exactly when
    /// `held_back` is true; present and `null` otherwise.**
    ///
    /// The vocabulary is `read_output`'s, because the read is —
    /// `output_since_start` runs through the same pipeline. This tool's
    /// `held_back` is wider by one term, a match whose range intersects
    /// the withheld region, and that term is the secret holdback by
    /// construction, so it reports `in_flight_secret` — which is also
    /// the boundary `next_cursor` is set from on that arm.
    pub held_back_cause: Option<HeldBackCause>,
    pub next_cursor: Option<u64>,
    /// Set **only** when the daemon clamped the requested deadline. A
    /// field that is always present carries no information.
    // REQ-T-008.
    pub clamped_timeout_secs: Option<u64>,
    /// `"pattern_did_not_match_but_session_is_at_prompt"` when the wait
    /// expired against a session already back at a measured prompt — the
    /// signature of a regex written for somebody else's `$PS1`.
    ///
    /// **Absent when it does not fire, not null** — the same convention
    /// as `clamped_timeout_secs` above, and the opposite of
    /// `send_input`'s `warning`, which is emitted on every write and null
    /// when there is nothing to say. The two tools differ on purpose: a
    /// write always has an answer to give about a secret prompt, and a
    /// wait does not.
    // The write's answer is REQ-SEC-011's.
    pub warning: Option<String>,
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
    /// would be a guess.
    pub bytes_written: Option<u64>,
    /// `"session_awaiting_secret"` when the write went to an echo-off
    /// session — the write still happened — or
    /// `"pattern_did_not_match_but_session_is_at_prompt"` when a
    /// `wait_for` ended unmatched against a session already at a measured
    /// prompt. The first takes precedence if both could apply.
    ///
    /// **Present on every write, null when there is nothing to say** —
    /// the opposite of `wait_for_pattern`'s `warning`, which is omitted
    /// unless it fires.
    //
    // `session_awaiting_secret` is REQ-SEC-011, and it is why a write
    // always has an answer to give. Both cannot apply today, since an
    // `AwaitingSecret` session is not `AtPrompt`; the precedence is written
    // down against a future mode that breaks that.
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
    pub held_back_cause: Option<HeldBackCause>,
    pub next_cursor: Option<u64>,
    pub clamped_timeout_secs: Option<u64>,
    pub interaction_mode: Option<InteractionMode>,
    pub detection_tier: Option<DetectionTier>,
    pub screen_tracking: Option<ScreenTracking>,
    pub title: Option<String>,
    pub prompt: Option<Prompt>,
}

/// `request_secret_input`. No field here can hold the secret's value: a
/// caller learns a byte count and an outcome, never the value.
//
// **That is this type's job** (REQ-SEC-004, REQ-T-015). §9.2 marks the
// secret `n/a` for redaction rather than "redacted", because it reaches
// no boundary a redactor could run at: the protections are a type that
// cannot serialise, a write path that consumes, a `Drop` that zeroes —
// and this schema, which has nowhere to put it.
// `request_secret_input_has_no_field_that_could_carry_a_value` asserts
// the key set **exactly**, so a field added later fails whatever it is
// called.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestSecretInput {
    /// `secret_provided`: bytes actually written to the PTY,
    /// post-normalisation and including the appended `\n` when
    /// `append_newline`. A **count**, which is the whole of what a
    /// caller learns.
    pub bytes_written: Option<u64>,
    /// On both `secret_provided` and `secret_cancelled`.
    ///
    /// **Absent on the two paths that raise nothing**: a call cancelled
    /// before it raised or adopted anything, and one refused
    /// `at_shell_prompt` before the raise. Neither has a request to name.
    /// Every other `secret_cancelled` carries one, including an
    /// `at_shell_prompt` the writer returned after a human answered.
    // GH #127 and GH #262 respectively.
    pub request_id: Option<String>,
    /// `secret_cancelled` only: `user_cancelled` | `timeout` |
    /// `too_large` | `concurrent_request_pending` | `caller_cancelled` |
    /// `not_echo_off` | `at_shell_prompt`.
    pub reason: Option<String>,
    /// `session_died` only.
    // §5.1.
    pub exit_code: Option<i32>,
    // ---- §5.4's session-state block, on `secret_provided` (REQ-T-019).
    // Built by `mcp::detection`'s one builder. §5.4 is explicit that a
    // tool declaring `prompt` declares the whole block, because a second
    // variant means a second builder — which is exactly how
    // `list_sessions[].prompt` diverged for five revisions.
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
    /// Unix seconds at which the exit was first observed.
    pub exited_at_unix_secs: Option<u64>,
}

/// Ring-buffer extent for one session.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Buffer {
    pub head: u64,
    pub tail: u64,
    /// Bytes currently held in the ring, i.e. `head - tail`.
    // §5.4. Declared since rev. 2 with nothing emitting it until 0.0.5's
    // resource layer gave it a consumer.
    pub total_bytes: Option<u64>,
    /// The `holdfast://` URI that fetches this buffer in bulk.
    // §5.5. Declared since rev. 2 with no producer; emitted only now that
    // `resources/read` resolves it, because a URI that does not resolve is
    // worse than an absent one.
    pub resource_uri: Option<String>,
}

/// One session record, shared by `status` and `list_sessions` entries.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub id: Option<String>,
    pub name: Option<String>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    /// The `[[security.profiles]]` entry this session was started from,
    /// or **`null`** for one started with `command`/`args`.
    ///
    /// `command` and `args` above are the argv that ran and say nothing
    /// about where it came from: a profile-started session and an
    /// agent-authored one that produced the same argv are otherwise
    /// indistinguishable on this record, and only the first can ever
    /// receive a keychain credential. `null` is affirmative rather than an
    /// omitted key, because the negative case is the one an operator is
    /// looking for.
    ///
    /// The **name** and nothing more: not the operator's template and not
    /// the `vars` the agent supplied.
    //
    // §9.6, GH #46. Name-only is `binding_resolved`'s rule.
    pub profile: Option<String>,
    pub state: Option<SessionState>,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    /// Unix seconds at which the exit was first *observed*, absent while
    /// the session is alive.
    // §5.2. Named for its unit per REQ-T-018.
    pub exited_at_unix_secs: Option<u64>,
    pub shell_integration: Option<ShellIntegration>,
    /// Whose markers the session is using. Null until the first marker
    /// arrives.
    pub osc133_source: Option<Osc133Source>,
    /// Whether the newest history entry has its command text. It describes
    /// the last command recorded and cannot predict the next. Null until
    /// the first entry is recorded.
    pub command_capture: Option<CommandCapture>,
    pub command_count: Option<u64>,
    pub started_at_unix_secs: Option<u64>,
    pub last_activity_unix_ms: Option<i64>,
    /// Unix seconds at which the idle reaper will terminate this session.
    /// **`null` means reaping is disabled** for it — `idle_timeout_secs =
    /// 0` — which is a different statement from a deadline far in the
    /// future.
    // §5.2, REQ-S-004/REQ-S-007. Named for its unit per REQ-T-018.
    pub idle_deadline_unix_secs: Option<u64>,
    pub buffer: Option<Buffer>,
    /// Cumulative `kind -> count` for the session. Distinct from
    /// `read_output`'s `redactions`, which is per response. Keys are rule
    /// kinds plus the reserved `unresolved` pseudo-kind, which
    /// `read_output`'s `redactions` describes.
    // §9.2, REQ-O-012.
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

/// One command the session ran, from its OSC 133 markers.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandEntry {
    /// Monotonic per session; survives ring eviction.
    pub index: u64,
    /// The echoed command line, best-effort and redacted. A command wider
    /// than the terminal can come back as `[REDACTED:unresolved]`, as its
    /// tail, or with part of it repeated in front, depending on the shell;
    /// the tool's description says which.
    /// **Null when no text was captured** — no `B` marker armed the
    /// capture before this command's `C` — which is never spelled `""`:
    /// an empty string is a capture that saw no echo.
    pub command: Option<String>,
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
/// still-populated screen.
//
// Optional-but-declared is 0.0.2's rule for exactly this case.
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
    /// Both shapes: some cells carry `[REDACTED:unresolved]` because the
    /// secret holdback is withholding the bytes that wrote them. The grid
    /// is **masked, not truncated**.
    //
    // §4.1's holdback. It is not covered by the tail-read bypass, which is
    // licensed by a per-call opt-in this tool does not have (§5.2,
    // REQ-O-003).
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
/// `delivered` says the signal was written to the process group, and the
/// session-state fields beside it are what tell whether anything acted on
/// it — a session that was `Executing` and is now `AtPrompt` is an
/// interrupt that landed.
//
// A **prompt-bearing** response (§5.2, REQ-T-019). Declaring `prompt`
// without the four siblings is what
// `every_tool_that_declares_prompt_declares_the_same_block` refuses.
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
    // Optional for the reason the module header gives, and this is the
    // field that proved it: `get_command_history` answers a missing
    // session through `envelope::from_error`, whose `data` is `{}`.
    // Declared as a bare `Vec` this was `required`, so Holdfast's own
    // `session_not_found` response failed its own advertised schema —
    // caught by `get_command_history_session_not_found_response_matches_
    // its_schema`, which is the only path that reaches it.
    //
    // `ListSessions::sessions` is deliberately *not* optional: that tool
    // takes no arguments, emits only `ok`, and therefore has no second
    // `data` shape.
    //
    // `//` rather than `///`, because a doc comment here is this field's
    // published description and none of it is for an agent.
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
