//! The global TOML configuration file (§10.1, §10.2).
//!
//! Discovery is `$XDG_CONFIG_HOME/clasp/config.toml`, falling back to
//! `~/.config/clasp/config.toml` (REQ-CFG-002). **`CLASP_RUNTIME_DIR`
//! does not move it** — REQ-CFG-005 makes that variable *instance*
//! selection, and wiring config discovery to it would turn the one
//! environment variable this project allows into exactly the override
//! REQ-CFG-001 forbids.
//!
//! **A missing file is not an error**; it resolves to
//! [`Config::default`]. Only a file that exists and does not parse, or
//! parses and fails validation, is an error — and an error rejects
//! daemon startup before a socket is bound (REQ-CFG-003).
//!
//! **Unknown keys are rejected, not ignored** (§10.1). Every struct in
//! this module carries `#[serde(deny_unknown_fields)]`, at the top level
//! *and* inside each table, because that is what makes withdrawing a
//! knob mean anything: an operator who still sets `http_socket_path`,
//! `log_dir` or `dangerous_commands_enabled` believes the daemon changed
//! behaviour, and rejection is what turns a removal into a message.
//!
//! **§10.2's example is a fixture, not an illustration.** Every key it
//! prints is modelled here, including the ones no milestone honours yet
//! — a published key this loader did not model would give an operator
//! who copied the example verbatim a daemon that refuses to start and an
//! error naming the *spec's* key as the typo. At the revision this file
//! was written against that is **43 keys across 7 tables**: `[limits]`
//! 17, `[terminal]` 5, `[prompts]` 4, `[security]` 5, `[ui]` 4,
//! `[notifications]` 3, `[daemon]` 5. Read the breakdown, never the
//! total — 43 was also the pre-rev-48 count across *eight* tables, so a
//! check against the sum agrees with two revisions while being wrong
//! against both.
//!
//! **"Honoured in 0.0.5? no" means parsed, validated and unread — it
//! does not mean absent** (REQ-CFG-004's second clause). Each such field
//! carries a doc comment naming its owning milestone, so a later
//! milestone wires the value rather than adding the field.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::detect::{PromptPattern, MAX_EXTRA_PATTERNS};

/// Everything that can go wrong turning a file into a [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file {path} could not be read: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Includes the unknown-key case: `toml`'s `deny_unknown_fields`
    /// message names the offending key, which is §10.1's contract.
    #[error("config file {path} is not valid: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// A file that parsed and then failed a semantic rule. The message
    /// always names the key and the value (§10.1, REQ-CFG-003).
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

// ------------------------------------------------------------ discovery

/// `$XDG_CONFIG_HOME/clasp/config.toml`, else `$HOME/.config/clasp/config.toml`.
///
/// `None` when neither variable is set, which is the same as "no file":
/// a process with no home is not a misconfigured one.
pub fn config_path() -> Option<PathBuf> {
    config_path_from(
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

fn config_path_from(xdg_config_home: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    let base = match xdg_config_home {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => {
            let home = home?;
            if home.as_os_str().is_empty() {
                return None;
            }
            home.join(".config")
        }
    };
    Some(base.join("clasp").join("config.toml"))
}

/// Load the global config from its discovered path.
///
/// A missing file — or no discoverable path at all — is
/// [`Config::default`], not an error.
pub fn load() -> Result<Config, ConfigError> {
    match config_path() {
        Some(path) => load_from(&path),
        None => Ok(Config::default()),
    }
}

/// Load from an explicit path. A file that does not exist resolves to
/// [`Config::default`]; anything else that fails is an error.
pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    parse_named(&text, path)
}

/// Parse and validate a config from a string, for tests and for callers
/// that already hold the bytes.
pub fn parse_str(text: &str) -> Result<Config, ConfigError> {
    parse_named(text, Path::new("<config>"))
}

fn parse_named(text: &str, path: &Path) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    config.validate()?;
    Ok(config)
}

// -------------------------------------------------------------- schema

/// The whole of `config.toml`.
///
/// `deny_unknown_fields` here rejects an unmodelled *table*; the same
/// attribute on each table below rejects an unmodelled *key*. §10.1
/// requires both, and a top-level-only version silently accepts
/// `[daemon] log_dir`, which is the exact case the rule exists for.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub terminal: TerminalConfig,
    #[serde(default)]
    pub prompts: PromptsConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    /// §5.8.2 spells this as an **array of tables**, `[[adapters]]`. A
    /// `[adapters]` table and a `[[adapters]]` array are mutually
    /// exclusive in TOML, so a loader modelling the table form makes an
    /// operator following the normative section unable to start.
    #[serde(default)]
    pub adapters: Vec<AdapterSpec>,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

/// §4.2's limits table.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "d_max_concurrent_sessions")]
    pub max_concurrent_sessions: usize,
    /// `0` **disables** reaping for a session (REQ-S-004, §4.2). One of
    /// the two keys in this file where zero is legal.
    #[serde(default = "d_default_idle_timeout_secs")]
    pub default_idle_timeout_secs: u64,
    #[serde(default = "d_output_buffer_bytes")]
    pub output_buffer_bytes: usize,
    #[serde(default = "d_read_output_default_max_bytes")]
    pub read_output_default_max_bytes: usize,
    #[serde(default = "d_read_output_hard_max_bytes")]
    pub read_output_hard_max_bytes: usize,
    #[serde(default = "d_resource_read_max_bytes")]
    pub resource_read_max_bytes: usize,
    #[serde(default = "d_output_broadcast_capacity")]
    pub output_broadcast_capacity: usize,
    /// **Reserved and unread.** v0.1.0 ships one outstanding secret
    /// request per session, hardcoded; §4.2 marks the knob *"fixed in
    /// v0.1.0 (not configurable)"* and §10.2 publishes it anyway, which
    /// is consistent — the key is in the schema and ignored. It is a
    /// `[limits]` key: putting it in [`SecurityConfig`] would make
    /// §10.2's own published example fail `deny_unknown_fields`.
    #[serde(default = "d_max_outstanding_secret_requests_per_session")]
    pub max_outstanding_secret_requests_per_session: u32,
    #[serde(default = "d_redaction_lookbehind_bytes")]
    pub redaction_lookbehind_bytes: usize,
    #[serde(default = "d_redaction_lookahead_bytes")]
    pub redaction_lookahead_bytes: usize,
    #[serde(default = "d_partial_secret_scan_bytes")]
    pub partial_secret_scan_bytes: usize,
    #[serde(default = "d_prefilter_prefix_expansion_limit")]
    pub prefilter_prefix_expansion_limit: usize,
    #[serde(default = "d_ansi_incomplete_max_bytes")]
    pub ansi_incomplete_max_bytes: usize,
    #[serde(default = "d_wait_for_pattern_max_timeout_secs")]
    pub wait_for_pattern_max_timeout_secs: u64,
    /// **Unread — 0.0.9** (§5.7 file transfer).
    #[serde(default = "d_file_transfer_chunk_bytes")]
    pub file_transfer_chunk_bytes: usize,
    /// **Unread — 0.0.9** (§5.7 file transfer).
    #[serde(default = "d_file_transfer_max_bytes")]
    pub file_transfer_max_bytes: u64,
    #[serde(default = "d_command_history_max_entries")]
    pub command_history_max_entries: usize,
}

/// §4.2's terminal knobs.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalConfig {
    /// `off` | `adaptive` | `on` (§4.5).
    #[serde(default = "d_screen_tracking_default")]
    pub screen_tracking_default: String,
    #[serde(default = "d_screen_tracking_idle_disable_secs")]
    pub screen_tracking_idle_disable_secs: u64,
    #[serde(default = "d_terminal_queries")]
    pub terminal_queries: bool,
    #[serde(default = "d_terminal_query_replies_per_min")]
    pub terminal_query_replies_per_min: u32,
    #[serde(default = "d_shell_integration")]
    pub shell_integration: bool,
}

/// §8.6's prompt-detection knobs.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptsConfig {
    #[serde(default = "d_settle_threshold_ms")]
    pub settle_threshold_ms: u64,
    #[serde(default = "d_cursor_prompt_chars")]
    pub cursor_prompt_chars: String,
    #[serde(default = "d_cursor_stable_samples")]
    pub cursor_stable_samples: u32,
    /// Config patterns **append** to the built-in set. §8.6 promises the
    /// config can *"override or extend"* and §10.2 publishes one key,
    /// spelled for the extend half; `PatternSet::build`'s `replace` flag
    /// is the override mechanism and no TOML key reaches it, so this
    /// loader passes `replace: false`. Inventing an
    /// `extra_patterns_replace` to complete §8.6's sentence would be a
    /// plan naming a config key on a surface the spec has not specified.
    #[serde(default)]
    pub extra_patterns: Vec<PromptPattern>,
}

/// §9's security knobs.
///
/// **There is no preflight kill switch.** `dangerous_commands_enabled`
/// stood here and is withdrawn: §9.3 specifies the preflight and names
/// no way to turn it off, a working `false` would make REQ-T-002,
/// REQ-SEC-001, REQ-SEC-001a and REQ-SEC-002 falsifiable from a config
/// file, and — unlike `redaction_enabled`, which §9.4's `session_start`
/// row carries on every session — nothing at all would record that the
/// preflight was off. A config carrying the key is **rejected**.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default = "d_redaction_enabled")]
    pub redaction_enabled: bool,
    /// **Parsed and deliberately not passed to `RuleSet`.** The
    /// `ExtraRule` → `RuleSpec` mapping is a §15.1 open question: §10.2
    /// publishes `{ name, kind, regex }`, `RuleSpec` requires `pattern`
    /// plus non-empty `positive`/`negative`, and `builtin_with_extra`
    /// takes a TOML *string* rather than a struct. Wiring it with the
    /// examples requirement makes §10.2's own example unloadable; wiring
    /// it without makes the loader construct rules the compiler was
    /// written to refuse, on the redaction path. So the field is modelled
    /// permissively — the shape is exactly what is undecided — and
    /// `a_user_redaction_pattern_is_accepted_and_not_yet_in_force` says
    /// in its name that it reaches no redactor.
    #[serde(default)]
    pub extra_redaction_patterns: Vec<toml::Value>,
    /// **Unread — 0.0.7.** `prompt` | `keychain` | `both` (§9.6).
    #[serde(default = "d_secret_provider")]
    pub secret_provider: String,
    /// **Unread — 0.0.7.**
    #[serde(default = "d_autofill_on_echo_off")]
    pub autofill_on_echo_off: bool,
    /// **Unread — 0.0.8.**
    #[serde(default = "d_strict_confirmation")]
    pub strict_confirmation: bool,
    /// **Unread — 0.0.7.** §10.2's example is fully commented, so
    /// nothing in the published fixture exercises this; §9.6 defines the
    /// block normatively, so an operator who uncomments it must not get a
    /// rejected config.
    #[serde(default)]
    pub secret_bindings: Vec<SecretBinding>,
}

/// One operator-configured secret binding (§9.6). **Unread in 0.0.5.**
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// The override key, and the only part of a binding any surface
    /// shows: `BindingApprovalRequired` (§7.5), `GET
    /// /api/binding-approvals` (§7.6.3) and the `binding_resolved` /
    /// `binding_approval` audit kinds (§18.7) all carry `binding_name`
    /// and nothing else identifying.
    pub name: String,
    pub match_command: String,
    pub match_prompt: String,
    pub provider: String,
    pub reference: String,
    #[serde(default)]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub require_confirm: bool,
}

/// §7.6's web-UI bridge knobs. **All unread — 0.0.10.**
///
/// **There is no socket-path knob.** All three sockets live in the
/// runtime directory §7.1 discovers and none is individually
/// relocatable: a knob that moved one out would put it outside the
/// `0700` verification §7.1 performs, and would let two daemons under
/// different `CLASP_RUNTIME_DIR`s share an `http.sock` while disagreeing
/// about which instance they are. A config carrying `http_socket_path`
/// is **rejected**.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiConfig {
    /// `0` = ephemeral (the default); any other value pins the port.
    #[serde(default = "d_ui_bridge_pinned_port")]
    pub ui_bridge_pinned_port: u16,
    #[serde(default = "d_ui_token_idle_ttl_secs")]
    pub ui_token_idle_ttl_secs: u64,
    #[serde(default = "d_ui_token_absolute_ttl_secs")]
    pub ui_token_absolute_ttl_secs: u64,
    /// A `[ui]` key and **not** a `[limits]` one, which is not where
    /// §4.2's table would lead you to put it.
    #[serde(default = "d_max_bridge_sessions")]
    pub max_bridge_sessions: usize,
}

/// §5.8.3's notification knobs. **All unread — 0.0.9.**
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsConfig {
    /// `desktop` | `webhook` | `command` | `none` (default).
    #[serde(default = "d_sink")]
    pub sink: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// All **six** of §5.8.3's kinds by default. An omitted kind is a
    /// *suppressed* one, so a short default silently disables
    /// `coalesced` — the rate limiter's own overflow summary, which
    /// REQ-AF-008 asserts arrives.
    #[serde(default = "d_events")]
    pub events: Vec<String>,
    #[serde(default = "d_notification_rate_limit_per_min")]
    pub notification_rate_limit_per_min: u32,
}

/// One `[[adapters]]` entry (§5.8.2). **Unread — 0.0.9.**
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSpec {
    pub name: String,
    pub match_command: String,
    #[serde(default)]
    pub prompt_patterns: Vec<AdapterPromptPattern>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// A prompt pattern inside an `[[adapters]]` entry.
///
/// `kind` is **optional**: §5.8.2 carries it on every vendored row and
/// §10.2's commented example does not, so a loader modelling only
/// `{ regex, score }` rejects the normative shape.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPromptPattern {
    pub regex: String,
    pub score: f32,
    #[serde(default)]
    pub kind: Option<String>,
}

/// §7.3 and §19.1's daemon knobs.
///
/// **There is no log-directory knob.** The three log paths are §19.1's,
/// and the one thing that relocates any of them is `CLASP_RUNTIME_DIR`,
/// which is instance selection rather than a knob. `log_dir` is
/// withdrawn and a config carrying it is **rejected**; the two retention
/// knobs stay, because a retention window is behaviour this file
/// configures and a path is not.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// The client-less daemon exit (§7.3, REQ-D-006). **`0` disables
    /// it** — the second of the two keys in this file where zero is
    /// legal. §7.3 says the exit is *"configurable, can be disabled"*
    /// and names no value; `0` is the spelling
    /// `[limits] default_idle_timeout_secs` already uses for the same
    /// idea in the same file.
    #[serde(default = "d_idle_shutdown_after_secs")]
    pub idle_shutdown_after_secs: u64,
    /// **Unread — 0.0.9** (§5.8.1 recording).
    #[serde(default = "d_record_all_sessions")]
    pub record_all_sessions: bool,
    /// **Unread — 0.0.7** (§9.6 keychain approval window).
    #[serde(default = "d_binding_approval_timeout_secs")]
    pub binding_approval_timeout_secs: u64,
    /// §19.1: `audit.log` rotates daily and is kept this many **days**.
    #[serde(default = "d_audit_retention_days")]
    pub audit_retention_days: u32,
    /// §19.1: `daemon.log` rotates weekly and is kept this many
    /// **weeks** — that is §19.1's published spelling, verbatim. Do not
    /// normalise it to days; `deny_unknown_fields` turns a renamed knob
    /// into a daemon that rejects the spec's own config file.
    #[serde(default = "d_daemon_log_retention_weeks")]
    pub daemon_log_retention_weeks: u32,
}

// ------------------------------------------------------------- defaults
//
// One function per knob, used by both `serde(default = ...)` and the
// `Default` impls below, so a default has exactly one spelling.

fn d_max_concurrent_sessions() -> usize {
    8
}
fn d_default_idle_timeout_secs() -> u64 {
    1800
}
fn d_output_buffer_bytes() -> usize {
    1_048_576
}
fn d_read_output_default_max_bytes() -> usize {
    32_768
}
fn d_read_output_hard_max_bytes() -> usize {
    262_144
}
fn d_resource_read_max_bytes() -> usize {
    4_194_304
}
fn d_output_broadcast_capacity() -> usize {
    256
}
fn d_max_outstanding_secret_requests_per_session() -> u32 {
    1
}
fn d_redaction_lookbehind_bytes() -> usize {
    512
}
fn d_redaction_lookahead_bytes() -> usize {
    8192
}
fn d_partial_secret_scan_bytes() -> usize {
    512
}
fn d_prefilter_prefix_expansion_limit() -> usize {
    64
}
fn d_ansi_incomplete_max_bytes() -> usize {
    64
}
fn d_wait_for_pattern_max_timeout_secs() -> u64 {
    3600
}
fn d_file_transfer_chunk_bytes() -> usize {
    65_536
}
fn d_file_transfer_max_bytes() -> u64 {
    104_857_600
}
fn d_command_history_max_entries() -> usize {
    1000
}
fn d_screen_tracking_default() -> String {
    "adaptive".to_string()
}
fn d_screen_tracking_idle_disable_secs() -> u64 {
    300
}
fn d_terminal_queries() -> bool {
    true
}
fn d_terminal_query_replies_per_min() -> u32 {
    60
}
fn d_shell_integration() -> bool {
    true
}
fn d_settle_threshold_ms() -> u64 {
    250
}
fn d_cursor_prompt_chars() -> String {
    "$%#>):❯".to_string()
}
fn d_cursor_stable_samples() -> u32 {
    3
}
fn d_redaction_enabled() -> bool {
    true
}
fn d_secret_provider() -> String {
    "prompt".to_string()
}
fn d_autofill_on_echo_off() -> bool {
    false
}
fn d_strict_confirmation() -> bool {
    false
}
fn d_ui_bridge_pinned_port() -> u16 {
    0
}
fn d_ui_token_idle_ttl_secs() -> u64 {
    3600
}
fn d_ui_token_absolute_ttl_secs() -> u64 {
    14_400
}
fn d_max_bridge_sessions() -> usize {
    16
}
fn d_sink() -> String {
    "none".to_string()
}
fn d_events() -> Vec<String> {
    NOTIFICATION_EVENT_KINDS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}
fn d_notification_rate_limit_per_min() -> u32 {
    10
}
fn d_idle_shutdown_after_secs() -> u64 {
    86_400
}
fn d_record_all_sessions() -> bool {
    false
}
fn d_binding_approval_timeout_secs() -> u64 {
    120
}
fn d_audit_retention_days() -> u32 {
    14
}
fn d_daemon_log_retention_weeks() -> u32 {
    4
}

/// §5.8.3's six event kinds, in that section's order. The default value
/// of `[notifications] events` is all six.
pub const NOTIFICATION_EVENT_KINDS: [&str; 6] = [
    "session_exited",
    "awaiting_secret",
    "awaiting_confirmation",
    "session_reaped",
    "transfer_complete",
    "coalesced",
];

/// §5.8.3's sinks, in that section's order.
pub const NOTIFICATION_SINKS: [&str; 4] = ["desktop", "webhook", "command", "none"];

/// §9.6's secret providers.
pub const SECRET_PROVIDERS: [&str; 3] = ["prompt", "keychain", "both"];

/// §4.5's screen-tracking modes, matching `screen::ScreenTracking`.
pub const SCREEN_TRACKING_MODES: [&str; 3] = ["off", "adaptive", "on"];

macro_rules! table_default {
    ($t:ty { $($field:ident : $d:ident),* $(,)? } $( ; $($extra:ident),* )? ) => {
        impl Default for $t {
            fn default() -> Self {
                Self {
                    $($field: $d(),)*
                    $($($extra: Default::default(),)*)?
                }
            }
        }
    };
}

table_default!(LimitsConfig {
    max_concurrent_sessions: d_max_concurrent_sessions,
    default_idle_timeout_secs: d_default_idle_timeout_secs,
    output_buffer_bytes: d_output_buffer_bytes,
    read_output_default_max_bytes: d_read_output_default_max_bytes,
    read_output_hard_max_bytes: d_read_output_hard_max_bytes,
    resource_read_max_bytes: d_resource_read_max_bytes,
    output_broadcast_capacity: d_output_broadcast_capacity,
    max_outstanding_secret_requests_per_session: d_max_outstanding_secret_requests_per_session,
    redaction_lookbehind_bytes: d_redaction_lookbehind_bytes,
    redaction_lookahead_bytes: d_redaction_lookahead_bytes,
    partial_secret_scan_bytes: d_partial_secret_scan_bytes,
    prefilter_prefix_expansion_limit: d_prefilter_prefix_expansion_limit,
    ansi_incomplete_max_bytes: d_ansi_incomplete_max_bytes,
    wait_for_pattern_max_timeout_secs: d_wait_for_pattern_max_timeout_secs,
    file_transfer_chunk_bytes: d_file_transfer_chunk_bytes,
    file_transfer_max_bytes: d_file_transfer_max_bytes,
    command_history_max_entries: d_command_history_max_entries,
});

table_default!(TerminalConfig {
    screen_tracking_default: d_screen_tracking_default,
    screen_tracking_idle_disable_secs: d_screen_tracking_idle_disable_secs,
    terminal_queries: d_terminal_queries,
    terminal_query_replies_per_min: d_terminal_query_replies_per_min,
    shell_integration: d_shell_integration,
});

table_default!(PromptsConfig {
    settle_threshold_ms: d_settle_threshold_ms,
    cursor_prompt_chars: d_cursor_prompt_chars,
    cursor_stable_samples: d_cursor_stable_samples,
}; extra_patterns);

table_default!(SecurityConfig {
    redaction_enabled: d_redaction_enabled,
    secret_provider: d_secret_provider,
    autofill_on_echo_off: d_autofill_on_echo_off,
    strict_confirmation: d_strict_confirmation,
}; extra_redaction_patterns, secret_bindings);

table_default!(UiConfig {
    ui_bridge_pinned_port: d_ui_bridge_pinned_port,
    ui_token_idle_ttl_secs: d_ui_token_idle_ttl_secs,
    ui_token_absolute_ttl_secs: d_ui_token_absolute_ttl_secs,
    max_bridge_sessions: d_max_bridge_sessions,
});

table_default!(NotificationsConfig {
    sink: d_sink,
    events: d_events,
    notification_rate_limit_per_min: d_notification_rate_limit_per_min,
}; webhook_url, command);

table_default!(DaemonConfig {
    idle_shutdown_after_secs: d_idle_shutdown_after_secs,
    record_all_sessions: d_record_all_sessions,
    binding_approval_timeout_secs: d_binding_approval_timeout_secs,
    audit_retention_days: d_audit_retention_days,
    daemon_log_retention_weeks: d_daemon_log_retention_weeks,
});

// ----------------------------------------------------------- validation

impl Config {
    /// Semantic validation, run at load and therefore **before**
    /// `bind_control` (REQ-CFG-003). A daemon that starts with a bad
    /// config and logs a warning is the failure mode this exists to
    /// prevent: the operator believes a limit is in force and it is not.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        // Zero is legal in exactly two places in this file, and both are
        // documented "disable" values: `[limits] default_idle_timeout_secs`
        // (REQ-S-004) and `[daemon] idle_shutdown_after_secs` (§7.3).
        // A blanket `> 0` validator makes two documented capabilities
        // unreachable. `[ui] ui_bridge_pinned_port = 0` is a third zero,
        // but it is a port rather than a cap and §10.2's own comment
        // spells it as the default.
        nonzero("limits.max_concurrent_sessions", l.max_concurrent_sessions)?;
        nonzero("limits.output_buffer_bytes", l.output_buffer_bytes)?;
        nonzero(
            "limits.read_output_default_max_bytes",
            l.read_output_default_max_bytes,
        )?;
        nonzero(
            "limits.read_output_hard_max_bytes",
            l.read_output_hard_max_bytes,
        )?;
        nonzero("limits.resource_read_max_bytes", l.resource_read_max_bytes)?;
        nonzero(
            "limits.output_broadcast_capacity",
            l.output_broadcast_capacity,
        )?;
        nonzero(
            "limits.max_outstanding_secret_requests_per_session",
            l.max_outstanding_secret_requests_per_session as usize,
        )?;
        nonzero(
            "limits.redaction_lookahead_bytes",
            l.redaction_lookahead_bytes,
        )?;
        nonzero(
            "limits.partial_secret_scan_bytes",
            l.partial_secret_scan_bytes,
        )?;
        nonzero(
            "limits.prefilter_prefix_expansion_limit",
            l.prefilter_prefix_expansion_limit,
        )?;
        nonzero(
            "limits.ansi_incomplete_max_bytes",
            l.ansi_incomplete_max_bytes,
        )?;
        nonzero(
            "limits.wait_for_pattern_max_timeout_secs",
            l.wait_for_pattern_max_timeout_secs as usize,
        )?;
        nonzero(
            "limits.file_transfer_chunk_bytes",
            l.file_transfer_chunk_bytes,
        )?;
        nonzero(
            "limits.file_transfer_max_bytes",
            l.file_transfer_max_bytes as usize,
        )?;
        nonzero(
            "limits.command_history_max_entries",
            l.command_history_max_entries,
        )?;

        if l.read_output_default_max_bytes > l.read_output_hard_max_bytes {
            return Err(ConfigError::Invalid(format!(
                "limits.read_output_default_max_bytes = {} exceeds \
                 limits.read_output_hard_max_bytes = {}",
                l.read_output_default_max_bytes, l.read_output_hard_max_bytes
            )));
        }

        // `PatternSet::build` enforces this too, as a
        // `ClaspError::InvalidPattern` from another layer. Validated here
        // as well, with the count in the message, so an over-long list is
        // a named config fault rather than an error the operator has to
        // trace back to a key.
        if self.prompts.extra_patterns.len() > MAX_EXTRA_PATTERNS {
            return Err(ConfigError::Invalid(format!(
                "prompts.extra_patterns has {} entries; at most {MAX_EXTRA_PATTERNS} are accepted",
                self.prompts.extra_patterns.len()
            )));
        }
        nonzero(
            "prompts.cursor_stable_samples",
            self.prompts.cursor_stable_samples as usize,
        )?;
        nonzero(
            "prompts.settle_threshold_ms",
            self.prompts.settle_threshold_ms as usize,
        )?;

        one_of(
            "terminal.screen_tracking_default",
            &self.terminal.screen_tracking_default,
            &SCREEN_TRACKING_MODES,
        )?;
        nonzero(
            "terminal.terminal_query_replies_per_min",
            self.terminal.terminal_query_replies_per_min as usize,
        )?;
        nonzero(
            "terminal.screen_tracking_idle_disable_secs",
            self.terminal.screen_tracking_idle_disable_secs as usize,
        )?;

        one_of(
            "security.secret_provider",
            &self.security.secret_provider,
            &SECRET_PROVIDERS,
        )?;

        nonzero(
            "ui.ui_token_idle_ttl_secs",
            self.ui.ui_token_idle_ttl_secs as usize,
        )?;
        nonzero(
            "ui.ui_token_absolute_ttl_secs",
            self.ui.ui_token_absolute_ttl_secs as usize,
        )?;
        nonzero("ui.max_bridge_sessions", self.ui.max_bridge_sessions)?;

        one_of(
            "notifications.sink",
            &self.notifications.sink,
            &NOTIFICATION_SINKS,
        )?;
        let known: BTreeSet<&str> = NOTIFICATION_EVENT_KINDS.iter().copied().collect();
        for kind in &self.notifications.events {
            if !known.contains(kind.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "notifications.events contains `{kind}`, which is not one of {}",
                    NOTIFICATION_EVENT_KINDS.join(", ")
                )));
            }
        }
        nonzero(
            "notifications.notification_rate_limit_per_min",
            self.notifications.notification_rate_limit_per_min as usize,
        )?;

        nonzero(
            "daemon.binding_approval_timeout_secs",
            self.daemon.binding_approval_timeout_secs as usize,
        )?;
        nonzero(
            "daemon.audit_retention_days",
            self.daemon.audit_retention_days as usize,
        )?;
        nonzero(
            "daemon.daemon_log_retention_weeks",
            self.daemon.daemon_log_retention_weeks as usize,
        )?;

        for adapter in &self.adapters {
            if adapter.name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "adapters[].name must not be empty".into(),
                ));
            }
        }
        for binding in &self.security.secret_bindings {
            if binding.name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "security.secret_bindings[].name must not be empty".into(),
                ));
            }
        }
        Ok(())
    }

    /// The redaction rule set this config puts in force (§9.2).
    ///
    /// Today it is exactly [`RuleSet::builtin`]:
    /// `security.extra_redaction_patterns` is parsed, validated and
    /// **not** in it, because §15.1 has not settled the `ExtraRule` →
    /// `RuleSpec` mapping (see that field's own doc for why guessing is
    /// worse than stopping).
    ///
    /// **This function is the seam that stop is written on.** It exists
    /// so there is one named place a config-derived rule set is built,
    /// rather than a `RuleSet::builtin()` call scattered at each
    /// construction site: the milestone that resolves §15.1 replaces
    /// this body with a `builtin_with_extra`-shaped call, and
    /// `a_user_redaction_pattern_is_accepted_and_not_yet_in_force`
    /// reddens on the same commit — which is the point. That test also
    /// watches the rule set `ClaspServer` actually hands the read path,
    /// so wiring the key anywhere else reddens it too.
    pub fn redaction_rules(
        &self,
    ) -> Result<crate::output::rules::RuleSet, crate::output::rules::RuleError> {
        crate::output::rules::RuleSet::builtin()
    }

    /// The four §4.2 knobs `OutputProcessor` already takes as parameters.
    pub fn processing_limits(&self) -> crate::output::ProcessingLimits {
        crate::output::ProcessingLimits {
            lookbehind_bytes: self.limits.redaction_lookbehind_bytes,
            lookahead_bytes: self.limits.redaction_lookahead_bytes,
            partial_secret_scan_bytes: self.limits.partial_secret_scan_bytes,
            ansi_incomplete_max_bytes: self.limits.ansi_incomplete_max_bytes,
        }
    }
}

fn nonzero(key: &str, value: usize) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::Invalid(format!(
            "{key} = 0, but zero is meaningless for this limit"
        )));
    }
    Ok(())
}

fn one_of(key: &str, value: &str, allowed: &[&str]) -> Result<(), ConfigError> {
    if !allowed.contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{key} = \"{value}\", which is not one of {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::rules::RuleSet;

    /// §10.2's example, byte-for-byte, vendored into the test binary.
    /// The file on disk is the artifact an operator would copy; this is
    /// the same bytes so the assertion runs without a path lookup.
    const EXAMPLE: &str = include_str!("../tests/fixtures/example_config.toml");

    fn without_line(src: &str, needle: &str) -> String {
        src.lines()
            .filter(|l| !l.contains(needle))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Insert `line` immediately after the `[table]` header.
    fn with_key_under(src: &str, table: &str, line: &str) -> String {
        let mut out = Vec::new();
        let mut done = false;
        for l in src.lines() {
            out.push(l.to_string());
            if !done && l.trim() == table {
                out.push(line.to_string());
                done = true;
            }
        }
        assert!(done, "fixture has no `{table}` header");
        out.join("\n")
    }

    #[test]
    fn an_absent_config_file_is_not_an_error() {
        let missing = std::path::Path::new("/nonexistent/clasp-does-not-exist/config.toml");
        let cfg = load_from(missing).expect("a missing config file is Config::default(), not Err");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn a_valid_config_overrides_only_the_keys_it_names() {
        let cfg = parse_str("[limits]\nmax_concurrent_sessions = 3\n").expect("loads");
        assert_eq!(cfg.limits.max_concurrent_sessions, 3);
        // At least two siblings must survive: folding a whole section
        // resets them and passes any single-knob assertion.
        assert_eq!(
            cfg.limits.output_buffer_bytes,
            d_output_buffer_bytes(),
            "a sibling in the same table was reset — the fold is per struct, not per field"
        );
        assert_eq!(
            cfg.limits.read_output_hard_max_bytes,
            d_read_output_hard_max_bytes()
        );
        // And a sibling *table* must survive too.
        assert_eq!(cfg.daemon.audit_retention_days, d_audit_retention_days());
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_ignored() {
        let e = parse_str("[limits]\nmax_concurent_sessions = 4\n")
            .expect_err("a typo'd knob that silently does nothing is indistinguishable from one that does not work");
        let msg = e.to_string();
        assert!(
            msg.contains("max_concurent_sessions"),
            "the error must name the key; got: {msg}"
        );
    }

    #[test]
    fn an_unknown_table_is_rejected_too() {
        let e = parse_str("[limmits]\nmax_concurrent_sessions = 4\n").expect_err(
            "deny_unknown_fields applies at the top level as well as inside each table",
        );
        assert!(e.to_string().contains("limmits"), "{e}");
    }

    #[test]
    fn the_published_example_config_loads() {
        // Two assertions, deliberately separate: a fixture that is not
        // valid TOML fails for a reason that has nothing to do with the
        // loader, and reading that failure as a loader bug is how a stale
        // copy of §10.2 takes a test down with it.
        let tables: toml::Table =
            toml::from_str(EXAMPLE).expect("tests/fixtures/example_config.toml is not valid TOML");
        assert_eq!(tables.len(), 7, "§10.2's table count moved");
        let per_table: Vec<(String, usize)> = tables
            .iter()
            .map(|(k, v)| (k.clone(), v.as_table().map(|t| t.len()).unwrap_or(0)))
            .collect();
        let total: usize = per_table.iter().map(|(_, n)| n).sum();
        assert_eq!(
            total, 43,
            "§10.2's key count moved; per-table: {per_table:?}"
        );
        // The breakdown, never the sum: 43 was also the pre-rev-48 total
        // across *eight* tables, so a check against the total agrees with
        // two revisions of §10.2 while being wrong against both.
        for (table, want) in [
            ("limits", 17),
            ("terminal", 5),
            ("prompts", 4),
            ("security", 5),
            ("ui", 4),
            ("notifications", 3),
            ("daemon", 5),
        ] {
            let got = tables
                .get(table)
                .and_then(|v| v.as_table())
                .map(|t| t.len())
                .unwrap_or_else(|| panic!("§10.2 lost its [{table}] table"));
            assert_eq!(got, want, "[{table}] has {got} keys, expected {want}");
        }

        parse_str(EXAMPLE).expect("§10.2's published example must load as a Config");
    }

    // `the_fixture_on_disk_is_the_one_the_tests_compile_in` stood here
    // and is deleted. It read
    // `$CARGO_MANIFEST_DIR/tests/fixtures/example_config.toml` and
    // compared it to `EXAMPLE` — the `include_str!` of *that same path*,
    // so it compared the file to itself and could not fail. The
    // "vendored copy" its message named does not exist: there is one
    // fixture in the tree, and Cargo's dep-info tracks `include_str!`,
    // so a stale-build divergence is not reachable either.
    // `the_published_example_config_loads` is the guard over that file.

    #[test]
    fn an_adapters_array_of_tables_is_accepted() {
        let src = "\
[[adapters]]
name = \"myapp\"
match_command = \"^myapp$\"
notes = \"an example\"
prompt_patterns = [ { regex = \"myapp> $\", score = 0.9, kind = \"prompt\" } ]
";
        let cfg = parse_str(src).expect("§5.8.2's array-of-tables shape must load");
        assert_eq!(cfg.adapters.len(), 1);
        assert_eq!(cfg.adapters[0].name, "myapp");
        assert_eq!(cfg.adapters[0].prompt_patterns.len(), 1);
        assert_eq!(
            cfg.adapters[0].prompt_patterns[0].kind.as_deref(),
            Some("prompt"),
            "`kind` is optional but must be carried when supplied"
        );
        // A `kind`-free entry must also load: §10.2's commented example
        // drops it and §5.8.2 carries it, so both shapes are real.
        let no_kind = parse_str(
            "[[adapters]]\nname = \"a\"\nmatch_command = \"^a$\"\nprompt_patterns = [ { regex = \"a> $\", score = 0.5 } ]\n",
        )
        .expect("a kind-free adapter pattern must load");
        assert!(no_kind.adapters[0].prompt_patterns[0].kind.is_none());

        // The pairing: the *table* spelling is what must be rejected.
        let e = parse_str("[adapters]\nname = \"myapp\"\n")
            .expect_err("`[adapters]` as a table is the spelling §5.8.2 forbids");
        assert!(e.to_string().contains("adapters"), "{e}");
    }

    #[test]
    fn a_secret_bindings_array_is_accepted() {
        let src = "\
[[security.secret_bindings]]
name = \"prod-ssh\"
match_command = \"^ssh\\\\s+(\\\\S+@)?prod-0[12]\\\\b\"
match_prompt = \"(?i)password\"
provider = \"secret-service\"
reference = \"service=clasp,account=prod-ssh\"
max_uses = 20
require_confirm = false
";
        let cfg = parse_str(src).expect("§9.6's binding block must load");
        assert_eq!(cfg.security.secret_bindings.len(), 1);
        let b = &cfg.security.secret_bindings[0];
        assert_eq!(b.name, "prod-ssh");
        assert_eq!(b.provider, "secret-service");
        assert_eq!(b.max_uses, Some(20));
        assert!(!b.require_confirm);
        // Nothing reads any of the seven in 0.0.5 — that is 0.0.7's — so
        // the assertion here is that they *parse*, not that they act.
    }

    #[test]
    fn a_config_carrying_http_socket_path_is_rejected() {
        let src = with_key_under(
            EXAMPLE,
            "[ui]",
            "http_socket_path = \"/tmp/elsewhere.sock\"",
        );
        let e = parse_str(&src).expect_err("a withdrawn knob is rejected, not ignored");
        assert!(
            e.to_string().contains("http_socket_path"),
            "the error must name the key; got: {e}"
        );
    }

    #[test]
    fn a_config_carrying_log_dir_is_rejected() {
        let src = with_key_under(EXAMPLE, "[daemon]", "log_dir = \"/tmp/somewhere-else\"");
        let e = parse_str(&src).expect_err("a withdrawn knob is rejected, not ignored");
        assert!(
            e.to_string().contains("log_dir"),
            "the error must name the key; got: {e}"
        );
        // In the same test: a rejection must not be mistaken for a
        // relocation. `RuntimePaths` is the only source of the log
        // directory, and nothing in this module can move it.
        let paths = crate::daemon::RuntimePaths::with_dir("/tmp/clasp-config-log-dir-probe");
        assert_eq!(
            paths.log_dir(),
            std::path::Path::new("/tmp/clasp-config-log-dir-probe/logs"),
            "RuntimePaths::log_dir() answered to a config key"
        );
    }

    #[test]
    fn a_config_carrying_dangerous_commands_enabled_is_rejected() {
        // `false`, not `true`: `true` was the withdrawn default, so an
        // accept-and-ignore loader and a correct one are
        // indistinguishable on it. `false` is the value an operator
        // writes when they mean to switch the preflight off, and it is
        // the value whose silent acceptance is the harm.
        let src = with_key_under(EXAMPLE, "[security]", "dangerous_commands_enabled = false");
        let e = parse_str(&src).expect_err("there is no preflight kill switch");
        assert!(
            e.to_string().contains("dangerous_commands_enabled"),
            "the error must name the key; got: {e}"
        );
    }

    #[test]
    fn the_same_fixture_without_that_key_loads() {
        // One arm per withdrawn key. Without these, a loader that
        // rejects every `[ui]` table, or every `[security]` table, or
        // every config, passes all three rejection rows perfectly.
        for (table, line, needle) in [
            (
                "[ui]",
                "http_socket_path = \"/tmp/elsewhere.sock\"",
                "http_socket_path",
            ),
            ("[daemon]", "log_dir = \"/tmp/somewhere-else\"", "log_dir"),
            (
                "[security]",
                "dangerous_commands_enabled = false",
                "dangerous_commands_enabled",
            ),
        ] {
            let with = with_key_under(EXAMPLE, table, line);
            parse_str(&with).expect_err("the rejection arm");
            let without = without_line(&with, needle);
            parse_str(&without).unwrap_or_else(|e| {
                panic!("byte-identical fixture minus `{needle}` must load; got: {e}")
            });
        }
    }

    #[test]
    fn the_bridge_and_notification_caps_carry_their_4_2_defaults() {
        let d = Config::default();
        assert_eq!(d.ui.max_bridge_sessions, 16);
        assert_eq!(d.notifications.notification_rate_limit_per_min, 10);
        // Paired with an override, because a default-only assertion
        // passes against a consumer that hardcodes the number and never
        // reads the file.
        let cfg = parse_str(
            "[ui]\nmax_bridge_sessions = 4\n\n[notifications]\nnotification_rate_limit_per_min = 99\n",
        )
        .expect("loads");
        assert_eq!(cfg.ui.max_bridge_sessions, 4);
        assert_eq!(cfg.notifications.notification_rate_limit_per_min, 99);
    }

    #[test]
    fn the_notification_event_default_is_all_six_kinds() {
        // As a *sequence*: a set comparison would pass against a
        // reordering §5.8.3 fixes, and an omitted kind is a suppressed
        // one — a short default silently disables `coalesced`, which is
        // the rate limiter's own overflow summary.
        assert_eq!(
            Config::default().notifications.events,
            vec![
                "session_exited",
                "awaiting_secret",
                "awaiting_confirmation",
                "session_reaped",
                "transfer_complete",
                "coalesced",
            ]
        );
    }

    #[test]
    fn the_terminal_query_knobs_are_read_from_the_file() {
        let d = Config::default();
        assert!(d.terminal.terminal_queries);
        assert_eq!(d.terminal.terminal_query_replies_per_min, 60);
        let cfg = parse_str("[terminal]\nterminal_queries = false\nterminal_query_replies_per_min = 5\n")
            .expect("rev. 48 uncommented both keys; a loader modelling only three [terminal] keys refuses the published example");
        assert!(!cfg.terminal.terminal_queries);
        assert_eq!(cfg.terminal.terminal_query_replies_per_min, 5);
    }

    #[test]
    fn the_reserved_knobs_are_accepted_and_left_unread() {
        let cfg = parse_str(
            "[limits]\nmax_outstanding_secret_requests_per_session = 4\n\n[daemon]\nrecord_all_sessions = true\n",
        )
        .expect("§10.2 publishes both; rejecting one is REQ-CFG-004's second clause inverted");
        assert_eq!(cfg.limits.max_outstanding_secret_requests_per_session, 4);
        assert!(cfg.daemon.record_all_sessions);
        // And 0.0.5's behaviour is unchanged by either: the concurrency
        // limit is still `max_concurrent_sessions`, not the secret knob.
        assert_eq!(
            cfg.limits.max_concurrent_sessions,
            d_max_concurrent_sessions(),
            "a reserved knob changed a limit that governs"
        );
    }

    #[test]
    fn idle_timeout_zero_is_accepted_because_zero_means_disabled() {
        let cfg = parse_str("[limits]\ndefault_idle_timeout_secs = 0\n")
            .expect("`0` disables reaping for a session (REQ-S-004); a blanket non-zero rule makes a documented capability unreachable");
        assert_eq!(cfg.limits.default_idle_timeout_secs, 0);
    }

    #[test]
    fn idle_shutdown_after_secs_zero_is_accepted_because_zero_means_disabled() {
        let cfg = parse_str("[daemon]\nidle_shutdown_after_secs = 0\n")
            .expect("`0` disables the client-less daemon exit (§7.3)");
        assert_eq!(cfg.daemon.idle_shutdown_after_secs, 0);
    }

    #[test]
    fn a_zero_cap_that_means_nothing_is_rejected_and_the_message_names_it() {
        let e = parse_str("[limits]\nmax_concurrent_sessions = 0\n")
            .expect_err("zero concurrent sessions is a daemon that can do nothing");
        let msg = e.to_string();
        assert!(msg.contains("max_concurrent_sessions"), "{msg}");
        assert!(msg.contains('0'), "the message names the value too: {msg}");
    }

    #[test]
    fn an_over_long_extra_patterns_list_is_a_named_config_fault() {
        let mut src = String::from("[prompts]\nextra_patterns = [\n");
        for i in 0..(MAX_EXTRA_PATTERNS + 1) {
            src.push_str(&format!("  {{ regex = 'p{i}$', score = 0.5 }},\n"));
        }
        src.push_str("]\n");
        let e = parse_str(&src).expect_err("65 patterns is one over MAX_EXTRA_PATTERNS");
        let msg = e.to_string();
        assert!(msg.contains("extra_patterns"), "{msg}");
        assert!(
            msg.contains(&MAX_EXTRA_PATTERNS.to_string()),
            "the count belongs in the message so the operator can act: {msg}"
        );
        // The pairing: exactly MAX_EXTRA_PATTERNS must still load, or
        // this row passes against a validator that rejects any list.
        let mut ok = String::from("[prompts]\nextra_patterns = [\n");
        for i in 0..MAX_EXTRA_PATTERNS {
            ok.push_str(&format!("  {{ regex = 'p{i}$', score = 0.5 }},\n"));
        }
        ok.push_str("]\n");
        parse_str(&ok).expect("exactly MAX_EXTRA_PATTERNS must load");
    }

    #[test]
    fn extra_patterns_deserialise_into_the_type_start_session_already_uses() {
        let cfg = parse_str(
            "[prompts]\nextra_patterns = [ { regex = '\\(myapp\\)\\s*$', score = 0.9 } ]\n",
        )
        .expect("loads");
        assert_eq!(
            cfg.prompts.extra_patterns,
            vec![PromptPattern {
                regex: r"\(myapp\)\s*$".to_string(),
                score: 0.9,
            }],
            "the config and `start_session(prompt_patterns:)` must land on one type"
        );
    }

    #[test]
    fn a_user_redaction_pattern_is_accepted_and_not_yet_in_force() {
        // Step 4c's blocker, made visible. §15.1 has not settled whether
        // a user rule must supply `positive`/`negative`, whether the
        // field is `regex` or `pattern`, and whether
        // `builtin_with_extra` gains a struct-taking sibling — so this
        // loader parses the key and passes it to no `RuleSet`.
        //
        // This test is deliberately ugly to have to write. It is the
        // honest shape of a stopped seam, and its name is as much the
        // deliverable as its assertion.
        let cfg = parse_str(
            "[security]\nextra_redaction_patterns = [ { name = \"internal-token\", kind = \"internal-token\", regex = 'INT_[A-Z0-9]{32}' } ]\n",
        )
        .expect("§10.2's own example rule must load");
        assert_eq!(cfg.security.extra_redaction_patterns.len(), 1);

        // Both rule sets below are derived **from `cfg`**. The earlier
        // version of this test read `RuleSet::builtin()` into a local
        // named `active` and compared it to `RuleSet::builtin()` — a
        // tautology, which meant the tripwire this test exists to be
        // stayed green whether or not a later milestone wired the key.
        //
        // Two observations rather than one, because there are two places
        // the wiring can land and a tripwire watching only one of them is
        // one the wiring steps over:
        //
        //  1. `Config::redaction_rules()`, the accessor this file names
        //     as the seam. A milestone that resolves §15.1 by making the
        //     config build its own set edits *that function*.
        //  2. the set the read path actually runs with, taken from the
        //     server this `cfg` builds. A milestone that instead wires
        //     the key where `ClaspServer` assembles its
        //     `OutputProcessor` never touches `redaction_rules()`, and
        //     only this second observation catches it.
        let from_config = cfg.redaction_rules().expect("built-in rules compile");
        let server = crate::mcp::ClaspServer::with_audit_path_and_config(None, &cfg);

        let builtin = RuleSet::builtin().expect("built-in rules compile");
        for (what, active) in [
            ("Config::redaction_rules()", &from_config),
            (
                "the OutputProcessor the read path runs with",
                &*server.processor.rules,
            ),
        ] {
            assert_eq!(
                active.len(),
                builtin.len(),
                "{what} carries {} rules against the built-in set's {} — §15.1 \
                 settled and the key is in force. This test is the record of why \
                 it was left unwired; read it before deleting it.",
                active.len(),
                builtin.len()
            );
            // Length alone would pass against a wiring that *replaced* a
            // built-in of the same name, so name the rule too. (It is
            // absent from `data/redaction_default.toml`, which is what
            // makes its presence mean "the config's rule arrived".)
            assert!(
                !active.rules.iter().any(|r| r.name == "internal-token"),
                "the config's rule reached {what} — §15.1 is still open, so this \
                 is the guess this step declines to make"
            );
        }
    }

    #[test]
    fn an_invalid_enum_value_names_the_key_and_the_allowed_set() {
        let e = parse_str("[notifications]\nsink = \"carrier-pigeon\"\n").expect_err("closed set");
        let msg = e.to_string();
        assert!(msg.contains("notifications.sink"), "{msg}");
        assert!(msg.contains("carrier-pigeon"), "{msg}");
        assert!(
            msg.contains("desktop"),
            "the allowed set belongs in the message: {msg}"
        );
        parse_str("[notifications]\nsink = \"desktop\"\n").expect("a real sink loads");
    }

    #[test]
    fn config_discovery_prefers_xdg_config_home_over_home() {
        assert_eq!(
            config_path_from(Some("/x".into()), Some("/h".into())),
            Some(PathBuf::from("/x/clasp/config.toml"))
        );
        assert_eq!(
            config_path_from(None, Some("/h".into())),
            Some(PathBuf::from("/h/.config/clasp/config.toml")),
        );
        // An empty XDG_CONFIG_HOME is no instruction, not an empty base.
        assert_eq!(
            config_path_from(Some("".into()), Some("/h".into())),
            Some(PathBuf::from("/h/.config/clasp/config.toml")),
        );
        assert_eq!(config_path_from(None, None), None);
    }

    #[test]
    fn config_discovery_ignores_the_runtime_dir_variable() {
        // REQ-CFG-005 makes `CLASP_RUNTIME_DIR` instance selection, not
        // a configuration knob. Wiring config discovery to it would
        // recreate exactly the override REQ-CFG-001 forbids.
        let derived = config_path_from(Some("/x".into()), Some("/h".into())).unwrap();
        assert!(
            !derived.to_string_lossy().contains("runtime"),
            "config discovery must not read CLASP_RUNTIME_DIR"
        );
    }

    #[test]
    fn the_processing_limits_come_from_the_file() {
        let cfg = parse_str(
            "[limits]\nredaction_lookbehind_bytes = 7\nredaction_lookahead_bytes = 11\npartial_secret_scan_bytes = 13\nansi_incomplete_max_bytes = 17\n",
        )
        .expect("loads");
        let l = cfg.processing_limits();
        assert_eq!(l.lookbehind_bytes, 7);
        assert_eq!(l.lookahead_bytes, 11);
        assert_eq!(l.partial_secret_scan_bytes, 13);
        assert_eq!(l.ansi_incomplete_max_bytes, 17);
        // Paired with the default, so a `processing_limits()` that
        // ignored the file and returned `Default::default()` is red
        // above rather than green here.
        assert_eq!(
            Config::default().processing_limits().lookbehind_bytes,
            crate::output::ProcessingLimits::default().lookbehind_bytes
        );
    }
}
