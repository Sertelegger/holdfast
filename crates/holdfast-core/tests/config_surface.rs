//! Every key in `config.toml` is classified **effective** or **inert**, and
//! the enumeration is derived from the structs rather than written down
//! (GH #128).
//!
//! ## What this file is for
//!
//! GH #128 is not "these four keys are broken". It is *"accepted
//! configuration does not reliably describe effective behaviour"* — an
//! operator reads their own file and gets a false account of what the
//! daemon does. Every key in that issue passed the schema test and the
//! load test. What none of them had was a test that made somebody
//! **decide**, in the tree, whether the value reaches the runtime.
//!
//! So this file asserts one thing: **every key is in exactly one of the
//! two tables below.** A key in neither fails the test with a message
//! telling the author to classify it. Adding a knob without deciding
//! its status is a build-gate failure, not a silent pass.
//!
//! It deliberately does **not** assert that the inert set is empty.
//! Shrinking it is the restructuring GH #128 asks for and this file is
//! the foundation under that work, not the work — but the tables move as
//! that lands, and moving one is a visible line in a diff, which is the
//! whole point.
//!
//! ## Why the enumeration is a serde walk and not a list
//!
//! A hand-written list of keys rots the moment somebody adds a field:
//! the new key is absent from the list, so the list agrees with itself
//! and the field is never classified. A walk over `Serialize` output
//! cannot miss a field the struct has. That is why [`config::Config`]
//! and friends carry `Serialize` — it is derived for this test, and it
//! is the only mechanical enumeration of the surface that exists.
//!
//! ## Two kinds of blindness the walk has, and what covers each
//!
//! 1. **An empty collection hides its element keys.** `Config::default()`
//!    has `profiles: []`, so it can never show `security.profiles[].program`.
//!    Covered by [`populated`], whose collections are all non-empty, and
//!    by [`no_container_in_the_exemplar_is_empty`], which fails if a new
//!    collection is left empty there. That check is what stops the
//!    exemplar from rotting the way a hand-written list would.
//! 2. **A free-form map's keys are the operator's, not the schema's.**
//!    `[security.profiles.vars]` holds slot names somebody chose. Those
//!    are values, not keys, so the walk stops at the map. The three such
//!    fields are named in [`FREE_FORM`] and nowhere else.
//!
//! ## What "effective" and "inert" mean here
//!
//! **Effective**: some runtime path reads the value out of a *loaded*
//! `Config` and it changes what the daemon does. Both entry points that
//! build one are real —
//! `crates/holdfast-core/src/daemon/server.rs:1415` and
//! `crates/holdfast-core/src/mcp/mod.rs:664` both call `config::load()` —
//! so a read off `HoldfastServer::config` is a read of the operator's
//! file.
//!
//! **Inert**: nothing outside the definition, the `Default` impl,
//! `Config::validate`, §10.2's published fixture and the tests reads it.
//!
//! **Load-time validation alone is not consumption**, and that is the
//! line most likely to be argued with, so it is stated: a key that
//! `Config::validate` range-checks and that nothing then reads is
//! **inert**. `prompts.settle_threshold_ms` is the case that shows why —
//! a zero is refused at startup while every non-zero value is ignored,
//! which is the most misleading surface an operator can be given. Those
//! entries say `VALIDATE-ONLY` in their evidence.
//!
//! ## The tables have teeth, and exactly this much
//!
//! A table-driven test that passes whatever the tables say is worse than
//! no test. Three checks make these tables falsifiable:
//!
//! - An **effective** entry must cite a `path:line` that exists, and at
//!   least one citation must be outside `config.rs` — a consumer inside
//!   `config.rs` is validation, not runtime.
//! - An **inert** entry marked [`Inert::NeverNamed`] is checked against
//!   the source tree: no non-comment line under `crates/*/src`, outside
//!   `config.rs`, may write the field's identifier. Wire a consumer for
//!   one of those keys and this test goes red until it is reclassified.
//! - [`Inert::NamedElsewhere`] is the honest escape hatch for an
//!   identifier that appears for unrelated reasons (`sink` is the audit
//!   log's file handle; `command` is everywhere). Those entries are
//!   prose-checked, and the note says by what argument.
//!
//! Plus one behavioural probe,
//! [`every_key_the_processing_limits_seam_carries_is_classified_effective`],
//! which exists because a mutation test walked straight past all three:
//! a key consumed under a *different* name downstream is invisible to an
//! identifier scan, and `[limits]` has exactly one such seam.
//!
//! The residual weakness, stated rather than left to be discovered:
//! moving an `Inert::NamedElsewhere` key from effective to inert is
//! **not** caught mechanically, and neither is downgrading an effective
//! key that no probe covers. `NeverNamed` covers 15 of the inert keys and
//! the probe covers four of the effective ones; the rest are prose, read
//! by a human, and rechecked by rerunning the greps the notes name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use holdfast_core::config::{
    AdapterPromptPattern, AdapterSpec, Config, LimitsConfig, NotificationsConfig, PromptsConfig,
    SecretBinding, SecurityConfig, SessionProfile,
};
use holdfast_core::detect::PromptPattern;
use serde_json::Value;

// ------------------------------------------------------------ enumeration

/// Flatten a serialised config into dotted key paths.
///
/// A struct table (`[limits]`) is not itself a key — it holds no value —
/// so objects recurse and only leaves are emitted. An array **is** a key
/// (an operator can write `events = [...]`), so it is emitted *and*, when
/// its elements are tables, descended into under a `[]` suffix. An empty
/// object is a free-form map with no schema below it, so it is a leaf.
///
/// A [`FREE_FORM`] path is a leaf whatever is inside it. That is not a
/// convenience: `[security.profiles.vars]`'s keys are slot names the
/// operator invented, so descending would enumerate one exemplar's
/// choices as though they were schema. This test found that out the
/// direct way — the first run demanded a classification for
/// `security.profiles[].vars.slot`.
fn flatten(prefix: &str, value: &Value, out: &mut BTreeSet<String>) {
    if FREE_FORM.contains(&prefix) {
        out.insert(prefix.to_string());
        return;
    }
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&path, child, out);
            }
        }
        Value::Array(items) => {
            out.insert(prefix.to_string());
            if let Some(first @ Value::Object(_)) = items.first() {
                flatten(&format!("{prefix}[]"), first, out);
            }
        }
        _ => {
            out.insert(prefix.to_string());
        }
    }
}

fn as_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("a config serialises")
}

/// A `Config` with every collection non-empty, so the walk reaches the
/// keys that live inside `[[security.profiles]]` and friends.
///
/// **The values are nonsense on purpose.** Nothing here is asserted
/// against; the only property that matters is that each collection has an
/// element, so its element type's fields are visible to [`flatten`]. It
/// is checked for validity by [`the_exemplar_is_a_config_an_operator_could_write`]
/// so that the enumerated surface is a surface somebody can really write,
/// and for completeness by [`no_container_in_the_exemplar_is_empty`].
fn populated() -> Config {
    Config {
        prompts: PromptsConfig {
            extra_patterns: vec![PromptPattern {
                regex: "^enumerated: $".to_string(),
                score: 0.5,
            }],
            ..PromptsConfig::default()
        },
        security: SecurityConfig {
            // A rule the shipped set really has: `Config::validate`
            // refuses a name it does not, so an invented one here fails
            // `the_exemplar_is_a_config_an_operator_could_write` instead
            // of enumerating a key.
            disabled_redaction_rules: vec!["jwt".to_string()],
            profiles: vec![SessionProfile {
                name: "enumerated".to_string(),
                program: "true".to_string(),
                args: vec!["{slot}".to_string()],
                vars: BTreeMap::from([("slot".to_string(), "^ok$".to_string())]),
                env: BTreeMap::new(),
                cwd: None,
            }],
            secret_bindings: vec![SecretBinding {
                name: "enumerated".to_string(),
                profile: "enumerated".to_string(),
                match_prompt: String::new(),
                provider: "keychain".to_string(),
                reference: "enumerated".to_string(),
                max_uses: Some(1),
                require_confirm: true,
            }],
            ..SecurityConfig::default()
        },
        notifications: NotificationsConfig {
            webhook_url: Some("https://example.invalid/hook".to_string()),
            command: Some(vec!["true".to_string()]),
            ..NotificationsConfig::default()
        },
        adapters: vec![AdapterSpec {
            name: "enumerated".to_string(),
            match_command: "^true$".to_string(),
            prompt_patterns: vec![AdapterPromptPattern {
                regex: "^enumerated: $".to_string(),
                score: 0.5,
                kind: Some("password".to_string()),
            }],
            notes: Some("enumerated".to_string()),
        }],
        ..Config::default()
    }
}

/// Every dotted key the schema has.
///
/// The union of two walks. `Config::default()` contributes the empty
/// collections as leaves — `security.profiles` is a key in its own right,
/// and "is the list read at all" is a different question from "is
/// `program` read" — and [`populated`] contributes what is inside them.
fn surface() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    flatten("", &as_json(&Config::default()), &mut out);
    flatten("", &as_json(&populated()), &mut out);
    out
}

/// Collections whose contents are the operator's names rather than the
/// schema's keys, so the walk stops at the collection itself.
///
/// `extra_redaction_patterns` is here for a second reason worth keeping
/// visible: its element shape is the §15.1 open question GH #128 calls
/// *"the serious one"*. There is no element schema to enumerate because
/// nobody has decided on one.
const FREE_FORM: &[&str] = &[
    "security.extra_redaction_patterns",
    "security.profiles[].vars",
    "security.profiles[].env",
];

// ------------------------------------------------------------- the tables

/// Keys whose value reaches the runtime and changes what the daemon does.
///
/// The evidence names the consumer as `path:line`. At least one citation
/// must be outside `config.rs`, because a read inside `config.rs` is
/// `validate` or the `processing_limits` seam and neither is a consumer
/// on its own.
const EFFECTIVE: &[(&str, &str)] = &[
    // ---- [limits]
    (
        "limits.max_concurrent_sessions",
        "crates/holdfast-core/src/mcp/mod.rs:381 — SessionRegistry::new(config.limits.max_concurrent_sessions).",
    ),
    (
        "limits.default_idle_timeout_secs",
        "crates/holdfast-core/src/mcp/tools.rs:393 — start_session falls back to it when the call omits idle_timeout_secs; reaches SessionConfig at tools.rs:416.",
    ),
    (
        "limits.resource_read_max_bytes",
        "crates/holdfast-core/src/mcp/mod.rs:628 (MCP resources/read) and crates/holdfast-core/src/daemon/server.rs:2231 (control protocol) — both pass it as read_resource's ceiling.",
    ),
    (
        "limits.redaction_lookbehind_bytes",
        "Renamed at the seam: crates/holdfast-core/src/config.rs:1730 maps it to ProcessingLimits::lookbehind_bytes, read on the live path at crates/holdfast-core/src/output/mod.rs:564 and crates/holdfast-core/src/session/mod.rs:1986.",
    ),
    (
        "limits.redaction_lookahead_bytes",
        "Renamed at the seam: crates/holdfast-core/src/config.rs:1731 maps it to ProcessingLimits::lookahead_bytes, read at crates/holdfast-core/src/output/mod.rs:565 and crates/holdfast-core/src/session/mod.rs:1989.",
    ),
    (
        "limits.partial_secret_scan_bytes",
        "crates/holdfast-core/src/config.rs:1732 maps it onto ProcessingLimits; read at crates/holdfast-core/src/output/mod.rs:566 and crates/holdfast-core/src/session/mod.rs:1992.",
    ),
    (
        "limits.ansi_incomplete_max_bytes",
        "crates/holdfast-core/src/config.rs:1733 maps it onto ProcessingLimits; read at crates/holdfast-core/src/output/mod.rs:349, which holds back an unfinished trailing escape.",
    ),
    // ---- [security]
    (
        "security.disabled_redaction_rules",
        "crates/holdfast-core/src/config.rs:1688 hands it to RuleSet::builtin_without, and crates/holdfast-core/src/mcp/mod.rs:341 is where HoldfastServer takes that set for its OutputProcessor — so it changes what read_output, resources/read and every attached observer are served. crates/holdfast-core/src/mcp/tools.rs:438 hands the same Arc to each session's screen tracker (get_screen_state) and crates/holdfast-core/src/mcp/tools.rs:604 reports the resulting set in the §9.4 session_start row. Behaviourally probed through the tool surface by tests/integration.rs::a_disabled_redaction_rule_stops_redacting_and_its_neighbours_do_not.",
    ),
    (
        "security.secret_provider",
        "crates/holdfast-core/src/mcp/tools.rs:1911 gates request_secret_input's keychain step; crates/holdfast-core/src/secret/binding.rs:651 refuses autofill when it spells `prompt`.",
    ),
    (
        "security.autofill_on_echo_off",
        "crates/holdfast-core/src/mcp/tools.rs:2945 — the first line of watch_for_autofill returns early when it is false, so the echo-drop listener is armed or is not.",
    ),
    (
        "security.secret_bindings",
        "crates/holdfast-core/src/mcp/tools.rs:1912 (emptiness fast path) and crates/holdfast-core/src/secret/binding.rs:661 — the Vec is what select() searches.",
    ),
    (
        "security.secret_bindings[].name",
        "crates/holdfast-core/src/secret/binding.rs:755 — claim_binding_use keys the use counter on it; it is also the binding_resolved audit field at binding.rs:803.",
    ),
    (
        "security.secret_bindings[].profile",
        "crates/holdfast-core/src/secret/binding.rs:413 — the selection predicate compares it against the session's profile.",
    ),
    (
        "security.secret_bindings[].match_prompt",
        "crates/holdfast-core/src/secret/binding.rs:435 — matched against the prompt line when non-empty.",
    ),
    (
        "security.secret_bindings[].provider",
        "crates/holdfast-core/src/secret/provider.rs:440 — ArgvProvider::from_config chooses the credential-store subprocess from it.",
    ),
    (
        "security.secret_bindings[].reference",
        "crates/holdfast-core/src/secret/provider.rs:441 — the lookup key handed to the provider argv.",
    ),
    (
        "security.secret_bindings[].max_uses",
        "crates/holdfast-core/src/secret/binding.rs:755 — claim_binding_use bounds the count; exhaustion falls through at binding.rs:756.",
    ),
    (
        "security.secret_bindings[].require_confirm",
        "crates/holdfast-core/src/secret/binding.rs:667 — true routes through §17.5's BindingApprovalRequired instead of injecting silently.",
    ),
    (
        "security.profiles",
        "crates/holdfast-core/src/mcp/tools.rs:747 — start_session searches it for the named profile and refuses with invalid_params at tools.rs:737 on a miss.",
    ),
    (
        "security.profiles[].name",
        "crates/holdfast-core/src/mcp/tools.rs:752 — the lookup key; copied onto the session at tools.rs:762, which is what binding selection later compares.",
    ),
    (
        "security.profiles[].program",
        "crates/holdfast-core/src/mcp/tools.rs:768 — becomes Launch::command and then the binary PtySpawnConfig executes.",
    ),
    (
        "security.profiles[].args",
        "crates/holdfast-core/src/secret/profile.rs:446 — render() builds the child's argv from it; reaches the child at crates/holdfast-core/src/mcp/tools.rs:287.",
    ),
    (
        "security.profiles[].vars",
        "crates/holdfast-core/src/secret/profile.rs:433 — each pattern is compiled and matched whole against the agent's slot value; a mismatch refuses the session.",
    ),
    (
        "security.profiles[].env",
        "crates/holdfast-core/src/mcp/tools.rs:773 — becomes Launch::env and then the child's environment overrides at tools.rs:339.",
    ),
    (
        "security.profiles[].cwd",
        "crates/holdfast-core/src/mcp/tools.rs:778 — becomes Launch::cwd, canonicalised and applied to the child at tools.rs:308.",
    ),
    (
        "security.keychain_provider_timeout_secs",
        "crates/holdfast-core/src/secret/provider.rs:487 — the budget the provider subprocess is bounded by.",
    ),
    (
        "security.max_secret_bytes_ceiling",
        "crates/holdfast-core/src/mcp/tools.rs:1788 rejects a larger request_secret_input argument; crates/holdfast-core/src/attach/conn.rs:900 bounds an attach client's SecretInput submission.",
    ),
    (
        "security.secret_input_max_timeout_secs",
        "crates/holdfast-core/src/mcp/tools.rs:1767 — request_secret_input refuses a timeout_secs above it.",
    ),
    // ---- [daemon]
    (
        "daemon.idle_shutdown_after_secs",
        "crates/holdfast-core/src/daemon/server.rs:838 — client_less_exit_due reads it every reaper tick and shuts the daemon down.",
    ),
    (
        "daemon.binding_approval_timeout_secs",
        "crates/holdfast-core/src/mcp/tools.rs:2571 — run_binding_approval passes it to secret::approval_window, which sets the approval expiry.",
    ),
    (
        "daemon.audit_retention_days",
        "crates/holdfast-core/src/daemon/paths.rs:43 — LogRetention::from(&Config); the window is applied at paths.rs:1179 and swept from crates/holdfast-core/src/daemon/server.rs:940.",
    ),
    (
        "daemon.daemon_log_retention_weeks",
        "crates/holdfast-core/src/daemon/paths.rs:44 — same LogRetention chain; applied at paths.rs:1185.",
    ),
];

/// How an inert claim is backed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inert {
    /// No non-comment line under `crates/*/src`, outside `config.rs`, so
    /// much as writes this identifier — so no consumer can exist.
    /// Machine-checked by [`every_never_named_key_is_really_never_named`],
    /// and that check is what makes moving a live key into this table go
    /// red.
    NeverNamed,
    /// The identifier does appear elsewhere — an unrelated struct field, a
    /// local binding, an English word, a doc comment naming the knob it
    /// is not reading — so the absence argument is made by hand and the
    /// note says how.
    NamedElsewhere,
}

/// Keys that are accepted and do not reach the runtime.
const INERT: &[(&str, Inert, &str)] = &[
    // ---- [limits]
    (
        "limits.output_buffer_bytes",
        Inert::NamedElsewhere,
        "GH #128's repro. The live value is SessionConfig::buffer_capacity, which crates/holdfast-core/src/mcp/tools.rs:394 never sets, so it falls through to the hardcoded twin registry::DEFAULT_BUFFER_BYTES (crates/holdfast-core/src/session/registry.rs:64, also 1 MiB). The other mentions are doc comments and one operator-facing error string in daemon/server.rs.",
    ),
    (
        "limits.read_output_default_max_bytes",
        Inert::NeverNamed,
        "GH #128's repro. The hardcoded twin DEFAULT_READ_MAX_BYTES (crates/holdfast-core/src/mcp/tools.rs:87) is what read_output applies at tools.rs:850.",
    ),
    (
        "limits.read_output_hard_max_bytes",
        Inert::NeverNamed,
        "GH #128's repro. The hardcoded twin MAX_READ_MAX_BYTES (crates/holdfast-core/src/mcp/tools.rs:88) is the cap applied at tools.rs:853.",
    ),
    (
        "limits.output_broadcast_capacity",
        Inert::NeverNamed,
        "The hardcoded twin session::OUTPUT_BROADCAST_FRAMES (crates/holdfast-core/src/session/mod.rs:40) sizes the channel at session/mod.rs:703. VALIDATE-ONLY otherwise.",
    ),
    (
        "limits.max_outstanding_secret_requests_per_session",
        Inert::NeverNamed,
        "The field's own doc says \"Reserved and unread\"; §4.2 marks the knob fixed in v0.1.0 and §10.2 publishes it anyway. The slot is structurally one per session. VALIDATE-ONLY.",
    ),
    (
        "limits.prefilter_prefix_expansion_limit",
        Inert::NamedElsewhere,
        "The one §4.2 redaction knob left off the processing_limits() seam. The hardcoded twin DEFAULT_PREFIX_EXPANSION_LIMIT (crates/holdfast-core/src/output/prefix_index.rs:24) is what PrefixIndex::build gets at output/mod.rs:226. The single other mention is the doc comment at prefix_index.rs:23 naming the knob it is standing in for.",
    ),
    (
        "limits.wait_for_pattern_max_timeout_secs",
        Inert::NeverNamed,
        "The hardcoded twin WAIT_FOR_PATTERN_MAX_TIMEOUT_SECS (crates/holdfast-core/src/mcp/tools.rs:107) is the cap resolve_wait_timeout applies at tools.rs:125.",
    ),
    (
        "limits.file_transfer_chunk_bytes",
        Inert::NamedElsewhere,
        "Doc says \"Unread — 0.0.9\"; no file-transfer feature exists. The single mention is the doc comment at crates/holdfast-core/src/pty/worker/child.rs:85 noting a same-valued constant.",
    ),
    (
        "limits.file_transfer_max_bytes",
        Inert::NeverNamed,
        "Doc says \"Unread — 0.0.9\"; no file-transfer feature exists.",
    ),
    (
        "limits.command_history_max_entries",
        Inert::NamedElsewhere,
        "The live value is SessionConfig::history_max_entries, which crates/holdfast-core/src/mcp/tools.rs:394 never sets, so it falls through to the hardcoded twin detect::history::DEFAULT_MAX_ENTRIES (crates/holdfast-core/src/detect/history.rs:13). The one mention is that constant's doc comment naming this key.",
    ),
    // ---- [terminal]
    (
        "terminal.screen_tracking_default",
        Inert::NeverNamed,
        "start_session resolves an absent tool argument with ScreenTracking::default() (crates/holdfast-core/src/mcp/tools.rs:362), never the config. VALIDATE-ONLY.",
    ),
    (
        "terminal.screen_tracking_idle_disable_secs",
        Inert::NamedElsewhere,
        "ScreenConfig::default() supplies DEFAULT_IDLE_DISABLE (crates/holdfast-core/src/screen/mod.rs:31) at tools.rs:466; the config value has no path to it. The mentions are doc comments at screen/mod.rs:30 and screen/tracking.rs:155 naming the knob. VALIDATE-ONLY.",
    ),
    (
        "terminal.terminal_queries",
        Inert::NamedElsewhere,
        "crates/holdfast-core/src/mcp/tools.rs:409 resolves it as args.terminal_queries.unwrap_or(true). The other hits are the identically named SessionConfig/wire field, which is the per-call argument rather than this key.",
    ),
    (
        "terminal.terminal_query_replies_per_min",
        Inert::NamedElsewhere,
        "SessionConfig::default() supplies DEFAULT_TERMINAL_QUERY_REPLIES_PER_MIN (crates/holdfast-core/src/screen/queries.rs:59, also 60) at tools.rs:433. Same-value coincidence only. VALIDATE-ONLY.",
    ),
    (
        "terminal.shell_integration",
        Inert::NamedElsewhere,
        "GH #128's repro. crates/holdfast-core/src/mcp/tools.rs:401 resolves it as args.shell_integration.unwrap_or(true), so integration is injected whatever the file says. The other hits are the identically named SessionConfig/wire field.",
    ),
    // ---- [prompts]
    (
        "prompts.settle_threshold_ms",
        Inert::NamedElsewhere,
        "GH #128's repro, and the sharpest VALIDATE-ONLY case: config.rs refuses a zero at startup and then ignores every other value. crates/holdfast-core/src/mcp/tools.rs:396 uses DEFAULT_SETTLE_THRESHOLD_MS (crates/holdfast-core/src/detect/detector.rs:9, 250 ms). The other hits are the identically named DetectionConfig/wire field.",
    ),
    (
        "prompts.cursor_prompt_chars",
        Inert::NamedElsewhere,
        "crates/holdfast-core/src/screen/mod.rs:531 scores the cursor line against DEFAULT_PROMPT_CHARS (crates/holdfast-core/src/screen/cursor.rs:12). ScreenConfig has no field for it, so no plumbing exists even in principle. The mention is that constant's doc comment.",
    ),
    (
        "prompts.cursor_stable_samples",
        Inert::NamedElsewhere,
        "ScreenConfig::default() supplies DEFAULT_CURSOR_STABLE_SAMPLES (crates/holdfast-core/src/screen/cursor.rs:15, also 3) at tools.rs:466. Same-value coincidence only. The other hits are the identically named ScreenConfig/wire field. VALIDATE-ONLY.",
    ),
    (
        "prompts.extra_patterns",
        Inert::NamedElsewhere,
        "crates/holdfast-core/src/mcp/tools.rs:377 builds PatternSet::build's `extra` argument solely from args.prompt_patterns — the wire argument. The config vec is never appended. VALIDATE-ONLY (a length cap).",
    ),
    (
        "prompts.extra_patterns[].regex",
        Inert::NamedElsewhere,
        "Its only read, crates/holdfast-core/src/mcp/tools.rs:382, iterates args.prompt_patterns, not the config vec, so no config-sourced regex is ever compiled. `regex` is also the crate name and the adapters element field.",
    ),
    (
        "prompts.extra_patterns[].score",
        Inert::NamedElsewhere,
        "Its only read, crates/holdfast-core/src/mcp/tools.rs:383, iterates args.prompt_patterns. Not even range-checked by Config::validate.",
    ),
    // ---- [security]
    (
        "security.redaction_enabled",
        Inert::NamedElsewhere,
        "REFUSED-AT-LOAD, and inert by decision rather than by oversight (GH #128). It was classified effective here on one ground — crates/holdfast-core/src/mcp/tools.rs copied it into the §9.4 session_start row — while gating no redactor, so `false` bought an operator every rule still running and an audit trail asserting on every session that they were not. crates/holdfast-core/src/config.rs:1473 now refuses `false` at load, naming security.disabled_redaction_rules, which is the mechanism; the row describes the effective rule set instead (crates/holdfast-core/src/mcp/tools.rs:604). `true` is the only accepted value, it is the default, and nothing reads it — which is this table's own definition of inert, VALIDATE-ONLY. The single non-comment mention outside config.rs is crates/holdfast-core/src/mcp/tools.rs:4936, the assertion that the row no longer carries the field; a test of a field's absence is not a consumer of it.",
    ),
    (
        "security.extra_redaction_patterns",
        Inert::NamedElsewhere,
        "GH #128 calls this the serious one, and the code is honest about it: the doc comment says \"Parsed and deliberately not passed to RuleSet\", and crates/holdfast-core/src/config.rs:2911 is the test a_user_redaction_pattern_is_accepted_and_not_yet_in_force, which asserts the rule set equals RuleSet::builtin(). The §15.1 ExtraRule → RuleSpec mapping is undecided. The one mention is the doc comment at crates/holdfast-core/src/output/rules.rs:31 saying it cannot take one.",
    ),
    (
        "security.strict_confirmation",
        Inert::NeverNamed,
        "Doc says \"Unread — 0.0.8\". §9.3.1's strict mode is not built, so REQ-CFG-006's HOLDFAST_STRICT_CONFIRMATION latch has nothing to tighten either.",
    ),
    // ---- [ui]
    (
        "ui.ui_bridge_pinned_port",
        Inert::NeverNamed,
        "The whole bridge/* surface is 0.0.10's; the struct doc says \"All unread — 0.0.10\".",
    ),
    (
        "ui.ui_token_idle_ttl_secs",
        Inert::NeverNamed,
        "0.0.10. VALIDATE-ONLY.",
    ),
    (
        "ui.ui_token_absolute_ttl_secs",
        Inert::NeverNamed,
        "0.0.10. VALIDATE-ONLY.",
    ),
    (
        "ui.max_bridge_sessions",
        Inert::NamedElsewhere,
        "0.0.10. VALIDATE-ONLY. The one mention is crates/holdfast-core/src/protocol/method.rs:179, a doc comment saying its only producer, bridge/register, is 0.0.10's.",
    ),
    // ---- [notifications]
    (
        "notifications.sink",
        Inert::NamedElsewhere,
        "There is no notification module in the crate at all; the struct doc says \"All unread — 0.0.9\". Every `sink` hit in the tree is the audit log's file handle (crates/holdfast-core/src/audit.rs:30) or a test's capture buffer. VALIDATE-ONLY.",
    ),
    (
        "notifications.webhook_url",
        Inert::NeverNamed,
        "0.0.9; nothing in the crate mentions a webhook. Not even validated.",
    ),
    (
        "notifications.command",
        Inert::NamedElsewhere,
        "0.0.9. `command` is the most common identifier in the crate — the session's command line, the history entry, the spawn argument — and none of those is this key. Not even validated.",
    ),
    (
        "notifications.events",
        Inert::NamedElsewhere,
        "0.0.9. Every `events` hit is a broadcast receiver or an OSC-133 event vector. VALIDATE-ONLY.",
    ),
    (
        "notifications.notification_rate_limit_per_min",
        Inert::NeverNamed,
        "0.0.9. VALIDATE-ONLY.",
    ),
    // ---- [[adapters]]
    (
        "adapters",
        Inert::NeverNamed,
        "VALIDATE-ONLY: crates/holdfast-core/src/config.rs:1648 iterates it to refuse an empty name, and nothing else in the workspace reads it. The struct doc says \"Unread — 0.0.9\". Nothing in detect/ ever receives a Config.",
    ),
    (
        "adapters[].name",
        Inert::NamedElsewhere,
        "VALIDATE-ONLY: the non-empty rule at crates/holdfast-core/src/config.rs:1654. `name` is also SessionProfile's and SecretBinding's override key.",
    ),
    (
        "adapters[].match_command",
        Inert::NamedElsewhere,
        "No consumer. Every other mention is prose about SecretBinding::match_command, a different field retired by GH #46.",
    ),
    (
        "adapters[].prompt_patterns",
        Inert::NamedElsewhere,
        "No consumer. The hits are start_session's identically named wire argument, which does not come from the config.",
    ),
    (
        "adapters[].notes",
        Inert::NamedElsewhere,
        "No consumer. The two other hits are the English word in a doc comment and a shell command inside a test fixture byte string.",
    ),
    (
        "adapters[].prompt_patterns[].regex",
        Inert::NamedElsewhere,
        "Never compiled — the adapters vec reaches no detector. `regex` is also the crate name and PromptPattern's field.",
    ),
    (
        "adapters[].prompt_patterns[].score",
        Inert::NamedElsewhere,
        "Never fed to the detector's combiner. `score` is also PromptPattern's field and the detector's own vocabulary.",
    ),
    (
        "adapters[].prompt_patterns[].kind",
        Inert::NamedElsewhere,
        "No consumer. `kind` is the audit record's and the MCP error's discriminator throughout the crate.",
    ),
    // ---- [daemon]
    (
        "daemon.record_all_sessions",
        Inert::NeverNamed,
        "Doc says \"Unread — 0.0.9\" (§5.8.1 recording). Not even validated.",
    ),
];

// ------------------------------------------------------------- the checks

#[test]
fn every_config_key_is_classified_effective_or_inert() {
    let surface = surface();
    let effective: BTreeSet<&str> = EFFECTIVE.iter().map(|(k, _)| *k).collect();
    let inert: BTreeSet<&str> = INERT.iter().map(|(k, _, _)| *k).collect();

    assert_eq!(
        EFFECTIVE.len(),
        effective.len(),
        "EFFECTIVE lists a key twice"
    );
    assert_eq!(INERT.len(), inert.len(), "INERT lists a key twice");

    let both: Vec<&&str> = effective.intersection(&inert).collect();
    assert!(
        both.is_empty(),
        "these keys are in both tables, so neither claim means anything: {both:#?}"
    );

    let unclassified: Vec<&String> = surface
        .iter()
        .filter(|k| !effective.contains(k.as_str()) && !inert.contains(k.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "config key(s) with no classification: {unclassified:#?}\n\n\
         You have added a key to `config.toml`'s schema. Before it ships, decide \
         which it is and add it to EFFECTIVE or INERT in \
         crates/holdfast-core/tests/config_surface.rs:\n\
         - EFFECTIVE: some runtime path reads it off a loaded Config and it changes \
           what the daemon does. Cite the consumer as path:line.\n\
         - INERT: it is accepted and never read. Say what wins instead, and whether \
           anything outside config.rs even names it.\n\
         Accepting a key that does nothing is GH #128. Refusing to classify it is how \
         GH #128 happened."
    );

    let stale: Vec<&&str> = effective
        .union(&inert)
        .filter(|k| !surface.contains(**k))
        .collect();
    assert!(
        stale.is_empty(),
        "these table entries name no key the schema has — a rename or a removal left \
         them behind: {stale:#?}"
    );
}

#[test]
fn no_container_in_the_exemplar_is_empty() {
    let mut empty = Vec::new();
    find_empty_containers("", &as_json(&populated()), &mut empty);
    assert!(
        empty.is_empty(),
        "`populated()` leaves these collections empty, so the walk cannot see the keys \
         inside them and they will never be classified: {empty:#?}\n\n\
         Give each one an element in `populated()`, or — if its contents are names the \
         operator chooses rather than keys the schema defines — add it to FREE_FORM and \
         say why."
    );
}

/// Every path whose value is an empty array or an empty object, stopping
/// at [`FREE_FORM`] for the same reason [`flatten`] does.
fn find_empty_containers(prefix: &str, value: &Value, out: &mut Vec<String>) {
    if FREE_FORM.contains(&prefix) {
        return;
    }
    match value {
        Value::Object(map) if map.is_empty() => out.push(prefix.to_string()),
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                find_empty_containers(&path, child, out);
            }
        }
        Value::Array(items) => match items.first() {
            None => out.push(prefix.to_string()),
            Some(first) => find_empty_containers(&format!("{prefix}[]"), first, out),
        },
        _ => {}
    }
}

#[test]
fn the_exemplar_is_a_config_an_operator_could_write() {
    // Otherwise the enumerated surface could contain keys no real config
    // can carry, and the classification would be about a shape that does
    // not exist.
    populated()
        .validate()
        .expect("the enumeration exemplar is a valid config");
}

#[test]
fn every_effective_key_cites_a_consumer_outside_config_rs() {
    for (key, evidence) in EFFECTIVE {
        let citations = citations(evidence);
        assert!(
            !citations.is_empty(),
            "{key} is claimed effective with no path:line citation: {evidence}"
        );
        for (path, line) in &citations {
            let full = workspace_root().join(path);
            let text = std::fs::read_to_string(&full)
                .unwrap_or_else(|e| panic!("{key} cites {path}, which cannot be read: {e}"));
            let lines = text.lines().count();
            assert!(
                *line <= lines,
                "{key} cites {path}:{line}, but that file has {lines} lines — the citation \
                 has rotted past the end of the file"
            );
        }
        assert!(
            citations
                .iter()
                .any(|(p, _)| p != "crates/holdfast-core/src/config.rs"),
            "{key} is claimed effective but every citation is inside config.rs. A read \
             there is `validate` or the `processing_limits` seam; neither is a consumer. \
             Name the file that acts on the value."
        );
    }
}

#[test]
fn every_never_named_key_is_really_never_named() {
    let sources = source_files();
    for (key, backing, note) in INERT {
        if *backing != Inert::NeverNamed {
            continue;
        }
        let ident = leaf(key);
        let mut found = Vec::new();
        for path in &sources {
            let text = std::fs::read_to_string(path).expect("read a source file");
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if writes_identifier(line, ident) {
                    found.push(format!("{}:{}", display(path), n + 1));
                }
            }
        }
        assert!(
            found.is_empty(),
            "{key} is marked Inert::NeverNamed, but `{ident}` is written on these \
             non-comment lines outside config.rs: {found:#?}\n\n\
             Either it is read now — move it to EFFECTIVE and cite the consumer — or the \
             hits are unrelated, in which case mark it Inert::NamedElsewhere and say so. \
             Note currently reads: {note}"
        );
    }
}

/// The four keys `Config::processing_limits()` carries, probed
/// behaviourally rather than argued from a grep.
///
/// **This test exists because a mutation test got past everything else in
/// this file.** `limits.redaction_lookbehind_bytes` was moved from
/// EFFECTIVE into INERT as [`Inert::NeverNamed`] and all six checks stayed
/// green — correctly, on their own terms: nothing outside `config.rs`
/// writes that identifier, because `processing_limits()` renames it to
/// `lookbehind_bytes` on the way out. A renaming seam is precisely where
/// an identifier-absence argument stops being evidence, and it is the one
/// seam `[limits]` has.
///
/// So this asks the question the other way round. Change the key; the
/// struct `OutputProcessor` is built from must change with it, and a key
/// that changes it is effective whatever the table says.
#[test]
fn every_key_the_processing_limits_seam_carries_is_classified_effective() {
    /// A key, and the one-line edit that sets it to [`PROBE`].
    type Probe = (&'static str, fn(&mut LimitsConfig));

    let probes: &[Probe] = &[
        ("limits.redaction_lookbehind_bytes", |l| {
            l.redaction_lookbehind_bytes = PROBE
        }),
        ("limits.redaction_lookahead_bytes", |l| {
            l.redaction_lookahead_bytes = PROBE
        }),
        ("limits.partial_secret_scan_bytes", |l| {
            l.partial_secret_scan_bytes = PROBE
        }),
        ("limits.ansi_incomplete_max_bytes", |l| {
            l.ansi_incomplete_max_bytes = PROBE
        }),
    ];
    let base = seam(&Config::default());
    for (key, set) in probes {
        let mut config = Config::default();
        set(&mut config.limits);
        assert_ne!(
            seam(&config),
            base,
            "{key} no longer reaches processing_limits(); this probe has gone stale and \
             is asserting nothing"
        );
        assert!(
            EFFECTIVE.iter().any(|(k, _)| k == key),
            "{key} changes the ProcessingLimits the output processor is built from, so \
             it is effective whatever the tables say — and the `NeverNamed` scan cannot \
             see it, because the seam renames it."
        );
    }

    // The converse, because it is the plausible thing to get wrong: the
    // fourth §4.2 redaction knob looks like it belongs on this seam and is
    // not on it. `processing_limits()` carries four fields and the table
    // has five; `prefilter_prefix_expansion_limit` is the one left off, so
    // `PrefixIndex::build` gets a constant instead.
    let mut config = Config::default();
    config.limits.prefilter_prefix_expansion_limit = PROBE;
    assert_eq!(
        seam(&config),
        base,
        "limits.prefilter_prefix_expansion_limit now reaches processing_limits() — it is \
         effective, and both its INERT entry and this assertion need to change"
    );
}

/// A value no `d_*` default has, so a probe cannot pass by coincidence.
const PROBE: usize = 4243;

/// `Config::processing_limits()`'s four fields, positionally.
///
/// Spelled out rather than compared with `PartialEq` because
/// `ProcessingLimits` does not derive it, and deriving it on a production
/// type for one test's convenience is a change to the crate for a reason
/// the crate does not have.
fn seam(config: &Config) -> [usize; 4] {
    let limits = config.processing_limits();
    [
        limits.lookbehind_bytes,
        limits.lookahead_bytes,
        limits.partial_secret_scan_bytes,
        limits.ansi_incomplete_max_bytes,
    ]
}

#[test]
fn the_walk_sees_a_key_that_only_a_populated_collection_can_show() {
    // The enumeration's own load-bearing property, asserted rather than
    // assumed: `Config::default()` alone cannot reach inside a collection,
    // so a test built on it would silently never classify these.
    let mut from_default = BTreeSet::new();
    flatten("", &as_json(&Config::default()), &mut from_default);
    assert!(!from_default.contains("security.profiles[].program"));
    assert!(surface().contains("security.profiles[].program"));

    // And the reverse: a populated collection hides nothing the default
    // shows, because both walks are unioned.
    assert!(surface().is_superset(&from_default));
}

// ---------------------------------------------------------------- helpers

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/holdfast-core has a workspace root two levels up")
        .to_path_buf()
}

fn display(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// The last identifier in a dotted path: `security.profiles[].program` is
/// `program`.
fn leaf(key: &str) -> &str {
    key.rsplit('.')
        .next()
        .expect("a non-empty key")
        .trim_end_matches("[]")
}

/// Every `crates/…rs:LINE` in an evidence string.
fn citations(evidence: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for token in evidence.split_whitespace() {
        let token = token.trim_matches(|c: char| !c.is_ascii_graphic() || c == ',' || c == ';');
        let Some((path, rest)) = token.split_once(".rs:") else {
            continue;
        };
        if !path.starts_with("crates/") {
            continue;
        }
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(line) = digits.parse::<usize>() {
            out.push((format!("{path}.rs"), line));
        }
    }
    out
}

/// Every `.rs` file under a crate's `src/`, except the config module
/// itself — its definitions, defaults, validation and unit tests are
/// exactly what an inert key is allowed to be named by.
fn source_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = workspace_root().join("crates");
    for entry in std::fs::read_dir(&crates).expect("read crates/") {
        let src = entry.expect("a crates/ entry").path().join("src");
        if src.is_dir() {
            collect_rs(&src, &mut out);
        }
    }
    let config_rs = workspace_root().join("crates/holdfast-core/src/config.rs");
    out.retain(|p| *p != config_rs);
    out.sort();
    assert!(
        out.len() > 20,
        "the source scan found only {} files, so it is not scanning the tree",
        out.len()
    );
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether `line` writes `ident` as a whole word.
///
/// Whole-word is the point: `limits.command_history_max_entries`'s leaf
/// must not match `history_max_entries`, and `notifications.sink` must
/// match `self.sink` but not `sinks`.
fn writes_identifier(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(at) = line[from..].find(ident) {
        let start = from + at;
        let end = start + ident.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
