//! The global TOML configuration file (§10.1, §10.2).
//!
//! Discovery is `$XDG_CONFIG_HOME/holdfast/config.toml`, falling back to
//! `~/.config/holdfast/config.toml` (REQ-CFG-002). **`HOLDFAST_RUNTIME_DIR`
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
use crate::protocol::MAX_FRAME_BYTES;

/// Everything that can go wrong turning a file into a [`Config`].
///
/// **Every message in here has already been through the redactor.** A
/// config file is a place credentials live, and every one of these
/// errors is on a path that ends in `daemon.log`: `config::load()?` →
/// `server::run`'s `Err` → `holdfast daemon run`'s `eprintln!` → the child
/// stderr `spawn.rs` redirects into the log, where it sits for the
/// §19.1 retention window. §9.2 lists *"daemon.log error contexts (when
/// they include byte excerpts)"* among the boundaries that route through
/// the redactor, and this module is one of the producers that owes it.
///
/// Construct through [`ConfigError::invalid`] and [`ConfigError::parse`]
/// rather than by naming the variants — those are where [`redacted`]
/// runs, and a message assembled anywhere else is one nothing redacts.
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
    ///
    /// **The `toml::de::Error` is rendered, redacted, and then dropped
    /// — deliberately, and it must stay dropped.** Its `Display` is a
    /// caret diagram containing the offending *line*, so
    /// `api_token = "ghp_…"` under `[security]` — an unmodelled key,
    /// which `deny_unknown_fields` makes an error by construction —
    /// renders the credential verbatim. Keeping the error as a
    /// `#[source]` beside a redacted `Display` would not help: a caller
    /// that walks the chain, or one `{:#}` in a future logging crate,
    /// puts the raw rendering back on the same path. There is no second
    /// copy to walk to.
    ///
    /// The carets are counted against the *unredacted* line and so no
    /// longer line up under a redacted one. That is cosmetic; the line
    /// number, the key and the expected-key list all survive, which is
    /// what §10.1 asks the message to carry.
    #[error("config file {path} is not valid: {message}")]
    Parse { path: PathBuf, message: String },
    /// A file that parsed and then failed a semantic rule. The message
    /// always names the key and the value (§10.1, REQ-CFG-003) — and the
    /// value is operator-supplied, so it is redacted like any other.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// The file exists and this process declines to read it. See
    /// [`trust_verdict`] for the three questions and why each threshold
    /// is where it is.
    #[error("config file {path} {reason}")]
    Untrusted { path: PathBuf, reason: String },
}

impl ConfigError {
    /// A validation failure, with the operator's value redacted.
    fn invalid(message: impl AsRef<str>) -> Self {
        ConfigError::Invalid(redacted(message.as_ref()))
    }

    /// A refusal to read a file that failed [`trust_verdict`].
    fn untrusted(path: &Path, reason: &str) -> Self {
        ConfigError::Untrusted {
            path: path.to_path_buf(),
            reason: redacted(reason),
        }
    }

    /// A parse failure, with the offending source line redacted.
    fn parse(path: &Path, source: &toml::de::Error) -> Self {
        ConfigError::Parse {
            path: path.to_path_buf(),
            message: redacted(&source.to_string()),
        }
    }
}

/// Put a diagnostic through the §9.2 redactor before it can become a
/// [`ConfigError`].
///
/// The same built-in rule set every other output boundary uses, taken
/// from the same process-wide table rather than compiled per error, so a
/// rule that redacts a token in `read_output` redacts it here too. A
/// secret whose shape no rule matches still gets through — that is the
/// standing limit of pattern redaction and it is not specific to this
/// module — but the vendor tokens and the `…token = "…"` /
/// `…password = "…"` assignment shapes that dominate a config file do
/// not.
fn redacted(message: &str) -> String {
    crate::output::redact::redact_str(&crate::output::rules::builtin_shared(), message)
}

// ------------------------------------------------------------ discovery

/// `$XDG_CONFIG_HOME/holdfast/config.toml`, else `$HOME/.config/holdfast/config.toml`.
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
    Some(base.join("holdfast").join("config.toml"))
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
///
/// **The file is judged before it is read, and judged through the open
/// descriptor rather than through the path.** `fstat` on the descriptor
/// that is about to be read is what makes the check and the read talk
/// about the same file: a path checked and then opened is two lookups
/// with a window between them, and the window is the whole attack. It is
/// also what makes a symlink a non-question — see [`trust_verdict`].
///
/// **`O_NONBLOCK` on the open, and it is load-bearing rather than
/// tidiness.** Opening a fifo for reading waits for a writer, in the
/// kernel, *before* any `fstat` a check could perform — so without the
/// flag a config path pointing at a fifo hangs daemon startup and
/// [`trust_verdict`] never gets a turn. On a regular file the flag has
/// no effect on the read that follows, which is why it can simply stay
/// set.
pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(source) => return Err(io_error(path, source)),
    };
    let meta = file.metadata().map_err(|e| io_error(path, e))?;
    if let Some(reason) = untrusted_reason(&meta) {
        return Err(ConfigError::untrusted(path, &reason));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| io_error(path, e))?;
    parse_named(&text, path)
}

fn io_error(path: &Path, source: std::io::Error) -> ConfigError {
    ConfigError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// [`trust_verdict`] over what `fstat` reported, split out so the
/// verdict itself can be tested against ownerships an unprivileged test
/// process cannot create.
///
/// Unix-only, as this crate already is (`daemon::paths` and
/// `daemon::peer` both reach for `std::os::unix` unconditionally). A
/// Windows port owes this function an ACL-shaped answer, not a `#[cfg]`
/// that returns "trusted".
fn untrusted_reason(meta: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    trust_verdict(
        meta.is_file(),
        meta.uid(),
        meta.mode() & 0o777,
        crate::daemon::peer::current_uid(),
    )
}

/// Whether this process will read `config.toml`, given what `fstat` says
/// about the descriptor it just opened. `None` is "trusted".
///
/// **Refuse and report; never repair.** A `chmod` from here would follow
/// the very symlink it is meant to defend against, and a repair that
/// runs before an assertion makes the assertion vacuous — which is how
/// `ensure_dir`'s own test went blind, and why `audit.log`'s `0600` is
/// established by a single opener with no verify-and-tighten. This
/// function returns a sentence the operator can act on and reads
/// nothing.
///
/// **A symlink is not one of the questions, deliberately.** Dotfile
/// managers — stow, chezmoi, yadm — symlink `~/.config/**` into a
/// repository, so refusing a symlinked `config.toml` outright would
/// refuse a large class of ordinary installs to no end. What matters is
/// what the link *resolves to*, and because the three questions below
/// are asked of the open descriptor, that is exactly what they are asked
/// of: a link into the operator's own dotfiles passes, and a link to
/// another user's file, to `/dev/null` or to a fifo does not.
///
/// The three questions, and why each threshold is where it is:
///
/// * **A regular file.** `/dev/null` reads as an empty document, an
///   empty document parses, and the result is [`Config::default`] — every
///   knob the operator set, silently gone, with nothing reported
///   anywhere. A fifo is worse than silent: `read_to_string` blocks
///   until something writes, so a config path pointing at one hangs
///   startup rather than failing it.
///
/// * **Owned by us, or by root.** Anyone else owning this file owns the
///   daemon's limits. Root is allowed, as OpenSSH's `StrictModes` allows
///   it, and that is a deliberate divergence from
///   [`peer::is_authorized`](crate::daemon::peer::is_authorized), which
///   refuses root: there root is a *peer* asking to drive another user's
///   sessions, here it is the owner of a file inside that user's own
///   home — a state one `sudo $EDITOR ~/.config/holdfast/config.toml`
///   produces, and one root could reach by any other route anyway.
///
/// * **Not world-writable** — `0o002`, and pointedly not `0o022`.
///   Group-writable is what an editor produces under the `umask 002`
///   that Debian, Ubuntu and RHEL ship: `0664`, on systems whose
///   user-private groups make that the user alone. Refusing it would
///   refuse a stock install, which is the mistake `ensure_dir` made on a
///   `0775` `~/.holdfast/logs` and had to take back. World-writable has no
///   such benign origin — it wants `umask 000` or a deliberate `chmod` —
///   and it means any local user can rewrite the file.
fn trust_verdict(is_file: bool, uid: u32, mode: u32, euid: u32) -> Option<String> {
    if !is_file {
        return Some(
            "is not a regular file, so it is not a configuration: a device would \
             read as an empty document and resolve to the built-in defaults with \
             nothing reported, and a fifo would block startup until something \
             wrote to it. Point the path at a file, or remove it."
                .to_string(),
        );
    }
    if uid != euid && uid != 0 {
        return Some(format!(
            "is owned by uid {uid}, and this process runs as uid {euid}: another \
             local user owns the file that sets this daemon's limits. Refusing to \
             read it — check what is in it, then `chown {euid}` it or move it aside."
        ));
    }
    if mode & 0o002 != 0 {
        return Some(format!(
            "is mode {mode:o}: world-writable, so any local user can rewrite the \
             file that sets this daemon's limits. Refusing rather than tightening \
             it — a chmod follows a symlink, and a control that repairs before it \
             checks has stopped checking. `chmod o-w` it, then start again."
        ));
    }
    None
}

/// Parse and validate a config from a string, for tests and for callers
/// that already hold the bytes.
pub fn parse_str(text: &str) -> Result<Config, ConfigError> {
    parse_named(text, Path::new("<config>"))
}

fn parse_named(text: &str, path: &Path) -> Result<Config, ConfigError> {
    let config: Config =
        toml::from_str(text).map_err(|source| ConfigError::parse(path, &source))?;
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
    /// `prompt` | `keychain` | `both` (§9.6). **Read** — it is §5.2 step
    /// one's gate, via `secret::binding::keychain_step_runs`.
    #[serde(default = "d_secret_provider")]
    pub secret_provider: String,
    /// §9.6's silent injection. **Read** — `HoldfastServer::watch_for_autofill`
    /// arms a listener on §8.3's echo-drop edge when it is set, and arms
    /// nothing at all when it is not.
    ///
    /// **Default `false`, and REQ-SEC-014 makes that default a requirement
    /// in its own right**: *"silent credential injection is powerful and
    /// should be opted into per deployment, not inherited."* With it on and
    /// a matching binding, the daemon resolves a credential and types it
    /// into the child with no agent tool call and no human in the loop
    /// (§16.4: *"steps 4–7 collapse"*).
    ///
    /// ## What an operator is opting into, stated here rather than only in
    /// an issue tracker (GH #43)
    ///
    /// The write is refused unless the child is still at an echo-off read
    /// (read from the tty at the moment of writing, not from a cache) and
    /// nothing has been written to the child since **before the provider
    /// ran**. That second window is wider than "since the credential was
    /// resolved", which is what this sentence used to say: the
    /// `expect_writes` snapshot is taken where the caller *decides* to
    /// resolve — `autofill_from_binding`'s `AutofillGuard`, built before
    /// the `spawn_blocking` that runs the provider — so it covers the
    /// whole provider round trip and not just the interval after the
    /// value came back.
    /// [`crate::session::WriteRequest::SecretIfUnread`]'s doc on that field
    /// says the same thing from the writer's side, and is where the
    /// reasoning is.
    ///
    /// **One case gets past both**, and it is filed rather than
    /// fixed: a child that drops echo, emits *nothing*, then draws its
    /// prompt, while a byte written earlier still sits unread in the tty
    /// input queue. That byte answers the echo-off read and the credential
    /// answers the **next** one, which usually echoes — so it reaches the
    /// ring buffer, and `read_output` serves the ring buffer to the agent.
    ///
    /// It is narrow: it needs this flag on, `secret_provider` allowing the
    /// keychain, a binding that matches the session, and that exact
    /// silence-with-queued-input shape. It is not theoretical — it has been
    /// reproduced. The obstacle to closing it is a PTY-lifetime tension
    /// (see `write_secret_if_unread`), not a missing check here.
    #[serde(default = "d_autofill_on_echo_off")]
    pub autofill_on_echo_off: bool,
    /// **Unread — 0.0.8.**
    #[serde(default = "d_strict_confirmation")]
    pub strict_confirmation: bool,
    /// §9.6's operator bindings. **Read** by `secret::binding::select`.
    /// §10.2's example is fully commented, so nothing in the published
    /// fixture exercises this; §9.6 defines the block normatively, so an
    /// operator who uncomments it must not get a rejected config.
    #[serde(default)]
    pub secret_bindings: Vec<SecretBinding>,
    /// §9.6's operator-declared session profiles (GH #46). **Read** by
    /// `start_session` and named by every [`SecretBinding`].
    ///
    /// **This is what retires GH #45's bypass class rather than
    /// mitigating it.** Through 0.0.7 the agent authored the whole command
    /// line and this file tried to decide whether that string was one the
    /// operator meant; four guard shapes failed at it, and the last round
    /// made the guard larger and weaker at once. A profile inverts the
    /// direction: the operator writes the command line, the agent fills
    /// named slots, and `crate::secret::profile` carries the argument for
    /// why a slot is a different problem from a command line.
    #[serde(default)]
    pub profiles: Vec<SessionProfile>,

    // ---- 0.0.7's three. None of them appears in §4.2 or §10.2 (Q2, Q3,
    // Q4), so they are additive: a config written against the published
    // example still loads, because every one carries a default.
    /// Bounds the provider subprocess so a credential store waiting on a
    /// biometric prompt cannot hold the session's only request slot.
    #[serde(default = "d_keychain_provider_timeout_secs")]
    pub keychain_provider_timeout_secs: u32,
    /// Ceiling on `request_secret_input`'s `max_secret_bytes` argument.
    /// 65536 matches §7.6.3's 64 KiB web secret-body cap and
    /// `send_input.data`'s 64 KiB cap, so a client that can submit it can
    /// also carry it.
    #[serde(default = "d_max_secret_bytes_ceiling")]
    pub max_secret_bytes_ceiling: u32,
    /// Ceiling on `request_secret_input`'s `timeout_secs` argument.
    #[serde(default = "d_secret_input_max_timeout_secs")]
    pub secret_input_max_timeout_secs: u32,
}

/// One operator-declared session profile (§9.6, GH #46).
///
/// ```toml
/// [[security.profiles]]
/// name    = "prod-ssh"
/// program = "ssh"                       # a literal. NO substitution.
/// args    = ["{user}@{host}"]
///
///   [security.profiles.vars]
///   user = "^[a-z][a-z0-9_-]{0,30}$"
///   host = "^prod-0[12]$"
/// ```
///
/// **The agent supplies values into the slots and never writes a command
/// line.** `crate::secret::profile` holds the rules, the substitution and —
/// more importantly — the argument for why a slot is a different problem
/// from a regex over a command line. Read it before adding a knob here.
///
/// Every rule is refused at load by [`Config::validate`], with the message
/// naming the key.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionProfile {
    /// The override key. A [`SecretBinding`] attaches to a profile by this
    /// name, and `start_session(profile:)` names it. Unique, and a binding
    /// naming an unknown one is a load error.
    pub name: String,
    /// **A literal program name, and it admits no `{…}`.** If the agent
    /// could influence the program it would choose the binary, and no
    /// pattern over an *argument* can bound that. Refused at load.
    pub program: String,
    /// The argument template. `{name}` is a slot; `{{` and `}}` are
    /// literal braces.
    ///
    /// **A `Vec<String>`, and that is the structural guarantee rather than
    /// a serde convenience.** Substitution happens *within* one element, so
    /// a value containing a space, a quote, a `;` or a leading `-` stays
    /// one argument and can never become a second one. Nothing joins these
    /// and nothing re-splits them.
    #[serde(default)]
    pub args: Vec<String>,
    /// `{slot name: regex}`. Each pattern is matched against the agent's
    /// value **whole**, through `secret::binding::whole_line` — the same
    /// anchoring, compiled by the same function at load and at render, so
    /// the two cannot disagree (GH #50).
    ///
    /// Every slot in [`args`](Self::args) needs an entry here and every
    /// entry needs a slot; both directions are refused at load, because a
    /// slot with no pattern is unguarded and a pattern with no slot is a
    /// typo the operator should learn about at startup.
    #[serde(default)]
    pub vars: std::collections::BTreeMap<String, String>,
}

/// One operator-configured secret binding (§9.6). **Unread in 0.0.5.**
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// The override key, and the only part of **the binding** any surface
    /// shows: `BindingApprovalRequired` (§7.5), `GET
    /// /api/binding-approvals` (§7.6.3) and the `binding_resolved` /
    /// `binding_approval` audit kinds (§18.7) all carry `binding_name`
    /// and never the `reference` or the resolved value (REQ-SEC-016).
    ///
    /// **It is no longer the only identifying thing on those surfaces**,
    /// and the earlier wording that said so has been corrected rather than
    /// left to be believed: `BindingApprovalRequired` also carries the
    /// **session's** command line (GH #45), and `GET
    /// /api/binding-approvals` will when 0.0.10 builds it — that one is
    /// future tense, as `approval.rs` and `tests/secrets.rs` both say and
    /// as an earlier draft of this sentence did not. The reason is that a
    /// name an operator chose months ago is not something a human can
    /// decide from. It is identifying by construction — of the session,
    /// not of the credential, which is the distinction REQ-SEC-016
    /// actually draws.
    pub name: String,
    /// **The [`SessionProfile`] this credential is for** — the field that
    /// decides whether this binding fires (GH #46).
    ///
    /// **The subject is the session's own `profile`**, which is a name the
    /// *operator* wrote, copied onto the session by `start_session` after
    /// the profile was looked up. A session started with `command`/`args`
    /// carries no profile, so **no `command`/`args` session can ever
    /// receive a keychain credential**. That is the safety property; it is
    /// also a real capability loss, and `crate::secret::profile`'s header
    /// states both halves.
    ///
    /// **This replaced `match_command` and `match_example`, and the
    /// replacement is structural rather than better-written.** Those two
    /// were a regex over `Session.command` and `Session.args` joined — a
    /// string the agent wrote in full — plus a load-time corpus judging
    /// what the regex admitted. Four guard shapes failed at that:
    /// anchoring (bypassed at the other end), a ~180-line syntactic
    /// scanner (20 accepted spellings), a 9-probe behavioural corpus (the
    /// whole insertion class missed), and a 51-probe corpus, where the
    /// cheapest dodge fell to **one character** — `[^ ]*`, because all 51
    /// probe texts contain a space. The guard got weaker as it got larger.
    ///
    /// **The asymmetry that makes a profile different from a pattern**:
    /// a slot is bounded and cannot add an argument, so a wide slot
    /// pattern is bounded damage where a wide `match_command` was not.
    /// `crate::secret::profile` carries that argument at length, and it is
    /// the thing to read before proposing a regex over the command line
    /// here for convenience.
    ///
    /// A binding naming a profile the config does not declare is refused
    /// by [`Config::validate`], with the message naming both.
    ///
    /// **What selection costs, stated here rather than only in an issue
    /// tracker.** The first binding in configured order whose profile the
    /// session carries is the one whose `reference` is handed to
    /// `provider` and whose value is written into the child at its
    /// echo-off read (§5.2's step 1), inside `max_uses`.
    /// [`require_confirm`](Self::require_confirm) — **`true` by default**
    /// — puts a human in front of that and shows them this session's
    /// command line; with it off the injection is silent. What all of the
    /// above protects is the credential's **bytes**, not its effect: an
    /// agent that can legitimately start the `prod-ssh` profile still gets
    /// a shell there. `secret::binding`'s "What this still does not close"
    /// carries the residuals.
    pub profile: String,
    /// **Not a security control**, and it must not be documented as one
    /// (GH #45 round 3). It is a *conjunct*, so it can only narrow a
    /// selection [`profile`](Self::profile) already made, and the agent —
    /// which chooses the child — chooses the prompt text too.
    ///
    /// **Unchanged by GH #46's retirement of `match_command`, and that is
    /// worth saying rather than leaving to be inferred.** It narrowed
    /// within a `match_command` and it narrows within a profile; the three
    /// reasons it gets no load-time check of its own are the same three,
    /// and `secret::binding`'s header still carries them along with the
    /// one-bit-oracle note.
    ///
    /// What it is for: disambiguating **between prompts inside a session
    /// that has already matched** — *"this credential is for the login
    /// prompt, not the sudo prompt"*. `""`, the documented default, means
    /// "this binding does not select on the prompt".
    pub match_prompt: String,
    pub provider: String,
    pub reference: String,
    #[serde(default)]
    pub max_uses: Option<u32>,
    /// **Defaults to `true`** (GH #45).
    ///
    /// It defaulted to `false` through 0.0.7, which made silent
    /// resolution the shape an operator got by omitting a line. That is
    /// the wrong default for a key whose *on* position is the only thing
    /// standing between a matched binding and a credential typed into a
    /// child, and it is the wrong default specifically because the thing
    /// being matched — the session's command line — is written by the
    /// agent.
    ///
    /// **The asymmetry with `autofill_on_echo_off`, which defaults `false`
    /// and stays there, is deliberate.** That key decides whether the
    /// credential store is consulted *at all* without a tool call; this
    /// one decides whether a human sees the command line first. The safe
    /// position of the first is *off* and of the second is *on*, and both
    /// are the position that requires somebody to have decided.
    #[serde(default = "d_require_confirm")]
    pub require_confirm: bool,
}

/// §7.6's web-UI bridge knobs. **All unread — 0.0.10.**
///
/// **There is no socket-path knob.** All three sockets live in the
/// runtime directory §7.1 discovers and none is individually
/// relocatable: a knob that moved one out would put it outside the
/// `0700` verification §7.1 performs, and would let two daemons under
/// different `HOLDFAST_RUNTIME_DIR`s share an `http.sock` while disagreeing
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
/// and the one thing that relocates any of them is `HOLDFAST_RUNTIME_DIR`,
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
    /// §17.5's binding-approval window, **read by
    /// `mcp::tools`'s `run_binding_approval`** through
    /// [`crate::secret::approval_window`].
    ///
    /// **An operator can measure a window shorter than this number, and
    /// that is the invariant rather than a defect** (§17.5, indexed at
    /// §25): with a call waiting, the window is
    /// `min(binding_approval_timeout_secs, half the caller's remaining
    /// deadline)`, so REQ-SEC-017's fall-through to the human prompt stays
    /// reachable. Both this and `request_secret_input.timeout_secs`
    /// default to 120, so the un-halved reading consumes the caller's
    /// whole deadline and the fall-through never runs.
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
fn d_keychain_provider_timeout_secs() -> u32 {
    10
}
fn d_max_secret_bytes_ceiling() -> u32 {
    65_536
}
fn d_secret_input_max_timeout_secs() -> u32 {
    900
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
/// See [`SecretBinding::require_confirm`] for why this is `true`.
fn d_require_confirm() -> bool {
    true
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
    keychain_provider_timeout_secs: d_keychain_provider_timeout_secs,
    max_secret_bytes_ceiling: d_max_secret_bytes_ceiling,
    secret_input_max_timeout_secs: d_secret_input_max_timeout_secs,
}; extra_redaction_patterns, secret_bindings, profiles);

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
            return Err(ConfigError::invalid(format!(
                "limits.read_output_default_max_bytes = {} exceeds \
                 limits.read_output_hard_max_bytes = {}",
                l.read_output_default_max_bytes, l.read_output_hard_max_bytes
            )));
        }

        // I-9's second half (milestone-review.md:453). `MAX_FRAME_BYTES`
        // is enforced on the *encoded, post-redaction* response
        // (`daemon::server::write_response`) and it **rejects**, so a
        // buffer cap that reaches it guarantees every response built at
        // that size is refused at the wire — not a slow degradation, a
        // hard failure on the first oversized read. This is the
        // cross-check `write_response`'s doc comment names as still
        // owed.
        //
        // **Do not size the headroom off the cap alone; redaction can
        // make the encoded body *larger* than the raw bytes that went
        // in.** A `[REDACTED:<kind>]` marker is sized by the rule's
        // *kind*, never by what it replaces, so a short secret can grow.
        // Worked from `data/redaction_default.toml`, not asserted: the
        // worst case is `database-connection-password` (kind
        // `connection-string`, the longest kind name shipped, so the
        // widest marker — `[REDACTED:connection-string]` is 28 bytes).
        // Its minimum match is `amqp://a:x@` (11 bytes: the shortest
        // scheme the rule accepts, a 1-byte user, a 1-byte password —
        // the pattern requires at least one byte of each, never zero).
        // Redacting just the password leaves the 10 bytes of context
        // (`amqp://a:` + `@`) untouched and appends the 28-byte marker:
        // 38 bytes from 11, a ~3.45x ratio — and because the match ends
        // on a word boundary the same as it started, that string tiles
        // back-to-back with no separator, so ~3.45x is the ratio for a
        // buffer built *entirely* from the worst case, not just for one
        // occurrence in it. No other rule in the shipped set comes
        // close: every other rule's fixed context is longer, its kind
        // name shorter, or its minimum value longer, and several rules
        // shrink outright (`AKIAIOSFODNN7EXAMPLE`, 20 bytes, becomes
        // `[REDACTED:aws]`, 14).
        //
        // Rounded up to a flat 4x for a plain number and a safety
        // margin over the derived 3.45x, so a buffer at the ceiling
        // below cannot cross `MAX_FRAME_BYTES` even if every byte in it
        // is the worst case, with the remaining ~12 MiB absorbing the
        // response envelope's own few hundred bytes many times over.
        // `resource_read_max_bytes`'s shipped default (4 MiB) is
        // already exactly `MAX_FRAME_BYTES / 4` (§10.2) — this turns
        // that from a coincidence the next edit could silently break
        // into a named, enforced invariant.
        //
        // **Refused, not clamped.** A clamp would silently substitute a
        // smaller cap than the one the operator wrote and put a stale
        // number in front of them on every read; refusing at startup —
        // this project's standing preference over detect-and-repair —
        // means the config they believe is in force is the config that
        // is. See `trust_verdict`'s doc comment for the same call made
        // the same way a few functions up.
        let frame_headroom_ceiling = MAX_FRAME_BYTES / 4;
        at_most(
            "limits.output_buffer_bytes",
            l.output_buffer_bytes,
            frame_headroom_ceiling,
        )?;
        at_most(
            "limits.resource_read_max_bytes",
            l.resource_read_max_bytes,
            frame_headroom_ceiling,
        )?;

        // `PatternSet::build` enforces this too, as a
        // `HoldfastError::InvalidPattern` from another layer. Validated here
        // as well, with the count in the message, so an over-long list is
        // a named config fault rather than an error the operator has to
        // trace back to a key.
        if self.prompts.extra_patterns.len() > MAX_EXTRA_PATTERNS {
            return Err(ConfigError::invalid(format!(
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
        // §9.6, REQ-SEC-014. Autofill resolves from a credential store,
        // and `prompt` is the mode that has none: the combination reads
        // as "on" and behaves as "off", for the single most consequential
        // switch in the file. Naming **both** keys is the point — an
        // operator who set one of them cannot see from the other's line
        // that the pair is the fault.
        if self.security.autofill_on_echo_off && self.security.secret_provider == "prompt" {
            return Err(ConfigError::invalid(
                "security.autofill_on_echo_off = true requires \
                 security.secret_provider = \"keychain\" or \"both\"; it is \"prompt\", \
                 which resolves no credential and would leave autofill silently off",
            ));
        }
        // §9.6's session profiles (GH #46). **Before the bindings**,
        // because a binding names a profile and the name check below has
        // nothing to check against until this loop has established what
        // the declared set is.
        //
        // Every rule lives in `secret::profile::validate` beside the
        // substitution it constrains — one function, so the thing checked
        // at load is the thing rendered at `start_session` (GH #50's
        // lesson, generalised). What is checked *here* is the pair of
        // properties only this loop can see: the name is non-empty, and it
        // is unique.
        let mut profile_names: BTreeSet<&str> = BTreeSet::new();
        for profile in &self.security.profiles {
            if profile.name.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "security.profiles[].name must not be empty",
                ));
            }
            if !profile_names.insert(profile.name.as_str()) {
                // Refused rather than last-wins: with two profiles of one
                // name, a binding attaches to whichever the loader kept,
                // and an operator reading the file cannot tell which that
                // was.
                return Err(ConfigError::invalid(format!(
                    "security.profiles[\"{}\"] is declared twice; a profile name is what a \
                     binding and a start_session call name, so it must identify one profile",
                    profile.name
                )));
            }
            if let Err(fault) = crate::secret::profile::validate(profile) {
                return Err(ConfigError::invalid(format!(
                    "security.profiles[\"{}\"]{fault}",
                    profile.name
                )));
            }
        }
        // A typo'd binding that never matches is indistinguishable from a
        // credential store that is down, so an uncompilable pattern stops
        // the daemon rather than becoming a binding that quietly does
        // nothing.
        for binding in &self.security.secret_bindings {
            // §9.6 reads an empty `match_prompt` as "this binding does not
            // select on the prompt"; the empty regex compiles and matches
            // everything, so it is not special-cased here. It is compiled
            // **bare**, because `secret::binding::matches` compiles it
            // bare — its subject is a line, not a whole command line, and
            // it is deliberately unanchored.
            if let Err(e) = regex::Regex::new(&binding.match_prompt) {
                return Err(ConfigError::invalid(format!(
                    "security.secret_bindings[\"{}\"].match_prompt = {:?} is not a \
                     valid regex: {e}",
                    binding.name, binding.match_prompt
                )));
            }
            // **Rule 5's second half (GH #46).** A binding attaches to a
            // profile by name, and a name the config does not declare is a
            // binding that can never fire — which from the outside is
            // indistinguishable from a credential store that is down, the
            // same argument the `match_prompt` compile above makes.
            //
            // What used to sit here was GH #45's `match_command` /
            // `match_example` corpus: the pattern compiled through
            // `whole_line`, then judged against a fixed set of hostile
            // rewrites of the operator's example. It is **deleted** rather
            // than left dormant. Four guard shapes over that pair failed,
            // and the last got weaker as it got larger; keeping it as a
            // second line would keep a surface whose whole premise —
            // classifying a string the agent wrote in full — is the thing
            // profiles remove. `crate::secret::profile`'s header is where
            // that argument lives.
            if !self
                .security
                .profiles
                .iter()
                .any(|p| p.name == binding.profile)
            {
                return Err(ConfigError::invalid(format!(
                    "security.secret_bindings[\"{}\"].profile = {:?} names no \
                     [[security.profiles]] entry; a binding attaches to a profile the \
                     operator declared, and one that names nothing could never fire",
                    binding.name, binding.profile
                )));
            }
        }

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
                return Err(ConfigError::invalid(format!(
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
                return Err(ConfigError::invalid("adapters[].name must not be empty"));
            }
        }
        for binding in &self.security.secret_bindings {
            if binding.name.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "security.secret_bindings[].name must not be empty",
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
    /// watches the rule set `HoldfastServer` actually hands the read path,
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
        return Err(ConfigError::invalid(format!(
            "{key} = 0, but zero is meaningless for this limit"
        )));
    }
    Ok(())
}

fn one_of(key: &str, value: &str, allowed: &[&str]) -> Result<(), ConfigError> {
    if !allowed.contains(&value) {
        return Err(ConfigError::invalid(format!(
            "{key} = \"{value}\", which is not one of {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// **GH #45's probe corpus stood here and is deleted, not dormant (GH #46).**
//
// `Probe`, `ProbeKind` (including round 4's `Infix`), `token_boundaries`,
// the 23 `INSERTIONS`, 3 `PREFIXES` and 2 `REPLACEMENTS`, `hostile_probes`,
// `ExampleFault`, `MATCH_EXAMPLE_REPAIR` and `admits_only_its_example` —
// about 430 lines — went with `match_command` and `match_example`.
//
// It is deleted rather than kept as defence in depth because its premise
// went with it: it approximated *"what does this operator-authored regex
// admit, given that an adversary writes the string it is matched
// against"*, and there is no longer such a string. Keeping it would keep
// a surface that four rounds proved cannot be finished, guarding a field
// nothing reads.
//
// `secret::binding::whole_line` is **kept**, because slot patterns need
// it — the anchoring was the half of GH #45 that was right.
// ---------------------------------------------------------------------

/// `value` must leave headroom under a wire cap. See the I-9 comment in
/// [`Config::validate`] for what `ceiling` is and why.
fn at_most(key: &str, value: usize, ceiling: usize) -> Result<(), ConfigError> {
    if value > ceiling {
        return Err(ConfigError::invalid(format!(
            "{key} = {value}, which leaves no headroom under the {MAX_FRAME_BYTES}-byte \
             control-protocol frame cap; secret redaction can make a response larger \
             than the bytes that went in, so {key} must stay at or below {ceiling}"
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
        let missing = std::path::Path::new("/nonexistent/holdfast-does-not-exist/config.toml");
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
[[security.profiles]]
name = \"prod-ssh\"
program = \"ssh\"
args = [\"{host}\"]

[security.profiles.vars]
host = \"^prod-0[12]$\"

[[security.secret_bindings]]
name = \"prod-ssh-cred\"
profile = \"prod-ssh\"
match_prompt = \"(?i)password\"
provider = \"secret-service\"
reference = \"service=holdfast,account=prod-ssh\"
max_uses = 20
require_confirm = false
";
        let cfg = parse_str(src).expect("§9.6's binding block must load");
        assert_eq!(cfg.security.secret_bindings.len(), 1);
        let b = &cfg.security.secret_bindings[0];
        assert_eq!(b.name, "prod-ssh-cred");
        assert_eq!(b.profile, "prod-ssh");
        assert_eq!(b.provider, "secret-service");
        assert_eq!(b.max_uses, Some(20));
        assert!(!b.require_confirm);
    }

    // ------------------------------------------ §9.6's session profiles
    //
    // GH #46. The substitution and its rules live in
    // `crate::secret::profile`, with its own rows; what is asserted here
    // is the **config surface** — that §10.2's published block loads, and
    // that each rule reaches `Config::validate` and refuses with a
    // message naming the key.

    /// §10.2's `[[security.profiles]]` block, **uncommented out of the
    /// published example rather than re-typed** (Global Constraint 15).
    ///
    /// §10.2 is *"the most copied block in the document and the least
    /// swept"*, and a remembered fixture drifts silently. This one cannot:
    /// it is the bytes of `example_config.toml`, which
    /// `the_published_example_config_loads` already pins against the
    /// document, with the comment markers taken off exactly as an operator
    /// takes them off.
    ///
    /// The selection rule is *"a line that is TOML after uncommenting"* —
    /// a table header or a `key =`. The prose lines between the keys are
    /// what the operator skips, and the guard against a mis-selection is
    /// that the result is **parsed and its values asserted**, so a
    /// heuristic that swallowed a sentence fails here rather than
    /// producing a fixture nobody checked.
    fn spec_profile_block() -> String {
        let mut out: Vec<String> = Vec::new();
        let mut inside = false;
        for line in EXAMPLE.lines() {
            let Some(bare) = line.strip_prefix('#') else {
                continue;
            };
            let bare = bare.strip_prefix(' ').unwrap_or(bare);
            if bare.trim() == "[[security.profiles]]" {
                inside = true;
            }
            if !inside {
                continue;
            }
            let t = bare.trim_start();
            let is_toml = t.starts_with('[')
                || t.split('=').next().is_some_and(|k| {
                    !k.is_empty()
                        && k.trim() == k.trim_end()
                        && k.trim_end()
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && !k.trim_end().is_empty()
                        && k.contains(char::is_alphabetic)
                        && t.contains('=')
                });
            if is_toml {
                out.push(bare.to_string());
            }
            if t.starts_with("host") {
                break;
            }
        }
        assert!(
            out.iter().any(|l| l.trim() == "[[security.profiles]]"),
            "the published example no longer carries a `[[security.profiles]]` block"
        );
        out.join("\n")
    }

    /// The block an operator actually uncomments, loaded rather than read
    /// by eye.
    #[test]
    fn the_published_profile_block_loads() {
        let src = spec_profile_block();
        let cfg = parse_str(&src)
            .unwrap_or_else(|e| panic!("§10.2's profile block must load; got {e}\n---\n{src}"));
        assert_eq!(cfg.security.profiles.len(), 1, "{src}");
        let p = &cfg.security.profiles[0];
        assert_eq!(p.name, "prod-ssh");
        assert_eq!(p.program, "ssh");
        assert_eq!(p.args, vec!["{user}@{host}"]);
        assert_eq!(p.vars.len(), 2, "{:?}", p.vars);
        assert_eq!(p.vars["host"], "^prod-0[12]$");
        assert_eq!(p.vars["user"], "^[a-z][a-z0-9_-]{0,30}$");
        cfg.validate().expect("and it must validate");
    }

    /// A `[[security.profiles]]` block for the rows below, spelled with
    /// TOML **multi-line literal** strings so a row may carry `'`, `"` and
    /// a backslash without an escaping scheme of its own.
    fn profile_block(name: &str, program: &str, args: &[&str], vars: &[(&str, &str)]) -> String {
        let args = args
            .iter()
            .map(|a| format!("'''{a}'''"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut src = format!(
            "[[security.profiles]]\nname = '''{name}'''\nprogram = '''{program}'''\n\
             args = [{args}]\n"
        );
        if !vars.is_empty() {
            src.push_str("\n[security.profiles.vars]\n");
            for (k, v) in vars {
                src.push_str(&format!("{k} = '''{v}'''\n"));
            }
        }
        src
    }

    /// `parse_str` runs `Config::validate` itself, so a refusal is
    /// whatever the loader an operator's daemon uses would have said.
    fn profile_refusal(src: &str) -> String {
        parse_str(src)
            .map(|_| ())
            .expect_err("this profile must not load")
            .to_string()
    }

    /// **Rule 1.** If the agent could influence the program it chooses the
    /// binary, and no pattern over an *argument* can bound that.
    #[test]
    fn a_slot_in_program_is_a_load_error_naming_the_key() {
        let msg = profile_refusal(&profile_block(
            "prod-ssh",
            "{prog}",
            &["{host}"],
            &[("host", "^prod-0[12]$")],
        ));
        assert!(msg.contains("program"), "{msg}");
        assert!(
            msg.contains("prod-ssh"),
            "the message must name the profile: {msg}"
        );
        // The pairing that keeps the rule from being "refuse everything":
        // the same block with a literal program loads.
        let ok = profile_block("prod-ssh", "ssh", &["{host}"], &[("host", "^prod-0[12]$")]);
        parse_str(&ok).expect("parses").validate().expect("loads");
    }

    /// **Rule 2, first direction.** A slot with no `vars` entry could never
    /// be filled, so the profile could never start — and nothing would
    /// bound what filled it if it could.
    #[test]
    fn a_slot_with_no_vars_entry_is_a_load_error_naming_the_key() {
        let msg = profile_refusal(&profile_block(
            "prod-ssh",
            "ssh",
            &["{user}@{host}"],
            &[("host", "^prod-0[12]$")],
        ));
        assert!(msg.contains("user"), "{msg}");
        assert!(msg.contains("prod-ssh"), "{msg}");
    }

    /// **Rule 2, second direction.** An unused var is a typo, and the
    /// operator should learn it at startup rather than at 3am.
    #[test]
    fn a_vars_entry_no_slot_uses_is_a_load_error_naming_the_key() {
        let msg = profile_refusal(&profile_block(
            "prod-ssh",
            "ssh",
            &["{host}"],
            &[("host", "^prod-0[12]$"), ("hsot", "^x$")],
        ));
        assert!(msg.contains("hsot"), "{msg}");
        assert!(msg.contains("prod-ssh"), "{msg}");
    }

    /// **Rule 3.** Compiled through `secret::binding::whole_line`, the
    /// same wrap the renderer applies — GH #50 was two compiles that could
    /// disagree about whether the operator had written a regex at all.
    #[test]
    fn a_slot_pattern_that_does_not_compile_is_a_load_error_naming_the_key() {
        let msg = profile_refusal(&profile_block(
            "prod-ssh",
            "ssh",
            &["{host}"],
            &[("host", "^prod-0(")],
        ));
        assert!(msg.contains("host"), "{msg}");
        assert!(msg.contains("prod-ssh"), "{msg}");
        assert!(msg.contains("regex"), "{msg}");
    }

    /// **Rule 5, first half.** A profile name is what a binding and a
    /// `start_session` call name, so it has to identify one profile.
    #[test]
    fn two_profiles_with_one_name_are_refused() {
        let mut src = profile_block("prod-ssh", "ssh", &["{host}"], &[("host", "^prod-01$")]);
        src.push_str(&profile_block(
            "prod-ssh",
            "psql",
            &["{host}"],
            &[("host", "^prod-02$")],
        ));
        let msg = profile_refusal(&src);
        assert!(msg.contains("prod-ssh"), "{msg}");
        assert!(msg.contains("twice"), "{msg}");
        // And two *differently* named profiles load, so the rule is about
        // the collision rather than about there being two.
        let mut ok = profile_block("prod-ssh", "ssh", &["{host}"], &[("host", "^prod-01$")]);
        ok.push_str(&profile_block(
            "prod-db",
            "psql",
            &["{host}"],
            &[("host", "^prod-02$")],
        ));
        parse_str(&ok).expect("parses").validate().expect("loads");
    }

    #[test]
    fn an_empty_profile_name_is_refused() {
        let msg = profile_refusal(&profile_block(
            "   ",
            "ssh",
            &["{host}"],
            &[("host", "^prod-01$")],
        ));
        assert!(msg.contains("security.profiles[].name"), "{msg}");
    }

    /// A brace that opens nothing is a typo in a slot name. Treating it as
    /// a literal would leave the operator with a template whose slot never
    /// gets filled and a `vars` pattern nothing consults.
    #[test]
    fn a_malformed_slot_is_a_load_error_naming_the_argument() {
        let msg = profile_refusal(&profile_block(
            "prod-ssh",
            "ssh",
            &["{host"],
            &[("host", "^prod-01$")],
        ));
        assert!(msg.contains("args[0]"), "{msg}");
        assert!(msg.contains("prod-ssh"), "{msg}");
    }

    /// An unknown key inside a profile is a load error like every other
    /// unknown key (§10.1) — so a `match_command` an operator carried over
    /// from rev. 54 fails loudly rather than sitting there doing nothing.
    #[test]
    fn an_unknown_key_inside_a_profile_is_rejected() {
        let src = "[[security.profiles]]\nname = \"p\"\nprogram = \"ssh\"\nargz = []\n";
        let e = parse_str(src).expect_err("an unmodelled key must not be ignored");
        assert!(e.to_string().contains("argz"), "{e}");
    }

    /// **`require_confirm` defaults to `true`** (GH #45).
    ///
    /// A binding that omits the key resolves a credential into a child
    /// **after** a human has seen the command line, not before. It
    /// defaulted `false` through 0.0.7, which made silent resolution what
    /// an operator got by leaving a line out — of a key whose whole job is
    /// to put a person in front of a decision about a command line the
    /// agent wrote.
    ///
    /// **Both directions, because a default is only a default if the
    /// explicit value still wins.** A validator that ignored the key and
    /// forced `true` would pass a one-sided row, and would silently
    /// override every operator who had written `false` on purpose.
    #[test]
    fn require_confirm_defaults_on() {
        let block = |line: &str| {
            format!(
                "[[security.profiles]]\nname = \"prod-ssh\"\nprogram = \"ssh\"\n\
                 args = ['prod-01']\n\
                 [[security.secret_bindings]]\nname = \"prod-ssh-cred\"\n\
                 profile = \"prod-ssh\"\nmatch_prompt = \"\"\n\
                 provider = \"secret-service\"\nreference = \"r\"\n{line}"
            )
        };
        let omitted = parse_str(&block("")).expect("a binding without the key must load");
        assert!(
            omitted.security.secret_bindings[0].require_confirm,
            "a binding that says nothing about `require_confirm` resolves a credential \
             with no human in the loop"
        );
        // The pairing. An operator who wrote `false` meant `false`.
        let off = parse_str(&block("require_confirm = false\n")).expect("load");
        assert!(!off.security.secret_bindings[0].require_confirm);
        let on = parse_str(&block("require_confirm = true\n")).expect("load");
        assert!(on.security.secret_bindings[0].require_confirm);
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
        let paths = crate::daemon::RuntimePaths::with_dir("/tmp/holdfast-config-log-dir-probe");
        assert_eq!(
            paths.log_dir(),
            std::path::Path::new("/tmp/holdfast-config-log-dir-probe/logs"),
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

    /// §4.2 and §9.6's defaults, **as literals**.
    ///
    /// Every value below is written out rather than compared to its own
    /// `d_*` function: `assert_eq!(cfg.security.autofill_on_echo_off,
    /// d_autofill_on_echo_off())` is the default compared to itself and
    /// stays green through any change to it, which is precisely the
    /// mutation REQ-SEC-014 names by hand.
    #[test]
    fn the_security_defaults_are_the_ones_the_spec_states() {
        // An *empty* config, not `Config::default()`: this has to be the
        // value an operator with no `[security]` table gets, which is a
        // property of the serde attributes rather than of the `Default`
        // impl. The two are wired to the same `d_*` fns and can still
        // disagree — a missing `#[serde(default = …)]` is a load error,
        // and a missing `table_default!` row is `E0063`, but a row
        // pointing at the *wrong* fn is neither.
        let cfg = parse_str("").expect("an empty config is all defaults");
        let s = &cfg.security;

        assert_eq!(s.secret_provider, "prompt");
        assert!(
            !s.autofill_on_echo_off,
            "REQ-SEC-014: silent credential injection is opt-in per deployment"
        );
        assert!(s.secret_bindings.is_empty());
        assert!(s.redaction_enabled);
        assert!(!s.strict_confirmation);
        assert_eq!(s.keychain_provider_timeout_secs, 10);
        assert_eq!(s.max_secret_bytes_ceiling, 65_536);
        assert_eq!(s.secret_input_max_timeout_secs, 900);

        // §10.2 sites this one under `[daemon]`, not `[security]` — the
        // siting is odd and is the plan's Q14, but `deny_unknown_fields`
        // makes the table name load-bearing, so a reader looking for it
        // beside its siblings has to be told where it actually is.
        assert_eq!(cfg.daemon.binding_approval_timeout_secs, 120);

        // And the same values through `Default`, which is the path every
        // in-process host takes.
        let d = Config::default();
        assert_eq!(d.security, cfg.security);
        assert_eq!(
            d.daemon.binding_approval_timeout_secs,
            cfg.daemon.binding_approval_timeout_secs
        );
    }

    /// The per-field fold, from the direction that actually bites.
    ///
    /// A section-level default rebuilds `SecurityConfig` whenever any one
    /// of its keys is present, which is the shape a hand-written fold
    /// reaches for — and it takes `secret_bindings` with it, silently
    /// disarming every operator binding on the box.
    #[test]
    fn setting_one_security_knob_does_not_clear_the_bindings() {
        const TWO_BINDINGS: &str = "\
[[security.profiles]]
name = \"prod-ssh\"
program = \"ssh\"
args = [\"prod-01\"]

[[security.profiles]]
name = \"prod-db\"
program = \"psql\"
args = [\"-h\", \"prod\"]

[[security.secret_bindings]]
name = \"prod-ssh-cred\"
profile = \"prod-ssh\"
match_prompt = \"(?i)password\"
provider = \"secret-service\"
reference = \"service=holdfast,account=prod-ssh\"

[[security.secret_bindings]]
name = \"prod-db-cred\"
profile = \"prod-db\"
match_prompt = \"\"
provider = \"pass\"
reference = \"db/prod\"
";
        // A sibling scalar set in the same table as the array.
        let with_knob = parse_str(&format!(
            "[security]\nsecret_provider = \"both\"\n{TWO_BINDINGS}"
        ))
        .expect("a sibling knob beside two bindings must load");
        assert_eq!(with_knob.security.secret_provider, "both");
        assert_eq!(
            with_knob.security.secret_bindings.len(),
            2,
            "setting one `[security]` key cleared the bindings — the fold is per section, \
             not per field"
        );
        assert_eq!(with_knob.security.secret_bindings[1].name, "prod-db-cred");
        assert_eq!(
            with_knob.security.profiles.len(),
            2,
            "the same fold reaches `profiles`, and a binding whose profile went with it \
             stops loading at all"
        );

        // **The pairing.** Without it this test is satisfied by a loader
        // that never folds at all — one that ignores `secret_provider`
        // and leaves the bindings alone by doing nothing.
        let without_knob =
            parse_str(TWO_BINDINGS).expect("bindings with no sibling knob must load");
        assert_eq!(without_knob.security.secret_bindings.len(), 2);
        assert_eq!(
            without_knob.security.secret_provider, "prompt",
            "the knob-free config must still carry the default, or the assertion above \
             is about a loader that reads no knobs"
        );
    }

    /// REQ-CFG-003, at the value level. The socket half — that a daemon
    /// carrying this config binds nothing — is
    /// `autofill_without_a_keychain_provider_stops_the_daemon` in
    /// `crates/holdfast/tests/daemon_cli.rs`, because both a rejection
    /// and a warning print something and only one leaves no socket.
    #[test]
    fn autofill_without_a_keychain_provider_is_rejected() {
        let e =
            parse_str("[security]\nautofill_on_echo_off = true\nsecret_provider = \"prompt\"\n")
                .expect_err(
                    "a switch that reads as \"on\" and behaves as \"off\" is the failure \
                 REQ-CFG-003 refuses",
                );
        let msg = e.to_string();
        // **Both** keys. An operator who set one of them cannot see from
        // the other's name alone that the *pair* is the fault.
        assert!(
            msg.contains("autofill_on_echo_off"),
            "the error must name the key that was set: {msg}"
        );
        assert!(
            msg.contains("secret_provider"),
            "the error must name the key that made it invalid: {msg}"
        );

        // **The pairing, and without it the rule is \"autofill is never
        // allowed\".** Both keychain-bearing modes must start cleanly.
        for provider in ["keychain", "both"] {
            let cfg = parse_str(&format!(
                "[security]\nautofill_on_echo_off = true\nsecret_provider = \"{provider}\"\n"
            ))
            .unwrap_or_else(|e| panic!("autofill with secret_provider = {provider:?}: {e}"));
            assert!(cfg.security.autofill_on_echo_off);
        }
        // And the default `prompt` with autofill *off* is the shipped
        // configuration; a rule that rejected it would reject every
        // stock install.
        assert!(parse_str("[security]\nsecret_provider = \"prompt\"\n").is_ok());
    }

    /// An operator's typo must not become a binding that silently never
    /// matches — which is indistinguishable from a credential store that
    /// is down.
    #[test]
    fn a_binding_whose_regex_does_not_compile_is_rejected() {
        // `match_prompt` is the **only** regex a binding carries since GH
        // #46 took `match_command` away. It is still validated, and for
        // the same reason: it is a conjunct, so a pattern that cannot
        // compile makes the whole binding unselectable.
        let with_prompt = |value: &str| {
            let mut src =
                profile_block("prod-ssh", "ssh", &["{host}"], &[("host", "^prod-0[12]$")]);
            src.push_str(&format!(
                "[[security.secret_bindings]]\nname = \"prod-ssh-cred\"\n\
                 profile = \"prod-ssh\"\nmatch_prompt = '''{value}'''\n\
                 provider = \"secret-service\"\nreference = \"r\"\n"
            ));
            src
        };
        let msg = profile_refusal(&with_prompt("^ssh ("));
        assert!(
            msg.contains("match_prompt"),
            "the error must name the field: {msg}"
        );
        assert!(
            msg.contains("prod-ssh-cred"),
            "the error must name the binding, or an operator with six of them \
             cannot find it: {msg}"
        );

        // **The pairing.** A shape that *does* compile must load, or the
        // rule has become "no bindings". The **empty** `match_prompt` is
        // the case a naive non-empty check would break: §9.6 reads it as
        // "this binding does not select on the prompt".
        let ok = parse_str(&with_prompt("")).expect("a valid binding must load");
        assert_eq!(ok.security.secret_bindings.len(), 1);
        assert_eq!(ok.security.secret_bindings[0].match_prompt, "");
        let narrowing =
            parse_str(&with_prompt("(?i)password")).expect("a real prompt pattern must load");
        assert_eq!(
            narrowing.security.secret_bindings[0].match_prompt,
            "(?i)password"
        );
    }

    /// A `[[security.secret_bindings]]` block naming one profile, for the
    /// rows whose subject is the binding rather than the profile.
    fn binding_for(profile: &str) -> String {
        format!(
            "[[security.secret_bindings]]\nname = \"prod-ssh-cred\"\n\
             profile = '''{profile}'''\n\
             match_prompt = \"\"\n\
             provider = \"secret-service\"\nreference = \"r\"\n"
        )
    }

    /// **Rule 5's second half (GH #46).** A binding attaches to a profile
    /// by name; one naming a profile the config does not declare could
    /// never fire, which from the outside is indistinguishable from a
    /// credential store that is down.
    ///
    /// This is where GH #45's ~430-line probe corpus used to be exercised
    /// — 68 refusals, 23 acceptances, 51 probes across four categories,
    /// and a `TAILORED_TO_THE_CORPUS` row recording the dodge none of it
    /// could close. All of it went with `match_command` and
    /// `match_example`. What replaces it is a name comparison, and the
    /// reason that is enough is not that the check got better: it is that
    /// the thing being checked is now a string the **operator** wrote.
    #[test]
    fn a_binding_naming_an_unknown_profile_is_refused() {
        let mut src = profile_block("prod-ssh", "ssh", &["{host}"], &[("host", "^prod-0[12]$")]);
        src.push_str(&binding_for("prod-sshh"));
        let msg = profile_refusal(&src);
        assert!(msg.contains("prod-sshh"), "{msg}");
        assert!(
            msg.contains("prod-ssh-cred"),
            "the error must name the binding, or an operator with six of them cannot \
             find it: {msg}"
        );

        // **The pairing**, without which the rule above is satisfied by a
        // validator that refuses every binding. The same block with the
        // name spelled correctly loads.
        let mut ok = profile_block("prod-ssh", "ssh", &["{host}"], &[("host", "^prod-0[12]$")]);
        ok.push_str(&binding_for("prod-ssh"));
        let cfg = parse_str(&ok).expect("a binding naming a declared profile must load");
        assert_eq!(cfg.security.secret_bindings.len(), 1);
        assert_eq!(cfg.security.secret_bindings[0].profile, "prod-ssh");

        // And a binding with **no profiles declared at all** is the same
        // fault, which is the shape an operator upgrading from rev. 54
        // actually meets.
        let alone = profile_refusal(&binding_for("prod-ssh"));
        assert!(alone.contains("prod-ssh"), "{alone}");
    }

    /// **GH #50, re-sited onto the surface that still uses `whole_line`.**
    ///
    /// The defect was that `Config::validate` compiled the operator's
    /// pattern *bare* while the matcher compiled it *wrapped*, so the two
    /// could disagree about whether it was even a regex and the daemon
    /// would start with a rule that could never fire. `match_command` is
    /// gone; slot patterns are wrapped by the same `whole_line` at load
    /// and at render, so the same defect is available and the same row
    /// closes it.
    ///
    /// The witness is a free-spacing pattern ending in a `#` comment.
    /// Bare, it compiles. Wrapped, the comment runs to end of line and
    /// swallows the `)\z` the wrapper appended, so it does not.
    #[test]
    fn a_slot_pattern_that_compiles_bare_but_not_wrapped_is_a_load_error() {
        const COMMENTED: &str = "(?x)^prod-0[12]  # whichever box";
        regex::Regex::new(COMMENTED).expect(
            "the premise: bare, this compiles, which is why a bare check would let it \
             through",
        );
        assert!(
            regex::Regex::new(&crate::secret::binding::whole_line(COMMENTED)).is_err(),
            "the pairing: wrapped, it does not — if this ever compiles, the row below \
             is asserting nothing"
        );
        let e = profile_refusal(&profile_block(
            "prod-ssh",
            "ssh",
            &["{host}"],
            &[("host", COMMENTED)],
        ));
        assert!(e.contains("host"), "{e}");
        assert!(e.contains("prod-ssh"), "{e}");
    }

    /// The `regex` behaviour `secret::binding::whole_line` is built on,
    /// asserted here so a crate upgrade that changes it fails **loudly**
    /// rather than silently widening every operator's binding.
    ///
    /// **This row exists because the thing it pins cannot be pinned any
    /// other way.** `whole_line` wraps an operator's pattern in
    /// `\A(?:…)\z` rather than `^(?:…)$`, and in `regex` 1.13.1 those two
    /// are *behaviourally identical* — `$` is end-of-haystack with
    /// multi-line off, not Perl's "before a final newline". So no
    /// behavioural test can tell the two spellings apart, and a review
    /// that mutated one into the other correctly found the whole suite
    /// still green.
    ///
    /// `\A`/`\z` is still the right spelling: it says what it means
    /// whatever flags an operator sets inside the group, and it does not
    /// depend on a crate default that could move. This row is what makes
    /// the second half of that sentence checkable.
    #[test]
    fn this_crates_dollar_is_end_of_text_not_end_of_line() {
        let dollar = regex::Regex::new("^abc$").expect("compiles");
        assert!(dollar.is_match("abc"));
        assert!(
            !dollar.is_match("abc\n"),
            "`$` now matches before a trailing newline, as Perl's does. \
             `secret::binding::whole_line` uses `\\A`/`\\z` and is unaffected — but \
             anything in this tree that anchors with `^`/`$` needs re-reading, and \
             every operator's slot pattern ending in `$` now admits a value with a \
             trailing newline on it."
        );
        assert!(!dollar.is_match("abc\nx"));
        // The pairing: `\z` agrees with `$` today, which is the fact that
        // makes the two wrappings indistinguishable by behaviour.
        let z = regex::Regex::new(r"\Aabc\z").expect("compiles");
        assert!(z.is_match("abc"));
        assert!(!z.is_match("abc\n"));
        // And `\Z` is not a thing here: a slot pattern carrying one is
        // refused by `secret::profile::validate`'s compile check, which
        // wraps through the same `whole_line`. (Round 2's
        // `strip_inert_tail` used to be the reason this mattered; it was
        // deleted with the rest of the scanner in `624c1e6`, and the
        // corpus that replaced it went with `match_command` at GH #46.)
        //
        // **Assembled at run time rather than written as a literal**, and
        // that is not obfuscation for its own sake: clippy's
        // `invalid_regex` lint reads literal arguments and refuses to
        // compile the very expression this row exists to evaluate. Two
        // independent checkers agreeing that `\Z` is not valid here is
        // the finding, so the row keeps the run-time half and this
        // comment keeps the compile-time one.
        let upper_z = format!(r"\Aabc\{}", 'Z');
        assert!(
            regex::Regex::new(&upper_z).is_err(),
            "`\\Z` compiles now, so a slot pattern can end in one and mean something \
             other than end-of-text instead of being refused as an invalid regex"
        );
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

    // ------------------------------------------ I-9's second half (headroom)

    /// A buffer cap that reaches the wire cap is rejected at load, not
    /// discovered the first time a session produces enough output to hit
    /// it.
    ///
    /// The value under test is exactly [`MAX_FRAME_BYTES`] itself, and
    /// that choice is the point: a validator written as "reject anything
    /// *over* the wire cap" — the `cap it at 16 MiB` mistake the fix
    /// this test guards was warned away from — would wave this value
    /// through, since it does not exceed the cap, it *is* the cap. Only
    /// a check that requires real headroom under `MAX_FRAME_BYTES`
    /// catches it, which is the difference this row exists to pin down.
    /// The literal is [`MAX_FRAME_BYTES`] itself rather than a value
    /// derived from whatever ceiling `Config::validate` computes
    /// internally, so this test does not share an expression with the
    /// code it is checking.
    #[test]
    fn a_buffer_cap_at_the_frame_cap_is_rejected() {
        for key in ["output_buffer_bytes", "resource_read_max_bytes"] {
            let src = format!("[limits]\n{key} = {MAX_FRAME_BYTES}\n");
            let e = parse_str(&src).expect_err(&format!(
                "{key} at the wire cap must be rejected, not silently accepted"
            ));
            let msg = e.to_string();
            assert!(msg.contains(key), "the error must name the key: {msg}");
        }
    }

    /// The pairing, and the negative control the row above needs: absent
    /// it, a validator that rejects every buffer cap — not just ones
    /// that reach the wire cap — would pass the positive row perfectly.
    /// This is [`Config::default`] under [`Config::validate`] directly,
    /// not a round trip through TOML: `load_from`'s missing-file and
    /// `load`'s no-discoverable-path arms both return
    /// `Ok(Config::default())` without ever calling `validate`, so a
    /// round trip through those entry points would not exercise this
    /// clause at all.
    #[test]
    fn the_shipped_buffer_defaults_clear_the_headroom_check() {
        let cfg = Config::default();
        assert_eq!(cfg.limits.output_buffer_bytes, d_output_buffer_bytes());
        assert_eq!(
            cfg.limits.resource_read_max_bytes,
            d_resource_read_max_bytes()
        );
        cfg.validate()
            .expect("the shipped defaults must clear the new headroom check");
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
        //     the key where `HoldfastServer` assembles its
        //     `OutputProcessor` never touches `redaction_rules()`, and
        //     only this second observation catches it.
        let from_config = cfg.redaction_rules().expect("built-in rules compile");
        let server = crate::mcp::HoldfastServer::with_audit_path_and_config(None, &cfg);

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
            Some(PathBuf::from("/x/holdfast/config.toml"))
        );
        assert_eq!(
            config_path_from(None, Some("/h".into())),
            Some(PathBuf::from("/h/.config/holdfast/config.toml")),
        );
        // An empty XDG_CONFIG_HOME is no instruction, not an empty base.
        assert_eq!(
            config_path_from(Some("".into()), Some("/h".into())),
            Some(PathBuf::from("/h/.config/holdfast/config.toml")),
        );
        assert_eq!(config_path_from(None, None), None);
    }

    #[test]
    fn config_discovery_ignores_the_runtime_dir_variable() {
        // REQ-CFG-005 makes `HOLDFAST_RUNTIME_DIR` instance selection, not
        // a configuration knob. Wiring config discovery to it would
        // recreate exactly the override REQ-CFG-001 forbids.
        let derived = config_path_from(Some("/x".into()), Some("/h".into())).unwrap();
        assert!(
            !derived.to_string_lossy().contains("runtime"),
            "config discovery must not read HOLDFAST_RUNTIME_DIR"
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

    // -------------------------------------------- §9.2 on the error path

    /// A credential in the shape `data/redaction_default.toml`'s own
    /// `github-token` positive example uses. Not a live token.
    const CREDENTIAL: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    /// Nothing an operator typed into `config.toml` reaches a diagnostic
    /// unredacted — on **either** path a bad config can take.
    ///
    /// The shape rather than the finding. I-1 was reported against the
    /// parse path, where `toml`'s caret diagram renders the whole
    /// offending line; the validation path is the same disclosure with a
    /// different producer, because §10.1 has those messages name the
    /// value on purpose. A row asserting only that the error is
    /// non-empty, or only that it names the key, passes against exactly
    /// the `eprintln!` chain that put a token in `daemon.log`.
    #[test]
    fn no_operator_supplied_value_survives_into_an_error_message() {
        for (what, src, still_named) in [
            // `deny_unknown_fields` makes *any* unmodelled key an error,
            // so an operator who invents `api_token` — the shape the
            // review names — takes this path by construction.
            (
                "an unknown key on the parse path",
                format!("[security]\napi_token = \"{CREDENTIAL}\"\n"),
                "api_token",
            ),
            (
                "a rejected enum value on the validation path",
                format!("[notifications]\nsink = \"{CREDENTIAL}\"\n"),
                "notifications.sink",
            ),
        ] {
            let e = parse_str(&src).expect_err(what);
            let msg = e.to_string();
            assert!(
                !msg.contains(CREDENTIAL),
                "{what}: the credential is in the diagnostic verbatim, and this \
                 diagnostic is `daemon.log`-bound: {msg}"
            );
            assert!(
                msg.contains("[REDACTED:"),
                "{what}: the value must be *replaced*, not merely dropped — a \
                 message that silently loses it tells the operator nothing: {msg}"
            );
            assert!(
                msg.contains(still_named),
                "{what}: §10.1 still requires the error to name the key, and a \
                 redactor that ate the diagnostic is not a fix: {msg}"
            );
            // And the chain, which a logger may walk rather than print.
            // A redacted `Display` over a raw `#[source]` is the same
            // disclosure one `{:#}` away.
            let mut cursor = std::error::Error::source(&e);
            while let Some(err) = cursor {
                assert!(
                    !err.to_string().contains(CREDENTIAL),
                    "{what}: `Display` is redacted but the source chain is not: {err}"
                );
                cursor = err.source();
            }
        }
    }

    // ------------------------------------ the file itself as a trust boundary

    /// The half of the check that a stock install has to survive, paired
    /// with the half that has to fire. Without the pairing, a `load_from`
    /// that refused *every* file passes the refusal row perfectly.
    #[test]
    fn a_world_writable_config_is_refused_and_the_modes_a_stock_install_carries_are_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[limits]\nmax_concurrent_sessions = 3\n").expect("write");
        let chmod = |m: u32| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).expect("chmod")
        };

        chmod(0o666);
        let e = load_from(&path).expect_err("any local user can rewrite this file");
        let msg = e.to_string();
        assert!(
            msg.contains("666"),
            "the mode belongs in the message: {msg}"
        );
        assert!(
            msg.contains("world-writable"),
            "and so does what is wrong with it: {msg}"
        );
        // Refused, *not* repaired: the mode on disk is untouched, so the
        // operator can still see what it was. A control that chmods and
        // then proceeds is one whose assertion has stopped meaning
        // anything.
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o666,
            "the refusal tightened the file instead of reporting it"
        );

        // 0664 is the one that decides whether this check refuses a
        // stock install: it is what an editor writes under the `umask
        // 002` Debian, Ubuntu and RHEL ship, and refusing 0775 on
        // `~/.holdfast/logs` for the same reason is a bug this milestone
        // already had to take back once.
        for mode in [0o600, 0o640, 0o644, 0o664] {
            chmod(mode);
            let cfg = load_from(&path)
                .unwrap_or_else(|e| panic!("mode {mode:o} is a stock install; got: {e}"));
            assert_eq!(cfg.limits.max_concurrent_sessions, 3);
        }
    }

    #[test]
    fn a_config_path_that_resolves_to_a_device_is_refused_and_one_that_resolves_to_a_file_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");

        // `/dev/null` is the silent case and the reason this question is
        // asked at all: it reads as an empty document, an empty document
        // parses, and the operator's whole file becomes
        // `Config::default()` with nothing reported. A fifo would be the
        // same check and a worse test — `read_to_string` on one blocks
        // until something writes, so a fifo row would hang rather than
        // fail whenever the check is absent.
        let devnull = dir.path().join("config.toml");
        std::os::unix::fs::symlink("/dev/null", &devnull).expect("symlink");
        let e = load_from(&devnull).expect_err("a device is not a configuration");
        assert!(e.to_string().contains("regular file"), "{e}");

        // The pairing, and the other half of the stock-install question:
        // stow, chezmoi and yadm all symlink `~/.config/**` into a
        // repository, so a symlink that resolves to a regular file the
        // caller owns must load. Refusing symlinks as such would refuse
        // every dotfile-managed install.
        let real = dir.path().join("real.toml");
        std::fs::write(&real, "[limits]\nmax_concurrent_sessions = 5\n").expect("write");
        let link = dir.path().join("linked.toml");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let cfg = load_from(&link).expect("a stow-style symlink to a regular file must load");
        assert_eq!(cfg.limits.max_concurrent_sessions, 5);
    }

    /// The fifo, which the regular-file question alone does not reach.
    ///
    /// Bounded, and here the **timeout is the evidence** rather than a
    /// way of giving up: the failure being guarded against is a daemon
    /// that never starts, so an unbounded `load_from` on this path would
    /// hang CI instead of reddening it. Opening a fifo for reading waits
    /// for a writer, which is *before* any `fstat` the check could do —
    /// so this is not the same row as `/dev/null` and a check that only
    /// looked at metadata would never get to run.
    #[test]
    fn a_config_path_that_resolves_to_a_fifo_does_not_block_startup() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path has no NUL");
        // SAFETY: `mkfifo` takes a NUL-terminated path and a mode, and
        // `c` outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");

        let (tx, rx) = std::sync::mpsc::channel();
        let probe = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(load_from(&probe).is_err());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(refused) => assert!(refused, "a fifo is not a configuration"),
            Err(_) => panic!(
                "`load_from` is still blocked in `open`, with no writer coming: that \
                 is a daemon that never starts and never says why"
            ),
        }
    }

    /// Ownership, against uids this process cannot create.
    ///
    /// An unprivileged test cannot `chown`, so this row is asserted
    /// against the verdict rather than through `load_from`. Being
    /// honest about what that costs: unlike the two rows above, this one
    /// could not have failed before the check existed, because the
    /// function it calls is part of the fix. It is a guard on the
    /// thresholds, not the discriminator for the finding.
    ///
    /// The numbers are literals on purpose. Deriving the expected mode
    /// from the same expression the check uses would have both sides of
    /// the contract agree by construction.
    #[test]
    fn the_trust_verdict_thresholds_are_the_ones_a_stock_install_survives() {
        assert!(trust_verdict(true, 1000, 0o600, 1000).is_none());
        assert!(
            trust_verdict(true, 1000, 0o664, 1000).is_none(),
            "group-writable is `umask 002`, which Debian, Ubuntu and RHEL ship"
        );
        assert!(
            trust_verdict(true, 0, 0o644, 1000).is_none(),
            "root-owned is trusted, as OpenSSH's StrictModes has it — one \
             `sudo $EDITOR ~/.config/holdfast/config.toml` produces it"
        );

        let other = trust_verdict(true, 2000, 0o600, 1000).expect("another user's file");
        assert!(other.contains("2000") && other.contains("1000"), "{other}");
        assert!(
            trust_verdict(true, 1000, 0o666, 1000).is_some(),
            "world-writable"
        );
        assert!(
            trust_verdict(false, 1000, 0o600, 1000).is_some(),
            "not a file"
        );
        // Ownership is asked before mode, so the sharper of two faults is
        // the one reported.
        assert!(trust_verdict(true, 2000, 0o666, 1000)
            .expect("both faults")
            .contains("owned by uid 2000"));
    }
}
