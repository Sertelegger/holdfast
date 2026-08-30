//! The 0.0.2 tool set: start_session, read_output, send_input, terminate,
//! status, list_sessions, get_command_history.

use super::envelope::{self, Status};
use super::{caller, detection, schema, HoldfastServer};
use crate::detect::{
    detect_shell, DetectionConfig, InteractionMode, PatternSet, PromptPattern,
    DEFAULT_SETTLE_THRESHOLD_MS,
};
use crate::output::ansi::AnsiMode;
use crate::output::encoding::TextEncoding;
use crate::output::redact::{redact_for_display, redact_str};
use crate::output::rules::RuleSet;
use crate::output::{ReadOptions, ReadRequest, ReadStart};
use crate::pty::{clamp_geometry, InProcessPty, PtyBackend, PtySpawnConfig};
use crate::screen::{ScreenCapture, ScreenConfig, ScreenTracking};
use crate::secret::binding::{Autofill, Resolved};
use crate::secret::{CancelReason, RaisedBy, Resolution, SlotSnapshot, SlotTake};
use crate::session::SecretWrite;
use crate::session::{new_session_id, wait, Session, SessionConfig, WriteRequest};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// What §5.2's mutually exclusive pair resolved to: **the whole process**
/// the child will be spawned as — program, argv, environment and working
/// directory — and the operator's profile name when there was one.
///
/// **It exists so there is exactly one place `start_session` reads any of
/// them from.** With `command`/`args`/`env`/`cwd` and `profile`/`vars`
/// both on the argument struct, a later edit that reached for
/// `args.command` somewhere below would silently reintroduce the
/// agent-authored command line for that one surface — the audit record,
/// the spawn, the `details` string. Resolving once, into a type with no
/// `Option<String>` command, makes that a compile error rather than a
/// review catch.
///
/// **`env` and `cwd` are on this type because that argument was made for
/// the command line and applied to nothing else (GH #55).** A
/// profile-started session took the agent's `env` unfiltered, so
/// `PATH` repointed the operator's literal `ssh` and `LD_PRELOAD`
/// captured the credential out of an *absolute* `program` running the
/// operator's own argv — both driven, both with `require_confirm` showing
/// the human the legitimate command line, because it was the legitimate
/// command line. The environment chooses the binary as effectively as the
/// argv does, and it is now resolved in the same place, once.
struct Launch {
    command: String,
    args: Vec<String>,
    /// Extra environment, **sorted**, exactly as `start_session` used to
    /// sort the agent's own map — so the `env_keys` audit field and the
    /// child's environment compare between runs.
    env: Vec<(String, String)>,
    /// The directory *requested*, not the effective one:
    /// `start_session` canonicalises it and rejects a non-directory, and
    /// both sources go through that one check so an operator's typo is
    /// the same refusal an agent's would have been.
    cwd: Option<String>,
    profile: Option<String>,
}

/// Hard cap on a single `send_input` payload.
///
/// `data` was unbounded. The PTY master is a blocking fd whose drain rate
/// is entirely up to the child, so a large payload to a child that is not
/// reading is precisely the input that parks a thread. 64 KiB is far more
/// than any keystroke or realistic paste and an order of magnitude below
/// the 1 MiB output buffer, so no legitimate caller meets it; it also
/// matches the 64 KiB body cap the web API applies to secret submission
/// (spec §7.6). Oversize is a *protocol* error rather than a status: the
/// request violates the input schema, it does not fail operationally.
const MAX_SEND_INPUT_BYTES: usize = 64 * 1024;

/// `read_output`'s `max_bytes` when the caller does not supply one, and the
/// ceiling it is clamped to. Both are advertised to the agent in
/// `ReadOutputArgs::max_bytes`' description, so both are pinned as literals
/// against that description in `tests::the_advertised_byte_caps_are_the_ones_
/// the_code_applies` — a default that drifts from its documentation is a
/// silent short read, which looks to the agent exactly like a child that
/// stopped talking.
const DEFAULT_READ_MAX_BYTES: usize = 32 * 1024;
const MAX_READ_MAX_BYTES: usize = 256 * 1024;

/// How long `send_input` waits for the write to reach the child before
/// answering `timeout`.
///
/// Matches `terminate`'s default SIGTERM grace. A write to a healthy
/// child completes in microseconds; anything near this deadline means the
/// child has stopped draining its tty, and the agent is better served by
/// a `timeout` it can act on than by a tool call that never returns.
const SEND_INPUT_TIMEOUT: Duration = Duration::from_secs(5);

/// `wait_for_pattern`'s default deadline and the ceiling the daemon
/// enforces whatever the caller asks for (§4.2, REQ-T-008).
///
/// `0` does not mean "return immediately" and does not mean "wait for
/// ever": §5.2 defines it as "no explicit *caller* deadline", which the
/// daemon still bounds at the cap so a pending wait cannot be retained
/// indefinitely.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 30;
pub const WAIT_FOR_PATTERN_MAX_TIMEOUT_SECS: u64 = 3600;

/// How often a withheld match re-checks the holdback boundary while it
/// waits for the in-flight secret to finish arriving.
const HOLDBACK_RELEASE_POLL: Duration = Duration::from_millis(50);

/// How often a pattern-less wait re-reads `interaction_mode`.
///
/// The same 50 ms as the holdback poll, for the same reason: it is short
/// against any human-scale deadline and long against the detector's own
/// settle threshold, so it neither reports a transition late nor spins.
const IDLE_WAIT_POLL: Duration = Duration::from_millis(50);

/// REQ-T-008. Returns the deadline to wait for, and the cap to report in
/// `clamped_timeout_secs` — **only** when a clamp actually happened, so an
/// agent that asked for 30 s never sees the field and one that asked for
/// `0` or 24 h learns the deadline it will really get.
fn resolve_wait_timeout(requested: Option<u64>) -> (Duration, Option<u64>) {
    let cap = WAIT_FOR_PATTERN_MAX_TIMEOUT_SECS;
    match requested {
        None => (Duration::from_secs(DEFAULT_WAIT_TIMEOUT_SECS), None),
        // "No caller deadline", still bounded here.
        Some(0) => (Duration::from_secs(cap), Some(cap)),
        Some(n) if n > cap => (Duration::from_secs(cap), Some(cap)),
        Some(n) => (Duration::from_secs(n), None),
    }
}

/// Compile a caller-supplied pattern. A bad regex is an input-schema
/// violation (§5.1), not an operational failure, so it takes the protocol
/// channel. The size limit bounds compilation of a pathological pattern;
/// without it a caller can make the server allocate for as long as it
/// likes before the first byte is ever scanned.
fn compile_pattern(pattern: &str) -> Result<regex::bytes::Regex, ErrorData> {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| ErrorData::invalid_params(format!("pattern is not a valid regex: {e}"), None))
}

/// The `timeout` envelope for a write that never reached the child.
fn write_timed_out(details: impl Into<String>) -> CallToolResult {
    envelope::envelope(
        Status::Timeout,
        // `bytes_written` is null rather than 0 on purpose: `write_all`
        // may have pushed part of the payload into the tty before it
        // parked, so any number here would be a guess. Null says
        // "unknown", which is the truth. §18.1 mandates no `data` fields
        // for `timeout`, and `isError` stays false, so an agent that
        // dispatches on `status` handles this without special-casing.
        json!({
            "bytes_written": serde_json::Value::Null,
            "timeout_ms": SEND_INPUT_TIMEOUT.as_millis() as u64,
        }),
        details,
    )
}

/// Unix seconds. Spec §5.4 requires RFC-3339 timestamp strings; that
/// arrives in 0.0.3 along with the audit log, which needs a date crate
/// anyway. The field is named `started_at_unix_secs` here rather than
/// `started_at` so the wire format does not silently claim to be
/// RFC 3339 when it is not.
fn unix_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `Default` is derived so callers (and tests) can set the fields they
/// care about and leave the rest: every later milestone adds arguments
/// here, and struct literals that must be updated in a dozen places
/// each time are pure churn.
#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct StartSessionArgs {
    /// Program to run, e.g. "bash". Mutually exclusive with `profile`;
    /// supply exactly one.
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments passed to the program. Only with `command`.
    #[serde(default)]
    pub args: Vec<String>,
    /// Name of an operator-declared session profile to start (spec §9.6).
    /// The operator wrote the command line; supply values for its slots in
    /// `vars`. Mutually exclusive with `command`/`args`. **Only a
    /// profile-started session can be given a keychain credential.**
    #[serde(default)]
    pub profile: Option<String>,
    /// Values for the named slots in `profile`'s argument template. Every
    /// slot needs one, no other key is accepted, and each value must match
    /// the pattern the operator declared for that slot. Only with
    /// `profile`.
    #[serde(default)]
    pub vars: Option<BTreeMap<String, String>>,
    /// Optional human-readable alias, unique among live sessions.
    #[serde(default)]
    pub name: Option<String>,
    /// Working directory for the spawned process. Must already exist.
    /// Defaults to the directory the Holdfast server itself was started in.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Extra environment variables for the spawned process. Do not pass
    /// secrets: these values cross the MCP boundary (spec §5.2).
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    /// Terminal width in columns, 1 to 1000. Defaults to 120. A value
    /// outside that range is clamped to it, not rejected.
    #[serde(default)]
    pub cols: Option<u16>,
    /// Terminal height in rows, 1 to 1000. Defaults to 40. A value
    /// outside that range is clamped to it, not rejected.
    #[serde(default)]
    pub rows: Option<u16>,
    /// Tier-B VT100 emulation: "off", "adaptive" (default), or "on".
    /// Full emulation costs ~11.6 ms per MiB on the write path, so
    /// "adaptive" turns it on only when something needs the rendered
    /// screen. Leave it alone unless you are profiling.
    #[serde(default)]
    pub screen_tracking: Option<String>,
    /// Extra tier-3 prompt patterns, each `{regex, score}` with score in
    /// [0,1]. Added to the bundled table unless `prompt_patterns_replace`.
    #[serde(default)]
    pub prompt_patterns: Option<Vec<PromptPatternArg>>,
    /// Replace the bundled tier-3 pattern table instead of extending it.
    #[serde(default)]
    pub prompt_patterns_replace: Option<bool>,
    /// Milliseconds of silence that count as fully settled for the
    /// tier-3 quiescence score. Defaults to 250.
    #[serde(default)]
    pub settle_threshold_ms: Option<u64>,
    /// Inject OSC 133 shell integration when the command is bash, zsh,
    /// or fish. Defaults to true.
    #[serde(default)]
    pub shell_integration: Option<bool>,
    /// Answer the closed terminal-query set (Primary Device Attributes
    /// only). Defaults to true; `false` accepts the startup stall — 10 s
    /// for fish — in exchange for writing nothing into the child's input.
    #[serde(default)]
    pub terminal_queries: Option<bool>,
    /// Seconds of inactivity after which the idle reaper terminates this
    /// session. Defaults to the daemon's `default_idle_timeout_secs`
    /// (1800 unless configured). `0` disables reaping for this session.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PromptPatternArg {
    /// Rust regex matched against the session's last logical line.
    pub regex: String,
    /// Score in [0,1] contributed when the regex matches.
    pub score: f32,
}

#[tool_router(vis = "pub(crate)")]
impl HoldfastServer {
    /// Start a PTY-backed shell or program and return its session id.
    /// Runs in `cwd` if given, otherwise in the directory the Holdfast
    /// server was started in.
    #[tool(
        annotations(
            title = "Start a PTY-backed shell session",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema::envelope_schema::<schema::StartSession>()
    )]
    pub async fn start_session(
        &self,
        Parameters(args): Parameters<StartSessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // §5.2's mutually exclusive pair, resolved **before** anything
        // else looks at the process. Everything below reads `launch` and
        // not `args.command`/`args.args`/`args.env`/`args.cwd`, so there
        // is one place the child's program, argv, environment and working
        // directory come from (GH #46, GH #55).
        let launch = self.resolve_launch(&args)?;
        let mut cfg = PtySpawnConfig::new(&launch.command);
        cfg.args = launch.args.clone();

        // `portable-pty` silently *discards* a cwd that is not an existing
        // directory and falls back to $HOME, so an unvalidated cwd means
        // the agent is told `ok` while running somewhere else entirely.
        // Validate here, and pin the default explicitly rather than
        // inheriting that $HOME fallback.
        //
        // The path is *canonicalised* rather than echoed back: §5.2 says
        // the returned `cwd` is the effective working directory the child
        // was spawned in, so handing a caller its own "." or a symlinked
        // path straight back would answer a question it did not ask.
        // `canonicalize` also fails outright on a path that does not
        // exist, which subsumes half the check; `is_dir` still matters
        // because an existing *file* canonicalises perfectly well.
        //
        // **`launch.cwd`, so an operator's profile `cwd` takes exactly
        // this path** — the same existence check, the same
        // canonicalisation, the same `invalid_params`. One resolution
        // function for both sources is what keeps the directory that is
        // approved, reported and actually run in from diverging.
        cfg.cwd = match &launch.cwd {
            Some(cwd) => {
                let resolved = std::path::Path::new(cwd)
                    .canonicalize()
                    .ok()
                    .filter(|p| p.is_dir());
                match resolved {
                    Some(p) => Some(p.to_string_lossy().into_owned()),
                    None => {
                        return Err(ErrorData::invalid_params(
                            format!("cwd is not an existing directory: {cwd}"),
                            None,
                        ))
                    }
                }
            }
            // `getcwd(2)` already resolves symlinks, so this is canonical
            // by construction; canonicalise anyway so both arms are
            // provably producing the same kind of path.
            None => std::env::current_dir()
                .and_then(|p| p.canonicalize())
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
        };

        // **`launch.env`, and there is no `args.env` read anywhere below
        // this line** (GH #55). On a profile-started session this is the
        // operator's own map and the agent supplied none, because
        // `resolve_launch` refused the call outright if it tried. Already
        // sorted by whichever arm built it, so `env_keys` compares between
        // runs.
        cfg.env = launch.env.clone();

        if let Some(c) = args.cols {
            cfg.cols = c;
        }
        if let Some(r) = args.rows {
            cfg.rows = r;
        }
        // The same bound `resize` applies, applied *before* the spawn.
        // `Session::resize` is the funnel for every later change of
        // geometry, but the spawn predates the session, so a zero or
        // 65 535-wide grid could otherwise be set here and never pass
        // through it. Clamping `cfg` rather than a copy is what keeps the
        // child's `winsize`, the `ScreenConfig` below and the size the
        // session reports from being three different numbers.
        let (cols, rows) = clamp_geometry(cfg.cols, cfg.rows);
        cfg.cols = cols;
        cfg.rows = rows;

        // Validate before spawning: an unrecognised mode is an input
        // error, and silently falling back to the default would leave the
        // operator believing they had turned emulation off.
        let mode = match args.screen_tracking.as_deref() {
            None => ScreenTracking::default(),
            Some(s) => match ScreenTracking::parse(s) {
                Some(m) => m,
                None => {
                    return Err(ErrorData::invalid_params(
                        format!("screen_tracking must be off, adaptive or on; got {s:?}"),
                        None,
                    ));
                }
            },
        };

        // Detection config is built *before* the spawn: a bad regex is
        // the caller's error and must not leave a live child behind.
        let extra: Vec<PromptPattern> = args
            .prompt_patterns
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|p| PromptPattern {
                regex: p.regex.clone(),
                score: p.score,
            })
            .collect();
        let patterns =
            match PatternSet::build(&extra, args.prompt_patterns_replace.unwrap_or(false)) {
                Ok(p) => p,
                Err(e) => return envelope::from_error(&e),
            };
        let idle_timeout_secs_resolved = args
            .idle_timeout_secs
            .unwrap_or(self.config.limits.default_idle_timeout_secs);
        let config = SessionConfig {
            detection: DetectionConfig {
                settle_threshold_ms: args
                    .settle_threshold_ms
                    .unwrap_or(DEFAULT_SETTLE_THRESHOLD_MS),
                patterns,
            },
            shell_integration: if args.shell_integration.unwrap_or(true) {
                detect_shell(&launch.command, &launch.args)
            } else {
                None
            },
            // §4.2/§4.5.1. The per-session half of a knob §4.2 lists as
            // "global config + per-session"; 0.0.5 brings the config file
            // and with it the global half.
            terminal_queries: args.terminal_queries.unwrap_or(true),
            // REQ-CFG-001's precedence pair, folded per field: the
            // per-session argument beats the config file, which beats the
            // hardcoded default. The two keys are spelled differently on
            // purpose — `[limits] default_idle_timeout_secs` globally and
            // `idle_timeout_secs` here — and unifying them would delete
            // the distinction the precedence rule is about.
            idle_timeout_secs: idle_timeout_secs_resolved,
            // §9.6, GH #46. **The name the operator wrote**, taken off the
            // profile that was looked up rather than off the argument that
            // looked it up — so a session can only carry a profile the
            // config declares. It is the only thing `secret::binding`
            // selects on, and it is `None` for a `command`/`args` session,
            // which is what makes *"a session started with `command`/`args`
            // can never receive a keychain credential"* a property of the
            // data rather than a check.
            profile: launch.profile.clone(),
            // §16.7's other half. `..SessionConfig::default()` supplies
            // `Clock::system()`, so leaving this unset stamps the
            // session's deadline from wall time while the reaper decides
            // about it on the daemon's injectable clock — the two halves
            // of one decision read off two clocks, which is the failure
            // `Clock::now_ms` was added to prevent one layer down.
            clock: self.clock.clone(),
            ..SessionConfig::default()
        };

        let backend = match InProcessPty::spawn(&cfg) {
            Ok(b) => Arc::new(b) as Arc<dyn PtyBackend>,
            Err(e) => {
                // `brief` matters here: portable-pty's spawn error embeds
                // the whole $PATH, which would land in the transcript.
                return Ok(envelope::envelope(
                    Status::SpawnFailed,
                    json!({ "command": launch.command }),
                    format!("spawn failed: {}", envelope::brief(&e)),
                ));
            }
        };

        let session = Session::new(
            new_session_id(),
            args.name.clone(),
            launch.command.clone(),
            launch.args.clone(),
            backend,
            config,
        );

        // Before the registry insert, so no caller can observe a session
        // whose Tier-B geometry still holds the constructor default. It is
        // also what teaches the session its own size, which `resize`
        // reports back.
        session.set_screen_config(ScreenConfig {
            mode,
            rows: cfg.rows,
            cols: cfg.cols,
            ..ScreenConfig::default()
        });

        if let Err(e) = self.registry.insert(Arc::clone(&session)) {
            // Registry rejected it; don't leak the child.
            let _ = session.signal(crate::pty::Signal::Kill);
            return envelope::from_error(&e);
        }

        // §9.6's `autofill_on_echo_off`, armed here because this is where a
        // session comes into existence and the edge it listens for can fire
        // as soon as the child runs. **After the insert**, so the session
        // the listener holds is the one every other surface can see; a
        // listener armed on a session the registry then refused would
        // resolve a credential into a child that is being killed.
        //
        // Spawns nothing at all unless the operator opted in — see
        // [`Self::watch_for_autofill`].
        self.watch_for_autofill(&session);

        // §9.4's `session_start`, with its field list verbatim.
        //
        // `command` and `args` are *not* pre-redacted here: `record`
        // redacts every string it is handed, unconditionally, which is
        // the property that makes an audit leak impossible rather than
        // merely unlikely. A second redaction at the call site would be
        // one more place that can be forgotten.
        //
        // `env_keys` is built from the key set, so the values are
        // **structurally absent** rather than redacted (REQ-SEC-006). The
        // redactor catches secret-*shaped* values; a password like
        // `correct horse battery staple` matches no rule and would be
        // logged in full. Sorted, so the field compares between runs.
        //
        // **No response carries `env`, and none should.** §9.2 requires
        // `env` values to be redacted "in any echo back via `status`
        // etc."; the cheapest way to satisfy that is to have no echo, so
        // `session_record` must not grow an `env` field —
        // `no_tool_advertises_an_env_field_to_echo` in `tests/schema.rs`
        // is what keeps that decision from being undone by convenience.
        let env_keys: Vec<&str> = {
            let mut keys: Vec<&str> = cfg.env.iter().map(|(k, _)| k.as_str()).collect();
            keys.sort_unstable();
            keys
        };
        self.processor.audit.record(
            "session_start",
            Some(&session.id),
            json!({
                "command": cfg.command,
                "args": cfg.args,
                // §9.4's `profile` (rev. 55, GH #46). **The one field on
                // this row that says where `command`/`args` came from.**
                // Without it a profile-started session and an
                // agent-authored one that happens to produce the same argv
                // write byte-identical records — and only the first can
                // ever receive a keychain credential, which is the
                // distinction the whole feature exists to create. It is
                // recorded for the same reason `binding_resolved` records
                // the binding *name*: an operator reading the trail is
                // reconstructing which decisions were theirs.
                //
                // **`null`, not an absent key**, when the session was
                // started with `command`/`args`. An omitted field cannot
                // be told from one a writer forgot, and the negative case
                // — *"this session could not have received a credential"*
                // — is the fact an operator is looking for.
                //
                // **The name and nothing more.** Not the operator's
                // template and not the `vars` the agent supplied: the
                // argv that actually ran is already on this row, redacted
                // element-wise, and a slot value keyed by the operator's
                // own slot name would be a second copy of agent text on a
                // surface that does not need one.
                "profile": launch.profile,
                "cwd": cfg.cwd,
                "env_keys": env_keys,
                // The **resolved** value, not the argument: §9.4 wants to
                // record what this session will actually be reaped at,
                // and that is the per-session argument when one was
                // supplied and `[limits] default_idle_timeout_secs`
                // otherwise. This was `null` through 0.0.4 with a comment
                // saying a number would be "a promise nothing keeps" —
                // true while no milestone had built the reaper, and no
                // longer true now that Task 16 has.
                "idle_timeout_secs": idle_timeout_secs_resolved,
                // **Read from the operator's config, not written as a
                // literal.** This stood as `true` unconditionally, with
                // a comment promising to wire it "when `redaction_enabled`
                // becomes a per-session argument". `[security]
                // redaction_enabled` is already a live, validated,
                // operator-settable key; the literal made this row an
                // audit record asserting a fact it had not checked, and
                // the day the knob is honoured on the read path the one
                // field whose job is to make the redaction posture
                // reconstructible would have been false by construction
                // — with no test in the tree failing. A field that is
                // sometimes wrong is worse than no field, so it reads
                // the same value the reader will.
                //
                // What it records is the **configured posture**, which
                // is what §9.4 asks of a `session_start` row: `read_output`
                // and `resources/read` still take a per-call `redact`,
                // and an individual read that opts out is recorded by
                // §9.4's separate `redaction_disabled` entry from inside
                // `Session::read_processed`. The two rows answer
                // different questions and neither substitutes for the
                // other.
                "redaction_enabled": self.config.security.redaction_enabled,
                "pid": session.pid(),
            }),
        );

        // REQ-R-006's create half: `resources/list` would now answer
        // differently, so the client is told to re-list. Fired after the
        // session is in the registry, or the re-list races the insert.
        self.notify_resource_list_changed();

        Ok(envelope::ok(
            json!({
                "session_id": session.id,
                "name": session.name,
                "pid": session.pid(),
                "cwd": cfg.cwd,
                "shell_integration": session.shell_integration.map(|s| s.as_str()),
                "started_at_unix_secs": unix_secs(session.created_at),
            }),
            format!("started `{}` as {}", launch.command, session.id),
        ))
    }

    /// §5.2's mutually exclusive pair: `command`/`args`, or `profile`/`vars`.
    ///
    /// **Every refusal here is an input violation (§5.1) and therefore
    /// `invalid_params`, not a `Status`.** That is this tool's own habit —
    /// `cwd is not an existing directory` and `screen_tracking must be off,
    /// adaptive or on` are the two already in this function — and
    /// `request_secret_input` states the rule outright: *"an input-schema
    /// violation is `invalid_params`"*. No new `Status` variant was added
    /// and none of the existing eleven describes an argument the caller
    /// could fix, so this adds nothing to §18.1's ordering, its six
    /// enumeration sites, or
    /// `every_declared_status_is_returned_by_a_real_response`.
    ///
    /// **A refusal for a failed slot pattern names the *var* and never
    /// echoes the value** — it may be a hostname the operator considers
    /// sensitive, and §9.2's habit is to name the field rather than the
    /// content. `secret::profile::VarFault`'s `Display` is where that is
    /// enforced, so this function cannot leak a value by forgetting to.
    fn resolve_launch(&self, args: &StartSessionArgs) -> Result<Launch, ErrorData> {
        match (&args.command, &args.profile) {
            (Some(_), Some(_)) => Err(ErrorData::invalid_params(
                "`command` and `profile` are mutually exclusive: supply `command`/`args` for \
                 an ordinary session, or `profile`/`vars` for an operator-declared one"
                    .to_string(),
                None,
            )),
            (None, None) => Err(ErrorData::invalid_params(
                "start_session needs either `command` or `profile`".to_string(),
                None,
            )),
            (Some(command), None) => {
                // **`vars` without a `profile` is refused rather than
                // ignored.** An agent that believes it constrained a
                // session and did not is an agent acting on a session that
                // is not the one it asked for.
                if args.vars.is_some() {
                    return Err(ErrorData::invalid_params(
                        "`vars` is only meaningful with `profile`; a `command` session has no \
                         slots to fill"
                            .to_string(),
                        None,
                    ));
                }
                let mut env: Vec<(String, String)> = args
                    .env
                    .iter()
                    .flatten()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                env.sort();
                Ok(Launch {
                    command: command.clone(),
                    args: args.args.clone(),
                    // **Unchanged for an ordinary session, deliberately.**
                    // Nothing is at stake in a session that cannot receive
                    // a credential: an agent that can name the program can
                    // already name any program, so its environment adds no
                    // capability. GH #55 is about the *other* arm.
                    env,
                    cwd: args.cwd.clone(),
                    profile: None,
                })
            }
            (None, Some(name)) => {
                // **`args` alongside a `profile` is refused, and this is
                // the one refusal in this function that is load-bearing
                // rather than tidy.** The whole property is that arguments
                // come from the operator's template, so an agent-supplied
                // `args` appended to the rendered argv would hand back
                // exactly the capability profiles exist to remove. It is
                // *also* structurally impossible — nothing below reads
                // `args.args` on this arm — and refusing as well means an
                // agent that passed some is told so rather than silently
                // running a session it did not ask for.
                if !args.args.is_empty() {
                    return Err(ErrorData::invalid_params(
                        "`args` is only meaningful with `command`: a profile's arguments come \
                         from the operator's template, and supplying more would be the thing \
                         profiles exist to prevent"
                            .to_string(),
                        None,
                    ));
                }
                // **`env` and `cwd` are refused for the same reason, and
                // GH #55 is what taught this arm that (driven twice).**
                // Profiles stopped the agent authoring the command line
                // and left it authoring the *process*: `env: {PATH: …}`
                // repointed the operator's literal `ssh` at the agent's
                // own binary, and `env: {LD_PRELOAD: …}` — with `program`
                // an absolute path, which is the obvious fix for the
                // first — captured the credential out of the operator's
                // binary running the operator's argv. In both,
                // `require_confirm` showed the human `ssh prod-01`,
                // because that *is* the line.
                //
                // **Refused wholesale rather than filtered.** The class is
                // the environment, not a list of names, and an allowlist
                // or blocklist of variables is the shape that failed four
                // times over `match_command`: it enumerates the ways an
                // adversary can influence a process, and there is no
                // complete list. A profile declares its own `env`/`cwd`,
                // literal, and that is the whole of what the child gets.
                if args.env.is_some() {
                    return Err(ErrorData::invalid_params(
                        "`env` is only meaningful with `command`: a profile's environment is \
                         the operator's, and an agent-supplied one chooses which binary the \
                         profile's `program` actually runs"
                            .to_string(),
                        None,
                    ));
                }
                if args.cwd.is_some() {
                    return Err(ErrorData::invalid_params(
                        "`cwd` is only meaningful with `command`: a profile's working \
                         directory is the operator's, and a `program` may be relative to it"
                            .to_string(),
                        None,
                    ));
                }
                let Some(profile) = self
                    .config
                    .security
                    .profiles
                    .iter()
                    .find(|p| p.name == *name)
                else {
                    // The **name**, which the agent supplied, and no list
                    // of the profiles that do exist: an operator's profile
                    // names are their configuration, and enumerating them
                    // for a caller that guessed wrong is a surface §9.6
                    // does not give the agent anywhere else.
                    return Err(ErrorData::invalid_params(
                        format!("no session profile named `{name}` is configured"),
                        None,
                    ));
                };
                let supplied = args.vars.clone().unwrap_or_default();
                let rendered = crate::secret::profile::render(profile, &supplied)
                    .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                Ok(Launch {
                    command: profile.program.clone(),
                    args: rendered,
                    // **All four come off the profile on this arm**, and
                    // none of them off `args`. `BTreeMap` iterates sorted,
                    // so this matches the ordering the other arm imposes.
                    env: profile
                        .env
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    cwd: profile.cwd.clone(),
                    // The **profile's** name and not the argument's, so a
                    // session can only ever carry a name the config
                    // declares. They are equal here; taking it from the
                    // profile is what keeps that true if the lookup ever
                    // stops being an exact-name comparison.
                    profile: Some(profile.name.clone()),
                })
            }
        }
    }

    /// Read output from a session. Supply exactly one of since_cursor,
    /// tail_lines, or tail_bytes. Output is ANSI-stripped and
    /// secret-redacted by default.
    #[tool(
        annotations(
            title = "Read session output",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::ReadOutput>()
    )]
    pub async fn read_output(
        &self,
        Parameters(args): Parameters<ReadOutputArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Argument validation precedes resolution: an input-schema
        // violation is a protocol error (§5.1) and must not be masked by
        // a `session_not_found` envelope when both are wrong at once.
        let selectors = [
            args.since_cursor.is_some(),
            args.tail_lines.is_some(),
            args.tail_bytes.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if selectors != 1 {
            return Err(ErrorData::invalid_params(
                "supply exactly one of since_cursor, tail_lines, tail_bytes",
                None,
            ));
        }
        // `max_bytes: 0` is not a smaller read, it is a read that can
        // never make progress: the response is `bytes_returned: 0,
        // truncated_for_size: true, next_cursor: <the cursor it was
        // given>`, so an agent following the documented "retry at
        // next_cursor" rule live-locks. Clamping to 1 would keep the loop
        // technically advancing at one byte per round trip, which is not a
        // service to anyone; the request is a caller bug, so it is
        // rejected like every other schema violation (§5.1) and for the
        // same reason — the agent gets told what is wrong instead of
        // silently getting something it did not ask for.
        if args.max_bytes == Some(0) {
            return Err(ErrorData::invalid_params(
                "max_bytes must be at least 1",
                None,
            ));
        }

        // Unknown enum values are input-schema violations, which §5.1
        // routes to the protocol channel rather than `isError: true`.
        let ansi = match args.ansi.as_deref().unwrap_or("strip") {
            "strip" => AnsiMode::Strip,
            "raw" => AnsiMode::Raw,
            other => {
                return Err(ErrorData::invalid_params(
                    format!("ansi must be \"strip\" or \"raw\", got {other:?}"),
                    None,
                ))
            }
        };
        let text_encoding = match args.text_encoding.as_deref() {
            None => TextEncoding::Utf8,
            Some(name) => match TextEncoding::parse(name) {
                Some(e) => e,
                None => {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "text_encoding must be \"utf8\", \"base64\", or \
                             \"lossy_printable\", got {name:?}"
                        ),
                        None,
                    ))
                }
            },
        };

        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        let max_bytes = args
            .max_bytes
            .unwrap_or(DEFAULT_READ_MAX_BYTES)
            .min(MAX_READ_MAX_BYTES);
        let start = if let Some(c) = args.since_cursor {
            ReadStart::Cursor(c)
        } else if let Some(n) = args.tail_lines {
            ReadStart::TailLines(n)
        } else {
            ReadStart::TailBytes(args.tail_bytes.unwrap().min(max_bytes))
        };

        // The §9.4 caller seam, derived server-side from the
        // authenticated connection: there is deliberately no path from a
        // tool argument to either field, because a caller that can name
        // itself can lie about it (REQ-SEC-018). `tool` stays a literal
        // at the call site; `client_kind` comes from the uid-checked
        // handshake the daemon scoped this call to, and is `in_process`
        // when there is no control-protocol connection at all.
        let surface = caller::audit_surface("read_output");
        let read = session.read_processed(
            &ReadRequest {
                start,
                max_bytes,
                options: ReadOptions {
                    ansi,
                    text_encoding,
                    redact: args.redact.unwrap_or(true),
                },
                tool: surface.tool,
                client_kind: surface.client_kind,
            },
            &self.processor,
        );
        let state = session.state();

        Ok(envelope::ok(
            detection::with_detection(
                json!({
                    "output": read.output,
                    "cursor": read.cursor,
                    "bytes_returned": read.bytes_returned,
                    "truncated_at_tail": read.truncated_at_tail,
                    "truncated_for_size": read.truncated_for_size,
                    "held_back": read.held_back,
                    "next_cursor": read.next_cursor,
                    // §5.2 declares this without a `?` and nothing had
                    // ever emitted it. The bulk counterpart to this
                    // incremental read: same processor, same redaction
                    // defaults, same audit behaviour (§5.5.5).
                    "resource_uri": crate::mcp::resources::ResourceUri::buffer_uri(&session.id),
                    "redactions": read.redactions,
                    "state": state.as_str(),
                    "exit_code": session.exit_code(),
                }),
                &session,
                &self.processor,
            ),
            format!("{} bytes", read.bytes_returned),
        ))
    }

    /// Return the rendered terminal grid instead of the byte stream. This
    /// is the right read for a full-screen program: `read_output` on a TUI
    /// returns redraw soup, this returns what a human would see.
    ///
    /// Pass `diff_from` with the `screen_revision` of your previous call
    /// to get only the changed regions, which for a single keystroke is
    /// typically tens of bytes rather than a whole grid.
    #[tool(
        annotations(
            title = "Read the rendered terminal screen",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::GetScreenState>()
    )]
    pub async fn get_screen_state(
        &self,
        Parameters(args): Parameters<GetScreenStateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        // §5.2: `redact` defaults to **true**. Resolved here and nowhere
        // else, so the default lives in one place.
        let redact = args.redact.unwrap_or(true);
        // §9.4: turning redaction off is an auditable event, and the
        // record is written where the caller is known rather than inside
        // the tracker. `tool` is a `&'static str` literal at the call site
        // — §9.4 forbids any code path from request params to it — and
        // `client_kind` is derived by `mcp::caller` from the uid-checked
        // handshake the daemon scoped this call to (REQ-SEC-018). The
        // same pair 0.0.3's `read_processed` passes, for the same reasons.
        if !redact {
            let surface = caller::audit_surface("get_screen_state");
            self.processor.audit.record_redaction_disabled(
                Some(&session.id),
                surface.tool,
                surface.client_kind,
            );
        }

        // Enabling Tier B costs one buffer re-seed (§4.5); the call
        // succeeds either way, so this is never an error path — which is
        // also why §5.3 classifies the tool `readOnlyHint: true` despite
        // it: the change is to Holdfast's bookkeeping, not to the session.
        let capture = session.screen_state(args.diff_from, redact, &self.processor);
        let tracking = session.screen_tracking();

        let (mut data, details) = match capture {
            ScreenCapture::Full(g) => (
                json!({
                    "screen_revision": g.screen_revision,
                    "rows": g.rows,
                    "cols": g.cols,
                    "cursor": { "row": g.cursor_row, "col": g.cursor_col, "visible": g.cursor_visible },
                    "alt_screen": g.alt_screen,
                    "title": g.title,
                    "lines": g.lines,
                    // §5.2, REQ-O-003: on **both** shapes, and it reports
                    // a *masked* grid rather than a truncated read — some
                    // cells carry `[REDACTED:unresolved]` instead of what
                    // the child painted. An installer's masked field and a
                    // genuinely blank one are the same pixels, so an agent
                    // driving a TUI has to be able to tell.
                    "held_back": g.held_back,
                }),
                format!("full {}x{} grid", g.rows, g.cols),
            ),
            ScreenCapture::Delta(d) => (
                json!({
                    "screen_revision": d.screen_revision,
                    "base_revision": d.base_revision,
                    "diff": d.diff,
                    "held_back": d.held_back,
                }),
                format!("diff from revision {}", d.base_revision),
            ),
        };
        // Read *after* the capture, which is the call that can change it:
        // this is the one tool that reports the tier it left the session
        // in, and it is what tells the agent whether the next call costs a
        // re-seed (§5.2).
        data["screen_tracking"] = json!(tracking);

        // A grid remains readable after the child exits — the agent still
        // wants to see the final screen — so `session_died` carries data
        // rather than replacing it. It is not an error status (§5.1).
        let status = if session.is_alive() {
            Status::Ok
        } else {
            data["exit_code"] = json!(session.exit_code());
            Status::SessionDied
        };
        Ok(envelope::envelope(status, data, details))
    }

    /// Resize a session's terminal, raising `SIGWINCH` in the child so a
    /// full-screen program redraws at the new size. The reported
    /// dimensions are read back from the session rather than echoed from
    /// the request, so a request outside the supported 1..=1000 range
    /// comes back carrying the clamped size it actually reached. Resizing
    /// to the size already in force is a no-op and leaves any outstanding
    /// `get_screen_state` revision usable.
    #[tool(
        annotations(
            title = "Resize a session's terminal",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::Resize>()
    )]
    pub async fn resize(
        &self,
        Parameters(args): Parameters<ResizeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };
        if !session.is_alive() {
            return Ok(envelope::envelope(
                Status::SessionDied,
                json!({ "exit_code": session.exit_code() }),
                "session has exited",
            ));
        }
        // A failing `ioctl` is Holdfast failing to do its job, not a session
        // outcome, so it takes the protocol channel (§5.1) — and it
        // matters that it does: the alternative is an `ok` reporting
        // dimensions the terminal never reached.
        if let Err(e) = session.resize(args.cols, args.rows) {
            return envelope::from_error(&e);
        }
        let (cols, rows) = session.size();
        Ok(envelope::ok(
            json!({ "cols": cols, "rows": rows }),
            format!("resized to {cols}x{rows}"),
        ))
    }

    /// Send Ctrl+C (SIGINT) to the session's foreground process group, so
    /// it reaches the command being interrupted rather than the shell
    /// hosting it.
    ///
    /// `delivered` reports that the signal was **written**, not that the
    /// child reacted — nothing in Holdfast can observe the latter. The
    /// session-state block beside it is what tells you whether it landed:
    /// a session that was `Executing` and is now `AtPrompt` is an
    /// interrupt that worked.
    #[tool(
        annotations(
            title = "Send Ctrl+C to a session's process group",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema::envelope_schema::<schema::Interrupt>()
    )]
    pub async fn interrupt(
        &self,
        Parameters(args): Parameters<InterruptArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };
        if !session.is_alive() {
            return Ok(envelope::envelope(
                Status::SessionDied,
                json!({ "exit_code": session.exit_code() }),
                "session has exited",
            ));
        }
        // `Signal::Interrupt`, which `InProcessPty` routes to the
        // *foreground* group via `killpg(tcgetpgrp(master) ?: pgid)`.
        // Never `terminate`'s sweep: that hits every group in the session
        // and would kill the shell hosting the command being interrupted.
        if let Err(e) = session.signal(crate::pty::Signal::Interrupt) {
            return envelope::from_error(&e);
        }
        Ok(envelope::ok(
            detection::with_detection(json!({ "delivered": true }), &session, &self.processor),
            "SIGINT sent to the foreground process group",
        ))
    }

    /// Wait until a regex matches the session's output, or the deadline
    /// passes. Scans history from since_cursor (default: live output
    /// only) and then live output, so a pattern that arrives while the
    /// call is in flight is not missed. match.text and
    /// output_since_start are secret-redacted; match.offset is the raw
    /// byte offset.
    #[tool(
        annotations(
            title = "Wait for a regex to match output",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::WaitForPattern>()
    )]
    pub async fn wait_for_pattern(
        &self,
        Parameters(args): Parameters<WaitForPatternArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Argument validation before resolution, as everywhere (§5.1).
        // `None` is the pattern-less wait and is not an error.
        // **An empty pattern is refused rather than aliased** (review
        // finding). Absent and `null` are byte-identical and both mean the
        // pattern-less wait; `""` compiled to a regex that matches at offset
        // zero, so it returned `matched: true` with `match.text: ""` at once
        // — measured against a running `sleep 30`, and against an already
        // dead session, where it also skipped the `session_died` the pattern
        // path would have reported.
        //
        // Making `pattern` optional is exactly what makes `""` a likely
        // client encoding of "omit". Silently treating it as omitted would
        // hide that bug in the caller; refusing it names it. Two spellings
        // for one meaning, and an error for the third.
        let pattern = match args.pattern.as_deref() {
            Some("") => {
                return Err(ErrorData::invalid_params(
                    "pattern must not be empty — omit it entirely to wait for the session \
                     to stop executing",
                    None,
                ))
            }
            Some(p) => Some(compile_pattern(p)?),
            None => None,
        };
        if args.max_bytes == Some(0) {
            return Err(ErrorData::invalid_params(
                "max_bytes must be at least 1",
                None,
            ));
        }
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };
        let max_bytes = args
            .max_bytes
            .unwrap_or(DEFAULT_READ_MAX_BYTES)
            .min(MAX_READ_MAX_BYTES);
        let (timeout, clamped) = resolve_wait_timeout(args.timeout_secs);

        let (status, fields) = match &pattern {
            Some(p) => {
                self.run_wait(&session, p, args.since_cursor, max_bytes, timeout, clamped)
                    .await
            }
            None => self.run_wait_for_idle(&session, timeout, clamped).await,
        };
        // `matched` for a pattern wait, `reached` for a pattern-less one:
        // the two answer different questions and are not spelled the same
        // so that a caller cannot read one as the other. **The `details`
        // sentence has to keep that distinction too** — it used to collapse
        // both into one bool three lines below the comment asserting they
        // must not be, and then said "pattern matched" on a call that
        // supplied no pattern. `AwaitingSecret` was the worst case: the
        // right reading is "stop, call `request_secret_input`", and what an
        // agent was told is that its absent pattern had matched.
        let satisfied = fields
            .get("matched")
            .or_else(|| fields.get("reached"))
            .and_then(|m| m.as_bool())
            .unwrap_or(false);
        let mut data =
            detection::with_detection(serde_json::Value::Object(fields), &session, &self.processor);
        // After `with_detection`, not before: the warning is read out of
        // the detection fields this response is about to carry.
        if let Some(w) = detection::unmatched_at_prompt(&data) {
            data["warning"] = json!(w);
        }
        let details = match (&pattern, satisfied) {
            (Some(_), true) => "pattern matched".to_string(),
            (Some(_), false) => format!("pattern did not match within {}s", timeout.as_secs()),
            // Names the mode, because that is the whole answer this form
            // gives and the caller is told to read it.
            (None, true) => {
                let mode = data
                    .get("interaction_mode")
                    .and_then(|m| m.as_str())
                    .unwrap_or("not executing");
                format!("session is {mode}")
            }
            (None, false) => format!("session still executing after {}s", timeout.as_secs()),
        };
        Ok(envelope::envelope(status, data, details))
    }

    /// Send keystrokes to a session's stdin.
    #[tool(
        annotations(
            title = "Send keystrokes to a session",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema::envelope_schema::<schema::SendInput>()
    )]
    pub async fn send_input(
        &self,
        Parameters(args): Parameters<SendInputArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Bound the payload before anything else, for the same reason
        // read_output validates before resolution: a schema violation is a
        // protocol error (§5.1) and must not be masked by a
        // `session_not_found` envelope when both are wrong at once.
        if args.data.len() > MAX_SEND_INPUT_BYTES {
            return Err(ErrorData::invalid_params(
                format!(
                    "data is {} bytes; send_input accepts at most {MAX_SEND_INPUT_BYTES}",
                    args.data.len()
                ),
                None,
            ));
        }
        // Compiled before the session is resolved, and before the write:
        // a bad regex must not leave input typed into a shell (§5.1).
        let wait_pattern = match &args.wait_for {
            Some(p) => Some(compile_pattern(p)?),
            None => None,
        };

        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };
        if !session.is_alive() {
            return Ok(envelope::envelope(
                Status::SessionDied,
                json!({ "exit_code": session.exit_code() }),
                "session has exited",
            ));
        }

        // Sampled *before* the write, so the flag describes the state
        // the agent acted on rather than whatever the write provoked.
        let awaiting = session.detection().interaction_mode == InteractionMode::AwaitingSecret;

        let mut payload = args.data.into_bytes();
        if args.append_newline.unwrap_or(true) {
            payload.push(b'\n');
        }

        // The write goes to a *blocking* master fd, and the child decides
        // when it drains. A child in raw mode that never reads fills the
        // line discipline's input buffer and parks the writer for as long
        // as it likes. Running that inline burned a tokio worker per call
        // and could not be cancelled, so a handful of such calls took the
        // whole MCP server down — including `terminate`, the only way out.
        // `spawn_blocking` moves it to the blocking pool, and the deadline
        // means the tool answers whether or not the child ever cooperates.
        let writer_session = Arc::clone(&session);
        // `write_input_acked`, not `write_input`: the ack carries the
        // `buffer.head` sampled inside this task immediately before the
        // write. That is `wait_for`'s scan start (§5.2), and sampling it
        // in the handler instead races the child's echo — a fast command's
        // first bytes land between the handler's snapshot and the write
        // and then vanish from `output_since_start`.
        let write = tokio::task::spawn_blocking(move || writer_session.write_input_acked(&payload));
        let ack = match tokio::time::timeout(SEND_INPUT_TIMEOUT, write).await {
            Ok(Ok(Ok(ack))) => ack,
            // An earlier write is still parked on this session's writer
            // lock, so this one never even reached the fd.
            Ok(Ok(Err(crate::HoldfastError::WriteTimeout))) => {
                return Ok(write_timed_out(
                    "a previous write to this session is still blocked; the child is not \
                     reading its terminal",
                ));
            }
            // The child can die between the liveness check above and the
            // write; a real PTY reports that as EIO. That *is*
            // `session_died` — but only here, where the context makes it
            // true. `from_error` deliberately refuses to guess.
            Ok(Ok(Err(e))) => {
                return Ok(envelope::envelope(
                    Status::SessionDied,
                    json!({ "exit_code": session.exit_code() }),
                    format!("session exited during the write: {e}"),
                ));
            }
            // The blocking task panicked. That is a Holdfast bug, not a
            // session outcome, so it takes the protocol channel (§5.1).
            Ok(Err(join)) => {
                return Err(ErrorData::internal_error(
                    format!("write task failed: {}", envelope::brief(&join)),
                    None,
                ));
            }
            // The deadline elapsed. `spawn_blocking` tasks cannot be
            // cancelled, so that thread is still parked on the fd — and
            // measurably stays parked even after the child is killed,
            // because Linux does not wake a blocked pty-master writer when
            // the slave closes. It is detached rather than leaked into the
            // request path: it holds only the writer lock, which is what
            // makes the bounded-acquisition branch above fire for every
            // later write instead of queueing behind it. `holdfast mcp` bounds
            // its runtime shutdown for the same reason.
            Err(_elapsed) => {
                return Ok(write_timed_out(
                    "the child did not accept the input within the write deadline; it may be \
                     in a mode where it is not reading its terminal",
                ));
            }
        };

        // REQ-SEC-011: the write still happens — the agent may know
        // something Holdfast does not — but the event is made visible.
        let warning = awaiting.then_some("session_awaiting_secret");
        let written = ack.bytes_written;

        let Some(pattern) = wait_pattern else {
            return Ok(envelope::ok(
                detection::with_detection(
                    json!({ "bytes_written": written, "warning": warning }),
                    &session,
                    &self.processor,
                ),
                format!("wrote {written} bytes"),
            ));
        };

        // `wait_for` shares `wait_for_pattern`'s semantics verbatim,
        // through the same function (§5.2). The one difference is where
        // "start" is: `send_input` has no `since_cursor`, so it scans from
        // the writer task's `pre_write_head`.
        let (timeout, clamped) = resolve_wait_timeout(args.timeout_secs);
        let (status, mut fields) = self
            .run_wait(
                &session,
                &pattern,
                Some(ack.pre_write_head),
                DEFAULT_READ_MAX_BYTES,
                timeout,
                clamped,
            )
            .await;
        fields.insert("bytes_written".into(), json!(written));
        fields.insert("warning".into(), json!(warning));
        let matched = fields
            .get("matched")
            .and_then(|m| m.as_bool())
            .unwrap_or(false);
        let mut data =
            detection::with_detection(serde_json::Value::Object(fields), &session, &self.processor);
        // REQ-SEC-011's warning outranks this one: a write into an
        // echo-off session is a security event, and a mis-written regex
        // is a usability one. They cannot both apply anyway — a session
        // that is `AwaitingSecret` is not `AtPrompt` — so this is a
        // precedence rule against future modes rather than today's.
        if warning.is_none() {
            if let Some(w) = detection::unmatched_at_prompt(&data) {
                data["warning"] = json!(w);
            }
        }
        Ok(envelope::envelope(
            status,
            data,
            if matched {
                format!("wrote {written} bytes; pattern matched")
            } else {
                format!("wrote {written} bytes; pattern did not match")
            },
        ))
    }

    /// Terminate a session, killing its whole process group. Idempotent.
    #[tool(
        annotations(
            title = "Terminate a session",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::Terminate>()
    )]
    pub async fn terminate(
        &self,
        Parameters(args): Parameters<TerminateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        // Idempotent per REQ-T-010: an already-dead session reports its
        // cached exit info rather than an error.
        if !session.is_alive() {
            return Ok(envelope::ok(
                json!({
                    "exit_code": session.exit_code(),
                    "already_exited": true,
                    "exited_at_unix_secs": session.exited_at_secs(),
                }),
                "session had already exited",
            ));
        }

        let force = args.force.unwrap_or(false);
        let grace_ms = args.timeout_secs.unwrap_or(5) as u64 * 1000;

        if force {
            let _ = session.signal(crate::pty::Signal::Kill);
        } else {
            let _ = session.signal(crate::pty::Signal::Terminate);
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(grace_ms);
            while session.is_alive() && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            if session.is_alive() {
                let _ = session.signal(crate::pty::Signal::Kill);
            }
        }

        // Give the child a moment to be reaped so exit_code is populated.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The session stays in the registry. Spec §4.1: an exited session
        // keeps its id (and releases only its name), so the agent can
        // still read the output the command produced before it was
        // stopped. Removing it here would delete that buffer and make the
        // second `terminate` a `session_not_found` error, which REQ-T-010
        // forbids.
        Ok(envelope::ok(
            json!({
                "exit_code": session.exit_code(),
                "already_exited": false,
                // Read *after* the kill and the reap sleep above, so the
                // latch has been armed by the `state()`/`is_alive()` calls
                // on the way through.
                "exited_at_unix_secs": session.exited_at_secs(),
            }),
            "terminated",
        ))
    }

    /// Detailed status of one session, including what it is doing right
    /// now and how that was determined.
    #[tool(
        annotations(
            title = "Get detailed session status",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::SessionRecord>()
    )]
    pub async fn status(
        &self,
        Parameters(args): Parameters<StatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };
        Ok(envelope::ok(
            detection::with_detection(
                session_record(&session, &self.processor.rules),
                &session,
                &self.processor,
            ),
            format!("status of {}", session.id),
        ))
    }

    /// Every session this server knows about, live or exited, with what
    /// each one is doing. Exited sessions stay listed and keep their output
    /// buffer, so a command's final output can still be read after the
    /// shell is gone; read `state` to tell the two apart rather than
    /// assuming everything returned here is running.
    #[tool(
        annotations(
            title = "List all sessions",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::ListSessions>()
    )]
    pub async fn list_sessions(&self) -> Result<CallToolResult, ErrorData> {
        let sessions: Vec<serde_json::Value> = self
            .registry
            .all()
            .iter()
            .map(|s| {
                detection::with_detection(
                    session_record(s, &self.processor.rules),
                    s,
                    &self.processor,
                )
            })
            .collect();
        let n = sessions.len();
        Ok(envelope::ok(
            json!({ "sessions": sessions }),
            format!("{n} session(s)"),
        ))
    }

    /// Commands run in the session, with exit codes and output spans,
    /// derived from OSC 133 shell-integration markers. If the session ran
    /// a nested integrated shell, the entry for the command that launched
    /// it can be closed early with that shell's first exit code, so a
    /// reported exit for a command that may still be running should be
    /// corroborated with `status` before acting on it.
    ///
    /// `command` is best-effort: it is reconstructed from the terminal's
    /// echo of what was typed, so a command longer than the terminal width
    /// is captured truncated to its tail (125 characters at 80 columns
    /// yields 47), and non-ASCII bytes are recorded as Latin-1. A truncated
    /// tail looks exactly like a complete shorter command, with no ellipsis
    /// and no error, so do not read `command` as a transcript of what ran.
    #[tool(
        annotations(
            title = "List commands run, with exit codes",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema::envelope_schema::<schema::CommandHistory>()
    )]
    pub async fn get_command_history(
        &self,
        Parameters(args): Parameters<GetCommandHistoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        // "No marker has arrived" is the only honest test: a shell can be
        // recognised and still emit nothing (a `sh` symlinked to dash).
        if !session.history_active() {
            let reason = match session.shell_integration {
                None => "shell integration was not injected for this command",
                Some(_) => "this shell has emitted no OSC 133 markers",
            };
            return Ok(envelope::envelope(
                Status::Unavailable,
                json!({ "reason": reason, "entries": [], "truncated_at_tail": false }),
                "command history needs an integrated shell",
            ));
        }

        let limit = args
            .limit
            .unwrap_or(50)
            .min(crate::detect::DEFAULT_MAX_ENTRIES);
        let entries: Vec<serde_json::Value> = session
            .command_history(args.since_index.unwrap_or(0), limit)
            .iter()
            .map(|e| {
                json!({
                    "index": e.index,
                    // **A redacted surface, and the one where secrets are
                    // likeliest** (§9.2, REQ-O-010): `command` is the
                    // terminal's echo of a line the human or the agent
                    // typed, and `export GH_TOKEN=…` is how a token
                    // reaches a shell. `read_output` redacts that same
                    // echo and `session_record` redacts `command`/`args`,
                    // so an unredacted copy here was a bypass of the
                    // redactor at an output boundary — with shell
                    // integration on by default for bash/zsh/fish, in the
                    // default configuration.
                    "command": redact_str(&self.processor.rules, &e.command),
                    "exit_code": e.exit_code,
                    "started_at_unix_ms": e.started_at_unix_ms,
                    "duration_ms": e.duration_ms,
                    "output_start_cursor": e.output_start_cursor,
                    "output_end_cursor": e.output_end_cursor,
                })
            })
            .collect();

        let n = entries.len();
        Ok(envelope::ok(
            json!({
                "entries": entries,
                "truncated_at_tail": session.history_truncated(),
                "total": session.command_count(),
            }),
            format!("{n} command(s)"),
        ))
    }

    /// Ask a human at an attached client to type a credential straight
    /// into this session's PTY.
    ///
    /// **You will never see the value.** It travels client → daemon →
    /// PTY and enters no response, no log and no broadcast; what comes
    /// back is a byte count. You cannot name a secret either: bindings
    /// match the session's own command line and the observed prompt, and
    /// `prompt_text` reaches no lookup (§9.6, REQ-SEC-012).
    #[tool(
        annotations(
            title = "Request a secret from the user",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema::envelope_schema::<schema::RequestSecretInput>()
    )]
    pub async fn request_secret_input(
        &self,
        Parameters(args): Parameters<RequestSecretInputArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Every bound below is a **protocol error**, not a status (§5.1):
        // an input-schema violation is `invalid_params`, the same shape
        // `read_output`'s cursor rule already uses. `secret_cancelled`
        // describes a request that was raised and did not complete, which
        // none of these is.
        //
        // Bytes, not characters. §9.5 says bytes.
        if args.prompt_text.len() > MAX_PROMPT_TEXT_BYTES {
            return Err(ErrorData::invalid_params(
                format!(
                    "prompt_text is {} bytes; request_secret_input accepts at most \
                     {MAX_PROMPT_TEXT_BYTES}",
                    args.prompt_text.len()
                ),
                None,
            ));
        }
        // **§5.2's *"the window starts at this call"*, stamped at the one
        // line where that is literally true.** This call has two waits in
        // series — §17.5's binding approval and then the human prompt —
        // and neither may compute a start of its own: a stage that took
        // `now + timeout_secs` would hand itself a fresh full window laid
        // end to end with the previous one. So there is exactly one stamp,
        // off `self.clock` like every other deadline in the daemon
        // (REQ-S-005), and both waits are derived from it: the approval's
        // `min(binding_approval_timeout_secs, remaining / 2)` below, and
        // `caller_deadline`, which is `await_secret`'s deadline verbatim.
        //
        // The check is `grep 'from_secs(timeout_secs' tools.rs |
        // grep -v '//'`, and it returns **exactly one** line: the
        // `caller_deadline` assignment after the bound is validated.
        //
        // **The second filter is not decoration.** Without it the check
        // cannot verify anything, because this comment quotes the pattern
        // and therefore matches it: the grep returns two, a reader
        // concludes the invariant is broken, and the next reader stops
        // trusting the comment. A self-verifying check that cannot verify
        // is worse than no check at all, so the pattern is stated in a
        // form that excludes the prose stating it.
        let call_start = self.clock.now();
        let security = &self.config.security;
        let timeout_secs = args.timeout_secs.unwrap_or(DEFAULT_SECRET_TIMEOUT_SECS);
        // Bounded in **both** directions. A one-sided check passes every
        // test that only probes the top, and `timeout_secs: 0` here is
        // not `wait_for_pattern`'s "no caller deadline": a request with
        // no deadline and a caller waiting on it is a call that never
        // returns.
        if timeout_secs == 0 || timeout_secs > security.secret_input_max_timeout_secs {
            return Err(ErrorData::invalid_params(
                format!(
                    "timeout_secs must be between 1 and {} (security.\
                     secret_input_max_timeout_secs); got {timeout_secs}",
                    security.secret_input_max_timeout_secs
                ),
                None,
            ));
        }
        // **The call's one deadline, and every wait below is bounded by
        // it.** §5.2 says the window starts at *this call*; it does not
        // say "at each stage of this call", and a stage that recomputed
        // `now + timeout_secs` would hand itself a fresh full window. With
        // §17.5's approval in front of the prompt path that is not
        // theoretical: an approval may consume up to half of
        // `timeout_secs`, so a recomputed prompt deadline lets a
        // `require_confirm` call run for **1.5×** the number the agent
        // declared. One origin, computed once, threaded into both waits.
        let caller_deadline = call_start + Duration::from_secs(timeout_secs as u64);
        let max_secret_bytes = args.max_secret_bytes.unwrap_or(DEFAULT_MAX_SECRET_BYTES);
        if max_secret_bytes == 0 || max_secret_bytes > security.max_secret_bytes_ceiling {
            return Err(ErrorData::invalid_params(
                format!(
                    "max_secret_bytes must be between 1 and {} (security.\
                     max_secret_bytes_ceiling); got {max_secret_bytes}",
                    security.max_secret_bytes_ceiling
                ),
                None,
            ));
        }

        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        // §3.6, and §5.2: *"On Windows native, `request_secret_input`
        // returns `not_supported_on_platform` **before allocating a
        // `request_id`**."*
        //
        // **Sited after session resolution and before `raise_or_adopt`.**
        // Ahead of the lookup it answers "your platform is the problem"
        // to a call whose *argument* was — a bad session id is still
        // `session_not_found`, and an input-schema violation is still
        // `invalid_params`. Behind the raise it broadcasts a prompt to a
        // human on a platform that cannot answer it.
        //
        // **A branch over a field, not `#[cfg(windows)] return …`.** The
        // `#[cfg]` decides the *value* (see `crate::platform`); it does
        // not decide the branch. An inline `cfg` leaves a status that no
        // test on any CI runner can produce, which is REQ-T-017's defect
        // exactly, and it ships silently.
        if !self.capabilities.out_of_band_secret_input {
            return Ok(envelope::envelope(
                Status::NotSupportedOnPlatform,
                json!({}),
                "out-of-band secret input needs a daemon holding the session and a client \
                 attached to it; this platform has neither",
            ));
        }

        if !session.is_alive() {
            return Ok(envelope::envelope(
                Status::SessionDied,
                json!({ "exit_code": session.exit_code() }),
                "session has exited",
            ));
        }

        let append_newline = args.append_newline.unwrap_or(true);
        let hub = self.attach_hub();

        // ------------------------------------------- §5.2's step 1
        //
        // ```text
        // 1. Keychain — only when `secret_provider` is `keychain` or
        //               `both` AND a binding matches this session.
        // 2. Prompt   — broadcast AwaitingSecret and wait for a
        //               SecretInput.
        // ```
        //
        // **Before `raise_or_adopt`, because it is step 1.** A resolution
        // that ran after the raise would broadcast a prompt to every
        // attached human and then answer it from a credential store a
        // moment later, which is the affordance appearing and vanishing
        // for no reason a human can see.
        //
        // **`args.prompt_text` is not in scope for any of this**, and
        // that is REQ-SEC-012: nothing under `secret::binding` has a
        // parameter it could be passed in. The redaction below is
        // deliberately sited *after* this block so that the agent's
        // string does not even exist as a local while step 1 runs.
        //
        // Skipped when the slot already has a call waiting on it: that is
        // the collision condition, `raise_or_adopt` answers it below with
        // the first caller's request untouched, and autofilling here
        // would put a second value into a PTY that already has one
        // caller's write on the way.
        //
        // **And skipped entirely — no `.await` at all — when step 1
        // cannot produce anything.** This is not an optimisation, it is
        // the difference between the default posture costing nothing and
        // costing a `spawn_blocking` round trip: under `prompt` mode with
        // no bindings, which is a stock install, `autofill_from_binding`
        // would hop to the blocking pool only to answer `ModeIsPrompt`.
        // That hop is a **suspension point ahead of `raise_or_adopt`**,
        // and it widens the window in which a client can fulfil an
        // outstanding echo-drop raise before this call has registered its
        // waiter — measured, on
        // `a_secret_the_agent_requested_reaches_the_child_and_none_of_the_surfaces`,
        // which went red the first time this block existed
        // unconditionally. A call that pays nothing when the feature is
        // off keeps 0.0.6's timing exactly.
        //
        // `keychain_step_runs` is *also* checked inside `autofill`, which
        // is public and must be correct when called directly. Two copies
        // of one rule, deliberately, in the shape `take_if_unadopted` and
        // `unadopted_sessions` already use here: this one is a *guard*
        // that decides whether to suspend, the other is the rule itself,
        // and they call the same function so a change to the rule cannot
        // apply to one and not the other.
        let step_one_possible =
            crate::secret::binding::keychain_step_runs(&self.config.security.secret_provider)
                && !self.config.security.secret_bindings.is_empty();
        if step_one_possible && !hub.secrets().has_waiter(&session.id) {
            match self.autofill_from_binding(&session, append_newline).await {
                StepOne::Done(done) => return Ok(done),
                // §17.5's `Pending`. **Sited here and not inside
                // `autofill_from_binding`, because this is where
                // `args.prompt_text` is allowed to exist.**
                // `BindingApprovalRequired` carries the agent's text so a
                // human sees what is being asked for, and
                // `autofill_from_binding`'s whole security property is
                // that it has no parameter that text could enter
                // (REQ-SEC-012). Keeping the approval out here costs one
                // `match` arm and keeps that signature exact.
                StepOne::NeedsApproval {
                    binding_name,
                    provider,
                    raised_before,
                } => {
                    // Redacted before any human is shown it, on the same
                    // rule the `AwaitingSecret` broadcast below follows —
                    // and a *second* redaction rather than a hoisted
                    // one, so that ordering claim above stays true.
                    // The agent's own string, on its way to every
                    // attached client's approval dialog — so stripped as
                    // well as redacted (GH #45).
                    let approval_prompt =
                        redact_for_display(&self.processor.rules, &args.prompt_text);
                    if let Some(done) = self
                        .run_binding_approval(
                            &session,
                            &binding_name,
                            &provider,
                            &approval_prompt,
                            append_newline,
                            Some(caller_deadline),
                            raised_before,
                        )
                        .await
                    {
                        return Ok(done);
                    }
                }
                // REQ-SEC-017's fall-through, and every other
                // non-resolution: step 2.
                StepOne::FellThrough => {}
            }
        }

        // Redacted before it reaches anybody. §9.2 names only the audit
        // surface, and redacting the broadcast too costs one call, keeps
        // one rule for the string, and stops a human being shown a
        // secret-shaped value in the modal they are about to type into.
        let prompt_text = redact_for_display(&self.processor.rules, &args.prompt_text);

        // REQ-SEC-010a. Raise if the slot is vacant, **adopt** if an echo
        // drop already raised one — §16.4 steps 3–7 are an adoption end
        // to end, so that is the ordinary case — and collide only if the
        // request already has a call waiting on it.
        let adopted = match hub.secrets().raise_or_adopt(
            &session.id,
            &prompt_text,
            Some(max_secret_bytes),
            append_newline,
        ) {
            Ok(a) => a,
            // The first caller's request is untouched: no close
            // broadcast, no slot change, no deadline reset.
            Err(collision) => {
                // §9.4's two entries are written **per tool call**, and a
                // collision is a call. `raised_by` is the *request's* —
                // whatever raised the one this call collided with — which
                // is how an operator sees that a second caller arrived at
                // somebody else's request rather than raising its own.
                self.audit_secret_request(
                    &session.id,
                    &collision.request_id,
                    &args.prompt_text,
                    timeout_secs,
                    max_secret_bytes,
                    collision.raised_by,
                );
                self.audit_secret_resolved(
                    &session.id,
                    &collision.request_id,
                    CancelReason::ConcurrentRequestPending.as_str(),
                    None,
                );
                return Ok(envelope::envelope(
                    Status::SecretCancelled,
                    json!({
                        "request_id": collision.request_id,
                        "reason": CancelReason::ConcurrentRequestPending.as_str(),
                    }),
                    "this session already has a secret request with a call waiting on it",
                ));
            }
        };
        let request_id = adopted.request_id.clone();
        // **Per call, and this is the line that makes §5.2's *"a raised
        // request that no call ever adopts produces no
        // `secret_input_request` entry"* true.** Written before the wait,
        // so an operator reading a trail mid-flight sees an outstanding
        // request rather than nothing at all.
        //
        // `args.prompt_text` and not the pre-redacted `prompt_text`:
        // `AuditLog::record` redacts every string it is handed, and
        // handing it the already-redacted copy would make the end-to-end
        // assertion pass without the redactor ever running here.
        self.audit_secret_request(
            &session.id,
            &request_id,
            &args.prompt_text,
            timeout_secs,
            max_secret_bytes,
            adopted.raised_by,
        );
        // **Only the raising call broadcasts.** An adopting call must not
        // re-announce a request a human may already be typing into, and
        // must not replace its text.
        if adopted.raised_here {
            hub.broadcast_awaiting_secret(&session.id, &request_id, &adopted.prompt_text);
        }

        // §9.5's rung 3, evaluated **at the moment this caller begins
        // waiting** — the only moment at which "nobody is looking" is a
        // fact rather than a guess.
        //
        // **At most once per request, by two independent guards.** A
        // colliding second call returns above and never reaches here; and
        // `claim_notice` flips the flag under the slot's own lock and
        // answers `true` to exactly one caller, so even a call that did
        // reach here could not put a second identical line into the
        // buffer the agent reads back. A re-raise after a timeout is a
        // *different* request with a fresh flag and is announced again —
        // a counter hoisted to the session would leave the re-raised
        // request silently unannounced.
        if hub.clients_of(&session.id).is_empty()
            && hub.secrets().claim_notice(&session.id, &request_id)
        {
            session.inject_notice(&crate::secret::buffer_notice(&session.id));
        }

        let resolution = self
            .await_secret(&session, &request_id, adopted.rx, caller_deadline)
            .await;

        // **Two vocabularies for one event, and they must not be
        // unified.** This field carries the *tool status* — `secret_provided`
        // — while §7.5's `SecretRequestClosed.outcome` carries the *frame
        // outcome*, `fulfilled`. They describe the same moment from two
        // sides: this row records what the caller was told, the frame
        // records what the clients were told. Mapping one enum onto the
        // other loses `concurrent_request_pending`, which no frame has.
        let (outcome, bytes_written) = match &resolution {
            Resolution::Provided { bytes_written } => ("secret_provided", Some(*bytes_written)),
            Resolution::Cancelled(reason) => (reason.as_str(), None),
            // **§9.4's enumeration is short by one and this is the
            // divergence, recorded rather than repaired.** Its five
            // values are the four `secret_cancelled` reasons plus
            // `secret_provided`; a session that exits under a waiting
            // call is answered `session_died` (§5.1) and has no row.
            // Writing nothing would leave a `secret_input_request` with
            // no resolution in the trail, which an operator reads as
            // "still outstanding" — strictly worse than a sixth value in
            // an audit-only field whose stated job is to record the tool
            // status. Flagged for §9.4 rather than fixed there.
            Resolution::SessionDied { .. } => ("session_died", None),
        };
        self.audit_secret_resolved(&session.id, &request_id, outcome, bytes_written);

        Ok(match resolution {
            Resolution::Provided { bytes_written } => envelope::envelope(
                Status::SecretProvided,
                detection::with_detection(
                    json!({ "bytes_written": bytes_written, "request_id": request_id }),
                    &session,
                    &self.processor,
                ),
                format!("{bytes_written} byte(s) written to the session"),
            ),
            Resolution::Cancelled(reason) => envelope::envelope(
                Status::SecretCancelled,
                json!({ "request_id": request_id, "reason": reason.as_str() }),
                format!("the secret request ended: {}", reason.as_str()),
            ),
            Resolution::SessionDied { exit_code } => envelope::envelope(
                Status::SessionDied,
                json!({ "exit_code": exit_code }),
                "the session exited while the request was outstanding",
            ),
        })
    }
}

impl HoldfastServer {
    /// §5.2's step 1: resolve this session's secret from a credential
    /// store, or answer `None` and let the caller fall through to the
    /// prompt.
    ///
    /// **The signature is the security property.** It takes the session
    /// and the request's `append_newline` and nothing else — there is no
    /// parameter through which `request_secret_input`'s `prompt_text`
    /// could reach a binding lookup, which is REQ-SEC-012's structural
    /// half at the one call site that could break it (§9.6: *"There is no
    /// 'agent asks for a named secret' API at all"*).
    ///
    /// **`spawn_blocking`, because [`crate::secret::binding::autofill`]
    /// waits on an OS process.** A provider taking its full
    /// `keychain_provider_timeout_secs` would otherwise stall a runtime
    /// worker for ten seconds — and `op read` blocking on a biometric
    /// prompt is exactly that case.
    ///
    /// Every fall-through is silent to the agent: [`StepOne::FellThrough`]
    /// is indistinguishable from a session with no bindings configured at
    /// all. An agent that could tell "your binding is exhausted" from "you
    /// have no binding" could enumerate an operator's bindings from the
    /// outside. [`StepOne::NeedsApproval`] is **not** an exception: the
    /// caller either resolves after a human approves, or falls through
    /// exactly as it would have for any other reason, and no status of
    /// its own reaches the agent (§18.1 deleted `binding_approval_denied`
    /// for that reason).
    async fn autofill_from_binding(&self, session: &Arc<Session>, append_newline: bool) -> StepOne {
        let hub = self.attach_hub();
        // **The slot as it stands *before* the provider runs.** This call
        // is about to be away for up to `keychain_provider_timeout_secs`,
        // and the whole point of reading it now is to be able to tell,
        // afterwards, whether the thing it is about to satisfy is still
        // there. See `SecretSlots::take_if_unadopted_matching`.
        //
        // A *snapshot* and not the outstanding id: the id alone cannot see
        // a raise that appeared **and was answered** while the provider
        // ran, because that leaves the slot vacant again (GH #35).
        //
        // And the session's write count beside it: a credential resolved
        // for *this* read must not be written if something else has
        // answered that read in the meantime, and nothing about that
        // touches a slot.
        let raised_before = AutofillGuard {
            slot: hub.secrets().snapshot(&session.id),
            writes: session.writes_performed(),
        };

        let security = self.config.security.clone();
        let processor = Arc::clone(&self.processor);
        let for_task = Arc::clone(session);
        let outcome = tokio::task::spawn_blocking(move || {
            crate::secret::binding::autofill(&security, &for_task, append_newline, &processor.audit)
        })
        .await;

        let resolved = match outcome {
            Ok(Autofill::Resolved(resolved)) => resolved,
            // §17.5's `Pending`: nothing has been resolved, no use has
            // been spent, and no provider has run. Handed back rather
            // than acted on here — see [`StepOne::NeedsApproval`].
            Ok(Autofill::FellThrough(crate::secret::FellThrough::NeedsApproval {
                binding_name,
                provider,
            })) => {
                return StepOne::NeedsApproval {
                    binding_name,
                    provider,
                    raised_before,
                }
            }
            // Every other answer means the same thing: step 2.
            Ok(Autofill::FellThrough(_)) => return StepOne::FellThrough,
            // The blocking task panicked. Falling through is the safe
            // reading — a human can still answer — and the panic is
            // already on `daemon.log` through the runtime's own hook.
            Err(_) => return StepOne::FellThrough,
        };

        match self
            .inject_resolved(session, resolved, &raised_before)
            .await
        {
            Some(done) => StepOne::Done(done),
            None => StepOne::FellThrough,
        }
    }

    /// Put a resolved value into the session's PTY, or drop it and fall
    /// through — the tail §5.2's step 1 and §17.5's `Approved` arm share.
    ///
    /// **One copy, because the slot check is the dangerous part.**
    /// `raised_before` is the slot as it stood before this call went away
    /// — for the plain path, before the provider ran; for the approval
    /// path, before the whole human round trip — and the three-way answer
    /// below is what stops a credential being typed into a prompt somebody
    /// else has already answered. A second hand-written copy of that would
    /// be a second place to get it wrong, in the one function where
    /// getting it wrong puts a password on the tty input queue.
    async fn inject_resolved(
        &self,
        session: &Arc<Session>,
        resolved: Resolved,
        raised_before: &AutofillGuard,
    ) -> Option<CallToolResult> {
        let hub = self.attach_hub();
        let Resolved {
            binding_name,
            secret,
            ..
        } = resolved;

        // **Close the raise before the write is queued**, and for the same
        // reason `attach::conn`'s `SecretInput` arm does: two answers to
        // one prompt must produce one write.
        //
        // **And do not write at all if the raise went away.** A human at
        // an attached client can answer an outstanding raise *while the
        // provider is running* — `conn.rs` reaches the slot through
        // `take(session_id, Some(&request_id))`, which needs only a
        // matching id and not the absence of a waiter, so it wins that
        // race. Writing anyway would put the resolved value into the tty
        // input queue **behind** the human's, where the child's next read
        // consumes it: for a shell, a credential run as a command. So a
        // raise that was outstanding when this call started must still be
        // there, unadopted and under the same id, or the value is dropped
        // — `SecretBytes::drop` zeroes it — and the call falls through to
        // the prompt path like any other non-resolution.
        //
        // **And the same is true when nothing was outstanding before.** A
        // raise can appear inside the window and be adopted by *another
        // tool call*; writing into that is the identical failure reached
        // from the other side. One three-way answer under one lock covers
        // both, and it has to be one answer rather than a `has_waiter`
        // probe afterwards — a check-then-act here is the race being
        // closed, not a way of closing it.
        //
        // **And the same again when a raise appeared and was answered
        // inside the window** (GH #35). That leaves the slot vacant, which
        // no re-check can tell from "nothing happened", so the snapshot
        // carries the slot's closure count and `NotYours` is what comes
        // back. This arm used to read `Vacant if raised_before.is_none()`;
        // that guard is now subsumed — `Vacant` means the slot has not
        // been through a request since the snapshot *and* holds nothing —
        // and keeping it would have been a condition that cannot be false.
        //
        // The `binding_resolved` entry and the spent `max_uses` claim
        // stand: the binding *did* resolve, and §9.6 counts resolutions
        // from the store rather than values written to a PTY.
        //
        // ## And the question the slot cannot answer, which is not asked here
        //
        // **Everything above observes `SecretSlots`, and the child's read
        // can be satisfied by routes that never touch a slot**: an MCP
        // `send_input` (REQ-SEC-011 allows it during `AwaitingSecret`, with
        // a warning), a human typing ordinary input at an attached
        // terminal, or the child abandoning the read itself. With a client
        // attached those end with `forward_events` closing the raise on
        // `AwaitingSecretLeft`, so the closure count moves and the check
        // above refuses. **With nobody attached there is no raise at all**,
        // the count never moves, and the slot answers `Vacant` for a child
        // that has already moved on — which is the unattended case
        // `autofill_on_echo_off` exists for.
        //
        // A version of this function asked `session.is_awaiting_secret()`
        // right here and **it did not close that**, for two measured
        // reasons: the flag is a cache the reader thread refreshes only
        // when the child produces output, so a child that is silent
        // between two reads leaves it reading `true` indefinitely; and
        // even a correct answer is separated from the write by the write
        // queue, which `send_input`'s bytes share. Both are stated in full
        // at [`WriteRequest::SecretIfUnread`], which is where the question
        // is now asked — on the writer thread, one statement before the
        // write, against the tty rather than a cache of it.
        //
        // **It also asked the wrong question.** §8.3's classification is
        // narrower than "echo is off": `Fullscreen` and `AtPrompt` preempt
        // it, so a genuine `getpass` inside an alt-screen TUI is not
        // `AwaitingSecret` — and `request_secret_input` had no echo-state
        // precondition before that check existed. The writer gates on the
        // echo state itself, which is the condition the harm actually
        // turns on.
        let request_id = match hub
            .secrets()
            .take_if_unadopted_matching(&session.id, &raised_before.slot)
        {
            SlotTake::Taken(raised) => {
                let id = raised.request_id().to_string();
                drop(raised);
                Some(id)
            }
            SlotTake::Vacant => None,
            SlotTake::NotYours => {
                drop(secret);
                return None;
            }
        };
        // **The closure is broadcast after the outcome is known, not
        // before.** The take has to happen first — two answers to one
        // prompt must produce one write — but the *word* must not: a write
        // the writer declines would otherwise have told every attached
        // client `fulfilled` for a value the child never received.
        let close = |outcome: &str| {
            if let Some(id) = &request_id {
                hub.broadcast_secret_closed(&session.id, id, outcome);
            }
        };

        // The same write path a client's `SecretInput` takes, plus the two
        // conditions §9.6's autofill needs and a human's keystroke does
        // not: the value moves into the queue as a `SecretBytes` and is
        // zeroed by its own `Drop` whether the writer writes it or refuses
        // it.
        let (write, ack) = WriteRequest::secret_if_unread(secret, raised_before.writes);
        if session.write_queue().send(write).await.is_err() {
            close("cancelled");
            return Some(self.session_died_under_autofill(session));
        }
        let bytes_written = match ack.await {
            Ok(Ok(SecretWrite::Written(n))) => n as u64,
            // Refused at the write. **Falls through like every other
            // non-resolution**, so the agent learns nothing it could not
            // learn from a session with no bindings at all — and the
            // reason goes to `daemon.log`, which is where an operator
            // debugging "my binding never fires" will look. The binding
            // name is safe there; the reference and the value have no path
            // to it (REQ-SEC-016).
            Ok(Ok(SecretWrite::Declined(why))) => {
                crate::diag!(
                    "holdfast: the `{binding_name}` binding resolved but the value was \
                     not written: {why:?}"
                );
                close("cancelled");
                return None;
            }
            _ => {
                close("cancelled");
                return Some(self.session_died_under_autofill(session));
            }
        };
        close("fulfilled");
        // §4.1 counts a write as activity, or a session idle-reaps while
        // its own credential is being filled in.
        session.note_activity();

        let mut data = json!({ "bytes_written": bytes_written });
        // Present only when there *was* a raised request to close.
        // §9.6's autofill raises none of its own: there is no prompt, so
        // there is nothing for an id to name.
        if let Some(id) = request_id {
            data["request_id"] = json!(id);
        }
        Some(envelope::envelope(
            Status::SecretProvided,
            detection::with_detection(data, session, &self.processor),
            format!(
                "{bytes_written} byte(s) written to the session from the \
                 `{binding_name}` binding"
            ),
        ))
    }

    /// §17.5's whole lifecycle for one caller: raise, broadcast, wait,
    /// audit, and — on `approve` only — resolve and inject.
    ///
    /// `Some` is this call's answer and `None` means **fall through to
    /// the human-prompt path**, which is what REQ-SEC-017 requires of
    /// both `Denied` and `Expired` and what every other non-resolution in
    /// §5.2's step 1 already does.
    ///
    /// **The window is the lesser of the configured value and half the
    /// caller's remaining deadline** — see
    /// [`crate::secret::approval_window`], which is where the arithmetic
    /// and its argument live. Using the configured value unconditionally
    /// makes REQ-SEC-017's fall-through unreachable whenever the two
    /// knobs are equal, which on shipped defaults is always.
    ///
    /// **`caller_deadline` is `None` for §9.6's `autofill_on_echo_off`
    /// path, and then the configured value applies in full.** §17.5 states
    /// exactly that: the halving exists so a caller's prompt path inherits
    /// at least half of what is left, and *"with no caller — the
    /// `autofill_on_echo_off` path (§9.6), which has no deadline to
    /// divide"* — there is nothing to divide and nothing waiting to
    /// inherit it. An `Option` rather than a synthetic far-future
    /// `Instant`, because a synthetic one would make `remaining / 2` a
    /// number that happens to exceed the configured value rather than a
    /// case the arithmetic knows about.
    ///
    /// **The timer decides nothing**, exactly as in [`Self::await_secret`]:
    /// on expiry the caller asks the registry, under the same lock every
    /// other transition takes, whether it is still the one waiting. A
    /// `select!` that dropped the receiver would lose an `ApproveBinding`
    /// landing in that window and fall through having been approved.
    #[allow(clippy::too_many_arguments)]
    async fn run_binding_approval(
        &self,
        session: &Arc<Session>,
        binding_name: &str,
        provider: &str,
        prompt_text: &str,
        append_newline: bool,
        caller_deadline: Option<std::time::Instant>,
        raised_before: AutofillGuard,
    ) -> Option<CallToolResult> {
        let hub = self.attach_hub();
        let window = crate::secret::approval_window(
            self.config.daemon.binding_approval_timeout_secs,
            caller_deadline.map(|d| d.saturating_duration_since(self.clock.now())),
        );
        // Epoch seconds off **this daemon's clock**, so a manual-clock
        // test and the daemon agree about when this expires. `now_ms`
        // exists for exactly this: `Instant` is monotonic and has no
        // epoch, and a field named `_unix_secs` must carry one.
        let expires_at_unix_secs = self
            .clock
            .now_ms()
            .saturating_add(window.as_millis() as i64)
            .max(0) as u64
            / 1000;
        // **What the human is actually approving** (GH #45). A binding
        // name reads the same for `ssh prod-01` and for `ssh prod-01 -o
        // ProxyCommand=nc 127.0.0.1 2222`, and the second is the one a
        // person would refuse — so the line goes on the frame beside the
        // name. Redacted element-wise before the join **and stripped of
        // every character that could rewrite the line it is printed on**,
        // because `command`/`args` are the agent's own strings and this
        // frame reaches every attached client.
        let approval = crate::secret::Approval::new(
            &session.id,
            binding_name,
            &crate::secret::binding::redacted_command_line(
                &self.processor.rules,
                &session.command,
                &session.args,
            ),
            provider,
            prompt_text,
            expires_at_unix_secs,
        );
        // `None` means this session already has an approval pending —
        // a second concurrent call reaching step 1 before the first
        // raised its secret request. Falling through is right: the
        // first call owns the question, and two approvals for one
        // session would ask a human twice about one prompt.
        let rx = hub.approvals().raise(approval.clone())?;
        hub.broadcast_binding_approval(&approval);

        let deadline = self.clock.now() + window;
        let sleep = self.clock.sleep_until(deadline);
        tokio::pin!(sleep);
        tokio::pin!(rx);

        // §5.1's third way out, subscribed **before** the first poll so
        // an exit landing in between is still queued for us.
        let mut events = session.subscribe_events();
        let exit = session_exit(session, &mut events);
        tokio::pin!(exit);

        let woke = tokio::select! {
            r = &mut rx => match r {
                Ok(decided) => ApprovalWoke::Decided(decided),
                // The sender went away without answering: somebody took
                // the slot without deciding, which is §17.5's
                // `Superseded` however it was reached.
                Err(_) => ApprovalWoke::Superseded,
            },
            _ = &mut sleep => ApprovalWoke::Deadline,
            _ = &mut exit => ApprovalWoke::Exited,
        };

        // **Each arm is written out, and the two that may read the
        // receiver again are separated from the one that must not.** The
        // first draft folded all three non-decision arms into one
        // `other =>` branch that fell through to the hand-over read on any
        // `taken == false`. On the `Superseded` arm that is a **second
        // poll of a `oneshot::Receiver` that has already completed** —
        // tokio answers it `panic!("called after complete")` — so the
        // branch whose whole purpose was to handle a lost approval
        // defensively was the one that aborted the tool call instead. It
        // is unreachable today only because nothing but this function
        // takes an approval slot, and **Task 13's own hand-off (wiring
        // `forward_events` → `supersede`) is exactly what makes it live**.
        let end = match woke {
            ApprovalWoke::Decided(d) => ApprovalEnd::Decided(d),

            // The receiver completed *inside the `select!`*, with an
            // `Err`. There is nothing further to read and never will be —
            // the sender is gone — so this arm reads nothing. It clears
            // the slot if anything is still there (there should not be;
            // whatever dropped the sender took it) and classifies the
            // loss by [`lost_approval`], **not by the fact that this arm
            // is the one that woke**.
            ApprovalWoke::Superseded => {
                hub.approvals().supersede(&session.id);
                lost_approval(session)
            }

            // The window elapsed. The slot has to be taken under the lock
            // before anything is concluded: a decision that landed between
            // the wake and this line is the truth, and the timer is not.
            ApprovalWoke::Deadline => {
                if hub
                    .approvals()
                    .expire(&session.id, &approval.approval_id)
                    .is_some()
                {
                    ApprovalEnd::Expired
                } else {
                    // Somebody decided between the wake and the lock.
                    // Their answer is on our receiver, or is about to be —
                    // and on *this* arm the receiver has not been polled
                    // to completion, so reading it is legal.
                    //
                    // Real time and not `self.clock`, for the reason
                    // `await_secret` gives: a manual clock nothing
                    // advances would park here forever, and a hand-over
                    // that has already happened is not a deadline.
                    match tokio::time::timeout(SECRET_HANDOVER_GRACE, &mut rx).await {
                        Ok(Ok(d)) => ApprovalEnd::Decided(d),
                        // **The same classifier**, and this is the second
                        // producer of a lost approval. Here the child is
                        // normally alive, which is why the old fold's
                        // blanket `session_died` was wrong on this path.
                        _ => lost_approval(session),
                    }
                }
            }

            // The child ended. Same discipline, and the same classifier:
            // it answers `SessionExited` here because the session really
            // is gone, not because this is the arm that woke.
            ApprovalWoke::Exited => {
                if hub.approvals().supersede(&session.id).is_some() {
                    lost_approval(session)
                } else {
                    match tokio::time::timeout(SECRET_HANDOVER_GRACE, &mut rx).await {
                        Ok(Ok(d)) => ApprovalEnd::Decided(d),
                        _ => lost_approval(session),
                    }
                }
            }
        };

        let (outcome, decided_by) = match &end {
            ApprovalEnd::Decided(d) => (
                match d.decision {
                    crate::attach::frames::ApprovalDecision::Approve => {
                        crate::secret::Outcome::Approved
                    }
                    crate::attach::frames::ApprovalDecision::Deny => crate::secret::Outcome::Denied,
                },
                Some(d.decided_by.as_str()),
            ),
            ApprovalEnd::Expired => (crate::secret::Outcome::Expired, None),
            // §17.5: *"approval discarded; no injection"*, and no audit
            // line at all — §9.4's `outcome` vocabulary has no value for
            // this state (Q13). `audit_binding_approval` is what applies
            // that, off `Outcome::audit_value`.
            ApprovalEnd::SessionExited | ApprovalEnd::Discarded => {
                (crate::secret::Outcome::Superseded, None)
            }
        };
        crate::secret::audit_binding_approval(
            &self.processor.audit,
            &approval,
            outcome,
            decided_by,
        );

        match end {
            ApprovalEnd::Decided(d)
                if d.decision == crate::attach::frames::ApprovalDecision::Approve => {}
            // A denial or an expiry: **REQ-SEC-017**, which names exactly
            // those two and requires the fall-through.
            //
            // A `Discarded` approval joins them, and **that is a choice
            // rather than a requirement — flagged, not cited.**
            // REQ-SEC-017 says *"denied or expired"*; §17.5's `Superseded`
            // row says only *"approval discarded; no injection"*, which is
            // a **prohibition and not a destination** — both candidate
            // answers satisfy it, and the spec picks neither. The choice
            // made here is the human prompt, on the same reading every
            // other non-resolution in §5.2's step 1 already gets: an
            // approval that was never granted is *not approved*, and the
            // fall-through is what the agent gets for every other reason
            // a binding did not resolve. Recorded so the next reader looks
            // rather than stops.
            ApprovalEnd::Decided(_) | ApprovalEnd::Expired | ApprovalEnd::Discarded => return None,
            // The session is gone. §5.1's answer is exact, and it is
            // **not** a fall-through: that would raise a request, write a
            // `secret_input_request` line, and broadcast an
            // `AwaitingSecret` affordance pointing at a child that is
            // already dead — which `await_secret`'s re-raise arm refuses
            // to do for the same reason.
            ApprovalEnd::SessionExited => {
                return Some(envelope::envelope(
                    Status::SessionDied,
                    json!({ "exit_code": session.exit_code() }),
                    "the session exited while a binding approval was outstanding",
                ))
            }
        }

        // §17.5's `Approved`: *"resolve reference, inject value into PTY,
        // zero it, audit-log"*. The resolution happens **now** and not
        // before the approval — a value fetched speculatively and
        // discarded on denial is a credential read out of a store nobody
        // agreed to read.
        let security = self.config.security.clone();
        let processor = Arc::clone(&self.processor);
        let for_task = Arc::clone(session);
        let name = binding_name.to_string();
        let outcome = tokio::task::spawn_blocking(move || {
            crate::secret::binding::autofill_approved(
                &security,
                &for_task,
                &name,
                append_newline,
                &processor.audit,
            )
        })
        .await;

        let resolved = match outcome {
            Ok(Autofill::Resolved(resolved)) => resolved,
            // An approved binding whose provider refused, whose budget is
            // spent, or which the session no longer selects. Silent to
            // the agent and identical to every other fall-through: the
            // human is asked for the value instead.
            _ => return None,
        };
        self.inject_resolved(session, resolved, &raised_before)
            .await
    }

    /// §9.6's `autofill_on_echo_off`: the daemon's own listener on §8.3's
    /// echo-drop edge, armed once per session.
    ///
    /// > *"When §8.3 raises `interaction_mode: AwaitingSecret` and a
    /// > binding matches, Holdfast can resolve and inject **without any
    /// > agent tool call at all** if `security.autofill_on_echo_off = true`
    /// > (default `false`). That default is deliberate: silent credential
    /// > injection is powerful and should be opted into per deployment, not
    /// > inherited."*
    ///
    /// §16.4's closing note is the behavioural statement: *"steps 4–7
    /// collapse: the daemon resolves and injects at step 3 and the agent
    /// never makes a secret-related call at all."*
    ///
    /// **Off, this function spawns nothing and subscribes to nothing**, and
    /// that is REQ-SEC-014 as behaviour rather than as a config assertion:
    /// with the flag unset there is no listener, so no binding is consulted
    /// and no provider can run however the session behaves. It is the same
    /// discipline `request_secret_input`'s `step_one_possible` guard uses —
    /// the default posture costs nothing, not even a task.
    ///
    /// **The mode and binding-set guards are the same two functions step 1
    /// checks**, deliberately, in the shape this file already uses twice:
    /// one copy is a guard that decides whether to spawn, the other is the
    /// rule itself inside [`crate::secret::binding::autofill`], and they
    /// call the same function so the rule cannot change for one and not the
    /// other. `autofill_on_echo_off = true` with `secret_provider =
    /// "prompt"` is refused at config load (Task 1), so the mode check here
    /// is defence in depth for a `SecurityConfig` built in Rust.
    ///
    /// **This listener does not raise the request, and that is a decision.**
    /// §16.4 step 3's raise is `attach::conn::forward_events`', once per
    /// connection, and it stays there: a raise made here would have no
    /// owner when nobody is attached, because the `AwaitingSecretLeft` and
    /// `Exited` arms that close a slot are also per connection — leaving a
    /// per-daemon entry keyed by a session nothing ever releases, which is
    /// GH #24's shape and one this project has already paid for. What this
    /// listener does instead is *satisfy* whatever raise exists: with a
    /// client attached the autofill takes that raise and closes it
    /// `fulfilled`, which is the `SecretRequestClosed { outcome:
    /// "fulfilled" }` §7.5 promises; with nobody attached there is no raise
    /// to close and no client to tell.
    pub(crate) fn watch_for_autofill(&self, session: &Arc<Session>) {
        if !self.config.security.autofill_on_echo_off
            || !crate::secret::binding::keychain_step_runs(&self.config.security.secret_provider)
            || self.config.security.secret_bindings.is_empty()
        {
            return;
        }
        // Subscribe **then** re-check liveness, the same order
        // [`session_exit`] uses and for a sharper reason here: this task
        // holds an `Arc<Session>`, so the sender never drops under it and a
        // `Closed` would never arrive. A child that ended between the
        // caller's spawn and this subscription would leave the task parked
        // on a `recv()` that can no longer produce anything, holding the
        // session alive forever.
        let mut events = session.subscribe_events();
        if !session.is_alive() {
            return;
        }
        let server = self.clone();
        let session = Arc::clone(session);
        tokio::spawn(async move {
            use crate::session::SessionEvent;
            use tokio::sync::broadcast::error::RecvError;
            loop {
                match events.recv().await {
                    Ok(SessionEvent::AwaitingSecretEntered { .. }) => {
                        // **The prompt text is not carried across.** It is
                        // read off the session inside step 1, from the
                        // detector's own line, exactly as a tool-call
                        // autofill reads it — this listener has no argument
                        // to pass and must not grow one (REQ-SEC-012).
                        server.autofill_on_echo_drop(&session).await;
                    }
                    // The child ended. Nothing further can drop echo, and
                    // an autofill for a dead session is a write to a closed
                    // PTY.
                    Ok(SessionEvent::Exited { .. }) => return,
                    Ok(SessionEvent::AwaitingSecretLeft) => {}
                    // An edge is not a stream. A lagged listener has missed
                    // an echo drop, and there is nothing to replay: the
                    // session is the authority on whether it is still
                    // blocked, and it says so on the next edge.
                    Err(RecvError::Lagged(_)) if !session.is_alive() => return,
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                }
            }
        });
    }

    /// One echo drop, resolved and injected with no tool call in sight.
    ///
    /// **The `CallToolResult` is built and discarded, and that is §16.4's
    /// "steps 4–7 collapse" rather than waste.** `autofill_from_binding` is
    /// the whole of step 1 including the slot check that stops a credential
    /// being typed into a prompt somebody else has already answered
    /// (GH #35), and a second hand-written copy of that tail is a second
    /// place to get it wrong in the one function where getting it wrong
    /// puts a password on a tty input queue. The answer it produces has
    /// nobody to go to; the write it performed is the point.
    ///
    /// **Skipped when a tool call is already waiting on the slot.** That
    /// call owns the answer — it will run step 1 itself — and injecting
    /// behind it is the same two-values-in-one-`getpass` failure the slot
    /// check exists to prevent, reached from a third side.
    async fn autofill_on_echo_drop(&self, session: &Arc<Session>) {
        if self.attach_hub().secrets().has_waiter(&session.id) {
            return;
        }
        // `true`: an echo-off prompt is waiting for a *line*, which is the
        // same default `RaisedRequest` carries for a raise with no waiter.
        // There is no caller here to have expressed `append_newline`.
        match self.autofill_from_binding(session, true).await {
            StepOne::Done(_) => {}
            // §17.5, with no caller. **`require_confirm` is still honoured
            // — autofill is not "skip every gate"**, which is exactly the
            // silent injection REQ-SEC-014's default protects against.
            StepOne::NeedsApproval {
                binding_name,
                provider,
                raised_before,
            } => {
                // The session's own prompt line, already redacted on the
                // way out of the reader (§9.2). There is no agent string on
                // this path, so the human is shown what the *child* asked
                // for, which is the only description that exists.
                let prompt_text = session.prompt_last_line_redacted();
                let _ = self
                    .run_binding_approval(
                        session,
                        &binding_name,
                        &provider,
                        &prompt_text,
                        true,
                        // No caller, so nothing to halve: §17.5's
                        // configured value applies in full.
                        None,
                        raised_before,
                    )
                    .await;
            }
            // Every fall-through leaves the child exactly as §8.3 found it:
            // blocked at an echo-off prompt with whatever affordance a
            // human already has. There is no caller to tell and nothing to
            // fall through *to*.
            StepOne::FellThrough => {}
        }
    }

    /// The session died under an autofill write.
    ///
    /// Same shape as the prompt path's §5.1 answer. The
    /// `binding_resolved` entry is already written and stays: the binding
    /// *did* resolve, and the session dying afterwards is a different
    /// fact.
    fn session_died_under_autofill(&self, session: &Arc<Session>) -> CallToolResult {
        envelope::envelope(
            Status::SessionDied,
            json!({ "exit_code": session.exit_code() }),
            "the session exited while its binding was being resolved",
        )
    }

    /// §9.4's `secret_input_request`.
    ///
    /// **`prompt_text` is handed over raw.** `AuditLog::record` redacts
    /// every string in the payload it is given, so pre-redacting here
    /// would make an end-to-end assertion about that redaction pass
    /// whether or not it happened. The secret *value* never comes near
    /// this call — §9.2 marks it `n/a` because it reaches no boundary a
    /// redactor could run at, and if a value ever arrives here the
    /// protection that matters has already failed.
    ///
    /// **`timeout_secs` and `max_secret_bytes` are the *effective*
    /// values**, after defaults. An entry recording `null` for an omitted
    /// argument tells an operator nothing about what the daemon enforced,
    /// and the omitted form is the common call shape.
    fn audit_secret_request(
        &self,
        session_id: &str,
        request_id: &str,
        prompt_text: &str,
        timeout_secs: u32,
        max_secret_bytes: u32,
        raised_by: RaisedBy,
    ) {
        self.processor.audit.record(
            "secret_input_request",
            Some(session_id),
            json!({
                "request_id": request_id,
                "prompt_text": prompt_text,
                "timeout_secs": timeout_secs,
                "max_secret_bytes": max_secret_bytes,
                // §5.2's mismatch record, and the only one §9.4 provides:
                // a call that *raised* the slot is by construction a call
                // that arrived with no echo-drop raise outstanding. It
                // does not say which mode the session was in; the
                // additive fix is Q9 and is not invented here.
                "raised_by": raised_by.as_str(),
            }),
        );
    }

    /// §9.4's `secret_input_resolved`.
    ///
    /// **`bytes_written` is absent, not `0`, on every outcome but
    /// `secret_provided`** — an operator reading `0` cannot tell it from
    /// a zero-length secret.
    ///
    /// It *is* emitted on an adopted resolution, for a value a human may
    /// have entered on their own initiative, so that value's length
    /// becomes visible to the agent. §5.2 judges that acceptable — it is
    /// the same number the agent would have received had it called first
    /// — and names omitting it as a mitigation it is deliberately
    /// deferring. So: not a new finding, and not quietly omitted here.
    fn audit_secret_resolved(
        &self,
        session_id: &str,
        request_id: &str,
        outcome: &str,
        bytes_written: Option<u64>,
    ) {
        let mut fields = serde_json::Map::new();
        fields.insert("request_id".into(), json!(request_id));
        fields.insert("outcome".into(), json!(outcome));
        if let Some(n) = bytes_written {
            fields.insert("bytes_written".into(), json!(n));
        }
        self.processor.audit.record(
            "secret_input_resolved",
            Some(session_id),
            serde_json::Value::Object(fields),
        );
    }

    /// Wait for the outstanding request to resolve, or for this call's
    /// own deadline.
    ///
    /// **The timer decides nothing.** A `select!` that dropped the
    /// receiver on expiry would lose a `SecretInput` landing in that
    /// window: the value is written to the PTY and the agent is told
    /// `timeout`. So on expiry the caller asks the slot, under the same
    /// lock every other transition takes, whether it is still the waiter.
    ///
    /// **`deadline` is passed in, not recomputed here, and that is a
    /// correctness property rather than a style.** §5.2's rule is that the
    /// window starts at *this call* — which is what makes an adopting
    /// call's deadline its own rather than one that may already have
    /// elapsed — and this function is no longer the first thing the call
    /// does. §17.5's binding approval runs ahead of it and may consume up
    /// to half of `timeout_secs`; a `self.clock.now() + timeout_secs`
    /// computed *here* would therefore be a second full window laid end to
    /// end with the first, and a `require_confirm` call could run for
    /// **1.5×** the number the agent declared. The origin is
    /// `request_secret_input`'s `call_start`, stamped once, on the same
    /// clock the approval's arithmetic uses.
    async fn await_secret(
        &self,
        session: &Arc<Session>,
        request_id: &str,
        rx: tokio::sync::oneshot::Receiver<Resolution>,
        deadline: std::time::Instant,
    ) -> Resolution {
        let sleep = self.clock.sleep_until(deadline);
        tokio::pin!(sleep);
        // **Not `tokio::pin!(rx)`.** See [`AnswerOnce`]: the hand-over
        // read below must be impossible to express once this `select!`
        // has resolved the receiver, and an `Option` the read has to
        // `take` out is what makes it impossible rather than merely
        // avoided.
        let mut rx = AnswerOnce(Some(rx));

        // §5.1's and §5.2's ways out, subscribed **before** the first
        // poll so an edge landing in between is still queued for us. One
        // subscription and one future: the two events arrive on the same
        // ordered broadcast, so whichever comes first is the one that
        // ended the wait, and there is no tie between them to break.
        let mut events = session.subscribe_events();
        let ended = secret_condition_ended(session, &mut events);
        tokio::pin!(ended);

        let woke = tokio::select! {
            r = rx.recv() => match r {
                Ok(resolution) => return resolution,
                // The answering half went away without answering. Fall
                // through to the close, which reports what really
                // happened rather than inventing a reason here.
                Err(_) => Woke::Deadline,
            },
            // `&mut sleep`, so the receiver is still ours afterwards.
            _ = &mut sleep => Woke::Deadline,
            end = &mut ended => match end {
                SecretEnded::Exited(code) => Woke::Exited(code),
                SecretEnded::EchoReturned => Woke::EchoReturned,
            },
        };

        let hub = self.attach_hub();
        match hub
            .secrets()
            .close_on_caller_timeout(&session.id, request_id)
        {
            // The slot was still ours, so nobody resolved it and we now
            // own the close. We *are* the waiter, so there is nobody to
            // answer — the value is returned below.
            Some(raised) => {
                drop(raised);
                match woke {
                    // §5.1: the code, not `timeout` a window later. **No
                    // re-raise**: a child that has exited is not sitting
                    // at a prompt, and a request raised against a dead
                    // session is an affordance pointing at nothing.
                    Woke::Exited(code) => {
                        hub.broadcast_secret_closed(&session.id, request_id, "cancelled");
                        Resolution::SessionDied {
                            exit_code: code.or_else(|| session.exit_code()),
                        }
                    }
                    // §5.2's supersede, reached without an attached
                    // client: the echo-off condition cleared and nothing
                    // was written. **No re-raise** — the child is not at
                    // a prompt any more, and an affordance pointing at
                    // one that has gone is the same defect the exit arm
                    // refuses above.
                    Woke::EchoReturned => {
                        hub.broadcast_secret_closed(&session.id, request_id, "cancelled");
                        Resolution::Cancelled(CancelReason::UserCancelled)
                    }
                    Woke::Deadline => {
                        hub.broadcast_secret_closed(&session.id, request_id, "timeout");
                        // **Q1: a call-driven timeout re-raises if the
                        // child is still asking.** §5.2 makes the deadline
                        // close the *request*, not merely the call — but
                        // the raise is edge-triggered on the transition
                        // *into* `AwaitingSecret`, so closing it while the
                        // child sits at its echo-off prompt removes the
                        // human's affordance and nothing will ever put it
                        // back. New id, new broadcast, `echo_drop`, no
                        // waiter. §5.2's invariant holds: the ids are
                        // sequential, never concurrent.
                        if session.is_awaiting_secret() {
                            let (re, first) =
                                hub.raise_secret(&session.id, &session.prompt_last_line_redacted());
                            if first {
                                hub.broadcast_awaiting_secret(
                                    &session.id,
                                    &re.request_id,
                                    &re.prompt_text,
                                );
                            }
                        }
                        Resolution::Cancelled(CancelReason::Timeout)
                    }
                }
            }
            // Somebody took the slot between the timer firing and this
            // lock. Their answer is on our receiver, or is about to be —
            // the fulfilment path takes the slot before it queues the
            // write and only learns `bytes_written` afterwards. **Report
            // the truth, not the timer.**
            //
            // The grace is real time rather than `self.clock`: a manual
            // clock that nothing advances would park here forever, and a
            // hand-over that has already happened is not a deadline.
            //
            // **`take()`, and the `None` arm is GH #38 closed by
            // construction.** The `select!` above reaches `Woke::Deadline`
            // two ways, and on one of them — the receiver completing with
            // `Err` — there is nothing further to read and never will be.
            // Re-polling a completed `oneshot::Receiver` is not a stale
            // answer, it is `panic!("called after complete")`, which
            // reaches the agent as a `JoinError::Panic` instead of a
            // status. Remembering which arm woke would work and is
            // exactly the discipline this file has already been bitten by
            // (see `run_binding_approval`'s `Superseded` arm), so the
            // receiver is not left where a second read could name it.
            None => match rx.take() {
                Some(rx) => match tokio::time::timeout(SECRET_HANDOVER_GRACE, rx).await {
                    Ok(Ok(resolution)) => resolution,
                    _ => Resolution::Cancelled(CancelReason::Timeout),
                },
                // The answering half dropped its sender without answering
                // *and* something else has since taken the slot. No value
                // was handed over, so the reason the timer would have
                // given is the truthful one.
                None => Resolution::Cancelled(CancelReason::Timeout),
            },
        }
    }

    /// Run one wait and render §5.2's eight shared fields.
    ///
    /// **`wait_for_pattern` and `send_input(wait_for=)` both come through
    /// here, and that is the requirement rather than tidiness**: §5.2 says
    /// the two share holdback semantics *verbatim*, and a second
    /// implementation is what makes "verbatim" drift.
    /// Wait until the session stops executing, for a caller that gave no
    /// pattern.
    ///
    /// **Returns as soon as `interaction_mode` is anything but
    /// `Executing`, and that is the whole contract.** `AtPrompt` is the
    /// expected answer; the other three are returned just as promptly and
    /// on purpose. A `Fullscreen` session never reaches a prompt while
    /// the TUI is up, so blocking would burn the deadline to learn
    /// something knowable now. `AwaitingSecret` *is* a prompt, but one
    /// the caller must answer with `request_secret_input` and never
    /// `send_input` — stalling there would hide the one action that
    /// makes progress. `Exited` has no prompt to reach at all.
    ///
    /// So the caller must read `interaction_mode`, not just `reached`.
    /// That is why §8.3's tier rule applies here: `with_detection`
    /// attaches `detection_tier` and `prompt.reason` to this response,
    /// and at `heuristic` an `AtPrompt` is a guess from quiescence rather
    /// than an OSC 133 marker. A bare boolean would have replaced a
    /// visible wrong answer — the timeout beside `AtPrompt` this whole
    /// feature exists to retire — with an invisible one.
    async fn run_wait_for_idle(
        &self,
        session: &Arc<Session>,
        timeout: Duration,
        clamped: Option<u64>,
    ) -> (Status, serde_json::Map<String, serde_json::Value>) {
        let deadline = std::time::Instant::now() + timeout;

        // **The first sample used to be taken before any sleep, and that is
        // the whole bug this loop is shaped around.** `send_input("make")`
        // followed by `wait_for_pattern()` races the detector's transition
        // into `Executing`: at the instant the wait arrives the shell may not
        // have echoed the line yet, so the mode is still `AtPrompt` and a
        // level-triggered read answers `reached: true`, `status: "ok"` —
        // "the command finished" for a command that has not started.
        // Measured at **1 in 20 on an idle box**, and reported at
        // `detection_tier: "semantic"`, the tier an agent is told to trust.
        // That is the failure this feature exists to retire, inverted: the
        // old bug printed `timeout` beside a true `AtPrompt`, this one
        // printed `ok` beside a false one.
        //
        // Two signals close it, and neither is sufficient alone.
        //
        // **The command counter**, when shell integration is live: a count
        // above the baseline is positive proof that a command really started
        // after this wait began, so returning at the next non-`Executing`
        // sample needs no further evidence. It cannot carry the whole fix
        // because a session with no OSC 133 never advances it, and because a
        // command that finished *before* the call never will either.
        //
        // **A settle window** for everything else: `AtPrompt` has to hold
        // for at least as long as the detector's own quiescence threshold
        // before it is believed, because inside that window "at a prompt" and
        // "has not started yet" are the same observation. The window is read
        // from the session rather than hardcoded — an operator who raises
        // `settle_threshold_ms` would otherwise silently reopen the race.
        //
        // **Residual, stated rather than hidden:** a session that is
        // genuinely idle now pays the settle window before answering. That is
        // the price of not lying, and it is bounded by the threshold. The
        // deeper limitation stands and is documented on the tool: with no
        // pattern this answers *is the session executing*, and only shell
        // integration upgrades that to *did the command finish*.
        // **`command_count()` counts commands *started*, not finished**, and
        // reading it as a completion signal is a mistake this function made
        // once already: `send_input("sleep 30")` emits OSC 133 `C`, the count
        // advances, and a wait that treats that as "done" answers `ok` while
        // the command runs — measured at 19 failures in 30 on an idle box,
        // strictly worse than the race it was meant to close. The completion
        // signal is `output_end_cursor`, set by the `D` marker, exactly as
        // `CommandEntry::exit_code` documents.
        let baseline = session.command_count();
        // **Bounded by the caller's deadline as well as by the detector**
        // (review finding). `settle_threshold_ms` is a per-session argument
        // and a config key, so an operator who raised it past the timeout
        // made short pattern-less waits *unsatisfiable*: measured with
        // `settle_threshold_ms: 5000` and `timeout_secs: 1`, an idle bash
        // returned `reached: false` beside `AtPrompt` at `semantic` tier and
        // confidence 1.0 — the truth and the false thing in one payload,
        // which is the exact failure this whole feature exists to retire.
        //
        // Clamping trades a little of the settle window's protection on very
        // short deadlines for never being guaranteed to lie. The other two
        // guards below — `saw_executing` and the command-history probe —
        // are unaffected and cover the common case; this window is only the
        // fallback for "no shell integration and never observed executing".
        let settle = Duration::from_millis(session.settle_threshold_ms()).min(timeout);
        let mut saw_executing = false;
        let mut idle_since: Option<std::time::Instant> = None;
        // The mode the wait stopped on, or `None` if the deadline won.
        //
        // **A mode and not a bool** (review finding). Folding `Exited`,
        // `AwaitingSecret`, `Fullscreen` and `AtPrompt` into `true` is why a
        // dead session answered `ok` / "pattern matched" with no
        // `exit_code`, while the *pattern* path answered `session_died` for
        // the identical state: one tool, two forms, disagreeing on the wire.
        // The caller maps this to status, details and `exit_code`.
        let stopped_on: Option<InteractionMode> = loop {
            // **Liveness first, and read from the process rather than the
            // detector.** The detector's cached mode can still say `AtPrompt`
            // for a session that has already exited — observed once at
            // `semantic` tier with confidence 1.0 — and the pattern path does
            // not have that blind spot because it polls `is_alive` directly.
            if !session.is_alive() {
                break Some(InteractionMode::Exited);
            }
            let mode = session.detection().interaction_mode;
            match mode {
                // Neither can be mistaken for "about to start the command
                // you just sent", so both answer at once.
                InteractionMode::Exited | InteractionMode::AwaitingSecret => break Some(mode),
                // §5.2: a TUI never returns to `AtPrompt`, so this reports
                // the mode promptly rather than running out the deadline.
                InteractionMode::Fullscreen => break Some(mode),
                InteractionMode::Executing => {
                    saw_executing = true;
                    idle_since = None;
                }
                InteractionMode::AtPrompt => {
                    // Watched it run and watched it stop. Nothing ambiguous
                    // is left, at any tier.
                    if saw_executing {
                        break Some(mode);
                    }
                    // Never saw it execute, so `AtPrompt` is either "finished
                    // before the call" or "not started yet" — the same
                    // observation. Shell integration settles it when present.
                    match session.command_history(baseline, 1).first() {
                        // Started since the baseline and its `D` closed it.
                        Some(e) if e.output_end_cursor.is_some() => break Some(mode),
                        // Started and still open: keep waiting, and do not let
                        // the settle window expire underneath a running child.
                        Some(_) => idle_since = None,
                        // Nothing started. Believe the prompt only once it has
                        // held for the detector's own quiescence window — read
                        // from the session, because an operator who raises
                        // `settle_threshold_ms` would otherwise reopen the race.
                        None => {
                            let since = *idle_since.get_or_insert_with(std::time::Instant::now);
                            if since.elapsed() >= settle {
                                break Some(mode);
                            }
                        }
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            tokio::time::sleep(IDLE_WAIT_POLL).await;
        };

        let mut fields = serde_json::Map::new();
        fields.insert("reached".into(), json!(stopped_on.is_some()));
        if let Some(c) = clamped {
            fields.insert("clamped_timeout_secs".into(), json!(c));
        }
        // **`Exited` is a death, not a success.** §18.1 puts this tool in the
        // `session_died` row with `data.exit_code` set, and the pattern path
        // already answers that way; this one answered `ok` with no exit code,
        // so an agent had to make a second `status` call to discover its
        // shell was gone.
        let status = match stopped_on {
            Some(InteractionMode::Exited) => {
                fields.insert("exit_code".into(), json!(session.exit_code()));
                Status::SessionDied
            }
            Some(_) => Status::Ok,
            None => Status::Timeout,
        };
        (status, fields)
    }

    async fn run_wait(
        &self,
        session: &Arc<Session>,
        pattern: &regex::bytes::Regex,
        since_cursor: Option<u64>,
        max_bytes: usize,
        timeout: Duration,
        clamped: Option<u64>,
    ) -> (Status, serde_json::Map<String, serde_json::Value>) {
        let deadline = std::time::Instant::now() + timeout;
        let outcome = wait::for_pattern(
            session,
            pattern,
            wait::WaitSpec {
                since_cursor,
                timeout,
            },
        )
        .await;

        // A match that intersects `[holdback_boundary, buffer.head)` is
        // withheld — the identical predicate `read_output` applies
        // (REQ-O-004, §4.1). There is no separate match contract and no
        // pending-match lifecycle; if one appears here, re-read §4.1.
        let mut boundary = session.holdback_boundary(&self.processor);
        let mut withheld = outcome.found.is_some_and(|m| m.end > boundary);
        // The boundary advances as the in-flight secret finishes
        // arriving, so a partial that completes before the deadline
        // releases the text (§18.2's second worked example). Only a
        // deadline that elapses with the match still withheld answers
        // `timeout`.
        while withheld && std::time::Instant::now() < deadline && session.is_alive() {
            tokio::time::sleep(HOLDBACK_RELEASE_POLL).await;
            boundary = session.holdback_boundary(&self.processor);
            withheld = outcome.found.is_some_and(|m| m.end > boundary);
        }

        // `output_since_start` runs through the same pipeline as
        // `read_output`, and is clipped **before** `match.offset` when the
        // match is withheld — otherwise the withheld bytes come back
        // through the surrounding context (§5.2).
        let context_cap = match outcome.found {
            Some(m) if withheld => {
                (m.start.saturating_sub(outcome.scan_start) as usize).min(max_bytes)
            }
            _ => max_bytes,
        };
        let context_surface = caller::audit_surface("wait_for_pattern");
        let context = session.read_processed(
            &ReadRequest {
                start: ReadStart::Cursor(outcome.scan_start),
                max_bytes: context_cap,
                options: ReadOptions::default(),
                tool: context_surface.tool,
                client_kind: context_surface.client_kind,
            },
            &self.processor,
        );

        let mut fields = serde_json::Map::new();
        fields.insert("matched".into(), json!(outcome.found.is_some()));
        fields.insert(
            "match".into(),
            match outcome.found {
                None => serde_json::Value::Null,
                Some(m) => {
                    // `offset` is always the raw byte offset, redacted or
                    // not, truncated or not. `text` is omitted — not
                    // nulled — when the match is withheld.
                    let mut obj = serde_json::Map::new();
                    obj.insert("offset".into(), json!(m.start));
                    if !withheld {
                        // **Through `read_processed`, over the expanded
                        // window** — §5.2's "`match.text` is routed
                        // through the OutputProcessor", which
                        // `redact_str` over the match slice alone was
                        // not. A *context* rule keys on a label lying
                        // outside the caller's match (`DD_API_KEY=`
                        // before a 32-hex value), so redacting a
                        // zero-context window can never fire it: 8 of the
                        // 51 built-in rules returned their value
                        // verbatim, beside an `output_since_start` that
                        // showed `[REDACTED:datadog]` for the same bytes
                        // in the same response. The read below is the
                        // same pass `output_since_start` runs — 512 bytes
                        // of lookbehind, trimmed back to the match — so
                        // the two agree by construction rather than by
                        // coincidence.
                        //
                        // It is a second `read_processed` and therefore a
                        // second contribution to `redaction_stats`, which
                        // is correct: that tally counts substitutions
                        // *delivered*, and this response delivers the
                        // marker twice (§5.2, REQ-O-012).
                        let match_surface = caller::audit_surface("wait_for_pattern");
                        let text = session.read_processed(
                            &ReadRequest {
                                start: ReadStart::Cursor(m.start),
                                max_bytes: (m.end - m.start) as usize,
                                options: ReadOptions::default(),
                                tool: match_surface.tool,
                                client_kind: match_surface.client_kind,
                            },
                            &self.processor,
                        );
                        obj.insert("text".into(), json!(text.output));
                    }
                    serde_json::Value::Object(obj)
                }
            },
        );
        fields.insert("output_since_start".into(), json!(context.output));
        fields.insert(
            "truncated_at_tail".into(),
            json!(outcome.truncated_at_tail || context.truncated_at_tail),
        );
        fields.insert(
            "truncated_for_size".into(),
            json!(context.truncated_for_size),
        );
        fields.insert("held_back".into(), json!(withheld || context.held_back));
        fields.insert(
            "next_cursor".into(),
            match (withheld, context.next_cursor) {
                (true, _) => json!(boundary),
                (false, c) => json!(c),
            },
        );
        if let Some(cap) = clamped {
            fields.insert("clamped_timeout_secs".into(), json!(cap));
        }

        let alive = session.is_alive();
        let status = match (outcome.found.is_some(), withheld, alive) {
            (true, false, _) => Status::Ok,
            // Matched but still withheld at the deadline: the operation
            // did not deliver a complete result, so it is not `ok`.
            (_, _, false) => Status::SessionDied,
            _ => Status::Timeout,
        };
        // **`session_died` carries the exit code**, as §18.1's row for this
        // tool requires and as `interrupt` and `send_input` already do. This
        // path reported the status and omitted the datum, so the one answer
        // where the exit code is the only actionable thing was the one
        // answer without it — pre-existing, and the same gap the pattern-less
        // path had for a different reason.
        if status == Status::SessionDied {
            fields.insert("exit_code".into(), json!(session.exit_code()));
        }
        (status, fields)
    }
}

/// The fields `status` and `list_sessions` share. Both are prompt-bearing
/// responses (§5.4), so both pass the result through `with_detection`.
///
/// **One record, one builder, and it stays that way** (REQ-T-016):
/// `schema::SessionRecord` is the advertised `outputSchema` for both
/// tools, so a field emitted by only one of them is the
/// declared-but-unemitted fault REQ-T-015 names.
///
/// It takes the rule set because REQ-T-011 makes `command` and `args`
/// redacted surfaces: a session started as
/// `aws --key AKIAIOSFODNN7EXAMPLE` would otherwise hand the credential
/// back on every `status` call, and `list_sessions` would hand back
/// every session's.
fn session_record(session: &Session, rules: &RuleSet) -> serde_json::Value {
    let state = session.state();
    json!({
        "id": session.id,
        "name": session.name,
        "command": redact_str(rules, &session.command),
        // Element-wise, never joined: joining with a space and redacting
        // the result would let a rule match across an argument boundary
        // and return one string where the agent expects an array.
        "args": session.args.iter().map(|a| redact_str(rules, a)).collect::<Vec<_>>(),
        // §9.6, GH #46. **Where the two fields above came from**, which
        // they cannot say themselves: a profile-started session and an
        // agent-authored one that produced the same argv are otherwise
        // identical on this record, and only the first can ever receive a
        // keychain credential.
        //
        // **Not redacted, and that is not an omission.** Every other
        // string here is agent-authored or child-authored; this one is a
        // name out of the operator's own config file, reached only by
        // having matched one. Running it through `redact_str` would let a
        // built-in rule blank out an operator's chosen name — the same
        // shape as a redactor switching off a binding (§20.6) — for a
        // value that cannot carry a secret unless the operator put one in
        // their own profile name.
        "profile": session.profile,
        "state": state.as_str(),
        "pid": session.pid(),
        "exit_code": session.exit_code(),
        // §5.4 names this field and 0.0.1 left it out with a stated
        // unblocker — "RFC-3339 needs a date crate that arrives in 0.0.3".
        // The crate arrived; the format did not change with it. The tree's
        // settled convention is an explicit `_unix_*` suffix (REQ-T-018),
        // so the wire format cannot silently claim to be RFC 3339.
        "exited_at_unix_secs": session.exited_at_secs(),
        "shell_integration": session.shell_integration.map(|s| s.as_str()),
        // What Holdfast *injected* is the line above; this is what has since
        // been observed on the wire (§18.2a, §8.5.1). The two answer
        // different questions and a session can carry `"fish"` here with
        // `"external"` below. `start_session`'s response deliberately gets
        // neither this nor a null for it: §5.2 does not list it there, and
        // it would be null at every call by construction.
        "osc133_source": session.osc133_source().map(|s| s.as_str()),
        "command_count": session.command_count(),
        "started_at_unix_secs": unix_secs(session.created_at),
        "last_activity_unix_ms": session.last_activity_ms(),
        // §5.2 declares `idle_deadline` and nothing emitted it. Named for
        // its unit per REQ-T-018 — `tests/schema.rs` keeps a
        // `BARE_TEMPORAL_NAMES` list with `idle_deadline` on it precisely
        // so the bare spelling cannot come back. `null` means reaping is
        // disabled for this session (`idle_timeout_secs = 0`), which is a
        // different statement from "the deadline is far away".
        "idle_deadline_unix_secs": session.idle_deadline_ms().map(|ms| ms / 1000),
        "buffer": {
            "head": session.buffer_head(),
            "tail": session.buffer_tail(),
            "total_bytes": session.buffer_head().saturating_sub(session.buffer_tail()),
            // §5.4 declared this from rev. 2 and nothing emitted it. It
            // is honest only now that `resources/read` resolves it —
            // emitting a URI that does not resolve is worse than an
            // absent field, which is why 0.0.3 was told not to stub it.
            "resource_uri": crate::mcp::resources::ResourceUri::buffer_uri(&session.id),
        },
        // The session's cumulative tally (§9.2, REQ-O-012), and a
        // *different* number from `read_output.redactions`: that one
        // describes the bytes one response returned, this one describes
        // the session. An empty `BTreeMap` serialises to `{}`, which is
        // what REQ-O-012 requires — present and empty, never absent.
        "redaction_stats": session.redaction_stats(),
    })
}

#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ReadOutputArgs {
    /// Session id or live session name.
    pub session: String,
    /// Read forward from this absolute byte offset.
    #[serde(default)]
    pub since_cursor: Option<u64>,
    /// Read the last N lines instead.
    #[serde(default)]
    pub tail_lines: Option<usize>,
    /// Read the last N bytes instead.
    #[serde(default)]
    pub tail_bytes: Option<usize>,
    /// Cap on RAW bytes read from the buffer. Defaults to 32768, hard
    /// limit 262144. Must be at least 1: a zero cap can never make
    /// forward progress. The encoded payload may be larger or smaller.
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// "strip" (default) removes ANSI/VT100 escape sequences; "raw"
    /// preserves them. Independent of `redact`.
    #[serde(default)]
    pub ansi: Option<String>,
    /// "utf8" (default), "base64", or "lossy_printable". Byte-exact
    /// capture is "base64" together with `redact: false`.
    #[serde(default)]
    pub text_encoding: Option<String>,
    /// Redact secrets (default true). Setting false returns raw secret
    /// bytes and is recorded in the audit log.
    #[serde(default)]
    pub redact: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SendInputArgs {
    /// Session id or live session name.
    pub session: String,
    /// Text to write to the session's stdin. At most 65536 bytes.
    pub data: String,
    /// Append a newline. Defaults to true.
    #[serde(default)]
    pub append_newline: Option<bool>,
    /// Regex to wait for after the write, with the same semantics and
    /// response fields as wait_for_pattern. Output is scanned from
    /// immediately before the write, so the child's echo is included.
    #[serde(default)]
    pub wait_for: Option<String>,
    /// Deadline for wait_for, in seconds. Defaults to 30; 0 means no
    /// caller deadline, capped at 3600.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WaitForPatternArgs {
    /// Session id or live session name.
    pub session: String,
    /// Rust regex matched against the session's raw output bytes.
    ///
    /// **Omit it to wait for the session to stop executing instead. An empty      string is rejected rather than treated as either, because it is a likely client      encoding of \"omit\" and it used to match at offset zero and complete instantly** —
    /// which is not the same claim as "the command finished"; see
    /// `run_wait_for_idle` for what each tier can actually establish. A
    /// shell-prompt regex is a guess about the operator's `$PS1` and
    /// silently never matches a customised one, so "wait until the
    /// command finishes" is answered from the detector rather than from
    /// text. Supply this only for a *program's* prompt — `Password:`,
    /// `(gdb)`, `>>>` — which is text no detector knows about.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Deadline in seconds. Defaults to 30. 0 means "no caller deadline"
    /// and is capped at 3600, reported back as clamped_timeout_secs.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Start scanning from this absolute offset. Defaults to the current
    /// buffer head, i.e. live output only.
    #[serde(default)]
    pub since_cursor: Option<u64>,
    /// Cap on RAW bytes of output_since_start. Defaults to 32768, hard
    /// limit 262144. Must be at least 1.
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TerminateArgs {
    /// Session id or live session name.
    pub session: String,
    /// Skip the graceful SIGTERM and send SIGKILL immediately.
    #[serde(default)]
    pub force: Option<bool>,
    /// Seconds to wait after SIGTERM before escalating. Defaults to 5.
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct StatusArgs {
    /// Session id or live session name.
    pub session: String,
}

/// `request_secret_input`'s arguments.
///
/// **The only `*Args` struct in the tree that denies unknown fields, and
/// deliberately so.** Every other one accepts an extra key silently, so
/// without this line REQ-SEC-010a's *"the tool accepts `session` and
/// never a `request_id`"* would rest on a schema a client is free to
/// ignore: a smuggled `request_id` would be swallowed rather than
/// refused, and the agent's inability to *name* a secret request would be
/// documentation instead of a control. Two consequences, both
/// load-bearing: the rejection surfaces as `invalid_params`, the same
/// shape as every other input-schema violation here; and `schemars` emits
/// `"additionalProperties": false` on this tool's input schema and no
/// other's.
///
/// It is **not** extended to the other ten args structs in this
/// milestone. Widening a deserialiser's strictness across the whole tool
/// surface is a client-compatibility decision, and it is not a secrets
/// decision.
#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestSecretInputArgs {
    /// Session id or live session name. **The only selector.** §5.2: the
    /// tool takes `session`, never a `request_id` — the id is returned to
    /// you and never accepted from you (REQ-SEC-010a).
    pub session: String,
    /// What is being asked for, e.g. "sudo password for deploy-user". At
    /// most 512 bytes of UTF-8 (§9.5). This reaches no credential lookup:
    /// bindings match the session's own command line and the observed
    /// prompt, never this string (§9.6, REQ-SEC-012).
    pub prompt_text: String,
    /// Default true. §5.2's normalisation is the daemon's job, not the
    /// client's: exactly one trailing `\r\n` or `\n` is stripped from the
    /// received bytes, then `\n` is appended when this is true.
    #[serde(default)]
    pub append_newline: Option<bool>,
    /// Default 120. Rejected when 0 or above
    /// `security.secret_input_max_timeout_secs` (default 900).
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    /// Default 4096. Rejected when 0 or above
    /// `security.max_secret_bytes_ceiling` (default 65536).
    #[serde(default)]
    pub max_secret_bytes: Option<u32>,
}

/// §9.5's cap on `request_secret_input.prompt_text`, in **bytes**.
///
/// Bytes and not characters: §9.5 says bytes, and a `chars().count()`
/// implementation admits 512 three-byte codepoints — 1536 bytes — into a
/// field that is broadcast to every attached client and written to the
/// audit log.
pub const MAX_PROMPT_TEXT_BYTES: usize = 512;

/// `request_secret_input.timeout_secs` when the caller does not say.
pub const DEFAULT_SECRET_TIMEOUT_SECS: u32 = 120;

/// `request_secret_input.max_secret_bytes` when the caller does not say.
pub const DEFAULT_MAX_SECRET_BYTES: u32 = 4096;

/// How long a timed-out caller waits for an answer it has just discovered
/// somebody else owns.
///
/// Not a deadline: by the time this is reached the slot has already been
/// taken by a resolver that is committed to answering, and the only thing
/// outstanding is a PTY write. It is bounded anyway, because an unbounded
/// wait in this position turns a wedged writer into a hung CI job rather
/// than a red row.
const SECRET_HANDOVER_GRACE: Duration = Duration::from_secs(10);

/// A resolution receiver that **cannot be polled after it completes**.
///
/// `tokio::sync::oneshot::Receiver` answers a second poll with
/// `panic!("called after complete")`, and it counts an `Err` — the sender
/// dropped without sending — as completing. GH #38 is that panic, reached
/// through a `select!` whose receiver arm falls through to a later
/// hand-over read of the same receiver: the branch written to handle a
/// lost answer *defensively* is the one that aborts the tool call, and the
/// agent gets a `JoinError::Panic` where a status belongs.
///
/// The cure is not to remember which arm woke. [`recv`](Self::recv) takes
/// the receiver **out** of the option on the way to resolving it, so the
/// arm that completed it leaves nothing behind that a later
/// [`take`](Self::take) can return, and the second read is a `None` the
/// compiler makes the caller handle rather than a panic at runtime. A
/// `select!` whose branches must not disagree about whether a value is
/// still readable is exactly the shape that should not be held together by
/// a comment.
struct AnswerOnce(Option<tokio::sync::oneshot::Receiver<Resolution>>);

impl AnswerOnce {
    /// Wait for the answer. Cancel-safe: a `recv` future dropped before it
    /// resolves puts nothing back, because it took nothing out — the
    /// receiver is only surrendered once it has actually completed.
    ///
    /// Parks forever if the receiver is already gone, which is correct for
    /// a `select!` arm and is why the hand-over read below uses
    /// [`take`](Self::take) instead of calling this again.
    async fn recv(&mut self) -> Result<Resolution, tokio::sync::oneshot::error::RecvError> {
        let Some(rx) = self.0.as_mut() else {
            return std::future::pending().await;
        };
        let answered = rx.await;
        self.0 = None;
        answered
    }

    /// The receiver, if it has **not** already completed. `None` is the
    /// state in which polling it again would panic.
    fn take(&mut self) -> Option<tokio::sync::oneshot::Receiver<Resolution>> {
        self.0.take()
    }
}

/// Why [`HoldfastServer::await_secret`] stopped waiting on its receiver.
///
/// Only the two that need a close. A receiver that answered returns
/// straight out of the `select!` and never reaches here.
enum Woke {
    /// The call's own `timeout_secs` elapsed — or the answering half was
    /// dropped without answering, which the close then reports truthfully
    /// rather than guessing at.
    Deadline,
    /// §5.1: the child ended while the call was waiting.
    Exited(Option<i32>),
    /// §5.2's supersede: echo came back with no value written.
    EchoReturned,
}

/// What ended a §17.5 binding-approval wait.
///
/// **A second enum rather than a widened [`Woke`], and the reason is that
/// the two waits end differently.** A secret request that times out
/// answers the caller `secret_cancelled { reason: "timeout" }`; an
/// approval that times out answers the caller *nothing at all* and falls
/// through to the human prompt. Folding them would put a `Deadline` arm
/// in front of two callers that must do opposite things with it, which is
/// how one of them comes to do the other's.
enum ApprovalWoke {
    /// An `ApproveBinding` arrived, with the deciding connection's kind.
    Decided(crate::secret::Decided),
    /// The approval window elapsed (§17.5's `Expired`).
    Deadline,
    /// The child ended (§17.5's `Superseded`).
    Exited,
    /// The registry entry went away without a decision, so the sender was
    /// dropped and **the receiver completed inside the `select!`**.
    ///
    /// **This variant's arm must not read the receiver again**, and the
    /// first draft did: it fell through to the hand-over read, and tokio
    /// answers a second poll of a completed `oneshot` with
    /// `panic!("called after complete")`, killing the tool-call task
    /// instead of answering it. Unreachable in this milestone — nothing
    /// but `run_binding_approval` takes an approval slot — and **Task
    /// 13's hand-off, wiring `forward_events` → `supersede`, is precisely
    /// what makes it reachable**, which is why it is fixed here rather
    /// than filed. The safe reading of a lost approval is *not approved*.
    Superseded,
}

/// How one §17.5 approval ended, **after** the slot has been taken under
/// the lock and the truth is settled.
///
/// A separate type from [`ApprovalWoke`], which records only *what woke
/// the wait*. The two differ on every arm that can be overtaken: a
/// `Deadline` wake whose `expire` finds the slot already gone did not
/// expire, and an `Exited` wake whose `supersede` finds it gone was
/// decided. Collapsing them is how a timer comes to report a decision
/// somebody else made.
enum ApprovalEnd {
    Decided(crate::secret::Decided),
    /// §17.5's `Expired`: the window elapsed with nobody deciding.
    Expired,
    /// §17.5's `Superseded`, by the one trigger this milestone can
    /// produce — the child ended. §5.1's `session_died` is exact.
    SessionExited,
    /// §17.5's `Superseded`, with the session still running: the slot was
    /// taken without a decision and there is still a child, and a human,
    /// to fall back to. **Falls through to the human prompt.**
    Discarded,
}

/// Classify a §17.5 approval that ended **without a decision**.
///
/// **The question is *"is there still a session and a human to fall back
/// to?"*, so the test is liveness — never which `select!` branch woke.**
/// That distinction is the whole of this function and it is not
/// hypothetical. `BindingApprovals::supersede`'s own doc says its caller
/// *"arrives from the session… a child that has exited supersedes
/// whatever is pending on it"*, and Task 13's sweep is
/// `attach::conn::forward_events`' **`Exited`** arm — so the third party
/// that will drop the sender **is itself a session exit**. Both the `rx`
/// branch (as `Err`) and the `exit` branch then become ready on one
/// event, and `tokio::select!` picks between ready branches at
/// **random**. Classifying by wake-cause would make one event produce two
/// different answers, one of which raises a secret request, writes a
/// `secret_input_request` line and broadcasts an `AwaitingSecret` to
/// every attached human — for a child that is already gone.
///
/// There is no parameter here a wake cause could be passed in through,
/// which is the structural half of the same statement.
///
/// **Both outcomes are §17.5's `Superseded`** for audit purposes — see
/// [`ApprovalEnd`]'s two variants and `Outcome::audit_value`, which
/// writes no `binding_approval` line for either (Q13). They differ only
/// in what this caller can still do.
fn lost_approval(session: &Arc<Session>) -> ApprovalEnd {
    if session.is_alive() {
        ApprovalEnd::Discarded
    } else {
        ApprovalEnd::SessionExited
    }
}

/// The state §9.6's autofill took its decision against, carried across
/// everything it waits on and checked again at the write.
///
/// **Two halves, because the credential can be invalidated two ways and
/// neither sees the other.**
///
/// * `slot` is the secret slot (GH #35): a raise answered while the
///   provider ran means a human has already typed a value.
/// * `writes` is [`Session::writes_performed`]: *anything* written to this
///   child in the window may have satisfied the read the credential was
///   resolved for — most obviously an MCP `send_input`, which §5.2 permits
///   during `AwaitingSecret` (REQ-SEC-011) and which touches no slot at
///   all.
///
/// The first is checked here, under the slot's lock; the second is checked
/// **in the writer thread**, because a check here is separated from the
/// write by the write queue and bytes already in that queue are exactly
/// the case it has to catch. See [`WriteRequest::SecretIfUnread`].
#[derive(Debug, Clone)]
struct AutofillGuard {
    slot: SlotSnapshot,
    writes: u64,
}

/// What §5.2's step 1 concluded, for the one caller that acts on it.
///
/// **Three answers and not `Option<CallToolResult>`, because §17.5 added
/// a third.** `None` used to mean *"fall through"* and now has to be told
/// apart from *"a human has to decide first"* — and the two are handled
/// in different places on purpose: the approval needs the agent's
/// `prompt_text`, and `autofill_from_binding`'s security property is that
/// it has no parameter that string could enter (REQ-SEC-012). Carrying
/// the distinction out as a value is what lets the approval be sited
/// where the string legitimately lives.
enum StepOne {
    /// Resolved, written, and this is the caller's answer.
    Done(CallToolResult),
    /// §17.5's `Pending`: a `require_confirm` binding matched. **Nothing
    /// has been resolved, no `max_uses` has been spent and no provider
    /// has run** — §9.6's *"ask me first"* is answered before the store
    /// is touched, not after.
    NeedsApproval {
        binding_name: String,
        provider: String,
        /// The slot as it stood **before** step 1 began, threaded through
        /// the approval wait so the check in
        /// [`HoldfastServer::inject_resolved`] covers the human round
        /// trip as well as the provider call. Read off the hub and never
        /// from an argument.
        raised_before: AutofillGuard,
    },
    /// Step 2: broadcast `AwaitingSecret` and wait for a human.
    FellThrough,
}

/// What ended the condition a secret request was waiting on.
enum SecretEnded {
    /// §5.1: the child ended.
    Exited(Option<i32>),
    /// §5.2's supersede: echo came back with no submission.
    EchoReturned,
}

/// Resolve when the child stops being able to answer: it exits, **or**
/// echo comes back with nothing written.
///
/// **The second half is I-1, and it is the same defect `session_exit`
/// exists for, one event over.** `request.rs` states the property
/// outright — *"`user_cancelled` has exactly one producer and it is this
/// line"* — and that line lives in `attach::conn::forward_events`, which
/// is **one task per attach connection** and is `abort()`ed with it. So
/// with nobody attached (which is exactly the deployment §9.5's rung-3
/// buffer notice exists for) a child that abandons its own echo-off read
/// produced no observer at all: the event went onto the session broadcast
/// and was consumed by nothing, the slot stayed raised, and the call sat
/// out its **entire** `timeout_secs` and answered `timeout`. Driven A/B by
/// the concurrency review: `user_cancelled after 2.0s` attached,
/// `timeout after 10.0s` unattended — the same child, decided by whether a
/// human happened to be watching. The mid-wait variant is the same defect
/// from the other side: a human who detaches takes the only producer with
/// them.
///
/// §5.1's `session_died` got its caller-owned second observer this
/// milestone; §5.2's supersede did not. This is it.
///
/// **The echo half is strictly edge-triggered and deliberately has no
/// level re-check**, unlike the liveness half below. `!is_awaiting_secret()`
/// is *also* true of a request the tool raised on a child whose echo was
/// never off at all — `no_client_attached_still_waits_the_full_window`
/// drives exactly that against a `cat` — and answering `user_cancelled`
/// there would invent §5.2's refused `no_client_attached` reason under a
/// different name. Only the **transition** means what `user_cancelled`
/// says. The residual is an edge landing between the raise and this
/// subscription, which is the same window `forward_events` has always had.
///
/// Two observers of one edge is the arrangement §5.1 already runs, and it
/// is safe for the same reason: whichever reaches the slot first answers,
/// and the loser's `close_on_caller_timeout` returns `None` and reads the
/// winner's answer off the hand-over channel. They agree.
async fn secret_condition_ended(
    session: &Session,
    events: &mut tokio::sync::broadcast::Receiver<crate::session::SessionEvent>,
) -> SecretEnded {
    use crate::session::SessionEvent;
    use tokio::sync::broadcast::error::RecvError;

    if !session.is_alive() {
        return SecretEnded::Exited(session.exit_code());
    }
    loop {
        match events.recv().await {
            Ok(SessionEvent::Exited { code }) => return SecretEnded::Exited(Some(code)),
            Ok(SessionEvent::AwaitingSecretLeft) => return SecretEnded::EchoReturned,
            Err(RecvError::Closed) => return SecretEnded::Exited(session.exit_code()),
            Err(RecvError::Lagged(_)) if !session.is_alive() => {
                return SecretEnded::Exited(session.exit_code())
            }
            Ok(_) | Err(RecvError::Lagged(_)) => {}
        }
    }
}

/// Resolve when this session's child ends, with the code it ended with.
///
/// **The session's own event stream, and not an attached client's.**
/// `SessionEvent` is consumed only in `attach::conn`, once per connection,
/// so a `request_secret_input` call on a session nobody has attached to
/// has no consumer at all — and an unattended session is precisely the
/// shape §9.5's buffer notice exists for. Worse, the consumer that *does*
/// exist loses to the event it handles: `attach::conn::run` ends its
/// `select!` the moment the forwarder reports `SessionExit` and then calls
/// `events.abort()`, so the arm that answers `session_died` is aborted by
/// the very exit that would have triggered it. Measured: a call on a
/// session killed under it returned `timeout` after its **full** window.
async fn session_exit(
    session: &Session,
    events: &mut tokio::sync::broadcast::Receiver<crate::session::SessionEvent>,
) -> Option<i32> {
    use crate::session::SessionEvent;
    use tokio::sync::broadcast::error::RecvError;

    // Subscribe-then-recheck. An exit landing between the caller's
    // liveness test and this subscription is in neither, and this call
    // would then wait out a window for a child that was already gone —
    // which is the defect, one race narrower.
    if !session.is_alive() {
        return session.exit_code();
    }
    loop {
        match events.recv().await {
            Ok(SessionEvent::Exited { code }) => return Some(code),
            // Every sender is gone, so the session is.
            Err(RecvError::Closed) => return session.exit_code(),
            // A lagged receiver may have skipped the exit. The session is
            // the authority and it does not lag; anything else is an edge
            // this call does not care about.
            Err(RecvError::Lagged(_)) if !session.is_alive() => return session.exit_code(),
            Ok(_) | Err(RecvError::Lagged(_)) => {}
        }
    }
}

/// `Default` for the reason 0.0.2 put it on `StartSessionArgs`: every
/// later milestone adds arguments here, and an exhaustive literal repaired
/// by naming the new field breaks again next milestone.
#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct GetScreenStateArgs {
    /// Session id or live session name.
    pub session: String,
    /// A `screen_revision` returned by an earlier call. When it names a
    /// revision Holdfast still retains, the response carries only the
    /// changed regions; otherwise a full grid comes back.
    #[serde(default)]
    pub diff_from: Option<u64>,
    /// Redact secrets in the rendered rows (default true). Setting false
    /// returns the screen with secret values intact and is recorded in
    /// the audit log. A `diff_from` naming a revision captured under the
    /// other setting returns a full grid rather than a diff.
    #[serde(default)]
    pub redact: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ResizeArgs {
    /// Session id or live session name.
    pub session: String,
    /// New terminal width in columns, 1 to 1000. A value outside that
    /// range is clamped to it; the response reports the size reached.
    pub cols: u16,
    /// New terminal height in rows, 1 to 1000. A value outside that
    /// range is clamped to it; the response reports the size reached.
    pub rows: u16,
}

#[derive(Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct InterruptArgs {
    /// Session id or live session name.
    pub session: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct GetCommandHistoryArgs {
    /// Session id or live session name.
    pub session: String,
    /// Most recent N entries. Defaults to 50.
    #[serde(default)]
    pub limit: Option<usize>,
    /// Only entries with `index >= since_index`.
    #[serde(default)]
    pub since_index: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SessionProfile;
    use crate::pty::MockPty;
    use crate::session::{new_session_id, Session, SessionConfig};
    use serde_json::Value;
    use std::time::Instant;

    /// **A lost §17.5 approval is classified by the session, never by
    /// which `select!` branch woke.**
    ///
    /// The deterministic half of
    /// `secret::binding::tests::an_exit_that_races_the_supersede_answers_the_same_way`:
    /// that row drives the real race and has to repeat, because
    /// `tokio::select!` picks between ready branches at random. This one
    /// asserts the rule itself, in one line each way, with no scheduler
    /// involved.
    ///
    /// The structural half is [`lost_approval`]'s signature — there is no
    /// parameter a wake cause could be passed in through — and this is
    /// the behavioural half.
    #[tokio::test]
    async fn a_lost_approval_is_classified_by_the_session_and_not_by_the_wake() {
        let pty = Arc::new(MockPty::new());
        let session = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::default(),
        );

        // A live session still has a human and a child to fall back to.
        assert!(
            matches!(lost_approval(&session), ApprovalEnd::Discarded),
            "a lost approval on a live session must fall through to the prompt"
        );

        pty.exit(0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.is_alive() {
            assert!(Instant::now() < deadline, "the fixture's child never died");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // And a dead one has neither, so §5.1's answer is the only honest
        // one. **The pairing above is what makes this an assertion about
        // liveness** rather than about a function that always says
        // `SessionExited`.
        assert!(
            matches!(lost_approval(&session), ApprovalEnd::SessionExited),
            "a lost approval on a dead session must not raise a prompt nobody can answer"
        );
    }

    /// The set of tools the router actually advertises.
    ///
    /// `tests/schema.rs` checks REQ-T-013 and REQ-T-014 — an
    /// `outputSchema` and the §5.3 annotations on *every* tool — against a
    /// hand-written list, because `tool_router()` is `pub(crate)` and an
    /// integration test cannot reach it. A tool added to this `impl` and
    /// not to that list would simply not be checked, and "every tool"
    /// would quietly mean "the four we remembered". This is the link that
    /// makes the enumeration complete: add a tool without listing it there
    /// and this goes red first.
    #[test]
    fn the_router_advertises_exactly_the_0_0_7_tool_set() {
        let mut names: Vec<String> = HoldfastServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "get_command_history",
                "get_screen_state",
                "interrupt",
                "list_sessions",
                "read_output",
                "request_secret_input",
                "resize",
                "send_input",
                "start_session",
                "status",
                "terminate",
                "wait_for_pattern",
            ],
            "the advertised tool set changed; update tests/schema.rs::TOOLS, \
             its annotation table, and scripts/mcp-smoke.sh (which only CI \
             runs) to match"
        );
    }

    /// §16.7's two halves have to be read off **one** clock, and
    /// `start_session` is where they were read off two.
    ///
    /// `Session::new` stamps `last_activity_ms` from
    /// `SessionConfig::clock`, and the reaper compares that stamp
    /// against `Clock::now_ms()`. But `start_session` built its config
    /// from `..SessionConfig::default()` and never set `clock`, and
    /// `HoldfastServer` had no clock to set it from — `Clock` had zero
    /// occurrences anywhere under `mcp/`. So a daemon built with
    /// `Daemon::with_clock(paths, Clock::manual(..))` advanced its own
    /// hand while every session it created was stamped from
    /// `SystemTime::now()`.
    ///
    /// **The hand is advanced before the session exists, which is the
    /// only way to see it.** `Clock::manual` anchors its epoch at
    /// construction, so a session created immediately after the server
    /// gets nearly the same number from either clock and the defect is
    /// invisible — which is exactly why it survived.
    ///
    /// The last two assertions are the point: an hour of hand against a
    /// 30-minute default idle timeout means the mixed-clock version does
    /// not merely mis-stamp, it **reaps a session one instruction after
    /// creating it**. The paired advance kills the opposite reading, a
    /// reaper that never reaps at all.
    #[tokio::test]
    async fn a_session_is_stamped_from_the_servers_clock_and_not_from_wall_time() {
        use crate::clock::Clock;
        use crate::session::Reaper;
        use std::time::Duration;

        let clock = Clock::manual(Instant::now());
        let server = HoldfastServer::with_audit_path_config_and_clock(
            None,
            &crate::config::Config::default(),
            clock.clone(),
        );
        clock.advance(Duration::from_secs(3600));

        server
            .start_session(Parameters(StartSessionArgs {
                // Reads its PTY and stays alive, so the session is live
                // when the reaper looks at it.
                command: Some("cat".into()),
                ..Default::default()
            }))
            .await
            .expect("start_session");

        let all = server.registry.all();
        assert_eq!(all.len(), 1, "the session was not created");
        let session = Arc::clone(&all[0]);

        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(
            session.last_activity_ms() > wall_ms + 3_000_000,
            "the session was stamped from wall time ({}) while the reaper \
             decides about it on the daemon's clock ({})",
            session.last_activity_ms(),
            clock.now_ms()
        );
        assert!(
            (session.last_activity_ms() - clock.now_ms()).abs() < 5_000,
            "the session is on neither clock: stamp {}, server clock {}",
            session.last_activity_ms(),
            clock.now_ms()
        );

        // And the consequence, which is the whole reason the seam
        // matters: `[limits] default_idle_timeout_secs` is 1800, so a
        // stamp an hour behind the reaper's `now` is already past its
        // deadline the instant the session is born.
        let reaper = Reaper::new(Arc::clone(&server.registry), clock.clone());
        assert_eq!(
            reaper.scan_once(),
            0,
            "the reaper killed a session created a moment ago"
        );
        assert!(session.is_alive());

        // The pairing: a reaper that reaps nothing at all satisfies the
        // row above perfectly.
        clock.advance(Duration::from_secs(1801));
        assert_eq!(reaper.scan_once(), 1);

        let _ = session.signal(crate::pty::Signal::Kill);
    }

    /// Start one session under `config` and return its `session_start`
    /// audit entry, read back off disk.
    ///
    /// The log goes to a temporary directory, never to the invoking
    /// user's `~/.holdfast/logs/audit.log`.
    async fn session_start_entry(config: &crate::config::Config) -> serde_json::Value {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("audit.log");
        let server = HoldfastServer::with_audit_path_and_config(Some(path.clone()), config);
        server
            .start_session(Parameters(StartSessionArgs {
                // Reads its PTY and stays alive, so nothing races the
                // log write with an exit.
                command: Some("cat".into()),
                ..Default::default()
            }))
            .await
            .expect("start_session");
        let text = std::fs::read_to_string(&path).expect("the audit log must exist");
        let entry = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("one JSON object a line"))
            .find(|e| e["kind"] == "session_start")
            .expect("§9.4 writes a `session_start` row");
        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
        entry
    }

    /// §9.4's `redaction_enabled` must report the **configured** posture.
    ///
    /// It was the literal `true`, with a comment promising to wire it
    /// later. `[security] redaction_enabled` is already a live,
    /// validated, operator-settable key, so an operator who set it
    /// `false` got an audit trail asserting the opposite on every
    /// session — the one field whose job is to make the redaction
    /// posture reconstructible, false by construction, with nothing in
    /// the tree failing.
    ///
    /// **Both rows, and they are not interchangeable.** The `false` row
    /// is the one the literal fails; the `true` row is what separates
    /// "reads the config" from a mutation that swapped one literal for
    /// the other. Neither alone is a test of this field.
    #[tokio::test]
    async fn session_start_records_the_configured_redaction_posture() {
        let mut off = crate::config::Config::default();
        off.security.redaction_enabled = false;
        assert_eq!(
            session_start_entry(&off).await["redaction_enabled"],
            serde_json::json!(false),
            "the operator turned redaction off and §9.4 recorded that it was on"
        );

        let mut on = crate::config::Config::default();
        on.security.redaction_enabled = true;
        assert_eq!(
            session_start_entry(&on).await["redaction_enabled"],
            serde_json::json!(true),
            "a row hardcoded to `false` satisfies the assertion above perfectly"
        );
    }

    // ============================== §9.6's session profiles (GH #46)
    //
    // **The adversarial pairing is the first two rows**, deliberately: a
    // positive that fails at the top if the wiring resolves nothing, and
    // then the negatives.
    //
    // The rows that would *render successfully* drive `echo-host`, whose
    // `program` is `echo`. The ones whose subject is GH #45 drive
    // `prod-ssh`, whose `program` is `ssh` — through [`resolve_launch`]
    // rather than through the tool, because the whole point of those rows
    // is the argv, and running them through `start_session` would mean
    // actually executing `ssh` at a `ProxyCommand` an agent chose. The
    // link between the two — that `start_session`'s session carries
    // exactly what `resolve_launch` returned — is itself an assertion, in
    // `a_profile_started_session_carries_the_operators_own_argv`.

    fn profile(name: &str, program: &str, args: &[&str], vars: &[(&str, &str)]) -> SessionProfile {
        SessionProfile {
            name: name.to_string(),
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            vars: vars
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            env: BTreeMap::new(),
            cwd: None,
        }
    }

    /// The three profiles these rows use — **validated through the real
    /// loader**, so none of them is a profile no operator could write.
    ///
    /// `wide` is deliberately as sloppy as a profile gets: `host` admits
    /// literally anything. It loads, which is §9.6's stated asymmetry —
    /// a slot is bounded, so a wide slot pattern is bounded damage, where
    /// `match_command = ".*"` was a load error because it was not.
    fn profiles_config() -> crate::config::Config {
        let mut cfg =
            crate::config::parse_str("").expect("the empty document is the shipped default");
        cfg.security.profiles = vec![
            profile(
                "prod-ssh",
                "ssh",
                &["{user}@{host}"],
                &[
                    ("user", "^[a-z][a-z0-9_-]{0,30}$"),
                    ("host", "^prod-0[12]$"),
                ],
            ),
            profile("wide", "ssh", &["{host}"], &[("host", "(?s).*")]),
            profile(
                "echo-host",
                "echo",
                &["--", "{host}"],
                &[("host", "^prod-0[12]$")],
            ),
        ];
        cfg.validate()
            .expect("these fixtures must be profiles an operator could actually load");
        cfg
    }

    fn server_with_profiles() -> HoldfastServer {
        HoldfastServer::with_audit_path_and_config(None, &profiles_config())
    }

    fn vars(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }

    fn refusal(server: &HoldfastServer, args: StartSessionArgs) -> String {
        server
            .resolve_launch(&args)
            .map(|l| format!("{} {:?}", l.command, l.args))
            .expect_err("this call shape must not resolve to an argv")
            .to_string()
    }

    /// **The positive, first.** A profile-started session runs the
    /// operator's program with the operator's argument template, carries
    /// the operator's profile name, and — the link every row below leans
    /// on — carries exactly what [`resolve_launch`] resolved.
    #[tokio::test]
    async fn a_profile_started_session_carries_the_operators_own_argv() {
        let server = server_with_profiles();
        let args = StartSessionArgs {
            profile: Some("echo-host".into()),
            vars: vars(&[("host", "prod-02")]),
            ..Default::default()
        };
        let resolved = server
            .resolve_launch(&args)
            .expect("the operator's own profile must resolve");
        server
            .start_session(Parameters(args))
            .await
            .expect("start_session");

        let all = server.registry.all();
        assert_eq!(all.len(), 1, "no session was created");
        let s = &all[0];
        assert_eq!(s.command, "echo");
        assert_eq!(s.args, vec!["--".to_string(), "prod-02".to_string()]);
        assert_eq!(
            s.profile.as_deref(),
            Some("echo-host"),
            "the session must carry the profile a binding selects on"
        );
        // The wiring, pinned: the session is what `resolve_launch` said,
        // so every row below that drives `resolve_launch` is a row about
        // the session `start_session` would have created.
        assert_eq!(s.command, resolved.command);
        assert_eq!(s.args, resolved.args);
        assert_eq!(s.profile, resolved.profile);

        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
    }

    /// The negative that separates the row above from a `start_session`
    /// that stamps a profile on everything: an ordinary `command` session
    /// carries **no** profile, which is the whole of *"a session started
    /// with `command`/`args` can never receive a keychain credential"*.
    #[tokio::test]
    async fn a_command_started_session_carries_no_profile() {
        let server = server_with_profiles();
        server
            .start_session(Parameters(StartSessionArgs {
                command: Some("cat".into()),
                args: vec!["-".into()],
                ..Default::default()
            }))
            .await
            .expect("start_session");
        let all = server.registry.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].command, "cat");
        assert_eq!(all[0].args, vec!["-".to_string()]);
        assert_eq!(all[0].profile, None);
        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
    }

    /// **GH #45's reproduction is not expressible through a profile**, and
    /// this row asserts that the attack cannot be *stated* rather than
    /// that it is caught.
    ///
    /// The reproduction is `start_session("ssh", ["prod-01", "-o",
    /// "ProxyCommand=nc 127.0.0.1 2222"])` — a **four-element** argv whose
    /// third and fourth elements are the agent's, resolving an operator's
    /// binding. Every call shape that could aim at it is enumerated below,
    /// and each one lands in exactly one of two places: an argument error,
    /// or an argv the operator's template shaped. Neither produces the
    /// line, and the last case is the interesting one — even with a slot
    /// pattern that admits the whole payload, the payload arrives as **one
    /// argument**, which `ssh` reads as a hostname.
    ///
    /// The `command`/`args` shape produces the four-element argv, because
    /// of course it does — that is an agent running `ssh` and it always
    /// could. What it cannot do is carry a profile, so no binding selects
    /// it and no credential is typed into it; that half is asserted here
    /// as `profile: None` and driven end to end in `secret::binding`.
    #[test]
    fn gh_45s_reproduction_is_not_expressible_through_a_profile() {
        let server = server_with_profiles();
        const PAYLOAD: &str = "-o ProxyCommand=nc 127.0.0.1 2222";
        let reproduction = vec![
            "prod-01".to_string(),
            "-o".to_string(),
            "ProxyCommand=nc 127.0.0.1 2222".to_string(),
        ];

        // 1. The agent tries to append its own arguments to the profile.
        assert!(refusal(
            &server,
            StartSessionArgs {
                profile: Some("prod-ssh".into()),
                args: vec!["-o".into(), "ProxyCommand=nc 127.0.0.1 2222".into()],
                vars: vars(&[("user", "ada"), ("host", "prod-01")]),
                ..Default::default()
            }
        )
        .contains("`args` is only meaningful with `command`"));

        // 2. The agent smuggles the payload into a slot the operator
        //    bounded. Refused by the pattern, naming the var.
        let msg = refusal(
            &server,
            StartSessionArgs {
                profile: Some("prod-ssh".into()),
                vars: vars(&[("user", "ada"), ("host", &format!("prod-01 {PAYLOAD}"))]),
                ..Default::default()
            },
        );
        assert!(msg.contains("host"), "{msg}");

        // 3. The agent invents a slot to carry it.
        assert!(refusal(
            &server,
            StartSessionArgs {
                profile: Some("prod-ssh".into()),
                vars: vars(&[("user", "ada"), ("host", "prod-01"), ("opts", PAYLOAD)]),
                ..Default::default()
            }
        )
        .contains("opts"));

        // 4. The agent supplies both halves and hopes one wins.
        assert!(refusal(
            &server,
            StartSessionArgs {
                command: Some("ssh".into()),
                args: reproduction.clone(),
                profile: Some("prod-ssh".into()),
                ..Default::default()
            }
        )
        .contains("mutually exclusive"));

        // 5. **The one that actually renders**, and the row's real
        //    subject. `wide`'s `host` admits the entire payload, so the
        //    operator has given the agent everything a pattern can give.
        //    The argv is still `["ssh", "<one argument>"]` — two elements,
        //    where the reproduction is four — because substitution happens
        //    inside one element and `args` is a `Vec<String>`.
        let wide = server
            .resolve_launch(&StartSessionArgs {
                profile: Some("wide".into()),
                vars: vars(&[("host", &format!("prod-01 {PAYLOAD}"))]),
                ..Default::default()
            })
            .expect("`.*` admits it — that is the operator's choice to make");
        assert_eq!(wide.command, "ssh");
        assert_eq!(wide.args.len(), 1, "{:?}", wide.args);
        assert_ne!(wide.args, reproduction);
        assert_eq!(wide.profile.as_deref(), Some("wide"));

        // 6. And the shape that *does* produce the line produces it
        //    without a profile, so nothing selects a binding for it.
        let plain = server
            .resolve_launch(&StartSessionArgs {
                command: Some("ssh".into()),
                args: reproduction.clone(),
                ..Default::default()
            })
            .expect("an agent running `ssh` itself is not what profiles refuse");
        assert_eq!(plain.args, reproduction);
        assert_eq!(
            plain.profile, None,
            "a `command` session that carried a profile would hand the whole feature back"
        );
    }

    /// The structural guarantee, driven through the surface the agent
    /// actually calls: no `vars` value can introduce a second argv
    /// element.
    ///
    /// `secret::profile`'s own row asserts this of `render`; this one
    /// asserts it of the argv `start_session` resolves, so a future
    /// `start_session` that split, joined or shell-quoted on the way past
    /// reddens here rather than in a module nobody changed.
    #[test]
    fn no_vars_value_can_introduce_a_second_argv_element() {
        let server = server_with_profiles();
        let template_len = 1; // `wide` is `args = ["{host}"]`.
        for value in [
            "prod-01 -o ProxyCommand=nc 127.0.0.1 2222",
            "prod-01; evil",
            "prod-01 && evil",
            "prod-01 | evil",
            "-oProxyCommand=/tmp/x",
            "--",
            "'quoted' \"twice\"",
            "a\tb",
            "a\nb",
            "$(evil) `evil`",
            "",
        ] {
            let launch = server
                .resolve_launch(&StartSessionArgs {
                    profile: Some("wide".into()),
                    vars: vars(&[("host", value)]),
                    ..Default::default()
                })
                .unwrap_or_else(|e| panic!("{value:?} should resolve: {e}"));
            assert_eq!(
                launch.args.len(),
                template_len,
                "{value:?} produced {:?}, which is not the shape `args = [\"{{host}}\"]` \
                 declares; a value may never add an argument",
                launch.args
            );
            assert_eq!(launch.args[0], value);
            assert_eq!(
                launch.command, "ssh",
                "the program is the operator's literal"
            );
        }
    }

    #[test]
    fn neither_command_nor_profile_is_an_argument_error() {
        let server = server_with_profiles();
        assert!(
            refusal(&server, StartSessionArgs::default()).contains("either `command` or `profile`")
        );
    }

    #[test]
    fn vars_alongside_a_command_is_an_argument_error() {
        let server = server_with_profiles();
        assert!(refusal(
            &server,
            StartSessionArgs {
                command: Some("cat".into()),
                vars: vars(&[("host", "prod-01")]),
                ..Default::default()
            }
        )
        .contains("`vars` is only meaningful with `profile`"));
    }

    /// The name the agent supplied, and **not** a list of the ones that
    /// exist: an operator's profile names are their configuration.
    #[test]
    fn an_unknown_profile_name_is_an_argument_error_that_enumerates_nothing() {
        let server = server_with_profiles();
        let msg = refusal(
            &server,
            StartSessionArgs {
                profile: Some("prod-sshh".into()),
                ..Default::default()
            },
        );
        assert!(msg.contains("prod-sshh"), "{msg}");
        assert!(
            !msg.contains("echo-host") && !msg.contains("wide"),
            "the refusal enumerated the operator's other profiles: {msg}"
        );
    }

    #[test]
    fn a_slot_with_no_value_is_an_argument_error_naming_the_key() {
        let server = server_with_profiles();
        let msg = refusal(
            &server,
            StartSessionArgs {
                profile: Some("prod-ssh".into()),
                vars: vars(&[("host", "prod-01")]),
                ..Default::default()
            },
        );
        assert!(msg.contains("user"), "{msg}");
    }

    /// §9.2's habit: name the field, never the content. A var value may be
    /// a hostname the operator considers sensitive, and a refusal that
    /// quoted it would put it in the agent's transcript — which is the one
    /// place §9.6 is trying to keep operator configuration out of.
    #[test]
    fn a_value_failing_its_pattern_is_refused_without_being_echoed() {
        let server = server_with_profiles();
        let sensitive = "bastion.internal.example.invalid";
        let msg = refusal(
            &server,
            StartSessionArgs {
                profile: Some("prod-ssh".into()),
                vars: vars(&[("user", "ada"), ("host", sensitive)]),
                ..Default::default()
            },
        );
        assert!(msg.contains("host"), "the refusal must name the var: {msg}");
        assert!(
            !msg.contains(sensitive),
            "the refusal echoed the value back to the agent: {msg}"
        );
        // The pairing: the same call with a value the operator admits
        // resolves, so the row above is about the pattern rather than
        // about `host` never working.
        server
            .resolve_launch(&StartSessionArgs {
                profile: Some("prod-ssh".into()),
                vars: vars(&[("user", "ada"), ("host", "prod-01")]),
                ..Default::default()
            })
            .expect("the operator's own value must resolve");
    }

    /// Start one session under `args` and hand back its `session_start`
    /// audit entry and its `status` record.
    ///
    /// The log goes to a temporary directory, never to the invoking user's
    /// `~/.holdfast/logs/audit.log`.
    async fn start_and_record(
        config: &crate::config::Config,
        args: StartSessionArgs,
    ) -> (serde_json::Value, serde_json::Value) {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("audit.log");
        let server = HoldfastServer::with_audit_path_and_config(Some(path.clone()), config);
        // **The control that makes every assertion below mean something.**
        // A server whose audit log did not open writes no rows at all, and
        // "the two rows differ" is then a statement about two absences.
        assert!(
            server.processor.audit.path().is_some(),
            "the audit trail is disabled, so comparing rows proves nothing"
        );
        server
            .start_session(Parameters(args))
            .await
            .expect("start_session");
        let id = server.registry.all()[0].id.clone();
        let record = server
            .status(Parameters(StatusArgs {
                session: id.clone(),
            }))
            .await
            .expect("status")
            .structured_content
            .clone()
            .expect("every tool returns a structured envelope")["data"]
            .clone();
        let text = std::fs::read_to_string(&path).expect("the audit log must exist");
        let entry = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("one JSON object a line"))
            .find(|e| e["kind"] == "session_start")
            .expect("§9.4 writes a `session_start` row");
        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
        (entry, record)
    }

    /// **§9.4's `profile`, and the case that motivated it.**
    ///
    /// Two sessions with the **same argv**, one started from an operator's
    /// profile and one written by the agent. Only the first can ever
    /// receive a keychain credential (`secret::binding::matches` selects
    /// on `Session.profile`), so an operator reading the trail has to be
    /// able to tell them apart — and without this field they could not,
    /// because every other value on the row is identical by construction.
    ///
    /// The row asserts that in the strong form: strip `profile` and the
    /// two `session_start` entries are **equal** once the three
    /// per-session values are removed. That is the finding, driven, rather
    /// than a `assert_ne!` that a single unrelated difference would
    /// satisfy.
    #[tokio::test]
    async fn the_trail_tells_a_profile_started_session_from_an_agent_authored_one() {
        let cfg = profiles_config();
        let (from_profile, profile_record) = start_and_record(
            &cfg,
            StartSessionArgs {
                profile: Some("echo-host".into()),
                vars: vars(&[("host", "prod-01")]),
                ..Default::default()
            },
        )
        .await;
        let (from_command, command_record) = start_and_record(
            &cfg,
            StartSessionArgs {
                // Byte for byte what `echo-host` renders.
                command: Some("echo".into()),
                args: vec!["--".into(), "prod-01".into()],
                ..Default::default()
            },
        )
        .await;

        // The premise: the argv really is the same on both rows, so the
        // field below is the only thing that can separate them.
        assert_eq!(from_profile["command"], from_command["command"]);
        assert_eq!(from_profile["args"], from_command["args"]);
        assert_eq!(from_profile["args"], serde_json::json!(["--", "prod-01"]));

        assert_eq!(from_profile["profile"], serde_json::json!("echo-host"));
        assert_eq!(
            from_command["profile"],
            serde_json::Value::Null,
            "a `command`/`args` session must say so affirmatively; an absent key cannot \
             be told from one a writer forgot"
        );
        assert!(
            from_command.get("profile").is_some(),
            "`profile` is null on this row, not missing from it"
        );

        // **The finding itself.** Remove `profile` and the two rows are
        // the same row.
        let strip = |mut e: serde_json::Value| {
            let o = e.as_object_mut().expect("an object");
            for volatile in ["ts", "session_id", "pid", "profile"] {
                o.remove(volatile);
            }
            e
        };
        assert_eq!(
            strip(from_profile.clone()),
            strip(from_command.clone()),
            "the two rows differ somewhere other than `profile`, so this row is no \
             longer about the field it names"
        );

        // And the same distinction on §5.2's record, which `status` and
        // `list_sessions` share.
        assert_eq!(profile_record["command"], command_record["command"]);
        assert_eq!(profile_record["args"], command_record["args"]);
        assert_eq!(profile_record["profile"], serde_json::json!("echo-host"));
        assert_eq!(command_record["profile"], serde_json::Value::Null);
    }

    /// Mutual exclusion through the **real tool**, so the pair is refused
    /// where an agent meets it and not only in a private helper — and with
    /// no session left behind, because the refusal precedes the spawn.
    #[tokio::test]
    async fn profile_and_command_are_mutually_exclusive_at_the_tool() {
        let server = server_with_profiles();
        let e = server
            .start_session(Parameters(StartSessionArgs {
                command: Some("cat".into()),
                profile: Some("echo-host".into()),
                vars: vars(&[("host", "prod-01")]),
                ..Default::default()
            }))
            .await
            .expect_err("supplying both must be an argument error");
        assert!(e.message.contains("mutually exclusive"), "{e:?}");
        assert!(
            server.registry.all().is_empty(),
            "an argument error must not leave a child behind"
        );
    }

    /// The advertised description of one tool argument, as the agent
    /// receives it.
    fn arg_description(schema: &serde_json::Map<String, serde_json::Value>, field: &str) -> String {
        schema
            .get("properties")
            .and_then(|p| p.get(field))
            .and_then(|f| f.get("description"))
            .and_then(|d| d.as_str())
            .unwrap_or_else(|| panic!("{field} has no advertised description"))
            .to_string()
    }

    /// The three advertised byte caps, as literals, each cross-checked
    /// against the description the agent actually reads.
    ///
    /// Literals for the reason `SEQUENCE_MAX`'s is one: comparing a
    /// constant against its own definition is a tautology, and nothing
    /// else in the workspace observed these three numbers. Dropping
    /// `read_output`'s default from 32768 to 1024 left the whole suite
    /// green while the schema went on promising 32768 — a silently short
    /// read, which is indistinguishable from a child that stopped talking
    /// for any agent sizing its reads against the documented default.
    /// `MAX_SEND_INPUT_BYTES` is bounded from above by
    /// `send_input_rejects_an_oversized_payload` and from below, as it
    /// happens, by the exactly-64-KiB payload in the wedged-write test —
    /// but that payload's size is incidental to what that test is about,
    /// so the coupling is stated here rather than left to it.
    ///
    /// The second clause of each row is what keeps this from being a
    /// second place to write the same number down. The description is
    /// what the agent sizes its requests against, so the constant and the
    /// text have to move together or one of them is a lie.
    #[test]
    fn the_advertised_byte_caps_are_the_ones_the_code_applies() {
        assert_eq!(DEFAULT_READ_MAX_BYTES, 32768, "read_output's default cap");
        assert_eq!(MAX_READ_MAX_BYTES, 262144, "read_output's hard limit");
        assert_eq!(MAX_SEND_INPUT_BYTES, 65536, "send_input's payload cap");

        let read_output = HoldfastServer::read_output_tool_attr();
        let max_bytes = arg_description(&read_output.input_schema, "max_bytes");
        for needle in ["32768", "262144"] {
            assert!(
                max_bytes.contains(needle),
                "read_output's advertised `max_bytes` no longer names \
                 {needle}:\n{max_bytes}"
            );
        }

        let send_input = HoldfastServer::send_input_tool_attr();
        let data = arg_description(&send_input.input_schema, "data");
        assert!(
            data.contains("65536"),
            "send_input's advertised `data` no longer names the cap it \
             rejects on:\n{data}"
        );
    }

    /// `get_command_history`'s caveats are part of the tool contract, not
    /// commentary: a truncated `command` looks exactly like a complete
    /// shorter one, and a nested shell's exit code looks exactly like the
    /// launching command's. Both are silent plausible wrongness, and the
    /// only place the misled consumer can read the warning is the
    /// description the router advertises.
    #[test]
    fn get_command_history_description_carries_its_caveats() {
        let tool = HoldfastServer::get_command_history_tool_attr();
        let description = tool.description.as_deref().unwrap_or("");
        // `80 columns` and `Latin-1` are here because the needle set was
        // narrower than the caveat it guards: deleting the quantification
        // ("125 characters at 80 columns yields 47") *and* the Latin-1
        // clause while keeping the phrase `truncated to its tail` survived
        // the whole suite. Those two are what tell the agent *how* wrong
        // `command` gets and on which inputs, and they are the first
        // casualties of a reword — the bare phrase would still be there.
        for needle in [
            "nested integrated shell",
            "truncated to its tail",
            "80 columns",
            "Latin-1",
        ] {
            assert!(
                description.contains(needle),
                "get_command_history's advertised description dropped \
                 {needle:?}:\n{description}"
            );
        }
    }

    /// `list_sessions` returns every entry in the registry, including
    /// exited ones — `SessionRegistry::all()` does no filtering. Its
    /// description said "live sessions", which is an agent-visible string
    /// describing something the code does not do: an agent told the list is
    /// live has no reason to look for a session it started and cannot find,
    /// and `state` is the field that actually answers the question.
    ///
    /// Pinned in both directions, because "mentions exited" alone would
    /// pass against a description that also still promised the list was
    /// live-only.
    #[test]
    fn list_sessions_description_does_not_promise_a_live_only_list() {
        let tool = HoldfastServer::list_sessions_tool_attr();
        let description = tool.description.as_deref().unwrap_or("");
        for needle in ["live or exited", "state"] {
            assert!(
                description.contains(needle),
                "list_sessions' advertised description dropped {needle:?}, \
                 which is what tells the agent the list is not live-only:\n{description}"
            );
        }
        assert!(
            !description.contains("live sessions"),
            "list_sessions' advertised description still promises a \
             live-only list, which `registry.all()` does not produce:\n{description}"
        );
    }

    /// REQ-T-008's four arms, on the pure function, in microseconds.
    ///
    /// **Nothing observed the returned `Duration` before this.** The only
    /// test named for the timeout —
    /// `a_zero_timeout_is_clamped_to_the_hour_cap_and_says_so` — asserts
    /// the *reported* `clamped_timeout_secs` field, and its fixture
    /// matches in the historical phase, so the deadline it was handed is
    /// never reached. Two mutations survive that arrangement:
    /// `Some(0) => (Duration::from_secs(0), Some(cap))`, which turns
    /// §5.2's "no caller deadline" into a call that returns immediately,
    /// and `DEFAULT_WAIT_TIMEOUT_SECS: 30 → 3600`, which turns the
    /// default wait into an hour. Neither is observable by waiting — an
    /// hour-long default is precisely the thing a suite cannot afford to
    /// measure — and both are four assertions here.
    ///
    /// The cap boundary is included because `n > cap` and `n >= cap` are
    /// one character apart and differ only at exactly 3600, where the
    /// second reports a clamp that did not happen.
    #[test]
    fn resolve_wait_timeout_answers_every_arm_with_the_deadline_it_will_use() {
        assert_eq!(
            resolve_wait_timeout(None),
            (Duration::from_secs(30), None),
            "no argument is a 30-second deadline, unclamped"
        );
        assert_eq!(
            resolve_wait_timeout(Some(0)),
            (Duration::from_secs(3600), Some(3600)),
            "0 is `no caller deadline`, bounded at the cap — never an \
             immediate return"
        );
        assert_eq!(
            resolve_wait_timeout(Some(99_999)),
            (Duration::from_secs(3600), Some(3600))
        );
        assert_eq!(
            resolve_wait_timeout(Some(3600)),
            (Duration::from_secs(3600), None),
            "exactly the cap is not a clamp"
        );
        assert_eq!(
            resolve_wait_timeout(Some(45)),
            (Duration::from_secs(45), None)
        );

        // The same second clause the byte-cap test carries: these two
        // numbers are advertised to the agent, on both tools that take
        // the argument, and a constant that drifts from its description
        // is a deadline the agent cannot predict.
        for (tool, schema) in [
            (
                "wait_for_pattern",
                HoldfastServer::wait_for_pattern_tool_attr(),
            ),
            ("send_input", HoldfastServer::send_input_tool_attr()),
        ] {
            let described = arg_description(&schema.input_schema, "timeout_secs");
            for needle in ["30", "3600"] {
                assert!(
                    described.contains(needle),
                    "{tool}'s advertised `timeout_secs` no longer names \
                     {needle}:\n{described}"
                );
            }
        }
    }

    // ------------------------------------------------------- the leak table
    //
    // **One assertion, every tool, both arrangements**: no tool response
    // may contain the secret anywhere in it, checked over the whole
    // serialised `CallToolResult` rather than field by field.
    //
    // Field-by-field is how C1 shipped. `prompt_last_line_is_redacted_on_
    // every_prompt_bearing_tool` reads four `last_line` values and asserts
    // on those four strings; the field it never thought to name is the
    // field that leaked. The whole-object form cannot have that gap: a
    // field added to a response next milestone is inside it on the day it
    // is added, and so is a tool, because the covered set is compared
    // against `tool_router()` rather than against a list someone
    // remembered to extend.
    //
    // What it cannot cover, stated rather than implied:
    //
    //   * `read_output(tail_bytes|tail_lines)` **bypasses the holdback by
    //     design** (REQ-O-003, §4.1's documented residual risk), so a tail
    //     read of an in-flight secret returns it and must. The table
    //     drives cursor reads only.
    //   * `read_output(redact: false)` is the audited escape hatch (§4.1)
    //     and returns secrets on purpose; `read_outputs_redact_argument_
    //     is_honoured…` in `tests/integration.rs` is what pins *that*
    //     direction.
    //   * `start_session` echoes no session content at all — its `data`
    //     carries ids, pid, cwd and flags. The only caller string it
    //     returns is `command`, in `details`, which is the agent's own
    //     argument coming back. It is driven here for enumeration, and
    //     its row is honestly a weak one.
    //   * A *closed* `get_command_history` entry has no in-flight tail:
    //     the line was submitted, so nothing more is arriving and there is
    //     nothing to withhold. The in-flight arrangement is therefore
    //     vacuous for it, for `terminate` (which returns no content at
    //     all) and for `start_session`.

    /// Complete, and therefore redactable by rule.
    const GITHUB_TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    /// A **context**-rule value: the rule keys on the `DD_API_KEY=` label
    /// beside it, which lies outside any match a caller writes for the
    /// value itself. 8 of the 51 built-in rules are this shape.
    const DATADOG_KEY: &str = "0123456789abcdef0123456789abcdef";
    /// 39 characters — one short of the github rule's 40-character
    /// minimum, so no rule can match it and only §4.1's holdback protects
    /// it.
    const IN_FLIGHT: &str = "ghp_0123456789abcdefghijABCDEFGHIJ01234";
    /// The **second** command's secret, and a third rule so the two
    /// history entries are distinguishable from each other rather than
    /// only from the unredacted form. See `every_tool`'s history row.
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    struct Row {
        tool: &'static str,
        /// The serialised `CallToolResult`: `content[0]` mirrors the
        /// structured body and `details` is free text, so a needle hiding
        /// in either is inside this.
        whole: Value,
        /// `structuredContent.data`, for the companion assertions.
        data: Value,
    }

    fn row(tool: &'static str, r: &CallToolResult) -> Row {
        Row {
            tool,
            whole: serde_json::to_value(r).expect("a tool result serialises"),
            data: r
                .structured_content
                .clone()
                .expect("every tool returns a structured envelope")["data"]
                .clone(),
        }
    }

    fn mock_session(
        server: &HoldfastServer,
        name: &str,
        args: Vec<String>,
        bytes: &[u8],
    ) -> (String, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        pty.queue_output(bytes);
        let session = Session::new(
            new_session_id(),
            Some(name.to_string()),
            "bash".into(),
            args,
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(64 * 1024),
        );
        let id = session.id.clone();
        server.registry.insert(session).expect("registry insert");
        (id, pty)
    }

    /// Poll the *session* until `pred` holds, so the arrangement is really
    /// in place before any tool is called.
    async fn settle(session: &Session, what: &str, mut pred: impl FnMut(&Session) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !pred(session) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(pred(session), "timed out waiting for {what}");
    }

    /// Every advertised tool, once each, plus `send_input(wait_for=)`
    /// because that shape carries `match.text` and the plain write does
    /// not. `terminate` runs last for the obvious reason.
    async fn every_tool(
        server: &HoldfastServer,
        id: &str,
        start_args: StartSessionArgs,
        pattern: &str,
    ) -> Vec<Row> {
        let session = |s: &str| s.to_string();
        let mut rows = Vec::new();
        rows.push(row(
            "start_session",
            &server
                .start_session(Parameters(start_args))
                .await
                .expect("start_session"),
        ));
        rows.push(row(
            "read_output",
            &server
                .read_output(Parameters(ReadOutputArgs {
                    session: session(id),
                    since_cursor: Some(0),
                    ..Default::default()
                }))
                .await
                .expect("read_output"),
        ));
        rows.push(row(
            "send_input",
            &server
                .send_input(Parameters(SendInputArgs {
                    session: session(id),
                    data: String::new(),
                    append_newline: Some(false),
                    ..Default::default()
                }))
                .await
                .expect("send_input"),
        ));
        rows.push(row(
            "send_input",
            &server
                .send_input(Parameters(SendInputArgs {
                    session: session(id),
                    data: String::new(),
                    append_newline: Some(false),
                    wait_for: Some(pattern.to_string()),
                    timeout_secs: Some(1),
                }))
                .await
                .expect("send_input(wait_for)"),
        ));
        rows.push(row(
            "wait_for_pattern",
            &server
                .wait_for_pattern(Parameters(WaitForPatternArgs {
                    session: session(id),
                    pattern: Some(pattern.to_string()),
                    timeout_secs: Some(1),
                    since_cursor: Some(0),
                    max_bytes: None,
                }))
                .await
                .expect("wait_for_pattern"),
        ));
        rows.push(row(
            "status",
            &server
                .status(Parameters(StatusArgs {
                    session: session(id),
                }))
                .await
                .expect("status"),
        ));
        rows.push(row(
            "list_sessions",
            &server.list_sessions().await.expect("list_sessions"),
        ));
        rows.push(row(
            "get_command_history",
            &server
                .get_command_history(Parameters(GetCommandHistoryArgs {
                    session: session(id),
                    limit: None,
                    since_index: None,
                }))
                .await
                .expect("get_command_history"),
        ));
        // Before `resize`, so the grid is rendered at the geometry the
        // fixture's lines were written for rather than at a width this
        // table chose for an unrelated reason.
        rows.push(row(
            "get_screen_state",
            &server
                .get_screen_state(Parameters(GetScreenStateArgs {
                    session: session(id),
                    ..Default::default()
                }))
                .await
                .expect("get_screen_state"),
        ));
        rows.push(row(
            "resize",
            &server
                .resize(Parameters(ResizeArgs {
                    session: session(id),
                    cols: 100,
                    rows: 30,
                }))
                .await
                .expect("resize"),
        ));
        rows.push(row(
            "interrupt",
            &server
                .interrupt(Parameters(InterruptArgs {
                    session: session(id),
                }))
                .await
                .expect("interrupt"),
        ));
        // Nobody is attached, so this raises, waits out its (shortest
        // legal) window and answers `secret_cancelled`. That is the row
        // this table wants: the *cancelled* shape is the one carrying a
        // `request_id` and a `reason` next to a session whose buffer is
        // full of the fixture's credentials.
        rows.push(row(
            "request_secret_input",
            &server
                .request_secret_input(Parameters(RequestSecretInputArgs {
                    session: session(id),
                    prompt_text: "a prompt".to_string(),
                    timeout_secs: Some(1),
                    ..Default::default()
                }))
                .await
                .expect("request_secret_input"),
        ));
        rows.push(row(
            "terminate",
            &server
                .terminate(Parameters(TerminateArgs {
                    session: session(id),
                    force: Some(true),
                    timeout_secs: None,
                }))
                .await
                .expect("terminate"),
        ));
        rows
    }

    /// The enumeration link: a tool added to the router and not to the
    /// table above is an unchecked surface, and this is what says so.
    fn covers_every_advertised_tool(rows: &[Row]) {
        let mut covered: Vec<String> = rows.iter().map(|r| r.tool.to_string()).collect();
        covered.sort();
        covered.dedup();
        let mut advertised: Vec<String> = HoldfastServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        advertised.sort();
        assert_eq!(
            covered, advertised,
            "the leak table does not drive every advertised tool; a tool \
             outside it is a response nothing checks for secrets"
        );
    }

    fn no_row_contains(rows: &[Row], needles: &[(&str, &str)]) {
        for r in rows {
            let text = r.whole.to_string();
            for (what, needle) in needles {
                assert!(
                    !text.contains(needle),
                    "{} returned the {what}:\n{text}",
                    r.tool
                );
            }
        }
    }

    fn data_of<'a>(rows: &'a [Row], tool: &str) -> &'a Value {
        &rows
            .iter()
            .find(|r| r.tool == tool)
            .unwrap_or_else(|| panic!("{tool} is not in the table"))
            .data
    }

    async fn kill_everything(server: &HoldfastServer) {
        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Arrangement 1 of 2: the secrets have fully arrived, so every rule
    /// that can fire has fired and every surface must show a marker.
    ///
    /// **Two commands, not one, and the second one is the assertion rather
    /// than the behaviour.** The shipped code redacts every entry; a
    /// mutation that redacts only `entries[0]` survived the whole 479-test
    /// workspace and was caught by `scripts/mcp-smoke.sh` alone, because a
    /// fixture with exactly one command cannot tell a per-entry loop from
    /// a first-element special case. Any per-entry regression that spares
    /// the first element now reddens `cargo test`.
    #[tokio::test]
    async fn no_tool_returns_a_completed_secret_anywhere_in_its_response() {
        let server = HoldfastServer::new();
        let echoed = format!("export GH_TOKEN={GITHUB_TOKEN} DD_API_KEY={DATADOG_KEY}");
        // A different rule on the second command, so the two entries are
        // distinguishable from each other: an implementation that redacted
        // entry 0 and copied its text into every later entry passes a pair
        // of identical commands.
        let echoed2 = format!("aws configure set aws_access_key_id {AWS_KEY}");
        // **A window title, because the table could not see one.** Every
        // fixture here set OSC 133 markers and no OSC 0/2, so `title` was
        // `None` on every row and the whole-object check passed over a
        // field this builder emitted verbatim. Same species as the
        // one-command history fixture below: a whole-response assertion is
        // only as wide as the response the fixture provokes.
        let mut bytes = format!("\x1b]0;deploy {GITHUB_TOKEN}\x07").into_bytes();
        bytes.extend_from_slice(b"\x1b]133;A\x07$ ");
        bytes.extend_from_slice(format!("\x1b]133;B\x07{echoed}\r\n").as_bytes());
        bytes.extend_from_slice(b"\x1b]133;C\x07ok\r\n\x1b]133;D;0\x07");
        bytes.extend_from_slice(b"\x1b]133;A\x07$ ");
        bytes.extend_from_slice(format!("\x1b]133;B\x07{echoed2}\r\n").as_bytes());
        bytes.extend_from_slice(b"\x1b]133;C\x07ok\r\n\x1b]133;D;0\x07");
        bytes.extend_from_slice(
            format!("\x1b]133;A\x07LAST={GITHUB_TOKEN} DD_API_KEY={DATADOG_KEY}").as_bytes(),
        );
        let (id, _pty) = mock_session(
            &server,
            "leak-complete",
            vec!["--norc".into(), format!("--token={GITHUB_TOKEN}")],
            &bytes,
        );
        let session = server.registry.get(&id).expect("the session");
        settle(
            &session,
            "both commands to close and the last line to land",
            |s| s.command_count() == 2 && s.detection().last_line.starts_with("LAST="),
        )
        .await;

        let rows = every_tool(
            &server,
            &id,
            StartSessionArgs {
                command: Some("bash".into()),
                args: vec![
                    "--norc".into(),
                    "--noprofile".into(),
                    "-c".into(),
                    format!("sleep 30 # GH_TOKEN={GITHUB_TOKEN}"),
                ],
                shell_integration: Some(false),
                ..Default::default()
            },
            "[0-9a-f]{32}",
        )
        .await;

        covers_every_advertised_tool(&rows);
        no_row_contains(
            &rows,
            &[
                ("github token", GITHUB_TOKEN),
                ("datadog key", DATADOG_KEY),
                ("aws key", AWS_KEY),
            ],
        );

        // The companions. `!contains` passes against a redactor that
        // deletes everything, so each surface that carried a secret is
        // pinned to the exact text it must have kept.
        let read = data_of(&rows, "read_output");
        // The leading marker is the **title sequence**, and it is worth a
        // sentence rather than a fixture that avoids it. A secret inside an
        // OSC payload is found by `find_spans` over the raw bytes, and the
        // marker is emitted in place of that span rather than fed to the
        // stripper — so where a terminal renders nothing for
        // `\x1b]0;…\x07`, `read_output` renders `[REDACTED:github]`. That
        // is pre-existing, correct, and pinned here because this is the
        // first fixture in the suite to put a secret inside an escape
        // sequence at all.
        assert_eq!(
            read["output"],
            json!(format!(
                "[REDACTED:github]\
                 $ export GH_TOKEN=[REDACTED:github] DD_API_KEY=[REDACTED:datadog]\r\n\
                 ok\r\n\
                 $ aws configure set aws_access_key_id [REDACTED:aws]\r\n\
                 ok\r\nLAST=[REDACTED:github] DD_API_KEY=[REDACTED:datadog]"
            ))
        );
        assert_eq!(
            read["held_back"],
            json!(false),
            "nothing is in flight in this arrangement"
        );
        assert_eq!(
            data_of(&rows, "wait_for_pattern")["match"]["text"],
            json!("[REDACTED:datadog]"),
            "a match whose rule keys on a label outside it (C3)"
        );
        // **Both** entries, by index. `entries[0]` alone is the one-entry
        // blind spot this fixture's second command exists to close.
        let entries = data_of(&rows, "get_command_history")["entries"].clone();
        assert_eq!(
            entries.as_array().map(Vec::len),
            Some(2),
            "the arrangement must really carry two closed commands: {entries}"
        );
        assert_eq!(
            entries[0]["command"],
            json!("export GH_TOKEN=[REDACTED:github] DD_API_KEY=[REDACTED:datadog]"),
            "the command line is an output boundary (C2)"
        );
        assert_eq!(
            entries[1]["command"],
            json!("aws configure set aws_access_key_id [REDACTED:aws]"),
            "every entry, not the first one"
        );
        let status = data_of(&rows, "status");
        // The non-degenerate positive for the whole §9.2 `last_line` rule,
        // and it lives *here* rather than in arrangement 2 because this is
        // the arrangement where nothing is withheld. A `last_line` blanked
        // unconditionally — the shape of the two suppression cases below —
        // fails this line and only this line.
        assert_eq!(
            status["prompt"]["last_line"],
            json!("LAST=[REDACTED:github] DD_API_KEY=[REDACTED:datadog]")
        );
        assert_eq!(
            status["args"],
            json!(["--norc", "--token=[REDACTED:github]"])
        );
        // Paired with `an_ordinary_window_title_is_reported_byte_identical`
        // in `mcp::detection`, which keeps a dropped field from passing.
        assert_eq!(status["title"], json!("deploy [REDACTED:github]"));

        // **The grid, and which of its fields this fixture populates.**
        // `no_row_contains` covers exactly the fields the response
        // actually carries, so a `get_screen_state` row whose `lines` were
        // empty and whose `title` were null would pass it while saying
        // nothing about either — which is how `title` survived three
        // milestones under this very guard. Each field the tool renders
        // separately is therefore pinned to the text it must have kept.
        let screen = data_of(&rows, "get_screen_state");
        assert_eq!(
            screen["screen_tracking"],
            json!("on"),
            "the call must have enabled Tier B, or the grid below is a \
             one-shot rather than the tracked screen"
        );
        // Rendered by `ScreenTracker` from its own parser, not by
        // `with_detection` from the scanner — two copies of one field, and
        // this is the one 0.0.4 adds.
        assert_eq!(screen["title"], json!("deploy [REDACTED:github]"));
        let lines: Vec<String> = screen["lines"]
            .as_array()
            .expect("a full grid")
            .iter()
            .map(|l| l.as_str().unwrap_or_default().trim_end().to_string())
            .collect();
        assert_eq!(
            lines[0], "$ export GH_TOKEN=[REDACTED:github] DD_API_KEY=[REDACTED:datadog]",
            "the rendered row, redacted and otherwise intact: {lines:?}"
        );
        assert_eq!(
            lines[2], "$ aws configure set aws_access_key_id [REDACTED:aws]",
            "every row, not the first one: {lines:?}"
        );
        assert_eq!(
            lines[4], "LAST=[REDACTED:github] DD_API_KEY=[REDACTED:datadog]",
            "{lines:?}"
        );

        kill_everything(&server).await;
    }

    /// Arrangement 2 of 2: a token one character short of its rule's
    /// minimum, still arriving. No rule can match it, so **only the
    /// holdback stands between it and the agent** — and the holdback was
    /// wired to `read_output.output` alone.
    #[tokio::test]
    async fn no_tool_returns_an_in_flight_partial_secret_anywhere_in_its_response() {
        let server = HoldfastServer::new();
        let mut bytes = b"\x1b]133;A\x07$ \x1b]133;B\x07echo hi\r\n\x1b]133;C\x07".to_vec();
        bytes.extend_from_slice(b"building\r\n\x1b]133;D;0\x07");
        // The tail, and nothing after it: a partial with bytes behind it
        // is no longer in flight and is released by design (§4.1).
        bytes.extend_from_slice(format!("TOKEN={IN_FLIGHT}").as_bytes());
        let (id, _pty) = mock_session(
            &server,
            "leak-partial",
            // Benign: an argument is the caller's own string coming back,
            // and an unredactable partial there would fail this table for
            // a self-echo rather than for a disclosure.
            vec!["--norc".into()],
            &bytes,
        );
        let session = server.registry.get(&id).expect("the session");
        settle(&session, "the partial to reach the tail", |s| {
            s.command_count() == 1 && s.detection().last_line.starts_with("TOKEN=")
        })
        .await;
        assert!(
            session.holdback_boundary(&server.processor) < session.buffer_head(),
            "the arrangement must really be withholding something"
        );

        let rows = every_tool(
            &server,
            &id,
            StartSessionArgs {
                command: Some("bash".into()),
                args: vec!["--norc".into(), "--noprofile".into()],
                shell_integration: Some(false),
                ..Default::default()
            },
            r"ghp_\w+",
        )
        .await;

        covers_every_advertised_tool(&rows);
        no_row_contains(&rows, &[("in-flight token", IN_FLIGHT)]);
        // Four bytes of a token are not a secret, but they are the seam:
        // an implementation clipping one character too few leaks 38 of
        // the 39 and still passes the line above.
        no_row_contains(&rows, &[("start of the token", "ghp_")]);

        // The companions: withheld, not erased.
        let read = data_of(&rows, "read_output");
        assert_eq!(
            read["output"],
            json!("$ echo hi\r\nbuilding\r\nTOKEN="),
            "everything up to the boundary is still delivered"
        );
        assert_eq!(read["held_back"], json!(true));
        // §9.2's holdback case, and it reads as a loss until you put the
        // two lines beside each other: `read_output` is withholding from
        // `TOKEN=` onward on this very response, so the reconstruction of
        // the same region is not reportable either. It answered `"TOKEN="`
        // through 0.0.3 — a per-line clip, which is sound only when the
        // anchor licensing the holdback is *on* the line. `cat id_rsa`
        // proves it is not always: the `-----BEGIN` sits lines above and
        // the rendered last line is unrecognisable base64.
        //
        // What the agent loses here is four characters of label. What it
        // keeps is everything it acts on, asserted below so a change that
        // blanked the block wholesale cannot pass as this rule.
        let status = data_of(&rows, "status");
        assert_eq!(
            status["prompt"]["last_line"],
            json!(""),
            "an active holdback suppresses the line it is withholding"
        );
        assert!(
            status["prompt"]["reason"]
                .as_str()
                .is_some_and(|r| !r.is_empty()),
            "the rest of the block is untouched: {}",
            status["prompt"]
        );
        assert!(
            status["interaction_mode"]
                .as_str()
                .is_some_and(|m| !m.is_empty() && m != "Unknown"),
            "the session is still classified while its line is withheld: {status}"
        );
        let matched = data_of(&rows, "wait_for_pattern");
        assert_eq!(matched["matched"], json!(true));
        assert_eq!(matched["held_back"], json!(true));
        assert!(
            matched["match"].get("text").is_none(),
            "a withheld match reports its offset and no text: {}",
            matched["match"]
        );

        // **`get_screen_state`'s row is clean here for a reason that is
        // not the holdback, and recording that is the point of this
        // block.** The rendered row reads `TOKEN=ghp_<39>`, and the
        // *generic* rule — label plus a long enough value — matches it
        // whole, so the grid is redacted by REQ-O-011 rather than
        // protected by §4.1. Change the label and no rule fires; see
        // `the_screen_grid_does_not_apply_the_byte_stream_holdback`, which
        // pins that case rather than leaving it to be discovered under a
        // guard that looks like it covers it.
        let screen_lines: Vec<String> = data_of(&rows, "get_screen_state")["lines"]
            .as_array()
            .expect("a full grid")
            .iter()
            .map(|l| l.as_str().unwrap_or_default().trim_end().to_string())
            .collect();
        assert_eq!(
            screen_lines[2], "TOKEN=[REDACTED:generic]",
            "a complete rule matched the rendered row: {screen_lines:?}"
        );

        kill_everything(&server).await;
    }

    /// **The record of a decision that landed, kept as an assertion.**
    ///
    /// This test was written as the reverse of what it now asserts. §4.1's
    /// holdback withholds an in-flight secret prefix from
    /// `read_output(since_cursor:)`, and the rendered grid used to ignore
    /// it — handing back 39 characters of a 40-character PAT while the
    /// same session's cursor read withheld exactly those bytes. It was
    /// pinned that way deliberately, so that whoever decided the question
    /// would find an assertion rather than a silence.
    ///
    /// **Spec rev. 47 decided it, and the grid now masks.** §4.1's
    /// exemption narrows to `read_output`'s `tail_lines`/`tail_bytes`
    /// *arguments* — the licence is the per-call opt-in, not the tail
    /// *shape* — and `get_screen_state` is named a non-member beside
    /// `holdfast logs --tail` and the `observer` stream. Cells the holdback is
    /// withholding carry `[REDACTED:unresolved]`, and `held_back` says so
    /// on the response, the way `read_output` already did.
    ///
    /// `unresolved` is a **reserved pseudo-kind**: every other
    /// `[REDACTED:<kind>]` marker names a rule that *matched*, and this one
    /// means the opposite — bytes withheld because a partial is still open.
    ///
    /// **The second arrangement is the control**, and it is not optional. A
    /// masked row and a `held_back: true` are both satisfied by an
    /// implementation that masks unconditionally, so an otherwise identical
    /// session whose tail is *not* a secret prefix goes through the same
    /// call and must come back unmasked.
    #[tokio::test]
    async fn the_screen_grid_masks_what_the_byte_stream_holdback_withholds() {
        let server = HoldfastServer::new();
        // The same 39-character partial as arrangement 2, behind a label
        // **no rule keys on** — `TOKEN=` is matched by the generic rule
        // and would hide the behaviour under a redaction.
        let bytes = format!("$ cat note\r\nsee {IN_FLIGHT}");
        let (id, _pty) = mock_session(&server, "grid-holdback", vec![], bytes.as_bytes());
        let session = server.registry.get(&id).expect("the session");
        settle(&session, "the partial to reach the tail", |s| {
            s.detection().last_line.starts_with("see ")
        })
        .await;

        // The arrangement really is one the byte stream is withholding
        // from, and the redactor really cannot see it. Both are asserted,
        // because either one failing would make this test a statement
        // about something else.
        assert!(
            session.holdback_boundary(&server.processor) < session.buffer_head(),
            "nothing is being withheld, so there is no masking to describe"
        );
        let read = row(
            "read_output",
            &server
                .read_output(Parameters(ReadOutputArgs {
                    session: id.clone(),
                    since_cursor: Some(0),
                    ..Default::default()
                }))
                .await
                .expect("read_output"),
        )
        .data;
        assert_eq!(read["held_back"], json!(true));
        assert!(
            !read["output"].as_str().unwrap_or_default().contains("ghp_"),
            "the cursor read must be withholding it: {}",
            read["output"]
        );

        // **The third arm, and REQ-O-011a requires it in this same moment.**
        // Arms one and two together are also satisfied by an
        // implementation that withdrew the tail-read exemption
        // altogether. §4.1 narrows that exemption to `read_output`'s
        // `tail_lines`/`tail_bytes` *arguments* — the licence is the
        // per-call opt-in, not the tail *shape* — so the same session,
        // asked the exempt way, must still hand the partial over.
        // Covering this only by separate unit tests elsewhere is the
        // arrangement REQ-O-011a names as insufficient.
        let tail = row(
            "read_output",
            &server
                .read_output(Parameters(ReadOutputArgs {
                    session: id.clone(),
                    tail_bytes: Some(256),
                    ..Default::default()
                }))
                .await
                .expect("read_output"),
        )
        .data;
        assert!(
            tail["output"]
                .as_str()
                .unwrap_or_default()
                .contains(IN_FLIGHT),
            "the per-call tail opt-in is still exempt and must return the \
             partial whole (§4.1, REQ-O-003): {}",
            tail["output"]
        );
        assert_eq!(
            tail["held_back"],
            json!(false),
            "a read that bypasses the holdback is not withholding anything"
        );

        let screen = row(
            "get_screen_state",
            &server
                .get_screen_state(Parameters(GetScreenStateArgs {
                    session: id.clone(),
                    ..Default::default()
                }))
                .await
                .expect("get_screen_state"),
        )
        .data;
        let lines: Vec<String> = screen["lines"]
            .as_array()
            .expect("a full grid")
            .iter()
            .map(|l| l.as_str().unwrap_or_default().trim_end().to_string())
            .collect();
        assert_eq!(
            lines[1], "see [REDACTED:unresolved]",
            "the grid must mask what the same session's cursor read is \
             withholding (rev. 47: §4.1, §9.2, REQ-O-003): {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("ghp_")),
            "no row may carry the partial, not merely the row it landed on: {lines:?}"
        );
        assert_eq!(
            screen["held_back"],
            json!(true),
            "a masked grid must say so, or the marker reads as program output"
        );

        // **The control.** Same tool, same path, same shape of payload —
        // the only difference is that the tail is not a secret prefix, so
        // no partial is open and nothing may be masked.
        let (clean_id, _clean_pty) = mock_session(
            &server,
            "grid-no-holdback",
            vec![],
            b"$ cat note\r\nsee plain",
        );
        let clean = server.registry.get(&clean_id).expect("the session");
        settle(&clean, "the clean tail to arrive", |s| {
            s.detection().last_line.starts_with("see ")
        })
        .await;
        let clean_screen = row(
            "get_screen_state",
            &server
                .get_screen_state(Parameters(GetScreenStateArgs {
                    session: clean_id.clone(),
                    ..Default::default()
                }))
                .await
                .expect("get_screen_state"),
        )
        .data;
        let clean_lines: Vec<String> = clean_screen["lines"]
            .as_array()
            .expect("a full grid")
            .iter()
            .map(|l| l.as_str().unwrap_or_default().trim_end().to_string())
            .collect();
        assert_eq!(
            clean_lines[1], "see plain",
            "nothing is in flight, so nothing may be masked: {clean_lines:?}"
        );
        assert_eq!(
            clean_screen["held_back"],
            json!(false),
            "held_back must separate the two arrangements, not be a constant"
        );

        kill_everything(&server).await;
    }
}
