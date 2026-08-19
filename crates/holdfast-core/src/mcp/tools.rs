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
use crate::output::redact::redact_str;
use crate::output::rules::RuleSet;
use crate::output::{ReadOptions, ReadRequest, ReadStart};
use crate::pty::{clamp_geometry, InProcessPty, PtyBackend, PtySpawnConfig};
use crate::screen::{ScreenCapture, ScreenConfig, ScreenTracking};
use crate::session::{new_session_id, wait, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
    /// Program to run, e.g. "bash".
    pub command: String,
    /// Arguments passed to the program.
    #[serde(default)]
    pub args: Vec<String>,
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
        let mut cfg = PtySpawnConfig::new(&args.command);
        cfg.args = args.args.clone();

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
        cfg.cwd = match &args.cwd {
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

        if let Some(env) = &args.env {
            cfg.env = env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>();
            cfg.env.sort();
        }

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
                detect_shell(&args.command, &args.args)
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
                    json!({ "command": args.command }),
                    format!("spawn failed: {}", envelope::brief(&e)),
                ));
            }
        };

        let session = Session::new(
            new_session_id(),
            args.name.clone(),
            args.command.clone(),
            args.args.clone(),
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
            format!("started `{}` as {}", args.command, session.id),
        ))
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
        let pattern = compile_pattern(&args.pattern)?;
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

        let (status, fields) = self
            .run_wait(
                &session,
                &pattern,
                args.since_cursor,
                max_bytes,
                timeout,
                clamped,
            )
            .await;
        let matched = fields
            .get("matched")
            .and_then(|m| m.as_bool())
            .unwrap_or(false);
        Ok(envelope::envelope(
            status,
            detection::with_detection(serde_json::Value::Object(fields), &session, &self.processor),
            if matched {
                "pattern matched".to_string()
            } else {
                format!("pattern did not match within {}s", timeout.as_secs())
            },
        ))
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
        Ok(envelope::envelope(
            status,
            detection::with_detection(serde_json::Value::Object(fields), &session, &self.processor),
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
}

impl HoldfastServer {
    /// Run one wait and render §5.2's eight shared fields.
    ///
    /// **`wait_for_pattern` and `send_input(wait_for=)` both come through
    /// here, and that is the requirement rather than tidiness**: §5.2 says
    /// the two share holdback semantics *verbatim*, and a second
    /// implementation is what makes "verbatim" drift.
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
    pub pattern: String,
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
    use crate::pty::MockPty;
    use crate::session::{new_session_id, Session, SessionConfig};
    use serde_json::Value;
    use std::time::Instant;

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
    fn the_router_advertises_exactly_the_0_0_4_tool_set() {
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
                command: "cat".into(),
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
                command: "cat".into(),
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
                    pattern: pattern.to_string(),
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
                command: "bash".into(),
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
                command: "bash".into(),
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
