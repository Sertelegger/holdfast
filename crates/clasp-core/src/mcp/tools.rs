//! The 0.0.2 tool set: start_session, read_output, send_input, terminate,
//! status, list_sessions, get_command_history.

use super::envelope::{self, Status};
use super::{detection, schema, ClaspServer};
use crate::detect::{
    detect_shell, DetectionConfig, InteractionMode, PatternSet, PromptPattern,
    DEFAULT_SETTLE_THRESHOLD_MS,
};
use crate::pty::{InProcessPty, PtyBackend, PtySpawnConfig};
use crate::session::{new_session_id, Session, SessionConfig};
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
    /// Defaults to the directory the CLASP server itself was started in.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Extra environment variables for the spawned process. Do not pass
    /// secrets: these values cross the MCP boundary (spec §5.2).
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    /// Terminal width in columns. Defaults to 120.
    #[serde(default)]
    pub cols: Option<u16>,
    /// Terminal height in rows. Defaults to 40.
    #[serde(default)]
    pub rows: Option<u16>,
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
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PromptPatternArg {
    /// Rust regex matched against the session's last logical line.
    pub regex: String,
    /// Score in [0,1] contributed when the regex matches.
    pub score: f32,
}

#[tool_router(vis = "pub(crate)")]
impl ClaspServer {
    /// Start a PTY-backed shell or program and return its session id.
    /// Runs in `cwd` if given, otherwise in the directory the CLASP
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

        if let Err(e) = self.registry.insert(Arc::clone(&session)) {
            // Registry rejected it; don't leak the child.
            let _ = session.signal(crate::pty::Signal::Kill);
            return envelope::from_error(&e);
        }

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
    /// tail_lines, or tail_bytes.
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

        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        let max_bytes = args
            .max_bytes
            .unwrap_or(DEFAULT_READ_MAX_BYTES)
            .min(MAX_READ_MAX_BYTES);
        // `truncated_for_size` means "this response was capped at
        // max_bytes" (§18.2). Each branch computes the half of that
        // question only it can answer — whether `max_bytes` was the
        // *binding* constraint on this particular read — rather than
        // re-deriving it from `head` afterwards, which would report a cap
        // that never happened whenever the reader thread appended in
        // between.
        let is_cursor_read = args.since_cursor.is_some();
        let (read, size_capped) = if let Some(c) = args.since_cursor {
            let r = session.read_from(c, max_bytes);
            // Necessary but not sufficient on its own: a forward read
            // fills exactly `max_bytes` both when it left bytes behind and
            // when the buffer happened to hold exactly that many. The
            // "and something was actually left behind" half is
            // `more_forward`, applied below — it needs the post-read head.
            let capped = r.bytes.len() >= max_bytes;
            (r, capped)
        } else if let Some(n) = args.tail_lines {
            // max_bytes is a raw-byte cap on *every* selector
            // (REQ-T-006), not just the cursor path. A tail read is
            // clipped from the front, so the newest bytes survive and the
            // returned cursor still points just past them.
            let mut r = session.read_tail_lines(n);
            let capped = r.bytes.len() > max_bytes;
            if capped {
                let drop = r.bytes.len() - max_bytes;
                r.bytes.drain(..drop);
            }
            (r, capped)
        } else {
            let requested = args.tail_bytes.unwrap();
            let r = session.read_tail_bytes(requested.min(max_bytes));
            // Both clauses are needed. `requested > max_bytes` alone
            // reports a cap even when the buffer held less than max_bytes,
            // so nothing was dropped. `r.bytes.len() >= max_bytes` alone
            // reports a cap when the caller asked for exactly max_bytes
            // and got exactly that -- also no truncation. Only when
            // max_bytes was the *binding* constraint was anything lost.
            // (A tail read always ends at `head`, so unlike the cursor
            // branch there is never anything "further forward" to fetch;
            // the two clauses here are the whole test.)
            let capped = requested > max_bytes && r.bytes.len() >= max_bytes;
            (r, capped)
        };

        // 0.0.1 returns raw bytes: no ANSI stripping, no redaction.
        // Both arrive in 0.0.3.
        let output = String::from_utf8_lossy(&read.bytes).to_string();
        let state = session.state();
        let more_forward = read.cursor < session.buffer_head();
        // The cursor branch's missing clause. Without it, 86 buffered
        // bytes read with `max_bytes: 86` answer `bytes_returned: 86,
        // truncated_for_size: true, next_cursor: null` — claiming a cap
        // while simultaneously reporting nothing left to fetch. Reusing
        // `more_forward` keeps the flag and `next_cursor` derived from one
        // fact instead of two that can disagree.
        let truncated_for_size = size_capped && (!is_cursor_read || more_forward);

        Ok(envelope::ok(
            detection::with_detection(
                json!({
                "output": output,
                "cursor": read.cursor,
                "bytes_returned": read.bytes.len(),
                "truncated_at_tail": read.truncated_at_tail,
                "truncated_for_size": truncated_for_size,
                "next_cursor": if more_forward { Some(read.cursor) } else { None },
                "state": state.as_str(),
                "exit_code": session.exit_code(),
                }),
                &session,
            ),
            format!("{} bytes", read.bytes.len()),
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
        let write = tokio::task::spawn_blocking(move || writer_session.write_input(&payload));
        let written = match tokio::time::timeout(SEND_INPUT_TIMEOUT, write).await {
            Ok(Ok(Ok(n))) => n,
            // An earlier write is still parked on this session's writer
            // lock, so this one never even reached the fd.
            Ok(Ok(Err(crate::ClaspError::WriteTimeout))) => {
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
            // The blocking task panicked. That is a CLASP bug, not a
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
            // later write instead of queueing behind it. `clasp mcp` bounds
            // its runtime shutdown for the same reason.
            Err(_elapsed) => {
                return Ok(write_timed_out(
                    "the child did not accept the input within the write deadline; it may be \
                     in a mode where it is not reading its terminal",
                ));
            }
        };

        // REQ-SEC-011: the write still happens — the agent may know
        // something CLASP does not — but the event is made visible.
        let warning = awaiting.then_some("session_awaiting_secret");

        Ok(envelope::ok(
            detection::with_detection(
                json!({ "bytes_written": written, "warning": warning }),
                &session,
            ),
            format!("wrote {written} bytes"),
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
                json!({ "exit_code": session.exit_code(), "already_exited": true }),
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
            json!({ "exit_code": session.exit_code(), "already_exited": false }),
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
            detection::with_detection(session_record(&session), &session),
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
            .map(|s| detection::with_detection(session_record(s), s))
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
                    "command": e.command,
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

/// The fields `status` and `list_sessions` share. Both are prompt-bearing
/// responses (§5.4), so both pass the result through `with_detection`.
fn session_record(session: &Session) -> serde_json::Value {
    let state = session.state();
    json!({
        "id": session.id,
        "name": session.name,
        "command": session.command,
        "args": session.args,
        "state": state.as_str(),
        "pid": session.pid(),
        "exit_code": session.exit_code(),
        "shell_integration": session.shell_integration.map(|s| s.as_str()),
        "command_count": session.command_count(),
        "started_at_unix_secs": unix_secs(session.created_at),
        "last_activity_unix_ms": session.last_activity_ms(),
        "buffer": {
            "head": session.buffer_head(),
            "tail": session.buffer_tail(),
        },
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
    /// Cap on bytes returned. Defaults to 32768, hard limit 262144.
    /// Must be at least 1: a zero cap can never make forward progress.
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SendInputArgs {
    /// Session id or live session name.
    pub session: String,
    /// Text to write to the session's stdin. At most 65536 bytes.
    pub data: String,
    /// Append a newline. Defaults to true.
    #[serde(default)]
    pub append_newline: Option<bool>,
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
    fn the_router_advertises_exactly_the_0_0_2_tool_set() {
        let mut names: Vec<String> = ClaspServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "get_command_history",
                "list_sessions",
                "read_output",
                "send_input",
                "start_session",
                "status",
                "terminate",
            ],
            "the advertised tool set changed; update tests/schema.rs::TOOLS \
             and its annotation table to match"
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

        let read_output = ClaspServer::read_output_tool_attr();
        let max_bytes = arg_description(&read_output.input_schema, "max_bytes");
        for needle in ["32768", "262144"] {
            assert!(
                max_bytes.contains(needle),
                "read_output's advertised `max_bytes` no longer names \
                 {needle}:\n{max_bytes}"
            );
        }

        let send_input = ClaspServer::send_input_tool_attr();
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
        let tool = ClaspServer::get_command_history_tool_attr();
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
        let tool = ClaspServer::list_sessions_tool_attr();
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
}
