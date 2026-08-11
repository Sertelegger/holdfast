//! The 0.0.1 tool set: start_session, read_output, send_input, terminate.

use super::envelope::{self, Status};
use super::ClaspServer;
use crate::pty::{InProcessPty, PtyBackend, PtySpawnConfig};
use crate::session::{new_session_id, registry::DEFAULT_BUFFER_BYTES, Session};
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

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
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
}

#[tool_router(vis = "pub(crate)")]
impl ClaspServer {
    /// Start a PTY-backed shell or program and return its session id.
    /// Runs in `cwd` if given, otherwise in the directory the CLASP
    /// server was started in.
    #[tool]
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
            DEFAULT_BUFFER_BYTES,
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
                "started_at_unix_secs": unix_secs(session.created_at),
            }),
            format!("started `{}` as {}", args.command, session.id),
        ))
    }

    /// Read output from a session. Supply exactly one of since_cursor,
    /// tail_lines, or tail_bytes.
    #[tool]
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

        let max_bytes = args.max_bytes.unwrap_or(32 * 1024).min(256 * 1024);
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
            format!("{} bytes", read.bytes.len()),
        ))
    }

    /// Send keystrokes to a session's stdin.
    #[tool]
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

        Ok(envelope::ok(
            json!({ "bytes_written": written }),
            format!("wrote {written} bytes"),
        ))
    }

    /// Terminate a session, killing its whole process group. Idempotent.
    #[tool]
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
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
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
