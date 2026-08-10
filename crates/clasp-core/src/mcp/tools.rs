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
        cfg.cwd = match &args.cwd {
            Some(cwd) => {
                if !std::path::Path::new(cwd).is_dir() {
                    return Err(ErrorData::invalid_params(
                        format!("cwd is not an existing directory: {cwd}"),
                        None,
                    ));
                }
                Some(cwd.clone())
            }
            None => std::env::current_dir()
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

        let session = match self.registry.get(&args.session) {
            Ok(s) => s,
            Err(e) => return envelope::from_error(&e),
        };

        let max_bytes = args.max_bytes.unwrap_or(32 * 1024).min(256 * 1024);
        // `truncated_for_size` means "this response was capped at
        // max_bytes" (§18.2). It is computed per branch rather than by
        // re-reading `head` afterwards: the reader thread can append
        // between the two calls, which would report a cap that never
        // happened.
        let (read, truncated_for_size) = if let Some(c) = args.since_cursor {
            let r = session.read_from(c, max_bytes);
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
            (r, requested > max_bytes)
        };

        // 0.0.1 returns raw bytes: no ANSI stripping, no redaction.
        // Both arrive in 0.0.3.
        let output = String::from_utf8_lossy(&read.bytes).to_string();
        let state = session.state();
        let more_forward = read.cursor < session.buffer_head();

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
    #[serde(default)]
    pub max_bytes: Option<usize>,
}
