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
}
