//! The MCP server: tool router, handler, and stdio entry point.

pub mod detection;
pub mod envelope;
pub mod schema;
pub mod tools;

use crate::audit::AuditLog;
use crate::output::rules::builtin_shared;
use crate::output::{OutputProcessor, ProcessingLimits};
use crate::session::SessionRegistry;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, ServerHandler, ServiceExt};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct ClaspServer {
    pub registry: Arc<SessionRegistry>,
    /// Redaction, ANSI stripping, holdback, encoding — shared by every
    /// read path so there is exactly one place secrets are removed.
    ///
    /// It owns the §9.4 trail as well (`processor.audit`): every string
    /// handed to that log is redacted before it is written, so no call
    /// site can leak a secret into it. The log lives *here*, on the one
    /// object every read already has to reach, rather than as a second
    /// field beside it — two handles to one log is two things that can
    /// be initialised differently.
    pub processor: Arc<OutputProcessor>,
}

impl ClaspServer {
    /// A server with the audit trail disabled. This is the constructor
    /// tests use: no test should write into the invoking user's home.
    pub fn new() -> Self {
        Self::with_audit_path(None)
    }

    /// A server whose audit trail is written to `path`, when given.
    ///
    /// A log that cannot be opened degrades to a disabled one with a
    /// message on stderr rather than refusing to start: a daemon that
    /// will not run because `~/.clasp/logs` is unwritable is a worse
    /// outcome than one that runs and says so. (`AuditLog::record`
    /// redacts either way, so the degraded mode cannot leak.)
    pub fn with_audit_path(path: Option<PathBuf>) -> Self {
        let rules = builtin_shared();
        let audit = match path {
            Some(p) => match AuditLog::to_path(&p, Arc::clone(&rules)) {
                Ok(log) => Arc::new(log),
                Err(e) => {
                    eprintln!("clasp: cannot open audit log {}: {e}", p.display());
                    Arc::new(AuditLog::disabled(Arc::clone(&rules)))
                }
            },
            None => Arc::new(AuditLog::disabled(Arc::clone(&rules))),
        };
        Self {
            registry: Arc::new(SessionRegistry::with_defaults()),
            processor: Arc::new(OutputProcessor::new(
                rules,
                audit,
                ProcessingLimits::default(),
            )),
        }
    }
}

impl Default for ClaspServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for ClaspServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo (= InitializeResult) and Implementation are
        // #[non_exhaustive]: build from Default, then assign.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new("clasp", env!("CARGO_PKG_VERSION"));
        // The first thing an agent reads about this server, and the one
        // piece of documentation that ships *inside* the protocol. It
        // described a four-tool surface for the whole of 0.0.2, so an
        // agent that trusted it never learned that `status`,
        // `list_sessions` or `get_command_history` existed.
        // `scripts/mcp-smoke.sh` asserts every tool name appears here.
        info.instructions = Some(
            "CLASP gives you PTY-backed shell sessions. start_session spawns a \
             shell or program; send_input types into it; read_output reads what \
             it printed using a cursor you carry between calls; terminate stops \
             it and its process group. status and list_sessions report what each \
             session is doing: interaction_mode is one of AtPrompt, Executing, \
             AwaitingSecret, Fullscreen, Exited, and detection_tier says whether \
             that was measured from OSC 133 shell integration (semantic), from a \
             terminal mode such as bracketed paste or termios ECHO \
             (terminal_mode), or guessed from output quiescence and prompt \
             patterns (heuristic). For bash, zsh and fish, CLASP injects OSC 133 \
             markers at start-up, and get_command_history then reports each \
             command's exit code and output span. Output is ANSI-stripped \
             and secret-redacted by default; secrets are replaced with \
             [REDACTED:<kind>] markers."
                .into(),
        );
        info
    }
}

/// Serve MCP over stdio until the client disconnects.
pub async fn serve_stdio() -> anyhow::Result<()> {
    // The audit path is resolved here rather than in `new()` so that only
    // the real server process ever writes to it.
    let server = ClaspServer::with_audit_path(crate::audit::default_path());
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
