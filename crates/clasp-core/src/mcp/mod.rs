//! The MCP server: tool router, handler, and stdio entry point.

pub mod detection;
pub mod envelope;
pub mod schema;
pub mod tools;

use crate::session::SessionRegistry;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, ServerHandler, ServiceExt};
use std::sync::Arc;

#[derive(Clone)]
pub struct ClaspServer {
    pub registry: Arc<SessionRegistry>,
}

impl ClaspServer {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(SessionRegistry::with_defaults()),
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
             command's exit code and output span. Output in this build is \
             returned raw and unredacted."
                .into(),
        );
        info
    }
}

/// Serve MCP over stdio until the client disconnects.
pub async fn serve_stdio() -> anyhow::Result<()> {
    let service = ClaspServer::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
