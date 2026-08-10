//! The MCP server: tool router, handler, and stdio entry point.

pub mod envelope;
pub mod tools;

use crate::session::SessionRegistry;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, tool_router, ServerHandler, ServiceExt};
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

// Tool methods live in `tools.rs`; this attribute collects them.
#[tool_router]
impl ClaspServer {}

#[tool_handler]
impl ServerHandler for ClaspServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo (= InitializeResult) and Implementation are
        // #[non_exhaustive]: build from Default, then assign.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new("clasp", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(
            "CLASP gives you PTY-backed shell sessions. start_session spawns a \
             shell or program; send_input types into it; read_output reads what \
             it printed using a cursor you carry between calls; terminate stops \
             it. Output in this build is returned raw and unredacted."
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
