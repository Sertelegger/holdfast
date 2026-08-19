//! The MCP server: tool router, handler, and stdio entry point.

pub mod caller;
pub mod detection;
pub mod envelope;
pub mod passthrough;
pub mod resources;
pub mod schema;
pub mod shim;
pub mod tools;

use crate::audit::AuditLog;
use crate::output::rules::builtin_shared;
use crate::output::OutputProcessor;
use crate::session::SessionRegistry;
use rmcp::model::{
    Implementation, ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{tool_handler, ErrorData, RoleServer, ServerHandler, ServiceExt};
use std::path::PathBuf;
use std::sync::Arc;

/// What an agent is told about this server, on either transport.
///
/// Both `ClaspServer` (in-process) and `shim::ShimServer`
/// (daemon-backed) build their `instructions` from this. The shim
/// appends one sentence about where sessions live and changes nothing
/// else, so a milestone that revises what the agent is told — 0.0.3's
/// redaction sentence was the first — revises it once.
// The first thing an agent reads about this server, and the one
// piece of documentation that ships *inside* the protocol. It
// described a four-tool surface for the whole of 0.0.2, so an
// agent that trusted it never learned that `status`,
// `list_sessions` or `get_command_history` existed.
// `scripts/mcp-smoke.sh` asserts every tool name appears here.
pub const INSTRUCTIONS: &str = "CLASP gives you PTY-backed shell sessions. start_session spawns a \
     shell or program; send_input types into it; read_output reads what \
     it printed using a cursor you carry between calls; \
     wait_for_pattern blocks until a regex matches new output, which \
     is how you wait for a command to finish or for a prompt to \
     appear; interrupt sends Ctrl+C to the foreground process group, \
     which stops the running command without killing the shell, and \
     terminate stops the session and its whole process group. \
     get_screen_state returns the rendered terminal grid rather than \
     the byte stream, which is the right read for a full-screen \
     program; pass diff_from with the screen_revision from your \
     previous call to get only the changed regions. screen_tracking on \
     a session's responses says whether that emulation is already \
     running. resize changes the terminal's dimensions and raises \
     SIGWINCH in the child, so a TUI redraws at the new size. status and list_sessions report what each \
     session is doing: interaction_mode is one of AtPrompt, Executing, \
     AwaitingSecret, Fullscreen, Exited, and detection_tier says whether \
     that was measured from OSC 133 shell integration (semantic), from a \
     terminal mode such as bracketed paste or termios ECHO \
     (terminal_mode), or guessed from output quiescence and prompt \
     patterns (heuristic). For bash, zsh and fish, CLASP injects OSC 133 \
     markers at start-up, and get_command_history then reports each \
     command's exit code and output span. Output is ANSI-stripped \
     and secret-redacted by default; secrets are replaced with \
     [REDACTED:<kind>] markers.";

/// Buffered `list_changed` pulses before a slow subscriber starts
/// missing them. Small on purpose: the notification is idempotent — a
/// client that missed three re-lists once — so a deep queue would buy
/// nothing and hold memory.
const RESOURCE_EVENT_CAPACITY: usize = 16;

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
    /// The operator's `config.toml`, resolved and validated (§10.1).
    ///
    /// Held whole rather than exploded into the knobs 0.0.5 happens to
    /// read, because REQ-CFG-004's second clause makes the *unread*
    /// knobs part of the contract: a later milestone wires a value that
    /// is already parsed and validated instead of adding a field and a
    /// second place for the operator's file to be misread.
    pub config: Arc<crate::config::Config>,
    /// A pulse whenever the resource list changes (REQ-R-006).
    ///
    /// §5.5 declares `listChanged: true`, and the event is a *pulse*
    /// rather than a delta because `notifications/resources/list_changed`
    /// carries no payload: the client re-lists. Session **creation**
    /// fires it here, synchronously, from `start_session`; session
    /// **exit** is observed rather than announced, so the daemon's
    /// periodic tick fires it — which is the half §5.5 says needs the
    /// daemon, since in hybrid mode the shim holds no registry.
    pub resource_list_changed: tokio::sync::broadcast::Sender<()>,
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
        Self::with_audit_path_and_config(path, &crate::config::Config::default())
    }

    /// The constructor the daemon uses: the same audit-path handling,
    /// plus the §4.2 knobs the operator's `config.toml` set (REQ-CFG-004).
    ///
    /// Only the knobs whose consumers already take them as parameters
    /// are wired here — `max_concurrent_sessions` on the registry and the
    /// four [`ProcessingLimits`] fields on the processor. The rest are
    /// parsed, validated and reachable through [`ClaspServer::config`];
    /// see `config.rs` for which milestone owns each.
    pub fn with_audit_path_and_config(
        path: Option<PathBuf>,
        config: &crate::config::Config,
    ) -> Self {
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
            registry: Arc::new(SessionRegistry::new(config.limits.max_concurrent_sessions)),
            processor: Arc::new(OutputProcessor::new(
                rules,
                audit,
                config.processing_limits(),
            )),
            config: Arc::new(config.clone()),
            resource_list_changed: tokio::sync::broadcast::channel(RESOURCE_EVENT_CAPACITY).0,
        }
    }

    /// Announce that `resources/list` would now answer differently.
    ///
    /// Lossy by construction: a subscriber that falls behind receives a
    /// lag error rather than every pulse, which is correct for a
    /// "re-list" signal and wrong for anything carrying state. That is
    /// the reason this carries none.
    pub fn notify_resource_list_changed(&self) {
        let _ = self.resource_list_changed.send(());
    }

    /// The operator configuration this server was built with.
    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }
}

impl Default for ClaspServer {
    fn default() -> Self {
        Self::new()
    }
}

/// The `resources` capability §5.5 requires, for either transport.
///
/// `listChanged: true` because the daemon emits
/// `notifications/resources/list_changed` when a session is created or
/// exits. `subscribe` is deliberately **absent** rather than `false`:
/// §5.5 writes `"subscribe": false`, `ResourcesCapability` is
/// `#[non_exhaustive]` so an explicit `false` cannot be constructed from
/// outside `rmcp`, and an omitted capability and a `false` one mean the
/// same thing to a client. v0.1.0 does not implement subscriptions
/// either way (§14.2).
pub fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities::builder()
        .enable_tools()
        .enable_resources()
        .enable_resources_list_changed()
        .build()
}

#[tool_handler]
impl ServerHandler for ClaspServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo (= InitializeResult) and Implementation are
        // #[non_exhaustive]: build from Default, then assign.
        let mut info = ServerInfo::default();
        info.capabilities = server_capabilities();
        info.server_info = Implementation::new("clasp", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(INSTRUCTIONS.into());
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(
            resources::list_resources(&self.registry),
        ))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(
            resources::list_resource_templates(),
        ))
    }

    async fn on_initialized(&self, context: rmcp::service::NotificationContext<RoleServer>) {
        // The peer is only reachable from here, so this is where
        // REQ-R-006's delivery half is wired: a task that forwards every
        // pulse to the client until the connection goes away.
        let mut events = self.resource_list_changed.subscribe();
        let peer = context.peer.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(()) => {
                        if peer.notify_resource_list_changed().await.is_err() {
                            return;
                        }
                    }
                    // Lagged: the list changed more often than this
                    // client drained. Re-listing once covers all of it.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        if peer.notify_resource_list_changed().await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let result = resources::read_resource(
            &self.registry,
            &self.processor,
            &request.uri,
            self.config.limits.resource_read_max_bytes,
        )?;
        Ok(result.into())
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
