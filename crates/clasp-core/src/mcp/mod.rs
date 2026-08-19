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
    /// The time source every session this server creates is stamped
    /// from (§16.7, REQ-S-005).
    ///
    /// **This field is the seam between the reaper's two halves.**
    /// `SessionConfig::clock` and `Clock::now_ms` were both added so
    /// that `scan_once`'s comparison — `clock.now_ms()` against
    /// `Session::last_activity_ms` — stays inside one clock. But
    /// `start_session` built its `SessionConfig` from
    /// `..SessionConfig::default()` and never set `clock`, and
    /// `ClaspServer` had no clock to give it: `Clock` had **zero**
    /// occurrences anywhere under `mcp/`. So
    /// `Daemon::with_clock(paths, Clock::manual(..))` ran the reaper on
    /// the hand while every session created through the tool surface
    /// stamped its deadline from `SystemTime::now()`, and the two halves
    /// of one decision were read off two clocks.
    ///
    /// It appeared to work only because `Clock::manual` anchors its
    /// epoch at construction, so the numbers coincide while the daemon
    /// and the session are created within about a second of each other
    /// — which is the failure `now_ms()` exists to prevent, one layer
    /// up, and the seam 0.0.6's over-`attach.sock` test is promised.
    pub clock: crate::clock::Clock,
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
        Self::with_audit_path_config_and_clock(path, config, crate::clock::Clock::system())
    }

    /// The constructor the **daemon** uses, and the only one that can
    /// hand a session the daemon's own clock.
    ///
    /// Every other constructor is wall time, which is right for them:
    /// `serve_stdio` and every in-process test run on the system clock,
    /// and a `Clock::manual` that nothing advances would freeze their
    /// deadlines. The daemon is the one host that owns a clock, so it is
    /// the one host that has to pass it down — see
    /// [`ClaspServer::clock`].
    pub fn with_audit_path_config_and_clock(
        path: Option<PathBuf>,
        config: &crate::config::Config,
        clock: crate::clock::Clock,
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
            clock,
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

/// The `resources` capability §5.5 requires, **for the in-process
/// transport**. The daemon-backed one advertises less — see
/// [`shim_capabilities`].
///
/// `listChanged: true` because [`ClaspServer::on_initialized`] holds the
/// MCP peer and forwards every [`resource_list_changed`] pulse to it, so
/// `notifications/resources/list_changed` really is delivered when a
/// session is created or exits. `subscribe` is deliberately **absent**
/// rather than `false`: §5.5 writes `"subscribe": false`,
/// `ResourcesCapability` is `#[non_exhaustive]` so an explicit `false`
/// cannot be constructed from outside `rmcp`, and an omitted capability
/// and a `false` one mean the same thing to a client. v0.1.0 does not
/// implement subscriptions either way (§14.2).
///
/// [`resource_list_changed`]: ClaspServer::resource_list_changed
pub fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities::builder()
        .enable_tools()
        .enable_resources()
        .enable_resources_list_changed()
        .build()
}

/// The same capabilities **minus `resources.listChanged`**, for
/// `shim::ShimServer`.
///
/// **REQ-R-006 has no delivery path in hybrid mode, so the shim must not
/// claim one.** The forwarder that turns a pulse into an MCP
/// notification is [`ClaspServer::on_initialized`], and it is reachable
/// only from a `ClaspServer` that holds an MCP peer. In hybrid mode that
/// object lives inside the **daemon**, where there is no peer: the
/// reaper's `poll_resource_list_changed` and `start_session` both fire
/// the pulse into a broadcast channel with zero receivers, and §7.4.1
/// reserves the streaming frames without using them in v0.1.0, so there
/// is no server→client push on the control protocol by which the pulse
/// could cross. `ShimServer` implements no `on_initialized` and holds no
/// subscription.
///
/// So `listChanged: true` on this transport was a promise the build
/// cannot keep, on the transport that is the **default**. An agent that
/// believed it would hold a stale `resources/list` for the life of the
/// connection and never re-list, which is strictly worse than being told
/// to poll. Advertising nothing is honest; advertising and dropping is
/// not.
///
/// **This is a deferral, not a retraction.** Delivering it needs a
/// server→client frame on `control.sock` and a shim-side subscription
/// task, which is a protocol addition and belongs with the milestone
/// that adds the streaming frames §7.4.1 already reserves. The
/// capability comes back on this transport when the pulse can reach the
/// peer, and not before. Until then the honest surface is: an agent
/// re-lists when it wants a current answer.
///
/// It is a separate function rather than a flag on
/// [`server_capabilities`] so that the two transports' answers cannot be
/// changed together by accident — the whole point is that they differ.
pub fn shim_capabilities() -> ServerCapabilities {
    ServerCapabilities::builder()
        .enable_tools()
        .enable_resources()
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
