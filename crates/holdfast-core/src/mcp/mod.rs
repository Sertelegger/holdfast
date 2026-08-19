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
/// Both `HoldfastServer` (in-process) and `shim::ShimServer`
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
pub const INSTRUCTIONS: &str = "Holdfast gives you PTY-backed shell sessions. start_session spawns a \
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
     patterns (heuristic). For bash, zsh and fish, Holdfast injects OSC 133 \
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
pub struct HoldfastServer {
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
    /// `HoldfastServer` had no clock to give it: `Clock` had **zero**
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
    /// Why the §9.4 trail is off when a path for it *was* supplied.
    ///
    /// **The audit log used to fail open with nothing but a line on
    /// stderr.** A root-owned `audit.log` left by one `sudo holdfast`
    /// produced a server that ran normally and recorded
    /// nothing — every `session_start`, every `redaction_disabled`,
    /// gone, with the daemon reporting perfect health. The comparison
    /// that settles it is `server::run`, which already refuses to start
    /// on a bad *config* (REQ-CFG-003) because an operator must not
    /// believe a limit is in force when it is not. A knob that is
    /// silently not in force and a trail that is silently not being
    /// written are the same failure, and the trail was getting the
    /// weaker treatment.
    ///
    /// Recorded rather than acted on *here* because the right response
    /// depends on the host: `run_with_config` treats it as fatal, which
    /// is what the daemon — the default transport, and the one that
    /// serves every client on the box — must do. `None` when no path
    /// was supplied at all: a deliberately disabled trail is a choice,
    /// not a failure, and that is what every test takes.
    pub audit_open_error: Option<String>,
}

impl HoldfastServer {
    /// A server with the audit trail disabled. This is the constructor
    /// tests use: no test should write into the invoking user's home.
    pub fn new() -> Self {
        Self::with_audit_path(None)
    }

    /// A server whose audit trail is written to `path`, when given.
    ///
    /// A log that cannot be opened leaves the trail **disabled** and the
    /// reason in [`audit_open_error`](HoldfastServer::audit_open_error).
    /// Construction does not fail, so that a host with no way to report
    /// (a test, an in-process embedder) is not forced to unwrap; the
    /// host decides. `run_with_config` decides *fatal*, because a daemon
    /// serving every client on the box with no §9.4 trail and no
    /// indication is the outcome REQ-CFG-003 refuses for a config knob.
    ///
    /// The line on stderr stays, and is now the *diagnostic* rather than
    /// the whole response to the failure. It goes out through
    /// [`crate::diag!`]: the daemon builds its server here too, and the
    /// daemon's stderr is `daemon.log`.
    pub fn with_audit_path(path: Option<PathBuf>) -> Self {
        Self::with_audit_path_and_config(path, &crate::config::Config::default())
    }

    /// The constructor the daemon uses: the same audit-path handling,
    /// plus the §4.2 knobs the operator's `config.toml` set (REQ-CFG-004).
    ///
    /// Only the knobs whose consumers already take them as parameters
    /// are wired here — `max_concurrent_sessions` on the registry and the
    /// four [`ProcessingLimits`] fields on the processor. The rest are
    /// parsed, validated and reachable through [`HoldfastServer::config`];
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
    /// [`HoldfastServer::clock`].
    pub fn with_audit_path_config_and_clock(
        path: Option<PathBuf>,
        config: &crate::config::Config,
        clock: crate::clock::Clock,
    ) -> Self {
        let rules = builtin_shared();
        // The failure is *carried out* of this function rather than
        // swallowed inside it. See `audit_open_error`.
        let (audit, audit_open_error) = match path {
            Some(p) => match AuditLog::to_path(&p, Arc::clone(&rules)) {
                Ok(log) => (Arc::new(log), None),
                Err(e) => {
                    let why = format!("cannot open audit log {}: {e}", p.display());
                    // `diag!`, not `eprintln!`. The daemon builds its
                    // server through this exact constructor, and the
                    // daemon's stderr *is* `daemon.log` — a §9.2
                    // redacted boundary — so this line lands in the log
                    // file. `{e}` is an `io::Error` over a path the
                    // operator chose; the redactor is what makes that
                    // safe to persist rather than the shape of the
                    // message.
                    crate::diag!("holdfast: {why}");
                    (Arc::new(AuditLog::disabled(Arc::clone(&rules))), Some(why))
                }
            },
            // No path asked for, so nothing failed.
            None => (Arc::new(AuditLog::disabled(Arc::clone(&rules))), None),
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
            audit_open_error,
        }
    }

    /// `Some(reason)` when a §9.4 trail was asked for and could not be
    /// opened, so this server is running with **no** audit log.
    ///
    /// A host that can refuse must refuse; see
    /// [`audit_open_error`](HoldfastServer::audit_open_error) on the field.
    pub fn audit_open_error(&self) -> Option<&str> {
        self.audit_open_error.as_deref()
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

impl Default for HoldfastServer {
    fn default() -> Self {
        Self::new()
    }
}

/// The `resources` capability §5.5 requires, **for the in-process
/// transport**. The daemon-backed one advertises less — see
/// [`shim_capabilities`].
///
/// `listChanged: true` because [`HoldfastServer::on_initialized`] holds the
/// MCP peer and forwards every [`resource_list_changed`] pulse to it, so
/// `notifications/resources/list_changed` really is delivered when a
/// session is created or exits. `subscribe` is deliberately **absent**
/// rather than `false`: §5.5 writes `"subscribe": false`,
/// `ResourcesCapability` is `#[non_exhaustive]` so an explicit `false`
/// cannot be constructed from outside `rmcp`, and an omitted capability
/// and a `false` one mean the same thing to a client. v0.1.0 does not
/// implement subscriptions either way (§14.2).
///
/// [`resource_list_changed`]: HoldfastServer::resource_list_changed
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
/// notification is [`HoldfastServer::on_initialized`], and it is reachable
/// only from a `HoldfastServer` that holds an MCP peer. In hybrid mode that
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
impl ServerHandler for HoldfastServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo (= InitializeResult) and Implementation are
        // #[non_exhaustive]: build from Default, then assign.
        let mut info = ServerInfo::default();
        info.capabilities = server_capabilities();
        info.server_info = Implementation::new("holdfast", env!("CARGO_PKG_VERSION"));
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
///
/// **The operator's `config.toml` is loaded here, and it is the same
/// file the daemon loads** (§10.1, REQ-CFG-002/004). This path used to
/// run the whole tool surface on `Config::default()`: an operator who
/// set `max_concurrent_sessions`, `default_idle_timeout_secs`,
/// `resource_read_max_bytes` or anything else, and then ran
/// `holdfast mcp --no-daemon`, got the built-in value on every one of them
/// with no warning on any channel. The hybrid transport was configured
/// only because the *daemon* loads the file (`server::run`), not because
/// the MCP server does — so the knob was in force or not depending on a
/// flag that says nothing about configuration. On Windows, where §3.3
/// and §3.6 make stdio the only transport until 0.0.11, that meant
/// `config.toml` did nothing at all.
///
/// **Config first, and before anything is served** — the same ordering
/// `server::run` states for the same reason (REQ-CFG-003): an invalid or
/// untrusted file refuses to start rather than starting on defaults,
/// because the failure the requirement exists to prevent is an operator
/// believing a limit is in force when it is not. That is a new refusal
/// on this transport, and deliberately the *same* refusal the daemon
/// already makes about the same bytes; a file that starts a daemon
/// starts this, and a file that stops a daemon stops this. A missing
/// file — the stock install — is [`crate::config::Config::default`] and
/// not an error, so nothing that works today begins refusing.
///
/// The §9.4 audit trail still fails **open** here, unlike
/// `run_with_config`, which refuses. That divergence is tracked
/// separately; it is not this function's to decide quietly.
pub async fn serve_stdio() -> anyhow::Result<()> {
    let config = crate::config::load()?;
    // The audit path is resolved here rather than in `new()` so that only
    // the real server process ever writes to it.
    let server = HoldfastServer::with_audit_path_and_config(crate::audit::default_path(), &config);
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An audit log that could not be opened must leave a mark the host
    /// can act on.
    ///
    /// It used to leave only a line on stderr, which under
    /// `holdfast daemon run` goes wherever the launcher pointed it — so a
    /// root-owned `audit.log` from one `sudo holdfast` gave
    /// a server that ran normally and wrote no §9.4 trail at all, with
    /// nothing in the process able to tell. `server::run_with_config`
    /// refuses to serve on this, and it can only refuse on something it
    /// can see.
    ///
    /// **Both pairings matter and they are different.** A log that opens
    /// must report no failure, or the daemon refuses to start on every
    /// healthy machine. And `None` — no trail asked for, which is what
    /// every test and every in-process embedder passes — must report no
    /// failure either, or the same refusal fires where nothing went
    /// wrong.
    #[test]
    fn an_audit_log_that_cannot_be_opened_is_recorded_and_not_only_printed() {
        let dir = tempfile::tempdir().expect("a temp dir");

        // A **directory** where the log file belongs. Chosen over a mode
        // trick because it fails the same way for root, and over a
        // missing parent because `open_log_append` creates parents — the
        // open itself has to be what fails, or this test is about
        // something else.
        let blocked = dir.path().join("blocked").join("audit.log");
        std::fs::create_dir_all(&blocked).expect("the obstruction");
        let server = HoldfastServer::with_audit_path(Some(blocked.clone()));
        let why = server
            .audit_open_error()
            .expect("an unopenable audit log must be reported, not swallowed");
        assert!(
            why.contains("audit log"),
            "the reason has to name what failed, since it is what the daemon \
             prints when it refuses: {why}"
        );

        let opens = dir.path().join("fine").join("audit.log");
        assert_eq!(
            HoldfastServer::with_audit_path(Some(opens)).audit_open_error(),
            None,
            "a log that opens is not a failure; this reports one on every \
             healthy machine"
        );
        assert_eq!(
            HoldfastServer::new().audit_open_error(),
            None,
            "no trail asked for is a choice, not a failure"
        );
    }
}
