//! The daemon: one Unix listener, one `SessionRegistry`, one method
//! dispatcher (spec §7.2, §7.3, §7.4).
//!
//! **The daemon never opens a TCP listener** (§7.2, §9.1, REQ-D-001).
//! The only `bind` in this file is `UnixListener::bind`. The web UI's
//! TCP exposure is a separate, user-invoked bridge process that arrives
//! in 0.0.10 and binds loopback in *its own* address space.

use super::paths::{RuntimePaths, SOCKET_MODE};
use super::peer;
use crate::mcp::caller::{self, Caller};
use crate::mcp::{passthrough, ClaspServer};
use crate::protocol::frame::{self, FrameError};
use crate::protocol::handshake::{self, ClientKind, HandshakeParams};
use crate::protocol::method::{self, ErrorCode, Request, Response};
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

/// `daemon/status` response data (§7.4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub pid: u32,
    pub uptime_secs: u64,
    pub version: String,
    pub sessions_live: u64,
    pub sessions_exited_retained: u64,
    /// Always 0 until the attach protocol lands in 0.0.6.
    pub attach_clients: u64,
    /// Always 0 until the web-UI bridge lands in 0.0.10.
    pub bridge_sessions: u64,
}

/// `daemon/stop` params (§7.4.1).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StopParams {
    #[serde(default)]
    pub force: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

/// `daemon/stop` response data.
///
/// `stopped_at_unix_secs`, not `stopped_at`, and **not** because a date
/// crate was missing. §5.4/REQ-T-018 require an integer since the epoch
/// under a name that states its unit: *"no MCP field is an RFC-3339
/// string"*, and a bare `stopped_at` is prohibited outright, not merely
/// unused — a bare name invites a consumer to parse a value that will
/// not parse. Same convention as `started_at_unix_secs` in 0.0.1 and
/// `idle_deadline_unix_secs` in Task 16.
///
/// **This stopped being an argument by analogy at rev. 47.** REQ-T-018
/// used to reach the MCP tool surface and this field had to borrow the
/// rule from §5.4; rev. 47 widened it to *"every timestamp on a
/// CLASP-defined wire surface — the MCP tool surface, the control
/// protocol (§7.4.1), the attach protocol (§7.5) and the HTTP API"*, and
/// names bare `started_at` as its own example. So the requirement now
/// binds this response directly, in the section the field lives in, and
/// §7.4.1's `stopped_at` is a REQ-T-018 violation in the spec rather
/// than a divergence in this plan.
///
/// §7.4.1's table still shows the pre-rev-38 `stopped_at`. §5.4 wins,
/// and says so by name: it records that this milestone re-affirmed the
/// integer form *after* the date crate the original deferral waited on
/// had already landed in 0.0.3, and that *"the spec is the artifact that
/// was wrong."* Do **not** "discharge the deferral" by emitting RFC 3339
/// now that `chrono` and `audit::now_rfc3339()` exist — that is a
/// REQ-T-018 violation reached by following an argument this comment
/// used to make.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopOutcome {
    pub stopped_at_unix_secs: u64,
    pub sessions_terminated: u64,
}

fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared daemon state. One per process.
pub struct Daemon {
    pub server: ClaspServer,
    paths: RuntimePaths,
    started_at: Instant,
    shutdown_tx: watch::Sender<bool>,
    connections: AtomicU64,
    /// The uid this daemon belongs to, captured once at construction
    /// rather than re-read per connection.
    ///
    /// **This field is the seam that makes §9.1's peer-credential gate
    /// testable at all.** A test process cannot become a second user, so
    /// "a foreign peer is refused" is unreachable while the daemon asks
    /// `geteuid()` on every connection: every in-process peer is us.
    /// Holding the owner as state lets a test build a daemon that
    /// believes it belongs to *someone else*, which makes an ordinary
    /// local connection a foreign one — see
    /// `a_connection_from_a_foreign_uid_is_closed_before_the_handshake`.
    owner_uid: u32,
}

impl Daemon {
    /// **`with_audit_path`, never `new()`.** `ClaspServer::new()` is
    /// documented at HEAD as *"a server with the audit trail disabled …
    /// this is the constructor tests use"*, and `serve_stdio()` — the
    /// only production host before this milestone — uses
    /// `with_audit_path(audit::default_path())`. A daemon built from
    /// `new()` writes **no** §9.4 trail at all: not `redaction_disabled`,
    /// not `session_start`, nothing. Since 0.0.5 makes the daemon the
    /// default host for every session, that would silently remove the
    /// audit log from the default transport — a security regression
    /// delivered by a transport change, and invisible to every test that
    /// does not read the log back.
    ///
    /// The path comes from `paths`, not from `audit::default_path()`,
    /// because `default_path()` takes no environment override
    /// (`audit.rs`: *"There is no environment override … the config-file
    /// path arrives with the daemon in 0.0.5"*). On the default instance
    /// `paths.audit_log()` **is** `~/.clasp/logs/audit.log`, so the two
    /// agree; under an explicit `CLASP_RUNTIME_DIR` the audit log follows
    /// the instance, which is what will stop every `daemon_cli.rs` test
    /// (Task 14) from appending to the developer's real audit log. See
    /// **Decisions taken** — §7.1 states the relocation for `daemon.log`
    /// only, and extending it to `audit.log` is this plan's call.
    pub fn new(paths: RuntimePaths) -> Arc<Self> {
        Self::with_owner_uid(paths, peer::current_uid())
    }

    /// [`Daemon::new`] with the owning uid supplied rather than read from
    /// the process.
    ///
    /// Private, and deliberately so: production has exactly one right
    /// answer for this and `new` supplies it. It exists because the
    /// §9.1 gate is otherwise unprovable in-process — see `owner_uid`.
    fn with_owner_uid(paths: RuntimePaths, owner_uid: u32) -> Arc<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let audit_path = paths.audit_log();
        Arc::new(Self {
            server: ClaspServer::with_audit_path(Some(audit_path)),
            paths,
            started_at: Instant::now(),
            shutdown_tx,
            connections: AtomicU64::new(0),
            owner_uid,
        })
    }

    pub fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    /// Total connections accepted by the listener since start.
    ///
    /// Counted in `serve`, *before* the §9.1 credential gate runs, so it
    /// says "the daemon saw this peer" and nothing about whether the peer
    /// was served. That is exactly what a refusal test needs: silence on
    /// a socket is also what connecting to a dead daemon looks like, and
    /// this counter is what separates the two.
    pub fn accepted_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    pub fn status(&self) -> DaemonStatus {
        let all = self.server.registry.all();
        let live = all.iter().filter(|s| s.is_alive()).count() as u64;
        DaemonStatus {
            pid: std::process::id(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sessions_live: live,
            sessions_exited_retained: all.len() as u64 - live,
            attach_clients: 0,
            bridge_sessions: 0,
        }
    }

    /// Ask the accept loop to stop. Returns how many live sessions were
    /// killed on the way out.
    pub fn shutdown(&self) -> u64 {
        let mut terminated = 0;
        for session in self.server.registry.all() {
            if session.is_alive() {
                let _ = session.signal(crate::pty::Signal::Kill);
                terminated += 1;
            }
        }
        let _ = self.shutdown_tx.send(true);
        terminated
    }

    pub fn shutdown_signalled(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }
}

/// Bind `control.sock` and tighten it to `0600`.
///
/// The bind→chmod window is closed by the enclosing `0700` directory:
/// another user cannot reach the socket even during it, because they
/// cannot traverse the parent.
pub fn bind_control(paths: &RuntimePaths) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    paths.ensure_dir()?;
    let path = paths.control_sock();

    if path.exists() {
        // A socket file whose daemon is gone is stale and must be
        // cleared; one whose daemon is alive is not ours to take.
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("a daemon is already listening on {}", path.display()),
                ))
            }
            Err(_) => std::fs::remove_file(&path)?,
        }
    }

    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    if mode != SOCKET_MODE {
        let _ = std::fs::remove_file(&path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is mode {mode:o}, expected {SOCKET_MODE:o}",
                path.display()
            ),
        ));
    }
    Ok(listener)
}

/// Accept connections until shutdown is signalled.
pub async fn serve(daemon: Arc<Daemon>, listener: UnixListener) {
    let mut shutdown = daemon.shutdown_signalled();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        daemon.connections.fetch_add(1, Ordering::Relaxed);
                        let d = Arc::clone(&daemon);
                        tokio::spawn(async move { handle_connection(d, stream).await });
                    }
                    Err(e) => {
                        eprintln!("clasp daemon: accept failed: {e}");
                    }
                }
            }
        }
    }
}

/// Run a daemon to completion: bind, write the pid file, serve, clean up.
pub async fn run(paths: RuntimePaths) -> anyhow::Result<()> {
    // `bind_control` runs `paths.ensure_dir()`, which creates the log
    // directory `0700`. That ordering is load-bearing rather than
    // incidental: `Daemon::new` opens the audit log from `paths`, and
    // `with_audit_path` degrades a log it cannot open to a *disabled*
    // one with a line on stderr. Construct the daemon before the
    // directory exists and the trail is silently off. The same ordering
    // holds in `TestDaemon::start`, which binds first for the same
    // reason.
    let listener = bind_control(&paths)?;
    write_pid_file(&paths)?;
    let daemon = Daemon::new(paths.clone());

    let sig_daemon = Arc::clone(&daemon);
    tokio::spawn(async move {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("clasp daemon: cannot install SIGTERM handler: {e}");
                    return;
                }
            };
        term.recv().await;
        sig_daemon.shutdown();
    });

    serve(Arc::clone(&daemon), listener).await;

    // Anything still alive after `shutdown()` (or after a shutdown that
    // never ran, e.g. a bind error unwinding) dies here.
    daemon.shutdown();
    let _ = std::fs::remove_file(paths.control_sock());
    let _ = std::fs::remove_file(paths.pid_file());
    Ok(())
}

fn write_pid_file(paths: &RuntimePaths) -> io::Result<()> {
    std::fs::write(
        paths.pid_file(),
        format!("{} {}\n", std::process::id(), env!("CARGO_PKG_VERSION")),
    )
}

/// Read `clasp.pid`. `None` if absent or unparseable.
pub fn read_pid_file(paths: &RuntimePaths) -> Option<u32> {
    let text = std::fs::read_to_string(paths.pid_file()).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// §9.1's admission decision, as one expression.
///
/// Extracted from `handle_connection` on purpose. Inline, the decision
/// was a three-armed `match` whose diagnostics were interleaved with its
/// verdict, and the `Err` arm — the one that must **fail closed** — could
/// be turned into `Err(_) => {}` with nothing in the workspace going red.
/// As a function it has one caller, three arms and a unit test that names
/// all three: `the_uid_gate_admits_only_the_owner_and_fails_closed`.
///
/// The `Err` arm answering `false` is the whole point. A daemon that
/// cannot read a peer's credentials knows nothing about that peer, and
/// "unknown" is not "ours".
fn peer_is_authorized(cred: &io::Result<peer::PeerCred>, our_uid: u32) -> bool {
    matches!(cred, Ok(c) if peer::is_authorized(c.uid, our_uid))
}

async fn handle_connection(daemon: Arc<Daemon>, mut stream: UnixStream) {
    // Credential check first, before a single frame is read. An
    // unauthorized peer gets no response at all: there is nothing to
    // negotiate, and a reply would confirm the daemon's existence.
    let cred = peer::peer_cred(&stream);
    if !peer_is_authorized(&cred, daemon.owner_uid) {
        // Diagnostics only, and after the verdict rather than inside it:
        // nothing below can change who is admitted.
        match &cred {
            Ok(c) => eprintln!(
                "clasp daemon: refused a connection from uid {} (daemon runs as uid {})",
                c.uid, daemon.owner_uid
            ),
            Err(e) => eprintln!("clasp daemon: cannot read peer credentials, refusing: {e}"),
        }
        return;
    }

    // The kind the peer declared in its handshake, on a connection whose
    // uid we just checked. This is the *only* source of caller identity
    // for the §9.4 audit record — see `mcp::caller`.
    let Some(client_kind) = do_handshake(&mut stream).await else {
        return;
    };

    loop {
        let req: Request = match frame::read_frame(&mut stream).await {
            Ok(r) => r,
            Err(FrameError::Eof) => return,
            Err(FrameError::TooLarge { len }) => {
                let resp = Response::error(
                    0,
                    ErrorCode::FrameTooLarge,
                    format!("frame of {len} bytes exceeds {}", frame::MAX_FRAME_BYTES),
                );
                let _ = frame::write_frame(&mut stream, &resp).await;
                return;
            }
            Err(e) => {
                let resp = Response::error(0, ErrorCode::ProtocolViolation, e.to_string());
                let _ = frame::write_frame(&mut stream, &resp).await;
                return;
            }
        };

        let (resp, stop_after) = dispatch(&daemon, &req, client_kind).await;
        if frame::write_frame(&mut stream, &resp).await.is_err() {
            return;
        }
        if let Some(code) = resp
            .control_error()
            .and_then(|e| ErrorCode::from_wire(&e.code))
        {
            if code.closes_connection() {
                return;
            }
        }
        if stop_after {
            daemon.shutdown();
            return;
        }
    }
}

/// Exchange the handshake.
///
/// `Some(kind)` is the peer's declared [`ClientKind`], which becomes the
/// connection's caller identity for §9.4. `None` means the connection
/// must close.
async fn do_handshake(stream: &mut UnixStream) -> Option<ClientKind> {
    let req: Request = match frame::read_frame(stream).await {
        Ok(r) => r,
        Err(_) => return None,
    };
    if req.method != method::METHOD_HANDSHAKE {
        // §7.4.1: "a connection that issues any other method first is
        // closed with ProtocolError { reason: no_handshake }".
        let resp = Response::error(
            req.id,
            ErrorCode::NoHandshake,
            format!(
                "expected {} first, got {}",
                method::METHOD_HANDSHAKE,
                req.method
            ),
        );
        let _ = frame::write_frame(stream, &resp).await;
        return None;
    }
    let params: HandshakeParams = match req.params_as() {
        Ok(p) => p,
        Err(e) => {
            let resp = Response::error(req.id, ErrorCode::BadParams, e.to_string());
            let _ = frame::write_frame(stream, &resp).await;
            return None;
        }
    };
    let data = handshake::evaluate(&params);
    let accepted = data.accepted;
    let details = if accepted {
        "handshake accepted".to_string()
    } else {
        data.reject_reason.clone().unwrap_or_default()
    };
    let resp = match Response::ok(req.id, &data, details) {
        Ok(r) => r,
        Err(e) => Response::error(req.id, ErrorCode::ProtocolViolation, e.to_string()),
    };
    if frame::write_frame(stream, &resp).await.is_err() {
        return None;
    }
    if accepted {
        Some(params.client_kind)
    } else {
        None
    }
}

/// The caller recorded for a request (§9.4).
///
/// `req` is taken and deliberately **not** consulted. The parameter is
/// here so that the guarantee is testable: `an_agent_cannot_influence_the
/// _recorded_caller` passes a request stuffed with every field an agent
/// might try — `surface`, `client_kind`, `caller` — and asserts the
/// answer is still the connection's. Make this function read `req` and
/// that test goes red, which is the whole point of the shape.
fn caller_for(connection: ClientKind, _req: &Request) -> Caller {
    Caller::from_client_kind(connection)
}

/// Route one request. The `bool` is "shut the daemon down after replying".
async fn dispatch(
    daemon: &Arc<Daemon>,
    req: &Request,
    client_kind: ClientKind,
) -> (Response, bool) {
    match req.method.as_str() {
        method::METHOD_HANDSHAKE => (
            Response::error(
                req.id,
                ErrorCode::ProtocolViolation,
                "handshake already completed on this connection",
            ),
            false,
        ),
        method::METHOD_DAEMON_STATUS => (
            Response::ok(req.id, &daemon.status(), "ok")
                .unwrap_or_else(|e| Response::error(req.id, ErrorCode::BadParams, e.to_string())),
            false,
        ),
        method::METHOD_DAEMON_STOP => {
            // `force` and `timeout_secs` describe how hard to push the
            // *sessions*; 0.0.5 always sends SIGKILL to the process
            // group, so both are accepted and recorded rather than
            // silently ignored. The graceful path lands with the
            // reaper's SIGTERM-then-SIGKILL escalation.
            let _params: StopParams = req.params_as().unwrap_or_default();
            let terminated = daemon.shutdown();
            let outcome = StopOutcome {
                stopped_at_unix_secs: unix_secs_now(),
                sessions_terminated: terminated,
            };
            (
                Response::ok(req.id, &outcome, "daemon stopping").unwrap_or_else(|e| {
                    Response::error(req.id, ErrorCode::BadParams, e.to_string())
                }),
                true,
            )
        }
        other => {
            // `req.tool_name()` rather than a second inline
            // `strip_prefix`: two spellings of one routing rule means
            // the tested one is not the shipped one, and `method.rs`'s
            // negative cases are what stop `daemon/status` reaching the
            // 0.0.2 `status` tool. Do not re-derive the strip here.
            let Some(tool) = req.tool_name() else {
                return (
                    Response::error(
                        req.id,
                        ErrorCode::UnknownMethod,
                        format!("no method {other}"),
                    ),
                    false,
                );
            };
            (dispatch_tool(daemon, req, tool, client_kind).await, false)
        }
    }
}

async fn dispatch_tool(
    daemon: &Arc<Daemon>,
    req: &Request,
    tool: &str,
    client_kind: ClientKind,
) -> Response {
    let args: serde_json::Value = match method::from_cbor(&req.params) {
        Ok(v) => v,
        Err(e) => {
            return Response::error(
                req.id,
                ErrorCode::BadParams,
                format!("tool arguments are not a JSON-shaped object: {e}"),
            )
        }
    };
    // Scope the call to the caller derived from the connection, so the
    // §9.4 audit write inside the read path records who asked without
    // any tool handler having to pass it down.
    let who = caller_for(client_kind, req);
    let call = async {
        // Read back from *inside* the scope rather than trusting `who`.
        // Recording `who` here would still pass if the `with_caller`
        // wrapper below were removed, and a missing wrapper is precisely
        // the failure that would make every future audit entry read
        // `in_process`.
        #[cfg(test)]
        tests::record_observed_caller(caller::current());
        passthrough::call_tool(&daemon.server, tool, args).await
    };
    match caller::with_caller(who, call).await {
        None => Response::error(req.id, ErrorCode::UnknownMethod, format!("no tool {tool}")),
        // A tool that returns `Err(ErrorData)` is reporting an MCP
        // *protocol* fault (§5.1) — a schema violation, not an outcome.
        // It maps onto `bad_params` so the shim can re-raise it as
        // `invalid_params` instead of handing the agent a tool status
        // that §18.1 does not define.
        Some(Err(e)) => Response::error(req.id, ErrorCode::BadParams, e.message.to_string()),
        Some(Ok(result)) => {
            let outcome = passthrough::result_to_outcome(&result);
            let details = outcome.details.clone();
            let status = outcome.status.clone();
            match method::to_cbor(&outcome.data) {
                Ok(data) => Response {
                    id: req.id,
                    status,
                    data,
                    details,
                },
                Err(e) => Response::error(req.id, ErrorCode::ProtocolViolation, e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    /// Every field name an agent might reach for to relabel itself.
    fn forged_read_output(kind_it_wants_to_look_like: &str) -> Request {
        Request::new(
            1,
            "tool/read_output",
            &json!({
                "session": "sess_x",
                "since_cursor": 0,
                "redact": false,
                // None of these are read. If any ever were, the audit log
                // would be attacker-controlled where it matters most.
                "surface": "clasp_logs",
                "client_kind": kind_it_wants_to_look_like,
                "caller": kind_it_wants_to_look_like,
                "audit": { "client_kind": kind_it_wants_to_look_like },
            }),
        )
        .unwrap()
    }

    #[test]
    fn an_agent_cannot_influence_the_recorded_caller() {
        // The agent connects as `Shim` and asks to be recorded as a human
        // running `clasp logs --raw`. §9.4's whole value is that it
        // cannot: the answer comes from the authenticated connection.
        let req = forged_read_output("cli");
        assert_eq!(
            caller_for(ClientKind::Shim, &req),
            Caller::Agent,
            "the recorded caller must come from the connection, not the request"
        );
        // §9.4's spelling, carried from the handshake verbatim — not
        // `agent`, which would give one actor two names in one log.
        assert_eq!(caller::Caller::Agent.as_str(), "shim");
    }

    #[test]
    fn the_cli_cannot_dress_itself_up_as_an_agent_either() {
        // The guard is not agent-specific: it is that params are never
        // consulted, in either direction.
        let req = forged_read_output("shim");
        assert_eq!(caller_for(ClientKind::Cli, &req), Caller::Cli);
    }

    thread_local! {
        static OBSERVED: std::cell::Cell<Option<Caller>> =
            const { std::cell::Cell::new(None) };
    }

    /// Called by `dispatch_tool` from inside the caller scope.
    pub(super) fn record_observed_caller(c: Caller) {
        OBSERVED.with(|o| o.set(Some(c)));
    }

    /// Drive a real dispatch and report what the tool call saw.
    ///
    /// `#[tokio::test]` is current-thread, so the thread-local is the
    /// same one `dispatch_tool` writes.
    async fn observed_caller_for(kind: ClientKind) -> Option<Caller> {
        OBSERVED.with(|o| o.set(None));
        let dir = format!(
            "/tmp/clasp-t-caller-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();
        let daemon = Daemon::new(paths);
        let req = forged_read_output("cli");
        let (_resp, _stop) = dispatch(&daemon, &req, kind).await;
        let _ = std::fs::remove_dir_all(&dir);
        OBSERVED.with(|o| o.get())
    }

    #[tokio::test]
    async fn a_tool_call_runs_inside_the_connections_caller_scope() {
        // Guards the wiring, not just the derivation: without the
        // `with_caller` wrapper in `dispatch_tool` this reports
        // `InProcess` and every §9.4 entry would lose its subject.
        assert_eq!(
            observed_caller_for(ClientKind::Shim).await,
            Some(Caller::Agent)
        );
        assert_eq!(
            observed_caller_for(ClientKind::Cli).await,
            Some(Caller::Cli),
            "a CLI read must not be recorded as the agent's"
        );
    }

    #[test]
    fn every_client_kind_maps_through_the_connection() {
        let req = forged_read_output("cli");
        for (kind, expected) in [
            (ClientKind::Shim, Caller::Agent),
            (ClientKind::Cli, Caller::Cli),
            (ClientKind::UiBridge, Caller::UiBridge),
        ] {
            assert_eq!(caller_for(kind, &req), expected);
        }
    }

    #[test]
    fn the_uid_gate_admits_only_the_owner_and_fails_closed() {
        // All three arms of the one expression `handle_connection`
        // consults. The third is the one worth having a test for: an
        // `Err` that answered `true` — the shape `Err(_) => {}` takes in
        // the inline `match` this replaced — hands an unauthenticated
        // peer a full session surface, and no other test in the workspace
        // can see it.
        let us = peer::current_uid();
        let ours = peer::PeerCred {
            uid: us,
            gid: 0,
            pid: None,
        };
        let theirs = peer::PeerCred {
            uid: us.wrapping_add(1),
            gid: 0,
            pid: None,
        };
        assert!(peer_is_authorized(&Ok(ours), us));
        assert!(
            !peer_is_authorized(&Ok(theirs), us),
            "another user's connection must be refused"
        );
        assert!(
            !peer_is_authorized(&Err(io::Error::from(io::ErrorKind::PermissionDenied)), us),
            "an unreadable credential must fail closed, not open"
        );
    }

    /// The gate is *wired*, not merely correct.
    ///
    /// `the_uid_gate_admits_only_the_owner_and_fails_closed` proves the
    /// decision; on its own, deleting the call site leaves it green. This
    /// one drives a real `serve`/`handle_connection` over a real socket
    /// and asserts the connection dies before the handshake is answered.
    ///
    /// The trick that makes it possible: the test cannot become a second
    /// user, so it makes the *daemon* belong to one. `owner_uid` is
    /// state, so a daemon built for `current_uid() + 1` sees every
    /// ordinary local connection — including this test's — as foreign.
    #[tokio::test]
    async fn a_connection_from_a_foreign_uid_is_closed_before_the_handshake() {
        let dir = format!(
            "/tmp/clasp-t-uidgate-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let paths = RuntimePaths::with_dir(&dir);
        let listener = bind_control(&paths).expect("bind control.sock");
        let daemon = Daemon::with_owner_uid(paths.clone(), peer::current_uid().wrapping_add(1));
        tokio::spawn(serve(Arc::clone(&daemon), listener));

        let mut stream = UnixStream::connect(paths.control_sock())
            .await
            .expect("connect");
        let req = Request::new(
            0,
            method::METHOD_HANDSHAKE,
            &HandshakeParams::current(ClientKind::Cli),
        )
        .unwrap();
        // The write may land or may race the close; either is fine, and
        // neither is the assertion.
        let _ = frame::write_frame(&mut stream, &req).await;

        // Bounded, because the failure this guards against is a daemon
        // that keeps the connection open — which as a bare `await` is a
        // hang rather than a red test.
        let answered = tokio::time::timeout(
            Duration::from_secs(5),
            frame::read_frame::<_, Response>(&mut stream),
        )
        .await;
        assert!(
            matches!(answered, Ok(Err(_))),
            "an unauthorized peer must be closed on without a reply; got {answered:?}"
        );
        // Without this the test would also pass against a daemon that
        // never ran: a socket nobody serves reads EOF too. The counter is
        // incremented in `serve` before the gate, so it proves the daemon
        // took this connection and then dropped it.
        assert_eq!(
            daemon.accepted_connections(),
            1,
            "the daemon must have accepted the connection before refusing it"
        );

        daemon.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
