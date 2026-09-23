//! The hybrid-mode MCP server (spec §3.3): an MCP server whose tool
//! handlers are thin RPC calls into a daemon.
//!
//! `ShimServer` declares no tools of its own: `call_tool` forwards by
//! name, so no tool *behaviour* lives outside `holdfast-core`, which is
//! what §3.5 means in practice.
//!
//! **`list_tools` is answered locally, not fetched.** This said the
//! opposite — that the manifest came from the daemon "verbatim" — and it
//! did not: [`passthrough::tool_manifest`] is
//! `HoldfastServer::tool_router().list_all()`, a static call **in the
//! shim's own process**, and §7.4.1 defines no `tool/list` method by
//! which one could be fetched. `is_passthrough_tool`, the guard on
//! `call_tool`, reads the same local set.
//!
//! It matters because §7.4.1 **explicitly permits** shim/daemon minor
//! skew (*"Same-major different-minor is forwards/backwards
//! compatible"*). Under that skew: a tool a daemon minor added is
//! invisible to an older shim, and a tool this shim knows and the daemon
//! lacks is advertised and then answered `unknown_method` — which
//! [`rebuild_tool_error`] now reports as `invalid_params`, matching what
//! an unknown tool gets in-process, rather than as a server fault.
//!
//! `every_router_tool_is_dispatchable` builds both sides from one
//! process and cannot see any of this. Closing it properly needs a
//! manifest method on the control protocol, which is a protocol addition
//! for a later milestone; what is fixed here is the description and the
//! one code the skew makes reachable.

use super::passthrough;
use crate::daemon::RuntimePaths;
use crate::protocol::client::{ClientError, ControlClient};
use crate::protocol::frame::FrameError;
use crate::protocol::handshake::ClientKind;
use crate::protocol::method::{self, CborValue, Response, TOOL_METHOD_PREFIX};
use crate::session::launch::{ClientLaunch, CLIENT_PARAM};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::json;
use serde_json::Value;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The one tool whose call carries the shim's own launch context.
const START_SESSION: &str = "start_session";

/// What a response carries when the call that produced it had to start a
/// new daemon first (GH #231). Put in front of `details`, or of the
/// message of an error, so it is the first thing read.
pub const DAEMON_RESTARTED: &str = "The Holdfast daemon had stopped, so a new one was \
    started for this call: every session from the previous daemon is gone, and its session \
    ids no longer resolve.";

#[derive(Clone)]
pub struct ShimServer {
    link: Arc<Link>,
}

/// The shim's connection to its daemon, and how to make another one when
/// that daemon goes away (GH #231).
///
/// **Why the shim respawns at all.** It auto-spawns a daemon at startup
/// (§3.4, §7.3) and then held one `ControlClient` for its life. After a
/// `holdfast daemon stop` — which is the only way to load a new build, so
/// it is every upgrade — or a crash, every tool call through every open
/// client answered `daemon_unreachable`, forever, until something *else*
/// started a daemon. The shim now does what it did at startup, through
/// the same `spawn::ensure_daemon`: connect, or run `holdfast daemon
/// start` — whose lock and re-check are what keep a dozen shims noticing
/// at once to one daemon, exactly as for a dozen starting at once.
struct Link {
    current: parking_lot::Mutex<Connected>,
    /// `None` for a shim built over a stand-in, which has nothing to
    /// respawn; such a shim reports a lost daemon as it always did.
    respawn: Option<Respawn>,
    /// Held across a reconnection, so calls that fail together reconnect
    /// once: the second finds the generation already moved on.
    reconnecting: tokio::sync::Mutex<()>,
    /// The generation of the newest reconnection that reached a
    /// **different** daemon. A call that failed on an older generation
    /// reports the restart even if another call did the reconnecting.
    restarted_at: AtomicU64,
}

#[derive(Clone)]
struct Connected {
    client: Arc<ControlClient>,
    /// Bumped by every reconnection.
    generation: u64,
    /// The daemon's pid from `holdfast.pid` when this connection was
    /// made. `None` when it could not be read, which counts as "unknown"
    /// and so as a restart: telling an agent its sessions may be gone
    /// when they are not costs a `list_sessions`; the reverse costs it a
    /// run of `session_not_found` it cannot explain.
    daemon_pid: Option<u32>,
}

struct Respawn {
    paths: RuntimePaths,
    exe: PathBuf,
}

/// A connection made by [`ShimServer::reconnect`].
struct Reconnected {
    client: Arc<ControlClient>,
    /// Whether it reaches a different daemon than the one that was lost —
    /// which is what makes the previous daemon's sessions gone.
    restarted: bool,
}

impl ShimServer {
    /// A shim that does not respawn: its daemon is a stand-in (every test
    /// in this file) or somebody else's to manage.
    pub fn new(client: Arc<ControlClient>) -> Self {
        Self::build(client, None, None)
    }

    /// The shim `holdfast mcp` runs: when its daemon goes away, it starts
    /// another exactly as it started the first (GH #231). `exe` is the
    /// `holdfast` binary that `holdfast daemon start` is run from.
    pub fn with_respawn(client: Arc<ControlClient>, paths: RuntimePaths, exe: PathBuf) -> Self {
        let daemon_pid = crate::daemon::server::read_pid_file(&paths);
        Self::build(client, Some(Respawn { paths, exe }), daemon_pid)
    }

    fn build(
        client: Arc<ControlClient>,
        respawn: Option<Respawn>,
        daemon_pid: Option<u32>,
    ) -> Self {
        Self {
            link: Arc::new(Link {
                current: parking_lot::Mutex::new(Connected {
                    client,
                    generation: 0,
                    daemon_pid,
                }),
                respawn,
                reconnecting: tokio::sync::Mutex::new(()),
                restarted_at: AtomicU64::new(0),
            }),
        }
    }

    fn connected(&self) -> Connected {
        self.link.current.lock().clone()
    }

    /// Replace a connection that `err` says is lost, starting a daemon if
    /// there is none (GH #231).
    ///
    /// `None` when there is nothing to do: this shim does not respawn, or
    /// `err` is not a lost daemon. **Only `Connect` and `Frame` are** —
    /// "nobody is listening" and "the connection broke". A refusal, a
    /// protocol-major mismatch above all, is a daemon that is there and
    /// said no, and starting a second one over it is the response §7.3
    /// forbids at startup and that is no better here.
    ///
    /// **Through `spawn::ensure_daemon`, the startup path, not a second
    /// one.** It connects if a daemon is answering — another shim may
    /// already have started one — and otherwise runs `holdfast daemon
    /// start`, whose lock and re-check under the lock are what made
    /// `two_shims_racing_to_start_share_one_daemon` true at startup and
    /// make it true here.
    async fn reconnect(
        &self,
        failed: &Connected,
        err: &ClientError,
    ) -> Option<Result<Reconnected, ClientError>> {
        let respawn = self.link.respawn.as_ref()?;
        if !matches!(err, ClientError::Connect { .. } | ClientError::Frame(_)) {
            return None;
        }
        let _one_at_a_time = self.link.reconnecting.lock().await;
        let now = self.connected();
        if now.generation != failed.generation {
            // Another call reconnected while this one waited for the lock.
            return Some(Ok(Reconnected {
                client: now.client,
                restarted: self.link.restarted_at.load(Ordering::SeqCst) > failed.generation,
            }));
        }
        // **A daemon that has just died can still be accepting.** Measured
        // with `SIGKILL`: the shim sees its own connection close before
        // the kernel has closed the dead daemon's listener, so the next
        // `connect` succeeds and the handshake is then reset — a `Frame`
        // error, which `ensure_daemon` rightly refuses to spawn over, for
        // §7.3's reason: a daemon that accepted is running, or looks it.
        // Here the connection that was lost a moment ago says otherwise,
        // so a reset or an EOF on the handshake is retried for as long as
        // a listener takes to close. A handshake that **times out** is not
        // retried: that is a wedged daemon, GH #15's case, reported as it
        // is at startup.
        let settle = std::time::Instant::now() + RECONNECT_SETTLE;
        let client = loop {
            match crate::daemon::spawn::ensure_daemon(
                &respawn.paths,
                &respawn.exe,
                ClientKind::Shim,
            )
            .await
            {
                Ok(c) => break Arc::new(c),
                Err(e) if a_closing_listener(&e) && std::time::Instant::now() < settle => {
                    tokio::time::sleep(RECONNECT_POLL).await;
                }
                Err(e) => return Some(Err(e)),
            }
        };
        let daemon_pid = crate::daemon::server::read_pid_file(&respawn.paths);
        let restarted = !(daemon_pid.is_some() && daemon_pid == now.daemon_pid);
        let generation = now.generation + 1;
        *self.link.current.lock() = Connected {
            client: Arc::clone(&client),
            generation,
            daemon_pid,
        };
        if restarted {
            self.link.restarted_at.store(generation, Ordering::SeqCst);
        }
        Some(Ok(Reconnected { client, restarted }))
    }

    /// One tool round trip on `client`, racing `cancelled` as §GH #127
    /// requires. `cancel_seen` records that the cancel arm fired, which
    /// is what stops a cancelled call from being re-sent after a
    /// reconnection.
    async fn round_trip<F: Future<Output = ()>>(
        client: &ControlClient,
        method: &str,
        params: CborValue,
        token: &str,
        mut cancelled: Pin<&mut F>,
        cancel_seen: &mut bool,
    ) -> Result<Response, ClientError> {
        let call = client.call_raw_cancellable(method, params, Some(token));
        tokio::pin!(call);
        tokio::select! {
            // **`biased`, so the call is polled before the cancel.**
            // `select!` is random by default, and a random order lets an
            // already-cancelled request take the cancel arm on the first
            // poll — before `call_raw_cancellable` has written anything
            // — so the daemon sees the cancel *first*, on the connection
            // the call was going to use. Nothing breaks (the daemon
            // remembers a cancel that beats its call; see
            // `Daemon::recently_cancelled`), but it makes the ordinary
            // case depend on a coin flip, and it cost this file's own
            // row a spurious pass before it cost it a failure.
            biased;
            r = &mut call => r,
            () = cancelled.as_mut(), if !*cancel_seen => {
                *cancel_seen = true;
                let _ = client.cancel(token).await;
                // `&mut call`, so the round trip is still ours: the
                // response is read, the connection goes back to the pool,
                // and the daemon's own word for how the call ended is what
                // reaches rmcp.
                (&mut call).await
            }
        }
    }

    /// Forward one tool call to the daemon and rebuild the MCP result.
    ///
    /// §7.4.1 fixes the mapping this implements, and the whole of it:
    /// the method is `tool/<tool_name>`, `params` **is** the MCP
    /// `arguments` — not a wrapper around them — and the response's
    /// `data`, `status` and `details` map onto the envelope's three
    /// fields. `the_shim_puts_7_4_1s_own_field_names_on_the_wire`
    /// asserts each of those against a hand-built CBOR map rather than
    /// against a round-trip through these same types.
    ///
    /// ## Cancellation (GH #127)
    ///
    /// Every forwarded call carries a fresh `cancel_token`, and this
    /// function races the round trip against `cancelled`. On a cancel it
    /// sends
    /// one `holdfast/cancel` — **on another connection**, which is
    /// available because `ControlClient` checks one out per in-flight
    /// call — and then goes on awaiting the original.
    ///
    /// **It waits rather than returning, and that is deliberate.** The
    /// daemon answers a cancelled `request_secret_input` with
    /// `secret_cancelled { reason: "caller_cancelled" }` within
    /// microseconds, so there is nothing to gain by abandoning the round
    /// trip — and abandoning it would drop the checked-out connection
    /// mid-response, which is one leaked socket per cancel and the
    /// descriptor-discipline failure GH #21 and GH #52 were. rmcp is
    /// already discarding whatever we return for a request the client
    /// cancelled.
    ///
    /// **`cancelled` is a future rather than rmcp's token**, so this
    /// signature names no type from a crate `holdfast-core` does not
    /// depend on — and so a test can drive the cancelled path with
    /// `std::future::ready(())` and the ordinary path with
    /// `std::future::pending()`, neither of which needs an rmcp `Peer`
    /// to construct.
    ///
    /// **The cancel is best-effort.** Its own failure is not the caller's
    /// business: the call is still outstanding and will still answer,
    /// and turning a failed cancel into a tool error would replace a
    /// real result with a transport complaint.
    async fn forward(
        &self,
        tool: &str,
        arguments: Option<serde_json::Map<String, Value>>,
        cancelled: impl std::future::Future<Output = ()>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut arguments = arguments.unwrap_or_default();
        // **GH #229: a session starts where its caller is.** This process
        // is the one the MCP client launched, in the client's project and
        // with the client's environment; the daemon is shared by every
        // client and its own directory and environment are whichever one
        // spawned it. So the shim says where it is, under a key no tool
        // argument can have, and the daemon decides what to do with it —
        // `session::launch` holds the rule, including the one kind of
        // session (a `profile`) that must ignore it. Inserted *over*
        // anything the MCP client put there: the context is this
        // process's to state, not the agent's.
        if tool == START_SESSION {
            let context = serde_json::to_value(ClientLaunch::of_this_process())
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
            arguments.insert(CLIENT_PARAM.to_string(), context);
        }
        let args = Value::Object(arguments);
        let params =
            method::to_cbor(&args).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let method_name = format!("{TOOL_METHOD_PREFIX}{tool}");
        tokio::pin!(cancelled);
        let mut cancel_seen = false;
        let first = self.connected();
        let outcome = Self::round_trip(
            &first.client,
            &method_name,
            params.clone(),
            &token,
            cancelled.as_mut(),
            &mut cancel_seen,
        )
        .await;

        // **GH #231: a lost daemon is replaced, and the call re-sent only
        // when it provably never reached the old one.** `Connect` is a
        // dial that failed and `BrokenPipe` a write into a connection
        // the daemon had already closed — the parked connection every
        // call after a `daemon stop` meets first. Anything else — above
        // all an EOF while reading the answer — may have run the call
        // before the daemon went, and re-sending a `send_input` or a
        // `start_session` would run it twice. That one is answered with
        // what is known, and no guess.
        let (resp, restarted) = match outcome {
            Ok(resp) => (resp, false),
            Err(e) => match self.reconnect(&first, &e).await {
                None => return Err(map_client_error(e)),
                Some(Err(spawn)) => return Err(respawn_failed(&e, spawn)),
                Some(Ok(fresh)) if never_reached_a_daemon(&e) && !cancel_seen => {
                    let resp = Self::round_trip(
                        &fresh.client,
                        &method_name,
                        params,
                        &token,
                        cancelled.as_mut(),
                        &mut cancel_seen,
                    )
                    .await
                    .map_err(map_client_error)?;
                    (resp, fresh.restarted)
                }
                Some(Ok(fresh)) => return Err(lost_in_flight(&e, fresh.restarted)),
            },
        };

        if let Some(e) = resp.control_error() {
            let mut err = rebuild_tool_error(e);
            if restarted {
                err.message = format!("{DAEMON_RESTARTED} {}", err.message).into();
            }
            return Err(err);
        }

        let data: Value = method::from_cbor(&resp.data)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let details = if restarted {
            format!("{DAEMON_RESTARTED} {}", resp.details)
        } else {
            resp.details
        };
        Ok(passthrough::outcome_to_result(passthrough::ToolOutcome {
            status: resp.status,
            data,
            details,
        }))
    }

    /// One `resource/*` round trip, returning the response `data`.
    ///
    /// The error path goes through [`rebuild_resource_error`] rather than
    /// [`rebuild_error`], because §5.5.2 requires a *structured*
    /// `data.code` that the control protocol has nowhere to carry and the
    /// daemon therefore encodes into the error message.
    async fn forward_resource(&self, method: &str, params: Value) -> Result<Value, ErrorData> {
        let params =
            method::to_cbor(&params).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let first = self.connected();
        // GH #231, as for a tool call — except that every `resource/*`
        // method only reads, so re-sending one that may have reached the
        // old daemon repeats nothing, and it is re-sent either way.
        let resp = match first.client.call_raw(method, params.clone()).await {
            Ok(resp) => resp,
            Err(e) => match self.reconnect(&first, &e).await {
                None => return Err(map_client_error(e)),
                Some(Err(spawn)) => return Err(respawn_failed(&e, spawn)),
                Some(Ok(fresh)) => fresh
                    .client
                    .call_raw(method, params)
                    .await
                    .map_err(map_client_error)?,
            },
        };
        if let Some(e) = resp.control_error() {
            return Err(rebuild_resource_error(e));
        }
        method::from_cbor(&resp.data).map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }
}

/// Rebuild the MCP error the agent would have seen in-process from
/// §7.4.1's error payload.
///
/// **`rpc_code` wins outright when the daemon sent one.** The control
/// protocol has no room for the JSON-RPC codes an MCP handler raises, so
/// the daemon flattens every `Err(ErrorData)` onto §18.3's nearest row,
/// `bad_params`. Rebuilding from `code` alone therefore reported every
/// *internal* fault as the agent's own bad argument: `openpty failed`
/// arrived as `invalid_params` here and as `internal_error` under
/// `--no-daemon`, so the two transports disagreed about whose fault it
/// was. `rpc_code` is the daemon's record of what the handler really
/// raised, and it is the whole of the answer when it is present.
///
/// Without it — a daemon one minor behind, or any control-protocol fault
/// that never came from a tool — the original mapping stands.
/// `bad_params` is `invalid_params`, which is right for §5.5.2's
/// validation faults; everything else is a server fault and says which
/// §18.3 code it was.
fn rebuild_error(e: method::ControlError) -> ErrorData {
    if let Some(code) = e.rpc_code {
        return ErrorData::new(rmcp::model::ErrorCode(code), e.message, None);
    }
    if e.code == method::ErrorCode::BadParams.as_str() {
        ErrorData::invalid_params(e.message, None)
    } else {
        ErrorData::internal_error(format!("[{}] {}", e.code, e.message), None)
    }
}

/// [`rebuild_error`], plus the one §18.3 code whose meaning is
/// transport-specific on a `tool/*` call.
///
/// **`unknown_method` on a tool call means "no such tool", and an
/// unknown tool is `-32602` on the MCP wire.** rmcp's router answers
/// `invalid_params("tool not found")` in-process, and `call_tool`'s own
/// guard two functions down answers `invalid_params` for a name outside
/// the manifest. Falling through to [`rebuild_error`] made the daemon's
/// answer `internal_error` instead — the same call, two diagnoses,
/// decided by which transport was in use.
///
/// Not hypothetical: §7.4.1 permits shim/daemon minor skew, and a tool
/// this shim advertises and an older daemon does not have lands exactly
/// here. `internal_error` tells the agent to give up on a server bug
/// where `invalid_params` tells it the tool does not exist, which is
/// both true and actionable.
///
/// `rpc_code` still wins when the daemon sent one, for
/// [`rebuild_error`]'s reason: it is the handler's own code, and this
/// arm is a guess made in its absence.
fn rebuild_tool_error(e: method::ControlError) -> ErrorData {
    if e.rpc_code.is_none() && e.code == method::ErrorCode::UnknownMethod.as_str() {
        return ErrorData::invalid_params(e.message, None);
    }
    rebuild_error(e)
}

/// [`rebuild_error`], plus the `{message, data}` envelope the daemon
/// writes for a `resource/read` fault.
///
/// **§5.5.2's four codes are structured `data`, not prose.** The
/// in-process transport answers a bad URI with
/// `ErrorData::invalid_params(message, Some({"code": "invalid_enum",
/// "param": "ansi", "value": "purple", "allowed": [...]}))` and an agent
/// branches on `data.code` to know whether to fix a name, a value or a
/// range. `ControlError` has nowhere to put that object, so
/// `daemon::server::dispatch_resource` JSON-encodes `{message, data}`
/// into the error *message* — and the rebuild here never decoded it. The
/// agent got a raw JSON blob where prose belongs and `data: null` where
/// the four codes belong, on the transport that is the default.
///
/// This is the decode for that encode. Nothing new crosses the wire: the
/// same bytes already travelled, in the wrong field.
///
/// Conservative about what it will unwrap — exactly the two keys, a
/// string `message` — because a §5.5.2 message is prose and any other
/// producer's message must be left alone. A message that is not this
/// envelope falls through unchanged.
fn rebuild_resource_error(e: method::ControlError) -> ErrorData {
    let mut out = rebuild_error(e);
    if let Some((message, data)) = decode_resource_envelope(&out.message) {
        out.message = message.into();
        out.data = data;
    }
    out
}

/// The `{message, data}` object `dispatch_resource` encodes, parsed back
/// out. `None` for anything else, including plain prose.
///
/// `data: null` becomes `None` rather than `Some(Value::Null)`: the
/// daemon writes `null` there for an `ErrorData` that carried no
/// structured payload — `resource_not_found`, for one — and
/// `Some(Value::Null)` would put a literal `"data": null` on the MCP wire
/// where the in-process transport omits the field.
fn decode_resource_envelope(message: &str) -> Option<(String, Option<Value>)> {
    let parsed: Value = serde_json::from_str(message).ok()?;
    let obj = parsed.as_object()?;
    // Both keys and only those two. A message that merely *happens* to
    // be a JSON object is not this envelope.
    if obj.len() != 2 || !obj.contains_key("data") {
        return None;
    }
    let message = obj.get("message")?.as_str()?.to_string();
    let data = match obj.get("data") {
        Some(Value::Null) | None => None,
        Some(d) => Some(d.clone()),
    };
    Some((message, data))
}

/// The daemon-backed server's `instructions`, **derived** from the
/// in-process text rather than copied from it.
///
/// Both transports build `list_tools` from the same in-process
/// `HoldfastServer::tool_router()`, so every tool description, output
/// schema and annotation already has exactly one definition — *derived*
/// on both sides rather than forwarded, which this comment used to
/// claim. That leaves `instructions` as the one agent-visible string
/// with no shared derivation of its own, so it is built from
/// [`super::INSTRUCTIONS`] and differs by exactly one appended sentence
/// — the single fact that is genuinely transport-specific.
///
/// A second hand-written copy would have been stale the day it was
/// written. 0.0.2 rewrote that string because it still described a
/// four-tool 0.0.1 surface, and 0.0.3 rewrote its closing sentence from
/// "returned raw and unredacted" to the redaction contract — neither
/// edit would have reached a copy living here, and hybrid mode is the
/// *default* transport, so the copy is the text most agents would read.
fn instructions() -> String {
    format!(
        "{} Sessions live in a background daemon and survive this connection.",
        super::INSTRUCTIONS
    )
}

fn map_client_error(e: ClientError) -> ErrorData {
    // §3.2: an unreachable daemon is a JSON-RPC internal error carrying
    // `data.reason = "daemon_unreachable"`, not a tool status.
    ErrorData::internal_error(
        "Internal error".to_string(),
        Some(serde_json::json!({
            "reason": "daemon_unreachable",
            "detail": e.to_string(),
        })),
    )
}

/// How long [`ShimServer::reconnect`] waits for a dead daemon's listener
/// to close. It closes as the process's descriptors are torn down, so
/// this bounds a race measured in microseconds, generously.
const RECONNECT_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);
const RECONNECT_POLL: std::time::Duration = std::time::Duration::from_millis(25);

/// A handshake refused by a listener that is going away: accepted, then
/// reset or closed. Not a timeout — that is a daemon that is there and
/// not answering.
fn a_closing_listener(e: &ClientError) -> bool {
    match e {
        ClientError::Frame(FrameError::Eof) => true,
        ClientError::Frame(FrameError::Io(io)) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

/// Whether a failed round trip provably never reached a daemon, so the
/// call can be re-sent without running it twice (GH #231).
///
/// `Connect` is a dial that failed: nothing was written. `BrokenPipe` is
/// a **write** that failed — a read reports a closed peer as EOF or a
/// reset, never as a broken pipe — so the daemon had closed the
/// connection before the request, or a truncated start of it, reached
/// it, and a truncated frame is not dispatched. Everything else, an EOF
/// while waiting for the answer above all, may have been run.
fn never_reached_a_daemon(e: &ClientError) -> bool {
    match e {
        ClientError::Connect { .. } => true,
        ClientError::Frame(FrameError::Io(io)) => io.kind() == std::io::ErrorKind::BrokenPipe,
        _ => false,
    }
}

/// The daemon went away and a new one could not be started.
///
/// Still §3.2's `daemon_unreachable`, because that is what it is; the
/// detail says both halves, since "cannot reach" alone reads as though
/// nothing was tried.
fn respawn_failed(lost: &ClientError, spawn: ClientError) -> ErrorData {
    ErrorData::internal_error(
        "Internal error".to_string(),
        Some(serde_json::json!({
            "reason": "daemon_unreachable",
            "detail": format!("{lost}; starting a new daemon failed: {spawn}"),
        })),
    )
}

/// A call that may have run on a daemon that has since gone (GH #231).
///
/// Not re-sent — see `forward` — so the answer is what is known: a new
/// daemon is up, the old one's sessions went with it, and whether this
/// call took effect first cannot be said. `daemon_restarted` names the
/// case; when the daemon on the far side turns out to be the same one,
/// the connection merely broke, and `daemon_unreachable` is the honest
/// reason for that.
fn lost_in_flight(e: &ClientError, restarted: bool) -> ErrorData {
    let (reason, message) = if restarted {
        (
            "daemon_restarted",
            "The Holdfast daemon stopped while this call was in flight, and a new one has been \
             started: every session from the previous daemon is gone, and whether this call \
             took effect before it stopped is unknown.",
        )
    } else {
        (
            "daemon_unreachable",
            "The connection to the Holdfast daemon broke while this call was in flight and has \
             been re-established; whether this call took effect is unknown.",
        )
    };
    ErrorData::internal_error(
        message.to_string(),
        Some(serde_json::json!({ "reason": reason, "detail": e.to_string() })),
    )
}

impl ServerHandler for ShimServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        // **`shim_capabilities`, not `server_capabilities`.** The
        // difference is `resources.listChanged`, which this transport
        // cannot deliver: the forwarder that turns a pulse into an MCP
        // notification is `HoldfastServer::on_initialized`, and in hybrid
        // mode that object runs inside the daemon with no MCP peer to
        // notify. See `super::shim_capabilities` for the deferral.
        info.capabilities = super::shim_capabilities();
        info.server_info = Implementation::new("holdfast", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(instructions());
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(passthrough::tool_manifest()))
    }

    /// **`context` is read rather than discarded** (GH #127).
    ///
    /// It used to be `_context`, and that one underscore was the whole
    /// bug: rmcp cancels `context.ct` when the client sends
    /// `notifications/cancelled`, and the shim is the only place in this
    /// process that can see it. rmcp does **not** abort the handler — it
    /// fires the token and still delivers whatever the handler eventually
    /// returns — so ignoring it meant a cancelled `request_secret_input`
    /// ran its whole window inside the daemon, holding the session's one
    /// request slot, while an attached human looked at a prompt whose
    /// asker had gone.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        // The guard reads the daemon-side manifest, so it needs no
        // updating when a milestone adds a tool.
        if !passthrough::is_passthrough_tool(&name) {
            return Err(ErrorData::invalid_params(format!("no tool {name}"), None));
        }
        Ok(self
            .forward(&name, request.arguments, context.ct.cancelled())
            .await?
            .into())
    }

    // §5.5's three methods, forwarded to §7.4.1's three control methods.
    // **The spellings differ on the two wires** — MCP says
    // `resources/templates/list`, the control protocol says
    // `resource/templates_list` — and the constants below are the only
    // place that mapping is written down.
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let data = self
            .forward_resource(method::METHOD_RESOURCE_LIST, json!({}))
            .await?;
        let resources = serde_json::from_value(data.get("resources").cloned().unwrap_or(json!([])))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let data = self
            .forward_resource(method::METHOD_RESOURCE_TEMPLATES_LIST, json!({}))
            .await?;
        let templates =
            serde_json::from_value(data.get("resourceTemplates").cloned().unwrap_or(json!([])))
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(ListResourceTemplatesResult::with_all_items(templates))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let data = self
            .forward_resource(method::METHOD_RESOURCE_READ, json!({ "uri": request.uri }))
            .await?;
        let result: ReadResourceResult = serde_json::from_value(data)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(result.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame;
    use crate::protocol::handshake::{self, ClientKind, HandshakeData};
    use crate::protocol::method::{CborValue, Request, Response};
    use serde_json::json;
    use std::path::PathBuf;

    /// Kills the mutation of hand-writing a second `instructions`
    /// literal here instead of deriving one. That copy cannot be kept in
    /// step by review: it says nothing wrong on the day it lands and
    /// goes stale the next time anyone edits the in-process string.
    ///
    /// `instructions()` is a free function precisely so this test can
    /// run without a `ControlClient` and therefore without a socket.
    #[test]
    fn the_shim_derives_its_instructions_from_the_in_process_ones() {
        let text = instructions();
        let shared = crate::mcp::INSTRUCTIONS;
        // The positive: everything the in-process server tells an agent
        // — the tool names `scripts/mcp-smoke.sh` asserts on, and the
        // output-handling sentence — is present here verbatim.
        assert!(
            text.starts_with(shared),
            "the shim's instructions must be the shared text plus a suffix, not a second copy"
        );
        let suffix = &text[shared.len()..];
        // The negative that separates that from the degenerate case:
        // `starts_with` is equally satisfied by an empty suffix, and the
        // one fact this transport must add for itself is that a session
        // outlives the connection that created it.
        assert!(
            suffix.contains("daemon"),
            "hybrid mode must still say sessions live in a daemon; suffix was {suffix:?}"
        );
        // And the suffix must not re-describe what the shared text
        // already covers: output handling has exactly one home, so a
        // stale "raw and unredacted" claim cannot be reintroduced here
        // after 0.0.3 removes it there.
        assert!(
            !suffix.contains("unredacted"),
            "output handling is described once, in the shared text; suffix was {suffix:?}"
        );
    }

    /// REQ-R-006 has no delivery path on this transport, so the
    /// handshake must not claim one.
    ///
    /// `HoldfastServer::on_initialized` is the only thing in the tree that
    /// turns a `resource_list_changed` pulse into an MCP notification,
    /// and it needs the MCP peer. In hybrid mode the `HoldfastServer` lives
    /// in the daemon, where there is no peer: the pulse goes into a
    /// broadcast channel with zero receivers, and §7.4.1's streaming
    /// frames are reserved and unused in v0.1.0, so nothing carries it
    /// across. An agent told `listChanged: true` holds a stale
    /// `resources/list` for the life of the connection.
    ///
    /// **Read through `get_info`, not off the free function.** A test
    /// that compared `shim_capabilities()` with `server_capabilities()`
    /// would be green while `get_info` went on returning the wrong one
    /// — which is the defect, exactly.
    ///
    /// The last assertion is the pairing: without it a build that
    /// dropped the notification from *both* transports passes, and that
    /// would be a regression on the transport that can deliver it.
    #[tokio::test]
    async fn the_shim_does_not_advertise_the_notification_it_cannot_deliver() {
        let dir = scratch_dir("caps");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");
        // No request is issued, so the reply template is never used; the
        // stand-in is here only to complete the handshake `connect`
        // needs.
        let _captured = stand_in_daemon(sock.clone(), CborValue::Map(vec![]));
        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let caps = shim.get_info().capabilities;
        let resources = caps
            .resources
            .expect("§5.5's resources capability is served on both transports");
        assert_eq!(
            resources.list_changed, None,
            "hybrid mode has no path from the daemon's pulse to the MCP peer, \
             so advertising `listChanged` promises a notification that is dropped"
        );
        // The rest of the surface is unchanged: this is one capability
        // withdrawn, not the resources surface retreating.
        assert!(
            caps.tools.is_some(),
            "the shim still serves tools/list and tools/call"
        );

        let in_process = crate::mcp::HoldfastServer::new()
            .get_info()
            .capabilities
            .resources
            .expect("§5.5's resources capability in-process");
        assert_eq!(
            in_process.list_changed,
            Some(true),
            "`--no-daemon` holds the MCP peer in `on_initialized` and does \
             deliver the notification; withdrawing it there too would be a \
             regression, and would satisfy the assertion above"
        );
    }

    /// A `/tmp` path short enough for `sockaddr_un.sun_path`.
    fn scratch_dir(tag: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        PathBuf::from(format!("/tmp/holdfast-t-shim-{tag}-{}", &unique[..8]))
    }

    struct Scoped(PathBuf);
    impl Drop for Scoped {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The value at `key` in a CBOR map, read as a **raw map** rather
    /// than through a derived `Deserialize`.
    ///
    /// This is the whole point of the test below. `Request`/`Response`
    /// decode through the same impls the shim encoded with, so they
    /// agree with themselves whatever the field names are — a
    /// `#[serde(rename_all = "camelCase")]` on either type is invisible
    /// to every round-trip assertion and fatal on the wire. Only a
    /// literal key lookup can see it.
    fn field<'a>(value: &'a CborValue, key: &str) -> &'a CborValue {
        let CborValue::Map(entries) = value else {
            panic!("§7.4's frames are maps, got {value:?}")
        };
        entries
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| {
                let keys: Vec<_> = entries.iter().filter_map(|(k, _)| k.as_text()).collect();
                panic!("no `{key}` on the wire; the frame carried {keys:?}")
            })
    }

    /// A stand-in daemon that completes the handshake, then captures the
    /// **raw** CBOR of the next request and answers it with a
    /// hand-built map.
    ///
    /// Hand-built in both directions on purpose. A stand-in that replied
    /// with `Response::ok(..)` would serialise through the same derive
    /// the shim deserialises with, which proves the shim agrees with
    /// this crate rather than with §7.4.1.
    /// **GH #127: a cancelled `call_tool` puts a `holdfast/cancel` on the
    /// wire, and still reads the answer it was waiting for.**
    ///
    /// The shim is where MCP cancellation enters this system and it used
    /// to end there — `_context`, bound and dropped. Four claims, and
    /// each of them is a step the old code took none of:
    ///
    /// 1. the forwarded call carries a `cancel_token`;
    /// 2. a cancel goes out, **on a second connection**, because the
    ///    daemon will not read another frame from the first until the
    ///    call it is carrying has returned;
    /// 3. it names the same token;
    /// 4. the shim goes on to read the original response rather than
    ///    abandoning the round trip — which would leak the checked-out
    ///    socket and is the descriptor discipline GH #21 and GH #52 are
    ///    about.
    ///
    /// **The stand-in answers the call only after the cancel has
    /// arrived**, so the ordering under test is always the hostile one
    /// rather than one that happens by luck.
    #[tokio::test]
    async fn a_cancelled_call_tool_sends_the_daemon_a_cancel_on_another_connection() {
        let dir = scratch_dir("cancel");
        std::fs::create_dir_all(&dir).unwrap();
        let _scoped = Scoped(dir.clone());
        let sock = dir.join("control.sock");

        let (calls_tx, calls_rx) = tokio::sync::oneshot::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        {
            let sock = sock.clone();
            tokio::spawn(async move {
                let listener = tokio::net::UnixListener::bind(&sock).unwrap();

                // Connection 1: the tool call. Captured and held.
                let (mut first, _) = listener.accept().await.unwrap();
                shake(&mut first).await;
                let call: CborValue = frame::read_frame(&mut first).await.unwrap();
                let call_id = u64::try_from(field(&call, "id").as_integer().unwrap()).unwrap();
                calls_tx.send(call).unwrap();

                // Connection 2: the cancel. It can only arrive here,
                // because nothing is reading connection 1 any more.
                let (mut second, _) = listener.accept().await.unwrap();
                shake(&mut second).await;
                let cancel: CborValue = frame::read_frame(&mut second).await.unwrap();
                let cancel_id = u64::try_from(field(&cancel, "id").as_integer().unwrap()).unwrap();
                cancel_tx.send(cancel).unwrap();
                let ack = Response::ok(
                    cancel_id,
                    &crate::protocol::method::CancelOutcome { cancelled: true },
                    "the call was signalled",
                )
                .unwrap();
                frame::write_frame(&mut second, &ack).await.unwrap();

                // Only now does the call answer, exactly as a daemon
                // whose `request_secret_input` has just been cancelled
                // would.
                let _ = release_rx.await;
                let reply = CborValue::Map(vec![
                    (
                        CborValue::Text("id".into()),
                        CborValue::Integer(call_id.into()),
                    ),
                    (
                        CborValue::Text("status".into()),
                        CborValue::Text("secret_cancelled".into()),
                    ),
                    (
                        CborValue::Text("data".into()),
                        CborValue::Map(vec![(
                            CborValue::Text("reason".into()),
                            CborValue::Text("caller_cancelled".into()),
                        )]),
                    ),
                    (
                        CborValue::Text("details".into()),
                        CborValue::Text("the secret request ended: caller_cancelled".into()),
                    ),
                ]);
                frame::write_frame(&mut first, &reply).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let mut arguments = serde_json::Map::new();
        arguments.insert("session".into(), json!("sess_abc"));
        arguments.insert("prompt_text".into(), json!("a credential"));
        //
        // **The cancellation fires only once the stand-in has the call**,
        // which is what makes the ordering under test the real one rather
        // than a race: `biased` makes the call arm poll first, and this
        // makes "first" mean "the request is on the wire".
        let (fire_tx, fire_rx) = tokio::sync::oneshot::channel::<()>();
        let forwarded = tokio::spawn(async move {
            shim.forward("request_secret_input", Some(arguments), async {
                let _ = fire_rx.await;
            })
            .await
        });

        let call = tokio::time::timeout(std::time::Duration::from_secs(10), calls_rx)
            .await
            .expect("the tool call never reached the stand-in")
            .expect("the call channel");
        // 1. The forwarded call names itself.
        let token = field(&call, "cancel_token")
            .as_text()
            .expect(
                "the forwarded call carries no `cancel_token`, so nothing could \
                     ever cancel it",
            )
            .to_string();
        assert!(
            !token.is_empty(),
            "the `cancel_token` is present but empty, which names every call at once"
        );

        // Now cancel, with the call outstanding on connection 1.
        fire_tx.send(()).unwrap();

        // 2 and 3. The cancel arrived, on its own connection, for that
        // token.
        let cancel = tokio::time::timeout(std::time::Duration::from_secs(10), cancel_rx)
            .await
            .expect(
                "no `holdfast/cancel` reached the daemon: the shim read the \
                 cancellation and did nothing with it",
            )
            .expect("the cancel channel");
        assert_eq!(
            field(&cancel, "method").as_text(),
            Some(crate::protocol::method::METHOD_CANCEL),
            "the second connection carried something other than a cancel"
        );
        assert_eq!(
            field(field(&cancel, "params"), "token").as_text(),
            Some(token.as_str()),
            "the cancel names a different call than the one it is cancelling"
        );

        // 4. And the original round trip is still the shim's: the
        // daemon's own word for how the call ended is what comes back.
        release_tx.send(()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), forwarded)
            .await
            .expect("the forward never returned after the cancel")
            .expect("the forward task")
            .expect("the stand-in answered ok");
        let body = result
            .structured_content
            .expect("the envelope has structured content");
        assert_eq!(
            body["status"], "secret_cancelled",
            "the shim abandoned the round trip instead of reading the answer: {body}"
        );
        assert_eq!(body["data"]["reason"], "caller_cancelled", "{body}");
    }

    /// **GH #127: `call_tool` reads the cancellation rmcp hands it.**
    ///
    /// **Written because replacing `context.ct.cancelled()` with
    /// `std::future::pending()` left every row in this file, in
    /// `tests/control_protocol.rs` and in `tests/secrets.rs` green** —
    /// warning-free, because `context` stays used by
    /// `ToolCallContext::new`. Every other shim row calls
    /// [`ShimServer::forward`] with a hand-supplied future, which is a
    /// defensible seam and one statement past the defect: this module's
    /// own doc says *"it used to be `_context`, and that one underscore
    /// was the whole bug"*, and that underscore was exactly what nothing
    /// could see.
    ///
    /// **A real `ShimServer` served over an in-memory duplex, driven by
    /// hand-written JSON-RPC.** `RequestContext` carries a `Peer` and a
    /// `Peer` is made by `serve()` and by nothing else, so the only way
    /// to reach `call_tool` at all is to be a client. The client half is
    /// written out rather than taken from rmcp because `client` is not
    /// one of rmcp's default features — and the hand-written form is the
    /// better assertion anyway, for this file's usual reason: it is the
    /// bytes an agent sends, not a round trip through the same impls the
    /// server decodes with.
    #[tokio::test]
    async fn call_tool_reads_the_cancellation_rmcp_hands_it() {
        use rmcp::service::ServiceExt;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = scratch_dir("ctbridge");
        std::fs::create_dir_all(&dir).unwrap();
        let _scoped = Scoped(dir.clone());
        let sock = dir.join("control.sock");

        // A daemon that accepts the tool call and never answers it, and
        // hands back whatever arrives on the next connection.
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (called_tx, called_rx) = tokio::sync::oneshot::channel();
        {
            let sock = sock.clone();
            tokio::spawn(async move {
                let listener = tokio::net::UnixListener::bind(&sock).unwrap();
                let (mut first, _) = listener.accept().await.unwrap();
                shake(&mut first).await;
                let call: CborValue = frame::read_frame(&mut first).await.unwrap();
                let _ = called_tx.send(call);

                let (mut second, _) = listener.accept().await.unwrap();
                shake(&mut second).await;
                let cancel: CborValue = frame::read_frame(&mut second).await.unwrap();
                let _ = cancel_tx.send(cancel);
                // Hold both open: an EOF would turn a missing cancel into
                // a framing error, which is a different failure wearing
                // the same colour.
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }

        let control = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };

        let (server_side, client_side) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            if let Ok(running) = ShimServer::new(Arc::new(control)).serve(server_side).await {
                let _ = running.waiting().await;
            }
        });

        let (rx, mut tx) = tokio::io::split(client_side);
        let mut rx = BufReader::new(rx);
        let mut line = String::new();
        let send = |v: serde_json::Value| {
            let mut s = v.to_string();
            s.push('\n');
            s
        };

        // ---- initialize, which is what makes a `Peer` exist at all.
        tx.write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "ct-probe", "version": "0.0.0" }
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), rx.read_line(&mut line))
            .await
            .expect("the shim never answered `initialize`")
            .unwrap();
        assert!(line.contains("\"result\""), "initialize failed: {line}");
        tx.write_all(
            send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).as_bytes(),
        )
        .await
        .unwrap();

        // ---- a tool call the stand-in daemon will never answer.
        tx.write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "request_secret_input",
                    "arguments": { "session": "sess_abc", "prompt_text": "a credential" }
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();

        // The call is really outstanding before the cancel, so the
        // ordering under test is the real one.
        tokio::time::timeout(std::time::Duration::from_secs(10), called_rx)
            .await
            .expect("the tool call never reached the stand-in daemon")
            .expect("the call channel");

        // ---- and the cancellation, exactly as an agent sends it.
        tx.write_all(
            send(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 1, "reason": "the user interrupted" }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();

        let cancel = tokio::time::timeout(std::time::Duration::from_secs(10), cancel_rx)
            .await
            .expect(
                "no `holdfast/cancel` reached the daemon: `call_tool` did not read the \
                 cancellation rmcp handed it",
            )
            .expect("the cancel channel");
        assert_eq!(
            field(&cancel, "method").as_text(),
            Some(crate::protocol::method::METHOD_CANCEL),
            "the second connection carried something other than a cancel"
        );

        server.abort();
    }

    /// The handshake half of a stand-in daemon, which every connection
    /// pays and no assertion here is about.
    async fn shake(stream: &mut tokio::net::UnixStream) {
        let hs: Request = frame::read_frame(stream).await.unwrap();
        let data = HandshakeData {
            protocol_major: handshake::PROTOCOL_MAJOR,
            protocol_minor: handshake::PROTOCOL_MINOR,
            daemon_version: "99.0.0".into(),
            build: "stand-in".into(),
            accepted: true,
            reject_reason: None,
        };
        let resp = Response::ok(hs.id, &data, "handshake accepted").unwrap();
        frame::write_frame(stream, &resp).await.unwrap();
    }

    fn stand_in_daemon(
        sock: PathBuf,
        reply: CborValue,
    ) -> tokio::sync::oneshot::Receiver<CborValue> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&sock).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            // The handshake is Task 4's contract and is already pinned
            // on the wire by `tests/control_protocol.rs`; here it is
            // just the price of admission, so it goes through the typed
            // helpers.
            let hs: Request = frame::read_frame(&mut stream).await.unwrap();
            let data = HandshakeData {
                protocol_major: handshake::PROTOCOL_MAJOR,
                protocol_minor: handshake::PROTOCOL_MINOR,
                daemon_version: "99.0.0".into(),
                build: "stand-in".into(),
                accepted: true,
                reject_reason: None,
            };
            let resp = Response::ok(hs.id, &data, "handshake accepted").unwrap();
            frame::write_frame(&mut stream, &resp).await.unwrap();

            // Everything after this point is raw.
            let req: CborValue = frame::read_frame(&mut stream).await.unwrap();
            let id = field(&req, "id")
                .as_integer()
                .expect("§7.4's id is an integer");
            let id = u64::try_from(id).expect("a request id fits u64");

            let mut entries = vec![(CborValue::Text("id".into()), CborValue::Integer(id.into()))];
            let CborValue::Map(rest) = reply else {
                panic!("the reply template is a map")
            };
            entries.extend(rest);
            frame::write_frame(&mut stream, &CborValue::Map(entries))
                .await
                .unwrap();

            let _ = tx.send(req);
            // Hold the connection open: an EOF here would race the
            // shim's read and turn a wire mismatch into a framing error,
            // which is a different failure wearing the same colour.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        rx
    }

    /// **The wire test.** Everything else in this file is built from the
    /// same types on both sides and is therefore blind to a rename; this
    /// one hand-builds the daemon's reply from literal CBOR keys and
    /// reads the shim's request back as a literal CBOR map.
    ///
    /// §7.4.1, verbatim: the shim *"forwards each MCP `tools/call` to the
    /// daemon as a control-protocol request with method
    /// `tool/<tool_name>` and `params` set to the MCP `arguments`"*, and
    /// *"the daemon's `data` field corresponds to the MCP
    /// `structuredContent.data`; `status` and `details` likewise map."*
    /// Both halves are asserted here against literals.
    #[tokio::test]
    async fn the_shim_puts_7_4_1s_own_field_names_on_the_wire() {
        let dir = scratch_dir("wire");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        // The daemon's answer, built from §7.4's four literal keys. A
        // `Response::ok(..)` here would agree with the shim by
        // construction and prove nothing about either.
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("ok".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("output".into()),
                        CborValue::Text("hello\n".into()),
                    ),
                    (
                        CborValue::Text("cursor".into()),
                        CborValue::Integer(6u64.into()),
                    ),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("read 6 bytes".into()),
            ),
        ]);
        let captured = stand_in_daemon(sock.clone(), reply);

        // Give the listener a moment to bind before connecting.
        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let mut arguments = serde_json::Map::new();
        arguments.insert("session".into(), json!("sess_abc"));
        arguments.insert("since_cursor".into(), json!(0));
        let result = shim
            .forward("read_output", Some(arguments), std::future::pending())
            .await
            .expect("the stand-in answered ok");

        // --- the request direction ---
        let req = captured.await.expect("the stand-in captured a request");

        // The method is the literal `tool/` prefix plus the tool name.
        // A shim that sent `tools/read_output`, or `read_output` bare,
        // or `{"tool": "read_output"}` round-trips against itself and
        // is refused by the daemon's `req.tool_name()`.
        assert_eq!(
            field(&req, "method").as_text(),
            Some("tool/read_output"),
            "§7.4.1: the method is `tool/<tool_name>`"
        );

        // `params` **is** the arguments map — not a wrapper carrying
        // them under `arguments`, which is the shape an MCP-shaped
        // forward would produce and which no round-trip test can see.
        let params = field(&req, "params");
        assert_eq!(
            field(params, "session").as_text(),
            Some("sess_abc"),
            "§7.4.1: `params` is set to the MCP `arguments`, verbatim"
        );
        assert_eq!(
            field(params, "since_cursor").as_integer(),
            Some(0u64.into()),
            "an argument that is not a string must survive the JSON→CBOR hop"
        );
        let CborValue::Map(param_entries) = params else {
            panic!("params is a map")
        };
        assert_eq!(
            param_entries.len(),
            2,
            "`params` must carry the arguments and nothing else; got {params:?}"
        );

        // --- the response direction ---
        // §7.4.1's three fields land on the envelope's three fields.
        // Reading `structured_content` as JSON is the right level here:
        // it is what the MCP client receives, and the assertion is that
        // the hand-built CBOR reached it intact.
        let body = result.structured_content.expect("§5.1's structured body");
        assert_eq!(
            body,
            json!({
                "status": "ok",
                "data": { "output": "hello\n", "cursor": 6 },
                "details": "read 6 bytes",
            }),
            "§7.4.1: data → structuredContent.data, status and details likewise"
        );
    }

    /// **GH #229: `start_session` carries the shim's own directory and
    /// environment, under the reserved key, on the wire.**
    ///
    /// The shim is the only process in the hybrid path that is the
    /// client's own; a daemon serving several clients cannot know which
    /// one's project a call belongs to unless the call says so. Read back
    /// as a literal CBOR map, for this file's usual reason: a round trip
    /// through `ClientLaunch` would agree with itself under any key.
    ///
    /// The value an MCP client put under the key is **overwritten**: the
    /// context is this process's to state, and a shim that passed an
    /// agent's through would let the agent name any directory as "where
    /// the client is" — harmless for a `command` session, which can name
    /// its own `cwd`, but the daemon should never have to reason about it.
    #[tokio::test]
    async fn start_session_carries_the_shims_own_directory_and_environment() {
        let dir = scratch_dir("client");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("ok".into()),
            ),
            (CborValue::Text("data".into()), CborValue::Map(vec![])),
            (
                CborValue::Text("details".into()),
                CborValue::Text("started".into()),
            ),
        ]);
        let captured = stand_in_daemon(sock.clone(), reply);
        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let mut arguments = serde_json::Map::new();
        arguments.insert("command".into(), json!("bash"));
        arguments.insert(CLIENT_PARAM.into(), json!({ "cwd": "/somebody/elses" }));
        shim.forward("start_session", Some(arguments), std::future::pending())
            .await
            .expect("the stand-in answered ok");
        let req = captured.await.expect("the stand-in captured a request");
        let params = field(&req, "params");
        assert_eq!(
            field(params, "command").as_text(),
            Some("bash"),
            "the caller's own arguments still travel verbatim"
        );

        let context = field(params, CLIENT_PARAM);
        let here = std::env::current_dir().unwrap();
        assert_eq!(
            field(context, "cwd").as_text(),
            Some(here.to_str().unwrap()),
            "the context must name this process's directory, not the one the MCP \
             client wrote under the key"
        );
        // One variable every test process has, compared by value: a shim
        // that sent an empty map, or the daemon's, would fail here.
        let path = std::env::var("PATH").expect("a test process has PATH");
        assert_eq!(
            field(field(context, "env"), "PATH").as_text(),
            Some(path.as_str()),
            "the context must carry this process's environment"
        );
    }

    /// **GH #231: which lost calls may be re-sent.** Only the two that
    /// provably never reached a daemon — a dial that failed, and a write
    /// into a connection already closed — because a `send_input` or a
    /// `start_session` re-sent after the old daemon ran it runs twice.
    /// Each refusal below is a failure that *can* follow a dispatched
    /// call; a classifier that answered `true` to any of them would re-send
    /// it.
    #[test]
    fn only_a_call_that_never_reached_a_daemon_is_re_sent() {
        let io = |kind| ClientError::Frame(FrameError::Io(std::io::Error::from(kind)));
        assert!(never_reached_a_daemon(&ClientError::Connect {
            path: "control.sock".into(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        }));
        assert!(never_reached_a_daemon(&io(std::io::ErrorKind::BrokenPipe)));
        for maybe_ran in [
            ClientError::Frame(FrameError::Eof),
            io(std::io::ErrorKind::ConnectionReset),
            io(std::io::ErrorKind::TimedOut),
            ClientError::IdMismatch {
                expected: 1,
                got: 2,
            },
        ] {
            assert!(!never_reached_a_daemon(&maybe_ran), "{maybe_ran:?}");
        }
    }

    /// The other classifier: which handshake failures are a dead daemon's
    /// listener still closing, and so worth one more `ensure_daemon`. A
    /// timeout is not — that is a daemon that is there and not answering,
    /// and GH #15 is why nothing spawns over it.
    #[test]
    fn a_reset_handshake_is_a_closing_listener_and_a_silent_one_is_not() {
        let io = |kind| ClientError::Frame(FrameError::Io(std::io::Error::from(kind)));
        assert!(a_closing_listener(&ClientError::Frame(FrameError::Eof)));
        assert!(a_closing_listener(&io(std::io::ErrorKind::ConnectionReset)));
        assert!(!a_closing_listener(&io(std::io::ErrorKind::TimedOut)));
        assert!(!a_closing_listener(&ClientError::Refused("too old".into())));
        assert!(!a_closing_listener(&ClientError::VersionMismatch {
            ours: 1,
            theirs: 2
        }));
    }

    /// The negative for the mapping above: a control-protocol *error*
    /// response is not an envelope, and must not be rebuilt as one.
    ///
    /// Hand-built from §7.4.1's literal error shape for the same reason
    /// — `Response::error(..)` would agree with `control_error()` by
    /// construction.
    #[tokio::test]
    async fn a_daemon_side_bad_params_is_re_raised_as_an_mcp_protocol_error() {
        let dir = scratch_dir("err");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("bad_params".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text("missing field `session`".into()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("missing field `session`".into()),
            ),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let err = shim
            .forward("read_output", None, std::future::pending())
            .await
            .expect_err("`bad_params` is a protocol fault, not a tool status");
        // §5.1 routes a schema violation to the protocol channel. The
        // code, not just the message: a shim that flattened every
        // daemon-side fault into `internal_error` would still carry the
        // text and would tell the agent it hit a server bug rather than
        // a fixable argument.
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "daemon `bad_params` re-raises as JSON-RPC invalid_params"
        );
        assert!(
            err.message.contains("missing field `session`"),
            "the daemon's own message must reach the agent: {}",
            err.message
        );
    }

    /// An internal fault must not read to the agent as its own bad
    /// input.
    ///
    /// The daemon flattens every `Err(ErrorData)` a tool raises onto
    /// §18.3's `bad_params`, because §18.3 has no JSON-RPC codes. While
    /// the rebuild read `code` alone, that flattening was lossy in the
    /// one direction that matters — `internal_error` came back as
    /// `invalid_params` — and the *same* fault under `--no-daemon` stayed
    /// `internal_error`, so the two transports disagreed about whose
    /// fault it was.
    ///
    /// Three distinct codes, not one: a rebuild that hardcoded
    /// `INVALID_PARAMS` passes any single-code row.
    #[test]
    fn rpc_code_decides_the_rebuilt_error_when_the_daemon_sent_one() {
        let with_rpc = |rpc: i32| method::ControlError {
            // Always `bad_params`, because that is what the daemon must
            // send for **every** tool fault. If the §18.3 code decided,
            // these three would be indistinguishable — which was the bug.
            code: method::ErrorCode::BadParams.as_str().into(),
            message: "openpty failed".into(),
            retriable: false,
            rpc_code: Some(rpc),
        };
        for code in [-32603, -32602, -32002] {
            let e = rebuild_error(with_rpc(code));
            assert_eq!(e.code, rmcp::model::ErrorCode(code));
            assert_eq!(e.message, "openpty failed");
        }
    }

    /// The fallback, which is what a daemon one minor behind sends: no
    /// `rpc_code`, and §18.3's code is all there is. §7.4.1 permits that
    /// skew explicitly, so this arm is a live path and not a leftover.
    #[test]
    fn without_an_rpc_code_the_18_3_code_still_decides() {
        let bare = |code: method::ErrorCode| method::ControlError {
            code: code.as_str().into(),
            message: "m".into(),
            retriable: false,
            rpc_code: None,
        };
        // §5.5.2's validation faults are `-32602` on the MCP wire, which
        // is why `bad_params` maps here and not to "internal error".
        assert_eq!(
            rebuild_error(bare(method::ErrorCode::BadParams)).code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
        // Everything else is a server fault, and says which §18.3 code
        // it was — the agent cannot act on it, but an operator can.
        let e = rebuild_error(bare(method::ErrorCode::ProtocolViolation));
        assert_eq!(e.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(
            e.message.contains("protocol_violation"),
            "the §18.3 code must survive into the message: {}",
            e.message
        );
    }

    /// A tool the daemon does not have must read as "no such tool", not
    /// as a server fault.
    ///
    /// `list_tools` is answered from the shim's **own** process —
    /// `passthrough::tool_manifest()` is
    /// `HoldfastServer::tool_router().list_all()`, and §7.4.1 defines no
    /// method by which a manifest could be fetched — while §7.4.1
    /// explicitly permits shim/daemon minor skew. So a tool this build
    /// advertises and an older daemon lacks is reachable, and it comes
    /// back `unknown_method`.
    ///
    /// In-process the identical call is `invalid_params("tool not
    /// found")`, from rmcp's router, and `call_tool`'s own guard answers
    /// `invalid_params` for a name outside the manifest. Reporting it as
    /// `internal_error` told the agent to give up on a server bug where
    /// the truth is that the tool does not exist.
    ///
    /// The paired row is the one that keeps this honest: a §18.3 code
    /// that really *is* a server fault must still arrive as one, or the
    /// fix is just a second flattening in the other direction.
    ///
    /// The first half goes over the socket, because `forward` *calling*
    /// the right rebuild is a separate claim from the rebuild being
    /// right — the same split that made the resource path's decode
    /// worth driving end to end.
    #[tokio::test]
    async fn an_unknown_tool_is_the_agents_bad_argument_and_not_a_server_fault() {
        let dir = scratch_dir("notool");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        // What a daemon one minor behind answers for `tool/<name>` when
        // it has no such tool: §18.3's `unknown_method`, and no
        // `rpc_code`, because no handler ever ran to raise one.
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("unknown_method".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text("no tool inspect_screen".into()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("no tool inspect_screen".into()),
            ),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));
        let err = shim
            .forward("inspect_screen", None, std::future::pending())
            .await
            .expect_err("a tool the daemon lacks is not an outcome");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "an unknown tool is `-32602` in-process; the daemon transport must agree"
        );

        let bare = |code: method::ErrorCode| method::ControlError {
            code: code.as_str().into(),
            message: "no tool inspect_screen".into(),
            retriable: false,
            rpc_code: None,
        };
        assert_eq!(
            rebuild_tool_error(bare(method::ErrorCode::ProtocolViolation)).code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "a real server fault must not be relabelled the agent's bad argument"
        );
        // And an `rpc_code` still wins: this arm is a guess made only in
        // its absence.
        assert_eq!(
            rebuild_tool_error(method::ControlError {
                code: method::ErrorCode::UnknownMethod.as_str().into(),
                message: "m".into(),
                retriable: false,
                rpc_code: Some(-32603),
            })
            .code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
        );
    }

    /// §5.5.2's structured `data.code` must survive the hybrid hop.
    ///
    /// The in-process transport answers a bad query parameter with
    /// `invalid_params(prose, Some({"code": "invalid_enum", …}))`, and an
    /// agent branches on `data.code` to know whether to fix a name, a
    /// value or a range. `ControlError` has nowhere to carry that object,
    /// so the daemon JSON-encodes `{message, data}` into the error
    /// *message* — and nothing decoded it: the agent received the raw
    /// blob as its prose and `data: null` where the four codes belong.
    ///
    /// **Driven through `forward_resource`, not through the free
    /// function.** The decode existing and the resource path *calling*
    /// it are two different claims, and only the second is the fix.
    #[tokio::test]
    async fn a_resource_fault_keeps_the_structured_code_5_5_2_requires() {
        let dir = scratch_dir("resdata");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        // The daemon's encoding, hand-built from §5.5.2's literal shape
        // rather than by calling the encoder — a round trip through one
        // expression would agree with itself whatever that shape is.
        let envelope = json!({
            "message": "ansi=purple is not one of strip, raw",
            "data": {
                "code": "invalid_enum",
                "param": "ansi",
                "value": "purple",
                "allowed": ["strip", "raw"],
            },
        })
        .to_string();
        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("bad_params".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text(envelope.clone()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                    (
                        CborValue::Text("rpc_code".into()),
                        CborValue::Integer((-32602i64).into()),
                    ),
                ]),
            ),
            (CborValue::Text("details".into()), CborValue::Text(envelope)),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let err = shim
            .forward_resource(
                method::METHOD_RESOURCE_READ,
                json!({ "uri": "holdfast://session/s/buffer?ansi=purple" }),
            )
            .await
            .expect_err("§5.5.2 routes a bad parameter to the protocol channel");

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(
            err.data.as_ref().map(|d| &d["code"]),
            Some(&json!("invalid_enum")),
            "§5.5.2's four codes are structured `data`, not prose; got data {:?}",
            err.data
        );
        // The other half of the same defect: the prose field held the
        // JSON blob. An agent shows `message` to a human.
        assert_eq!(
            err.message.as_ref(),
            "ansi=purple is not one of strip, raw",
            "the message field must carry prose, not the envelope it arrived in"
        );
    }

    /// The decode is deliberately narrow, and these are the rows that
    /// say so. A control error whose message is ordinary prose — every
    /// producer that is not `dispatch_resource` — must pass through
    /// untouched, or the shim starts inventing `data` from any message
    /// that happens to parse.
    #[test]
    fn only_the_daemons_own_two_key_envelope_is_unwrapped() {
        assert_eq!(
            decode_resource_envelope("no session sess_x"),
            None,
            "prose is not an envelope"
        );
        assert_eq!(
            decode_resource_envelope(r#"{"message":"m","data":null,"extra":1}"#),
            None,
            "a third key means this came from somewhere else"
        );
        assert_eq!(
            decode_resource_envelope(r#"{"code":"invalid_enum","param":"ansi"}"#),
            None,
            "§5.5.2's `data` object on its own is not the envelope"
        );
        // `data: null` is what the daemon writes for an `ErrorData` that
        // carried none — `resource_not_found`, for one. It must become
        // an absent field, not a literal `"data": null` on the MCP wire
        // where the in-process transport omits it.
        assert_eq!(
            decode_resource_envelope(r#"{"message":"no session sess_x","data":null}"#),
            Some(("no session sess_x".to_string(), None))
        );
    }

    /// **The wire test for the new field.** Everything above decodes
    /// through the same derived impl the daemon encodes with, so a
    /// rename of `rpc_code` — or a daemon that spelt it `rpcCode` — is
    /// invisible to all of it and fatal in production. Only a literal
    /// CBOR key can see it.
    #[tokio::test]
    async fn the_shim_reads_rpc_code_under_its_own_wire_name() {
        let dir = scratch_dir("rpccode");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        let reply = CborValue::Map(vec![
            (
                CborValue::Text("status".into()),
                CborValue::Text("error".into()),
            ),
            (
                CborValue::Text("data".into()),
                CborValue::Map(vec![
                    // The §18.3 code the daemon is obliged to send for
                    // *every* tool fault. Read alone it says
                    // "invalid_params", which is the wrong answer here.
                    (
                        CborValue::Text("code".into()),
                        CborValue::Text("bad_params".into()),
                    ),
                    (
                        CborValue::Text("message".into()),
                        CborValue::Text("write task failed".into()),
                    ),
                    (CborValue::Text("retriable".into()), CborValue::Bool(false)),
                    (
                        CborValue::Text("rpc_code".into()),
                        CborValue::Integer((-32603i64).into()),
                    ),
                ]),
            ),
            (
                CborValue::Text("details".into()),
                CborValue::Text("write task failed".into()),
            ),
        ]);
        let _captured = stand_in_daemon(sock.clone(), reply);

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        let shim = ShimServer::new(Arc::new(client));

        let err = shim
            .forward("send_input", None, std::future::pending())
            .await
            .expect_err("a tool protocol fault is not a tool status");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "a Holdfast bug must reach the agent as one, not as its own bad argument"
        );
        assert!(err.message.contains("write task failed"), "{}", err.message);
    }
}
