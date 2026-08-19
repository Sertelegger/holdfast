//! The client half of the control protocol: connect, handshake, call.
//!
//! Used by the MCP shim, by every CLI subcommand that talks to a running
//! daemon, and (from 0.0.10) by the web-UI bridge.

use super::frame::{self, FrameError};
use super::handshake::{self, ClientKind, HandshakeData, HandshakeParams};
use super::method::{self, CborValue, ErrorCode, Request, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the daemon at {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("control protocol framing: {0}")]
    Frame(#[from] FrameError),
    #[error("daemon refused the connection: {0}")]
    Refused(String),
    #[error(
        "control protocol major mismatch: this build speaks {ours}, the daemon speaks {theirs}"
    )]
    VersionMismatch { ours: u32, theirs: u32 },
    #[error("daemon replied to request {got}, expected {expected}")]
    IdMismatch { expected: u64, got: u64 },
    #[error("{method} failed: [{code}] {message}")]
    Method {
        method: String,
        code: String,
        message: String,
        retriable: bool,
    },
}

/// How many idle connections to keep parked between calls.
///
/// Connections are opened on demand and returned here when their call
/// finishes; a burst of concurrency that leaves more than this many idle
/// closes the surplus rather than hoarding descriptors for a peak that
/// may not recur. The sequential case — every CLI subcommand, and an
/// agent issuing one tool call at a time — never exceeds the one
/// connection [`ControlClient::connect`] already opened.
const MAX_IDLE_CONNECTIONS: usize = 8;

/// A set of connections to `control.sock`, each with the handshake
/// already done, one of which carries each call.
///
/// **One connection per *in-flight* call, not per client**, and that is
/// the whole of the concurrency model. v0.1.0 has no streaming (§7.4.1
/// reserves the frames but does not use them) and the daemon serves one
/// request at a time per connection
/// ([`daemon::server::handle_connection`]), so a call owns its
/// connection for the round trip. Response correlation stays trivially
/// correct — a reply arrives on the socket its request went out on, and
/// `id` is re-checked besides.
///
/// [`daemon::server::handle_connection`]: crate::daemon::server
///
/// ## Why this is not one connection under a mutex
///
/// It was, and holding that mutex across **both** the write and the read
/// made the whole MCP tool surface serialise behind whichever call was
/// outstanding. The shim holds one `Arc<ControlClient>` for the process
/// (`clasp mcp`), so a `wait_for_pattern` — 30 s by default,
/// [3600 s at the cap](crate::mcp::tools::WAIT_FOR_PATTERN_MAX_TIMEOUT_SECS)
/// — blocked `interrupt`, `terminate`, `read_output`, `status` and
/// `list_sessions`, **on every other session**, for its entire duration.
///
/// That is not a throughput note. The agent's documented escape from a
/// wait that will not finish is `interrupt`, and `interrupt` was
/// precisely the call it could not issue. Under `--no-daemon` the same
/// tools dispatch concurrently — `rmcp` spawns a task per request — so
/// the two transports disagreed about whether the escape hatch existed,
/// on the transport that is the default.
///
/// ## The bound, and why it is on *idle* rather than on in-flight
///
/// Capping in-flight calls would re-introduce the defect one level
/// deeper: with a cap of N, the N+1st call blocks, and the N+1st call is
/// the `interrupt`. So concurrency is bounded by the caller — which for
/// the shim is `rmcp`'s in-flight request count, exactly the bound the
/// in-process transport has — and what is capped is how many idle
/// connections are *kept*. The cost of a burst is one file descriptor
/// per overlapping call, on a uid-gated local socket driven by a trusted
/// agent; a descriptor limit reached here surfaces as
/// [`ClientError::Connect`] on one call rather than as a hang.
#[derive(Debug)]
pub struct ControlClient {
    /// Connections not currently carrying a call.
    idle: Mutex<Vec<UnixStream>>,
    /// How to open another one. `None` for a client built by
    /// [`handshake_on`](ControlClient::handshake_on) on a stream someone
    /// else connected, which cannot be reopened.
    dial: Option<Dial>,
    next_id: AtomicU64,
    daemon: HandshakeData,
}

/// What [`ControlClient`] needs to open a further connection.
#[derive(Debug)]
struct Dial {
    path: PathBuf,
    kind: ClientKind,
}

impl ControlClient {
    /// Connect and complete the `clasp/handshake` exchange.
    pub async fn connect(path: &Path, kind: ClientKind) -> Result<Self, ClientError> {
        let mut stream = dial(path).await?;
        let daemon = handshake_exchange(&mut stream, kind).await?;
        Ok(Self {
            idle: Mutex::new(vec![stream]),
            dial: Some(Dial {
                path: path.to_path_buf(),
                kind,
            }),
            next_id: AtomicU64::new(1),
            daemon,
        })
    }

    /// Handshake over an already-connected stream. Split out so tests can
    /// drive a stand-in daemon over a socket pair.
    ///
    /// A client built this way holds exactly the one connection it was
    /// given: nothing here names a path to reopen, so a caller that
    /// wants concurrency wants [`connect`](ControlClient::connect).
    pub async fn handshake_on(
        mut stream: UnixStream,
        kind: ClientKind,
    ) -> Result<Self, ClientError> {
        let daemon = handshake_exchange(&mut stream, kind).await?;
        Ok(Self {
            idle: Mutex::new(vec![stream]),
            dial: None,
            next_id: AtomicU64::new(1),
            daemon,
        })
    }

    /// What the daemon told us about itself during the handshake.
    ///
    /// The first connection's answer. Every later one handshakes against
    /// the same daemon and is refused outright if it disagrees, so there
    /// is no reading of this that could go stale without the call that
    /// opened the connection having already failed.
    pub fn daemon_info(&self) -> &HandshakeData {
        &self.daemon
    }

    /// Send a request, wait for its response, return it verbatim —
    /// including error responses, which the caller may want to inspect.
    pub async fn call_raw(&self, method: &str, params: CborValue) -> Result<Response, ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = Request {
            id,
            method: method.to_string(),
            params,
        };

        // The connection is checked out for the round trip and nothing
        // else is held — no lock spans the `await`s below, which is the
        // entire point of the change.
        let mut stream = self.checkout().await?;
        let resp = exchange(&mut stream, &req, id).await;
        if reusable(&resp) {
            self.checkin(stream).await;
        }
        resp
    }

    /// A connection ready to carry one call: a parked one if there is
    /// one, otherwise a new one, handshake included.
    async fn checkout(&self) -> Result<UnixStream, ClientError> {
        // Bound the guard to this statement. Holding it across the dial
        // below would serialise exactly what this function exists to
        // stop serialising.
        let parked = self.idle.lock().await.pop();
        if let Some(stream) = parked {
            return Ok(stream);
        }
        let Some(d) = &self.dial else {
            return Err(ClientError::Connect {
                path: "the caller-supplied stream this client was built on".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "that connection is gone and this client cannot open another",
                ),
            });
        };
        let mut stream = dial(&d.path).await?;
        // Every connection handshakes for itself. A daemon replaced
        // mid-session by one from another protocol major refuses here,
        // on the call that opened the connection, rather than being
        // papered over by the first connection's verdict.
        handshake_exchange(&mut stream, d.kind).await?;
        Ok(stream)
    }

    /// Park a connection for the next call, or let it close.
    async fn checkin(&self, stream: UnixStream) {
        let mut idle = self.idle.lock().await;
        if idle.len() < MAX_IDLE_CONNECTIONS {
            idle.push(stream);
        }
    }

    /// Typed call: serialise params, deserialise data, and turn an error
    /// response into a `ClientError::Method`.
    pub async fn call<P, D>(&self, method: &str, params: &P) -> Result<D, ClientError>
    where
        P: Serialize,
        D: DeserializeOwned,
    {
        let resp = self.call_raw(method, method::to_cbor(params)?).await?;
        if let Some(e) = resp.control_error() {
            return Err(ClientError::Method {
                method: method.to_string(),
                code: e.code,
                message: e.message,
                retriable: e.retriable,
            });
        }
        Ok(resp.data_as()?)
    }
}

async fn dial(path: &Path) -> Result<UnixStream, ClientError> {
    UnixStream::connect(path)
        .await
        .map_err(|source| ClientError::Connect {
            path: path.display().to_string(),
            source,
        })
}

/// One request/response round trip on a connection nobody else holds.
async fn exchange(
    stream: &mut UnixStream,
    req: &Request,
    id: u64,
) -> Result<Response, ClientError> {
    frame::write_frame(stream, req).await?;
    let resp: Response = frame::read_frame(stream).await?;
    // Belt and braces now that correlation is also structural: a reply
    // arrives on the socket its request left on, and it must still carry
    // the id that request had.
    if resp.id != id {
        return Err(ClientError::IdMismatch {
            expected: id,
            got: resp.id,
        });
    }
    Ok(resp)
}

/// Whether the connection that produced this outcome can carry another
/// call.
///
/// Two ways it cannot. A transport fault leaves the stream at an unknown
/// offset — half a frame may be written, or a length prefix read without
/// its body — and re-using it would desynchronise every later call on
/// it. And §18.3's `closes_connection()` codes are the ones the daemon
/// answers and then hangs up on (`handle_connection`), so parking that
/// stream would hand a later call a socket already at EOF.
///
/// **The unknown code fails closed, and here that is not theoretical.**
/// This is the one side of the protocol that parses a code it did not
/// write: §7.4.1 permits shim/daemon *minor* skew explicitly, so a
/// daemon one minor ahead can answer a §18.3 row this build has never
/// heard of, and [`ErrorCode::from_wire`] rightly refuses to guess at
/// it. Reading that `None` as "not closing" parks a socket the daemon
/// has already hung up on, and the cost lands on the *next* call, which
/// meets an EOF it has no explanation for. Not parking a connection that
/// was in fact still good costs one reconnect.
///
/// The remaining case is `daemon/stop`, which the daemon answers `ok`
/// and then closes. It is deliberately not special-cased here: teaching
/// this function one method's semantics would put the daemon's shutdown
/// rule in two places, and the only caller that issues it —
/// `clasp daemon stop` — drops the client immediately afterwards.
fn reusable(outcome: &Result<Response, ClientError>) -> bool {
    match outcome {
        Err(_) => false,
        Ok(resp) => match resp.control_error() {
            None => true,
            Some(e) => ErrorCode::from_wire(&e.code).is_some_and(|code| !code.closes_connection()),
        },
    }
}

/// The `clasp/handshake` exchange, and both of §18.3a's gates.
///
/// A free function because **every** connection performs it, not just
/// the first: it is what a pooled connection must do before it may carry
/// a call, and having it inside `handshake_on` meant the only way to
/// perform it was to build a whole client around it.
async fn handshake_exchange(
    stream: &mut UnixStream,
    kind: ClientKind,
) -> Result<HandshakeData, ClientError> {
    let params = HandshakeParams::current(kind);
    let req = Request::new(0, method::METHOD_HANDSHAKE, &params)?;
    frame::write_frame(stream, &req).await?;
    let resp: Response = frame::read_frame(stream).await?;
    if resp.id != 0 {
        return Err(ClientError::IdMismatch {
            expected: 0,
            got: resp.id,
        });
    }
    if let Some(e) = resp.control_error() {
        return Err(ClientError::Refused(format!("[{}] {}", e.code, e.message)));
    }
    let daemon: HandshakeData = resp.data_as()?;

    // Two independent gates (§18.3a). `accepted` is the daemon's own
    // verdict; the major comparison is ours. A daemon from a different
    // major that (wrongly) accepted us is still refused here, so a
    // protocol break can never be papered over by one side being
    // lenient.
    //
    // Both gates are exercised **separately** over a socket, because a
    // suite that only ever meets a daemon failing both cannot tell one
    // gate from two:
    // `the_client_refuses_a_daemon_that_rejects_it_on_a_matching_major`
    // reaches only the first, and
    // `the_client_refuses_a_daemon_that_advertises_another_major`
    // only the second.
    if !daemon.accepted {
        return Err(ClientError::Refused(
            daemon
                .reject_reason
                .unwrap_or_else(|| "no reason given".into()),
        ));
    }
    if daemon.protocol_major != handshake::PROTOCOL_MAJOR {
        return Err(ClientError::VersionMismatch {
            ours: handshake::PROTOCOL_MAJOR,
            theirs: daemon.protocol_major,
        });
    }
    Ok(daemon)
}

impl ClientError {
    /// Whether a retry could plausibly succeed (§18.3's Retriable
    /// column, plus "the daemon is not there yet").
    pub fn retriable(&self) -> bool {
        match self {
            Self::Connect { .. } => true,
            Self::Method { retriable, .. } => *retriable,
            _ => false,
        }
    }

    /// Whether the daemon closed the connection when it answered this
    /// (§18.3's closing column, via [`ErrorCode::closes_connection`]).
    ///
    /// The caller-facing half of the rule [`reusable`] enforces inside
    /// this module. `ClientError::Method` carries `code` as a raw
    /// `String`, so without this a caller told `protocol_violation` has
    /// no way to distinguish "that request was wrong" from "that
    /// connection is over" — which is exactly the guessing
    /// [`ErrorCode::from_wire`]'s doc comment says a client must not be
    /// left to do.
    ///
    /// **Fails closed on an unknown code, for the same reason
    /// [`reusable`] does**: §7.4.1 permits minor skew, so a code this
    /// build does not know may well be a closing one, and answering
    /// `false` there would tell a caller a dead connection is live.
    pub fn closes_connection(&self) -> bool {
        match self {
            Self::Method { code, .. } => {
                ErrorCode::from_wire(code).is_none_or(ErrorCode::closes_connection)
            }
            _ => false,
        }
    }

    /// True when the connection failed on protocol-version grounds —
    /// the case §23.3 says must never silently degrade. Covers both the
    /// daemon's §18.3a refusal tokens and our own local re-check.
    pub fn is_version_mismatch(&self) -> bool {
        match self {
            Self::VersionMismatch { .. } => true,
            Self::Refused(reason) => {
                reason.contains(handshake::REJECT_CLIENT_TOO_NEW)
                    || reason.contains(handshake::REJECT_CLIENT_TOO_OLD)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::method::CborValue;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    /// Everything this client does over a socket is tested in
    /// `tests/control_protocol.rs`, against a real daemon — a unit test
    /// there could only talk to a mock, which would test the mock. These
    /// two classifiers are the exception: they are pure functions over
    /// the error enum, and 0.0.5 has no reconnecting caller to exercise
    /// them, so without a test here they ship unasserted (see **Notes
    /// for the next milestone**: they are hooks 0.0.11's shim uses).
    ///
    /// The concurrency row at the bottom is the other exception, and for
    /// the opposite reason: what it asserts is a property of *this*
    /// type — that one call does not wait on another — and the only
    /// thing it needs from the far end is that a request go
    /// unanswered. A real daemon can supply that only by really waiting
    /// 30 s, and the arrival of the first request has to be observed
    /// exactly rather than slept for, or the row passes against the
    /// defect whenever the second call happens to reach the wire first.
    fn connect_error() -> ClientError {
        ClientError::Connect {
            path: "/tmp/nope/control.sock".into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        }
    }

    fn method_error(retriable: bool) -> ClientError {
        ClientError::Method {
            method: "daemon/status".into(),
            code: "daemon_shutting_down".into(),
            message: "stopping".into(),
            retriable,
        }
    }

    #[test]
    fn retriable_covers_a_missing_daemon_and_defers_to_the_wire_flag_otherwise() {
        // "The daemon is not there yet" is the auto-spawn case: a shim
        // that treated a refused connect as fatal could never wait for a
        // daemon it just started.
        assert!(connect_error().retriable());
        // §18.3's Retriable column is the daemon's answer, not ours. A
        // mutant that hardcoded either constant is caught by the pair.
        assert!(method_error(true).retriable());
        assert!(!method_error(false).retriable());
        // Framing, a foreign major and a mis-correlated reply are all
        // deterministic: retrying repeats them.
        assert!(!ClientError::Frame(FrameError::Eof).retriable());
        assert!(!ClientError::VersionMismatch {
            ours: handshake::PROTOCOL_MAJOR,
            theirs: handshake::PROTOCOL_MAJOR + 1,
        }
        .retriable());
        assert!(!ClientError::IdMismatch {
            expected: 1,
            got: 2
        }
        .retriable());
    }

    #[test]
    fn a_version_mismatch_is_recognised_through_either_peers_verdict() {
        // Our own re-check.
        assert!(ClientError::VersionMismatch {
            ours: handshake::PROTOCOL_MAJOR,
            theirs: handshake::PROTOCOL_MAJOR + 1,
        }
        .is_version_mismatch());

        // The daemon's, carried as §18.3a's token inside a sentence —
        // which is why this is `contains` and not equality.
        for token in [
            handshake::REJECT_CLIENT_TOO_NEW,
            handshake::REJECT_CLIENT_TOO_OLD,
        ] {
            let reason = format!("{token} — daemon speaks protocol 1.x; upgrade the client.");
            assert!(
                ClientError::Refused(reason).is_version_mismatch(),
                "{token} must be recognised inside the sentence the wire carries"
            );
        }

        // The negative that separates "a refusal" from "a version
        // refusal": 0.0.6 adds refusals with other causes, and a
        // classifier that answered `true` for every `Refused` would
        // report them all as protocol breaks.
        assert!(!ClientError::Refused("attach session is read-only".into()).is_version_mismatch());
        assert!(!connect_error().is_version_mismatch());
        assert!(!method_error(true).is_version_mismatch());
    }

    /// A `ControlError` payload this build cannot classify, on the wire
    /// as a `Response`. `Response::error` cannot build one — it takes an
    /// `ErrorCode` — which is exactly why this arm had no coverage.
    fn response_with_wire_code(code: &str) -> Response {
        let payload = crate::protocol::method::ControlError {
            code: code.into(),
            message: "m".into(),
            retriable: false,
            rpc_code: None,
        };
        Response {
            id: 1,
            status: "error".into(),
            data: method::to_cbor(&payload).unwrap(),
            details: "m".into(),
        }
    }

    /// The one place in the protocol where a code arrives that this
    /// build did not write, so the one place `from_wire`'s `None` is
    /// reachable in production.
    ///
    /// §7.4.1 permits shim/daemon **minor** skew explicitly, so a daemon
    /// one minor ahead can answer a §18.3 row this build has never heard
    /// of. Read as "not closing", that parks a socket the daemon has
    /// already hung up on and the next call meets an EOF with no
    /// explanation. Fail closed: the cost of being wrong the other way
    /// is one reconnect.
    #[test]
    fn a_connection_is_not_parked_after_a_code_this_build_cannot_classify() {
        // The positives, or a `reusable` that answered `false` to
        // everything would pass every closing case and open a fresh
        // connection per call.
        assert!(reusable(&Ok(Response::ok(1, &json!({}), "ok").unwrap())));
        for code in [
            ErrorCode::UnknownMethod,
            ErrorCode::BadParams,
            ErrorCode::LimitReached,
            ErrorCode::DaemonShuttingDown,
        ] {
            assert!(
                reusable(&Ok(Response::error(1, code, "m"))),
                "{} is a per-request fault; §18.3 keeps the connection",
                code.as_str()
            );
        }
        // §18.3's three closing rows, named rather than filtered through
        // `closes_connection()` — deriving the expectation from the
        // predicate under test would make this vacuous.
        for code in [
            ErrorCode::FrameTooLarge,
            ErrorCode::NoHandshake,
            ErrorCode::ProtocolViolation,
        ] {
            assert!(
                !reusable(&Ok(Response::error(1, code, "m"))),
                "{} means the daemon hung up",
                code.as_str()
            );
        }
        assert!(
            !reusable(&Ok(response_with_wire_code("a_code_from_the_future"))),
            "an unrecognised code must fail closed"
        );
        // A transport fault leaves the stream at an unknown offset.
        assert!(!reusable(&Err(ClientError::Frame(FrameError::Eof))));
    }

    /// The caller-facing half. `ClientError::Method` carries `code` as a
    /// raw `String`, so without a classifier a caller told
    /// `protocol_violation` cannot tell "that request was wrong" from
    /// "that connection is over" — the guessing `from_wire`'s doc
    /// comment says a client must never be left to do.
    #[test]
    fn a_method_error_says_whether_it_ended_the_connection() {
        let with = |code: &str| ClientError::Method {
            method: "daemon/status".into(),
            code: code.into(),
            message: "m".into(),
            retriable: false,
        };
        assert!(with("protocol_violation").closes_connection());
        assert!(with("frame_too_large").closes_connection());
        assert!(with("no_handshake").closes_connection());
        assert!(!with("bad_params").closes_connection());
        assert!(!with("unknown_method").closes_connection());
        assert!(!with("limit_reached").closes_connection());
        // `daemon_shutting_down` answers `false` deliberately: the daemon
        // does close that connection, but on its own schedule and not on
        // this code's account (§18.3).
        assert!(!with("daemon_shutting_down").closes_connection());
        assert!(
            with("a_code_from_the_future").closes_connection(),
            "fail closed on a code from a newer daemon"
        );
        // Not every error is a method error, and the classifier must not
        // claim a failed connect ended a connection that never existed.
        assert!(!connect_error().closes_connection());
        assert!(!ClientError::Frame(FrameError::Eof).closes_connection());
    }

    // ------------------------------------- one call per connection (C-3)

    /// A `/tmp` path short enough for `sockaddr_un.sun_path`.
    fn scratch_dir(tag: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        PathBuf::from(format!("/tmp/clasp-t-client-{tag}-{}", &unique[..8]))
    }

    struct Scoped(PathBuf);
    impl Drop for Scoped {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn no_params() -> CborValue {
        CborValue::Map(Vec::new())
    }

    /// Answer `clasp/handshake` as an accepting daemon of this build.
    async fn accept_handshake(stream: &mut UnixStream) {
        let req: Request = frame::read_frame(stream).await.expect("a handshake first");
        let data = HandshakeData {
            protocol_major: handshake::PROTOCOL_MAJOR,
            protocol_minor: handshake::PROTOCOL_MINOR,
            daemon_version: "stand-in".into(),
            build: "stand-in".into(),
            accepted: true,
            reject_reason: None,
        };
        let resp = Response::ok(req.id, &data, "handshake accepted").unwrap();
        frame::write_frame(stream, &resp).await.unwrap();
    }

    /// **Imp C-3.** A call must not wait on another call outstanding on
    /// the same client.
    ///
    /// The shim holds one `Arc<ControlClient>` for the whole process
    /// (`clasp mcp`), so while `call_raw` held one mutex across both the
    /// write and the read, a `wait_for_pattern` — 30 s by default, 3600 s
    /// at the cap — blocked `interrupt`, `terminate`, `read_output`,
    /// `status` and `list_sessions`, **on every other session**, for its
    /// whole duration. The agent's documented escape from a wait that
    /// will not finish is `interrupt`, and `interrupt` was exactly the
    /// call it could not issue. Under `--no-daemon` the same tools
    /// dispatch concurrently, so the two transports disagreed about
    /// whether the escape hatch existed.
    ///
    /// **The premise is observed, not slept for.** `started_rx` fires
    /// only once the stand-in has read the first request off the wire, so
    /// the first call is provably in flight before the second is issued.
    /// Without that, a second call that happened to reach the mutex first
    /// would pass against the very defect this row exists to catch —
    /// `tokio::sync::Mutex::lock` on an uncontended mutex need not yield.
    ///
    /// **The timeout is a red test, not a hang.** Every failure here is
    /// something that does not return, and there is no `nextest.toml` in
    /// this repo to turn an unbounded wait into anything but a hung CI
    /// job — so the elapsed arm is `expect`ed, never matched as success.
    #[tokio::test]
    async fn a_call_proceeds_while_another_is_outstanding_on_the_same_client() {
        let dir = scratch_dir("concurrent");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let listen_at = sock.clone();
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&listen_at).unwrap();

            // The first connection takes one request and never answers
            // it. `held` stays in scope for the life of this task on
            // purpose: dropping it would EOF the client's read, the
            // "outstanding" call would complete, and the row would pass
            // against the defect.
            let (mut held, _) = listener.accept().await.unwrap();
            accept_handshake(&mut held).await;
            let _outstanding: Request = frame::read_frame(&mut held).await.unwrap();
            let _ = started_tx.send(());

            // Every later connection is answered immediately. There is
            // no second connection to accept unless the client opened
            // one, which is the whole question.
            loop {
                let (mut next, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    accept_handshake(&mut next).await;
                    while let Ok(req) = frame::read_frame::<_, Request>(&mut next).await {
                        let resp =
                            Response::ok(req.id, &json!({ "delivered": true }), "ok").unwrap();
                        if frame::write_frame(&mut next, &resp).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break Arc::new(c),
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };

        let outstanding = {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.call_raw("tool/wait_for_pattern", no_params()).await })
        };

        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("the stand-in never received the first request")
            .expect("the stand-in dropped the channel");

        let escape = tokio::time::timeout(
            Duration::from_secs(5),
            client.call_raw("tool/interrupt", no_params()),
        )
        .await
        .expect(
            "an outstanding wait blocked the interrupt that is the documented way \
             out of it — one client serialised the entire tool surface, on every \
             session, for the wait's whole duration",
        )
        .expect("the stand-in answered the second call");
        assert_eq!(escape.status, "ok");

        // The two really did overlap. Without this the row would also
        // pass against a client that simply queued the second call
        // behind the first and got lucky with the timings.
        assert!(
            !outstanding.is_finished(),
            "the first call completed, so the second never overtook anything"
        );
    }

    /// The pairing: a client that opened a *fresh* connection for every
    /// call would satisfy the row above and leak a descriptor per tool
    /// call for the life of the shim.
    ///
    /// Sequential calls must reuse the one connection `connect` already
    /// opened — which is also what keeps every CLI subcommand, and an
    /// agent working one tool call at a time, byte-identical to the
    /// single-connection client this replaced.
    #[tokio::test]
    async fn sequential_calls_reuse_one_connection() {
        let dir = scratch_dir("reuse");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");

        let (count_tx, count_rx) = std::sync::mpsc::channel();
        let listen_at = sock.clone();
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&listen_at).unwrap();
            loop {
                let (mut next, _) = listener.accept().await.unwrap();
                count_tx.send(()).unwrap();
                tokio::spawn(async move {
                    accept_handshake(&mut next).await;
                    while let Ok(req) = frame::read_frame::<_, Request>(&mut next).await {
                        let resp = Response::ok(req.id, &json!({}), "ok").unwrap();
                        if frame::write_frame(&mut next, &resp).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let client = loop {
            match ControlClient::connect(&sock, ClientKind::Shim).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        for _ in 0..5 {
            let resp = tokio::time::timeout(
                Duration::from_secs(5),
                client.call_raw("tool/status", no_params()),
            )
            .await
            .expect("a sequential call did not come back")
            .expect("the stand-in answered");
            assert_eq!(resp.status, "ok");
        }

        assert_eq!(
            count_rx.try_iter().count(),
            1,
            "five sequential calls opened more than the one connection `connect` \
             made: a connection per call leaks a descriptor per tool call"
        );
    }
}
