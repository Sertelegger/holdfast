//! The client half of the control protocol: connect, handshake, call.
//!
//! Used by the MCP shim, by every CLI subcommand that talks to a running
//! daemon, and (from 0.0.10) by the web-UI bridge.

use super::frame::{self, FrameError};
use super::handshake::{self, ClientKind, HandshakeData, HandshakeParams};
use super::method::{self, CborValue, Request, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
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

/// One connection to `control.sock`, with the handshake already done.
///
/// Calls are serialised by an internal mutex. v0.1.0 has no streaming
/// (§7.4.1 reserves the frames but does not use them), so a single
/// in-flight request per connection is the whole concurrency model —
/// and it makes response correlation trivially correct.
#[derive(Debug)]
pub struct ControlClient {
    stream: Mutex<UnixStream>,
    next_id: AtomicU64,
    daemon: HandshakeData,
}

impl ControlClient {
    /// Connect and complete the `clasp/handshake` exchange.
    pub async fn connect(path: &Path, kind: ClientKind) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|source| ClientError::Connect {
                path: path.display().to_string(),
                source,
            })?;
        Self::handshake_on(stream, kind).await
    }

    /// Handshake over an already-connected stream. Split out so tests can
    /// drive a stand-in daemon over a socket pair.
    pub async fn handshake_on(
        mut stream: UnixStream,
        kind: ClientKind,
    ) -> Result<Self, ClientError> {
        let params = HandshakeParams::current(kind);
        let req = Request::new(0, method::METHOD_HANDSHAKE, &params)?;
        frame::write_frame(&mut stream, &req).await?;
        let resp: Response = frame::read_frame(&mut stream).await?;
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
        // verdict; the major comparison is ours. A daemon from a
        // different major that (wrongly) accepted us is still refused
        // here, so a protocol break can never be papered over by one side
        // being lenient.
        //
        // Both gates are exercised **separately** over a socket, because
        // a suite that only ever meets a daemon failing both cannot tell
        // one gate from two:
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

        Ok(Self {
            stream: Mutex::new(stream),
            next_id: AtomicU64::new(1),
            daemon,
        })
    }

    /// What the daemon told us about itself during the handshake.
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
        let mut stream = self.stream.lock().await;
        frame::write_frame(&mut *stream, &req).await?;
        let resp: Response = frame::read_frame(&mut *stream).await?;
        if resp.id != id {
            return Err(ClientError::IdMismatch {
                expected: id,
                got: resp.id,
            });
        }
        Ok(resp)
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

    /// Everything this client does over a socket is tested in
    /// `tests/control_protocol.rs`, against a real daemon — a unit test
    /// there could only talk to a mock, which would test the mock. These
    /// two classifiers are the exception: they are pure functions over
    /// the error enum, and 0.0.5 has no reconnecting caller to exercise
    /// them, so without a test here they ship unasserted (see **Notes
    /// for the next milestone**: they are hooks 0.0.11's shim uses).
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
}
