//! Daemon ↔ client contract tests over a real Unix socket (spec §11.5).
//!
//! Every test gets its own runtime directory, so a wedged daemon from a
//! failed run cannot poison the next one, and the tests can run in
//! parallel.
//!
//! **Read every assertion here with "what would a broken daemon have to
//! do to still pass this?" in hand**, and one failure mode above all:
//! both peers are built from this crate, so a test that encodes with the
//! same derived `serde` impl it decodes with round-trips perfectly
//! against a wire format §7.4.1 does not describe. Everything here is
//! blind to a `#[serde(rename_all = ...)]` by construction *except* the
//! five assertions that step outside the derived impl, and it is worth
//! knowing which side each of them covers:
//!
//! * `the_handshake_frames_carry_the_7_4_1_field_names_on_the_wire` —
//!   the only one that escapes in **both** directions. It hand-builds
//!   its request as a `CborValue::Map` of literal keys and reads the
//!   response back as a raw map.
//! * `daemon_status_data_carries_the_7_4_1_field_names_on_the_wire` —
//!   response only; `daemon/status` takes no params, so there is nothing
//!   else to pin.
//! * `daemon_stop_data_names_its_timestamp_with_its_unit_on_the_wire` —
//!   response only. It **sends a typed `StopParams`**, so it says
//!   nothing about the request half.
//! * `an_unknown_method_is_an_error_that_keeps_the_connection_open` —
//!   §7.4.1's common error payload, as a raw map. That payload is on
//!   every failure path here and every other test reads it typed.
//! * `daemon_stop_params_are_parsed_under_their_7_4_1_names` — the
//!   request half `daemon_stop_data_…` leaves open, pinned the one way a
//!   rename cannot survive: a correctly named field carrying an
//!   ill-typed value must come back `bad_params`, where a renamed field
//!   is an unknown key and is dropped in silence.

use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::server::{self, Daemon, DaemonStatus, StopOutcome, StopParams};
use holdfast_core::protocol::client::{ClientError, ControlClient};
use holdfast_core::protocol::frame;
use holdfast_core::protocol::handshake::{self, ClientKind, HandshakeData, HandshakeParams};
use holdfast_core::protocol::method::{self, CborValue, ErrorCode, Request, Response};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;

/// A daemon serving in this test's own process, plus its paths. The
/// directory is removed on drop, so a socket never leaks between runs.
struct TestDaemon {
    daemon: Arc<Daemon>,
    paths: RuntimePaths,
}

impl TestDaemon {
    async fn start(tag: &str) -> Self {
        Self::start_with(tag, holdfast_core::config::Config::default()).await
    }

    /// A daemon built from an explicit `config.toml`, which is how the
    /// precedence half of REQ-CFG-001 is testable over the wire: the
    /// global value has to reach the daemon that runs `start_session`.
    async fn start_with(tag: &str, config: holdfast_core::config::Config) -> Self {
        // Short path: `sockaddr_un.sun_path` cannot hold a socket under
        // the workspace's `target/` directory.
        let paths = RuntimePaths::with_dir(scratch_dir(tag));
        let (listener, _) = server::bind_control(&paths).expect("bind control.sock");
        let daemon = Daemon::with_config(paths.clone(), config);
        tokio::spawn(server::serve(Arc::clone(&daemon), listener));
        // The connect probe below proves the socket *file* is bound, and
        // nothing more. `bind_control` hands back an already-`listen()`ing
        // `UnixListener`, so the kernel backlog accepts this connection
        // on the first iteration — before `serve` has been polled once.
        // The loop never runs twice in this build; it is kept against a
        // future `TestDaemon` that binds asynchronously.
        let sock = paths.control_sock();
        for _ in 0..200 {
            if UnixStream::connect(&sock).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // **This** is the line that waits for the accept loop to be
        // polled. Until it runs, `tokio::spawn` has only *scheduled*
        // `serve`, and a test whose assertions are synchronous — the
        // fd-table scan in `the_daemon_binds_only_the_control_socket` —
        // can run before the daemon has executed a single line, which
        // makes it silently blind to anything `serve` does. Do not delete
        // it as redundant with the loop above: that is the regression,
        // and it has been observed once already.
        tokio::task::yield_now().await;
        Self { daemon, paths }
    }

    async fn client(&self) -> Result<ControlClient, ClientError> {
        ControlClient::connect(&self.paths.control_sock(), ClientKind::Cli).await
    }

    async fn raw(&self) -> UnixStream {
        UnixStream::connect(self.paths.control_sock())
            .await
            .expect("connect")
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.daemon.shutdown();
        remove_dir_all_retrying(self.paths.dir());
    }
}

/// A short, unique `/tmp` path for one test's runtime directory.
fn scratch_dir(tag: &str) -> PathBuf {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    PathBuf::from(format!("/tmp/holdfast-it-{tag}-{}", &unique[..8]))
}

/// Remove a test's runtime directory, retrying briefly.
///
/// A single best-effort `remove_dir_all` is not quite enough: the accept
/// loop and any in-flight `handle_connection` tasks are still winding
/// down when `drop` runs, and a directory walk that races one of them can
/// fail partway and leave the tree behind. Retrying makes "each test
/// removes its own directory" true rather than usually true — which is
/// what keeps `/tmp` clean across the thousands of runs a CI matrix does.
fn remove_dir_all_retrying(dir: &std::path::Path) {
    for _ in 0..20 {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// A stand-in daemon that answers each request with `reply`.
///
/// Needed for the three cases the *real* daemon can never produce: a
/// foreign major it advertises as its own, a refusal on a matching major,
/// and a response addressed to a request the client never sent.
///
/// It keeps serving after the handshake rather than closing, and that is
/// load-bearing: a client that walked past one of its two connect gates
/// would otherwise meet an EOF, and an EOF is an error too — the
/// `expect_err` would then pass for the wrong reason.
struct StandInDaemon {
    dir: PathBuf,
}

impl StandInDaemon {
    fn start<F>(tag: &str, reply: F) -> Self
    where
        F: Fn(&Request) -> Response + Send + 'static,
    {
        let dir = scratch_dir(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::UnixListener::bind(dir.join("control.sock")).unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            while let Ok(req) = frame::read_frame::<_, Request>(&mut stream).await {
                let resp = reply(&req);
                if frame::write_frame(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
        });
        Self { dir }
    }

    fn sock(&self) -> PathBuf {
        self.dir.join("control.sock")
    }
}

impl Drop for StandInDaemon {
    fn drop(&mut self) {
        remove_dir_all_retrying(&self.dir);
    }
}

/// A handshake reply this build would accept, so a stand-in can vary one
/// field at a time and the test names which gate it is aiming at.
fn acceptable_handshake_data() -> HandshakeData {
    HandshakeData {
        protocol_major: handshake::PROTOCOL_MAJOR,
        protocol_minor: handshake::PROTOCOL_MINOR,
        daemon_version: "99.0.0".into(),
        build: "fake".into(),
        accepted: true,
        reject_reason: None,
    }
}

/// The **wire** keys of a CBOR map, sorted.
///
/// Decoding as a raw map is the only formulation that can see a field
/// rename: `data_as::<T>()` deserialises through the same derived impl
/// the daemon serialised with, so it agrees with itself whatever the
/// names are. §7.4/§7.4.1 fix the names, not a map order, so the
/// comparison is sorted.
fn sorted_map_keys(value: &CborValue) -> Vec<String> {
    let CborValue::Map(entries) = value else {
        panic!("§7.4.1's payload is a map, got {value:?}")
    };
    let mut keys: Vec<String> = entries
        .iter()
        .map(|(k, _)| {
            k.as_text()
                .expect("text keys — an integer-keyed map is a different wire format")
                .to_owned()
        })
        .collect();
    keys.sort_unstable();
    keys
}

/// Assert the daemon closed this connection, within a deadline.
///
/// **A bare `frame::read_frame(&mut stream).await` cannot express this
/// property.** If the daemon wrongly keeps the connection open the read
/// never returns; libtest has no per-test timeout and this tree carries
/// no `.config/nextest.toml`, so the mutation that ought to redden the
/// test wedges the whole binary instead — a hung CI job, which reads as
/// an infrastructure problem rather than as the finding it is.
///
/// `Err(Elapsed)` is deliberately **not** accepted as success. Elapsing
/// *is* the failure here: it means the connection was still open. The
/// only passing shape is `Ok(Err(_))` — the read completed, and what it
/// found was EOF or a broken pipe.
async fn assert_daemon_closed(stream: &mut UnixStream, what: &str) {
    let after = tokio::time::timeout(
        Duration::from_secs(5),
        frame::read_frame::<_, Response>(stream),
    )
    .await;
    assert!(
        matches!(after, Ok(Err(_))),
        "{what}: the daemon must close the connection, got {after:?}"
    );
}

/// Poll a session's output through `tool/read_output` until `needle`
/// appears. Returns everything read.
async fn read_until(client: &ControlClient, session: &str, needle: &str) -> String {
    let mut acc = String::new();
    let mut cursor = 0u64;
    for _ in 0..60 {
        let params = method::to_cbor(&json!({
            "session": session,
            "since_cursor": cursor,
        }))
        .unwrap();
        let resp = client.call_raw("tool/read_output", params).await.unwrap();
        let data: Value = method::from_cbor(&resp.data).unwrap();
        acc.push_str(data["output"].as_str().unwrap_or_default());
        cursor = data["cursor"].as_u64().unwrap_or(cursor);
        if acc.contains(needle) {
            return acc;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    acc
}

async fn start_bash(client: &ControlClient, name: &str) -> String {
    let params = method::to_cbor(&json!({
        "command": "bash",
        "args": ["--norc", "--noprofile"],
        "name": name,
    }))
    .unwrap();
    let resp = client.call_raw("tool/start_session", params).await.unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    data["session_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn the_socket_and_its_directory_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let d = TestDaemon::start("perms").await;

    let sock_mode = std::fs::metadata(d.paths.control_sock())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let dir_mode = std::fs::metadata(d.paths.dir())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o600, "control.sock is mode {sock_mode:o}");
    assert_eq!(dir_mode, 0o700, "runtime dir is mode {dir_mode:o}");
}

#[tokio::test]
async fn the_daemon_binds_only_the_control_socket() {
    // REQ-D-001 / §7.2: the daemon never opens a TCP listener. `attach`
    // and `http` are reserved names in 0.0.5 and must not exist yet
    // either — a stray bind would show up as a file here.
    let d = TestDaemon::start("onlyunix").await;
    assert!(d.paths.control_sock().exists());
    assert!(
        !d.paths.attach_sock().exists(),
        "attach.sock belongs to 0.0.6"
    );
    assert!(!d.paths.http_sock().exists(), "http.sock belongs to 0.0.10");

    #[cfg(target_os = "linux")]
    {
        // Cross-check against the kernel rather than trusting the file
        // listing: enumerate this process's socket inodes and assert none
        // of them appears in the TCP tables.
        //
        // Scope, stated honestly: this runs inside the *test* process,
        // which hosts the daemon via `bind_control` + `serve`, so it sees
        // a TCP listener opened by either of those. It cannot see one
        // opened in `server::run`, which only the real binary calls — and
        // it can only see listeners that are already bound when it runs.
        // `the_running_daemon_holds_no_listening_tcp_socket` in
        // `crates/holdfast/tests/daemon_cli.rs` will be the authoritative
        // check — it reads the fd table of a real, separately-spawned
        // daemon process and covers every path in it — but that file
        // arrives with Task 14 and is **not in the tree yet**. Until it
        // does, this test is the only cross-check there is, and its
        // stated scope is the whole of what is proven.
        let mut our_inodes = std::collections::HashSet::new();
        for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let s = target.to_string_lossy().into_owned();
                if let Some(inode) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    our_inodes.insert(inode.to_string());
                }
            }
        }
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(contents) = std::fs::read_to_string(table) else {
                continue;
            };
            for line in contents.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // Column 3 is `st`; 0A is TCP_LISTEN. Column 9 is inode.
                if fields.len() > 9 && fields[3] == "0A" && our_inodes.contains(fields[9]) {
                    panic!("the daemon process holds a listening TCP socket: {line}");
                }
            }
        }
    }
}

#[tokio::test]
async fn handshake_is_required_before_any_other_method() {
    let d = TestDaemon::start("nohs").await;
    let mut stream = d.raw().await;

    let req = Request::new(1, method::METHOD_DAEMON_STATUS, &json!({})).unwrap();
    frame::write_frame(&mut stream, &req).await.unwrap();
    let resp: Response = frame::read_frame(&mut stream).await.unwrap();

    let e = resp.control_error().expect("must be an error response");
    assert_eq!(e.code, ErrorCode::NoHandshake.as_str());
    assert!(!e.retriable);

    // §7.4.1: the connection is closed, not merely faulted.
    assert_daemon_closed(&mut stream, "a method before the handshake").await;

    // Documentation, not an independent guard — the same annotation
    // `paths.rs` puts on its twin. `.expect("must be an error response")`
    // above has already proven `resp.data` is a `ControlError` map, and a
    // `ControlError` cannot deserialise as a `DaemonStatus`, so nothing
    // that reaches this line can fail it. It is kept because it states
    // the consequence the two assertions above only imply.
    assert!(resp.data_as::<DaemonStatus>().is_err());
}

#[tokio::test]
async fn a_client_with_a_newer_major_is_refused_and_cannot_proceed() {
    // The breaking-change gate of §23.3, exercised end to end over a real
    // socket rather than against `handshake::evaluate` alone.
    let d = TestDaemon::start("toonew").await;
    let mut stream = d.raw().await;

    let params = HandshakeParams {
        protocol_major: handshake::PROTOCOL_MAJOR + 1,
        protocol_minor: 0,
        client_kind: ClientKind::Shim,
        client_version: "99.0.0".into(),
    };
    let req = Request::new(0, method::METHOD_HANDSHAKE, &params).unwrap();
    frame::write_frame(&mut stream, &req).await.unwrap();
    let resp: Response = frame::read_frame(&mut stream).await.unwrap();
    let data: HandshakeData = resp.data_as().unwrap();

    assert!(!data.accepted, "a newer major must not be accepted");
    assert!(data
        .reject_reason
        .as_deref()
        .unwrap()
        .starts_with(handshake::REJECT_CLIENT_TOO_NEW));

    // The refusal has teeth: the daemon closed the connection, so the
    // rejected client cannot simply carry on and call methods.
    let follow_up = Request::new(1, method::METHOD_DAEMON_STATUS, &json!({})).unwrap();
    let wrote = frame::write_frame(&mut stream, &follow_up).await;
    let read: Result<Response, _> = frame::read_frame(&mut stream).await;
    assert!(
        wrote.is_err() || read.is_err(),
        "a refused client must not be able to call methods"
    );
}

/// §20.8's older-major arm, over a real socket.
///
/// Named `..._over_the_socket_too` rather than sharing
/// `handshake.rs`'s `an_older_major_is_refused_too`: two tests with one
/// name means `cargo test an_older_major_is_refused_too` runs both, and
/// a reader tracing REQ-D-003a to its integration arm can land on the
/// unit test and conclude the arm exists while looking at the wrong one.
#[tokio::test]
async fn an_older_major_is_refused_over_the_socket_too() {
    let d = TestDaemon::start("tooold").await;
    let mut stream = d.raw().await;

    let params = HandshakeParams {
        protocol_major: handshake::PROTOCOL_MAJOR - 1,
        protocol_minor: 0,
        client_kind: ClientKind::Cli,
        client_version: "0.0.0".into(),
    };
    let req = Request::new(0, method::METHOD_HANDSHAKE, &params).unwrap();
    frame::write_frame(&mut stream, &req).await.unwrap();
    let resp: Response = frame::read_frame(&mut stream).await.unwrap();
    let data: HandshakeData = resp.data_as().unwrap();
    assert!(!data.accepted);
    assert!(data
        .reject_reason
        .as_deref()
        .unwrap()
        .starts_with(handshake::REJECT_CLIENT_TOO_OLD));
}

#[tokio::test]
async fn the_client_refuses_a_daemon_that_advertises_another_major() {
    // The mirror image (§18.3a's last paragraph): a lenient daemon that
    // accepts us anyway must not be able to talk us into a wire format we
    // do not implement. Driven by a stand-in daemon rather than the real
    // one, because the real one would never produce this response.
    //
    // `accepted` is deliberately left `true`: this reaches the client's
    // *second* gate only. The first is
    // `the_client_refuses_a_daemon_that_rejects_it_on_a_matching_major`.
    let stand_in = StandInDaemon::start("lenient", |req| {
        let data = HandshakeData {
            protocol_major: handshake::PROTOCOL_MAJOR + 1,
            accepted: true, // lenient, and wrong
            ..acceptable_handshake_data()
        };
        Response::ok(req.id, &data, "welcome").unwrap()
    });

    let err = ControlClient::connect(&stand_in.sock(), ClientKind::Shim)
        .await
        .expect_err("the client must refuse a foreign major");
    assert!(err.is_version_mismatch(), "got {err}");
    assert!(
        matches!(err, ClientError::VersionMismatch { .. }),
        "got {err}"
    );
}

#[tokio::test]
async fn the_client_refuses_a_daemon_that_rejects_it_on_a_matching_major() {
    // §18.3a's *first* gate, isolated. The major matches, so nothing but
    // `accepted: false` can refuse this connection — which is what makes
    // the test able to fail: delete the `if !daemon.accepted` block in
    // `ControlClient::handshake_on` and `connect` returns `Ok`, while
    // every other test in this file stays green because the real daemon
    // never refuses and accepts in the same breath.
    let stand_in = StandInDaemon::start("refusing", |req| {
        let data = HandshakeData {
            accepted: false,
            reject_reason: Some(format!(
                "{} — daemon speaks protocol {}.x; upgrade the client.",
                handshake::REJECT_CLIENT_TOO_OLD,
                handshake::PROTOCOL_MAJOR
            )),
            ..acceptable_handshake_data()
        };
        Response::ok(req.id, &data, "refused").unwrap()
    });

    let err = ControlClient::connect(&stand_in.sock(), ClientKind::Shim)
        .await
        .expect_err("the daemon's own verdict must be honoured");
    let ClientError::Refused(reason) = &err else {
        panic!("the first gate reports the daemon's reason, got {err}")
    };
    assert!(
        reason.starts_with(handshake::REJECT_CLIENT_TOO_OLD),
        "the daemon's reason must reach the caller verbatim: {reason}"
    );
    // §23.3: a version refusal must never silently degrade, whichever
    // peer noticed it. `Refused` is the branch of `is_version_mismatch`
    // the foreign-major test above cannot reach.
    assert!(err.is_version_mismatch(), "got {err}");
}

/// A refusal about the **connection** reaches the caller, even though it
/// cannot carry the request's id.
///
/// `handle_connection` builds `frame_too_large` and `protocol_violation`
/// from the frame layer, *before* the body has been decoded, so there is
/// no id to answer with and it necessarily sends `id: 0`. The client
/// checked the id first, so the operator was told "daemon replied to
/// request 1, expected 1"-shaped nonsense — "daemon replied to request 0"
/// — for "your frame was too big", and the `ControlError` explaining it
/// was **discarded unread**. On a fresh connection `id: 0` is also
/// indistinguishable from a duplicate handshake reply.
///
/// The negative below is what makes this a rule about *those codes*
/// rather than the removal of id correlation.
#[tokio::test]
async fn a_connection_scoped_refusal_reaches_the_caller_despite_carrying_id_zero() {
    let stand_in = StandInDaemon::start("framelevel", |req| {
        if req.method == method::METHOD_HANDSHAKE {
            Response::ok(req.id, &acceptable_handshake_data(), "welcome").unwrap()
        } else {
            // Exactly what `handle_connection`'s `FrameError::TooLarge`
            // arm sends: the frame layer had no decoded body to take an
            // id from.
            Response::error(0, ErrorCode::FrameTooLarge, "frame of 99 bytes exceeds 42")
        }
    });

    let client = ControlClient::connect(&stand_in.sock(), ClientKind::Cli)
        .await
        .unwrap();
    let resp = client
        .call_raw(method::METHOD_DAEMON_STATUS, CborValue::Map(Vec::new()))
        .await
        .expect("a connection-scoped refusal is an answer, not a correlation fault");
    let e = resp
        .control_error()
        .expect("and the payload must survive to the caller");
    assert_eq!(e.code, "frame_too_large");
    assert!(e.message.contains("exceeds"), "{}", e.message);
    // The whole point: `id: 0` was not treated as a mis-correlation.
    assert_eq!(resp.id, 0);
}

/// The negative for the row above. Waiving the id check for §18.3's
/// three closing codes must not waive it for anything else: a
/// mis-correlated reply hands the caller another call's payload typed as
/// its own, which is the hazard
/// `a_response_for_another_request_id_is_refused_rather_than_returned`
/// exists for.
#[tokio::test]
async fn a_per_request_error_on_the_wrong_id_is_still_a_correlation_fault() {
    let stand_in = StandInDaemon::start("idskewerr", |req| {
        if req.method == method::METHOD_HANDSHAKE {
            Response::ok(req.id, &acceptable_handshake_data(), "welcome").unwrap()
        } else {
            // `bad_params` is a per-request fault — §18.3 keeps the
            // connection — so this one really is mis-correlated.
            Response::error(req.id + 1, ErrorCode::BadParams, "nope")
        }
    });

    let client = ControlClient::connect(&stand_in.sock(), ClientKind::Cli)
        .await
        .unwrap();
    let err = client
        .call_raw(method::METHOD_DAEMON_STATUS, CborValue::Map(Vec::new()))
        .await
        .expect_err("a per-request error for another id is not this call's answer");
    assert!(
        matches!(
            err,
            ClientError::IdMismatch {
                expected: 1,
                got: 2
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_response_for_another_request_id_is_refused_rather_than_returned() {
    // §7.4's `id` is what correlates a reply with its request. Nothing in
    // this build pipelines, so a mis-correlated reply is a daemon bug
    // rather than a race — and a client that returned it anyway would
    // hand the caller another call's payload, typed as its own.
    let stand_in = StandInDaemon::start("idskew", |req| {
        if req.method == method::METHOD_HANDSHAKE {
            Response::ok(req.id, &acceptable_handshake_data(), "welcome").unwrap()
        } else {
            // Addressed to a request the client never sent.
            Response::ok(req.id + 1, &json!({}), "wrong id").unwrap()
        }
    });

    let client = ControlClient::connect(&stand_in.sock(), ClientKind::Cli)
        .await
        .expect("the handshake itself is well-formed");
    let err = client
        .call_raw(method::METHOD_DAEMON_STATUS, CborValue::Map(Vec::new()))
        .await
        .expect_err("a reply for another id is not this call's answer");
    // `expected: 1` also pins that the handshake consumed id 0, so the
    // first method call on every connection is id 1.
    assert!(
        matches!(
            err,
            ClientError::IdMismatch {
                expected: 1,
                got: 2
            }
        ),
        "got {err}"
    );
}

#[tokio::test]
async fn a_same_major_client_is_accepted_and_learns_the_daemon_version() {
    let d = TestDaemon::start("accept").await;
    let client = d.client().await.expect("handshake");
    let info = client.daemon_info();
    assert!(info.accepted);
    assert_eq!(info.protocol_major, handshake::PROTOCOL_MAJOR);
    assert_eq!(info.daemon_version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn the_handshake_frames_carry_the_7_4_1_field_names_on_the_wire() {
    // The trap this file is most exposed to. Both peers are built from
    // this crate, so `HandshakeParams`/`HandshakeData` are encoded and
    // decoded through the *same* derived impls everywhere else here: a
    // `#[serde(rename_all = "camelCase")]` on either would round-trip
    // perfectly and fail only against a peer built from §7.4.1.
    //
    // So the request below is a **hand-built CBOR map**, not a
    // serialised struct — the daemon has to parse the literal §7.4.1
    // names, and the literal `"cli"` of §7.4.1's `client_kind` — and the
    // response is read back as a raw map for the same reason.
    let d = TestDaemon::start("wirenames").await;
    let mut stream = d.raw().await;

    let params = CborValue::Map(vec![
        (
            CborValue::Text("protocol_major".into()),
            CborValue::Integer(handshake::PROTOCOL_MAJOR.into()),
        ),
        (
            CborValue::Text("protocol_minor".into()),
            CborValue::Integer(handshake::PROTOCOL_MINOR.into()),
        ),
        (
            CborValue::Text("client_kind".into()),
            CborValue::Text("cli".into()),
        ),
        (
            CborValue::Text("client_version".into()),
            CborValue::Text("0.0.0".into()),
        ),
    ]);
    let req = Request {
        id: 0,
        method: "holdfast/handshake".into(),
        params,
    };
    frame::write_frame(&mut stream, &req).await.unwrap();
    let resp: Response = frame::read_frame(&mut stream).await.unwrap();
    assert_eq!(
        resp.status, "ok",
        "the daemon must parse §7.4.1's own field names: {}",
        resp.details
    );

    assert_eq!(
        sorted_map_keys(&resp.data),
        [
            "accepted",
            "build",
            "daemon_version",
            "protocol_major",
            "protocol_minor"
        ],
        "§7.4.1's handshake response fields — `reject_reason` is absent \
         on an accepted handshake and asserted separately below"
    );

    // `reject_reason` is `skip_serializing_if`, so it can only be pinned
    // on a refusal — and a refusal is the one time a client that cannot
    // find the field is left with no diagnosis at all.
    let mut refused = d.raw().await;
    let bad = Request::new(
        0,
        method::METHOD_HANDSHAKE,
        &HandshakeParams {
            protocol_major: handshake::PROTOCOL_MAJOR + 1,
            protocol_minor: 0,
            client_kind: ClientKind::Cli,
            client_version: "99.0.0".into(),
        },
    )
    .unwrap();
    frame::write_frame(&mut refused, &bad).await.unwrap();
    let resp: Response = frame::read_frame(&mut refused).await.unwrap();
    assert_eq!(
        sorted_map_keys(&resp.data),
        [
            "accepted",
            "build",
            "daemon_version",
            "protocol_major",
            "protocol_minor",
            "reject_reason"
        ],
        "a refusal must name its reason under §18.3a's field name"
    );
}

#[tokio::test]
async fn an_unknown_method_is_an_error_that_keeps_the_connection_open() {
    let d = TestDaemon::start("unknown").await;
    let client = d.client().await.unwrap();

    let resp = client
        .call_raw("daemon/definitely_not_a_method", CborValue::Map(Vec::new()))
        .await
        .unwrap();
    let e = resp.control_error().expect("error response");
    assert_eq!(e.code, ErrorCode::UnknownMethod.as_str());

    // §7.4.1's "Common error response shape", as a raw map. This is the
    // payload *every* failure path on the wire carries, and seven tests
    // in this file read it — all of them through `control_error()`,
    // which deserialises with the same derived impl the daemon
    // serialised with. A `#[serde(rename_all)]` on `ControlError` would
    // round-trip green through every one of them and fail only against a
    // peer built from §7.4.1. The three `..._on_the_wire` tests pin
    // `HandshakeParams`, `HandshakeData`, `DaemonStatus` and
    // `StopOutcome`; this is the payload they left out.
    assert_eq!(
        sorted_map_keys(&resp.data),
        ["code", "message", "retriable"],
        "§7.4.1's common error response shape"
    );

    // Same connection, real method: `unknown_method` is per-request.
    let status: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(status.pid, std::process::id());
}

/// §18.3's **only** retriable code needs something that emits it.
///
/// `ErrorCode::retriable()` answers `true` for exactly one row and
/// `ClientError::retriable()` defers to the wire flag, so the whole
/// retry story rests on a daemon that is on its way out saying so. With
/// no producer the `Method` arm of `retriable()` can only ever answer
/// `false`, and a caller whose call landed one instant after a
/// `daemon/stop` — or after SIGTERM, or after §7.3's client-less exit —
/// is told nothing that distinguishes "come back in a moment" from "that
/// daemon crashed".
///
/// The shutdown is signalled **out of band** here rather than by issuing
/// `daemon/stop` on a second connection. That is the honest premise: all
/// three production paths converge on `Daemon::shutdown`, and driving it
/// directly means this row cannot be satisfied by a `daemon/stop` arm
/// that happens to special-case its own connection.
#[tokio::test]
async fn a_request_to_a_stopping_daemon_is_refused_with_the_retriable_code() {
    let d = TestDaemon::start("shuttingdown").await;
    let client = d.client().await.unwrap();

    // The control: the same call on the same connection succeeds while
    // the daemon is up. Without it this row would also pass against a
    // daemon that refused `daemon/status` unconditionally.
    let before: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(before.pid, std::process::id());

    d.daemon.shutdown();

    let err = client
        .call::<_, DaemonStatus>(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .expect_err("a daemon that has been asked to stop must not serve a new request");
    let ClientError::Method {
        code,
        retriable,
        message,
        ..
    } = &err
    else {
        panic!("expected §18.3's catalogued refusal, got {err:?}")
    };
    // The literal, not `ErrorCode::DaemonShuttingDown.as_str()`: this is
    // the one string a peer built from §18.3 rather than from this crate
    // has to recognise.
    assert_eq!(code, "daemon_shutting_down", "{message}");
    assert!(
        retriable,
        "§18.3 marks this row retriable, and it is the only row that is"
    );
    // The classifier the reconnect hook actually consults. `code` alone
    // would stay green against a producer that emitted the string with
    // the flag cleared.
    assert!(err.retriable(), "ClientError::retriable() must agree");

    // ------------------------------------------------------------------
    // And now the retry the daemon just invited, because asserting
    // `retriable: true` and then never retrying is what let I-1 ship.
    //
    // The refusal above arrived on a **pooled** connection, and the
    // daemon `return`ed from `handle_connection` on the statement after
    // it — so that socket is at EOF. While `daemon_shutting_down` read
    // as non-closing, `reusable()` parked it, this call checked it back
    // out, and the caller met `FrameError::Eof`, which
    // `ClientError::retriable()` classifies **false**. The daemon said
    // "reconnect and retry", the client's own pool made the retry a hard
    // failure, and every assertion above stayed green.
    //
    // The listener is drained to a known state first: `serve` breaks its
    // accept loop on the shutdown signal and drops the listener, so
    // once a raw dial is refused, every later dial is refused the same
    // way and this row has no window to be flaky in. It is a *bounded*
    // loop — an unbounded wait here would be a hung CI job rather than a
    // red test, and there is no `nextest.toml` to time it out.
    let sock = d.paths.control_sock();
    let mut listener_gone = false;
    for _ in 0..400 {
        if UnixStream::connect(&sock).await.is_err() {
            listener_gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        listener_gone,
        "a daemon told to stop must stop accepting; without this the retry below \
         could reach a live listener and the row would prove nothing"
    );

    let retry = client
        .call::<_, DaemonStatus>(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .expect_err("the daemon is still stopping, so the retry cannot succeed");
    // The shape, not the finding: whatever the retry meets, it must not
    // be *less* actionable than the refusal that invited it. A pooled
    // EOF answers `false` here; a fresh dial at a dead socket answers
    // `true` as `ClientError::Connect`, which is also the auto-spawn
    // signal — the honest report that the daemon is gone.
    assert!(
        retry.retriable(),
        "the daemon advertised a retriable refusal; the retry must not come back \
         fatal, got {retry:?}"
    );
    // And the finding itself, named, because `Frame(Eof)` is the one
    // outcome that proves the pool handed back the hung-up socket rather
    // than dialling.
    assert!(
        !matches!(retry, ClientError::Frame(_)),
        "the retry re-used the connection the daemon had already closed: {retry:?}"
    );
}

#[tokio::test]
async fn daemon_status_reports_real_session_counts() {
    let d = TestDaemon::start("status").await;
    let client = d.client().await.unwrap();

    let before: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(before.sessions_live, 0);
    assert_eq!(before.sessions_exited_retained, 0);
    assert_eq!(before.version, env!("CARGO_PKG_VERSION"));

    let id = start_bash(&client, "counted").await;

    let during: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(
        during.sessions_live, 1,
        "the count must reflect the session that was just started"
    );
    assert_eq!(during.sessions_exited_retained, 0);

    // Kill it and watch the two counters swap: `sessions_live` alone
    // could be satisfied by a hardcoded 1.
    let params = method::to_cbor(&json!({ "session": id, "force": true })).unwrap();
    client.call_raw("tool/terminate", params).await.unwrap();

    let after: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(after.sessions_live, 0);
    // §5.5.1 over §16.7/§17.1: a reaped session **keeps** its registry
    // entry. It is the retained row that makes `terminate` idempotent,
    // so a daemon that dropped it would answer 0 here and turn the
    // second `terminate` into `session_not_found`.
    assert_eq!(after.sessions_exited_retained, 1);
}

#[tokio::test]
async fn daemon_status_data_carries_the_7_4_1_field_names_on_the_wire() {
    // `call::<_, DaemonStatus>()` above cannot see a rename: it decodes
    // through the impl the daemon encoded with. `holdfast daemon status`
    // and the web UI are both built from this crate today, so nothing
    // else in the tree would notice either.
    let d = TestDaemon::start("statuskeys").await;
    let client = d.client().await.unwrap();
    let resp = client
        .call_raw(method::METHOD_DAEMON_STATUS, CborValue::Map(Vec::new()))
        .await
        .unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    assert_eq!(
        sorted_map_keys(&resp.data),
        [
            "attach_clients",
            "bridge_sessions",
            "pid",
            "sessions_exited_retained",
            "sessions_live",
            "uptime_secs",
            "version"
        ],
        "§7.4.1's `daemon/status` fields"
    );
}

#[tokio::test]
async fn daemon_stop_data_names_its_timestamp_with_its_unit_on_the_wire() {
    // REQ-T-018 binds the control protocol directly since rev. 47: every
    // timestamp on a Holdfast-defined wire surface is an integer since the
    // epoch under a name that states its unit, and a bare `stopped_at`
    // is prohibited outright rather than merely unused. §7.4.1's table
    // showed the pre-rev-38 bare `stopped_at` until rev. 48 brought it
    // into line — the code was right and the table was late — so this is
    // the assertion that stops a future reader "fixing" the field back.
    // A typed `StopOutcome` round-trip could not: both ends would agree
    // on whatever the name became.
    let d = TestDaemon::start("stopkeys").await;
    let client = d.client().await.unwrap();
    let resp = client
        .call_raw(
            method::METHOD_DAEMON_STOP,
            method::to_cbor(&StopParams::default()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    assert_eq!(
        sorted_map_keys(&resp.data),
        ["sessions_terminated", "stopped_at_unix_secs"],
        "§7.4.1's `daemon/stop` fields, under REQ-T-018's naming rule"
    );
}

#[tokio::test]
async fn daemon_stop_params_are_parsed_under_their_7_4_1_names() {
    // The test above decodes the *response* raw but sends
    // `method::to_cbor(&StopParams::default())` — the derived impl on
    // both ends — so `StopParams` had no wire pin anywhere in the tree.
    //
    // A hand-built map of the right shape would not be one either: serde
    // ignores unknown keys, so under a rename the daemon would accept
    // `{ force: true }` and answer `ok` exactly as before. Nor can
    // `deny_unknown_fields` supply it: §7.4.1 makes minor versions
    // additive, and an older daemon must tolerate a newer client's extra
    // params. What a rename **cannot** survive is a correctly named
    // field carrying an ill-typed value — under §7.4.1's names `force: 7`
    // cannot parse as `Option<bool>` and must come back `bad_params`;
    // rename the field and `force` is merely an unknown key, dropped in
    // silence, and the daemon answers `ok` and stops.
    //
    // This also pins the parse itself. Until this milestone's fix batch
    // the arm read `req.params_as().unwrap_or_default()`, which made
    // `daemon/stop` the one method that answered `ok` to structurally
    // garbage params — and stopped the daemon on the way.
    let d = TestDaemon::start("stopparams").await;
    let client = d.client().await.unwrap();

    for (field, ill_typed) in [("force", json!(7)), ("timeout_secs", json!("soon"))] {
        let mut map = serde_json::Map::new();
        map.insert(field.to_string(), ill_typed);
        let params = method::to_cbor(&Value::Object(map)).unwrap();
        let resp = client
            .call_raw(method::METHOD_DAEMON_STOP, params)
            .await
            .unwrap();
        let e = resp.control_error().unwrap_or_else(|| {
            panic!(
                "`{field}` carrying the wrong type must be refused: got status {:?}, {}",
                resp.status, resp.details
            )
        });
        assert_eq!(e.code, ErrorCode::BadParams.as_str(), "{}", e.message);
    }

    // The refusal is per-request. Were it not, each arm above would have
    // been the last thing this connection ever did, and the second would
    // have been measuring a dead daemon.
    let status: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(status.pid, std::process::id());

    // The control: the same two names, well typed, are accepted. Without
    // it the test would also pass against a daemon that answered
    // `bad_params` to every `daemon/stop` there is.
    let params = method::to_cbor(&json!({ "force": true, "timeout_secs": 5 })).unwrap();
    let resp = client
        .call_raw(method::METHOD_DAEMON_STOP, params)
        .await
        .unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
}

#[tokio::test]
async fn a_tool_call_crosses_the_socket_and_reaches_a_real_shell() {
    let d = TestDaemon::start("tool").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "toolsess").await;
    assert!(id.starts_with("sess_"));

    // `RPC''_MARKER` echoes back verbatim as `RPC''_MARKER` but *prints*
    // RPC_MARKER. Searching for a literal marker would match the PTY's
    // echo of the command line and would pass against a daemon that
    // never ran a shell at all.
    let params = method::to_cbor(&json!({
        "session": id,
        "data": "echo RPC''_MARKER",
    }))
    .unwrap();
    let resp = client.call_raw("tool/send_input", params).await.unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);

    let out = read_until(&client, &id, "RPC_MARKER").await;
    assert!(
        out.contains("RPC_MARKER"),
        "the shell behind the socket never ran the command; got: {out:?}"
    );
}

#[tokio::test]
async fn list_sessions_over_the_socket_reports_what_was_started() {
    let d = TestDaemon::start("list").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "listed").await;

    let resp = client
        .call_raw("tool/list_sessions", CborValue::Map(Vec::new()))
        .await
        .unwrap();
    assert_eq!(resp.status, "ok");
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let sessions = data["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["id"], id);
    assert_eq!(sessions[0]["name"], "listed");
    assert_eq!(sessions[0]["command"], "bash");
    assert_eq!(sessions[0]["state"], "Running");
    assert!(sessions[0]["pid"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn a_tools_schema_violation_stays_a_protocol_error_across_the_wire() {
    // §5.1 routes input-schema violations to the protocol channel, not to
    // a tool status. A transport that flattened them into `status: error`
    // would leave the agent unable to tell a bad call from a bad outcome.
    let d = TestDaemon::start("badparams").await;
    let client = d.client().await.unwrap();

    let params = method::to_cbor(&json!({ "session": "sess_x" })).unwrap();
    let resp = client.call_raw("tool/read_output", params).await.unwrap();
    let e = resp.control_error().expect("error response");
    assert_eq!(e.code, ErrorCode::BadParams.as_str());
    assert!(
        e.message.contains("exactly one of"),
        "the tool's own message must survive: {}",
        e.message
    );
    // §18.3's `bad_params` is the *control-protocol* code, and the
    // daemon has to flatten every `Err(ErrorData)` a tool raises onto it
    // because §18.3 has no JSON-RPC codes. Discarding the tool's own
    // code on the way made that flattening lossy in the one direction
    // that matters: `envelope::from_error` maps
    // `HoldfastError::Pty | HoldfastError::Io` to `internal_error` from about
    // a dozen sites in `tools.rs`, and every one of them then read to
    // the agent as a malformed *argument* in hybrid mode — while staying
    // a server fault under `--no-daemon`. Two transports, two diagnoses,
    // one fault.
    //
    // This is the wired end of that: a real tool's real `ErrorData`,
    // over a real socket. The literal is JSON-RPC 2.0's number rather
    // than `rmcp::model::ErrorCode::INVALID_PARAMS.0`, so it pins what a
    // peer built from the specification has to see.
    assert_eq!(
        e.rpc_code,
        Some(-32602),
        "the tool's own JSON-RPC code must survive the flattening"
    );
}

/// Start `bash -c <script>` on a PTY and return its session id.
async fn start_script(client: &ControlClient, name: &str, script: &str) -> String {
    let params = method::to_cbor(&json!({
        "command": "bash",
        "args": ["--norc", "--noprofile", "-c", script],
        "name": name,
    }))
    .unwrap();
    let resp = client.call_raw("tool/start_session", params).await.unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    data["session_id"].as_str().unwrap().to_string()
}

/// §5.2/§18.1's newest status, end to end.
///
/// `timeout` is `isError: false` and the control protocol carries no
/// `isError` field, so this is the row most easily lost in transit: a
/// daemon that treated any non-`ok` status as an error response, or a
/// shim that defaulted unknown statuses to "error", would tell the agent
/// a recoverable deadline was a hard failure.
///
/// Not a `#[tokio::test]`: the write this provokes stays parked in the
/// kernel forever — Linux does not wake a blocked pty-master writer when
/// the slave closes — and dropping a runtime waits for the blocking pool
/// unconditionally. The manual runtime bounds that wait, exactly as
/// `holdfast mcp` and `holdfast daemon run` do at exit.
#[test]
fn the_send_input_write_deadline_crosses_the_wire_as_a_non_error_timeout() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(write_deadline_body())
    }));
    rt.shutdown_timeout(Duration::from_secs(2));
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

async fn write_deadline_body() {
    let d = TestDaemon::start("wtimeout").await;
    let client = d.client().await.unwrap();

    // `stty raw` is the whole point. In canonical mode the line
    // discipline *discards* input it cannot buffer, so a write to a
    // non-reading child returns immediately; in raw mode it parks the
    // writer instead, and `exec sleep 300` guarantees nothing drains it.
    let id = start_script(&client, "deaf", "stty raw -echo; exec sleep 300").await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 64 KiB is `send_input`'s cap and far beyond anything the line
    // discipline will hold, so the write cannot complete.
    let payload = "x".repeat(64 * 1024);
    let params =
        method::to_cbor(&json!({ "session": id, "data": payload, "append_newline": false }))
            .unwrap();
    // Bounded, and generously: `SEND_INPUT_TIMEOUT` is 5 s, so 30 s is
    // slack rather than a race. The *arrival* of this response is the
    // property under test — remove `send_input`'s write deadline and no
    // response ever comes — so an unbounded `await` here turns the
    // mutation into a hung binary instead of a red test.
    // `rt.shutdown_timeout` in the caller does not help: it runs after
    // `rt.block_on` returns, and `block_on` is what would never return.
    let resp = tokio::time::timeout(
        Duration::from_secs(30),
        client.call_raw("tool/send_input", params),
    )
    .await
    .expect("send_input must answer: its write deadline is the property under test")
    .unwrap();

    assert_eq!(
        resp.status, "timeout",
        "a child that never reads its tty must produce `timeout`, got: {}",
        resp.details
    );
    // The load-bearing half: `timeout` crossed a transport with no
    // `isError` field and must still rebuild as a non-error.
    assert!(
        !holdfast_core::mcp::envelope::status_is_error(&resp.status),
        "§18.1 lists timeout with isError:false"
    );
    assert!(
        resp.control_error().is_none(),
        "a timeout is an outcome, not a control-protocol error"
    );
    let data: Value = method::from_cbor(&resp.data).unwrap();
    assert!(
        data["timeout_ms"].as_u64().unwrap_or(0) > 0,
        "the timeout envelope must report the deadline it applied: {data}"
    );
    assert!(data["bytes_written"].is_null(), "{data}");

    // The daemon is still usable after a parked write — the failure mode
    // that motivated the deadline in the first place.
    let status: DaemonStatus = client
        .call(method::METHOD_DAEMON_STATUS, &json!({}))
        .await
        .unwrap();
    assert_eq!(status.sessions_live, 1);

    let params = method::to_cbor(&json!({ "session": id, "force": true })).unwrap();
    let _ = client.call_raw("tool/terminate", params).await;
}

#[tokio::test]
async fn a_zero_max_bytes_read_is_a_protocol_error_across_the_wire() {
    // §5.2: `max_bytes` must be at least 1 — a zero cap can never make
    // forward progress, so it is a schema violation and must arrive as
    // `bad_params`, not as a tool status the agent would retry forever.
    let d = TestDaemon::start("zeromax").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "zero").await;

    let params =
        method::to_cbor(&json!({ "session": id, "since_cursor": 0, "max_bytes": 0 })).unwrap();
    let resp = client.call_raw("tool/read_output", params).await.unwrap();
    let e = resp.control_error().expect("error response");
    assert_eq!(e.code, ErrorCode::BadParams.as_str());
    assert!(e.message.contains("max_bytes"), "{}", e.message);
}

#[tokio::test]
async fn an_oversized_send_input_is_a_protocol_error_across_the_wire() {
    // §5.2 caps `data` at 64 KiB. Oversize violates the input schema, so
    // it takes the protocol channel rather than becoming a status.
    let d = TestDaemon::start("bigsend").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "big").await;

    let payload = "x".repeat(64 * 1024 + 1);
    let params = method::to_cbor(&json!({ "session": id, "data": payload })).unwrap();
    let resp = client.call_raw("tool/send_input", params).await.unwrap();
    let e = resp.control_error().expect("error response");
    assert_eq!(e.code, ErrorCode::BadParams.as_str());

    // The other side of the boundary, on the same session. Rejecting
    // 65537 alone is also passed by a cap of zero; the *pair* is what
    // separates `data.len() > MAX_SEND_INPUT_BYTES` from `>=`.
    //
    // That `>=` mutant is killed today only by accident:
    // `write_deadline_body` happens to send exactly 64 KiB, and the plan
    // itself calls that payload's size "incidental to what that test is
    // about". Change it to 1 KiB in some future edit — a change nothing
    // would flag — and the documented cap goes unguarded.
    //
    // `append_newline: false`, or the appended byte would push a legal
    // payload one over. A draining `bash`, not the wedged fixture: the
    // claim is that 65536 is accepted *by the schema*, and a wedged
    // child would answer `timeout` — not `bad_params` either, but for a
    // reason that has nothing to do with the cap.
    let at_cap = "x".repeat(64 * 1024);
    let params =
        method::to_cbor(&json!({ "session": id, "data": at_cap, "append_newline": false }))
            .unwrap();
    let resp = client.call_raw("tool/send_input", params).await.unwrap();
    assert!(
        resp.control_error().is_none(),
        "exactly {} bytes is the documented maximum and must be accepted, \
         not refused: {}",
        64 * 1024,
        resp.details
    );

    let params = method::to_cbor(&json!({ "session": id, "force": true })).unwrap();
    let _ = client.call_raw("tool/terminate", params).await;
}

#[tokio::test]
async fn an_unknown_tool_is_unknown_method_not_a_tool_status() {
    let d = TestDaemon::start("badtool").await;
    let client = d.client().await.unwrap();
    let resp = client
        .call_raw("tool/no_such_tool", CborValue::Map(Vec::new()))
        .await
        .unwrap();
    assert_eq!(
        resp.control_error().unwrap().code,
        ErrorCode::UnknownMethod.as_str()
    );
}

#[tokio::test]
async fn a_second_handshake_on_the_same_connection_is_a_protocol_violation() {
    let d = TestDaemon::start("rehs").await;
    let mut stream = d.raw().await;

    let good = Request::new(
        0,
        method::METHOD_HANDSHAKE,
        &HandshakeParams::current(ClientKind::Cli),
    )
    .unwrap();
    frame::write_frame(&mut stream, &good).await.unwrap();
    let first: Response = frame::read_frame(&mut stream).await.unwrap();
    assert!(first.data_as::<HandshakeData>().unwrap().accepted);

    frame::write_frame(&mut stream, &good).await.unwrap();
    let second: Response = frame::read_frame(&mut stream).await.unwrap();
    assert_eq!(
        second.control_error().unwrap().code,
        ErrorCode::ProtocolViolation.as_str()
    );
    // `protocol_violation` closes the connection (§18.3). Bounded: drop
    // `ProtocolViolation` from `ErrorCode::closes_connection`'s
    // `matches!` and the daemon returns to its read loop, so an
    // unbounded read here would block forever. `method.rs`'s
    // `exactly_three_codes_close_the_connection` goes red under the same
    // mutation, but it lives in the lib test binary — this one would
    // still wedge.
    assert_daemon_closed(&mut stream, "a second handshake").await;
}

#[tokio::test]
async fn daemon_stop_kills_live_sessions_and_ends_the_accept_loop() {
    let d = TestDaemon::start("stop").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "doomed").await;
    let pid = {
        let resp = client
            .call_raw("tool/list_sessions", CborValue::Map(Vec::new()))
            .await
            .unwrap();
        let data: Value = method::from_cbor(&resp.data).unwrap();
        data["sessions"][0]["pid"].as_u64().unwrap() as i32
    };

    let outcome: StopOutcome = client
        .call(
            method::METHOD_DAEMON_STOP,
            &StopParams {
                force: Some(true),
                timeout_secs: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.sessions_terminated, 1);
    assert!(outcome.stopped_at_unix_secs > 0);

    // The child is really gone: `kill(pid, 0)` fails once it is reaped.
    // Asserting only on `sessions_terminated` would pass against a
    // daemon that counted without signalling.
    let mut gone = false;
    for _ in 0..40 {
        // SAFETY: signal 0 performs the permission/existence check only.
        if unsafe { libc::kill(pid, 0) } != 0 {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone, "the session's process {pid} survived daemon/stop");
    assert!(!id.is_empty());

    // The accept loop stopped: a new connection gets no handshake.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fresh = tokio::time::timeout(Duration::from_millis(500), d.client()).await;
    assert!(
        matches!(fresh, Ok(Err(_)) | Err(_)),
        "the daemon must stop serving after daemon/stop"
    );
}

#[tokio::test]
async fn binding_twice_on_one_runtime_dir_is_refused() {
    // Two daemons on one socket would silently split the session set.
    let d = TestDaemon::start("dup").await;
    let err = server::bind_control(&d.paths).expect_err("second bind must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}

#[tokio::test]
async fn a_stale_socket_file_is_cleared_rather_than_blocking_startup() {
    let paths = RuntimePaths::with_dir(scratch_dir("stale"));
    paths.ensure_dir().unwrap();

    // A socket file with nobody behind it — what a SIGKILLed daemon
    // leaves. `UnixListener::bind` fails with EADDRINUSE on it, so
    // without the stale-file sweep the daemon could never restart.
    std::os::unix::net::UnixListener::bind(paths.control_sock()).unwrap();
    assert!(paths.control_sock().exists());

    let (listener, _) = server::bind_control(&paths).expect("stale socket must be cleared");
    drop(listener);
    remove_dir_all_retrying(paths.dir());
}

/// REQ-CFG-001's precedence pair, over the wire, where both layers can
/// actually be set: `hardcoded < global TOML < per-session args`.
///
/// **The two key names differ and that is the point.** The global knob is
/// `[limits] default_idle_timeout_secs` and the per-session argument is
/// `idle_timeout_secs`; unifying them would delete the distinction the
/// precedence rule is about, and under `deny_unknown_fields` a config
/// spelled with the narrow name would not load at all.
#[tokio::test]
async fn a_per_session_argument_beats_the_config_file() {
    let config = holdfast_core::config::parse_str("[limits]\ndefault_idle_timeout_secs = 60\n")
        .expect("the global half loads under its own name");
    let d = TestDaemon::start_with("precedence", config).await;
    let client = d.client().await.unwrap();

    // No argument: the config file's value governs, which is the arm
    // that fails if the daemon never reads its config.
    let params = method::to_cbor(&json!({
        "command": "bash",
        "args": ["--norc", "--noprofile"],
        "name": "from-config",
    }))
    .unwrap();
    let resp = client.call_raw("tool/start_session", params).await.unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let global_id = data["session_id"].as_str().unwrap().to_string();
    assert_eq!(
        d.daemon
            .server
            .registry
            .get(&global_id)
            .unwrap()
            .idle_timeout_secs(),
        60,
        "the global TOML value did not reach start_session"
    );

    // With an argument: 120 wins. Precedence applied in the wrong order
    // is indistinguishable unless both layers set the same knob, which
    // is why this test sets both.
    let params = method::to_cbor(&json!({
        "command": "bash",
        "args": ["--norc", "--noprofile"],
        "name": "from-argument",
        "idle_timeout_secs": 120,
    }))
    .unwrap();
    let resp = client.call_raw("tool/start_session", params).await.unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let per_session_id = data["session_id"].as_str().unwrap().to_string();
    assert_eq!(
        d.daemon
            .server
            .registry
            .get(&per_session_id)
            .unwrap()
            .idle_timeout_secs(),
        120,
        "the per-session argument lost to the config file"
    );
}

/// §5.2 declared `idle_deadline` from rev. 2 and nothing emitted it.
///
/// Asserted over the wire because the field is built in the one shared
/// `session_record`, so `status` and `list_sessions` must both carry it —
/// a field on only one of them is REQ-T-015's declared-but-unemitted
/// fault wearing the other shape.
#[tokio::test]
async fn status_reports_the_idle_deadline_and_null_means_disabled() {
    let d = TestDaemon::start("idledeadline").await;
    let client = d.client().await.unwrap();

    let reaped = start_bash(&client, "reapable").await;
    let params = method::to_cbor(&json!({ "session": reaped })).unwrap();
    let resp = client.call_raw("tool/status", params).await.unwrap();
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let deadline = data["idle_deadline_unix_secs"]
        .as_u64()
        .expect("a session with reaping enabled carries a deadline");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        deadline > now && deadline <= now + 1801,
        "the deadline must be about half an hour out, got {deadline} against {now}"
    );

    // The pairing: `null` means *disabled*, which is a different
    // statement from "far away". A deadline emitted as a far-future
    // sentinel instead would pass the arm above and make the disable
    // value unobservable.
    let params = method::to_cbor(&json!({
        "command": "bash",
        "args": ["--norc", "--noprofile"],
        "name": "never-reaped",
        "idle_timeout_secs": 0,
    }))
    .unwrap();
    let resp = client.call_raw("tool/start_session", params).await.unwrap();
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let forever = data["session_id"].as_str().unwrap().to_string();

    let params = method::to_cbor(&json!({ "session": forever })).unwrap();
    let resp = client.call_raw("tool/status", params).await.unwrap();
    let data: Value = method::from_cbor(&resp.data).unwrap();
    assert_eq!(
        data["idle_deadline_unix_secs"],
        Value::Null,
        "`idle_timeout_secs = 0` disables reaping; a sentinel deadline \
         eventually arrives"
    );

    // And `list_sessions` carries it too, through the same builder.
    let resp = client
        .call_raw("tool/list_sessions", method::to_cbor(&json!({})).unwrap())
        .await
        .unwrap();
    let data: Value = method::from_cbor(&resp.data).unwrap();
    for entry in data["sessions"].as_array().unwrap() {
        assert!(
            entry
                .as_object()
                .unwrap()
                .contains_key("idle_deadline_unix_secs"),
            "list_sessions dropped a field status carries: {entry}"
        );
    }
}

// ------------------------------------------------ MCP resources (§5.5)

async fn resource_list(client: &ControlClient) -> Vec<Value> {
    let resp = client
        .call_raw(
            method::METHOD_RESOURCE_LIST,
            method::to_cbor(&json!({})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    data["resources"].as_array().cloned().unwrap_or_default()
}

async fn resource_read(client: &ControlClient, uri: &str) -> Response {
    client
        .call_raw(
            method::METHOD_RESOURCE_READ,
            method::to_cbor(&json!({ "uri": uri })).unwrap(),
        )
        .await
        .unwrap()
}

fn first_text(resp: &Response) -> String {
    let data: Value = method::from_cbor(&resp.data).unwrap();
    data["contents"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn a_live_session_is_in_the_resource_list_and_an_exited_one_is_not() {
    let d = TestDaemon::start("reslist").await;
    let client = d.client().await.unwrap();

    // The pairing first: a list that returns nothing passes the
    // disappears-on-exit assertion perfectly.
    let id = start_bash(&client, "listed").await;
    let listed = resource_list(&client).await;
    assert_eq!(listed.len(), 1, "a live session must be listed: {listed:?}");
    assert_eq!(
        listed[0]["uri"].as_str().unwrap(),
        format!("holdfast://session/{id}/buffer")
    );
    assert_eq!(
        listed[0]["mimeType"].as_str().unwrap(),
        "text/plain; charset=utf-8",
        "§5.5.1: the listed type is the default-parameter URI's"
    );

    let params = method::to_cbor(&json!({ "session": id, "force": true })).unwrap();
    let resp = client.call_raw("tool/terminate", params).await.unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    for _ in 0..200 {
        if resource_list(&client).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        resource_list(&client).await.is_empty(),
        "§5.5.1 lists live sessions only; listing the whole registry \
         includes terminal sessions"
    );

    // And it is still ID-addressable, which is the other half of §5.5.1
    // and the reason the reaper keeps the registry entry.
    let resp = resource_read(&client, &format!("holdfast://session/{id}/buffer")).await;
    assert_eq!(
        resp.status, "ok",
        "an exited session stays ID-addressable: {}",
        resp.details
    );
}

#[tokio::test]
async fn a_name_keyed_uri_resolves_only_while_the_name_is_live() {
    let d = TestDaemon::start("resname").await;
    let client = d.client().await.unwrap();

    let first = start_bash(&client, "reused").await;
    let uri = "holdfast://session-name/reused/buffer";
    let resp = resource_read(&client, uri).await;
    assert_eq!(resp.status, "ok", "{}", resp.details);

    let params = method::to_cbor(&json!({ "session": first, "force": true })).unwrap();
    client.call_raw("tool/terminate", params).await.unwrap();
    for _ in 0..200 {
        if resource_list(&client).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // A *different* session takes the released name (REQ-S-002).
    let second = start_bash(&client, "reused").await;
    assert_ne!(first, second);
    let resp = resource_read(&client, uri).await;
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    assert_eq!(
        data["contents"][0]["uri"].as_str().unwrap(),
        uri,
        "the response echoes the URI the caller asked for"
    );
    // The id-keyed URI for the *old* session must still be distinct and
    // still resolve — a cached name→id mapping hands one session's
    // output to a reader who asked for another.
    let old = resource_read(&client, &format!("holdfast://session/{first}/buffer")).await;
    assert_eq!(old.status, "ok");
    let new = resource_read(&client, &format!("holdfast://session/{second}/buffer")).await;
    assert_eq!(new.status, "ok");
}

#[tokio::test]
async fn a_resource_read_and_a_read_output_return_the_same_bytes() {
    let d = TestDaemon::start("ressame").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "same").await;
    read_until(&client, &id, "$").await;

    // Same cursor, same knobs, both paths. A second read implementation
    // that drifted from the processor shows up here and nowhere else.
    let params = method::to_cbor(&json!({
        "session": id,
        "since_cursor": 0,
    }))
    .unwrap();
    let resp = client.call_raw("tool/read_output", params).await.unwrap();
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let via_tool = data["output"].as_str().unwrap().to_string();
    // The tool's own default cap is 32 KiB; ask the resource path for the
    // same window so the comparison is of bytes and not of caps.
    let uri = format!(
        "holdfast://session/{id}/buffer?since_cursor=0&max_bytes={}",
        32 * 1024
    );
    let via_resource = first_text(&resource_read(&client, &uri).await);
    assert_eq!(
        via_tool, via_resource,
        "the two paths must be the same processor, not two implementations"
    );
    assert!(
        !via_tool.is_empty(),
        "and the comparison must not be vacuous"
    );

    // `read_output` now emits the bulk URI beside its own bytes (§5.2).
    assert_eq!(
        data["resource_uri"].as_str().unwrap(),
        format!("holdfast://session/{id}/buffer")
    );
}

#[tokio::test]
async fn a_malformed_parameter_is_an_invalid_params_error() {
    let d = TestDaemon::start("resbad").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "bad").await;

    let resp = resource_read(
        &client,
        &format!("holdfast://session/{id}/buffer?ansi=purple"),
    )
    .await;
    assert!(resp.is_error(), "a bad enum must not default-and-continue");
    let err = resp.control_error().expect("a §7.4.1 error payload");
    assert_eq!(err.code, ErrorCode::BadParams.as_str());
    // The structured `data.code` §5.5.2 requires, carried through.
    assert!(
        err.message.contains("invalid_enum") && err.message.contains("ansi"),
        "the structured code must survive the control protocol: {}",
        err.message
    );
    // …and the JSON-RPC code the shim has to rebuild from. §18.3 has no
    // row for `-32602`, so `bad_params` above is the nearest catalogued
    // code and not the diagnosis; without `rpc_code` the shim can only
    // guess, and it guessed `-32602` for everything.
    assert_eq!(
        err.rpc_code,
        Some(-32602),
        "§5.5.2's validation faults are `-32602 Invalid params` on the MCP wire"
    );

    // The row that shows `-32602` is a *carried* value and not a
    // constant: a well-formed URI naming a session that does not exist
    // is `-32002 resource_not_found`, and reporting it as
    // `invalid_params` tells the agent its URI was malformed when it was
    // not.
    let resp = resource_read(&client, "holdfast://session/sess_nope/buffer").await;
    assert!(resp.is_error(), "an unknown session id is not a valid read");
    let err = resp.control_error().expect("a §7.4.1 error payload");
    assert_eq!(
        err.rpc_code,
        Some(-32002),
        "§5.5.1's not-found is `-32002`, not `-32602`: {}",
        err.message
    );

    // The pairing: a *good* parameter must still be honoured, or this
    // row passes against a server that rejects every query.
    let resp = resource_read(&client, &format!("holdfast://session/{id}/buffer?ansi=raw")).await;
    assert_eq!(resp.status, "ok", "{}", resp.details);
}

#[tokio::test]
async fn the_resource_templates_list_is_a_separate_method_with_no_mime_type() {
    let d = TestDaemon::start("restpl").await;
    let client = d.client().await.unwrap();
    let resp = client
        .call_raw(
            method::METHOD_RESOURCE_TEMPLATES_LIST,
            method::to_cbor(&json!({})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let templates = data["resourceTemplates"].as_array().unwrap();
    assert_eq!(templates.len(), 1);
    let t = &templates[0];
    assert!(t["uriTemplate"].as_str().unwrap().contains("{session_id}"));
    assert!(
        t.get("mimeType").is_none() || t["mimeType"].is_null(),
        "§5.5.2: the type depends on text_encoding, so the template names none: {t}"
    );
}

#[tokio::test]
async fn a_redact_false_resource_read_is_audited_as_resource_read() {
    let d = TestDaemon::start("resaudit").await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "audited").await;

    let uri = format!("holdfast://session/{id}/buffer?since_cursor=0&redact=false");
    let resp = resource_read(&client, &uri).await;
    assert_eq!(resp.status, "ok", "{}", resp.details);

    let log = std::fs::read_to_string(d.paths.audit_log()).expect("audit log");
    let entry = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|e| e["kind"] == "redaction_disabled")
        .expect("a redaction_disabled entry");
    assert_eq!(
        entry["tool"], "resource_read",
        "a resource path that bypassed the audited read path would leave \
         no entry at all, and one naming `read_output` would mean the \
         resource layer borrowed another surface's name"
    );
    // Derived server-side from the uid-checked handshake, never from the
    // request: this connection is a `cli` one.
    assert_eq!(entry["client_kind"], "cli");
}

#[tokio::test]
async fn a_caller_max_bytes_is_clamped_down_against_the_configured_ceiling() {
    // The ceiling is a config knob, so the clamp is observable by setting
    // it low rather than by asking for 4 MiB of a small buffer.
    let config =
        holdfast_core::config::parse_str("[limits]\nresource_read_max_bytes = 8\n").expect("loads");
    let d = TestDaemon::start_with("resclamp", config).await;
    let client = d.client().await.unwrap();
    let id = start_bash(&client, "clamped").await;
    read_until(&client, &id, "$").await;

    let uri = format!("holdfast://session/{id}/buffer?since_cursor=0&max_bytes=99999999");
    let resp = resource_read(&client, &uri).await;
    assert_eq!(resp.status, "ok", "{}", resp.details);
    let text = first_text(&resp);
    assert!(
        text.len() <= 8,
        "a caller asking for 99 MB got {} bytes against an 8-byte ceiling — \
         clamped up, or honoured",
        text.len()
    );

    // And the response says there is more, which is what makes the clamp
    // a continuation rather than a silent truncation.
    let data: Value = method::from_cbor(&resp.data).unwrap();
    let meta = &data["contents"][0]["_meta"]["holdfast"];
    assert_eq!(
        meta["truncated_for_size"],
        json!(true),
        "the size cap must be reported, and distinctly from held_back: {data}"
    );
    assert!(
        meta.get("held_back").is_none(),
        "§5.5.3: `held_back` and `truncated_for_size` are distinct, and \
         collapsing them into one flag is the fault to avoid: {data}"
    );
    let next = meta["next_uri"].as_str().expect("a continuation URI");
    assert!(next.contains("since_cursor="), "{next}");
}

#[tokio::test]
async fn list_changed_fires_on_create_and_on_exit() {
    // REQ-R-006. Subscribed on the daemon's own broadcast rather than on
    // an MCP peer, because the *source* is what this milestone owns: the
    // peer forwarder in `on_initialized` has no registry of its own.
    let d = TestDaemon::start("reschanged").await;
    // Seed the daemon's known set on an empty registry, the way
    // `reaper_loop` does before its first tick.
    assert!(
        !d.daemon.poll_resource_list_changed(),
        "nothing to announce yet"
    );
    let mut events = d.daemon.server.resource_list_changed.subscribe();
    let client = d.client().await.unwrap();

    let id = start_bash(&client, "announced").await;
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("no list_changed on create")
        .expect("the sender went away");

    // A tick lands between the create and the exit in any real daemon,
    // so let the daemon take the create into its known set the way
    // `reaper_loop` would. Without this the set never leaves "empty" and
    // the exit is not a change at all.
    assert!(
        d.daemon.poll_resource_list_changed(),
        "the daemon did not notice the new session on its tick"
    );

    let params = method::to_cbor(&json!({ "session": id, "force": true })).unwrap();
    client.call_raw("tool/terminate", params).await.unwrap();

    // The exit half is observed rather than announced, so the daemon's
    // periodic tick is what notices. Drive one sweep by hand rather than
    // waiting 30 s of wall time.
    let reaper = holdfast_core::session::Reaper::new(
        std::sync::Arc::clone(&d.daemon.server.registry),
        d.daemon.clock(),
    );
    for _ in 0..200 {
        reaper.scan_once();
        if d.daemon.server.registry.all().iter().all(|s| !s.is_alive()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // **The daemon's own detection, not the test's.** Calling
    // `notify_resource_list_changed()` here would put the repair path
    // ahead of the assertion: the row would pass against a daemon that
    // never notices an exit at all.
    assert!(
        d.daemon.poll_resource_list_changed(),
        "the daemon did not notice that a session left the list"
    );
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect(
            "no list_changed on exit — firing only on create leaves the \
                 agent's list stale in the direction that matters",
        )
        .expect("the sender went away");
}
