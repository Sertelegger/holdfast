//! The 0.0.10a worker link's frame catalogue and its codec (§4.1, §23.4).
//!
//! # Two rows of this file's test table are DEFERRED, and this block is
//! # where the exclusion is enumerated rather than lost
//!
//! The milestone plan's Task 1 table has five rows. Three are here.
//! **Two are not, and they are owed by Task 3**, the task that creates a
//! `holdfast pty-worker` process:
//!
//! * `the_worker_never_constructs_a_frame_near_the_cap` — "drive a
//!   worker with `yes` for 2 s; record the maximum encoded `Output`
//!   frame size observed; assert it is under 128 KiB".
//! * `a_fault_frame_carries_no_pty_bytes` — "drive a session emitting a
//!   recognisable string, force a worker fault, assert the `Fault`
//!   message does not contain it".
//!
//! Both assert properties of a **running** worker: one needs observed
//! frame sizes off a real PTY read loop and the other needs a fault
//! injected into one. Task 1 builds the catalogue and nothing that runs,
//! so neither can be written here — and writing either against a
//! hand-constructed frame would turn an assertion about behaviour into
//! an assertion about the fixture. `the_worker_never_constructs_a_frame_near_the_cap`
//! is explicit that the assertion must be on *observed* sizes and not on
//! the buffer constant, which is precisely the shape a stub would take.
//!
//! They are written out here, verbatim and by name, because §11.2's rule
//! is that an exclusion is enumerated or it is not an exclusion: an
//! unenumerated one is how a suite silently ends up running one arm.
//! Neither is stubbed and neither is `#[ignore]`d — an ignored test is a
//! row in the count that nobody reads, and this project has two of those
//! already.
//!
//! # What the three rows here are actually separating
//!
//! Both peers of this link are built from this crate, so **a round trip
//! that encodes and decodes with the same derived `serde` impl proves
//! very little on its own**. Each row below therefore carries the
//! negative that separates it from the degenerate case, and the negative
//! is the part to read first:
//!
//! * the round trip's payload is not valid UTF-8, because a `String`
//!   field round-trips perfectly against ASCII;
//! * the cap test encodes a body of *exactly* `MAX_FRAME_BYTES`, because
//!   "refuses over-cap" and "refuses everything large" look identical
//!   against a single over-cap fixture;
//! * the unknown-type test pairs with genuinely corrupt bytes and with a
//!   known type carrying bad fields, because a decoder that answered
//!   `Unknown` to every failure would pass the positive alone while
//!   swallowing a truncated frame.
//!
//! Nothing in *those three rows* spawns a process or opens a socket, so
//! nothing there can hang — but every `.await` still runs under an
//! explicit `tokio::time::timeout` whose elapsed arm fails the test, and
//! the rows Task 2 added below do open sockets and spawn a process.
//!
//! **The claim that used to stand here — "there is no per-test timeout in
//! this workspace (no `nextest.toml`)" — is no longer true**, and it is
//! corrected rather than left, because a stale reason is how a discipline
//! gets dropped by the next person who checks it. `.config/nextest.toml`
//! landed in #93 with `slow-timeout = { period = "60s", terminate-after =
//! 5 }`, so a hang is now *named* at 300 s instead of taking the job down
//! anonymously. That changes what a hang costs, not whether one is
//! acceptable: 300 s of a runner per wedged row, and a deadline that
//! belongs to the test rather than to the harness is the one that can say
//! which wait it was. The discipline stays.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use holdfast_core::protocol::frame::{FrameError, LENGTH_PREFIX_BYTES, MAX_FRAME_BYTES};
use holdfast_core::protocol::method::CborValue;
use holdfast_core::pty::worker::frames::{
    encode_frame, read_frame, DaemonFrame, LinkFrame, QueryKind, QueryResult, SignalOutcome,
    WorkerFrame, KNOWN_DAEMON_TYPES, KNOWN_WORKER_TYPES, WORKER_PROTOCOL_TAG,
};
use holdfast_core::pty::{LineDiscipline, PtySpawnConfig, Signal};

/// Every await in this file is on an in-memory slice, so this is a
/// deadline for a bug rather than for a peer. It is deliberately short:
/// a `read_frame` that ever starts waiting on something should fail this
/// file loudly rather than slow it down.
const DEADLINE: Duration = Duration::from_secs(5);

/// A payload no `String` field can carry.
///
/// **The three hostile shapes are separate on purpose**, because each
/// defeats a different wrong implementation:
///
/// * `0x00` defeats a C-string round trip, which truncates here;
/// * `0xFF` is not a legal UTF-8 byte in any position, so a lossy
///   `String::from_utf8_lossy` turns it into U+FFFD and never turns back;
/// * `0xE2 0x82` is the first two bytes of `€` with the third missing —
///   a *partial* sequence, which is the case a validity check that only
///   looks at leading bytes lets through.
///
/// PTY output is arbitrary bytes and a chunk boundary lands mid-sequence
/// routinely, so the third is the realistic one rather than the exotic
/// one.
fn hostile_payload() -> Vec<u8> {
    let mut v = b"before".to_vec();
    v.push(0x00);
    v.push(0xFF);
    v.extend_from_slice(&[0xE2, 0x82]);
    v.extend_from_slice(b"after");
    v
}

/// One constructed value per encodable [`DaemonFrame`] variant, in
/// catalogue order.
fn daemon_catalogue() -> Vec<DaemonFrame> {
    vec![
        DaemonFrame::Hello {
            build: WORKER_PROTOCOL_TAG.to_string(),
            session_id: "sess-01".to_string(),
        },
        DaemonFrame::Spawn {
            cfg: PtySpawnConfig {
                command: "/bin/bash".to_string(),
                args: vec!["--norc".to_string(), "-i".to_string()],
                cwd: Some("/tmp".to_string()),
                env: vec![("TERM".to_string(), "xterm-256color".to_string())],
                cols: 120,
                rows: 40,
            },
        },
        DaemonFrame::Write {
            bytes: hostile_payload(),
        },
        DaemonFrame::Signal {
            id: 7,
            sig: Signal::Interrupt,
        },
        DaemonFrame::Resize { cols: 80, rows: 24 },
        DaemonFrame::Query {
            id: 8,
            what: QueryKind::LineDiscipline,
        },
        DaemonFrame::Shutdown,
    ]
}

/// One constructed value per encodable [`WorkerFrame`] variant, in
/// catalogue order. `Unknown` is absent because it is decode-only; the
/// third test is what holds that claim up.
fn worker_catalogue() -> Vec<WorkerFrame> {
    vec![
        WorkerFrame::Ready {
            build: WORKER_PROTOCOL_TAG.to_string(),
        },
        WorkerFrame::Started {
            child_pid: 4242,
            pgid: Some(4242),
            sid: Some(4241),
        },
        WorkerFrame::SpawnFailed {
            message: "no such file or directory".to_string(),
        },
        WorkerFrame::Output {
            bytes: hostile_payload(),
        },
        WorkerFrame::Exited {
            code: Some(42),
            signal: Some("SIGTERM".to_string()),
        },
        WorkerFrame::Reply {
            id: 7,
            result: QueryResult::Signalled(SignalOutcome::Failed("no such process".to_string())),
        },
        WorkerFrame::Fault {
            message: "the pty master closed unexpectedly".to_string(),
        },
    ]
}

/// Encode `frame`, read it back off its own wire bytes, and return what
/// came out — under [`DEADLINE`], with the elapsed arm failing.
async fn round_trip<F: LinkFrame>(frame: &F) -> F {
    let wire = encode_frame(frame).expect("a catalogue frame encodes");
    tokio::time::timeout(DEADLINE, read_frame::<_, F>(&mut wire.as_slice()))
        .await
        .expect("read_frame returned within the deadline")
        .expect("a frame this build wrote is a frame this build reads")
}

/// Every [`QueryKind`], and the name each one answers to.
///
/// The `match` is the pin and it has **no `_` arm**: a query kind added
/// without a fixture here must be a compile error, because the two enums
/// `Query` and `Reply` carry are as much of the catalogue as the frames
/// themselves and are covered by exactly one fixture each otherwise.
fn query_kind_catalogue() -> Vec<(&'static str, QueryKind)> {
    let all = vec![
        ("LineDiscipline", QueryKind::LineDiscipline),
        ("ForegroundGroup", QueryKind::ForegroundGroup),
    ];
    for (name, kind) in &all {
        let pinned = match kind {
            QueryKind::LineDiscipline => "LineDiscipline",
            QueryKind::ForegroundGroup => "ForegroundGroup",
        };
        assert_eq!(name, &pinned);
    }
    all
}

/// Every [`QueryResult`], pinned the same way.
///
/// The `LineDiscipline` fixture is deliberately the tri-state case —
/// `echo` known, `canonical` unknown — because that is the pair
/// REQ-PD-021 makes representable *only* so its degradation rule is
/// falsifiable. A wire that collapsed `Option<bool>` to `bool` would
/// round-trip `Default::default()` unchanged.
fn query_result_catalogue() -> Vec<(&'static str, QueryResult)> {
    let all = vec![
        (
            "Discipline",
            QueryResult::Discipline(LineDiscipline {
                echo: Some(false),
                canonical: None,
            }),
        ),
        ("ForegroundGroup", QueryResult::ForegroundGroup(None)),
        (
            "Signalled",
            // The success arm, and it is the fixture that matters:
            // `Ok(())` is what ciborium 0.2.2 cannot decode, so a
            // catalogue that only ever exercised the failure arm would
            // have shipped a reply the daemon can send and never read.
            QueryResult::Signalled(Result::<(), String>::Ok(()).into()),
        ),
    ];
    for (name, result) in &all {
        let pinned = match result {
            QueryResult::Discipline(_) => "Discipline",
            QueryResult::ForegroundGroup(_) => "ForegroundGroup",
            QueryResult::Signalled(_) => "Signalled",
        };
        assert_eq!(name, &pinned);
    }
    all
}

/// The CBOR value of `key` in an encoded frame's body.
fn field(wire: &[u8], key: &str) -> CborValue {
    let body: CborValue = holdfast_core::protocol::frame::decode(&wire[LENGTH_PREFIX_BYTES..])
        .expect("the body is CBOR");
    let CborValue::Map(entries) = body else {
        panic!("a frame body is a map, got {body:?}");
    };
    entries
        .into_iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .unwrap_or_else(|| panic!("no `{key}` key in the encoded frame"))
        .1
}

#[tokio::test]
async fn every_daemon_frame_and_worker_frame_round_trips() {
    // Completeness first. Without this the test is a round trip of
    // whatever someone remembered to list, and a variant added without a
    // fixture is covered by nothing while the file still reads as a
    // catalogue test. The `KNOWN_*_TYPES` arrays are themselves pinned
    // by the exhaustive `tag()` matches in `frames.rs`, so this closes
    // the loop from variant -> tag -> catalogue -> fixture.
    let daemon = daemon_catalogue();
    let worker = worker_catalogue();
    assert_eq!(
        daemon.iter().map(|f| f.tag().unwrap()).collect::<Vec<_>>(),
        KNOWN_DAEMON_TYPES,
        "every DaemonFrame variant has a fixture, in catalogue order"
    );
    assert_eq!(
        worker.iter().map(|f| f.tag().unwrap()).collect::<Vec<_>>(),
        KNOWN_WORKER_TYPES,
        "every encodable WorkerFrame variant has a fixture, in catalogue order"
    );

    // The pairing, stated as an assertion rather than left to the
    // fixture's good intentions: a payload that happens to be valid
    // UTF-8 round-trips through a `String` field perfectly, and this row
    // would then prove nothing while still passing. If someone tidies
    // `hostile_payload` into ASCII, this is what reddens.
    let payload = hostile_payload();
    assert!(
        std::str::from_utf8(&payload).is_err(),
        "the round-trip payload must not be valid UTF-8, or the row is decorative"
    );

    for frame in &daemon {
        assert_eq!(&round_trip(frame).await, frame, "{frame:?}");
    }
    for frame in &worker {
        assert_eq!(&round_trip(frame).await, frame, "{frame:?}");
    }

    // `Query` and `Reply` each got one fixture above, which covers the
    // frame and one arm of the enum inside it. The other arms are wire
    // surface too — `QueryResult::Discipline` is the only thing that
    // carries `LineDiscipline` across the link, and its `Option<bool>`
    // pair is the one place a tri-state could collapse to a bool without
    // any frame changing shape.
    for (name, what) in query_kind_catalogue() {
        let frame = DaemonFrame::Query { id: 9, what };
        assert_eq!(round_trip(&frame).await, frame, "QueryKind::{name}");
    }
    for (name, result) in query_result_catalogue() {
        let frame = WorkerFrame::Reply { id: 9, result };
        assert_eq!(round_trip(&frame).await, frame, "QueryResult::{name}");
    }

    // The second separation, and the one that catches the mutation that
    // actually compiles. Dropping `#[serde(with = "serde_bytes")]` does
    // *not* break the equality above: `Vec<u8>` then encodes as a CBOR
    // array of 256-valued integers and decodes straight back. It is 8x
    // larger on every chunk of PTY output and it is not what §7.4's
    // codec choice is for, so the shape is asserted directly.
    for (frame, label) in [
        (
            encode_frame(&WorkerFrame::Output {
                bytes: payload.clone(),
            })
            .unwrap(),
            "WorkerFrame::Output",
        ),
        (
            encode_frame(&DaemonFrame::Write {
                bytes: payload.clone(),
            })
            .unwrap(),
            "DaemonFrame::Write",
        ),
    ] {
        let bytes = field(&frame, "bytes");
        assert!(
            matches!(&bytes, CborValue::Bytes(b) if b == &payload),
            "{label}.bytes must be a CBOR byte string, got {bytes:?}"
        );
    }
}

#[tokio::test]
async fn an_output_frame_over_the_cap_is_refused_not_clipped() {
    // The per-frame overhead is *measured*, not counted by hand: a
    // fixture sized against a hand-computed constant lands next to the
    // cap instead of on it, and then every assertion below is about a
    // size nobody meant. The probe payload is over 65535 so its CBOR
    // byte-string header is four bytes wide, the same width the 16 MiB
    // payloads below get, which is what makes the difference constant.
    const PROBE: usize = 100_000;
    let probe = encode_frame(&WorkerFrame::Output {
        bytes: vec![0u8; PROBE],
    })
    .expect("a 100 KB frame is far below the cap");
    let overhead = probe.len() - LENGTH_PREFIX_BYTES - PROBE;

    // The pairing, and it goes first because it is the one that
    // separates `>` from `>=`. §7.4's bound is exclusive: a body of
    // exactly MAX_FRAME_BYTES is legal. Without this, "refuses over-cap"
    // and "refuses everything large" are the same test.
    let at_cap = encode_frame(&WorkerFrame::Output {
        bytes: vec![0u8; MAX_FRAME_BYTES - overhead],
    })
    .expect("a body of exactly the cap is legal, not TooLarge");
    assert_eq!(
        at_cap.len() - LENGTH_PREFIX_BYTES,
        MAX_FRAME_BYTES,
        "the fixture must land on the cap exactly, or the expect above proves nothing"
    );

    // One byte past. The `len` is pinned rather than merely matched on
    // the variant, because a codec that reported the *payload* length
    // instead of the *body* length would still be TooLarge here.
    let over = encode_frame(&WorkerFrame::Output {
        bytes: vec![0u8; MAX_FRAME_BYTES - overhead + 1],
    });
    assert!(
        matches!(&over, Err(FrameError::TooLarge { len }) if *len == MAX_FRAME_BYTES + 1),
        "expected TooLarge {{ len: {} }}, got {:?}",
        MAX_FRAME_BYTES + 1,
        over.as_ref().map(|w| w.len()).map_err(|e| e.to_string())
    );

    // "Refused, not clipped" is a claim about what reached the socket,
    // so assert the socket. This is the whole of a sender: encode, then
    // write what came back. A truncating codec would put 16 MiB of a
    // clipped frame into the sink here and the daemon would read it as a
    // complete frame; an encoder that wrote as it serialised would leave
    // a partial one, which is worse, because the length prefix would
    // then describe bytes that never arrive and the link would hang
    // rather than error.
    let mut sink: Vec<u8> = Vec::new();
    let sent = tokio::time::timeout(DEADLINE, async {
        let wire = encode_frame(&WorkerFrame::Output {
            bytes: vec![0u8; MAX_FRAME_BYTES - overhead + 1],
        })?;
        sink.write_all(&wire).await.expect("write to a Vec");
        Ok::<(), FrameError>(())
    })
    .await
    .expect("the send path completed within the deadline");
    assert!(
        matches!(sent, Err(FrameError::TooLarge { .. })),
        "got {sent:?}"
    );
    assert!(
        sink.is_empty(),
        "an over-cap frame put {} bytes on the wire",
        sink.len()
    );
}

#[tokio::test]
async fn an_unknown_frame_type_decodes_to_unknown_and_does_not_panic() {
    // A frame from a build that knows a type this one does not. Hand-
    // built as CBOR, because there is no way to construct it through
    // `WorkerFrame` — which is the point: this is the arm that exists
    // for a peer that is not this build.
    let nonsense = holdfast_core::protocol::frame::encode(&CborValue::Map(vec![
        (
            CborValue::Text("type".into()),
            CborValue::Text("Nonsense".into()),
        ),
        (
            CborValue::Text("whatever".into()),
            CborValue::Integer(1.into()),
        ),
    ]))
    .expect("a small map encodes");

    let decoded: WorkerFrame = tokio::time::timeout(DEADLINE, read_frame(&mut nonsense.as_slice()))
        .await
        .expect("read_frame returned within the deadline")
        .expect("an unknown type is skipped, not an error");
    assert_eq!(
        decoded,
        WorkerFrame::Unknown {
            type_name: "Nonsense".to_string()
        }
    );

    // Separation 1: corrupt bytes are still an error. A decoder that
    // answered `Unknown` to every decode failure would pass the
    // assertion above while swallowing a truncated frame, and a
    // swallowed truncation is a desynchronised stream rather than a
    // skipped message.
    let corrupt = [0u8, 0, 0, 3, 0xff, 0xff, 0xff];
    let r: Result<WorkerFrame, _> = tokio::time::timeout(DEADLINE, read_frame(&mut &corrupt[..]))
        .await
        .expect("read_frame returned within the deadline");
    assert!(matches!(r, Err(FrameError::Cbor(_))), "got {r:?}");

    // Separation 2: a type this build *does* know, whose fields do not
    // fit, is also an error and not `Unknown`. `Output` without `bytes`
    // is a worker that changed a frame's shape without changing its
    // name, and reading it as a skippable unknown would drop a chunk of
    // PTY output silently.
    let malformed = holdfast_core::protocol::frame::encode(&CborValue::Map(vec![(
        CborValue::Text("type".into()),
        CborValue::Text("Output".into()),
    )]))
    .expect("a small map encodes");
    let r: Result<WorkerFrame, _> =
        tokio::time::timeout(DEADLINE, read_frame(&mut malformed.as_slice()))
            .await
            .expect("read_frame returned within the deadline");
    assert!(matches!(r, Err(FrameError::Cbor(_))), "got {r:?}");

    // Separation 3: the asymmetry. The same unknown `type` arriving at
    // the *worker* is an error, because the worker is the side that
    // acts and it has no safe answer to an instruction it cannot read.
    // Without this, "unknown types are skipped" could have been
    // implemented once, for both directions, and a `Write` frame this
    // build does not understand would be dropped instead of refused.
    let r: Result<DaemonFrame, _> =
        tokio::time::timeout(DEADLINE, read_frame(&mut nonsense.as_slice()))
            .await
            .expect("read_frame returned within the deadline");
    assert!(matches!(r, Err(FrameError::Cbor(_))), "got {r:?}");

    // Separation 4: `Unknown` is decode-only. Asserted through `tag()`
    // and the catalogue rather than by encoding it, because encoding it
    // trips `encode_frame`'s `debug_assert!` — which is the enforcement
    // working, and a test that has to panic to prove a thing cannot also
    // assert what it proved.
    assert!(
        WorkerFrame::Unknown {
            type_name: "Nonsense".to_string()
        }
        .tag()
        .is_none(),
        "Unknown has no wire type"
    );
    assert!(
        !KNOWN_WORKER_TYPES.contains(&"Unknown"),
        "listing Unknown in the catalogue would make every unknown frame an error"
    );

    // And the daemon direction has no such variant at all, so nothing
    // there can be skipped by accident.
    assert!(!KNOWN_DAEMON_TYPES.contains(&"Unknown"));
}

/// Task 2's rows: the per-session worker socket (§4.1, §7.1, §7.7,
/// REQ-SPTY-004).
///
/// # `#[cfg(unix)]` on the module, matching the module it tests
///
/// `pty::worker::socket` is Unix-gated because `daemon::server` is —
/// `bind_socket_within`, `SocketIdentity` and `OwnedSocket` all became
/// Unix-only in the GH #19 work. `windows-cross` and `windows-native`
/// build `--all-targets`, so this file is compiled there too and an
/// ungated import of a gated symbol reddens a required check. The rows
/// above stay cross-platform: they test a serde catalogue.
///
/// # These five rows drive `pty::worker::socket` directly, where the
/// # plan's table says "after a session starts"
///
/// **It cannot say that yet, and stubbing the difference would be worse
/// than moving the seam.** Four of the five rows in Task 2's table are
/// written against `start_session`, which cannot reach a worker until
/// Task 3 builds the `holdfast pty-worker` binary and Task 12 teaches the
/// one construction site to choose a backend. Every assertion survives
/// the translation with its substance intact — a socket's mode is the
/// same mode whether the bind was reached through `start_session` or
/// through `WorkerSocket::bind` — so the rows are here, driving the unit,
/// rather than `#[ignore]`d until the milestone that would have made them
/// end-to-end. What does **not** survive is enumerated below, because
/// §11.2's rule is that an exclusion is enumerated or it is not an
/// exclusion.
///
/// # Two more rows are DEFERRED, and one row keeps a deferred half
///
/// Owed by **Task 3** (the worker binary) and **Task 12** (backend
/// selection), which is the pair that makes a session use a worker at
/// all:
///
/// * `a_started_session_gets_a_0600_worker_socket` — the end-to-end form
///   of `the_worker_socket_is_0600_and_owned_by_the_daemons_uid`: call
///   `start_session`, then `stat` the socket the daemon actually bound
///   for it. The unit row proves the bind is correct; only this one
///   proves `start_session` reaches it, which is Task 12's single changed
///   line and is asserted here by nothing.
/// * `a_worker_that_exits_immediately_makes_start_session_spawn_failed` —
///   the end-to-end form of the accept deadline: spawn a fake worker
///   binary that exits without connecting, and assert the MCP response
///   carries `status: "spawn_failed"`. `a_worker_that_never_connects_…`
///   below asserts the error that maps *into* it, and the mapping itself;
///   the §18.1 status string is produced by `mcp::tools`, which has no
///   worker to fail at yet.
///
/// And `a_second_process_cannot_take_the_workers_slot` keeps half of its
/// table entry deferred: the pairing there reads "the **real worker**
/// still attaches", and the real worker is Task 3's. The row below
/// substitutes *this test process* for it — a genuinely different process
/// is the impostor, and the connection that must be accepted is the one
/// whose pid the socket was told to expect. That is the property the peer
/// check has; "the peer was spawned with a `pty-worker` argv" is not, and
/// asserting it needs Task 3.
#[cfg(unix)]
mod per_session_socket {
    use std::io::Read;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use holdfast_core::daemon::paths::{RuntimePaths, DIR_MODE, SOCKET_MODE};
    use holdfast_core::daemon::peer;
    use holdfast_core::pty::worker::socket::{AcceptError, WorkerSocket, WORKER_ACCEPT_TIMEOUT};
    use holdfast_core::HoldfastError;

    /// A plausible id, in the shape `session::new_session_id` emits —
    /// `sess_` plus twelve hex digits. Spelled out rather than generated,
    /// because the socket *path* is derived from it and a fixture that
    /// varied its length would vary how close these rows run to
    /// `sun_path`'s 108 bytes.
    const SESSION_ID: &str = "sess_0123456789ab";

    /// A mode `bind` never produces, used to identify the survivor in the
    /// identity row.
    const SUBSTITUTE_MODE: u32 = 0o644;

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777
    }

    #[tokio::test]
    async fn the_worker_socket_is_0600_and_owned_by_the_daemons_uid() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind the worker socket");

        let md = std::fs::symlink_metadata(sock.path()).expect("stat the socket");

        // That it is a socket at all, first. Every assertion below holds
        // just as well of a regular file, so without this the row would
        // survive a `bind` that created one — which is what an
        // `OpenOptions`-shaped "fix" for some future `EADDRINUSE` would
        // leave behind.
        assert!(
            md.file_type().is_socket(),
            "{} is not a socket: {:?}",
            sock.path().display(),
            md.file_type()
        );

        // REQ-SPTY-004's headline. **Exact equality, and it does not
        // depend on the ambient umask in either direction**: dropping the
        // explicit `chmod` leaves `0777 & ~umask`, which is `0755` under
        // the common `022` and `0700` under `077` — neither is `0600`, so
        // the row reddens whatever the developer's shell is set to. Only
        // a umask of `0177` would produce `0600` by accident, and that is
        // not a umask anyone has.
        assert_eq!(
            mode_of(sock.path()),
            SOCKET_MODE,
            "{} must be exactly {SOCKET_MODE:o}",
            sock.path().display()
        );
        assert_eq!(
            md.uid(),
            peer::current_uid(),
            "the socket must be owned by the uid the daemon runs as"
        );
        // The uid the module *recorded* for its peer check, against the
        // uid the filesystem reports. Read from two places on purpose:
        // `owner_uid` is what `accept_worker` compares a peer against, and
        // a bind that recorded the wrong one would leave the peer check
        // comparing against a uid nothing owns.
        assert_eq!(sock.owner_uid(), md.uid());

        // **The pairing.** A `0600` socket inside a `0755` directory is
        // reachable by any local user who can traverse the parent, so a
        // row that checked only the socket would be satisfied by the
        // arrangement REQ-SPTY-004 exists to prevent. It runs the other
        // way too: a `0700` parent is not a licence to leave the socket
        // wide, because the directory guard is the one that has to fail
        // before the mode matters.
        assert_eq!(
            mode_of(&paths.worker_dir()),
            DIR_MODE,
            "workers/ must be exactly {DIR_MODE:o}"
        );
    }

    #[tokio::test]
    async fn the_worker_directory_mode_is_verified_after_creation_not_just_requested() {
        // **Arm A: world-readable, and correctable.** `create_dir_all`
        // succeeds on an existing directory whatever its permissions —
        // the exact hole §7.1 documents for the runtime directory — so a
        // `workers/` inherited from an older build, or left by a
        // wider-umask install, would otherwise be bound inside as it
        // stands.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        std::fs::create_dir(paths.worker_dir()).unwrap();
        std::fs::set_permissions(paths.worker_dir(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert_eq!(
            mode_of(&paths.worker_dir()),
            0o755,
            "the fixture must start wide, or the row asserts nothing"
        );

        let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("a 0755 workers/ is correctable");
        assert_eq!(
            mode_of(&paths.worker_dir()),
            DIR_MODE,
            "an existing workers/ must be tightened, not accepted"
        );
        // And the socket really was bound inside it, so "corrects the
        // mode" cannot be satisfied by a bind that failed early and left
        // a directory nothing had reached.
        assert!(sock.path().exists());
        drop(sock);

        // **Arm B: group/world-WRITABLE, which is refused rather than
        // tightened.** The asymmetry is `Writable::Refuse`'s and it is
        // deliberate: another local user may already have planted a
        // socket in a writable directory, and a `chmod` does not undo
        // what is already there. This arm separates "the mode is
        // verified" from "the mode is tightened" — a guard that only ever
        // chmods passes arm A and silently adopts this directory.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        std::fs::create_dir(paths.worker_dir()).unwrap();
        std::fs::set_permissions(paths.worker_dir(), std::fs::Permissions::from_mode(0o777))
            .unwrap();

        let err = WorkerSocket::bind(&paths, SESSION_ID)
            .expect_err("a group/world-writable workers/ must be refused");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "got {err} ({:?})",
            err.kind()
        );
        assert!(
            !paths.worker_sock(SESSION_ID).exists(),
            "a refused bind must leave no socket behind"
        );
        assert_eq!(
            mode_of(&paths.worker_dir()),
            0o777,
            "refusing rather than chmodding is the point of this arm"
        );
    }

    /// Set on the child in `a_second_process_cannot_take_the_workers_slot`.
    const CHILD_ENV: &str = "HOLDFAST_TEST_WORKER_SOCK_CHILD";
    /// The socket the child connects to.
    const SOCK_ENV: &str = "HOLDFAST_TEST_WORKER_SOCK_PATH";
    /// Where the child records that it connected, so the parent can tell
    /// "the impostor was refused" from "`--exact` matched nothing" —
    /// which libtest reports as a *successful* run of zero tests, and
    /// which would otherwise read as a pass.
    const REPORT_ENV: &str = "HOLDFAST_TEST_WORKER_SOCK_REPORT";
    const CHILD_CONNECTED: &str = "holdfast-worker-sock-child-connected";
    const CHILD_TEST: &str = "per_session_socket::the_child_that_connects_to_a_worker_socket";
    /// What the legitimate peer writes, so "the accepted stream is ours"
    /// is asserted on bytes that crossed it rather than on credentials
    /// alone — credentials read off the wrong stream still name a
    /// legitimate-looking peer.
    const TOKEN: &[u8] = b"holdfast-worker-token";

    #[tokio::test]
    async fn a_second_process_cannot_take_the_workers_slot() {
        if std::env::var_os(CHILD_ENV).is_some() {
            // We *are* the child, re-entered under a different test name.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind the worker socket");
        let report = scratch.path().join("child-report");

        // **A real second process, not a second connection from this
        // one.** `SO_PEERCRED` reports the connecting process's pid, so
        // an impostor simulated in-process would carry *our* pid and be
        // indistinguishable from the legitimate peer — the row would then
        // pass against a check that compares nothing. The re-exec idiom
        // is `daemon::paths`'s
        // `home_dir_reads_home_first_and_user_profile_only_as_a_fallback`.
        let child =
            std::process::Command::new(std::env::current_exe().expect("this test binary's path"))
                .arg(CHILD_TEST)
                .arg("--exact")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env(CHILD_ENV, "1")
                .env(SOCK_ENV, sock.path())
                .env(REPORT_ENV, &report)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("re-exec this test binary");

        // The impostor must be in the accept queue **first**, or the row
        // proves only that a legitimate peer is accepted. Bounded, with
        // the elapsed arm failing: an unbounded poll for a file a crashed
        // child will never write is the hang this milestone is most
        // afraid of.
        let connected = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if std::fs::read_to_string(&report).is_ok_and(|r| r.contains(CHILD_CONNECTED)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            connected.is_ok(),
            "the impostor never connected, so this row asserted nothing"
        );

        // Now the legitimate peer: this process, whose pid is the one the
        // socket is told to expect. `join!` rather than a spawned task
        // because `accept_worker_within` borrows the listener.
        let our_pid = std::process::id();
        let path = sock.path().to_path_buf();
        let (accepted, _client) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(
                sock.accept_worker_within(our_pid, Duration::from_secs(10)),
                async {
                    let mut c = tokio::net::UnixStream::connect(&path)
                        .await
                        .expect("the legitimate peer connects");
                    c.write_all(TOKEN)
                        .await
                        .expect("the legitimate peer writes");
                    c
                }
            )
        })
        .await
        .expect("the accept resolved within the test's own deadline");
        let mut accepted = accepted.expect("the legitimate peer must be accepted");

        // **The pairing, and it is the whole row.** A peer check that
        // refused everyone would satisfy "the impostor was refused" and
        // prove nothing; this is what separates the two.
        let mut got = vec![0u8; TOKEN.len()];
        tokio::time::timeout(Duration::from_secs(10), accepted.read_exact(&mut got))
            .await
            .expect("the accepted stream produced its bytes within the deadline")
            .expect("the accepted stream is readable");
        assert_eq!(
            got, TOKEN,
            "the accepted stream is not the legitimate peer's"
        );
        assert_eq!(
            peer::peer_cred(&accepted).expect("peer credentials").pid,
            Some(our_pid as i32),
            "the accepted peer must be the pid the socket was told to expect"
        );

        let out = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || child.wait_with_output()),
        )
        .await
        .expect("the impostor exited within the deadline")
        .expect("the blocking join")
        .expect("the impostor's output");
        assert!(
            out.status.success(),
            "the impostor was not refused: exit {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The other half of the row above; a no-op unless re-entered as a
    /// child, so the ordinary suite runs it and it costs nothing.
    ///
    /// It asserts the **harm**: a refused connection is one whose peer
    /// reads EOF. Not a flag and not a log line — the observable
    /// consequence of the daemon dropping the stream.
    #[test]
    fn the_child_that_connects_to_a_worker_socket() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let path = std::env::var_os(SOCK_ENV).expect("the socket path");
        let mut stream =
            std::os::unix::net::UnixStream::connect(&path).expect("connect to the worker socket");

        // Written before the read, so the parent sees it whether the row
        // held or not — its absence must mean "did not connect", never
        // "failed". A file rather than a line on stdout: this crate denies
        // `clippy::print_stdout` at the root and `source_guards` scans for
        // it, and a file does not depend on `--nocapture`.
        if let Some(report) = std::env::var_os(REPORT_ENV) {
            std::fs::write(
                report,
                format!("{CHILD_CONNECTED} pid={}", std::process::id()),
            )
            .expect("record that this child connected");
        }

        // **Bounded, and the timeout is a failure rather than the expected
        // answer.** Without it, a daemon that accepted the impostor would
        // leave this read parked forever and the parent would wait on a
        // child that never exits — a hung suite instead of a red row,
        // which is the shape this milestone's constraint 4 forbids.
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("bound the read");
        let mut buf = [0u8; 1];
        match stream.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!(
                "the impostor was served {n} byte(s) instead of being refused: {:?}",
                &buf[..n]
            ),
            Err(e) => panic!(
                "the impostor was neither refused nor served within 15s: {e} ({:?})",
                e.kind()
            ),
        }
    }

    #[tokio::test]
    async fn the_socket_is_unlinked_only_while_its_identity_still_matches() {
        // Arm A: the positive, and it goes first because without it the
        // row is satisfied by a teardown that never unlinks anything.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind");
        let path = sock.path().to_path_buf();
        assert!(path.exists());
        assert!(sock.remove_if_ours(), "our own socket must be unlinked");
        assert!(
            !path.exists(),
            "{} survived a teardown that owns it",
            path.display()
        );
        // Idempotent: the `Drop` below runs `remove_if_ours` again and
        // must find nothing to do rather than erroring, or removing
        // whatever a later binder has put there.
        assert!(!sock.remove_if_ours());
        drop(sock);

        // **Arm B: substitution, not inode reuse.** The table entry asks
        // for this to be verified, and the verification is that the
        // hoped-for collision does not happen: tmpfs, btrfs and APFS
        // allocate inode numbers from a monotonic counter and never hand
        // one back, so a row that unlinked and waited for a successor to
        // be given the same inode would pass vacuously on three of the
        // four filesystems this project runs on. Substituting a
        // *different* socket at the path asks the same question — "is the
        // file at this path still the one I bound" — on all of them.
        //
        // The inode numbers are deliberately NOT asserted to differ: on
        // ext4 they legitimately can be equal, which is the 500/500
        // measurement the `O_PATH` pin exists for, and asserting
        // inequality would turn that filesystem's correct behaviour into
        // a red test. The mode marker below identifies the survivor
        // instead.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind");
        let path = sock.path().to_path_buf();

        std::fs::remove_file(&path).expect("clear the path for the substitute");
        let substitute = std::os::unix::net::UnixListener::bind(&path).expect("substitute socket");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SUBSTITUTE_MODE))
            .expect("mark the substitute");

        assert!(
            !sock.remove_if_ours(),
            "somebody else's socket must not be unlinked"
        );
        assert!(
            path.exists(),
            "the substitute at {} was unlinked by a teardown that does not own it",
            path.display()
        );
        // The marker, so "it exists" cannot be satisfied by our own socket
        // somehow surviving: `bind` produces `0600` and nothing in the
        // module produces `0644`.
        assert_eq!(
            mode_of(&path),
            SUBSTITUTE_MODE,
            "the surviving file is not the substitute"
        );

        // And `Drop` must not undo the answer `remove_if_ours` just gave.
        drop(sock);
        assert!(
            path.exists(),
            "Drop unlinked the substitute that remove_if_ours had spared"
        );
        drop(substitute);
    }

    #[tokio::test]
    async fn a_worker_that_never_connects_becomes_spawn_failed_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::with_dir(dir.path());
        let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind");

        // **This is the milestone's archetypal hang row.** The outer
        // deadline is the test's own and its elapsed arm FAILS: written
        // as `matches!(r, Err(_))` around the await, a removed
        // `tokio::time::timeout` inside `accept_worker` would be accepted
        // as a pass and the guard would be decorative. Nothing connects to
        // this socket, so the only way out is the deadline under test.
        //
        // `u32::MAX` is the expected pid on purpose: nothing can hold it,
        // so even a stray connection could not satisfy the accept and
        // turn this row green for the wrong reason.
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(10), sock.accept_worker(u32::MAX))
            .await
            .expect(
                "accept_worker did not return on its own; the test's 10 s deadline elapsed \
                 instead, which is exactly the unbounded accept this row exists to catch",
            );
        let elapsed = started.elapsed();

        let err = outcome.expect_err("nothing connected, so the accept cannot have succeeded");
        assert!(
            matches!(err, AcceptError::TimedOut(d) if d == WORKER_ACCEPT_TIMEOUT),
            "expected TimedOut({WORKER_ACCEPT_TIMEOUT:?}), got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(6),
            "the accept took {elapsed:?}, which is not the 5 s deadline it claims"
        );

        // **`spawn_failed`-shaped, and this is where that claim is checked
        // rather than asserted in a doc comment.** REQ-SPTY-001 adds no
        // `Status` value for a worker that never started; `start_session`
        // maps a backend construction `Err` to `Status::SpawnFailed`
        // without inspecting it, and `Pty` is the variant
        // `InProcessPty::spawn` returns for every one of its own failures.
        // A conversion that produced `Io` instead would still reach
        // `spawn_failed` today and would diverge the moment anything
        // matches on the error.
        let mapped = HoldfastError::from(err);
        assert!(
            matches!(mapped, HoldfastError::Pty(_)),
            "a failed accept must arrive as the same error variant a failed \
             InProcessPty::spawn does, got {mapped:?}"
        );
    }
}
