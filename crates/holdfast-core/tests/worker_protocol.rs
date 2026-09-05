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
//! Nothing here spawns a process or opens a socket, so nothing here can
//! hang — but every `.await` still runs under an explicit
//! `tokio::time::timeout` whose elapsed arm fails the test. There is no
//! per-test timeout in this workspace (no `nextest.toml`), an unbounded
//! wait is a hung CI job rather than a red build, and the discipline is
//! cheaper to keep than to reintroduce once `read_frame` is reading from
//! a socket instead of a slice.

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
