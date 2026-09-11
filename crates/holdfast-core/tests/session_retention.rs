//! What a finished session costs, and what it still answers (GH #129).
//!
//! §5.5.1 keeps exited sessions on purpose, so the fix these rows cover
//! is **not** "retain less". It is: stop retaining the machinery that
//! only a running child needs, keep every observable a finished session
//! already offers, and put an explicit bound — records *and* bytes — on
//! the history that is retained deliberately.
//!
//! The three claims, one row each:
//!
//! 1. A completed session gives up its writer thread.
//! 2. A completed session answers everything it answered before.
//! 3. The completed set is bounded in both directions, and a live
//!    session is never in it.
//!
//! **Every wait here is a bounded poll that panics on its deadline**,
//! never a sleep followed by an assertion: a thread count read off a
//! wall-clock sleep is a coin flip on a loaded machine, and a sleep that
//! is treated as success is a row that passes against the defect.

use holdfast_core::detect::InteractionMode;
use holdfast_core::output::OutputProcessor;
use holdfast_core::pty::{MockPty, PtyBackend, Signal};
use holdfast_core::screen::ScreenCapture;
use holdfast_core::session::{Retention, Session, SessionConfig, SessionRegistry, SessionState};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long any of these rows will wait for a condition before failing.
///
/// Generous, because it is only ever *reached* when the row is red: a
/// writer thread leaves `blocking_recv` in microseconds once its last
/// sender is gone, so a passing run spends no time here at all.
const WAIT: Duration = Duration::from_secs(20);

fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if pred() {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("timed out after {WAIT:?} waiting for {what}");
}

fn session(id: &str, buffer_capacity: usize) -> (Arc<Session>, Arc<MockPty>) {
    let pty = Arc::new(MockPty::new());
    let s = Session::new(
        id.to_string(),
        None,
        "mock".into(),
        vec![],
        Arc::clone(&pty) as Arc<dyn PtyBackend>,
        SessionConfig::with_buffer_capacity(buffer_capacity),
    );
    (s, pty)
}

/// Run one session end to end: fill its buffer, kill it, and wait for
/// both facts the rest of the file depends on — that the child is seen
/// dead, and that the reader has published everything it is ever going
/// to.
fn run_to_completion(s: &Arc<Session>, pty: &Arc<MockPty>, bytes: usize, code: i32) {
    if bytes > 0 {
        pty.queue_output(&vec![b'x'; bytes]);
        wait_until("the reader to drain the queued output", || {
            s.buffer_extent().1 >= bytes as u64
        });
    }
    pty.exit(code);
    wait_until("the child to be observed dead", || !s.is_alive());
    wait_until("the reader thread to finish", || s.reader_finished());
}

// ------------------------------------------------ 1. the parked threads

/// GH #129's measurement, as a row.
///
/// **The numbers it reproduced**, taken on this tree at `68ad7f2` before
/// the fix with this harness at a 1 MiB buffer: 24 writer threads left
/// parked — `/proc/self/status` `Threads:` went 2 → 26 — and 25_165_824
/// bytes (24.0 MiB) of ring buffer retained, with **zero** live
/// sessions. The independent review that filed the issue measured
/// 4 → 28 threads and ~24 MiB on the same shape. Afterwards the same
/// harness measured `Threads:` 2 → 3 and 16_777_216 bytes, the byte
/// bound having evicted the eight oldest records.
///
/// **The buffer here is 64 KiB and not the 1 MiB that was measured**,
/// and the reason is throughput rather than taste: `MockPty` moves its
/// queue a byte at a time, and 24 MiB of that is 4 s of a quiet machine
/// but more than 100 s when the whole workspace is running on two shared
/// cores — measured, as a `TIMEOUT` under `taskset -c 0,1` with
/// `nextest -j 8`. The claim this row carries is the **threads**; the
/// byte bound has two rows of its own below that reach it in
/// milliseconds, and the shipped numbers are pinned by a third.
///
/// **A live limit of 1 is what makes the shape visible.** Every session
/// but one is over before the next begins, so nothing here is a
/// concurrency cost — every thread the process is still holding at the
/// end belongs to a session that finished.
///
/// **The assertion is per session and not a process thread count**, and
/// that is not the weaker claim it looks like. `JoinHandle::is_finished`
/// is the standard library's own answer about *this* session's writer,
/// where a process thread count is a number every other test in the
/// binary also moves. The first draft of this row asserted a
/// process-wide gauge and failed 20 times in 20 runs under
/// `taskset -c 0,1 --test-threads 8`, with nothing wrong with the tree.
#[test]
fn twenty_four_completed_sessions_leave_no_writer_threads_behind() {
    const SESSIONS: usize = 24;
    const BUF: usize = 64 * 1024;

    let registry = SessionRegistry::new(1);
    // Held for the whole row, so each session can be asked whether its
    // own thread went away. Holding them cannot mask the leak: what
    // GH #129 measured is what the *registry* keeps, which
    // `retained_output_bytes` below reads.
    let mut all = Vec::new();

    for i in 0..SESSIONS {
        let (s, pty) = session(&format!("sess_gh129{i:04}"), BUF);
        registry
            .insert(Arc::clone(&s))
            .expect("the one live slot is free, because the previous session is over");
        run_to_completion(&s, &pty, BUF, 0);
        all.push(s);
    }
    // The daemon's periodic tick does this (`daemon::server::reaper_loop`);
    // `insert` does it for the twenty-three that had a successor. Called
    // by hand here because this row has no daemon and no successor for
    // the last session.
    registry.retire_exited();

    assert_eq!(registry.live_count(), 0, "no session is still running");
    wait_until("every completed session's writer thread to leave", || {
        all.iter().all(|s| s.writer_thread_finished())
    });

    // Nothing was thrown away to get there: 24 records of 64 KiB is
    // inside both shipped bounds, so this run costs the daemon its
    // history and nothing else. A fix that bought the threads by
    // dropping the records fails here.
    assert_eq!(registry.retained_count(), SESSIONS);
    assert_eq!(
        registry.retained_output_bytes(),
        (SESSIONS * BUF) as u64,
        "the registry lost output it was inside its own bounds to keep"
    );
    for s in &all {
        assert!(registry.get(&s.id).is_ok(), "{} stopped resolving", s.id);
    }
}

/// The shipped bounds, pinned where they can be read.
///
/// The two rows below drive the eviction logic at a budget they can
/// reach in milliseconds, so nothing else in this file asserts the
/// numbers a daemon actually runs with. Changing them is allowed;
/// changing them **silently** is what this stops.
#[test]
fn the_shipped_retention_bounds_are_sixty_four_records_and_sixteen_mebibytes() {
    let shipped = SessionRegistry::with_defaults().retention();
    assert_eq!(shipped, Retention::default());
    assert_eq!(shipped.max_records, 64);
    assert_eq!(shipped.max_bytes, 16 * 1024 * 1024);
    // The pair GH #129 measured — 24 sessions of 1 MiB — is over the
    // byte bound and under the record bound, which is the case the
    // second row below covers.
    assert!(24 * 1024 * 1024 > shipped.max_bytes);
    assert!(24 < shipped.max_records);
}

/// A **live** session keeps its writer, however many finished sessions
/// are swept around it — and a finished one keeps its writer until
/// something sweeps.
///
/// Two pairings in one row. The first catches a sweep that simply tears
/// every session down: that sweep passes the measurement above perfectly
/// and takes the write queue away from a running child. The second is
/// what stops the measurement above being satisfied by the *exit*
/// instead of by the sweep — the child dying is not what frees the
/// thread, and the gap between the two is exactly what GH #129 measured.
#[test]
fn a_live_session_keeps_the_writer_thread_a_finished_one_gives_up() {
    let registry = SessionRegistry::new(4);
    let (alive, _alive_pty) = session("sess_writerlive", 4096);
    let (over, over_pty) = session("sess_writerover", 4096);
    registry.insert(Arc::clone(&alive)).unwrap();
    registry.insert(Arc::clone(&over)).unwrap();

    assert!(
        !over.writer_thread_finished(),
        "the fixture spawned no writer"
    );
    run_to_completion(&over, &over_pty, 0, 0);
    assert!(
        !over.writer_thread_finished(),
        "the writer left without a sweep, so the rows here cannot tell the sweep \
         from the exit"
    );

    registry.retire_exited();
    wait_until("the finished session's writer to leave", || {
        over.writer_thread_finished()
    });
    assert!(
        !alive.writer_thread_finished(),
        "the sweep took the writer thread away from a session whose child is still running"
    );
}

/// The sweep runs on `insert`, so a busy daemon never waits a tick.
///
/// **The other half of `retire_exited`'s two callers**, and the one that
/// matters for the shape GH #129 was measured on: an agent driving one
/// short command after another makes a `start_session` call every few
/// seconds, and that call is the natural moment for the session before
/// it to stop being live. `daemon::server::reaper_loop` covers the quiet
/// daemon and has its own row; nothing here calls the sweep by hand,
/// which is what makes this row fail if `insert` stops doing it.
#[test]
fn a_new_session_retires_the_one_that_finished_before_it() {
    let registry = SessionRegistry::new(1);

    let (first, first_pty) = session("sess_insert0", 4096);
    registry.insert(Arc::clone(&first)).unwrap();
    run_to_completion(&first, &first_pty, 0, 0);
    assert_eq!(
        registry.retained_count(),
        0,
        "something other than the insert below retired it"
    );

    let (second, _second_pty) = session("sess_insert1", 4096);
    registry
        .insert(Arc::clone(&second))
        .expect("the slot the finished session gave up");

    assert_eq!(
        registry.retained_count(),
        1,
        "the insert did not retire the session that had already finished"
    );
    wait_until("the finished session's writer thread to leave", || {
        first.writer_thread_finished()
    });
    // And the record it retired is still the record §5.5.1 promises.
    assert!(registry.get("sess_insert0").is_ok());
}

/// The writer thread parks on its queue, so the only thing that can free
/// it is the last sender going away — and after that, an enqueue must
/// fail rather than sit in a channel nothing will ever drain.
///
/// **A live session's queue is untouched**, which is the half a wrong
/// sweep would break: two attach clients typing into a running session
/// both push through this channel.
#[test]
fn a_retired_session_refuses_writes_instead_of_queueing_them_for_nobody() {
    use holdfast_core::session::WriteRequest;

    let registry = SessionRegistry::with_defaults();
    let (alive, _alive_pty) = session("sess_queuelive", 4096);
    let (over, over_pty) = session("sess_queueover", 4096);
    registry.insert(Arc::clone(&alive)).unwrap();
    registry.insert(Arc::clone(&over)).unwrap();
    run_to_completion(&over, &over_pty, 0, 0);
    registry.retire_exited();

    let (req, _ack) = WriteRequest::input(b"hello\n".to_vec());
    assert!(
        over.write_queue().try_send(req).is_err(),
        "a retired session still accepted a write onto a queue nobody is draining"
    );
    let (req, _ack) = WriteRequest::input(b"hello\n".to_vec());
    assert!(
        alive.write_queue().try_send(req).is_ok(),
        "the sweep took the write queue away from a session whose child is still running"
    );
}

// ------------------------------------------- 2. what it still answers

/// The trap this change had to avoid, enumerated.
///
/// Everything a finished session answers is captured immediately before
/// the sweep and again immediately after it, and compared. A teardown
/// that quietly dropped an observable — the buffer, the exit code, the
/// history, the screen — would compile, would leave the thread rows
/// above green, and would be caught here.
///
/// **`exit_code` is the one that constrains the design.** It is read
/// from the backend, not cached on the session, so the PTY backend
/// cannot be part of what a retirement gives up — and neither can the
/// ring buffer, which is what `read_output` and `holdfast logs` read
/// from after the end. See `Session::retire` for the full list of what
/// is deliberately kept.
#[test]
fn a_retired_session_answers_everything_it_answered_before() {
    let processor = OutputProcessor::builtin().expect("the built-in rules compile");
    let registry = SessionRegistry::with_defaults();
    let (s, pty) = session("sess_observables", 64 * 1024);
    registry.insert(Arc::clone(&s)).unwrap();
    // Painted through the PTY rather than injected, so the ring buffer,
    // the detector and the grid all see the same bytes and none of the
    // observables below is trivially empty.
    const PAINTED: &[u8] = b"alpha\r\nbeta\r\ngamma\r\n";
    pty.queue_output(PAINTED);
    wait_until("the reader to publish the painted output", || {
        s.buffer_extent().1 >= PAINTED.len() as u64
    });
    run_to_completion(&s, &pty, 0, 0);

    // Tier B is off until something asks for a screen, so this call is
    // what puts a grid in the session to compare at all.
    let _ = s.screen_state(None, true, &processor);

    #[derive(Debug, PartialEq)]
    struct Observables {
        state: SessionState,
        exit_code: Option<i32>,
        exited_at_secs: Option<u64>,
        pid: Option<u32>,
        is_alive: bool,
        reader_finished: bool,
        buffer_extent: (u64, u64),
        buffer_slice: Vec<u8>,
        read_from: Vec<u8>,
        tail_bytes: Vec<u8>,
        tail_lines: Vec<u8>,
        command_count: u64,
        history_len: usize,
        history_truncated: bool,
        interaction_mode: InteractionMode,
        screen_tracking: &'static str,
        screen_lines: Vec<String>,
        redaction_stats: std::collections::BTreeMap<String, u64>,
        size: (u16, u16),
        desired_size: Option<(u16, u16)>,
        idle_timeout_secs: u64,
        idle_deadline_ms: Option<i64>,
        last_activity_ms: i64,
        writes_performed: u64,
        secret_episode: u64,
        awaiting_secret: bool,
        resolves_by_id: bool,
        in_all: bool,
    }

    let snapshot = |s: &Arc<Session>, registry: &SessionRegistry| {
        let (tail, head) = s.buffer_extent();
        let screen_lines = match s.screen_state(None, true, &processor) {
            ScreenCapture::Full(g) => g.lines,
            ScreenCapture::Delta(_) => panic!("a full capture was asked for"),
        };
        Observables {
            state: s.state(),
            exit_code: s.exit_code(),
            exited_at_secs: s.exited_at_secs(),
            pid: s.pid(),
            is_alive: s.is_alive(),
            reader_finished: s.reader_finished(),
            buffer_extent: (tail, head),
            buffer_slice: s.buffer_slice(tail, head),
            read_from: s.read_from(tail, 4096).bytes,
            tail_bytes: s.read_tail_bytes(64).bytes,
            tail_lines: s.read_tail_lines(4).bytes,
            command_count: s.command_count(),
            history_len: s.command_history(0, 100).len(),
            history_truncated: s.history_truncated(),
            interaction_mode: s.detection().interaction_mode,
            screen_tracking: s.screen_tracking(),
            screen_lines,
            redaction_stats: s.redaction_stats(),
            size: s.size(),
            desired_size: s.desired_size(),
            idle_timeout_secs: s.idle_timeout_secs(),
            idle_deadline_ms: s.idle_deadline_ms(),
            last_activity_ms: s.last_activity_ms(),
            writes_performed: s.writes_performed(),
            secret_episode: s.secret_episode(),
            awaiting_secret: s.is_awaiting_secret(),
            resolves_by_id: registry.get(&s.id).is_ok(),
            in_all: registry.all().iter().any(|o| o.id == s.id),
        }
    };
    // **`signal` is asserted outside the snapshot, deliberately.**
    // `Session::signal` stamps `last_activity` (§4.1), so calling it
    // from inside the snapshot would move two of the fields the
    // comparison is over and make the row fail against a correct tree —
    // which is exactly what it did when it was in there.

    let before = snapshot(&s, &registry);
    assert_eq!(registry.retire_exited(), 1, "the session was not retired");
    let after = snapshot(&s, &registry);

    assert_eq!(
        before, after,
        "retiring the session changed what it answers"
    );
    // The control: a snapshot of nothing compares equal to a snapshot of
    // nothing, so the assertion above has to be able to see a value.
    assert_eq!(after.state, SessionState::Exited(0));
    assert!(after.resolves_by_id && after.in_all);
    assert!(!after.is_alive && after.reader_finished);
    assert_eq!(after.buffer_slice, PAINTED, "the buffer compared empty");
    assert_eq!(after.screen_lines[0], "alpha", "the grid compared empty");

    // §5.2's `terminate` idempotence: signalling a corpse is `ok`, not
    // an error, and it must stay that way for a record whose machinery
    // has been torn down.
    assert!(s.signal(Signal::Kill).is_ok());

    // And the subscriptions a late attach takes are still takeable —
    // `forward_output` subscribes to both before it reads the state.
    let _output = s.subscribe();
    let _events = s.subscribe_events();
}

/// The output of a finished session survives the sweep, which is the
/// half of §5.5.1 that `read_output` and `holdfast logs` rest on.
///
/// Separate from the enumeration above because that row compares a
/// finished session against **itself** — a teardown that emptied the
/// buffer *before* the first snapshot would satisfy it. This one names
/// the bytes.
#[test]
fn a_retired_session_still_hands_back_the_output_it_produced() {
    let registry = SessionRegistry::with_defaults();
    let (s, pty) = session("sess_keepsoutput", 64 * 1024);
    registry.insert(Arc::clone(&s)).unwrap();
    pty.queue_output(b"first line\r\nsecond line\r\n");
    wait_until("the reader to publish the output", || {
        s.buffer_extent().1 >= 24
    });
    run_to_completion(&s, &pty, 0, 7);
    registry.retire_exited();

    let found = registry.get("sess_keepsoutput").expect("still addressable");
    let (tail, head) = found.buffer_extent();
    assert_eq!(
        String::from_utf8_lossy(&found.buffer_slice(tail, head)),
        "first line\r\nsecond line\r\n"
    );
    assert_eq!(found.state(), SessionState::Exited(7));
    assert_eq!(found.exit_code(), Some(7));
}

// ----------------------------------------------------- 3. the bounds

/// A cap on records alone is not a bound on memory, and a cap on bytes
/// alone is not a bound on records. Both are asserted, each against a
/// budget the other cannot reach.
#[test]
fn the_completed_set_is_bounded_by_records() {
    let registry = SessionRegistry::with_retention(
        1,
        Retention {
            max_records: 4,
            // Far past anything this row produces, so only the record
            // count can be what evicts.
            max_bytes: u64::MAX,
        },
    );
    let mut ids = Vec::new();
    for i in 0..10 {
        let (s, pty) = session(&format!("sess_rec{i:04}"), 4096);
        registry.insert(Arc::clone(&s)).unwrap();
        run_to_completion(&s, &pty, 0, 0);
        ids.push(s.id.clone());
    }
    registry.retire_exited();

    assert_eq!(registry.retained_count(), 4);
    // Oldest first: the six earliest are gone, the four newest are not.
    for gone in &ids[..6] {
        assert!(
            registry.get(gone).is_err(),
            "{gone} outlived the record bound"
        );
    }
    for kept in &ids[6..] {
        assert!(
            registry.get(kept).is_ok(),
            "{kept} was evicted although newer records were kept"
        );
    }
}

#[test]
fn the_completed_set_is_bounded_by_bytes() {
    const BUF: usize = 16 * 1024;
    let registry = SessionRegistry::with_retention(
        1,
        Retention {
            // Far past anything this row produces, so only the byte
            // budget can be what evicts.
            max_records: usize::MAX,
            max_bytes: (BUF * 3) as u64,
        },
    );
    let mut ids = Vec::new();
    for i in 0..10 {
        let (s, pty) = session(&format!("sess_byt{i:04}"), BUF);
        registry.insert(Arc::clone(&s)).unwrap();
        run_to_completion(&s, &pty, BUF, 0);
        ids.push(s.id.clone());
    }
    registry.retire_exited();

    assert!(
        registry.retained_output_bytes() <= (BUF * 3) as u64,
        "{} bytes retained against a budget of {}",
        registry.retained_output_bytes(),
        BUF * 3
    );
    assert_eq!(
        registry.retained_count(),
        3,
        "the byte budget should hold exactly three {BUF}-byte sessions"
    );
    assert!(registry.get(&ids[0]).is_err());
    assert!(registry.get(&ids[9]).is_ok());
}

/// The byte budget keeps the newest record whatever it costs.
///
/// Without this, an operator whose `output_buffer_bytes` is larger than
/// the retention budget gets **no** history at all: every session would
/// evict itself on the sweep that retired it, and `read_output` on a
/// session that had just finished would answer `session_not_found`.
#[test]
fn the_byte_budget_never_evicts_the_only_record_there_is() {
    const BUF: usize = 32 * 1024;
    let registry = SessionRegistry::with_retention(
        1,
        Retention {
            max_records: 16,
            max_bytes: 1024,
        },
    );
    let (s, pty) = session("sess_lonely", BUF);
    registry.insert(Arc::clone(&s)).unwrap();
    run_to_completion(&s, &pty, BUF, 0);
    registry.retire_exited();

    assert_eq!(registry.retained_count(), 1);
    assert!(
        registry.get("sess_lonely").is_ok(),
        "a session larger than the whole budget evicted itself, leaving no history"
    );
    assert!(registry.retained_output_bytes() > 1024);
}

/// A live session is neither retired nor evicted, however far past
/// either budget the registry is.
///
/// The bound applies to *records of sessions that are over*. A sweep
/// that counted a running session towards it would take a working
/// session's write queue away and then drop the only handle to it.
#[test]
fn a_live_session_is_neither_retired_nor_evicted() {
    let registry = SessionRegistry::with_retention(
        2,
        Retention {
            max_records: 1,
            max_bytes: 1,
        },
    );
    let (alive, _alive_pty) = session("sess_stillrunning", 4096);
    registry.insert(Arc::clone(&alive)).unwrap();

    for i in 0..6 {
        let (s, pty) = session(&format!("sess_churn{i:04}"), 4096);
        registry.insert(Arc::clone(&s)).unwrap();
        run_to_completion(&s, &pty, 1024, 0);
        registry.retire_exited();
    }

    assert_eq!(registry.retained_count(), 1);
    assert_eq!(registry.live_count(), 1);
    assert!(
        registry.get("sess_stillrunning").is_ok(),
        "the sweep evicted a session whose child is still running"
    );
    assert!(
        registry.all().iter().any(|s| s.id == "sess_stillrunning"),
        "the live session fell out of `all()`"
    );
}
