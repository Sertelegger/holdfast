//! Moving output processing off the runtime's worker threads (GH #201).
//!
//! ## Why this exists
//!
//! §4.3 promises the read path runs "outside any lock", and it does. What
//! it never promised — because §4.2a measured the default read at
//! **0.095 ms** and concluded *"the read path is cheap regardless of
//! frequency"* — is that the scan still runs **on a runtime worker**, and
//! that conclusion is the load-bearing one. GH #194 moved the number it
//! rests on: one byte ≥ `0x80` anywhere in the window costs 410×, so a
//! real 256 KiB read is 0.4–3.9 s of uninterruptible CPU on the thread
//! that was supposed to be polling the executor. §4.2a's figure is a
//! measurement of a path, not a licence for the path; when the
//! measurement moved, the licence went with it.
//!
//! **What that costs is not latency on the slow call.** Measured on the
//! shipped wire — a release build, one daemon, twelve worker threads,
//! two independent `holdfast mcp` processes, one in-flight `read_output`
//! and everything else idle. The thread census is from the same
//! arrangement in a debug build, where the read is long enough to sample
//! comfortably:
//!
//! | during one large read | before | after |
//! |---|---|---|
//! | daemon threads in `R` / in `S` | **1 / 15**, sampled every 250 ms | — |
//! | `status`, unrelated session, second client | answered **17** times, worst **2,061 ms** | **1,453** times, median 1.52 ms, worst **8.48 ms** |
//! | `holdfast list`, a third client | **rc=2 at 5,031 ms** | **rc=0 at 21.7 ms** |
//!
//! Baseline with nothing in flight: `status` 1.28–5.10 ms, `list` rc=0 in
//! 19.6 ms. The answer *count* is the clearest of those numbers —
//! seventeen replies across a 2.1 s window is a client that was stopped,
//! not one that was slow.
//!
//! **The census reconciles like this, and it is written out because the
//! first draft of this table did not and could not be checked.** Sixteen
//! threads carried the runtime's thread name, not twelve: twelve executor
//! workers plus, for the two sessions this daemon held, the four
//! `std::thread`s `Session::new` spawns — Linux copies the creating
//! thread's `comm` into a new one, so a plain thread spawned from a
//! worker is indistinguishable by name. Plus the main thread, seventeen
//! in all. Exactly **one** of the sixteen was running at every sample.
//!
//! So at most one of the twelve executor workers was doing anything,
//! which rules out both diagnoses that look obvious. It is not CPU
//! saturation — at least eleven workers were free — and it is not lock
//! contention, because `status` on an unrelated session shares no lock
//! with the read. A runtime whose every worker is parked has nobody left
//! in the I/O driver, so **one synchronous call in one handler stalls the
//! daemon's whole socket surface, accept loop included**. The `holdfast
//! list` row is that stall crossing a contract:
//! [`crate::protocol::handshake::HANDSHAKE_TIMEOUT`] is five seconds
//! because *"one frame each way between two local processes"* should
//! never take longer, and it is right about that — the frame was never
//! late, the daemon was never asked. (That bound is `handshake.rs`'s own
//! constant. The spec sets no handshake deadline at all, which is worth
//! knowing before citing §7.4 for it.)
//!
//! §5.2 already states the rule this module generalises, for the one path
//! that had learned it: *"one wedged session must not be able to consume
//! every worker in the server."*
//!
//! ## What it costs
//!
//! [`tokio::task::spawn_blocking`]'s **512 threads bound how many tasks
//! run, not how many are accepted, and the distinction is the whole
//! safety case.** Read from tokio 1.53.1's own source rather than from
//! its prose: `runtime/blocking/pool.rs` declares `queue: VecDeque<Task>`
//! with no capacity, and `spawn_task` does `shared.queue.push_back(task)`
//! **before** it looks at the thread cap — the at-cap arm is a bare
//! comment that falls through to `Ok(())`. `SpawnError` has exactly two
//! variants, `ShuttingDown` and `NoThreads`; there is no *"pool full"*.
//! So a saturated pool **queues, without limit**; it never refuses and it
//! never parks the runtime.
//!
//! ## What a queued call can still hold — and the two sites where that
//! is not nothing
//!
//! For `read_output` and `resources/read` the trade is clean: a queued
//! call holds no lock at all. `Session::read_processed` takes
//! `buffer.lock()` only to copy its window and releases it before the
//! first regex, so the worst those two can produce is a read that waits
//! while `status`, `list` and the accept loop keep answering.
//!
//! **`get_screen_state` and `resize` are not in that position, and an
//! earlier draft of this paragraph claimed they were.** Both hold
//! `Session::screen`'s lock across the whole of the work this module
//! moved — `screen_state` over `capture`, `resize` over `Screen::resize`,
//! re-seed included. The other consumers of that lock are on the
//! executor: `screen_tracking` and `cursor_signal`, reached from
//! `mcp::detection::with_detection`, which is the §5.4 block on
//! `read_output`, `send_input`, `wait_for_pattern`, **`status`** and
//! **`list_sessions`** — and `list_sessions` walks the registry, taking
//! every session's screen lock in turn. `holdfast list` is
//! `tool/list_sessions`, so it is the same canary as the table above.
//!
//! **Sized rather than alarmed about, because the numbers matter more
//! than the shape.** §4.2a measures the parser at ~86 MB/s, so the
//! largest seed `clamp_geometry` admits — 1000×1000×4 = 4 MiB — is ~46 ms
//! in release, and the sum is bounded by `limits.max_concurrent_sessions`
//! (default 8) because the lock is per session. That is sub-second
//! degradation of a control call, not GH #201's wedge, and it is **not a
//! regression**: before this module the holder of that lock was an
//! executor *worker*, which is strictly worse than a pool thread. What is
//! genuinely new is the count — the number of threads that can hold
//! per-session locks at once goes from the twelve workers to the pool's
//! bound.
//!
//! The same count argument, and the same verdict, applies to
//! `audit::AuditLog::record`, which the read path reaches for a
//! `redact: false` call: it takes one mutex, acquires no second one
//! inside it, and writes a single JSON line. Widening its waiters from
//! twelve to the pool's bound makes a convoy, not a stall — worth knowing
//! rather than worth changing.
//!
//! ## What the rest of the pool's occupants actually cost
//!
//! This paragraph claimed the other users were "transient" and it was
//! **half wrong**, so it is written out in full rather than summarised.
//!
//! * **The per-session PTY reader and writer are not on this pool at
//!   all.** They are raw `std::thread`s (`session::Session::new`),
//!   deliberately, so a session costs the pool nothing for its lifetime.
//!   This half is unconditional.
//! * **The secret providers return their thread, and by a stronger
//!   mechanism than a deadline.** There is no `tokio::time::timeout`
//!   around either hop. `secret::provider` runs a monotonic-clock poll
//!   loop that breaks on `ctx.is_cancelled()` or the deadline and then
//!   `kill_group`s the provider's whole process group, *inside* the
//!   blocking thread — so the thread finishes rather than being
//!   abandoned. What it can leave behind is two detached pipe readers,
//!   and those are `std::thread`s too.
//! * **`send_input`'s write is *answered* within `SEND_INPUT_TIMEOUT` but
//!   is not *bounded* by it.** `mcp::tools` wraps the `JoinHandle`, not
//!   the work; a `timeout` that elapses drops the handle and the pool
//!   thread stays parked on the fd. `tools.rs` says so at that very arm
//!   — *"that thread is still parked on the fd — and measurably stays
//!   parked even after the child is killed"* — and
//!   `pty::in_process::InProcessPty::write` says it from the other end:
//!   `WRITE_LOCK_TIMEOUT` bounds only `try_lock_for`, and the `write_all`
//!   after it has no deadline.
//!
//! What keeps that last one from multiplying is `WRITE_LOCK_TIMEOUT`
//! rather than `SEND_INPUT_TIMEOUT`: the parked writer holds the
//! session's writer lock, so the *next* write to the same wedged session
//! fails in two seconds instead of queueing behind it. One parked thread
//! per wedged write, not one per call — but those threads outlive the
//! session that made them, so over a long-lived daemon they accumulate.
//!
//! **That leak predates this module and is not repaired by it.** What
//! changed is the *shared fate*: before, exhausting the pool degraded
//! `send_input` and the secret paths only; now it takes the whole read
//! surface with it. Stating that plainly is the point of this section —
//! the headroom above is real, and it is headroom above a floor that
//! creeps.
//!
//! Measured, release build, all reads at the 256 KiB cap on one 1 MiB
//! buffer:
//!
//! | concurrent reads | daemon threads | `status` worst | `holdfast list` |
//! |---|---|---|---|
//! | 0 (baseline) | 18 | 5.14 ms | rc=0, 25.3 ms |
//! | 64 | 81 | 92.76 ms | rc=0 throughout, worst 533.7 ms |
//! | 256 | 273 | 210.23 ms | rc=0 throughout, worst 3,777 ms |
//!
//! Reaching 512 *running* needs 512 simultaneous in-flight tool calls —
//! one connection each, which is `protocol::client::ControlClient`'s
//! checkout pool and GH #127's doing, **not** something §7.4 says; past
//! that they queue rather than fail. What the 256 row shows is the trade working as
//! intended and not disappearing: the reads themselves degraded to
//! 59–144 s — twelve cores cannot do more — while the control plane
//! stayed answered. Before this change a **single** read failed it.
//!
//! ## What it deliberately does not fix
//!
//! **Work on the blocking pool cannot be cancelled** — the sentence
//! `send_input` has carried since 0.0.6. GH #127's
//! [`crate::request::CancelSignal`] reaches every tool and
//! `request_secret_input` is the only one that reads it; a cancelled read
//! stops being *awaited* and its scan runs to completion on a pool
//! thread.
//!
//! **That is not a regression, and the reason is worth stating once.** A
//! synchronous call in the middle of an `async fn` has no await point to
//! be dropped at either: before this module, a cancelled `read_output`
//! also ran its scan to the end, on a *worker* thread rather than a pool
//! one. Moving it changes which thread pays and nothing about what is
//! cancellable. Making these reads genuinely interruptible means a
//! cancellation check inside `OutputProcessor::process`, which is a
//! different change with a different test.

use rmcp::model::ErrorData;

/// Run `work` on the blocking pool and await the result.
///
/// `what` names the work in the one error this can produce, which is a
/// panic inside `work` — a Holdfast bug, so it takes the protocol
/// channel (§5.1) exactly as `send_input`'s join failure does rather
/// than being folded into a tool outcome. Inline, that panic unwound
/// through the connection task and the peer saw an unexplained EOF; as
/// an `internal_error` it says which stage died.
pub(crate) async fn off_runtime<T, F>(what: &'static str, work: F) -> Result<T, ErrorData>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|join| {
        ErrorData::internal_error(
            format!("{what} failed: {}", super::envelope::brief(&join)),
            None,
        )
    })
}

/// [`off_runtime`] for a caller with no error channel to answer on.
///
/// `run_wait` returns `(Status, Map)` and has no `Err` variant to carry
/// a join failure into, so this reproduces what the inline call already
/// did with a panic — it unwinds. That is the point rather than a
/// shortcut: inline, a panic inside `read_processed` unwound through the
/// connection task, `crate::diag::install_panic_hook` wrote it to
/// `daemon.log`, and the peer saw the connection end. Resuming the
/// unwind here keeps all three, so moving the work changes which thread
/// runs it and nothing a caller can observe.
///
/// Do not reach for this where an `ErrorData` fits. A named error beats
/// a dropped connection, which is why [`off_runtime`] is the default and
/// this is the exception with a reason.
pub(crate) async fn off_runtime_or_unwind<T, F>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(v) => v,
        Err(join) => match join.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            // Not a panic: the runtime is shutting down and took the
            // queued blocking task with it. `holdfast mcp` bounds that
            // window to `SHUTDOWN_GRACE`, so the process this is running
            // in is already on its way out and there is nobody left to
            // answer.
            Err(cancelled) => panic!("{cancelled}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole module exists for, asserted against the
    /// runtime rather than argued: while `off_runtime` is parked on a
    /// closure that never returns until it is told to, a
    /// `current_thread` runtime — one thread, no stealing, no slack —
    /// still drives another task to completion.
    ///
    /// **`current_thread` on purpose.** On a multi-thread runtime this
    /// row passes against the unfixed shape too, because eleven other
    /// workers pick the second task up; the single-threaded flavour is
    /// the only one where "the work left the executor" and "the work is
    /// merely somewhere else" have different answers.
    #[tokio::test]
    async fn work_on_the_pool_leaves_the_executor_free() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();

        let parked = tokio::spawn(off_runtime("a parked scan", move || {
            let _ = entered_tx.send(());
            // Blocks a *pool* thread, not a worker one. On the executor
            // this would be the whole runtime.
            release_rx
                .recv()
                .expect("the release channel outlives this");
            "done"
        }));

        entered_rx.await.expect("the closure reached the pool");
        // The claim: this resolves while the closure above is still
        // parked. It cannot on a runtime the closure is sitting on.
        tokio::task::yield_now().await;
        assert!(
            !parked.is_finished(),
            "the closure returned before it was released"
        );
        release_tx
            .send(())
            .expect("the pool thread is still waiting");
        assert_eq!(parked.await.expect("join").expect("no panic"), "done");
    }

    /// A panic on the pool is named, not an EOF.
    #[tokio::test]
    async fn a_panicking_closure_becomes_an_internal_error() {
        let err = off_runtime("a scan that panics", || panic!("boom"))
            .await
            .expect_err("a panicking closure must not report success");
        assert!(
            err.message.contains("a scan that panics"),
            "the error must name the stage: {}",
            err.message
        );
    }
}
