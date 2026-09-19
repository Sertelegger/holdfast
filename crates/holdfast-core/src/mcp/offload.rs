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
//! shipped wire — one daemon, twelve worker threads, one in-flight
//! `read_output`, everything else idle:
//!
//! | sampled during one large read | observed |
//! |---|---|
//! | daemon worker threads in `R` | **1** of 12 |
//! | daemon worker threads in `S` | 15 (incl. the blocking pool's) |
//! | `status` on an *unrelated* session, second client | **3,546 ms** (baseline 5–27 ms) |
//! | `holdfast list`, a third client | **rc=2 at 5,014 ms** |
//!
//! One running thread and fifteen asleep rules out both the diagnoses
//! that look obvious. It is not CPU saturation — eleven workers were
//! free — and it is not lock contention, because `status` on an unrelated
//! session shares no lock with the read. A runtime whose every worker is
//! parked has nobody left in the I/O driver, so **one synchronous call in
//! one handler stalls the daemon's whole socket surface, accept loop
//! included**. The `holdfast list` row is that stall crossing a contract:
//! [`crate::protocol::handshake::HANDSHAKE_TIMEOUT`] is five seconds
//! because *"one frame each way between two local processes"* should
//! never take longer, and it is right about that — the frame was never
//! late, the daemon was never asked.
//!
//! §5.2 already states the rule this module generalises, for the one path
//! that had learned it: *"one wedged session must not be able to consume
//! every worker in the server."*
//!
//! ## What it costs
//!
//! [`tokio::task::spawn_blocking`] is a **bounded** pool — 512 threads by
//! default, which nothing in this workspace overrides — and it is shared
//! with `send_input`'s write, both secret providers, and the PTY worker's
//! reader and writer. A saturated pool **queues**; it does not park the
//! runtime. So the worst this trade can produce is a read that waits for
//! a pool thread, while `status`, `list` and the accept loop keep
//! answering — which is the failure the whole exchange is for. Measured
//! at 64 concurrent 256 KiB reads the pool never came close: see the
//! `control_protocol` row that pins it.
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
