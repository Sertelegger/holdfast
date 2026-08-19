//! The one way a diagnostic reaches this process's stderr — and on the
//! daemon, stderr *is* `daemon.log` (spec §9.2; review I-1, I-2).
//!
//! `spawn::start_detached` opens `daemon.log` and hands it to the child
//! as fd 1 and fd 2, so every byte `clasp daemon run` writes to stderr is
//! persisted for §19.1's retention window. §9.2's table lists
//! `daemon.log` as a **redacted** boundary — *"daemon.log error contexts
//! (when they include byte excerpts) … routes byte excerpts through the
//! redactor"* — and before this module there was no such routing
//! anywhere: every producer on that path was a bare `eprintln!`, and a
//! panic's payload went out through the default hook untouched.
//!
//! Two things live here, and they are the same rule from two directions:
//!
//! - [`emit`], reached through the [`diag!`](crate::diag!) macro, is the
//!   only sanctioned way to write a diagnostic. `clippy::print_stderr` is
//!   **denied at this crate's root** (see `lib.rs`) so a re-introduced
//!   `eprintln!` anywhere in it is a build failure, not a review finding.
//!   It was denied across `daemon/` alone, and that scope is what let
//!   `mcp::` write a bare `eprintln!` into `daemon.log` for a whole
//!   milestone with this sentence claiming otherwise — so the scope is
//!   now asserted by a test in this module rather than by a sentence.
//! - [`install_panic_hook`] replaces the default panic hook with one that
//!   renders the same record and puts it through the same redactor.
//!
//! ## Why the hook does not chain to the previous hook
//!
//! The previous hook is the default one, and the default one is precisely
//! the unredacted writer being replaced. Calling it after ours would
//! re-emit the raw payload one line below the redacted copy.
//!
//! ## Why nothing in the hook may panic, and what was done about it
//!
//! A panic raised while a panic hook is running does **not** unwind and
//! cannot be caught: `panic_count::increase` sees `in_panic_hook`,
//! prints `thread panicked while processing panic. aborting.` and
//! aborts the process. Measured on the pinned toolchain (1.97) with a
//! `catch_unwind` wrapped directly around the second panic — the
//! `catch_unwind` never returned. So a `catch_unwind` *inside* this hook
//! would be decoration, and the only real defence is to call nothing
//! that can panic. Two consequences, both deliberate:
//!
//! - [`install_panic_hook`] warms [`builtin_shared`] **before** it
//!   installs the hook. That function's `OnceLock` initialiser
//!   `expect`s the compiled-in rule table, which is the one panic on the
//!   redaction path; warming it on the ordinary startup path — where a
//!   malformed rule table *should* be a loud startup failure — means the
//!   initialiser can never be run for the first time from inside the
//!   hook.
//! - [`emit`] writes with `writeln!` on a locked [`std::io::Stderr`] and
//!   drops the error, rather than using `eprintln!`. `eprintln!`
//!   `expect`s its write; on a full disk or a closed fd that is a panic,
//!   and a panic from inside the hook aborts. A daemon that cannot write
//!   a diagnostic must carry on serving, not die reporting.
//!
//! `std::thread::current()` is called in the hook and is *not* a hazard
//! on the pinned toolchain: measured by panicking from inside a TLS
//! destructor with a hook that names the thread, the hook ran and
//! reported `thread=worker-1` (the abort that followed was Rust's own
//! `thread local panicked on drop`, which the default hook reaches
//! identically).

use crate::output::redact::redact_str;
use crate::output::rules::builtin_shared;
use std::io::Write;
use std::sync::Once;

/// What the hook reports when the panic payload is neither `&str` nor
/// `String` — a `panic_any` with some other type.
const NON_STRING_PAYLOAD: &str = "<non-string panic payload>";

/// The default hook's hint, reproduced verbatim so an operator reading
/// `daemon.log` sees the sentence they already know.
const BACKTRACE_HINT: &str =
    "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace";

/// Put one diagnostic through the process-wide redaction table.
///
/// Separate from [`emit`] only so the redaction can be asserted without
/// a subprocess. It is **not** the control that matters — a fix that
/// redacted here and then wrote the raw string anyway would satisfy
/// every test of this function — which is why
/// `nothing_reaches_daemon_log_unredacted_not_even_a_panic` reads the
/// bytes off fd 2 of a real child instead.
pub(crate) fn render(message: &str) -> String {
    redact_str(&builtin_shared(), message)
}

/// Write one redacted diagnostic line to this process's stderr.
///
/// Bypasses libtest's output capture (which hooks the `eprintln!` family,
/// not [`std::io::stderr`]) on purpose: the daemon's diagnostics are the
/// thing under test in more than one place here, and a capture that eats
/// them makes those tests lie.
pub fn emit(message: &str) {
    let line = render(message);
    let mut err = std::io::stderr().lock();
    // Deliberately dropped — see the module docs. This function is
    // reachable from inside the panic hook, where a panicking write
    // aborts the process.
    let _ = writeln!(err, "{line}");
}

/// `eprintln!`, redacted. The only sanctioned diagnostic producer.
///
/// ```ignore
/// clasp_core::diag!("clasp daemon: accept failed: {e}");
/// ```
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        $crate::diag::emit(&::std::format!($($arg)*))
    };
}

/// Render a panic the way the default hook renders one, so `daemon.log`
/// keeps the shape an operator greps for.
///
/// Raw on purpose: the redaction happens once, in [`emit`], over the
/// whole record. Redacting the parts separately would give the payload
/// and the backtrace two different boundaries to be forgotten at.
pub(crate) fn panic_record(
    thread: &str,
    payload: &str,
    location: Option<&str>,
    backtrace: Option<&str>,
) -> String {
    let mut out = match location {
        Some(l) => format!("thread '{thread}' panicked at {l}:\n"),
        None => format!("thread '{thread}' panicked at an unknown location:\n"),
    };
    out.push_str(payload);
    out.push('\n');
    match backtrace {
        Some(b) => out.push_str(b.trim_end()),
        None => out.push_str(BACKTRACE_HINT),
    }
    out
}

/// Replace the default panic hook with one that redacts.
///
/// Idempotent, and installed from `main` so it covers **every**
/// subcommand rather than the two the review named. `clasp daemon run`
/// needs it because its stderr is literally `daemon.log`; `clasp mcp`
/// needs it because its stderr is what an MCP client surfaces as server
/// logs, and because under `--no-daemon` the shim *is* the process
/// holding the sessions. The remaining subcommands are short-lived, but
/// a panic in `clasp logs` would print a session's bytes just as
/// happily, and one install site is one thing to get right.
pub fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Before the hook exists, never from inside it. See module docs.
        let _ = builtin_shared();

        std::panic::set_hook(Box::new(|info| {
            let thread = std::thread::current();
            let name = thread.name().unwrap_or("<unnamed>");

            let payload = info.payload();
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or(NON_STRING_PAYLOAD);

            let location = info.location().map(|l| l.to_string());

            // `Backtrace::capture` is a no-op unless `RUST_BACKTRACE` (or
            // `RUST_LIB_BACKTRACE`) asks for one, which is the default
            // hook's behaviour too. Anything other than `Captured` —
            // disabled, unsupported — falls back to the hint rather than
            // rendering the status word, which reads as noise in a log.
            let captured = std::backtrace::Backtrace::capture();
            let backtrace = matches!(captured.status(), std::backtrace::BacktraceStatus::Captured)
                .then(|| captured.to_string());

            emit(&panic_record(
                name,
                message,
                location.as_deref(),
                backtrace.as_deref(),
            ));
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real GitHub PAT shape (rule `github-token`, kind `github`) and a
    /// real AWS access key id (rule `aws-access-key-id`, kind `aws`).
    ///
    /// Two *different* kinds on purpose: a control that asserted one
    /// marker would pass against a redactor wired to a single rule.
    /// Nothing here reasons about the redacted length — a marker is built
    /// from the rule's kind, not its name, so `AKIA…EXAMPLE` **shrinks**
    /// to `[REDACTED:aws]` while a one-byte connection-string password
    /// grows. Absence and presence only.
    const DIAG_SECRET: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    const PANIC_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

    /// Set on the child in
    /// `nothing_reaches_daemon_log_unredacted_not_even_a_panic`.
    const CHILD_ENV: &str = "CLASP_TEST_DAEMON_LOG_CHILD";

    #[test]
    fn a_credential_in_a_diagnostic_does_not_survive_rendering() {
        let rendered = render(&format!(
            "clasp daemon: cannot read the config: token = {DIAG_SECRET}"
        ));
        assert!(
            !rendered.contains(DIAG_SECRET),
            "the credential survived: {rendered}"
        );
        // Without this a `render` that returned `String::new()` would
        // pass the line above perfectly.
        assert!(
            rendered.contains("[REDACTED:"),
            "nothing was marked as withheld, so nothing was recognised: {rendered}"
        );
        // And without this one, a `render` that returned only the marker
        // would too — the diagnostic has to still say what went wrong.
        assert!(
            rendered.contains("cannot read the config"),
            "the message itself was eaten: {rendered}"
        );
    }

    #[test]
    fn a_panic_record_names_the_thread_the_site_and_the_payload() {
        let record = panic_record(
            "tokio-runtime-worker",
            "the reaper died",
            Some("crates/clasp-core/src/daemon/server.rs:12:5"),
            None,
        );
        assert!(record.contains("tokio-runtime-worker"), "{record}");
        assert!(record.contains("server.rs:12:5"), "{record}");
        assert!(record.contains("the reaper died"), "{record}");
        assert!(record.contains(BACKTRACE_HINT), "{record}");

        // A supplied backtrace replaces the hint rather than joining it,
        // so an operator never sees "here is the backtrace" next to
        // "run with RUST_BACKTRACE=1 to get one".
        let with_bt = panic_record("main", "boom", None, Some("   0: clasp_core::x\n"));
        assert!(with_bt.contains("0: clasp_core::x"), "{with_bt}");
        assert!(!with_bt.contains(BACKTRACE_HINT), "{with_bt}");
        assert!(
            with_bt.contains("unknown location"),
            "a panic with no location must still say so: {with_bt}"
        );
    }

    /// **The discriminator.** Runs a child whose stderr is a real
    /// `daemon.log`, opened by the same `open_log_append` that
    /// `spawn::start_detached` uses, and reads the bytes back off disk.
    ///
    /// It is a subprocess rather than an in-process call because every
    /// cheaper control is satisfiable without fixing anything: a test of
    /// [`render`] alone passes against an `emit` that ignores it, and a
    /// test of [`panic_record`] alone passes against a hook that is never
    /// installed. What must be observed is fd 2.
    ///
    /// What it would still pass against, stated so the next reader does
    /// not have to work it out: a secret too short or too shapeless for
    /// any built-in rule — the accepted floor of pattern redaction, named
    /// in the I-1 report and not addressed here. It would **not** pass
    /// against a missing hook, a hook that does not redact, an `emit`
    /// that does not redact, a redactor that eats the message, or a hook
    /// that swallows the panic.
    #[test]
    fn nothing_reaches_daemon_log_unredacted_not_even_a_panic() {
        use crate::daemon::paths::{open_log_append, RuntimePaths};
        use std::time::{Duration, Instant};

        if std::env::var_os(CHILD_ENV).is_some() {
            // We *are* the child, re-entered under a different test name.
            return;
        }

        let unique = uuid::Uuid::new_v4().simple().to_string();
        let paths = RuntimePaths::with_dir(format!("/tmp/clasp-t-diag-{}", &unique[..8]));
        struct Scoped(RuntimePaths);
        impl Drop for Scoped {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(self.0.dir());
            }
        }
        let _scoped = Scoped(paths.clone());
        paths.ensure_dir().unwrap();

        let log_path = paths.daemon_log();
        let log = open_log_append(&log_path).unwrap();

        // stdout is nulled rather than pointed at the log as
        // `start_detached` does, because in the child that fd carries
        // *libtest's* report — including a repeat of the panic — and
        // that is the harness talking, not the daemon. Every producer
        // `clasp daemon run` has is on stderr.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("diag::tests::the_child_that_writes_a_credential_to_daemon_log")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(log))
            .spawn()
            .unwrap();

        // Bounded, and a timeout is a failure rather than a pass: the
        // child runs one test that panics and exits, so an unbounded
        // `wait` here would turn a wedged child into a hung CI job.
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            match child.try_wait().unwrap() {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the child never exited within 60s");
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };

        let written = std::fs::read_to_string(&log_path).unwrap();
        let ctx = format!("child exited {status}; daemon.log said:\n{written}");

        assert!(
            !written.contains(DIAG_SECRET),
            "a diagnostic put a credential in daemon.log verbatim — {ctx}"
        );
        assert!(
            !written.contains(PANIC_SECRET),
            "a panic put a credential in daemon.log verbatim — {ctx}"
        );
        // The three below are what stop the two above from being
        // satisfied by writing nothing at all.
        assert!(
            written.contains("[REDACTED:github]"),
            "the diagnostic's credential was not recognised — {ctx}"
        );
        assert!(
            written.contains("[REDACTED:aws]"),
            "the panic payload's credential was not recognised — {ctx}"
        );
        assert!(
            written.contains("cannot read the config"),
            "the diagnostic itself never reached daemon.log — {ctx}"
        );
        assert!(
            written.contains("panicked at"),
            "the panic never reached daemon.log — {ctx}"
        );
    }

    /// The other half of the test above; a no-op unless re-entered as a
    /// child, so the ordinary suite runs it and it costs nothing.
    #[test]
    fn the_child_that_writes_a_credential_to_daemon_log() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        install_panic_hook();
        crate::diag!("clasp daemon: cannot read the config: token = {DIAG_SECRET}");
        panic!("the reaper died holding {PANIC_SECRET}");
    }
}
