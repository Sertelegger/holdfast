//! Daemon auto-spawn and the start lock (spec §7.3, §3.4).
//!
//! The sequence, which REQ-D-005 names verbatim: acquire `clasp.lock` →
//! re-check (another shim may have won the race) → fork-detach →
//! poll up to 2 s for the socket.

use super::paths::RuntimePaths;
use super::server;
use crate::protocol::client::{ClientError, ControlClient};
use crate::protocol::handshake::ClientKind;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

/// How long to wait for a freshly-spawned daemon's socket (§7.3 step 3).
pub const SPAWN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait for `clasp.lock` before giving up.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// An exclusive `flock` on `clasp.lock`, released on drop.
pub struct DaemonLock {
    file: std::fs::File,
}

impl DaemonLock {
    /// Acquire the lock, retrying until [`LOCK_TIMEOUT`].
    ///
    /// Non-blocking + poll rather than a blocking `LOCK_EX`: a wedged
    /// holder must not hang the MCP shim's startup forever.
    pub fn acquire(paths: &RuntimePaths) -> io::Result<Self> {
        Self::acquire_within(paths, LOCK_TIMEOUT)
    }

    /// [`acquire`](Self::acquire) with the deadline supplied.
    ///
    /// Private, and it exists for the tests rather than for a caller.
    /// With only the 5 s constant, an `acquire` that gave up on the
    /// *first* `EWOULDBLOCK` would be indistinguishable from this one —
    /// a contended probe returns `Err` either way — so the retry loop
    /// that §7.3's re-check depends on would ship unasserted. It also
    /// keeps the contended probe from paying the full 5 s to learn
    /// nothing. See `a_contended_acquire_retries_until_the_holder_releases`.
    fn acquire_within(paths: &RuntimePaths, timeout: Duration) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        paths.ensure_dir()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(paths.lock_file())?;

        let deadline = Instant::now() + timeout;
        loop {
            // SAFETY: `file` owns a live fd for the duration of the call.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(Self { file });
            }
            let err = io::Error::last_os_error();
            // `EWOULDBLOCK` and `EAGAIN` are the same value on Linux but
            // are permitted to differ; matching both keeps the retry from
            // silently becoming a hard failure on a platform where they
            // do (§7.3's re-check depends on this loop actually looping).
            let contended = matches!(
                err.raw_os_error(),
                Some(e) if e == libc::EWOULDBLOCK || e == libc::EAGAIN
            );
            if !contended || Instant::now() >= deadline {
                return Err(err);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        // SAFETY: same live fd; unlocking a lock we hold cannot fail in a
        // way we could act on.
        //
        // Dropping `file` would release the lock on its own — closing the
        // last fd on an open file description drops its `flock` — so this
        // is explicit rather than load-bearing, and no test here
        // discriminates it. It states the intent at the point the lock
        // ends, which is where a reader looks for it.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Whether a daemon is answering on `control.sock` right now.
///
/// A plain `connect` — not a handshake. This is a liveness probe used to
/// decide whether to spawn; version compatibility is decided later, by
/// the real client, and conflating the two would make a
/// version-mismatched daemon look absent and get a second one spawned
/// on top of it.
pub fn socket_is_live(paths: &RuntimePaths) -> bool {
    std::os::unix::net::UnixStream::connect(paths.control_sock()).is_ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartOutcome {
    AlreadyRunning { pid: Option<u32> },
    Started { pid: u32 },
}

/// Start a detached `clasp daemon run` and wait for it to answer.
///
/// This is the body of `clasp daemon start`. The detach is a genuine
/// double fork: this process `setsid`s and spawns the daemon, then
/// exits, so the daemon is re-parented to init and no zombie survives.
pub fn start_detached(paths: &RuntimePaths, exe: &Path) -> io::Result<StartOutcome> {
    use std::os::unix::process::CommandExt;

    paths.ensure_dir()?;
    let _lock = DaemonLock::acquire(paths)?;

    // Re-check under the lock: another shim may have raced us here and
    // already started one (§7.3 step 2).
    if socket_is_live(paths) {
        return Ok(StartOutcome::AlreadyRunning {
            pid: server::read_pid_file(paths),
        });
    }

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.daemon_log())?;
    let log_err = log.try_clone()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon")
        .arg("run")
        .env(super::paths::RUNTIME_DIR_ENV, paths.dir())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    // SAFETY: `setsid` is async-signal-safe and allocates nothing. It
    // detaches the daemon from this process's controlling terminal so a
    // Ctrl-C in the user's shell cannot reach it.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();

    let deadline = Instant::now() + SPAWN_TIMEOUT;
    while Instant::now() < deadline {
        if socket_is_live(paths) {
            return Ok(StartOutcome::Started { pid });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    // The daemon never answered. Reap it if it has already died, so a
    // failed start does not leave a zombie behind for the lifetime of
    // whatever called us.
    let _ = child.try_wait();
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "daemon (pid {pid}) did not answer on {} within {}s — see {}",
            paths.control_sock().display(),
            SPAWN_TIMEOUT.as_secs(),
            paths.daemon_log().display()
        ),
    ))
}

/// The shim's startup path (§3.4): connect, or spawn and connect.
///
/// The spawn goes through `clasp daemon start` rather than forking here,
/// so this process's direct child is short-lived and reaped by `status()`
/// — the second fork of the double fork. `daemon start` holds the lock
/// and does the re-check.
pub async fn ensure_daemon(
    paths: &RuntimePaths,
    exe: &Path,
    kind: ClientKind,
) -> Result<ControlClient, ClientError> {
    let sock = paths.control_sock();
    match ControlClient::connect(&sock, kind).await {
        Ok(c) => return Ok(c),
        // Only "nobody is listening" justifies a spawn. A refusal — a
        // protocol-major mismatch, above all — must surface, not trigger
        // a second daemon on top of the first.
        Err(e) if !matches!(e, ClientError::Connect { .. }) => return Err(e),
        Err(_) => {}
    }

    let status = std::process::Command::new(exe)
        .arg("daemon")
        .arg("start")
        .env(super::paths::RUNTIME_DIR_ENV, paths.dir())
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|source| ClientError::Connect {
            path: exe.display().to_string(),
            source,
        })?;
    if !status.success() {
        return Err(ClientError::Connect {
            path: sock.display().to_string(),
            source: io::Error::other(format!(
                "`clasp daemon start` exited with {status}; see {}",
                paths.daemon_log().display()
            )),
        });
    }

    ControlClient::connect(&sock, kind).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(tag: &str) -> RuntimePaths {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        RuntimePaths::with_dir(format!("/tmp/clasp-t-{tag}-{}", &unique[..8]))
    }

    struct Scoped(RuntimePaths);
    impl Drop for Scoped {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.dir());
        }
    }

    #[test]
    fn the_lock_is_exclusive_while_held_and_free_after() {
        let paths = temp_paths("lock");
        let _scoped = Scoped(paths.clone());

        let held = DaemonLock::acquire(&paths).unwrap();
        // A second `flock` from this same process would *succeed* (flock
        // is per open-file-description, and re-locking the same
        // description is a no-op), so the contention has to come from a
        // separate fd — which is what a second `acquire` opens.
        //
        // The short deadline is the only reason this uses
        // `acquire_within`: with `LOCK_TIMEOUT` the contended probe would
        // spin the full 5 s before answering, and the answer is the same
        // either way. That the loop *does* spin is the next test's job.
        let contended = DaemonLock::acquire_within(&paths, Duration::from_millis(50));
        assert!(
            contended.is_err(),
            "a second acquire must not get the lock while the first is held"
        );

        drop(held);
        DaemonLock::acquire(&paths).expect("the lock must be free once dropped");
    }

    #[test]
    fn a_contended_acquire_retries_until_the_holder_releases() {
        // §7.3's re-check is written against a lock that *waits*: two
        // shims racing to start a daemon must serialise, not have the
        // loser fail outright and report that no daemon could be
        // started. Nothing else here discriminates the retry — a
        // contended `acquire` answers `Err` whether the loop runs once or
        // two hundred times — so this is the only test that goes red if
        // the `std::thread::sleep`/`continue` path is removed and
        // `EWOULDBLOCK` becomes a hard failure.
        let paths = temp_paths("lockwait");
        let _scoped = Scoped(paths.clone());

        let held = DaemonLock::acquire(&paths).unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(held);
        });

        let started = Instant::now();
        let won = DaemonLock::acquire_within(&paths, LOCK_TIMEOUT);
        let waited = started.elapsed();
        releaser.join().unwrap();

        assert!(
            won.is_ok(),
            "acquire must wait out a holder that releases within the timeout: {:?}",
            won.err()
        );
        // The positive alone would also pass if the lock were never taken
        // at all — an `acquire` with the `flock` call deleted returns
        // instantly and succeeds. It cannot have been instant: the holder
        // was still holding for the first 150 ms.
        assert!(
            waited >= Duration::from_millis(100),
            "the lock was handed over in {waited:?}, which is faster than the \
             holder released it — it was never actually held"
        );
    }

    #[test]
    fn the_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let paths = temp_paths("lockmode");
        let _scoped = Scoped(paths.clone());
        let _held = DaemonLock::acquire(&paths).unwrap();
        let mode = std::fs::metadata(paths.lock_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "lock file is mode {mode:o}");
    }

    #[test]
    fn socket_is_live_is_false_when_nothing_is_listening() {
        let paths = temp_paths("nolisten");
        let _scoped = Scoped(paths.clone());
        paths.ensure_dir().unwrap();
        assert!(!socket_is_live(&paths));
    }

    #[test]
    fn socket_is_live_answers_only_for_the_control_socket() {
        // The negative above is satisfied by a probe that answers `false`
        // unconditionally, and by one that probes the wrong path. Both
        // mutants are live bugs with the same symptom: `ensure_daemon`
        // spawns a second daemon on top of a running one, or
        // `start_detached`'s re-check never fires and the two racing
        // shims both start one.
        let paths = temp_paths("live");
        let _scoped = Scoped(paths.clone());
        paths.ensure_dir().unwrap();
        assert!(!socket_is_live(&paths), "nothing is listening yet");

        // A listener on a *different* socket in the same directory must
        // not count. `attach.sock` is bound for real in 0.0.6, and a
        // probe that matched it would report a daemon that is not there.
        let attach = std::os::unix::net::UnixListener::bind(paths.attach_sock()).unwrap();
        assert!(
            !socket_is_live(&paths),
            "attach.sock is not control.sock; the probe must name the socket it means"
        );
        drop(attach);
        let _ = std::fs::remove_file(paths.attach_sock());

        let control = std::os::unix::net::UnixListener::bind(paths.control_sock()).unwrap();
        assert!(
            socket_is_live(&paths),
            "a bound control.sock must read as live"
        );
        drop(control);
    }
}
