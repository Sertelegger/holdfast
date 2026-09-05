//! The per-session daemon ↔ worker listener: bind before spawn, `0600`,
//! and the identity machinery that already exists (§4.1, §7.1, §7.7,
//! REQ-SPTY-004).
//!
//! # The ordering rule, which is the only non-obvious thing here
//!
//! **The daemon binds and listens *before* it spawns the worker.** The
//! other way round — worker binds, daemon polls for the path to appear —
//! is the readiness race §7.3 spent a whole subsection eliminating for
//! the daemon itself, and it reads identically whether the worker is
//! slow, wedged, or was never executable in the first place. Binding
//! first turns "did the worker start" into a bounded
//! [`accept`](WorkerSocket::accept_worker) with a deadline, and a
//! deadline that elapses is `spawn_failed` — a §18.1 status that already
//! exists. **0.0.10a adds no status value** (REQ-SPTY-001), which is why
//! [`AcceptError`] converts into [`HoldfastError::Pty`] and not into
//! anything new: `Pty` is what `InProcessPty::spawn` returns for every
//! one of its failures, so `start_session` reaches the same
//! `Status::SpawnFailed` arm without knowing which backend it asked.
//!
//! # Nothing here is re-derived, and that is the point
//!
//! [`daemon::server::bind_socket_within`] does the whole of it —
//! `0700`-verified parent, `bind.lock`, the stale-socket probe, the
//! `chmod` **followed by a re-read of the mode**, the four-field
//! [`SocketIdentity`] and the inert `O_PATH` pin. Every one of those is
//! load-bearing and two of them are load-bearing against a *measurement*:
//! ext4 handed a successor its predecessor's freed inode number 500 times
//! out of 500, and the pin is what stops it. A worker socket that grew
//! its own copy of that reasoning would be a second place for it to go
//! wrong, on the socket that carries the raw PTY stream.
//!
//! [`SocketIdentity`]: crate::daemon::server::SocketIdentity
//! [`daemon::server::bind_socket_within`]: crate::daemon::server
//!
//! # Unix only, and it is the module that is gated rather than its parts
//!
//! `daemon::server` became `#[cfg(unix)]` in the GH #19 Windows work, so
//! `bind_socket_within`, `SocketIdentity` and `OwnedSocket` are Unix-only
//! symbols. This module is gated at its declaration in
//! [`super`](crate::pty::worker) for that reason, and
//! [`frames`](super::frames) deliberately is not: the catalogue is a
//! serde definition with no platform in it, and gating it would take the
//! worker protocol's *types* off a Windows build to satisfy a dependency
//! only this file has. 0.0.10a ships no Windows code and REQ-CFG-007
//! defaults Windows to `in_process` until 0.0.11; **0.0.11 has to decide
//! where this machinery lives once Windows needs it**, and Windows 10+
//! supports `AF_UNIX`, so the likely answer is *ungate `daemon::server`*
//! rather than *write a second one*.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};

use crate::daemon::paths::RuntimePaths;
use crate::daemon::peer;
use crate::daemon::server::{bind_socket_within, OwnedSocket};
use crate::daemon::spawn::LOCK_TIMEOUT;
use crate::HoldfastError;

/// How long the daemon waits for the worker it just spawned to connect.
///
/// **5 s, which is [`LOCK_TIMEOUT`] and
/// [`HANDSHAKE_TIMEOUT`](crate::protocol::handshake::HANDSHAKE_TIMEOUT)
/// again, on purpose.** A daemon whose "something local should have
/// answered by now" deadline has one value is one an operator can reason
/// about; three values differing by a second each are three numbers
/// nobody can defend. It is not a spawn budget — the worker's only work
/// before connecting is `execve` plus one `connect(2)` on a socket that
/// is already listening — so the whole 5 s is slack, and a worker that
/// needs more of it than `holdfast daemon start` needs to see a socket
/// appear (`SPAWN_TIMEOUT`, 2 s) has not started.
pub const WORKER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Why the daemon gave up waiting for its worker.
///
/// **Two variants and no `WrongPeer`, deliberately.** A connection from
/// the wrong process is not a failure of the accept — it is a stranger
/// that gets dropped while the deadline keeps running, because the
/// scenario the peer check exists for is *some other local process got
/// here first* and returning an error would hand that process the
/// session-kill it was reaching for. See
/// [`accept_worker`](WorkerSocket::accept_worker).
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    /// Nobody the daemon was willing to talk to connected in time.
    ///
    /// **This is the `spawn_failed` arm and it is the reason the accept
    /// is bounded at all.** Unbounded, a worker that never `execve`d
    /// leaves `start_session` awaiting a connection that cannot arrive,
    /// on a task holding the session's registry slot.
    #[error("no worker connected within {0:?}")]
    TimedOut(Duration),
    /// The listener itself failed. Distinct from
    /// [`TimedOut`](Self::TimedOut) because they call for opposite
    /// responses from a reader of the log: one is a worker that did not
    /// start, the other is a daemon whose socket has gone.
    #[error("worker socket accept failed: {0}")]
    Io(#[from] io::Error),
}

/// **The one mapping, and REQ-SPTY-001 is why it exists.**
///
/// `Pty` is the variant `InProcessPty::spawn` returns for *every* one of
/// its failures — `openpty`, `spawn`, `clone reader`, `take writer` —
/// and `start_session` turns a spawn `Err` into `Status::SpawnFailed`
/// without inspecting it. Landing worker-side failures in the same
/// variant is what lets the backend seam stay invisible above the trait:
/// the caller sees the status it already had for a PTY that could not be
/// opened, and 0.0.10a adds no status, no field, and no second error
/// type for the agent to learn.
impl From<AcceptError> for HoldfastError {
    fn from(e: AcceptError) -> Self {
        HoldfastError::Pty(e.to_string())
    }
}

/// A bound, listening, `0600` socket for exactly one session's worker.
///
/// Created **before** the worker is spawned; dropped when the session is
/// gone, at which point [`remove_if_ours`](Self::remove_if_ours) unlinks
/// the path if and only if it still names the file this bound.
#[derive(Debug)]
pub struct WorkerSocket {
    path: PathBuf,
    listener: UnixListener,
    /// The four-field identity plus the `O_PATH` pin, taken by
    /// `bind_socket_within` under `bind.lock` against the file it just
    /// created. Never reconstructed here — an identity read after the
    /// lock was released is an identity of whatever the path names now.
    owned: OwnedSocket,
    /// The daemon's own euid, recorded at bind so the peer check has
    /// something to compare against that does not depend on the
    /// environment at accept time.
    our_uid: u32,
}

impl WorkerSocket {
    /// Bind `<runtime>/workers/<session_id>.sock`, `0600`, verified.
    ///
    /// # Neither `holdfast.lock` nor `bind.lock` is taken *here*, and the
    /// # omission is deliberate
    ///
    /// State it, because an unexplained missing lock reads as an
    /// oversight and gets "fixed":
    ///
    /// * **`bind.lock` protects a well-known path from a second binder.**
    ///   Its whole job is to make `control.sock`'s probe → unlink → bind
    ///   window atomic against another *daemon* racing for the same name.
    ///   A worker socket's name is a server-generated `sess_<12 hex>`
    ///   from [`crate::session::new_session_id`], handed out by the one
    ///   daemon that owns the registry: there is no second binder for
    ///   this path, and therefore no probe → unlink window to protect.
    /// * **`holdfast.lock` serialises daemon *starters*.** A session
    ///   start is not one, and `start_detached` holds it across a spawn
    ///   and a readiness poll — which is exactly the deadlock
    ///   [`RuntimePaths::bind_lock_file`] documents and the reason the
    ///   two locks are two files.
    ///
    /// **The tree does not let that be literally true, and pretending it
    /// does would be worse than saying so.** `bind_socket_within` takes
    /// `bind.lock` itself, for the duration of one bind, and the
    /// alternative — a second copy of the probe/chmod/verify/identity/pin
    /// sequence with the lock left out — trades a lock this call does not
    /// need for a duplicate of the code that is measured. So the honest
    /// claim is narrower than "no lock" and is the one that matters: **no
    /// lock is held across the spawn or the accept.** The window
    /// `bind.lock` is contended for here is one `bind(2)` wide, not one
    /// session long.
    ///
    /// **Two consequences for whoever wires this into `start_session`**
    /// (Task 12, not this task):
    ///
    /// 1. This function is **synchronous, must be called from inside a
    ///    Tokio runtime, and can block for up to [`LOCK_TIMEOUT`]** on a
    ///    contended `bind.lock` — an awkward trio, and all three are
    ///    inherited from `bind_socket_within` rather than chosen here.
    ///    The runtime requirement is not obvious from the signature: the
    ///    listener it returns is a `tokio::net::UnixListener`, whose
    ///    `bind` registers with the reactor and panics with *"there is no
    ///    reactor running"* outside one. Measured, by writing this
    ///    module's first three rows as plain `#[test]`s. The blocking
    ///    half is the same shape `bind_control` has, and `bind_control`
    ///    gets away with it by running once at startup, before there is a
    ///    runtime to starve.
    /// 2. Concurrent `start_session` calls serialise against each other
    ///    for that window. Measured against nothing, because nothing
    ///    calls this yet; it is written down so the first person to see
    ///    it in a profile knows it was seen rather than missed.
    pub fn bind(paths: &RuntimePaths, session_id: &str) -> io::Result<Self> {
        // `workers/` before the bind, and `0700`-verified rather than
        // merely created: `create_dir_all` succeeds on an existing
        // directory whatever its permissions, so an inherited `0755`
        // would leave every socket below it reachable by any local user.
        // `bind_socket_within` calls `ensure_dir` for the *runtime*
        // directory and knows nothing about this subdirectory, so the
        // parent it is about to bind inside would not otherwise be
        // checked at all.
        paths.ensure_worker_dir()?;
        let path = paths.worker_sock(session_id);
        let (listener, owned) = bind_socket_within(paths, path.clone(), LOCK_TIMEOUT)?;
        Ok(Self {
            path,
            listener,
            owned,
            our_uid: peer::current_uid(),
        })
    }

    /// The path a worker is told to connect to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The uid this socket was bound as — the one the peer check
    /// demands, and the one REQ-SPTY-004's ownership assertion is about.
    pub fn owner_uid(&self) -> u32 {
        self.our_uid
    }

    /// Wait for the worker at `worker_pid` to connect, under
    /// [`WORKER_ACCEPT_TIMEOUT`].
    ///
    /// # A stranger is dropped, not returned as an error
    ///
    /// `attach.sock` already establishes the peer-credential precedent
    /// (§7.5): read the peer's uid and refuse anyone who is not the
    /// owner. This adds pid equality on top, because uniquely here the
    /// daemon knows exactly which process it is expecting — it spawned
    /// it — and "some other local process connected to the listener
    /// first" is otherwise a way to take a session's worker slot.
    ///
    /// **First is the operative word, and it is why the loop continues
    /// rather than returning.** A refusal that ended the accept would
    /// mean any local process that can `connect(2)` to the path can kill
    /// a starting session by getting there before the worker does —
    /// turning a check that exists to stop an impostor into a cheaper
    /// denial of service than the one it prevents. The stranger's stream
    /// is dropped (it sees EOF), the deadline keeps running, and the
    /// worker that does arrive is still accepted.
    ///
    /// # What "the peer" means per platform
    ///
    /// `peer_cred` reports a pid from `SO_PEERCRED` on Linux and `None`
    /// everywhere else, where it is `getpeereid` and there is no pid to
    /// report. So the pid equality is **Linux-only in force**, and
    /// elsewhere this degrades to the uid check `attach.sock` already
    /// has. §7.1's `0700` directory and the socket's own `0600` are the
    /// controls that hold on every platform; the pid is defence in depth
    /// on the one that offers it. Adding macOS's `LOCAL_PEERPID` would
    /// mean a `getsockopt` in `daemon::peer` that **no CI job in this
    /// repository compiles, let alone runs** — every job is
    /// `ubuntu-24.04` — so it is named here as a gap rather than written
    /// unverifiably.
    ///
    /// A `peer_cred` that fails at all is refused: a daemon that cannot
    /// read a peer's credentials knows nothing about that peer, and
    /// "unknown" is not "the worker I spawned". That is
    /// `peer_is_authorized`'s rule in `daemon::server`, kept the same way
    /// here.
    pub async fn accept_worker(&self, worker_pid: u32) -> Result<UnixStream, AcceptError> {
        self.accept_worker_within(worker_pid, WORKER_ACCEPT_TIMEOUT)
            .await
    }

    /// [`accept_worker`](Self::accept_worker) with the deadline supplied,
    /// so a test can observe a refusal without paying
    /// [`WORKER_ACCEPT_TIMEOUT`] — the same reason `bind_control_within`
    /// and `acquire_bind_within` exist beside their defaults.
    ///
    /// `pub` rather than `pub(crate)`, unlike those two, because this
    /// module's tests are `tests/worker_protocol.rs` and an integration
    /// test is a separate crate. The row that matters —
    /// `a_worker_that_never_connects_becomes_spawn_failed_not_a_hang` —
    /// deliberately calls [`accept_worker`](Self::accept_worker) and pays
    /// the real 5 s, because a timeout row that supplies its own timeout
    /// asserts the parameter and not the constant.
    pub async fn accept_worker_within(
        &self,
        worker_pid: u32,
        timeout: Duration,
    ) -> Result<UnixStream, AcceptError> {
        // **The one wait in this module, and it is bounded.** There is a
        // `terminate-after` in `.config/nextest.toml` now, so a hang here
        // would be named rather than fatal — but that is a property of
        // how the suite is run, not of the daemon, and the daemon is the
        // process that must not park a session start forever.
        match tokio::time::timeout(timeout, self.accept_authorized(worker_pid)).await {
            Ok(accepted) => accepted,
            Err(_elapsed) => Err(AcceptError::TimedOut(timeout)),
        }
    }

    /// Accept until the peer is the one we spawned. Unbounded on its own;
    /// every caller wraps it in a deadline.
    async fn accept_authorized(&self, worker_pid: u32) -> Result<UnixStream, AcceptError> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            match self.authorize(&stream, worker_pid) {
                Ok(()) => return Ok(stream),
                Err(why) => {
                    // Dropped at the end of this arm, which is the
                    // refusal: the stranger's `read` returns EOF.
                    drop(stream);
                    // Loud, because a socket at `0600` inside a `0700`
                    // directory is not somewhere a stranger arrives by
                    // accident. Redacted, like every other `diag!`, and
                    // carrying no byte that came off the wire — nothing
                    // has been read from this stream and nothing will be.
                    crate::diag!(
                        "holdfast daemon: refused a connection on {}: {why}",
                        self.path.display()
                    );
                }
            }
        }
    }

    /// Whether `stream`'s peer is the worker at `worker_pid`. `Err`
    /// carries a reason for the log and never a byte from the peer.
    fn authorize(&self, stream: &UnixStream, worker_pid: u32) -> Result<(), String> {
        let cred = peer::peer_cred(stream)
            .map_err(|e| format!("the peer's credentials could not be read: {e}"))?;
        if !peer::is_authorized(cred.uid, self.our_uid) {
            return Err(format!("uid {} is not {}", cred.uid, self.our_uid));
        }
        match cred.pid {
            // The comparison is through `i64` rather than a cast in
            // either direction: `ucred.pid` is an `i32` and a worker pid
            // is a `u32`, so casting either way makes some value compare
            // equal to a value it is not.
            Some(pid) if i64::from(pid) == i64::from(worker_pid) => Ok(()),
            Some(pid) => Err(format!("pid {pid} is not the worker at {worker_pid}")),
            // Not Linux: `getpeereid` has no pid to give and the uid
            // check above is the whole of the answer. See the platform
            // note on `accept_worker`.
            None => Ok(()),
        }
    }

    /// Unlink the socket **only while its identity still matches**, and
    /// report whether it did.
    ///
    /// `remove_runtime_files_we_own`'s discipline, for the same reason:
    /// a path whose inode has changed underneath us names somebody
    /// else's socket, and unlinking it is precisely the bug the identity
    /// machinery exists to prevent. Every way the comparison can fail —
    /// the path is gone, the `stat` errors, the pin's `fstat` errors —
    /// fails closed, which here means *leave the file alone*.
    ///
    /// **No `bind.lock`, and unlike [`bind`](Self::bind) that is not
    /// narrowed by anything.** `remove_runtime_files_we_own` takes it
    /// because it is racing a *successor daemon* for `control.sock`; a
    /// worker socket's successor would have to be a second session with
    /// the same server-generated id.
    ///
    /// Idempotent: a second call finds the path gone and does nothing,
    /// which is what makes it safe to call explicitly and again from
    /// [`Drop`].
    pub fn remove_if_ours(&self) -> bool {
        if !self.owned.still_at(&self.path) {
            return false;
        }
        std::fs::remove_file(&self.path).is_ok()
    }
}

impl Drop for WorkerSocket {
    /// **The unlink is on `Drop` rather than only on an explicit
    /// teardown call**, because the failure being prevented is a
    /// `workers/` directory that accumulates one dead socket per session
    /// for the life of the daemon, and the paths that would forget to
    /// call it are the interesting ones: a `start_session` that fails
    /// after the bind, and a worker that never connects. Both drop this
    /// value on the way out and neither has a teardown path of its own.
    fn drop(&mut self) {
        self.remove_if_ours();
    }
}
