//! `attach.sock` (spec §7.2, §7.5). Same permissions, same peer check
//! and the same accept shape as `control.sock` — a different protocol on
//! top, which is the whole point of §23.2 separating the two milestones.
//!
//! **Unix-domain only, and that is REQ-D-001, not a default.** Nothing
//! in this file opens a `TcpListener`, and
//! `the_daemon_binds_only_unix_sockets_and_not_http` scans this
//! process's fd table against `/proc/net/tcp{,6}` with the attach
//! listener bound, so the absolute claim is checked against the kernel
//! rather than against this comment.

use std::io;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use super::paths::RuntimePaths;
use super::peer;
use super::server::{bind_socket, Daemon, OwnedSocket};

/// Bind `attach.sock`, `0600`, under the same `0700` runtime directory
/// and the same `bind.lock` as `control.sock`.
///
/// The [`OwnedSocket`] comes back for the same reason the control
/// socket's does: §7.3's teardown removes **both** sockets, and it must
/// be able to tell this daemon's from a successor's. See
/// [`bind_socket`]'s note on why the `(dev, ino, ctime)` + `O_PATH`
/// identity is not optional on the second socket either.
pub fn bind_attach(paths: &RuntimePaths) -> io::Result<(UnixListener, OwnedSocket)> {
    bind_socket(paths, paths.attach_sock())
}

/// Accept until shutdown. Peer credentials are checked **before a single
/// frame is read**; an unauthorized peer gets no response at all,
/// because there is nothing to negotiate and a reply would confirm the
/// daemon exists.
///
/// **The ordering is the control**, and it is the same one
/// `handle_connection` uses on `control.sock`: `peer_cred` →
/// `is_authorized` → *then* spawn something that will parse bytes. A
/// credential that cannot be read fails **closed** — the `Err` arm
/// refuses rather than falling through to a "well, probably us" default,
/// because the only way `getsockopt(SO_PEERCRED)` fails on a live socket
/// is a state this code does not understand.
pub async fn serve_attach(daemon: Arc<Daemon>, listener: UnixListener) {
    let mut shutdown = daemon.shutdown_signalled();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    match peer::peer_cred(&stream) {
                        Ok(cred) if peer::is_authorized(cred.uid, daemon.owner_uid()) => {}
                        Ok(cred) => {
                            crate::diag!(
                                "holdfast daemon: refused an attach connection from uid {} \
                                 (daemon runs as uid {})",
                                cred.uid,
                                daemon.owner_uid()
                            );
                            continue;
                        }
                        Err(e) => {
                            crate::diag!(
                                "holdfast daemon: cannot read attach peer credentials, refusing: {e}"
                            );
                            continue;
                        }
                    }
                    let d = Arc::clone(&daemon);
                    tokio::spawn(async move { handle_attach(d, stream).await });
                }
                Err(e) => crate::diag!("holdfast daemon: attach accept failed: {e}"),
            },
        }
    }
}

/// One accepted, uid-checked attach connection.
///
/// The §7.5 protocol itself is `crate::attach::conn`; this is the seam
/// the accept loop spawns onto, kept here so the accept path and the
/// protocol path stay in different files.
async fn handle_attach(daemon: Arc<Daemon>, stream: UnixStream) {
    // The socket boundary lands before the protocol does, so an
    // authorized peer is currently accepted and then closed. Nothing
    // asserts a *reply* here for that reason: the pairing that makes
    // "the daemon refused this peer" mean anything — a same-uid
    // connection that gets an `AttachReject` back — is written beside
    // `attach::conn::run`, where there is something to receive.
    let _ = (daemon, stream);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A short, unique `/tmp` runtime directory, removed on drop.
    /// `sockaddr_un.sun_path` cannot hold a path under the workspace's
    /// `target/`, which is why these do not use `tempfile`'s default.
    struct Scratch(RuntimePaths);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let unique = uuid::Uuid::new_v4().simple().to_string();
            let dir = PathBuf::from(format!("/tmp/holdfast-at-{tag}-{}", &unique[..8]));
            Self(RuntimePaths::with_dir(dir))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for _ in 0..20 {
                match std::fs::remove_dir_all(self.0.dir()) {
                    Ok(()) => return,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
                }
            }
        }
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777
    }

    #[tokio::test]
    async fn the_attach_socket_and_its_directory_are_owner_only() {
        // Both modes re-read from the filesystem rather than trusted from
        // the call that set them: the whole point of `bind_socket`'s
        // step 4 is that `set_permissions` succeeding is not the same
        // statement as the file being `0600`.
        let s = Scratch::new("perms");
        let (listener, _owned) = bind_attach(&s.0).expect("bind attach.sock");

        assert_eq!(
            mode_of(&s.0.attach_sock()),
            0o600,
            "attach.sock carries the same access boundary as control.sock (§7.7)"
        );
        assert_eq!(
            mode_of(s.0.dir()),
            0o700,
            "the runtime directory is what closes the bind→chmod window"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn a_pre_existing_world_readable_runtime_dir_is_tightened_before_attach_binds() {
        // The harm: `attach.sock` reachable through a directory another
        // user can traverse. The directory has to exist *and be wrong*
        // before the bind, or the assertion is about `create_dir_all`'s
        // default rather than about the guard.
        //
        // **Measured, and it corrects the plan's ladder:** deleting
        // `paths.ensure_dir()?` from `bind_socket_within` does **not**
        // turn this red, because `DaemonLock::acquire_bind_within` calls
        // `ensure_dir` too, three lines later and inside the same
        // function. The tightening therefore has two call sites and the
        // single-site mutation the plan names is survivable. That is not
        // a hole in this row — it asserts the *harm*, which is the
        // directory's mode after the bind, and the harm is genuinely
        // prevented either way. Reachability is proven by removing the
        // tightening itself (`ensure_owner_only` → `create_dir_all` in
        // `RuntimePaths::ensure_dir`), which turns this row and
        // `the_attach_socket_and_its_directory_are_owner_only` red and
        // nothing else here.
        let s = Scratch::new("wide");
        std::fs::create_dir_all(s.0.dir()).expect("mkdir");
        std::fs::set_permissions(s.0.dir(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");
        assert_eq!(mode_of(s.0.dir()), 0o755, "the fixture must start wrong");

        let (listener, _owned) = bind_attach(&s.0).expect("bind attach.sock");
        assert_eq!(
            mode_of(s.0.dir()),
            0o700,
            "binding attach.sock must tighten a pre-existing directory, not \
             inherit it: `create_dir_all` succeeds silently on a 0755 that is \
             already there"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn a_stale_attach_socket_is_replaced_and_a_live_one_is_not() {
        // Both halves, because each is satisfied by the mutation the
        // other catches. Dropping the connect probe passes the first
        // half and unlinks a *running* daemon's socket in the second;
        // refusing whenever the file exists passes the second half and
        // makes every restart after a crash fail to start.
        let s = Scratch::new("stale");
        s.0.ensure_dir().expect("mkdir");

        // Half one: a socket file with nobody behind it is stale.
        let dead = std::os::unix::net::UnixListener::bind(s.0.attach_sock()).expect("bind");
        drop(dead);
        assert!(
            s.0.attach_sock().exists(),
            "the fixture must leave the file behind"
        );
        let (live, _owned) = bind_attach(&s.0).expect("a stale attach.sock must be cleared");

        // Half two: one whose daemon answers is not ours to take.
        let again = bind_attach(&s.0);
        let err = again.expect_err("a live attach.sock must not be stolen");
        assert_eq!(
            err.kind(),
            io::ErrorKind::AddrInUse,
            "a bound attach.sock must refuse with AddrInUse, not be unlinked: {err}"
        );
        drop(live);
    }

    #[tokio::test]
    async fn the_daemon_binds_attach_but_not_http() {
        // Task 1 inverted 0.0.5's `!attach_sock().exists()` guard; this
        // is its positive half. `http.sock` is 0.0.10's and a stray bind
        // would show up here — which is the only guard there is against
        // that milestone creeping forward.
        let s = Scratch::new("nohttp");
        let (control, _c) = crate::daemon::server::bind_control(&s.0).expect("bind control.sock");
        let (attach, _a) = bind_attach(&s.0).expect("bind attach.sock");

        assert!(s.0.control_sock().exists(), "control.sock");
        assert!(s.0.attach_sock().exists(), "attach.sock is 0.0.6's");
        assert!(!s.0.http_sock().exists(), "http.sock belongs to 0.0.10");
        drop(attach);
        drop(control);
    }

    #[tokio::test]
    async fn the_teardown_removes_the_attach_socket_it_owns() {
        // §7.3 says "removes socket**s**", plural. A teardown that knew
        // only about `control.sock` left `attach.sock` behind for every
        // subsequent binder to probe and clear — and the control half of
        // this assertion is what stops the test passing against a
        // teardown that removed nothing at all.
        let s = Scratch::new("teardown");
        let (control, control_owned) =
            crate::daemon::server::bind_control(&s.0).expect("bind control.sock");
        let (attach, attach_owned) = bind_attach(&s.0).expect("bind attach.sock");
        drop(attach);
        drop(control);

        crate::daemon::server::remove_runtime_files_we_own(
            &s.0,
            &control_owned,
            Some(&attach_owned),
        );

        assert!(!s.0.control_sock().exists(), "control.sock left behind");
        assert!(!s.0.attach_sock().exists(), "attach.sock left behind");
    }

    #[tokio::test]
    async fn the_teardown_leaves_a_successors_attach_socket_alone() {
        // The C-5 window on the second socket. A's teardown arrives
        // after B has already rebound; identity, not existence, is what
        // separates them. Without this, "remove attach.sock too" is the
        // unconditional unlink §7.3's control half was fixed for.
        let s = Scratch::new("c5attach");
        let (control, control_owned) =
            crate::daemon::server::bind_control(&s.0).expect("bind control.sock");
        let (a_listener, a_owned) = bind_attach(&s.0).expect("A binds attach.sock");
        drop(a_listener);

        let (b_listener, _b_owned) = bind_attach(&s.0).expect("B rebinds attach.sock");

        // A's teardown, arriving late, carrying A's identity for both
        // sockets.
        drop(control);
        crate::daemon::server::remove_runtime_files_we_own(&s.0, &control_owned, Some(&a_owned));

        assert!(
            s.0.attach_sock().exists(),
            "A unlinked B's just-bound attach.sock: every client that dialled \
             in afterwards would get ENOENT against a daemon that is running"
        );
        // The pairing. Without it, a teardown that removed *nothing*
        // passes the assertion above, and this row would read as a guard
        // while guarding nothing.
        assert!(
            !s.0.control_sock().exists(),
            "the teardown must still remove the sockets it does own"
        );
        drop(b_listener);
    }
}
