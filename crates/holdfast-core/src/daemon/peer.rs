//! Peer-credential checking for `control.sock` (spec §9.1, REQ-D-001).
//!
//! Filesystem permission is the primary control, but it is not the only
//! one worth having: a `0600` socket inside a `0700` directory can still
//! be reached by root, or by a process that inherited the fd. Reading the
//! peer's uid off the connected socket closes that gap, and costs one
//! `getsockopt`.
//!
//! It is **not** justified by the `bind`→`chmod` window, and an earlier
//! draft of this comment claimed it was. `server.rs::bind_control` has
//! the right account: the enclosing `0700` directory closes that window
//! outright, because another user cannot traverse the parent to reach
//! the socket even while it is briefly `0755`. Overstating the case here
//! only weakened the two reasons above it, which are real.

use std::io;
use std::os::unix::io::AsRawFd;

/// Identity of the process on the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    /// `None` on platforms whose API does not report it (macOS).
    pub pid: Option<i32>,
}

/// The effective uid this process runs as.
pub fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, and returns a
    // plain integer.
    unsafe { libc::geteuid() }
}

/// Whether a connected peer may drive this daemon.
///
/// Strict equality, deliberately. Root is *not* granted an exception:
/// the daemon holds PTYs and buffers belonging to one user, and "root
/// may as well have shell access anyway" is an argument about the host,
/// not a reason for Holdfast to hand over another user's session.
pub fn is_authorized(peer_uid: u32, our_uid: u32) -> bool {
    peer_uid == our_uid
}

#[cfg(target_os = "linux")]
pub fn peer_cred<T: AsRawFd>(sock: &T) -> io::Result<PeerCred> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `sock` is a live socket fd for the duration of the call;
    // `ucred` and `len` are correctly sized for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // A short read would leave the tail of `ucred` at its initial value.
    // Initialising to `u32::MAX` rather than 0 means such a truncation
    // cannot be mistaken for "uid 0", which `is_authorized` would refuse
    // anyway but which would read as a real answer in a log line.
    //
    // **This branch has no test and cannot be given one from here.** A
    // real Linux kernel always writes the full `ucred`, so provoking a
    // short read means faking `getsockopt`, which would test the fake.
    // It is defence against a future porting mistake, recorded as
    // unprovable rather than counted as covered.
    if (len as usize) != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SO_PEERCRED returned {len} bytes, expected {}",
                std::mem::size_of::<libc::ucred>()
            ),
        ));
    }
    Ok(PeerCred {
        uid: ucred.uid,
        gid: ucred.gid,
        pid: Some(ucred.pid),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn peer_cred<T: AsRawFd>(sock: &T) -> io::Result<PeerCred> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: `sock` is a live socket fd; both out-params are owned
    // locals of the right type.
    let rc = unsafe { libc::getpeereid(sock.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred {
        uid,
        gid,
        pid: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    #[test]
    fn only_the_owning_uid_is_authorized() {
        let us = 1000;
        assert!(is_authorized(1000, us));
        assert!(!is_authorized(1001, us), "another user must be refused");
        assert!(!is_authorized(0, us), "root gets no exception");
    }

    /// RAII cleanup, mirroring `daemon::paths`'s guard of the same name.
    /// Cleanup at the end of the function runs only on the *passing*
    /// path, so a failing assertion leaks `/tmp/holdfast-t-peer-*` —
    /// exactly when someone is re-running the test. The retry loop is
    /// kept: the socket inside may not be unlinked the instant its
    /// listener drops.
    struct Scoped(String);
    impl Drop for Scoped {
        fn drop(&mut self) {
            for _ in 0..20 {
                match std::fs::remove_dir_all(&self.0) {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
                }
            }
        }
    }

    #[tokio::test]
    async fn peer_cred_reports_this_processs_real_uid() {
        // The assertion is `== current_uid()`, not `>= 0`: a stub that
        // returned a zeroed `ucred` would pass the latter on a
        // root-owned CI runner and fail here for every normal user.
        let dir = format!(
            "/tmp/holdfast-t-peer-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        std::fs::create_dir_all(&dir).unwrap();
        // Declared before the listener, so it drops after it.
        let _scoped = Scoped(dir.clone());
        let path = format!("{dir}/s.sock");
        let listener = UnixListener::bind(&path).unwrap();

        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let from_server = peer_cred(&server).unwrap();
        let from_client = peer_cred(&client).unwrap();

        assert_eq!(from_server.uid, current_uid());
        assert_eq!(from_client.uid, current_uid());
        assert!(is_authorized(from_server.uid, current_uid()));

        #[cfg(target_os = "linux")]
        assert_eq!(
            from_server.pid,
            Some(std::process::id() as i32),
            "SO_PEERCRED must report the connecting pid"
        );
    }

    #[test]
    fn peer_cred_on_a_non_socket_is_an_error() {
        // The `rc != 0` branch, which the short-read branch above it is
        // honestly recorded as unable to reach. This one *does* have a
        // seam and needs no fake: `peer_cred` is generic over `AsRawFd`,
        // so an ordinary file fd yields `ENOTSOCK` from the kernel.
        //
        // It is the branch `handle_connection` depends on to fail closed
        // — `peer_is_authorized(&Err(_), _)` is `false` — so "the error
        // path is reachable at all" is worth one assertion rather than
        // none.
        let f = std::fs::File::open("/dev/null").expect("/dev/null");
        let err = peer_cred(&f).expect_err("a plain file is not a socket");
        assert!(
            !matches!(err.kind(), std::io::ErrorKind::NotFound),
            "the error must come from getsockopt, not from opening the fd: {err}"
        );
    }
}
