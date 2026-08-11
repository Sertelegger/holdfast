//! `portable-pty`-backed PTY. Unix only in 0.0.1; Windows lands in 0.0.11.

use super::{PtyBackend, PtySpawnConfig, Signal};
use crate::{ClaspError, Result};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

/// How long a `tcgetattr` sample is reused. Matches the `is_alive`
/// caching policy in spec §4.1: cheap enough to sample per output chunk,
/// fresh enough that an echo drop is seen within one detector update.
///
/// `cfg(unix)` along with everything else that samples `ECHO`: there is
/// no `tcgetattr` off Unix, so on the 0.0.11 Windows build this and the
/// cache it governs are dead code, and CI runs with `-D warnings`.
#[cfg(unix)]
const ECHO_CACHE_TTL: Duration = Duration::from_millis(50);

/// How long `write` waits for the writer lock before giving up.
///
/// The master fd is blocking and the *child* decides when it drains, so a
/// raw-mode child that never reads leaves an in-flight `write_all` parked
/// indefinitely — holding this lock with it. Bounding acquisition means
/// the next write reports `timeout` promptly instead of parking a second
/// thread behind the first, which is how one wedged session used to
/// consume every worker in the server.
const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

pub struct InProcessPty {
    // `MasterPty: Downcast + Send` is **not** `Sync`, and `PtyBackend`
    // requires `Send + Sync`, so the master must sit behind a lock.
    master: Mutex<Box<dyn MasterPty + Send>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    pid: Option<u32>,
    /// Cached exit status so `exit_code` stays cheap and idempotent.
    exit: Mutex<Option<i32>>,
    /// How many times this PTY has actually asked the OS to deliver a
    /// signal (one count per `kill(2)` attempt).
    ///
    /// This exists to make the post-exit guard in `signal` *observable*.
    /// The guard is the only thing stopping a `/proc` sweep from
    /// signalling whatever session has since inherited a recycled PID, but
    /// `sweep` treats `ESRCH` as success, so removing the guard changes no
    /// return value — a test asserting `Ok(())` passes either way. Counting
    /// deliveries turns "no signal left this process" into something a test
    /// can assert. Deliberately not `#[cfg(test)]`: the integration tests
    /// link this crate externally and would not see it.
    signal_deliveries: AtomicUsize,
    /// Cached `ECHO` sample and the instant it was taken.
    #[cfg(unix)]
    echo: Mutex<Option<(Instant, Option<bool>)>>,
}

/// Signal a whole process group. Negative pid == "the group" for kill(2).
#[cfg(unix)]
fn killpg(pgid: i32, signum: i32) -> std::io::Result<()> {
    if unsafe { libc::kill(-pgid, signum) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl InProcessPty {
    pub fn spawn(cfg: &PtySpawnConfig) -> Result<Self> {
        let sys = native_pty_system();
        let pair = sys
            .openpty(PtySize {
                rows: cfg.rows,
                cols: cfg.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ClaspError::Pty(format!("openpty: {e}")))?;

        let mut cmd = CommandBuilder::new(&cfg.command);
        for a in &cfg.args {
            cmd.arg(a);
        }
        if let Some(cwd) = &cfg.cwd {
            cmd.cwd(cwd);
        }
        for (k, v) in &cfg.env {
            cmd.env(k, v);
        }
        // portable-pty performs setsid() + TIOCSCTTY in the child; this
        // makes the controlling-tty half explicit rather than implicit.
        #[cfg(unix)]
        cmd.set_controlling_tty(true);

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| ClaspError::Pty(format!("spawn: {e}")))?;
        // Drop the slave so the master sees EOF when the child exits.
        drop(pair.slave);

        let pid = child.process_id();
        // Take the reader and writer *before* moving the master into the
        // struct; `take_writer` may only be called once.
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| ClaspError::Pty(format!("clone reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| ClaspError::Pty(format!("take writer: {e}")))?;

        Ok(Self {
            master: Mutex::new(pair.master),
            child: Mutex::new(child),
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            pid,
            exit: Mutex::new(None),
            signal_deliveries: AtomicUsize::new(0),
            #[cfg(unix)]
            echo: Mutex::new(None),
        })
    }

    /// One `tcgetattr` against the master fd. The master reports the
    /// *slave's* line-discipline flags, which is exactly what §8.2 wants:
    /// whether the program on the other end has turned echo off.
    #[cfg(unix)]
    fn sample_echo(&self) -> Option<bool> {
        let master = self.master.lock();
        let fd = master.as_raw_fd()?;
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is the live master end, owned by `self.master` and
        // held under the lock above for the duration of the call.
        let rc = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
        drop(master);
        if rc != 0 {
            return None;
        }
        // SAFETY: tcgetattr returned 0, so the struct is initialised.
        let termios = unsafe { termios.assume_init() };
        Some(termios.c_lflag & libc::ECHO != 0)
    }

    /// Number of `kill(2)` calls this PTY has issued since it was spawned.
    ///
    /// Zero means no signal ever left this process — which is exactly the
    /// property the post-exit guard in `signal` exists to provide.
    pub fn signal_deliveries(&self) -> usize {
        self.signal_deliveries.load(Ordering::Relaxed)
    }

    /// Issue one `kill(2)`, counting the attempt.
    #[cfg(unix)]
    fn deliver(&self, pgid: i32, signum: i32) -> std::io::Result<()> {
        self.signal_deliveries.fetch_add(1, Ordering::Relaxed);
        killpg(pgid, signum)
    }

    /// The child's own process group and session id. `setsid()` in the
    /// child makes PGID == SID == PID.
    #[cfg(unix)]
    fn pgid(&self) -> Option<i32> {
        self.pid.map(|p| p as i32)
    }

    /// The terminal's foreground process group — the job that would
    /// receive a Ctrl-C typed at this terminal.
    #[cfg(unix)]
    fn foreground_pgid(&self) -> Option<i32> {
        self.master.lock().process_group_leader().or(self.pgid())
    }

    /// Every distinct process group in the child's session.
    ///
    /// Shell job control puts each background job in its own group, so
    /// this is the only set whose destruction satisfies REQ-P-006.
    #[cfg(target_os = "linux")]
    fn session_pgids(&self) -> Vec<i32> {
        let Some(sid) = self.pgid() else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return self.fallback_pgids();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{name}/stat")) else {
                continue;
            };
            // `comm` is parenthesised and may itself contain spaces and
            // ')', so the fields after it start past the LAST ')'.
            let Some((_, rest)) = stat.rsplit_once(')') else {
                continue;
            };
            let fields: Vec<&str> = rest.split_whitespace().collect();
            // rest: [0]=state [1]=ppid [2]=pgrp [3]=session
            if fields.len() < 4 {
                continue;
            }
            let (Ok(pgrp), Ok(session)) = (fields[2].parse::<i32>(), fields[3].parse::<i32>())
            else {
                continue;
            };
            if session == sid && pgrp > 0 && !out.contains(&pgrp) {
                out.push(pgrp);
            }
        }
        if out.is_empty() {
            self.fallback_pgids()
        } else {
            out
        }
    }

    /// Degraded sweep for Unix platforms without `/proc`. Full
    /// enumeration there needs `sysctl(KERN_PROC_SESSION)` — post-v0.1.0.
    #[cfg(all(unix, not(target_os = "linux")))]
    fn session_pgids(&self) -> Vec<i32> {
        self.fallback_pgids()
    }

    #[cfg(unix)]
    fn fallback_pgids(&self) -> Vec<i32> {
        let mut v = Vec::new();
        // The `> 0` guard matters: kill(-0, sig) signals CLASP's OWN
        // process group. Unreachable today (process_id() is >= 1), but
        // the foreground entry below guards it and asymmetry invites a
        // regression.
        if let Some(p) = self.pgid().filter(|p| *p > 0) {
            v.push(p);
        }
        if let Some(f) = self.master.lock().process_group_leader() {
            if f > 0 && !v.contains(&f) {
                v.push(f);
            }
        }
        v
    }

    /// Signal every process group in the session. Re-enumerates on each
    /// call, so groups created since the last sweep are still caught.
    #[cfg(unix)]
    fn sweep(&self, signum: i32) -> Result<()> {
        let groups = self.session_pgids();
        if groups.is_empty() {
            return Err(ClaspError::Pty("no process group to signal".into()));
        }
        let mut delivered = false;
        let mut last_err = None;
        for g in groups {
            match self.deliver(g, signum) {
                Ok(()) => delivered = true,
                // ESRCH: that group is already gone. Still a success.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => delivered = true,
                Err(e) => last_err = Some(e),
            }
        }
        match (delivered, last_err) {
            (true, _) => Ok(()),
            (false, Some(e)) => Err(ClaspError::Io(e)),
            (false, None) => Err(ClaspError::Pty("no process group to signal".into())),
        }
    }
}

impl PtyBackend for InProcessPty {
    fn write(&self, data: &[u8]) -> Result<()> {
        // `lock()` here would queue behind a parked writer forever; see
        // WRITE_LOCK_TIMEOUT. The `write_all` below can still block for as
        // long as the child refuses to drain — bounding *that* would need
        // a non-blocking fd and a poll loop, and the fd is shared with the
        // reader — so callers must additionally run this off the async
        // runtime under their own deadline.
        let Some(mut w) = self.writer.try_lock_for(WRITE_LOCK_TIMEOUT) else {
            return Err(ClaspError::WriteTimeout);
        };
        w.write_all(data)?;
        w.flush()?;
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.reader.lock().read(buf)?)
    }

    #[cfg(unix)]
    fn signal(&self, sig: Signal) -> Result<()> {
        // Never signal after exit: once the child is reaped its PID can
        // be recycled, and a sweep would then target a stranger's session.
        if !self.is_alive() {
            return Ok(());
        }
        match sig {
            // SIGINT must reach the command being interrupted. Targeting
            // the session leader would signal the shell hosting it.
            Signal::Interrupt => {
                let Some(g) = self.foreground_pgid() else {
                    return Err(ClaspError::Pty("no process group to signal".into()));
                };
                self.deliver(g, libc::SIGINT).map_err(ClaspError::Io)
            }
            Signal::Terminate => self.sweep(libc::SIGTERM),
            Signal::Kill => self.sweep(libc::SIGKILL),
        }
    }

    #[cfg(not(unix))]
    fn signal(&self, _sig: Signal) -> Result<()> {
        Err(ClaspError::Pty("signals are Unix-only in 0.0.1".into()))
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.master
            .lock()
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ClaspError::Pty(format!("resize: {e}")))
    }

    fn is_alive(&self) -> bool {
        if self.exit.lock().is_some() {
            return false;
        }
        let status = self.child.lock().try_wait();
        match status {
            Ok(Some(status)) => {
                *self.exit.lock() = Some(status.exit_code() as i32);
                false
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    #[cfg(unix)]
    fn echo_enabled(&self) -> Option<bool> {
        // A dead child's line discipline says nothing about what the
        // session is doing, and the fd may already be closed.
        if !self.is_alive() {
            return None;
        }
        let mut cache = self.echo.lock();
        if let Some((at, value)) = *cache {
            if at.elapsed() < ECHO_CACHE_TTL {
                return value;
            }
        }
        let value = self.sample_echo();
        *cache = Some((Instant::now(), value));
        value
    }

    fn exit_code(&self) -> Option<i32> {
        if let Some(c) = *self.exit.lock() {
            return Some(c);
        }
        let _ = self.is_alive(); // populates the cache on transition
        *self.exit.lock()
    }

    fn pid(&self) -> Option<u32> {
        self.pid
    }
}
