//! `portable-pty`-backed PTY. Unix only in 0.0.1; Windows lands in 0.0.11.

use super::{PtyBackend, PtySpawnConfig, Signal};
use crate::{ClaspError, Result};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};

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
        })
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
            match killpg(g, signum) {
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
        let mut w = self.writer.lock();
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
                killpg(g, libc::SIGINT).map_err(ClaspError::Io)
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
