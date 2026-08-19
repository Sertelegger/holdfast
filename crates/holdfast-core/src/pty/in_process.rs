//! `portable-pty`-backed PTY. Unix only in 0.0.1; Windows lands in 0.0.11.

use super::{PtyBackend, PtySpawnConfig, Signal};
// Only the Unix `line_discipline` names this type; on other platforms the
// trait default answers and importing it unconditionally is a warning the
// Windows-cross clippy gate turns into an error.
#[cfg(unix)]
use super::LineDiscipline;
use crate::{HoldfastError, Result};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
}

/// `tcgetpgrp`'s answer as §8.3's tri-state: a group, or **unknown**.
///
/// A process group id is positive. `tcgetpgrp` answers `0` once the child
/// has been reaped and `-1` on error, and both are *unknown* rather than a
/// group — reading either as one would make §8.3's owner/holder comparison
/// fail against a value that names nothing (REQ-PD-025).
///
/// **Separated out because it is otherwise untestable, and that is a
/// measured fact rather than a stylistic one.** `portable-pty` 0.9.0's own
/// `process_group_leader` already maps non-positive to `None`
/// (`unix.rs:374`), so no value reaching `foreground_group` through that
/// backend can exercise the rule and a mutation widening it to `g >= 0`
/// passes the whole workspace. The rule still belongs here — the trait is
/// `MasterPty`, not that one implementation — so it is written where it can
/// be pinned instead of where it cannot.
#[cfg(unix)]
fn valid_group(g: Option<i32>) -> Option<i32> {
    g.filter(|g| *g > 0)
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
            .map_err(|e| HoldfastError::Pty(format!("openpty: {e}")))?;

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
            .map_err(|e| HoldfastError::Pty(format!("spawn: {e}")))?;
        // Drop the slave so the master sees EOF when the child exits.
        drop(pair.slave);

        let pid = child.process_id();
        // Take the reader and writer *before* moving the master into the
        // struct; `take_writer` may only be called once.
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| HoldfastError::Pty(format!("clone reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| HoldfastError::Pty(format!("take writer: {e}")))?;

        Ok(Self {
            master: Mutex::new(pair.master),
            child: Mutex::new(child),
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            pid,
            exit: Mutex::new(None),
            signal_deliveries: AtomicUsize::new(0),
        })
    }

    /// One `tcgetattr` against the master fd. The master reports the
    /// *slave's* line-discipline flags, which is exactly what §8.2 wants:
    /// whether the program on the other end has turned echo off.
    ///
    /// **This is deliberately not cached, and that is a fix rather than an
    /// omission.** Through 0.0.2 the sample was reused for 50 ms, on §4.5's
    /// instruction to cache it "per §4.1 `is_alive` policy". The 50 ms was
    /// agent-visible and wrong:
    ///
    /// - `ECHO` is *off* at a readline prompt (§8.2). When a command is
    ///   submitted, readline writes `\x1b[?2004l` and restores the line
    ///   discipline — so for up to 50 ms the classifier saw a **stale**
    ///   echo-off beside a current bracketed-paste-off and answered §8.3's
    ///   echo rung: `AwaitingSecret` / `terminal_mode` / **0.95**, which
    ///   §8.4 tells the agent to answer by interrupting a human for a
    ///   password. For `sleep 5`. Measured as a 1-in-10 flake in the
    ///   0.0.2 acceptance matrix.
    /// - §8.8's echo-off caveat does not cover it. That caveat is about a
    ///   program that genuinely disabled echo; here nothing did, and the
    ///   session was never in the state being reported.
    ///
    /// The caching instruction did not survive its own premise. §4.1 caches
    /// `is_alive` because "the PromptDetector calls `is_alive()` per output
    /// chunk"; **nothing calls `line_discipline` per chunk** — the read path
    /// never samples it, `Session::detection` does, once per tool call. And
    /// `is_alive` itself is not cached in this backend while the child
    /// lives (see below): `waitpid(WNOHANG)` runs on every call. So the
    /// cache was the only one of its kind, and it was buying a call
    /// frequency that does not exist.
    ///
    /// Measured cost of what it saved: **524 ns** per sample (200k samples,
    /// debug build, including the master mutex) — against an MCP tool call
    /// that serialises a JSON response.
    ///
    /// **What an uncached sample buys, exactly.** `Session::detection`
    /// samples under the detector lock, so no chunk can be classified
    /// between the sample and the classification: the value handed to
    /// §8.3's ladder is never older than the newest byte the ladder has
    /// seen. The residual is the child's own non-atomicity — readline
    /// writes `\x1b[?2004l` and *then* calls `tcsetattr` — and measurement
    /// says that window runs the safe way round: over 12 runs the restored
    /// `ECHO` was observable 8–29 µs **before** the `\x1b[?2004l` bytes
    /// were readable from the master, because seeing the bytes costs a
    /// `read` wakeup and seeing the flag costs one ioctl. To read echo-off
    /// there now, the child would have to be descheduled between its own
    /// `fflush` and its `tcsetattr` for longer than Holdfast takes to read and
    /// classify the bytes it just wrote — and throughout such a window the
    /// terminal genuinely *does* have echo off, which is the case §8.8
    /// already documents.
    #[cfg(unix)]
    fn sample_line_discipline(&self) -> LineDiscipline {
        let master = self.master.lock();
        let Some(fd) = master.as_raw_fd() else {
            return LineDiscipline::UNKNOWN;
        };
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is the live master end, owned by `self.master` and
        // held under the lock above for the duration of the call.
        let rc = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
        drop(master);
        if rc != 0 {
            return LineDiscipline::UNKNOWN;
        }
        // SAFETY: tcgetattr returned 0, so the struct is initialised.
        let termios = unsafe { termios.assume_init() };
        // Both flags out of the one struct. Reading `ICANON` here costs
        // nothing the `ECHO` read did not already pay for, and taking them
        // together is what makes them describe the same instant.
        LineDiscipline {
            echo: Some(termios.c_lflag & libc::ECHO != 0),
            canonical: Some(termios.c_lflag & libc::ICANON != 0),
        }
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
        // The `> 0` guard matters: kill(-0, sig) signals Holdfast's OWN
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
            return Err(HoldfastError::Pty("no process group to signal".into()));
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
            (false, Some(e)) => Err(HoldfastError::Io(e)),
            (false, None) => Err(HoldfastError::Pty("no process group to signal".into())),
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
            return Err(HoldfastError::WriteTimeout);
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
                    return Err(HoldfastError::Pty("no process group to signal".into()));
                };
                self.deliver(g, libc::SIGINT).map_err(HoldfastError::Io)
            }
            Signal::Terminate => self.sweep(libc::SIGTERM),
            Signal::Kill => self.sweep(libc::SIGKILL),
        }
    }

    #[cfg(not(unix))]
    fn signal(&self, _sig: Signal) -> Result<()> {
        Err(HoldfastError::Pty("signals are Unix-only in 0.0.1".into()))
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
            .map_err(|e| HoldfastError::Pty(format!("resize: {e}")))
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

    /// Sampled on every call, with **no cache**, and both flags out of one
    /// `tcgetattr`. See `sample_line_discipline`.
    #[cfg(unix)]
    fn line_discipline(&self) -> LineDiscipline {
        // A dead child's line discipline says nothing about what the
        // session is doing, and the fd may already be closed.
        if !self.is_alive() {
            return LineDiscipline::UNKNOWN;
        }
        self.sample_line_discipline()
    }

    /// The raw `tcgetpgrp`, with **no fallback** — deliberately not
    /// `foreground_pgid`. See the trait's doc and REQ-PD-025: the
    /// fallback that makes `interrupt` correct makes detection wrong,
    /// because it re-asserts session scope while presenting as a known
    /// answer.
    #[cfg(unix)]
    fn foreground_group(&self) -> Option<i32> {
        valid_group(self.master.lock().process_group_leader())
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

/// §11.1 `pty::echo_freshness` — the `ECHO` sample must describe the line
/// discipline the session has *now*.
///
/// These live beside the implementation rather than in `tests/` because
/// the property is about the master fd, and driving it needs the fd. Every
/// other `line_discipline` test in the tree drives it
/// through a *child* (`stty -echo`, readline), which means it can only
/// observe transitions the child chooses to make, when the child gets
/// round to making them. Setting termios from the master end makes the
/// transition an instruction rather than an event, which is what turns the
/// 0.0.2 flake into an assertion.
#[cfg(all(test, unix))]
mod echo_freshness {
    use super::*;
    use crate::pty::PtySpawnConfig;
    use std::time::Instant;

    /// A child that never touches the line discipline, so every change
    /// below is one this test made.
    fn inert() -> PtySpawnConfig {
        let mut cfg = PtySpawnConfig::new("sleep");
        cfg.args = vec!["300".into()];
        cfg
    }

    /// Set `ECHO` on the slave's line discipline, from the master end.
    ///
    /// The master and the slave share one termios — which is the whole
    /// reason `sample_line_discipline` can read the slave's flags off the
    /// master — so this is the same state change `stty -echo` makes, minus
    /// the child.
    fn set_echo(pty: &InProcessPty, on: bool) {
        let master = pty.master.lock();
        let fd = master.as_raw_fd().expect("master fd");
        let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is the live master end, held under the lock above.
        assert_eq!(unsafe { libc::tcgetattr(fd, t.as_mut_ptr()) }, 0);
        // SAFETY: tcgetattr returned 0, so the struct is initialised.
        let mut t = unsafe { t.assume_init() };
        if on {
            t.c_lflag |= libc::ECHO;
        } else {
            t.c_lflag &= !libc::ECHO;
        }
        // SAFETY: as above; `t` is a fully initialised termios.
        assert_eq!(unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) }, 0);
    }

    #[test]
    fn line_discipline_reports_the_line_discipline_it_has_now_not_the_one_it_had() {
        // The 0.0.2 defect, driven rather than raced.
        //
        // Through 0.0.2 the sample was cached for 50 ms. Nothing in the
        // suite could see that, because every other test polls until the
        // answer it wants shows up — a stale answer just costs one more
        // poll. What made it agent-visible is §8.3 combining this reading
        // with a bracketed-paste mode read from the byte stream: a
        // 50 ms-old echo-off from a readline prompt beside the
        // bracketed-paste-off of the command that was just submitted is
        // the exact signature of `AwaitingSecret`, and §8.4 answers that
        // by interrupting a human for a password. Measured at 1-in-10 in
        // the acceptance matrix.
        //
        // Asserting *both* directions on every flip is what stops this
        // being answerable by a constant: `Some(true)` fails the first
        // half, `Some(false)` the second.
        let pty = InProcessPty::spawn(&inert()).expect("spawn");

        let mut fastest = Duration::from_secs(3600);
        for flip in 0..20 {
            let started = Instant::now();
            set_echo(&pty, false);
            assert_eq!(
                pty.line_discipline().echo,
                Some(false),
                "flip {flip}: echo was just turned off"
            );
            set_echo(&pty, true);
            assert_eq!(
                pty.line_discipline().echo,
                Some(true),
                "flip {flip}: a cached sample outlived the line discipline \
                 it described — the session is reported as having echo off \
                 while the terminal has it on"
            );
            fastest = fastest.min(started.elapsed());
        }

        // The test says something only if at least one flip pair fits
        // inside the window the old cache held its answer for. Four
        // `tcsetattr`-class syscalls take microseconds, so this is a
        // check that the machine is sane rather than a timing assumption:
        // without it, a run slow enough for every pair to straddle 50 ms
        // would pass against the very bug it exists to catch, and pass
        // silently.
        assert!(
            fastest < Duration::from_millis(50),
            "no flip completed inside the 50 ms window the withdrawn cache \
             reused its answer for (fastest was {fastest:?}), so this run \
             proves nothing"
        );

        pty.signal(Signal::Kill).expect("kill");
    }

    #[test]
    fn a_dead_childs_line_discipline_is_not_reported_from_an_earlier_sample() {
        // The pair to the above, for the one answer that is *not* a fresh
        // sample. `line_discipline` short-circuits on liveness, and with the
        // cache gone the only thing standing between a reaped child and a
        // `tcgetattr` on its fd is that guard. Removing the guard reports
        // `Some(_)` here.
        let mut cfg = PtySpawnConfig::new("sleep");
        cfg.args = vec!["300".into()];
        let pty = InProcessPty::spawn(&cfg).expect("spawn");
        set_echo(&pty, false);
        assert_eq!(pty.line_discipline().echo, Some(false));

        pty.signal(Signal::Kill).expect("kill");
        let deadline = Instant::now() + Duration::from_secs(5);
        while pty.is_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!pty.is_alive(), "the child never died");
        assert_eq!(
            pty.line_discipline(),
            LineDiscipline::UNKNOWN,
            "a dead child's line discipline says nothing about the session"
        );
    }
}

/// §11.1 — the *detection* foreground accessor, which is not `interrupt`'s
/// and must not become it (REQ-PD-025).
///
/// Beside the implementation for the same reason as `echo_freshness`: both
/// accessors under test are private inherent methods, and the distinction
/// between them is invisible from outside the module.
#[cfg(all(test, unix))]
mod foreground_scope {
    use super::*;
    use crate::pty::PtySpawnConfig;
    use std::time::Instant;

    /// `tcgetpgrp`'s non-positive answers are **unknown**, not groups.
    ///
    /// The reaped-child test below cannot reach this rule: `portable-pty`
    /// filters `pid > 0` before Holdfast sees the value, so `Some(0)` never
    /// arrives through that backend and a widened guard passes the whole
    /// workspace. Asserting the rule directly is what makes it a rule
    /// rather than a comment — and `Some(-1)` is here too, because
    /// `tcgetpgrp`'s error return is the other non-group it can produce
    /// and a guard spelled `!= 0` would let it through into an
    /// owner/holder comparison.
    #[test]
    fn a_non_positive_foreground_group_is_unknown_rather_than_a_group() {
        assert_eq!(valid_group(Some(0)), None, "a reaped child's tcgetpgrp");
        assert_eq!(valid_group(Some(-1)), None, "tcgetpgrp's error return");
        assert_eq!(valid_group(None), None);
        assert_eq!(valid_group(Some(4242)), Some(4242), "a real group survives");
    }

    /// REQ-PD-025: the detection accessor must not be `interrupt`'s.
    ///
    /// `foreground_pgid` falls back to the child's own group because a
    /// best-effort signal target beats none. `foreground_group` must not,
    /// because that fallback re-asserts session scope while presenting as
    /// a known answer — the fix wearing the defect's clothes, and the
    /// obvious line to write.
    ///
    /// A reaped child is the discriminator and it is measured:
    /// `tcgetpgrp` answers 0, so the raw accessor reports **unknown**
    /// while the fallback still reports the child's pgid. Both assertions
    /// are needed — the first alone passes for an accessor that always
    /// returns `None`, and it also catches the narrower mistake of
    /// accepting `Some(0)` as a group.
    ///
    /// The child is `sleep 300`, killed here, rather than the
    /// `bash -c "exit 0"` this test used through 0.0.2. That child was
    /// designed to exit as fast as it could, so the live-state
    /// precondition below was a *race against it* rather than an
    /// observation: on a 48-core box confined to `taskset -c 0,1` at
    /// `--test-threads=8`, 7 of 20 lib-suite runs panicked on "a live
    /// child holds the terminal" with the child already reaped
    /// (`is_alive()` false at the assertion). Deleting that precondition
    /// would have been the cheap repair and the wrong one — it is the
    /// only assertion excluding an accessor that always answers `None` —
    /// so instead the reaping became something this test *performs*,
    /// between the two observations, at a point of its choosing.
    #[test]
    fn the_detection_accessor_does_not_fall_back_to_the_childs_own_group() {
        let mut cfg = PtySpawnConfig::new("sleep");
        cfg.args = vec!["300".into()];
        let pty = InProcessPty::spawn(&cfg).expect("spawn");

        // No wait loop guarding this, deliberately: the terminal already
        // has a foreground group when `spawn` returns. `portable-pty`
        // does its `setsid`/`TIOCSCTTY` in a `pre_exec` closure, and
        // std's Unix `Command::spawn` blocks the parent on the CLOEXEC
        // sync pipe until the child either reports a `pre_exec` failure
        // or reaches `execvp` — so the child has taken the terminal
        // before the parent holds a `Child` at all. Measured at 0 misses
        // in 1000 spawns under the contention above; a wait loop here
        // would weaken this to "eventually holds" for nothing.
        //
        // While it lives the two accessors agree, which is what makes the
        // divergence below a property of the *reaped* state rather than
        // of one accessor being broken outright.
        let live = pty.foreground_group();
        assert!(live.is_some(), "a live child holds the terminal");
        assert_eq!(
            live,
            pty.foreground_pgid(),
            "a live child's terminal needs no fallback, so both accessors \
             answer with its own group"
        );

        // Now take the child away, on this test's schedule rather than
        // the child's. The kernel clears the terminal's foreground group
        // in `disassociate_ctty` during `do_exit`, before the parent can
        // reap, so once `is_alive` reports false the reaped state below
        // has already settled — no polling for it, and nothing to hope
        // about.
        pty.signal(Signal::Kill).expect("kill");
        let deadline = Instant::now() + Duration::from_secs(5);
        while pty.is_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!pty.is_alive(), "the child never exited");

        assert_eq!(
            pty.foreground_group(),
            None,
            "detection must report unknown: `tcgetpgrp` answers 0 for a \
             reaped child, and 0 is not a process group"
        );
        assert!(
            pty.foreground_pgid().is_some(),
            "signalling still has a target"
        );
    }
}
