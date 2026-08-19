//! Runtime directory and socket discovery (spec §7.1, §7.2, §19.1).
//!
//! Every path CLASP binds lives under one `0700` directory owned by the
//! invoking user. That directory permission — not any in-band credential
//! — is the first half of the daemon's trust boundary (§9.1); the
//! peer-credential check in `daemon::peer` is the second.
//!
//! **Logs are not sockets.** §7.1 relocates `daemon.log` under the
//! runtime directory only when `CLASP_RUNTIME_DIR` is explicitly set, so
//! an isolated instance leaves nothing in the user's home. With the
//! variable unset, §19.1's `~/.clasp/logs` applies: `$XDG_RUNTIME_DIR` is
//! tmpfs on most Linux systems and is cleared at logout, which cannot
//! hold the retention windows §19.1 specifies.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const SECS_PER_DAY: u64 = 86_400;

/// The two §19.1 retention windows, in §19.1's own units — days for the
/// audit log, **weeks** for the daemon log. The asymmetry is deliberate:
/// the two rotation periods differ, and `deny_unknown_fields` makes a
/// renamed knob a daemon that rejects the spec's own config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRetention {
    pub audit_days: u32,
    pub daemon_log_weeks: u32,
}

impl Default for LogRetention {
    fn default() -> Self {
        Self {
            audit_days: 14,
            daemon_log_weeks: 4,
        }
    }
}

impl From<&crate::config::Config> for LogRetention {
    fn from(c: &crate::config::Config) -> Self {
        Self {
            audit_days: c.daemon.audit_retention_days,
            daemon_log_weeks: c.daemon.daemon_log_retention_weeks,
        }
    }
}

/// What one sweep did, so a caller can log it and a test can assert it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogSweep {
    /// Files that were created by a rotation on this pass.
    pub rotated: Vec<PathBuf>,
    /// Rotated files removed because they aged past their window.
    pub removed: Vec<PathBuf>,
}

/// Which boundary a log rolls on (§19.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Period {
    Daily,
    Weekly,
}

impl Period {
    /// The stamp that names the period a timestamp falls in. Two
    /// timestamps in the same period produce the same stamp, which is
    /// the whole of the roll predicate.
    fn stamp(self, at: SystemTime) -> String {
        let at: chrono::DateTime<chrono::Utc> = at.into();
        match self {
            // ISO year-week for the weekly log, so the last days of
            // December do not roll into the next January's stamp.
            Self::Weekly => at.format("%G-W%V").to_string(),
            Self::Daily => at.format("%Y-%m-%d").to_string(),
        }
    }
}

/// Roll `log` if its newest byte was written in an earlier period.
///
/// Returns the path the old content now lives at, or `None` when the
/// file is absent, empty, or still inside its period.
fn rotate(log: &Path, period: Period, now: SystemTime) -> io::Result<Option<PathBuf>> {
    let meta = match std::fs::metadata(log) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // An empty log has nothing to preserve, and rotating it would
    // produce a directory of empty files on a daemon nobody used.
    if meta.len() == 0 {
        return Ok(None);
    }
    let written = meta.modified()?;
    if period.stamp(written) == period.stamp(now) {
        return Ok(None);
    }
    let name = log
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir = log.parent().unwrap_or(Path::new("."));
    let base = period.stamp(written);
    // A second roll into the same stamp is possible when a daemon is
    // restarted after a long gap; suffix rather than overwrite, because
    // overwriting destroys the trail the rotation exists to preserve.
    let mut target = dir.join(format!("{name}.{base}"));
    let mut n = 1;
    while target.exists() {
        target = dir.join(format!("{name}.{base}.{n}"));
        n += 1;
    }
    std::fs::rename(log, &target)?;
    Ok(Some(target))
}

/// Delete every `<prefix>*` file in `dir` last written more than
/// `window` ago. The **current** log never matches, because `prefix`
/// carries the trailing dot a rotated name has and a live one does not.
fn retire(dir: &Path, prefix: &str, window: Duration, now: SystemTime) -> io::Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(prefix) {
            continue;
        }
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let age = match now.duration_since(meta.modified()?) {
            Ok(a) => a,
            // A file stamped in the future is not old.
            Err(_) => continue,
        };
        if age > window {
            let path = entry.path();
            std::fs::remove_file(&path)?;
            removed.push(path);
        }
    }
    removed.sort();
    Ok(removed)
}

/// Selects a CLASP *instance* (§7.1). Overrides discovery entirely and
/// relocates the sockets, the pid file, the lock file and the daemon log.
pub const RUNTIME_DIR_ENV: &str = "CLASP_RUNTIME_DIR";

/// Mode for the runtime and log directories: owner-only.
pub const DIR_MODE: u32 = 0o700;
/// Mode for every socket in it (spec §7.1: `0600` on each socket).
pub const SOCKET_MODE: u32 = 0o600;
/// Mode for every log file CLASP creates — the same `0600` as the
/// sockets, and for a stronger reason.
///
/// §9.4's audit trail records the command line, the argv, the cwd and
/// the env-var **key set** of everything the agent has run. A trail any
/// local user can read discloses more than the socket whose `0600` §7.1
/// spells out, so it does not get a weaker mode than the socket.
///
/// `0600` rather than `0400`, because the daemon appends to it for its
/// whole life; and an explicit mode rather than a umask, because a
/// umask is the invoking user's setting and the default one on every
/// mainstream distribution (`022`) yields `0644`.
pub const LOG_MODE: u32 = 0o600;

/// Open a CLASP log for appending, creating it — and the directory that
/// holds it — owner-only.
///
/// **Every log this codebase creates goes through here**, and the mode
/// lives at the point of creation rather than at the call sites for a
/// reason measured in this milestone: `serve_stdio` reaches
/// `AuditLog::to_path` with no `ensure_dir` ahead of it, so on a machine
/// that had never run the daemon `~/.clasp/logs/audit.log` was created
/// `0644` while the daemon's copy of the same file was `0600`. That is a
/// security property enforced on the transport somebody tested and not
/// on the one they did not, and a mode set at one call site would leave
/// the next caller free to reintroduce it.
///
/// The `open(2)` mode is applied by the kernel at creation and a umask
/// can only *clear* bits from it, so `0600` cannot be widened by the
/// environment. It has no effect on a file that already exists, which is
/// deliberate: there is **no verify-and-tighten step** here, for two
/// reasons. A `chmod` follows symlinks, so tightening a log another user
/// pre-created would chmod whatever they pointed it at. And a repair
/// path that runs before every assertion is exactly how
/// `ensure_dir_creates_the_tree_mode_0700` came to be unable to observe
/// its own `DirBuilder::mode` — see the note on that test.
pub fn open_log_append(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if let Some(parent) = path.parent() {
        // `recursive(true)` succeeds on a directory that already exists,
        // and applies `mode` only to the ones it creates — the same
        // "silently fine on a pre-existing world-readable directory"
        // that `ensure_dir` exists to catch on the runtime directory.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(LOG_MODE)
        .open(path)
}

/// Forces the process umask for the lifetime of the guard.
///
/// A mode test without this measures the developer's shell rather than
/// the code: under `umask 077` a file created with **no** explicit mode
/// already comes out `0600`, so the assertion passes against the very
/// defect it exists to catch. Forcing `022` — the default on every
/// mainstream distribution — makes the naive creation come out `0644`,
/// which is what gives the assertion something to discriminate.
///
/// The umask is process-global and the test binary is threaded, so this
/// is deliberately the loosest value anything here asserts against:
/// `022` can clear no bit of `0600` or `0700`, so a concurrent test
/// creating a file with an explicit mode is unaffected either way.
#[cfg(test)]
pub(crate) struct ForcedUmask(libc::mode_t);

#[cfg(test)]
impl ForcedUmask {
    pub(crate) fn loose() -> Self {
        // SAFETY: `umask` cannot fail; it returns the previous mask.
        Self(unsafe { libc::umask(0o022) })
    }
}

#[cfg(test)]
impl Drop for ForcedUmask {
    fn drop(&mut self) {
        // SAFETY: as above, restoring what we replaced.
        unsafe { libc::umask(self.0) };
    }
}

/// `sockaddr_un.sun_path` is 108 bytes on Linux and 104 on macOS, minus
/// the NUL. Binding a longer path fails with a confusing `EINVAL`, so we
/// check up front and say what is actually wrong (§7.1).
const MAX_SOCKET_PATH: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    dir: PathBuf,
    log_dir: PathBuf,
}

impl RuntimePaths {
    /// An **isolated instance** rooted at `dir` — what `CLASP_RUNTIME_DIR`
    /// selects, and what every test uses. Per §7.1 the daemon log moves
    /// under it too, so the instance leaves nothing behind in `~`.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let log_dir = dir.join("logs");
        Self { dir, log_dir }
    }

    /// The decision function behind [`discover`], with the environment
    /// passed in.
    ///
    /// Factored out because the test binary is threaded: `std::env::set_var`
    /// would race every other test in the process, so the branches are
    /// exercised through explicit inputs instead of a mutated environment.
    ///
    /// [`discover`]: RuntimePaths::discover
    pub fn resolve(
        runtime_dir_override: Option<PathBuf>,
        xdg_runtime_dir: Option<PathBuf>,
        home: Option<PathBuf>,
        is_linux: bool,
        is_macos: bool,
    ) -> io::Result<Self> {
        // §7.1: an explicit instance takes everything with it, logs
        // included.
        if let Some(dir) = runtime_dir_override {
            return Ok(Self::with_dir(dir));
        }

        let home = home.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("neither {RUNTIME_DIR_ENV}, XDG_RUNTIME_DIR, nor HOME is set"),
            )
        });

        // §19.1: the daemon log lives in `~/.clasp/logs` whenever the
        // instance is the default one, whatever the runtime directory is.
        let log_dir = match &home {
            Ok(h) => h.join(".clasp").join("logs"),
            Err(_) => PathBuf::new(),
        };

        if is_linux {
            if let Some(xdg) = xdg_runtime_dir {
                let log_dir = log_dir_or_err(log_dir, &home)?;
                return Ok(Self {
                    dir: xdg.join("clasp"),
                    log_dir,
                });
            }
        }
        let home = home?;
        let dir = if is_macos {
            home.join("Library/Application Support/clasp")
        } else {
            home.join(".clasp")
        };
        Ok(Self {
            log_dir: dir.join("logs"),
            dir,
        })
    }

    /// Spec §7.1: `$CLASP_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/clasp`
    /// (Linux), else `~/Library/Application Support/clasp` (macOS), else
    /// `~/.clasp`.
    pub fn discover() -> io::Result<Self> {
        Self::resolve(
            std::env::var_os(RUNTIME_DIR_ENV).map(PathBuf::from),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
            cfg!(target_os = "linux"),
            cfg!(target_os = "macos"),
        )
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// RPC for MCP tool handlers and CLI commands (§7.2).
    pub fn control_sock(&self) -> PathBuf {
        self.dir.join("control.sock")
    }

    /// Live PTY duplex stream. Reserved here, bound in 0.0.6.
    pub fn attach_sock(&self) -> PathBuf {
        self.dir.join("attach.sock")
    }

    /// Web UI HTTP/WS. Reserved here, bound in 0.0.10.
    ///
    /// **Derived, never configured.** §10.2 carried an `http_socket_path`
    /// knob until rev. 47 removed it: it was the only socket-path knob,
    /// it duplicated §7.1, and it could place a socket outside the
    /// directory whose `0700` mode §7.1 verifies — which would make
    /// REQ-CFG-005's own integration test falsifiable from a config
    /// file. `CLASP_RUNTIME_DIR` relocates all three sockets together as
    /// an *instance*, which is the only relocation §7.1 sanctions. Task
    /// 15 Step 4 rejects a config that carries the withdrawn key rather
    /// than ignoring it.
    pub fn http_sock(&self) -> PathBuf {
        self.dir.join("http.sock")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.dir.join("clasp.pid")
    }

    /// The **start** lock (§7.3 steps 1–2): who gets to decide that no
    /// daemon is running and spawn one.
    pub fn lock_file(&self) -> PathBuf {
        self.dir.join("clasp.lock")
    }

    /// The **bind** lock: who owns `bind_control`'s probe → unlink →
    /// bind window.
    ///
    /// **A second file, and it must stay a second file.** The obvious
    /// simplification — have `bind_control` take `clasp.lock` —
    /// deadlocks `clasp daemon start` outright: `start_detached` holds
    /// `clasp.lock` across the spawn *and* the 2 s poll that waits for
    /// the socket (`spawn.rs`, `let _lock = …` living to end of
    /// function), and the child `clasp daemon run` does not inherit it
    /// because Rust opens `O_CLOEXEC`. The child would block on the
    /// lock, never bind, and the parent would time out waiting for the
    /// socket it is itself preventing.
    ///
    /// The two locks answer different questions and neither subsumes the
    /// other: `clasp.lock` serialises *starters*, this one serialises
    /// *binders*. The case that needs it is the one `clasp.lock` cannot
    /// see — a `start_detached` that already timed out and released
    /// while its child was still binding.
    pub fn bind_lock_file(&self) -> PathBuf {
        self.dir.join("bind.lock")
    }

    /// §19.1's log directory — `~/.clasp/logs` by default, relocated
    /// under the runtime directory only for an explicit instance (§7.1).
    pub fn log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }

    pub fn daemon_log(&self) -> PathBuf {
        self.log_dir.join("daemon.log")
    }

    /// §9.4's audit trail, in the same directory as `daemon.log` and for
    /// the same reason.
    ///
    /// `audit::default_path()` is `~/.clasp/logs/audit.log` and takes no
    /// environment override, so on the **default** instance this returns
    /// exactly that path — the two agree by construction rather than by
    /// coincidence, because `log_dir` for the default instance *is*
    /// `~/.clasp/logs`. On an explicit `CLASP_RUNTIME_DIR` instance the
    /// audit log follows the instance, which §7.1 states only for
    /// `daemon.log`; see the decision recorded in **Decisions taken**.
    /// Without this, every `daemon_cli.rs` test with a private runtime
    /// directory would append to the developer's real audit log — the
    /// one file in the project a test must never touch.
    pub fn audit_log(&self) -> PathBuf {
        self.log_dir.join("audit.log")
    }

    /// Create the runtime and log directories `0700`, then *verify* the
    /// mode. Creating a directory that already exists is not an error,
    /// so an existing world-readable directory would otherwise sail
    /// through and the sockets inside it would be reachable by any local
    /// user with the right timing (§7.1).
    pub fn ensure_dir(&self) -> io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        self.check_socket_path_length()?;
        for dir in [self.dir.clone(), self.log_dir.clone()] {
            if !dir.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(DIR_MODE)
                    .create(&dir)?;
            }
            let mode = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
            // Tighten a *leak*; **refuse** a writable one. The two cases
            // differ in what tightening can still repair.
            //
            // A `0755` leftover from an earlier install leaks the names
            // of the sockets inside, and a chmod to `0700` removes that
            // leak outright — §7.1 describes exactly this case, and
            // tightening rather than rejecting it is this milestone's
            // recorded divergence from REQ-CFG-005's verification column.
            //
            // A group- or world-**writable** directory is not the same
            // thing, and a chmod does not repair it. Another local user
            // could already have pre-created `logs/` inside it as a
            // **symlink**: `dir.exists()` follows it, `metadata` follows
            // it, `set_permissions` would chmod the *target*, and
            // `Daemon::new` then appends §9.4 audit entries through an
            // attacker-chosen path. `bind_control`'s stale-socket sweep
            // defends `control.sock`; nothing defends `logs/`. Refusing
            // the parent is what closes it, and the loop reaches
            // `self.dir` before `self.log_dir`, so the refusal lands
            // before any such symlink is traversed.
            if mode & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is mode {mode:o}: group/world-writable, so another local user \
                         may already have planted entries inside it. Refusing rather than \
                         tightening — a chmod does not undo what is already there. Remove \
                         it, or set {RUNTIME_DIR_ENV} to a directory you own.",
                        dir.display()
                    ),
                ));
            }
            if mode != DIR_MODE {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE))?;
                let after = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
                if after != DIR_MODE {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "{} is mode {after:o}, and could not be tightened to {DIR_MODE:o}",
                            dir.display()
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Rotate the two §19.1 logs and delete what has aged out
    /// (REQ-SEC-009).
    ///
    /// §19.1 specifies **two** mechanisms per log and neither works
    /// alone: with nothing rotating there is only ever one `audit.log`
    /// and one `daemon.log`, and the retention sweep has nothing to
    /// choose between.
    ///
    /// | Log | Rotate | Retain | Knob |
    /// |---|---|---|---|
    /// | `audit.log` | daily | 14 days | `[daemon] audit_retention_days` |
    /// | `daemon.log` | weekly | 4 weeks | `[daemon] daemon_log_retention_weeks` |
    ///
    /// Rolls on the **period boundary** rather than on a size threshold:
    /// the retention windows are expressed in time, so a size-triggered
    /// roll makes "14 days" mean "14 files of unknown age".
    ///
    /// **Do not call this with an open handle on `audit.log`.** The
    /// daemon holds one for the process's lifetime, so the sweep either
    /// runs before that handle is taken — which is what `server::run`
    /// does at startup — or is followed by [`crate::audit::AuditLog::reopen`],
    /// which is what the periodic sweep does. A rename that leaves the
    /// daemon appending to an unlinked inode silently discards §9.4's
    /// trail while every file on disk looks correct.
    pub fn sweep_logs(&self, retention: LogRetention, now: SystemTime) -> io::Result<LogSweep> {
        let mut sweep = LogSweep::default();
        if !self.log_dir.exists() {
            return Ok(sweep);
        }
        if let Some(to) = rotate(&self.audit_log(), Period::Daily, now)? {
            sweep.rotated.push(to);
        }
        if let Some(to) = rotate(&self.daemon_log(), Period::Weekly, now)? {
            sweep.rotated.push(to);
        }
        sweep.removed.extend(retire(
            &self.log_dir,
            "audit.log.",
            Duration::from_secs(u64::from(retention.audit_days) * SECS_PER_DAY),
            now,
        )?);
        sweep.removed.extend(retire(
            &self.log_dir,
            "daemon.log.",
            Duration::from_secs(u64::from(retention.daemon_log_weeks) * 7 * SECS_PER_DAY),
            now,
        )?);
        Ok(sweep)
    }

    fn check_socket_path_length(&self) -> io::Result<()> {
        let path = self.control_sock();
        let len = path.as_os_str().len();
        if len > MAX_SOCKET_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "runtime directory is too deep: the control socket path is {len} bytes \
                     and the platform limit is {MAX_SOCKET_PATH}. Set {RUNTIME_DIR_ENV} to \
                     something shorter."
                ),
            ));
        }
        Ok(())
    }
}

/// `home` is only needed for the log directory on the XDG path, so its
/// absence is reported there rather than aborting discovery earlier.
fn log_dir_or_err(log_dir: PathBuf, home: &io::Result<PathBuf>) -> io::Result<PathBuf> {
    match home {
        Ok(_) => Ok(log_dir),
        Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Short by design: a socket path under a deep `target/` directory
    /// would exceed `sun_path`.
    fn temp_dir(tag: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        PathBuf::from(format!("/tmp/clasp-t-{tag}-{}", &unique[..8]))
    }

    struct Scoped(PathBuf);
    impl Drop for Scoped {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ------------------------------------------- §19.1 rotation/retention

    fn days(n: u64) -> Duration {
        Duration::from_secs(n * SECS_PER_DAY)
    }

    /// Backdate a file's mtime, which is how the rotation predicate and
    /// the retention window are driven without waiting a fortnight.
    fn backdate(path: &Path, by: Duration) {
        let f = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open for set_times");
        let when = SystemTime::now() - by;
        f.set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn rotation_starts_a_new_file_and_leaves_the_old_one_readable() {
        let dir = temp_dir("rot");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();

        write(&paths.audit_log(), "{\"kind\":\"before\"}\n");
        backdate(&paths.audit_log(), days(1));

        let now = SystemTime::now();
        let sweep = paths.sweep_logs(LogRetention::default(), now).unwrap();
        assert_eq!(sweep.rotated.len(), 1, "the daily boundary was crossed");
        let rolled = &sweep.rotated[0];

        // Rotation by truncation satisfies "a new file started" and
        // destroys the trail it was supposed to preserve. The old
        // content must still be readable from the rotated file.
        assert_eq!(
            std::fs::read_to_string(rolled).unwrap(),
            "{\"kind\":\"before\"}\n",
            "the rotated file lost the entries it was rotated to keep"
        );
        assert!(
            !paths.audit_log().exists(),
            "the live path is free for a fresh file"
        );
        write(&paths.audit_log(), "{\"kind\":\"after\"}\n");
        assert_eq!(
            std::fs::read_to_string(paths.audit_log()).unwrap(),
            "{\"kind\":\"after\"}\n"
        );
    }

    #[test]
    fn a_log_written_inside_its_period_is_not_rotated() {
        // The pairing: a sweep that rotates unconditionally passes the
        // row above perfectly and shreds a busy daemon's log every 24 h.
        let dir = temp_dir("norot");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();
        write(&paths.audit_log(), "{\"kind\":\"today\"}\n");
        write(&paths.daemon_log(), "INFO up\n");

        let sweep = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        assert!(sweep.rotated.is_empty(), "rotated inside the period");
        assert!(paths.audit_log().exists());
        assert!(paths.daemon_log().exists());
    }

    #[test]
    fn the_daemon_log_rolls_weekly_and_the_audit_log_daily() {
        // The two periods are different, and a sweep that used one for
        // both is invisible to every single-log test.
        let dir = temp_dir("period");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();
        write(&paths.audit_log(), "a\n");
        write(&paths.daemon_log(), "d\n");
        // Two days back: past the daily boundary, and — because the
        // stamp is an ISO year-week — not necessarily past the weekly
        // one. Assert the audit log rolled; say nothing about the daemon
        // log, whose answer depends on which weekday the suite runs.
        backdate(&paths.audit_log(), days(2));
        backdate(&paths.daemon_log(), days(2));
        let sweep = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        assert!(
            sweep.rotated.iter().any(|p| p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("audit.log.")),
            "a two-day-old audit log is past its daily boundary"
        );

        // Now push the daemon log far enough back that no ISO week
        // ambiguity remains, and assert it rolls on *its* boundary.
        write(&paths.daemon_log(), "d2\n");
        backdate(&paths.daemon_log(), days(10));
        let sweep = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        assert!(
            sweep.rotated.iter().any(|p| p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("daemon.log.")),
            "a ten-day-old daemon log is past its weekly boundary"
        );
    }

    #[test]
    fn retention_deletes_only_what_is_older_than_the_window() {
        let dir = temp_dir("retain");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();

        let keep = paths.log_dir().join("audit.log.2026-08-05");
        let drop = paths.log_dir().join("audit.log.2026-08-03");
        write(&keep, "kept\n");
        write(&drop, "dropped\n");
        backdate(&keep, days(13));
        backdate(&drop, days(15));

        let sweep = paths
            .sweep_logs(
                LogRetention {
                    audit_days: 14,
                    daemon_log_weeks: 4,
                },
                SystemTime::now(),
            )
            .unwrap();

        // The surviving file is the half that catches a sweep which
        // deletes everything; the removed one catches an off-by-one that
        // keeps forever.
        assert!(keep.exists(), "a 13-day-old file is inside a 14-day window");
        assert!(!drop.exists(), "a 15-day-old file is outside it");
        assert_eq!(sweep.removed, vec![drop]);
    }

    #[test]
    fn retention_never_deletes_the_live_log() {
        // The discriminator is the trailing dot: `audit.log.` matches a
        // rotated file and not the live one. A sweep written as
        // `starts_with("audit.log")` deletes the file the daemon is
        // appending to the first time the daemon outlives its window,
        // and every rotated-file test above passes against it.
        let dir = temp_dir("retain-live");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();

        let live = paths.audit_log();
        let rolled = paths.log_dir().join("audit.log.2026-01-01");
        write(&live, "live\n");
        write(&rolled, "rolled\n");
        backdate(&live, days(400));
        backdate(&rolled, days(400));

        let removed = retire(&paths.log_dir(), "audit.log.", days(14), SystemTime::now()).unwrap();
        assert_eq!(removed, vec![rolled.clone()]);
        assert!(!rolled.exists());
        assert!(
            live.exists(),
            "the live log was retired — a daemon older than its own retention window \
             loses the file it is writing to"
        );
    }

    #[test]
    fn a_second_roll_into_one_stamp_does_not_overwrite_the_first() {
        let dir = temp_dir("twice");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();

        write(&paths.audit_log(), "first\n");
        backdate(&paths.audit_log(), days(1));
        let a = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap()
            .rotated
            .remove(0);
        write(&paths.audit_log(), "second\n");
        backdate(&paths.audit_log(), days(1));
        let b = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap()
            .rotated
            .remove(0);

        assert_ne!(a, b, "the second roll overwrote the first day's trail");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "first\n");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "second\n");
    }

    #[test]
    fn an_empty_log_is_not_rotated() {
        let dir = temp_dir("empty");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();
        write(&paths.audit_log(), "");
        backdate(&paths.audit_log(), days(30));
        let sweep = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        assert!(
            sweep.rotated.is_empty(),
            "a daemon nobody used would accrue a directory of empty files"
        );
    }

    #[test]
    fn the_retention_window_comes_from_the_config_file() {
        let cfg = crate::config::parse_str(
            "[daemon]\naudit_retention_days = 3\ndaemon_log_retention_weeks = 1\n",
        )
        .expect("loads");
        assert_eq!(
            LogRetention::from(&cfg),
            LogRetention {
                audit_days: 3,
                daemon_log_weeks: 1
            }
        );
        // Paired with the default, so a conversion that ignored the
        // config and returned `Default::default()` is red above.
        assert_eq!(
            LogRetention::from(&crate::config::Config::default()),
            LogRetention::default()
        );
        // And the window it produces actually bites: a 4-day-old file is
        // outside a 3-day window and inside the 14-day default.
        let dir = temp_dir("window");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();
        let f = paths.log_dir().join("audit.log.2026-08-14");
        write(&f, "x\n");
        backdate(&f, days(4));
        paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        assert!(f.exists(), "4 days is inside the 14-day default");
        paths
            .sweep_logs(LogRetention::from(&cfg), SystemTime::now())
            .unwrap();
        assert!(!f.exists(), "4 days is outside the configured 3-day window");
    }

    #[test]
    fn the_daemon_keeps_writing_across_a_rotation() {
        use crate::audit::AuditLog;
        use crate::output::rules::builtin_shared;

        let dir = temp_dir("across");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();

        let log = AuditLog::to_path(paths.audit_log(), builtin_shared()).expect("open audit log");
        log.record("before", None, serde_json::json!({}));
        backdate(&paths.audit_log(), days(1));

        let sweep = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        assert_eq!(sweep.rotated.len(), 1);
        // The reopen is the whole point: without it the next `record`
        // lands in an unlinked inode, every file on disk looks correct,
        // and §9.4's trail stops.
        log.reopen().expect("reopen after rotation");
        log.record("after", None, serde_json::json!({}));

        let current = std::fs::read_to_string(paths.audit_log()).expect("the live log exists");
        assert!(
            current.contains("\"after\""),
            "the entry landed somewhere other than the current file: {current:?}"
        );
        assert!(
            !current.contains("\"before\""),
            "the pre-rotation entry is in the rotated file, not this one"
        );
        assert!(std::fs::read_to_string(&sweep.rotated[0])
            .unwrap()
            .contains("\"before\""));
    }

    #[test]
    fn every_socket_lives_in_the_runtime_directory() {
        let p = RuntimePaths::with_dir("/run/user/1000/clasp");
        assert_eq!(
            p.control_sock(),
            PathBuf::from("/run/user/1000/clasp/control.sock")
        );
        assert_eq!(
            p.attach_sock(),
            PathBuf::from("/run/user/1000/clasp/attach.sock")
        );
        assert_eq!(
            p.http_sock(),
            PathBuf::from("/run/user/1000/clasp/http.sock")
        );
        assert_eq!(
            p.pid_file(),
            PathBuf::from("/run/user/1000/clasp/clasp.pid")
        );
        assert_eq!(
            p.lock_file(),
            PathBuf::from("/run/user/1000/clasp/clasp.lock")
        );
    }

    /// **This pins the post-condition, not the creation mode.** Measured:
    /// changing the `DirBuilder`'s `.mode(DIR_MODE)` to `.mode(0o755)`
    /// leaves this test green, because the verify-and-tighten step below
    /// it reflows the defect away before the assertion ever runs. That is
    /// the right answer for the *guarantee* — the directory ends `0700`
    /// however it was created — but it means this test is not the guard
    /// on `DirBuilder::mode`, and nothing here is.
    /// `ensure_dir_tightens_a_pre_existing_world_readable_directory` is
    /// the test that actually discriminates the tighten step.
    #[test]
    fn ensure_dir_creates_the_tree_mode_0700() {
        let dir = temp_dir("mk");
        let _scoped = Scoped(dir.clone());
        let p = RuntimePaths::with_dir(&dir);
        p.ensure_dir().unwrap();

        for d in [p.dir().to_path_buf(), p.log_dir()] {
            let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is mode {mode:o}", d.display());
        }
    }

    /// **The creation mode, with a control that says the mode came from
    /// us.** Unlike `ensure_dir`, `open_log_append` has no
    /// verify-and-tighten step, so this assertion really does observe
    /// what `OpenOptions::mode` set — delete `.mode(LOG_MODE)` and the
    /// log comes out `0644` and this row goes red.
    ///
    /// The `naive` half is the control, and it is the one that stops
    /// this passing for the wrong reason: it creates a file exactly the
    /// way the defective code did, in the same directory, under the same
    /// forced umask. If the umask forcing failed to take, `naive` comes
    /// out `0600` too and its assertion fails — so a green run means the
    /// environment was genuinely permissive and the log was tight
    /// anyway.
    #[test]
    fn a_log_is_created_owner_only_under_an_owner_only_directory() {
        let dir = temp_dir("logmode");
        let _scoped = Scoped(dir.clone());
        let _umask = ForcedUmask::loose();

        let naive = dir.join("naive").join("daemon.log");
        std::fs::create_dir_all(naive.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&naive)
            .unwrap();
        assert_eq!(
            mode_of(&naive),
            0o644,
            "the control did not come out world-readable, so this test could \
             not have told a set mode from an ambient one"
        );
        assert_eq!(mode_of(naive.parent().unwrap()), 0o755);

        let log = dir.join("logs").join("audit.log");
        open_log_append(&log).unwrap();
        assert_eq!(
            mode_of(&log),
            LOG_MODE,
            "the log is readable by every local user"
        );
        assert_eq!(
            mode_of(log.parent().unwrap()),
            DIR_MODE,
            "the directory holding it leaks the names inside"
        );
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ensure_dir_tightens_a_pre_existing_world_readable_directory() {
        // `create_dir_all` succeeds silently on an existing directory, so
        // without the verify-and-tighten step a 0755 leftover from an
        // earlier install would stay 0755 and the sockets inside it would
        // be enumerable by any local user.
        let dir = temp_dir("loose");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );

        RuntimePaths::with_dir(&dir).ensure_dir().unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn ensure_dir_refuses_a_pre_existing_group_or_world_writable_directory() {
        // The residual the tighten step leaves behind. A `0755` leftover
        // is a leak and a chmod removes it; a writable one is a foothold
        // and a chmod does not, because `logs/` may already be somebody
        // else's symlink by the time we look — after which every §9.4
        // audit entry is appended to a path they chose.
        //
        // Both bits, separately: a mutation that checked only `0o002`
        // would sail past `0o770` on a shared group, which is the more
        // likely of the two in practice.
        for loose in [0o777, 0o757, 0o770] {
            let dir = temp_dir(&format!("wr{loose:o}"));
            let _scoped = Scoped(dir.clone());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(loose)).unwrap();

            let err = RuntimePaths::with_dir(&dir)
                .ensure_dir()
                .expect_err("a writable runtime directory must be refused, not tightened");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
            assert!(
                err.to_string().contains(RUNTIME_DIR_ENV),
                "the error must name the escape hatch: {err}"
            );
            // And it refused rather than repairing: a `logs/` created
            // under the loose mode is exactly what the refusal is for.
            assert!(
                !dir.join("logs").exists(),
                "nothing may be created inside a directory that was refused"
            );
        }
    }

    #[test]
    fn an_over_long_runtime_directory_is_rejected_with_advice() {
        let deep = PathBuf::from("/tmp").join("x".repeat(120));
        let err = RuntimePaths::with_dir(deep).ensure_dir().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains(RUNTIME_DIR_ENV),
            "the error must name the escape hatch: {err}"
        );
    }

    #[test]
    fn an_explicit_instance_takes_its_log_directory_with_it() {
        // §7.1: `CLASP_RUNTIME_DIR` relocates the daemon log too, so an
        // isolated instance leaves nothing in the user's home.
        let p = RuntimePaths::resolve(
            Some("/tmp/clasp-instance".into()),
            Some("/run/user/1000".into()),
            Some("/home/u".into()),
            true,
            false,
        )
        .unwrap();
        assert_eq!(p.dir(), Path::new("/tmp/clasp-instance"));
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/tmp/clasp-instance/logs/daemon.log")
        );
        assert_eq!(
            p.audit_log(),
            PathBuf::from("/tmp/clasp-instance/logs/audit.log")
        );
        // Both logs, not just the one §7.1 names. `audit::default_path()`
        // has no environment override, so if the audit log did not follow
        // the instance, every test with a private `CLASP_RUNTIME_DIR`
        // would append to the developer's real `~/.clasp/logs/audit.log`
        // — which the `daemon_log`-only version of this assertion could
        // not see.
        //
        // The loop below is **documentation, not an independent guard**:
        // any path that could trip it has already failed one of the two
        // `assert_eq!`s above, which pin both logs exactly. It states the
        // property the exact paths happen to satisfy; it cannot fail
        // alone, and it is recorded as such rather than left to read like
        // a second check.
        for log in [p.daemon_log(), p.audit_log()] {
            assert!(
                !log.starts_with("/home/u"),
                "an isolated instance must not write into the home directory: {}",
                log.display()
            );
        }
    }

    #[test]
    fn the_default_instance_logs_to_the_home_directory_not_tmpfs() {
        // §19.1 puts daemon.log in `~/.clasp/logs` with a 4-week
        // retention. `$XDG_RUNTIME_DIR` is tmpfs and is cleared at
        // logout, so a log written there could never survive its own
        // retention window — the bug this test exists to prevent.
        let p = RuntimePaths::resolve(
            None,
            Some("/run/user/1000".into()),
            Some("/home/u".into()),
            true,
            false,
        )
        .unwrap();
        assert_eq!(p.dir(), Path::new("/run/user/1000/clasp"));
        assert_eq!(
            p.control_sock(),
            PathBuf::from("/run/user/1000/clasp/control.sock")
        );
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/home/u/.clasp/logs/daemon.log"),
            "§19.1: the default instance logs under HOME, not under tmpfs"
        );
        // The pairing that makes `Daemon::new`'s audit path safe to take
        // from here: on the *default* instance it must be byte-identical
        // to `audit::default_path()`, or the daemon would write §9.4's
        // trail somewhere `clasp logs` and every operator runbook would
        // not look. This is the negative for the instance-relocation
        // assertion above — relocation must not leak into the default.
        assert_eq!(
            p.audit_log(),
            PathBuf::from("/home/u/.clasp/logs/audit.log"),
            "§9.4's default path is `~/.clasp/logs/audit.log` and takes no override"
        );
    }

    #[test]
    fn discovery_falls_back_to_the_home_directory_for_both() {
        // No XDG (or not Linux): runtime dir and logs coincide under
        // `~/.clasp`, which is what §7.1's fallback and §19.1 both name.
        let p = RuntimePaths::resolve(None, None, Some("/home/u".into()), true, false).unwrap();
        assert_eq!(p.dir(), Path::new("/home/u/.clasp"));
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/home/u/.clasp/logs/daemon.log")
        );

        let mac = RuntimePaths::resolve(None, None, Some("/Users/u".into()), false, true).unwrap();
        assert_eq!(
            mac.dir(),
            Path::new("/Users/u/Library/Application Support/clasp")
        );
        assert_eq!(
            mac.daemon_log(),
            PathBuf::from("/Users/u/Library/Application Support/clasp/logs/daemon.log")
        );
    }

    #[test]
    fn discovery_without_home_or_an_override_is_an_error() {
        let err = RuntimePaths::resolve(None, None, None, true, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains(RUNTIME_DIR_ENV), "{err}");
    }
}
