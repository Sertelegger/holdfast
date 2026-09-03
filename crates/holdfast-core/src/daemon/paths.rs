//! Runtime directory and socket discovery (spec §7.1, §7.2, §19.1).
//!
//! Every path Holdfast binds lives under one `0700` directory owned by the
//! invoking user. That directory permission — not any in-band credential
//! — is the first half of the daemon's trust boundary (§9.1); the
//! peer-credential check in `daemon::peer` is the second.
//!
//! **Logs are not sockets.** §7.1 relocates `daemon.log` under the
//! runtime directory only when `HOLDFAST_RUNTIME_DIR` is explicitly set, so
//! an isolated instance leaves nothing in the user's home. With the
//! variable unset, §19.1's `~/.holdfast/logs` applies: `$XDG_RUNTIME_DIR` is
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

/// How a roll moves the old bytes aside.
///
/// The choice is decided by **who opened the file**, not by taste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Roll {
    /// `rename(2)`: atomic, and it loses nothing to a concurrent write.
    /// Correct wherever the writer can *reopen* — `audit.log`, which
    /// `sweep_and_reopen` reopens through
    /// [`crate::audit::AuditLog::reopen`] immediately after the sweep.
    Rename,
    /// Copy the bytes to the stamped name, then truncate the original in
    /// place, so **every** descriptor already open on it stays valid and
    /// keeps writing to the live file.
    ///
    /// This is `daemon.log`'s, and it is the only shape that works for
    /// it. `daemon.log` is opened by the process that **spawns** the
    /// daemon (`spawn.rs`) and handed to it as fd 1 and fd 2; the daemon
    /// never opens it, so there is nothing for `run` to reopen and no
    /// ordering inside `run` that repairs a rename. After a rename the
    /// inherited descriptor writes to a file no path reaches, `retire`
    /// unlinks that file a retention window later, and the harm
    /// concentrates in *quiet* daemons — the ones whose log you only
    /// open once something has gone wrong.
    ///
    /// A `dup2` onto fd 1/2 is not the alternative it looks like: under
    /// systemd `holdfast daemon run` is started directly and fd 2 is the
    /// journal, so a `dup2` would redirect the journal's stream into a
    /// file, which is worse than the bug. Copy-truncate is correct
    /// whatever the inherited descriptor points at, including when it
    /// points at something that is not this file at all.
    ///
    /// The cost is a window between the copy and the truncate in which a
    /// concurrently-written line is lost, and briefly two copies of the
    /// bytes on disk. Both are bounded by one period of a diagnostic
    /// log, and neither is a reason to take it for `audit.log`.
    CopyTruncate,
}

/// Roll `log` if its newest byte was written in an earlier period.
///
/// Returns the path the old content now lives at, or `None` when the
/// file is absent, empty, or still inside its period.
fn rotate(log: &Path, period: Period, roll: Roll, now: SystemTime) -> io::Result<Option<PathBuf>> {
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
    match roll {
        Roll::Rename => std::fs::rename(log, &target)?,
        Roll::CopyTruncate => {
            // `fs::copy` carries the source's permission bits, so the
            // stamped file is `0600` like the log it came from.
            std::fs::copy(log, &target)?;
            // It does **not** carry the mtime, and `retire` measures the
            // retention window from the last byte written — which for
            // the rename half is what `rename` preserves for free.
            // Without this, `daemon.log.<stamp>` would be born *now* and
            // age out a full period late, on a clock `audit.log.<stamp>`
            // does not use.
            std::fs::File::options()
                .write(true)
                .open(&target)?
                .set_times(std::fs::FileTimes::new().set_modified(written))?;
            // Truncate rather than unlink-and-recreate: the whole point
            // is that the descriptor the daemon was handed still refers
            // to this inode afterwards. `O_APPEND` — which
            // `open_log_append` sets and the child inherits — makes the
            // next write land at the new end of file, offset zero.
            std::fs::File::options().write(true).open(log)?.set_len(0)?;
        }
    }
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
        // `DirEntry::metadata` is `lstat`-based. Not a safety property:
        // `remove_file` is `unlink(2)` and never follows a symlink, so
        // `std::fs::metadata` here would only take the age decision from
        // a file other than the one being unlinked.
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

/// Selects a Holdfast *instance* (§7.1). Overrides discovery entirely and
/// relocates the sockets, the pid file, the lock file and the daemon log.
pub const RUNTIME_DIR_ENV: &str = "HOLDFAST_RUNTIME_DIR";

/// Mode for the runtime and log directories: owner-only.
pub const DIR_MODE: u32 = 0o700;
/// Mode for every socket in it (spec §7.1: `0600` on each socket).
pub const SOCKET_MODE: u32 = 0o600;
/// Mode for every log file Holdfast creates — the same `0600` as the
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

/// Open a Holdfast log for appending, creating it — and the directory that
/// holds it — owner-only.
///
/// **Every log this codebase creates goes through here**, and the mode
/// lives at the point of creation rather than at the call sites for a
/// reason measured in this milestone: `serve_stdio` reaches
/// `AuditLog::to_path` with no `ensure_dir` ahead of it, so on a machine
/// that had never run the daemon `~/.holdfast/logs/audit.log` was created
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
#[cfg(unix)]
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

/// The same file, created without a mode, because Windows has none to set.
///
/// **This warns and proceeds; it does not refuse, and it does not pretend.**
/// The refusing version was considered and is wrong: a file created here
/// inherits the DACL of its parent, and the parent is inside the user's own
/// profile, so the inherited ACL grants the owning user, `SYSTEM` and
/// `Administrators` — not "everyone". That is a genuinely different posture
/// from a `0644` on Unix, and refusing to write an audit log over it would
/// trade a real capability for a risk that is largely already handled by the
/// platform.
///
/// What is *not* handled, and is what the warning is for: Holdfast asserts
/// nothing here. On Unix `LOG_MODE` is enforced and `ensure_owner_only`
/// re-checks it; here the ACL is whatever was inherited, which a machine
/// policy, a redirected profile, or a runtime directory relocated onto a
/// shared volume by `HOLDFAST_RUNTIME_DIR` can all widen without Holdfast
/// noticing. An explicit DACL is 0.0.11's, and the 0.0.11 plan records a
/// decision (D9) for the recording file's `0600` and **none** for this path.
#[cfg(windows)]
pub fn open_log_append(path: &Path) -> io::Result<std::fs::File> {
    warn_inherited_acl_once();

    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new().recursive(true).create(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Say once per process that the mode bits this module is named for are not
/// being applied.
///
/// **Once, and on stderr.** Once because this is a property of the platform
/// rather than of the file, and one line per log write would be noise an
/// operator learns to scroll past. On stderr via `diag::emit` because on
/// Windows the only transport is stdio-only MCP (§3.3) and **stdout is the
/// JSON-RPC wire** — a warning written there is a protocol violation, not a
/// diagnostic.
/// `pub(crate)` so `config::untrusted_reason` raises the same one. Two
/// warnings about one platform fact is two chances to ignore it.
#[cfg(windows)]
pub(crate) fn warn_inherited_acl_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        crate::diag::emit(
            "no supported permission model on this platform: Holdfast's runtime \
             directory, logs and config.toml are used with the ACL they inherit \
             from their parent. The 0700/0600 modes it enforces on Unix are not \
             applied, and the config trust check (owner and mode) does not run — \
             config.toml is read whoever owns it. Inside a normal user profile \
             the inherited ACL is owner + SYSTEM + Administrators, which is \
             usually what you want; on a redirected profile, a shared volume, or \
             a HOLDFAST_RUNTIME_DIR or XDG_CONFIG_HOME pointed somewhere else, it \
             may not be. Set the ACL yourself if that matters.",
        );
    });
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
#[cfg(all(test, unix))]
pub(crate) struct ForcedUmask(libc::mode_t);

#[cfg(all(test, unix))]
impl ForcedUmask {
    pub(crate) fn loose() -> Self {
        // SAFETY: `umask` cannot fail; it returns the previous mask.
        Self(unsafe { libc::umask(0o022) })
    }
}

#[cfg(all(test, unix))]
impl Drop for ForcedUmask {
    fn drop(&mut self) {
        // SAFETY: as above, restoring what we replaced.
        unsafe { libc::umask(self.0) };
    }
}

/// The user's home directory, as **this platform** names it.
///
/// **`USERPROFILE` on Windows, and without it the whole Windows build is
/// pathless.** `HOME` is a POSIX convention and a native Windows process
/// does not have it — measured: `cmd /c "echo %HOME%"` echoes the literal
/// `%HOME%`, while `%USERPROFILE%` is `C:\Users\<name>`. Every path this
/// module hands out is derived from this one answer, so with `HOME` unset
/// `RuntimePaths::discover()` returns `NotFound`, `serve_stdio` swallows it
/// with `.ok()`, and `holdfast mcp` runs with **no §9.4 audit trail at all**
/// — silently, because a missing trail looks exactly like a quiet one.
///
/// It is also what makes #19's "warn rather than refuse" posture reachable.
/// Both callers of `warn_inherited_acl_once` sit downstream of path
/// resolution, so before this the warning could not fire on the platform it
/// exists to describe. Measured on a native `holdfast.exe mcp --no-daemon`:
/// no warning, no trail.
///
/// `HOME` is still preferred where it is set, so a Windows user who exports
/// it — MSYS2 and Git Bash both do — keeps the instance they already had
/// rather than silently acquiring a second one under `%USERPROFILE%`.
///
/// The empty-string rule (GH #72) is deliberately NOT applied here: it lives
/// in `resolve`, which is the one place every caller passes through, and a
/// second copy is the hazard that rule's own comment is about.
pub(crate) fn home_dir() -> Option<PathBuf> {
    home_from(std::env::var_os("HOME"), std::env::var_os("USERPROFILE"))
}

/// [`home_dir`] over what the environment said, split out for the same reason
/// [`RuntimePaths::resolve`] and [`crate::config::config_path_from`] are:
/// the env is process-global and this test binary is threaded, so a test that
/// set `HOME` would be setting it for every other test at the same time.
fn home_from(
    home: Option<std::ffi::OsString>,
    user_profile: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(home) = home {
        return Some(PathBuf::from(home));
    }
    #[cfg(windows)]
    if let Some(profile) = user_profile {
        return Some(PathBuf::from(profile));
    }
    #[cfg(not(windows))]
    let _ = user_profile;
    None
}

/// **`open_log_append`'s cross-platform half, and the reason this module is
/// not `#[cfg(all(test, unix))]` either.**
///
/// The pre-PR review measured four mutations of this file's `#[cfg(windows)]`
/// bodies and all four SURVIVED both CI gates — `windows-cross` is
/// `cargo clippy`, which type-checks and never links, and no job ran a test
/// on that target. The sharpest of the four turned the Windows arm's
/// `.append(true)` into `.write(true).truncate(true)`, which zeroes the §9.4
/// audit trail on every process start and on every post-rotation reopen, and
/// nothing anywhere went red.
///
/// Two of that function's three obligations do not depend on mode bits at
/// all — it must CREATE the parent directory, and it must APPEND rather than
/// truncate — so they are asserted here, on every target, against whichever
/// arm this build compiled. Only the mode application stays untestable off
/// Unix. That is the review's own suggested shape: assert the shared contract
/// once cross-platform and leave just the `#[cfg]`-dependent part behind.
#[cfg(test)]
mod log_append_tests {
    use super::open_log_append;
    use std::io::Write;

    /// A scratch path under the system temp dir, so this runs identically on
    /// both platforms — `/tmp` is not a Windows path and `sun_path`'s length
    /// limit, which forces `/tmp` elsewhere in this file, is irrelevant here
    /// because nothing binds a socket.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        std::env::temp_dir().join(format!("holdfast-log-{tag}-{}", &unique[..8]))
    }

    #[test]
    fn it_creates_the_parent_directory_it_was_given() {
        let dir = scratch("mkparent");
        let path = dir.join("nested").join("audit.log");
        assert!(!path.exists(), "fixture must start absent");

        let file = open_log_append(&path).expect("open_log_append creates its parent");
        drop(file);

        assert!(path.is_file(), "the log itself was not created at {path:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn it_appends_and_does_not_truncate_what_is_already_there() {
        // **The mutation this exists for.** `.write(true).truncate(true)`
        // passes every other assertion in this file and silently empties the
        // audit trail; only reading back across two opens can see it.
        let dir = scratch("append");
        let path = dir.join("audit.log");

        let mut first = open_log_append(&path).expect("first open");
        first.write_all(b"line one\n").expect("first write");
        drop(first);

        let mut second = open_log_append(&path).expect("second open");
        second.write_all(b"line two\n").expect("second write");
        drop(second);

        let got = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            got, "line one\nline two\n",
            "the reopen truncated the trail instead of appending to it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// **Its own module, and NOT `#[cfg(all(test, unix))]` like the big one at the
/// bottom of this file.** The whole point of [`home_from`] is what it does on
/// a target that is not Unix, so gating its tests the way the mode-bit tests
/// are gated would leave the Windows arm asserted by nothing — which is the
/// exact shape #19 was fixing. These need no mode bits, no umask and no
/// filesystem, so nothing stops them running everywhere.
#[cfg(test)]
mod home_tests {
    use super::home_from;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn home_wins_wherever_it_is_set() {
        // The claim that a Windows user who exports `HOME` — MSYS2 and Git
        // Bash both do — keeps the instance they already had instead of
        // silently acquiring a second one under `%USERPROFILE%`.
        assert_eq!(
            home_from(os("/home/ada"), os(r"C:\Users\ada")),
            Some(PathBuf::from("/home/ada"))
        );
    }

    #[test]
    fn user_profile_is_the_windows_fallback_and_is_ignored_everywhere_else() {
        // **The separating negative, and it is the whole test.** Asserting
        // only that this returns `Some` on Windows would pass against a
        // fallback wired up on every platform, which would change where a
        // Unix box with no `HOME` puts its audit trail. The answer has to
        // DIFFER by platform, so the expectation is written from `cfg!`.
        let got = home_from(None, os(r"C:\Users\ada"));
        if cfg!(windows) {
            assert_eq!(got, Some(PathBuf::from(r"C:\Users\ada")));
        } else {
            assert_eq!(
                got, None,
                "USERPROFILE is a Windows convention and must not move a Unix instance"
            );
        }
    }

    #[test]
    fn neither_set_is_none_on_every_platform() {
        // `resolve` turns this into the `NotFound` that names all three
        // variables; the empty-string rule (GH #72) lives there too, and
        // deliberately not here — one spelling, one place.
        assert_eq!(home_from(None, None), None);
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
    /// An **isolated instance** rooted at `dir` — what `HOLDFAST_RUNTIME_DIR`
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
        _is_macos: bool,
    ) -> io::Result<Self> {
        // §7.1: an explicit instance takes everything with it, logs
        // included.
        if let Some(dir) = runtime_dir_override {
            return Ok(Self::with_dir(dir));
        }

        // **An empty `$HOME` is treated as unset** (GH #72). `HOME=""`
        // arrives here as `Some("")`, and `PathBuf::from("").join(".holdfast")`
        // is the *relative* `.holdfast` — so every path this type hands out
        // would resolve against whatever directory the process happened to
        // start in, and the audit trail is the one that matters: a log
        // written somewhere nobody will look is worse than no log, because
        // it reads as evidence of absence.
        //
        // The rule already existed one module over, in `audit`'s own path
        // helper, and did not exist here — which is exactly the hazard of a
        // second spelling. The second spelling is gone and the guard moved
        // to the one that remains, so every caller gets it rather than the
        // one that happened to be written by someone who thought of it.
        let home = home.filter(|h| !h.as_os_str().is_empty()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("neither {RUNTIME_DIR_ENV}, XDG_RUNTIME_DIR, nor HOME is set"),
            )
        });

        // §19.1: the daemon log lives in `~/.holdfast/logs` whenever the
        // instance is the default one, whatever the runtime directory is.
        let log_dir = match &home {
            Ok(h) => h.join(".holdfast").join("logs"),
            Err(_) => PathBuf::new(),
        };

        if is_linux {
            if let Some(xdg) = xdg_runtime_dir {
                let log_dir = log_dir_or_err(log_dir, &home)?;
                return Ok(Self {
                    dir: xdg.join("holdfast"),
                    log_dir,
                });
            }
        }
        let home = home?;
        // `~/.holdfast` on every platform without `XDG_RUNTIME_DIR`,
        // macOS included.
        //
        // **It was `~/Library/Application Support/holdfast` on macOS, and
        // that was wrong in three ways.** It contradicted §19.1 and §9.4,
        // which name `~/.holdfast/logs/audit.log` — and the `log_dir`
        // computed ten lines above was then overridden by `dir.join`
        // below, so the very comment describing the rule was violated by
        // the branch beneath it. It left a 0-byte `audit.log` at the
        // documented path, which reads as "the audit trail is broken"
        // rather than "wrong directory"; that cost a false security
        // finding. And `Application Support` is the macOS convention for
        // GUI applications — this tool's neighbours there are AddressBook
        // and Animoji — while every developer CLI on the same machine,
        // Claude Code's own `~/.claude` included, uses a dotfile or XDG.
        // Holdfast already resolved its *config* the Unix way, so the
        // runtime directory was the odd one out in its own codebase.
        //
        // It is also shorter, which is not cosmetic: `sun_path` is about
        // 104 bytes and this project has already been bitten by socket
        // paths that overran it.
        let dir = home.join(".holdfast");
        Ok(Self {
            log_dir: dir.join("logs"),
            dir,
        })
    }

    /// Spec §7.1: `$HOLDFAST_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/holdfast`
    /// (Linux), else `~/.holdfast`.
    pub fn discover() -> io::Result<Self> {
        Self::resolve(
            std::env::var_os(RUNTIME_DIR_ENV).map(PathBuf::from),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            home_dir(),
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
    /// file. `HOLDFAST_RUNTIME_DIR` relocates all three sockets together as
    /// an *instance*, which is the only relocation §7.1 sanctions. Task
    /// 15 Step 4 rejects a config that carries the withdrawn key rather
    /// than ignoring it.
    pub fn http_sock(&self) -> PathBuf {
        self.dir.join("http.sock")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.dir.join("holdfast.pid")
    }

    /// The **start** lock (§7.3 steps 1–2): who gets to decide that no
    /// daemon is running and spawn one.
    pub fn lock_file(&self) -> PathBuf {
        self.dir.join("holdfast.lock")
    }

    /// The **bind** lock: who owns `bind_control`'s probe → unlink →
    /// bind window.
    ///
    /// **A second file, and it must stay a second file.** The obvious
    /// simplification — have `bind_control` take `holdfast.lock` —
    /// deadlocks `holdfast daemon start` outright: `start_detached` holds
    /// `holdfast.lock` across the spawn *and* the 2 s poll that waits for
    /// the socket (`spawn.rs`, `let _lock = …` living to end of
    /// function), and the child `holdfast daemon run` does not inherit it
    /// because Rust opens `O_CLOEXEC`. The child would block on the
    /// lock, never bind, and the parent would time out waiting for the
    /// socket it is itself preventing.
    ///
    /// The two locks answer different questions and neither subsumes the
    /// other: `holdfast.lock` serialises *starters*, this one serialises
    /// *binders*. The case that needs it is the one `holdfast.lock` cannot
    /// see — a `start_detached` that already timed out and released
    /// while its child was still binding.
    pub fn bind_lock_file(&self) -> PathBuf {
        self.dir.join("bind.lock")
    }

    /// §19.1's log directory — `~/.holdfast/logs` by default, relocated
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
    /// `audit::default_path()` is `~/.holdfast/logs/audit.log` and takes no
    /// environment override, so on the **default** instance this returns
    /// exactly that path — the two agree by construction rather than by
    /// coincidence, because `log_dir` for the default instance *is*
    /// `~/.holdfast/logs`. On an explicit `HOLDFAST_RUNTIME_DIR` instance the
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
    ///
    /// The two directories get **different** answers to a
    /// group-writable mode, and the asymmetry is the point — see
    /// [`Writable`].
    pub fn ensure_dir(&self) -> io::Result<()> {
        self.check_socket_path_length()?;
        // `self.dir` first, and the order is load-bearing: on the
        // `~/.holdfast` fallback instance `log_dir` is *inside* it, so the
        // refusal below has to land before anything traverses a `logs/`
        // that may be somebody else's symlink.
        ensure_owner_only(&self.dir, Writable::Refuse)?;
        // **The log directory's parent, when it is not `self.dir`** (GH
        // #72). On the `~/.holdfast` fallback instance `log_dir` is inside
        // `dir`, which the line above already checked. On the
        // `XDG_RUNTIME_DIR` instance it is not: `dir` is
        // `$XDG_RUNTIME_DIR/holdfast` while `log_dir` is
        // `~/.holdfast/logs`, so `~/.holdfast` was only ever an
        // intermediate component — created by the recursive builder,
        // never `lstat`ed, and therefore **followed**. Measured: with
        // `~/.holdfast` pointing elsewhere and `XDG_RUNTIME_DIR` set, the
        // audit trail was written through the link, while the same link on
        // the fallback path was refused. That asymmetry was the finding.
        //
        // `Tighten` rather than `Refuse`, matching `log_dir` itself: this
        // is a directory the daemon is entitled to fix up, and refusing a
        // merely group-readable `~/.holdfast` would break installs that
        // predate the mode being enforced at all.
        if let Some(parent) = self.log_dir.parent() {
            if parent != self.dir {
                ensure_owner_only(parent, Writable::Tighten)?;
            }
        }
        ensure_owner_only(&self.log_dir, Writable::Tighten)
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
    ///
    /// **`daemon.log` gets no such requirement, because it could not
    /// meet one.** Its writer is the daemon's inherited fd 1/2, opened by
    /// `spawn.rs` in the *parent*; no call the daemon can make reopens
    /// it. It rolls by copy-truncate instead, which keeps that
    /// descriptor valid — see [`Roll::CopyTruncate`].
    pub fn sweep_logs(&self, retention: LogRetention, now: SystemTime) -> io::Result<LogSweep> {
        let mut sweep = LogSweep::default();
        if !self.log_dir.exists() {
            return Ok(sweep);
        }
        if let Some(to) = rotate(&self.audit_log(), Period::Daily, Roll::Rename, now)? {
            sweep.rotated.push(to);
        }
        if let Some(to) = rotate(&self.daemon_log(), Period::Weekly, Roll::CopyTruncate, now)? {
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

/// What a group- or world-**writable** directory gets: refused, or
/// tightened like any other too-loose mode.
///
/// Tighten a *leak*; **refuse** a writable one — the two cases differ in
/// what a chmod can still repair. A `0755` leftover from an earlier
/// install leaks the names of the sockets inside, and a chmod to `0700`
/// removes that leak outright (§7.1 describes exactly this case, and
/// tightening rather than rejecting it is this milestone's recorded
/// divergence from REQ-CFG-005's verification column). A **writable**
/// runtime directory is not the same thing: another local user could
/// already have pre-created `logs/` inside it as a **symlink**, and
/// `exists()` follows it, `metadata` follows it, `set_permissions` would
/// chmod the *target*, and `Daemon::new` then appends §9.4 audit entries
/// through an attacker-chosen path. `bind_control`'s stale-socket sweep
/// defends `control.sock`; nothing defends `logs/`. Refusing the parent
/// is what closes it.
///
/// **`log_dir` is not that parent, and refusing it refused correct
/// installs.** On the default instance it is `~/.holdfast/logs`, which every
/// install predating 0.0.5 created through `audit::default_path()`'s
/// plain `create_dir_all` under the ambient umask — `0775` under the
/// `002` that Debian, Ubuntu, RHEL and most corporate images ship. It
/// holds no socket. Refusing it made `holdfast daemon start` and the
/// systemd/launchd `holdfast daemon run` path (§7.3) fail on an untouched
/// install while `holdfast mcp` — which had relocated its log directory —
/// started fine: two entry points to one daemon disagreeing about
/// whether the install was startable. It gets the same tighten-or-fail a
/// `0755` leftover gets.
///
/// **What it does not get is a guarded parent, and this used to claim
/// otherwise.** The sentence here read "its parent chain is the user's
/// home, whose own mode is the gate" — true only on the `~/.holdfast`
/// fallback. On the XDG path the two live in different trees: `dir` is
/// `$XDG_RUNTIME_DIR/holdfast` and `log_dir` is `~/.holdfast/logs`, so
/// `log_dir`'s immediate parent is `~/.holdfast`, which the `Refuse` above
/// never sees and nothing else checks. A pre-0.0.5 `~/.holdfast` left at
/// `0775` on a host with a *shared* primary group is therefore writable
/// by someone else, and the tighten arm is what they would aim at. That
/// is why the check below refuses a symlink outright instead of trusting
/// a parent to have stopped one being planted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Writable {
    Refuse,
    Tighten,
}

/// Create `dir` `0700` if it is absent, then bring an existing one to
/// `0700` — or say why it cannot be.
/// Create `dir` and any missing parents at [`DIR_MODE`], and do nothing
/// else.
///
/// **Extracted so the creation mode is observable** (GH #72). Inside
/// `ensure_owner_only` it is not: the tighten step immediately reflows the
/// directory to `0700`, so changing this `mode` to `0o755` left the whole
/// suite green while opening a real window during which the directory —
/// and on the fallback instance the audit trail inside it — is
/// world-readable. The end state was measured and the transient was not,
/// which is the difference between a passing test and a covered one.
/// `the_directory_is_created_owner_only_before_anything_tightens_it` calls
/// this directly, where no tighten can hide the answer.
///
/// `DIR_MODE` is umask-proof by construction: `0700` has no group or other
/// bits for a umask to clear, so the assertion holds under any of them.
#[cfg(unix)]
fn create_owner_only(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)
}

/// The Windows arm: created with the inherited ACL, and named the same on
/// purpose so every caller reads identically. It is **not** owner-only by
/// construction here — see `open_log_append`'s Windows arm for why that is
/// warned about rather than refused.
#[cfg(windows)]
fn create_owner_only(dir: &Path) -> io::Result<()> {
    warn_inherited_acl_once();
    std::fs::DirBuilder::new().recursive(true).create(dir)
}

fn ensure_owner_only(dir: &Path, writable: Writable) -> io::Result<()> {
    // **The symlink refusal below is cross-platform in this function, and
    // that is NOT the same as being in force on Windows.** It is the half
    // that does not depend on mode bits: `symlink_metadata` follows no link
    // on either platform, and a planted `logs -> /elsewhere` redirects the
    // §9.4 trail just as effectively there. Only the mode inspection and the
    // tighten are Unix-gated, at the bottom.
    //
    // But every production caller of this function is inside `daemon::spawn`
    // or `daemon::server`, both `#[cfg(unix)]`, so on a Windows build nothing
    // reaches it: `open_log_append`'s Windows arm creates the parent with a
    // bare `DirBuilder` and a junction at `~/.holdfast/logs` goes unchecked.
    // The Unix `open_log_append` has the same gap, so this is pre-existing in
    // kind rather than introduced here — but the honest claim is "kept
    // compiling", not "kept in force". Closing it means routing
    // `open_log_append` through this function on both platforms, which is a
    // change to the Unix path and does not belong in a Windows fix.
    // `symlink_metadata`, not `exists()` and `metadata`: both of those
    // follow a link, and every decision below acts on what they report.
    // A planted `logs -> /elsewhere` would be chmodded at its *target*
    // and then have the §9.4 trail appended through it. Note this also
    // reaches a *dangling* link, which `exists()` reports as absent —
    // the create below would then have followed it.
    if std::fs::symlink_metadata(dir).is_err() {
        create_owner_only(dir)?;
    }
    let md = std::fs::symlink_metadata(dir)?;
    if md.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{d} is a symlink. Its target would be chmodded to {DIR_MODE:o} and the \
                 §9.4 audit trail appended through it, so a link planted by another local \
                 user redirects both. Replace it with a real directory, or set \
                 {RUNTIME_DIR_ENV} to run this instance from wherever you want it — that \
                 relocates the whole instance and gets checked the same way.",
                d = dir.display()
            ),
        ));
    }
    // Refusing rather than resolving is deliberate: resolving would mean
    // deciding whose target is acceptable, and `HOLDFAST_RUNTIME_DIR`
    // already expresses "put this somewhere else" without a link. A
    // residual remains — `set_permissions` below still resolves, so a
    // link swapped in after this check is not caught. Closing that needs
    // `openat(O_DIRECTORY|O_NOFOLLOW)` plus `fchmod`, which is worth
    // doing and is not this change.
    #[cfg(windows)]
    {
        // No mode to inspect and none to tighten to, so both decisions
        // below are unreachable here. `writable` is consumed so `-D
        // warnings` does not flag it, and the fact that its refusal has no
        // analogue on this platform is exactly what the warning says.
        let _ = writable;
        warn_inherited_acl_once();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode() & 0o777;
        if writable == Writable::Refuse && mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{d} is mode {mode:o}: group/world-writable, so another local user may \
                     already have planted entries inside it. Refusing rather than tightening \
                     — a chmod does not undo what is already there. Check what is inside it, \
                     then `chmod 700 {d}`; or set {RUNTIME_DIR_ENV} to run this instance from \
                     a directory somewhere else.",
                    d = dir.display()
                ),
            ));
        }
        if mode != DIR_MODE {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE))?;
            let after = std::fs::metadata(dir)?.permissions().mode() & 0o777;
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

/// `home` is only needed for the log directory on the XDG path, so its
/// absence is reported there rather than aborting discovery earlier.
fn log_dir_or_err(log_dir: PathBuf, home: &io::Result<PathBuf>) -> io::Result<PathBuf> {
    match home {
        Ok(_) => Ok(log_dir),
        Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
    }
}

// **The whole module, not the failing rows.** Every test here asserts a mode
// bit — `DirBuilder::mode`, `Permissions::from_mode`, the umask forced below
// — because that is what this module does. Gating them row by row would leave
// a handful that pass for want of anything to check, which reads as coverage
// and is not. `RuntimePaths`'s pure path arithmetic is worth testing on
// Windows and is not tested here today; splitting it out is a follow-up, not
// something to fake with a `#[cfg]`. Tracked in this branch's PR rather
// than in #19, which the branch closes.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Short by design: a socket path under a deep `target/` directory
    /// would exceed `sun_path`.
    fn temp_dir(tag: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        PathBuf::from(format!("/tmp/holdfast-t-{tag}-{}", &unique[..8]))
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

    /// The same property for the *other* log, which cannot be reached
    /// the same way.
    ///
    /// `daemon.log` is opened by the process that **spawns** the daemon
    /// (`spawn.rs`) and handed to it as fd 1 and fd 2; the daemon never
    /// opens it. So unlike `audit.log` there is nothing inside `run` to
    /// reopen and **no ordering can repair a rename** — after one, the
    /// descriptor the daemon was handed points at a file that has been
    /// renamed away, `retire("daemon.log.", …)` unlinks it a retention
    /// window later, and every diagnostic that daemon emits for the rest
    /// of its life lands in an unlinked inode while `spawn.rs` tells the
    /// user to "see daemon.log". A `dup2` cannot stand in: under systemd
    /// `holdfast daemon run` is started directly and fd 2 is the journal.
    /// Copy-truncate is what keeps the inherited descriptor valid
    /// whatever it points at.
    ///
    /// `rotation_starts_a_new_file_and_leaves_the_old_one_readable` is
    /// the pairing: `audit.log` keeps the rename, because its writer
    /// *can* reopen and a rename cannot lose a concurrently-written line
    /// the way the copy→truncate window can.
    #[test]
    fn the_daemon_log_survives_a_rotation_through_the_fd_it_was_handed() {
        use std::io::Write;

        let dir = temp_dir("dlogfd");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();

        // The stand-in for fd 1 and fd 2: opened once, by somebody else,
        // and never reopened.
        let mut inherited = open_log_append(&paths.daemon_log()).unwrap();
        inherited.write_all(b"before\n").unwrap();
        backdate(&paths.daemon_log(), days(10));

        let sweep = paths
            .sweep_logs(LogRetention::default(), SystemTime::now())
            .unwrap();
        let rolled = sweep
            .rotated
            .first()
            .expect("a ten-day-old daemon log is past its weekly boundary")
            .clone();
        assert!(rolled
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("daemon.log."));
        assert_eq!(
            std::fs::read_to_string(&rolled).unwrap(),
            "before\n",
            "the rotated file lost the bytes it was rotated to keep"
        );

        inherited.write_all(b"after\n").unwrap();
        let live = std::fs::read_to_string(paths.daemon_log()).expect(
            "daemon.log is gone, so the descriptor the daemon was handed now writes \
             where no path can reach and `holdfast daemon start`'s own advice is a dead end",
        );
        assert_eq!(
            live, "after\n",
            "the post-rotation write did not land in the live log"
        );

        // Retention parity. `retire` measures the window from the last
        // byte written, which is the mtime `rename` carries over for
        // free; a copy that let the stamped file be born *now* would
        // keep `daemon.log.<stamp>` a full extra period past what §19.1
        // specifies, on a clock the audit half does not use.
        let stamped_age = SystemTime::now()
            .duration_since(std::fs::metadata(&rolled).unwrap().modified().unwrap())
            .unwrap();
        assert!(
            stamped_age > days(9),
            "the rotated file was stamped at rotation time ({stamped_age:?} old), not at \
             its last write, so it ages out of retention on a different clock than a \
             rotated audit.log"
        );
    }

    #[test]
    fn every_socket_lives_in_the_runtime_directory() {
        let p = RuntimePaths::with_dir("/run/user/1000/holdfast");
        assert_eq!(
            p.control_sock(),
            PathBuf::from("/run/user/1000/holdfast/control.sock")
        );
        assert_eq!(
            p.attach_sock(),
            PathBuf::from("/run/user/1000/holdfast/attach.sock")
        );
        assert_eq!(
            p.http_sock(),
            PathBuf::from("/run/user/1000/holdfast/http.sock")
        );
        assert_eq!(
            p.pid_file(),
            PathBuf::from("/run/user/1000/holdfast/holdfast.pid")
        );
        assert_eq!(
            p.lock_file(),
            PathBuf::from("/run/user/1000/holdfast/holdfast.lock")
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

    /// The residual of the test above: the refusal is a rule about the
    /// directory that holds the **sockets**, and applying it to the log
    /// directory refused a correct install.
    ///
    /// `~/.holdfast/logs` on every install predating 0.0.5 was created by
    /// `audit::default_path()`'s plain `create_dir_all` under the ambient
    /// umask, which is `002` on Debian, Ubuntu, RHEL and most corporate
    /// images — `0775`. That directory's parent chain is the user's home,
    /// whose own mode is the gate, so a chmod does repair it and the
    /// symlink argument the refusal is written for does not reach it.
    ///
    /// Both halves are here because either alone is passed by a wrong
    /// fix. Without the first, a pre-0.0.5 install cannot start
    /// (`holdfast daemon start` refuses while `holdfast mcp` — resolving a
    /// different log directory — does not, so the two entry points to one
    /// daemon disagree about whether the install is startable). Without
    /// the second, deleting the refusal outright is green.
    #[test]
    fn a_group_writable_log_directory_is_tightened_and_the_runtime_directory_still_refused() {
        let dir = temp_dir("legacylogs");
        let _scoped = Scoped(dir.clone());
        let paths = RuntimePaths::with_dir(&dir);
        std::fs::create_dir_all(paths.log_dir()).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE)).unwrap();
        std::fs::set_permissions(paths.log_dir(), std::fs::Permissions::from_mode(0o775)).unwrap();
        // The fixture, asserted *before* the call that repairs it: a
        // repair path that runs ahead of its own assertion is how
        // `ensure_dir_creates_the_tree_mode_0700` went blind, and without
        // these two rows this test could not tell a tightened directory
        // from one that was never loose.
        assert_eq!(mode_of(&dir), DIR_MODE);
        assert_eq!(mode_of(&paths.log_dir()), 0o775);

        paths
            .ensure_dir()
            .expect("a 0775 log directory is the state every pre-0.0.5 install is in");
        assert_eq!(
            mode_of(&paths.log_dir()),
            DIR_MODE,
            "the log directory was accepted but not tightened"
        );
        assert_eq!(mode_of(&dir), DIR_MODE);

        // The control. A "fix" that drops the writable check has the
        // first half green and hands `logs/` back to the symlink case the
        // check exists for.
        let socket_dir = temp_dir("legacyroot");
        let _scoped = Scoped(socket_dir.clone());
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = RuntimePaths::with_dir(&socket_dir)
            .ensure_dir()
            .expect_err("a writable *runtime* directory must still be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            !socket_dir.join("logs").exists(),
            "nothing may be created inside a directory that was refused"
        );
        // And it names the remedy that actually applies. "Remove it"
        // deletes the audit trail and `HOLDFAST_RUNTIME_DIR` is instance
        // selection, not a permissions fix; the user owns this directory
        // and can chmod it.
        assert!(
            err.to_string()
                .contains(&format!("chmod 700 {}", socket_dir.display())),
            "the error must name the fix the user can actually apply: {err}"
        );
    }

    #[test]
    fn a_symlinked_log_directory_is_refused_and_its_target_left_alone() {
        // The tighten arm's hazard. `~/.holdfast` is checked by nothing on
        // the XDG path — `dir` and `log_dir` are in different trees
        // there — so a pre-0.0.5 `~/.holdfast` at 0775 on a host with a
        // shared primary group lets someone else plant `logs` as a link.
        let target = temp_dir("symlinkvictim");
        let _scoped_target = Scoped(target.clone());
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        let dir = temp_dir("symlinkroot");
        let _scoped = Scoped(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE)).unwrap();
        let paths = RuntimePaths::with_dir(&dir);
        std::os::unix::fs::symlink(&target, paths.log_dir()).unwrap();

        // The fixture, asserted before the call — the mode this test is
        // about is the one the call would change.
        assert_eq!(mode_of(&target), 0o755);

        let err = paths
            .ensure_dir()
            .expect_err("a symlinked log directory must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");

        // The harm, not the diagnosis. Before this fix `metadata` and
        // `set_permissions` both resolved the link, so the *target* was
        // chmodded to 0700 and the §9.4 trail was appended through it.
        // This row is what goes red if the check is reverted; an
        // assertion on the error alone would not.
        assert_eq!(
            mode_of(&target),
            0o755,
            "the symlink's target was chmodded through the link"
        );

        // The control, so this cannot pass by refusing every log
        // directory: a real one in the same shape still tightens.
        let ok_dir = temp_dir("symlinkcontrol");
        let _scoped_ok = Scoped(ok_dir.clone());
        let ok = RuntimePaths::with_dir(&ok_dir);
        std::fs::create_dir_all(ok.log_dir()).unwrap();
        std::fs::set_permissions(&ok_dir, std::fs::Permissions::from_mode(DIR_MODE)).unwrap();
        std::fs::set_permissions(ok.log_dir(), std::fs::Permissions::from_mode(0o775)).unwrap();
        ok.ensure_dir()
            .expect("a real 0775 log directory is still the ordinary pre-0.0.5 install");
        assert_eq!(mode_of(&ok.log_dir()), DIR_MODE);
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
        // §7.1: `HOLDFAST_RUNTIME_DIR` relocates the daemon log too, so an
        // isolated instance leaves nothing in the user's home.
        let p = RuntimePaths::resolve(
            Some("/tmp/holdfast-instance".into()),
            Some("/run/user/1000".into()),
            Some("/home/u".into()),
            true,
            false,
        )
        .unwrap();
        assert_eq!(p.dir(), Path::new("/tmp/holdfast-instance"));
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/tmp/holdfast-instance/logs/daemon.log")
        );
        assert_eq!(
            p.audit_log(),
            PathBuf::from("/tmp/holdfast-instance/logs/audit.log")
        );
        // Both logs, not just the one §7.1 names. `audit::default_path()`
        // has no environment override, so if the audit log did not follow
        // the instance, every test with a private `HOLDFAST_RUNTIME_DIR`
        // would append to the developer's real `~/.holdfast/logs/audit.log`
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
        // §19.1 puts daemon.log in `~/.holdfast/logs` with a 4-week
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
        assert_eq!(p.dir(), Path::new("/run/user/1000/holdfast"));
        assert_eq!(
            p.control_sock(),
            PathBuf::from("/run/user/1000/holdfast/control.sock")
        );
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/home/u/.holdfast/logs/daemon.log"),
            "§19.1: the default instance logs under HOME, not under tmpfs"
        );
        // The pairing that makes `Daemon::new`'s audit path safe to take
        // from here: on the *default* instance it must be byte-identical
        // to `audit::default_path()`, or the daemon would write §9.4's
        // trail somewhere `holdfast logs` and every operator runbook would
        // not look. This is the negative for the instance-relocation
        // assertion above — relocation must not leak into the default.
        assert_eq!(
            p.audit_log(),
            PathBuf::from("/home/u/.holdfast/logs/audit.log"),
            "§9.4's default path is `~/.holdfast/logs/audit.log` and takes no override"
        );
    }

    #[test]
    fn discovery_falls_back_to_the_home_directory_for_both() {
        // No XDG (or not Linux): runtime dir and logs coincide under
        // `~/.holdfast`, which is what §7.1's fallback and §19.1 both name.
        let p = RuntimePaths::resolve(None, None, Some("/home/u".into()), true, false).unwrap();
        assert_eq!(p.dir(), Path::new("/home/u/.holdfast"));
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/home/u/.holdfast/logs/daemon.log")
        );

        // macOS resolves like every other non-XDG platform. It used to
        // answer `~/Library/Application Support/holdfast`, which
        // contradicted §9.4 and §19.1 and put a 0-byte `audit.log` at the
        // documented path — a state that reads as a broken audit trail
        // rather than a misplaced one, and was filed as one.
        let mac = RuntimePaths::resolve(None, None, Some("/Users/u".into()), false, true).unwrap();
        assert_eq!(mac.dir(), Path::new("/Users/u/.holdfast"));
        assert_eq!(
            mac.daemon_log(),
            PathBuf::from("/Users/u/.holdfast/logs/daemon.log")
        );
        // The macOS flag no longer changes the answer, and this pins that
        // rather than leaving it to the reader of the `_is_macos` name.
        let not_mac =
            RuntimePaths::resolve(None, None, Some("/Users/u".into()), false, false).unwrap();
        assert_eq!(not_mac.dir(), mac.dir());
    }

    #[test]
    fn discovery_without_home_or_an_override_is_an_error() {
        let err = RuntimePaths::resolve(None, None, None, true, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains(RUNTIME_DIR_ENV), "{err}");
    }
    /// **The mode a directory is born with, not the mode it ends up
    /// wearing** (GH #72).
    ///
    /// `ensure_dir` tightens immediately after creating, so every existing
    /// assertion measures the end state and a creation at `0o755` passed
    /// all of them. The window is real: between `mkdir` and `chmod` the
    /// directory is world-readable, and on the fallback instance the §9.4
    /// audit trail lives inside it. This calls the creation directly,
    /// where nothing can reflow the answer first.
    #[test]
    fn the_directory_is_created_owner_only_before_anything_tightens_it() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "holdfast-t-mkmode-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let nested = base.join("a").join("b");
        create_owner_only(&nested).expect("create");
        for d in [&nested, &base.join("a"), &base] {
            let mode = std::fs::symlink_metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                DIR_MODE,
                "{} was created {mode:o}, not {DIR_MODE:o} — every component, \
                 because the recursive builder makes the intermediates too",
                d.display()
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **A symlinked `~/.holdfast` is refused on the XDG instance too**
    /// (GH #72).
    ///
    /// It was refused on the fallback instance, where `~/.holdfast` *is*
    /// `dir`, and followed on the XDG instance, where it is only an
    /// intermediate component of `log_dir` and so was created by the
    /// recursive builder without ever being `lstat`ed. Same planted link,
    /// two answers, decided by an environment variable.
    #[test]
    fn a_symlinked_holdfast_home_is_refused_on_the_xdg_instance() {
        // `/tmp` and a short suffix, not `temp_dir()`: on macOS that is a
        // long `/var/folders/...` path and `check_socket_path_length` —
        // which `ensure_dir` runs first — refused before this test's own
        // condition was ever reached, so the row passed for the wrong
        // reason until the assertion printed the message.
        let base = std::path::PathBuf::from(format!(
            "/tmp/hf-xl-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let home = base.join("home");
        let xdg = base.join("xdg");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".holdfast")).unwrap();

        let paths = RuntimePaths::resolve(None, Some(xdg.clone()), Some(home.clone()), true, false)
            .expect("resolve");
        let err = paths
            .ensure_dir()
            .expect_err("a symlinked ~/.holdfast must be refused on this path too");
        assert!(
            err.to_string().contains("symlink"),
            "the refusal must say what is wrong: {err}"
        );
        // And nothing was written through the link.
        assert!(
            !elsewhere.join("logs").exists(),
            "the audit directory was created through the planted link"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
