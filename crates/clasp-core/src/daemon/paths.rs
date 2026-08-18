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

/// Selects a CLASP *instance* (§7.1). Overrides discovery entirely and
/// relocates the sockets, the pid file, the lock file and the daemon log.
pub const RUNTIME_DIR_ENV: &str = "CLASP_RUNTIME_DIR";

/// Mode for the runtime and log directories: owner-only.
pub const DIR_MODE: u32 = 0o700;
/// Mode for every socket in it (spec §7.1: `0600` on each socket).
pub const SOCKET_MODE: u32 = 0o600;

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

    pub fn lock_file(&self) -> PathBuf {
        self.dir.join("clasp.lock")
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
