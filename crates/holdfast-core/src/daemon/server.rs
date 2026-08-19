//! The daemon: one Unix listener, one `SessionRegistry`, one method
//! dispatcher (spec §7.2, §7.3, §7.4).
//!
//! **The daemon never opens a TCP listener** (§7.2, §9.1, REQ-D-001).
//! The only `bind` in this file is `UnixListener::bind`. The web UI's
//! TCP exposure is a separate, user-invoked bridge process that arrives
//! in 0.0.10 and binds loopback in *its own* address space.

use super::paths::{LogRetention, RuntimePaths, SOCKET_MODE};
use super::peer;
use crate::clock::Clock;
use crate::config::Config;
use crate::mcp::caller::{self, Caller};
use crate::mcp::{passthrough, resources, HoldfastServer};
use crate::protocol::frame::{self, FrameError};
use crate::protocol::handshake::{self, ClientKind, HandshakeParams};
use crate::protocol::method::{self, ErrorCode, Request, Response};
use crate::session::Reaper;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

/// `holdfast.pid`'s creation mode.
///
/// Its own constant rather than a reuse of `SOCKET_MODE`: the two agree
/// today and answer different questions — one is the daemon's access
/// boundary, the other is house style for a file in an already-`0700`
/// directory — and a change to either must not silently move the other.
const PID_FILE_MODE: u32 = 0o600;

/// `daemon/status` response data (§7.4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub pid: u32,
    pub uptime_secs: u64,
    pub version: String,
    pub sessions_live: u64,
    pub sessions_exited_retained: u64,
    /// Always 0 until the attach protocol lands in 0.0.6.
    pub attach_clients: u64,
    /// Always 0 until the web-UI bridge lands in 0.0.10.
    pub bridge_sessions: u64,
}

/// `daemon/stop` params (§7.4.1).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StopParams {
    #[serde(default)]
    pub force: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

/// §7.4.1's and §3.2's default `daemon/stop` grace.
///
/// **Ten seconds, and deliberately not the reaper's five.** Three graces
/// meet in this milestone: `daemon/stop`'s 10 s (§7.4.1's `timeout_secs`
/// default, restated in §3.2 as *"wait up to 10 seconds for clean
/// shutdown"*), the idle reaper's 5 s (REQ-S-005, §16.7), and
/// `terminate(force=false)`'s 5 s (§5.2, REQ-P-004). The reaper's is the
/// one that leaked into this constant in an earlier revision, and it is
/// invisible to any test that passes an explicit `timeout_secs` — which
/// is why `stop_defaults_its_grace_to_ten_seconds_not_the_reapers_five`
/// reads the resolved value rather than timing the call.
pub const DEFAULT_STOP_GRACE_SECS: u32 = 10;

/// How often the graceful stop re-checks whether the sessions have gone.
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

impl StopParams {
    /// Whether this stop escalates immediately. Absent means `false`,
    /// which is §7.4.1's default and the graceful path.
    pub fn is_forced(&self) -> bool {
        self.force.unwrap_or(false)
    }

    /// The resolved grace: the caller's `timeout_secs`, or
    /// [`DEFAULT_STOP_GRACE_SECS`].
    pub fn grace(&self) -> Duration {
        Duration::from_secs(u64::from(
            self.timeout_secs.unwrap_or(DEFAULT_STOP_GRACE_SECS),
        ))
    }
}

/// `daemon/stop` response data.
///
/// `stopped_at_unix_secs`, not `stopped_at`, and **not** because a date
/// crate was missing. §5.4/REQ-T-018 require an integer since the epoch
/// under a name that states its unit: *"no MCP field is an RFC-3339
/// string"*, and a bare `stopped_at` is prohibited outright, not merely
/// unused — a bare name invites a consumer to parse a value that will
/// not parse. Same convention as `started_at_unix_secs` in 0.0.1 and
/// `idle_deadline_unix_secs` in Task 16.
///
/// **This stopped being an argument by analogy at rev. 47.** REQ-T-018
/// used to reach the MCP tool surface and this field had to borrow the
/// rule from §5.4; rev. 47 widened it to *"every timestamp on a
/// CLASP-defined wire surface — the MCP tool surface, the control
/// protocol (§7.4.1), the attach protocol (§7.5) and the HTTP API"*, and
/// names bare `started_at` as its own example. So the requirement now
/// binds this response directly, in the section the field lives in, and
/// §7.4.1's `stopped_at` is a REQ-T-018 violation in the spec rather
/// than a divergence in this plan.
///
/// §7.4.1's table showed the pre-rev-38 bare `stopped_at` until rev. 48
/// brought it into line; §5.4 had already ruled, and says so by name: it
/// records that this milestone re-affirmed the
/// integer form *after* the date crate the original deferral waited on
/// had already landed in 0.0.3, and that *"the spec is the artifact that
/// was wrong."* Do **not** "discharge the deferral" by emitting RFC 3339
/// now that `chrono` and `audit::now_rfc3339()` exist — that is a
/// REQ-T-018 violation reached by following an argument this comment
/// used to make.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopOutcome {
    pub stopped_at_unix_secs: u64,
    pub sessions_terminated: u64,
}

fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared daemon state. One per process.
pub struct Daemon {
    pub server: HoldfastServer,
    paths: RuntimePaths,
    started_at: Instant,
    shutdown_tx: watch::Sender<bool>,
    connections: AtomicU64,
    /// Connections accepted and not yet finished with.
    ///
    /// **§7.3's exit needs this because `last_client_connect` is stamped
    /// too late to see one.** That timestamp is written after the uid
    /// gate *and* after an accepted handshake, deliberately, so a
    /// refused peer cannot hold the daemon open — which leaves a
    /// connection that has been accepted but not yet handshaken
    /// invisible to `client_less_exit_due()`. The exit only arms after
    /// 24 h of silence, so the connection that races it is the one
    /// *ending* the silence, which is the only connection that can:
    /// the probability argument runs the opposite way from the usual
    /// one.
    ///
    /// Incremented in [`serve`] at accept, **before** the task is
    /// spawned, and decremented by [`InFlight`] on every exit path
    /// including a panic. Counting at accept rather than inside the task
    /// is what makes it see the connection the timestamp cannot; and it
    /// preserves the existing rule, because a refused peer holds the
    /// daemon open only for as long as its connection lasts, which for a
    /// uid refusal is one syscall and for a silent peer is bounded by
    /// [`handshake::HANDSHAKE_TIMEOUT`].
    in_flight: AtomicUsize,
    /// The uid this daemon belongs to, captured once at construction
    /// rather than re-read per connection.
    ///
    /// **This field is the seam that makes §9.1's peer-credential gate
    /// testable at all.** A test process cannot become a second user, so
    /// "a foreign peer is refused" is unreachable while the daemon asks
    /// `geteuid()` on every connection: every in-process peer is us.
    /// Holding the owner as state lets a test build a daemon that
    /// believes it belongs to *someone else*, which makes an ordinary
    /// local connection a foreign one — see
    /// `a_connection_from_a_foreign_uid_is_closed_before_the_handshake`.
    owner_uid: u32,
    /// Every deadline this daemon owns reads this, and nothing calls
    /// `Instant::now()` or `tokio::time::sleep` directly.
    ///
    /// `unix_secs_now()` is the deliberate exception and must stay one:
    /// `stopped_at_unix_secs` is a wall-clock fact reported to a caller,
    /// not a deadline, and a manual clock must not be able to stamp it.
    clock: Clock,
    /// When a client last completed the §9.1 gate, for §7.3's client-less
    /// exit. `None` means "never", which is what the window measures from
    /// on a daemon nobody has connected to.
    last_client_connect: Mutex<Option<Instant>>,
    /// The live-session ids the last `resources/list` would have shown,
    /// for REQ-R-006's **exit** half.
    ///
    /// A session's exit is observed rather than announced — nothing
    /// calls back when a child dies — so the daemon notices by comparing
    /// this set on its own tick. Creation does not go through here: it
    /// fires synchronously from `start_session`, because an agent that
    /// had to wait 30 s to learn about the session it just started would
    /// re-list at exactly the wrong moment.
    listed_sessions: Mutex<std::collections::BTreeSet<String>>,
}

impl Daemon {
    /// **`with_audit_path`, never `new()`.** `HoldfastServer::new()` is
    /// documented at HEAD as *"a server with the audit trail disabled …
    /// this is the constructor tests use"*, and `serve_stdio()` — the
    /// only production host before this milestone — uses
    /// `with_audit_path(audit::default_path())`. A daemon built from
    /// `new()` writes **no** §9.4 trail at all: not `redaction_disabled`,
    /// not `session_start`, nothing. Since 0.0.5 makes the daemon the
    /// default host for every session, that would silently remove the
    /// audit log from the default transport — a security regression
    /// delivered by a transport change, and invisible to every test that
    /// does not read the log back.
    ///
    /// The path comes from `paths`, not from `audit::default_path()`,
    /// because `default_path()` takes no environment override
    /// (`audit.rs`: *"There is no environment override … the config-file
    /// path arrives with the daemon in 0.0.5"*). On the default instance
    /// `paths.audit_log()` **is** `~/.holdfast/logs/audit.log`, so the two
    /// agree; under an explicit `HOLDFAST_RUNTIME_DIR` the audit log follows
    /// the instance, which is what will stop every `daemon_cli.rs` test
    /// (Task 14) from appending to the developer's real audit log. See
    /// **Decisions taken** — §7.1 states the relocation for `daemon.log`
    /// only, and extending it to `audit.log` is this plan's call.
    pub fn new(paths: RuntimePaths) -> Arc<Self> {
        Self::with_owner_uid(paths, peer::current_uid())
    }

    /// A daemon holding an operator configuration (§10.1).
    pub fn with_config(paths: RuntimePaths, config: Config) -> Arc<Self> {
        Self::build(paths, config, Clock::system(), peer::current_uid())
    }

    /// A daemon whose deadlines run on `clock`.
    ///
    /// **This is the seam two later milestones name.** 0.0.6's
    /// over-`attach.sock` reaper test and 0.0.7's decision not to build a
    /// second clock both depend on the daemon's timers being drivable
    /// from outside `session::reaper`.
    pub fn with_clock(paths: RuntimePaths, clock: Clock) -> Arc<Self> {
        Self::build(paths, Config::default(), clock, peer::current_uid())
    }

    /// Both seams at once, for a test that drives a configured deadline.
    pub fn with_config_and_clock(paths: RuntimePaths, config: Config, clock: Clock) -> Arc<Self> {
        Self::build(paths, config, clock, peer::current_uid())
    }

    /// [`Daemon::new`] with the owning uid supplied rather than read from
    /// the process.
    ///
    /// Private, and deliberately so: production has exactly one right
    /// answer for this and `new` supplies it. It exists because the
    /// §9.1 gate is otherwise unprovable in-process — see `owner_uid`.
    fn with_owner_uid(paths: RuntimePaths, owner_uid: u32) -> Arc<Self> {
        Self::build(paths, Config::default(), Clock::system(), owner_uid)
    }

    fn build(paths: RuntimePaths, config: Config, clock: Clock, owner_uid: u32) -> Arc<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let audit_path = paths.audit_log();
        Arc::new(Self {
            // The clock goes down to the server, and from there into
            // every `SessionConfig` `start_session` builds. Without it
            // `Daemon::with_clock` moves the reaper's hand while the
            // sessions it is deciding about are stamped from wall time.
            server: HoldfastServer::with_audit_path_config_and_clock(
                Some(audit_path),
                &config,
                clock.clone(),
            ),
            paths,
            // On the daemon's own clock, not `Instant::now()`. §7.3's
            // window falls back to this when no client has ever
            // connected, and comparing a hand-driven `now` against a
            // wall-clock origin would measure the gap between two clocks
            // rather than the window.
            started_at: clock.now(),
            shutdown_tx,
            connections: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            owner_uid,
            clock,
            last_client_connect: Mutex::new(None),
            listed_sessions: Mutex::new(std::collections::BTreeSet::new()),
        })
    }

    pub fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    /// The operator configuration this daemon was built with.
    pub fn config(&self) -> &Config {
        &self.server.config
    }

    /// The daemon's time source. Every deadline this milestone
    /// introduces reads it, and 0.0.6 takes this handle to drive them.
    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    /// When a client last completed the §9.1 gate, on the daemon's own
    /// clock. `None` when none ever has.
    pub fn last_client_connect(&self) -> Option<Instant> {
        *self.last_client_connect.lock()
    }

    /// Fire REQ-R-006's `list_changed` pulse if the set of live sessions
    /// has moved since the last call. Returns whether it fired.
    ///
    /// **This is the exit half and it belongs to the daemon**, which is
    /// what §5.5 means by saying the event originates daemon-side: in
    /// hybrid mode the shim holds no registry, so nothing there can
    /// notice a child that died. Called from the reaper's tick, which is
    /// the only periodic timer in the process, and reachable from a test
    /// so that "fires on exit" is an assertion rather than a hope.
    pub fn poll_resource_list_changed(&self) -> bool {
        let now_live: std::collections::BTreeSet<String> = self
            .server
            .registry
            .all()
            .into_iter()
            .filter(|s| s.is_alive())
            .map(|s| s.id.clone())
            .collect();
        let mut known = self.listed_sessions.lock();
        if *known == now_live {
            return false;
        }
        *known = now_live;
        drop(known);
        self.server.notify_resource_list_changed();
        true
    }

    /// Record a client connection for §7.3's window.
    ///
    /// Called **after** the uid gate and the handshake, so a peer that
    /// was refused does not hold the daemon open: the window is "no
    /// clients have connected", and a rejected connection is not one.
    fn note_client_connect(&self) {
        *self.last_client_connect.lock() = Some(self.clock.now());
    }

    /// Total connections accepted by the listener since start.
    ///
    /// Counted in `serve`, *before* the §9.1 credential gate runs, so it
    /// says "the daemon saw this peer" and nothing about whether the peer
    /// was served. That is exactly what a refusal test needs: silence on
    /// a socket is also what connecting to a dead daemon looks like, and
    /// this counter is what separates the two.
    pub fn accepted_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Connections accepted and not yet finished with — see
    /// [`Daemon::in_flight`].
    pub fn in_flight_connections(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn status(&self) -> DaemonStatus {
        let all = self.server.registry.all();
        let live = all.iter().filter(|s| s.is_alive()).count() as u64;
        DaemonStatus {
            pid: std::process::id(),
            // `self.clock`, not `started_at.elapsed()`. `elapsed()` is
            // `Instant::now() - started_at`, and `started_at` is stamped
            // from the daemon's clock — so under `Clock::manual` the two
            // are different clocks, an advanced hand puts the origin in
            // the future, `duration_since` saturates, and `daemon/status`
            // reports an uptime of zero for a daemon that has been up for
            // an hour. Identical under `Clock::system()`, which is every
            // shipped binary; this is what makes the seam usable by the
            // 0.0.6 tests that drive it.
            uptime_secs: self.clock.now().duration_since(self.started_at).as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sessions_live: live,
            sessions_exited_retained: all.len() as u64 - live,
            attach_clients: 0,
            bridge_sessions: 0,
        }
    }

    /// Ask the accept loop to stop, killing every live session outright.
    ///
    /// The immediate form: SIGKILL, no grace. Used by the SIGTERM
    /// handler, by `daemon/stop` with `force: true`, and by the
    /// belt-and-braces call at the end of [`run`]. The graceful form is
    /// [`Daemon::shutdown_graceful`].
    pub fn shutdown(&self) -> u64 {
        let mut terminated = 0;
        for session in self.server.registry.all() {
            if session.is_alive() {
                let _ = session.signal(crate::pty::Signal::Kill);
                terminated += 1;
            }
        }
        let _ = self.shutdown_tx.send(true);
        terminated
    }

    /// `daemon/stop` with `force: false`: SIGTERM every live session,
    /// wait up to `grace` for them to go, then SIGKILL whatever is left.
    ///
    /// Returns how many sessions were signalled, which is the count
    /// `StopOutcome.sessions_terminated` reports either way.
    ///
    /// The grace is §7.4.1's and §3.2's **10 s by default and not the
    /// reaper's 5** — see [`StopParams::grace`]. It covers *every*
    /// session sweeping down at once, including interactive shells, which
    /// ignore SIGTERM (§4.4) and always reach the escalation; the
    /// reaper's grace covers one session at a time.
    pub async fn shutdown_graceful(&self, grace: Duration) -> u64 {
        let live: Vec<_> = self
            .server
            .registry
            .all()
            .into_iter()
            .filter(|s| s.is_alive())
            .collect();
        for session in &live {
            let _ = session.signal(crate::pty::Signal::Terminate);
        }

        // **Not on a manual clock**, and this is the one caller
        // [`Clock::is_manual`] was written for.
        //
        // `Clock::sleep_until` on a hand parks until someone calls
        // `advance`, and the only thing that can is a test — which, on
        // this path, is blocked in this very `await`. `daemon/stop` is
        // reachable over the wire (`dispatch`'s `METHOD_DAEMON_STOP`
        // arm), so `{ force: false }` against a manual-clock daemon
        // holding one live session wedges `handle_connection`, the
        // client's `call`, and the suite. There is no `nextest.toml` in
        // this repo, so that is a hung CI job rather than a red test.
        //
        // Skipping the poll is the honest answer rather than a dodge: a
        // hand nobody is moving grants the child no grace it could
        // actually spend, and the ordering the graceful stop promises —
        // SIGTERM first, SIGKILL after — is preserved by the escalation
        // below. `Clock::system()` is unaffected, which is every
        // production daemon.
        if !live.is_empty() {
            // Poll rather than sleeping the whole grace: a well-behaved
            // child exits in milliseconds, and making every `clasp daemon
            // stop` cost ten seconds would be a tax on the common case.
            if !self.clock.is_manual() {
                let deadline = self.clock.now() + grace;
                while self.clock.now() < deadline {
                    if live.iter().all(|s| !s.is_alive()) {
                        break;
                    }
                    let next = (self.clock.now() + STOP_POLL_INTERVAL).min(deadline);
                    self.clock.sleep_until(next).await;
                }
            }
            for session in &live {
                if session.is_alive() {
                    let _ = session.signal(crate::pty::Signal::Kill);
                }
            }
        }

        let _ = self.shutdown_tx.send(true);
        live.len() as u64
    }

    /// §7.3's client-less exit, as a **conjunction** (REQ-D-006).
    ///
    /// *"Daemon exits … when **all** sessions have exited **and** no
    /// clients have connected for >24 hours (configurable, can be
    /// disabled)."* Both conjuncts, or the daemon reaches its window with
    /// live sessions and takes them down with it — a `sleep 86400` in a
    /// session nobody has attached to is exactly the case this feature
    /// must not kill, and it is the case the feature exists for.
    ///
    /// **`0` disables it**, which is 0.0.5's ruling: §7.3 says the exit
    /// is *"configurable, can be disabled"* and names neither the key nor
    /// the disabling value, and `0` is the spelling
    /// `[limits] default_idle_timeout_secs` already uses for the same
    /// idea in the same file.
    ///
    /// **The window's resolution is one reaper tick.** Nothing polls this
    /// predicate continuously: [`reaper_loop`] evaluates it once per
    /// [`SCAN_INTERVAL`](crate::session::reaper::SCAN_INTERVAL), which is
    /// 30 s, so a configured `idle_shutdown_after_secs` below 30 behaves
    /// as 30 and every window is rounded up to the next tick. That is
    /// immaterial at §7.3's 24-hour default and worth knowing before
    /// anyone configures seconds and times the result.
    pub fn client_less_exit_due(&self) -> bool {
        let window = self.config().daemon.idle_shutdown_after_secs;
        if window == 0 {
            return false;
        }
        // **A client mid-connect is a client.** `last_client_connect` is
        // stamped after the uid gate and an accepted handshake, so a
        // connection that has been accepted and is still handshaking is
        // invisible to the timestamp — and the connection that races
        // this exit is precisely the one *ending* the 24 hours of
        // silence that armed it. Without this conjunct the daemon exits
        // underneath it, and the client-side EOF surfaces as
        // `FrameError::Eof` rather than `ClientError::Connect`, which is
        // the one classification `spawn::ensure_daemon` will not start a
        // replacement for. `clasp mcp` then fails with
        // `daemon_unreachable` against a daemon that was alive moments
        // earlier.
        //
        // It is also what keeps a `start_session` arriving in that
        // window from being SIGKILLed by a shutdown that had already
        // concluded there were no sessions: a request can only be
        // dispatched on a connection that was counted at accept, which
        // is strictly earlier.
        if self.in_flight_connections() > 0 {
            return false;
        }
        // First conjunct: every session has exited. Exited sessions keep
        // their registry entries (§5.5.1), so this asks about liveness
        // rather than about emptiness.
        if self.server.registry.all().iter().any(|s| s.is_alive()) {
            return false;
        }
        // Second conjunct: the window runs from the **last connection**,
        // not from boot — a daemon in continuous use must not be killed
        // by a timer that started when the process did.
        let since = self.last_client_connect().unwrap_or(self.started_at);
        self.clock.now().saturating_duration_since(since) >= Duration::from_secs(window)
    }

    pub fn shutdown_signalled(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Whether a shutdown has been asked for and not yet finished.
    ///
    /// The **producer side** of §18.3's `daemon_shutting_down`, and the
    /// only one. Every path that ends this daemon — `daemon/stop`
    /// ([`dispatch`]), SIGTERM ([`run_with_config`]) and §7.3's
    /// client-less exit ([`reaper_loop`]) — goes through
    /// [`Daemon::shutdown`] or [`Daemon::shutdown_graceful`], and both
    /// set this flag before the process gets anywhere near exiting.
    ///
    /// It reads the same `watch` channel [`shutdown_signalled`] hands
    /// out rather than a second `AtomicBool`, so there is one answer to
    /// "is this daemon stopping" and no way for the accept loop and the
    /// dispatcher to disagree.
    ///
    /// [`shutdown_signalled`]: Daemon::shutdown_signalled
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    /// §19.1's periodic half: rotate, retire, and **reopen**.
    ///
    /// The daemon has held `audit.log` open since start-up, so a
    /// rotation renames the file out from under a live descriptor.
    /// Without the reopen every subsequent `record` lands in an
    /// **unlinked inode**: every file on disk looks correct and §9.4's
    /// trail silently stops.
    ///
    /// **The reopen is unconditional, and that is the fix rather than
    /// the shape.** `sweep_logs` rotates `audit.log` *first*
    /// (`paths.rs`) and can then fail in any of four later steps —
    /// `daemon.log`'s own rotate, or a `read_dir`, a `metadata` or a
    /// `remove_file` inside either `retire`. On that path the audit log
    /// has already been renamed away and the call returns `Err`, so a
    /// reopen gated on `Ok(sweep)` with a non-empty `rotated` is
    /// skipped exactly when it is needed most. Gating it on `rotated`
    /// at all buys one avoided `open` per day and costs the whole
    /// trail; there is no version of this worth making conditional.
    ///
    /// Extracted from `reaper_loop` so that it has a caller a test can
    /// reach. Neither half was reachable before: the loop is spawned
    /// only from `run`, which nothing in the workspace calls.
    pub(crate) fn sweep_and_reopen(&self) {
        if let Err(e) = self.paths.sweep_logs(
            LogRetention::from(self.config()),
            std::time::SystemTime::now(),
        ) {
            crate::diag!("clasp daemon: log rotation sweep failed: {e}");
        }
        if let Err(e) = self.server.processor.audit.reopen() {
            crate::diag!("clasp daemon: cannot reopen the audit log: {e}");
        }
    }
}

/// Which socket file a daemon bound, so its own teardown can tell that
/// file apart from a successor's.
///
/// **Identity, not liveness, and the difference is the whole point.**
/// `spawn::socket_is_live` answers *"is any process holding a descriptor
/// on this socket"*, and the teardown needs *"is the file at this path
/// still the one I created"*. Those diverge in both directions: a
/// concurrently-forked child that inherited the listening descriptor
/// keeps the socket answering after its owner has closed it, and a
/// successor's freshly bound socket answers exactly like one's own.
///
/// Read from a single `symlink_metadata` under `bind.lock`, so it names
/// the file this process bound and nothing later.
///
/// **`(dev, ino)` alone is not enough, and that is measured rather than
/// argued.** An unlinked inode's *number* goes back to the allocator,
/// and on ext4 the next binder gets it back: 500 rounds of the exact C-5
/// window — predecessor binds, closes its listener, successor unlinks the
/// stale file and binds — handed the successor the predecessor's inode
/// number **500 times out of 500**. The same probe on tmpfs collides 0
/// times, because tmpfs, btrfs and APFS allocate from a monotonic
/// counter and never reuse one. So on the filesystem `~/.holdfast` most
/// often lives on, the obvious comparison would have named a successor's
/// socket as our own with near-certainty inside the window it exists to
/// guard. [`OwnedSocket`]'s pin is what closes that; `ctime` is a second,
/// free line of defence taken from the same `stat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketIdentity {
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl SocketIdentity {
    /// The identity of whatever the path names right now, without
    /// following a final symlink.
    ///
    /// `symlink_metadata` rather than `metadata` throughout: a symlink
    /// planted at `control.sock` must read as *someone else's file*
    /// (mismatch, no unlink), never as a window onto the target's
    /// identity.
    fn of(path: &std::path::Path) -> io::Result<Self> {
        Self::from_meta(&std::fs::symlink_metadata(path)?)
    }

    fn from_meta(meta: &std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        })
    }
}

/// The `control.sock` this daemon bound: which file it is, and a
/// reference that keeps the answer true for as long as the daemon runs.
///
/// **The pin is the load-bearing half.** Comparing a recorded
/// [`SocketIdentity`] against the path only means something while the
/// recorded value still refers to one file, and an inode number that has
/// been freed refers to whatever gets it next — 500 times out of 500 on
/// ext4, measured. Holding any descriptor on the inode stops it being
/// freed, so the number cannot be handed on; the same probe with the pin
/// in place collided 0 times out of 500.
///
/// `ctime` would usually catch a reuse on its own, and deliberately is
/// not relied on to: file timestamps come from a coarse, once-per-tick
/// clock on kernels before fine-grained (multigrain) timestamps, and two
/// binds separated by microseconds would share one. That would make the
/// guard's correctness a property of the host's kernel version, which is
/// not something a release should have to know.
#[derive(Debug)]
pub struct OwnedSocket {
    /// What the socket looked like at `bind`, for the platforms and
    /// failures where there is no pin to ask instead.
    id: SocketIdentity,
    /// An inert `O_PATH` descriptor on the socket's inode. `None` off
    /// Linux, and on Linux if the open failed — both of which fall back
    /// to `id` rather than to nothing.
    pin: Option<std::fs::File>,
}

impl OwnedSocket {
    /// Whether `path` still names the socket this daemon bound.
    ///
    /// **With a pin, the comparison is against the inode we are holding
    /// open rather than against a number we wrote down.** That is the
    /// difference between "the path names inode 4711, and inode 4711 was
    /// ours" — which stops being true the moment 4711 is freed and
    /// reissued — and "the path names *this* inode, the one we still
    /// have a reference to", which cannot go stale while the reference
    /// exists. `fstat` on an `O_PATH` descriptor is allowed and is all
    /// this needs.
    ///
    /// Without a pin it falls back to the recorded identity, whose
    /// `ctime` is what carries it. Both arms fail closed: an error
    /// anywhere reads as "not ours", which skips the unlink and leaves a
    /// stale socket for the next binder to clear under this same lock.
    fn still_at(&self, path: &std::path::Path) -> bool {
        let Ok(now) = SocketIdentity::of(path) else {
            return false;
        };
        match &self.pin {
            Some(pin) => pin
                .metadata()
                .and_then(|m| SocketIdentity::from_meta(&m))
                .is_ok_and(|held| now == held),
            None => now == self.id,
        }
    }
}

/// Hold the socket's inode open so its *number* cannot be recycled while
/// we still have a claim on it.
///
/// `O_PATH` is the only way to open a socket file at all — a plain
/// `open(2)` on an `S_IFSOCK` inode fails `ENXIO`. What it returns is
/// inert: it cannot be read, written, or connected to, and it has no
/// effect on whether the socket answers `connect(2)`. That inertness is
/// why the pin is this and not a `dup` of the listener, which would keep
/// the socket *answering* across the teardown and turn `ensure_daemon`'s
/// clean `ECONNREFUSED`-and-auto-spawn into a connect-then-reset error
/// for any client that arrived in the window.
///
/// `.read(true)` is not a request for read access: `OpenOptions` refuses
/// to build a call with no access mode, and `O_PATH` overrides the one it
/// puts there.
///
/// **The failure is swallowed on purpose.** A daemon must not refuse to
/// start because a defensive descriptor could not be opened; without the
/// pin the identity falls back to `ctime`, which is where it was a commit
/// ago. `the_bound_socket_holds_its_inode_open_after_the_path_is_gone` is
/// what stops that silence hiding a `pin_inode` that never succeeds.
#[cfg(target_os = "linux")]
fn pin_inode(path: &std::path::Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(path)
        .ok()
}

/// No `O_PATH` outside Linux, and none needed: the filesystems a daemon
/// runs on there — APFS and HFS+ — allocate inode numbers from a
/// monotonic counter and never hand one back.
#[cfg(not(target_os = "linux"))]
fn pin_inode(_path: &std::path::Path) -> Option<std::fs::File> {
    None
}

/// Bind `control.sock`, tighten it to `0600`, and report which file that
/// turned out to be.
///
/// The bind→chmod window is closed by the enclosing `0700` directory:
/// another user cannot reach the socket even during it, because they
/// cannot traverse the parent.
///
/// **The [`OwnedSocket`] is returned rather than looked up later on
/// demand** so that no binder can reach [`remove_runtime_files_we_own`]
/// without one, and so that both the identity read and the pin happen
/// under the lock that makes them true.
pub fn bind_control(paths: &RuntimePaths) -> io::Result<(UnixListener, OwnedSocket)> {
    bind_control_within(paths, super::spawn::LOCK_TIMEOUT)
}

/// [`bind_control`] with the bind-lock deadline supplied, so a test can
/// observe contention without paying [`spawn::LOCK_TIMEOUT`].
///
/// [`spawn::LOCK_TIMEOUT`]: super::spawn::LOCK_TIMEOUT
pub(crate) fn bind_control_within(
    paths: &RuntimePaths,
    lock_timeout: Duration,
) -> io::Result<(UnixListener, OwnedSocket)> {
    use std::os::unix::fs::PermissionsExt;

    paths.ensure_dir()?;

    // **The probe → unlink → bind window below is not atomic**, and
    // without a lock it is a way to unlink a *live* daemon's socket.
    // Two `clasp daemon run` processes — or one started while another's
    // `start_detached` had already timed out at 2 s with its child still
    // binding — can both see "dead", after which the second's
    // `remove_file` removes the first's just-bound socket. The first
    // then serves live PTY sessions on an unlinked inode no client can
    // reach again, and it never learns that it happened.
    //
    // The lock is taken here rather than in [`run`] so that no caller
    // can forget it: `run` is not the only path that binds — the
    // `TestDaemon` harness and the uid-gate test bind directly.
    //
    // `bind.lock` and **not** `holdfast.lock`: see
    // [`RuntimePaths::bind_lock_file`]. Held to the end of this
    // function, which is exactly the window, and released on return.
    let _bind_lock = super::spawn::DaemonLock::acquire_bind_within(paths, lock_timeout)?;

    let path = paths.control_sock();

    // **`symlink_metadata` and not `exists()`**, which is `fs::metadata`
    // and therefore follows the final symlink. A *dangling* link at
    // `control.sock` — one whose target does not exist — made `exists()`
    // answer `false`, so the sweep below was skipped entirely; and
    // `UnixListener::bind` does not follow the trailing component
    // either, so it found the link, returned `EEXIST`, and the kernel
    // mapped that to `EADDRINUSE`. The daemon then failed to start with a
    // bare "address in use" and no remedy named, every subsequent start
    // failed identically, and nothing self-healed: `daemon stop` had no
    // daemon to stop, and `remove_runtime_files_we_own` is only reached
    // by a daemon that got *past* this function. The stale-socket branch
    // could not reach the one case that needs it most.
    //
    // Widening it is safe, and narrowly so. A dangling link fails
    // `connect` with `ENOENT` and falls to the `remove_file` arm;
    // `remove_file` is `unlink(2)`, which never follows a symlink, so a
    // planted `control.sock -> ~/.ssh/id_rsa` loses the link and not the
    // key. The two non-dangling cases are unchanged: a link to a live
    // socket still connects and still refuses, and a link to a dead file
    // was already `exists() == true` before this.
    if std::fs::symlink_metadata(&path).is_ok() {
        // A socket file whose daemon is gone is stale and must be
        // cleared; one whose daemon is alive is not ours to take.
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("a daemon is already listening on {}", path.display()),
                ))
            }
            Err(_) => std::fs::remove_file(&path)?,
        }
    }

    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    // One `stat`, two answers: the mode this re-reads rather than
    // trusting, and the identity the teardown compares against. Taken
    // after the `chmod`, because the `chmod` moves `ctime`; taken here,
    // because this is the last point at which `bind.lock` still
    // guarantees the path names the socket we just created.
    let meta = std::fs::symlink_metadata(&path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != SOCKET_MODE {
        let _ = std::fs::remove_file(&path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is mode {mode:o}, expected {SOCKET_MODE:o}",
                path.display()
            ),
        ));
    }
    // The pin is taken here, under `bind.lock` and against the file this
    // function just created, so there is no window in which the path
    // could have moved on to somebody else's socket before we hold it.
    Ok((
        listener,
        OwnedSocket {
            id: SocketIdentity::from_meta(&meta)?,
            pin: pin_inode(&path),
        },
    ))
}

/// Holds [`Daemon::in_flight`] up for the life of one connection.
///
/// A guard rather than a `fetch_sub` at the end of the task, so the
/// count is decremented on **every** exit path — including a panic
/// inside `handle_connection`, which would otherwise leave the counter
/// permanently non-zero and disable §7.3's exit for the life of the
/// process.
struct InFlight(Arc<Daemon>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections until shutdown is signalled.
pub async fn serve(daemon: Arc<Daemon>, listener: UnixListener) {
    let mut shutdown = daemon.shutdown_signalled();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        daemon.connections.fetch_add(1, Ordering::Relaxed);
                        // **Incremented here and not inside the task.**
                        // The point of the counter is to see a
                        // connection the handshake timestamp cannot, and
                        // a task that has been spawned but not yet
                        // polled is exactly that connection.
                        daemon.in_flight.fetch_add(1, Ordering::SeqCst);
                        let d = Arc::clone(&daemon);
                        tokio::spawn(async move {
                            let _open = InFlight(Arc::clone(&d));
                            handle_connection(d, stream).await;
                        });
                    }
                    Err(e) => {
                        crate::diag!("clasp daemon: accept failed: {e}");
                    }
                }
            }
        }
    }
}

/// How often the reaper loop re-runs the §19.1 rotation sweep.
///
/// §19.1 rolls on a period boundary and the retention windows are days
/// and weeks, so once a day is the right cadence — and it is on the
/// reaper's tick rather than on every write, which would put a directory
/// walk in the read path.
const LOG_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The daemon's one periodic tick: the idle reaper (§16.7), §7.3's
/// client-less exit, and §19.1's rotation sweep.
///
/// All three live here because the reaper is the only periodic timer in
/// the process, and a second one would be a second answer to "how often
/// does the daemon look at itself".
///
/// `pub(crate)` so the loop itself is testable. It was private and
/// spawned only from [`run`], which nothing in the workspace calls, so
/// deleting any single statement in the body — or the spawn — left the
/// **whole** workspace green while disabling the idle reaper (§16.7),
/// REQ-R-006's exit half, §7.3's client-less exit and §19.1's retention
/// sweep in production. Every §7.3 test asserted the *predicate*
/// `client_less_exit_due()` and none that anything acted on it.
pub(crate) async fn reaper_loop(daemon: Arc<Daemon>) {
    let reaper = Reaper::new(Arc::clone(&daemon.server.registry), daemon.clock());
    let mut shutdown = daemon.shutdown_signalled();
    let clock = daemon.clock();
    let mut next_log_sweep = clock.now() + LOG_SWEEP_INTERVAL;
    // Seed the known set, so the first tick does not announce every
    // session that already existed as a change.
    daemon.poll_resource_list_changed();

    loop {
        reaper.scan_once();
        // REQ-R-006's exit half, on the only periodic tick there is.
        daemon.poll_resource_list_changed();

        // §7.3's conjunction, checked after the sweep so a session the
        // reaper just took down counts towards "all sessions have
        // exited" on this pass rather than the next one.
        if daemon.client_less_exit_due() {
            daemon.shutdown();
            return;
        }

        if clock.now() >= next_log_sweep {
            daemon.sweep_and_reopen();
            next_log_sweep = clock.now() + LOG_SWEEP_INTERVAL;
        }

        tokio::select! {
            _ = shutdown.changed() => return,
            _ = reaper.wait_for_next_tick() => {}
        }
    }
}

/// The daemon's two long-lived tasks: the periodic tick, and the accept
/// loop. Returns when the accept loop stops, which is when shutdown has
/// been signalled — by `daemon/stop`, by SIGTERM, or by §7.3's
/// client-less exit acting from inside [`reaper_loop`].
///
/// **Separate from [`run`] because the spawn was otherwise untestable.**
/// `run` loads a config from the environment, binds a socket, writes a
/// pid file and installs a process-wide SIGTERM handler, so nothing in
/// the workspace calls it — and `tokio::spawn(reaper_loop(…))` sitting
/// inside it meant deleting the one line that starts the daemon's only
/// periodic timer left every test green while disabling four features
/// at once. Here it has a caller a test can drive over a real socket,
/// and `the_daemon_starts_its_periodic_tick_and_the_client_less_window_
/// stops_the_accept_loop` is the row that goes red without it.
pub async fn serve_daemon(daemon: Arc<Daemon>, listener: UnixListener) {
    tokio::spawn(reaper_loop(Arc::clone(&daemon)));
    serve(daemon, listener).await;
}

/// Run a daemon to completion: bind, write the pid file, serve, clean up.
pub async fn run(paths: RuntimePaths) -> anyhow::Result<()> {
    // **Config first, and before `bind_control`** (REQ-CFG-003). An
    // invalid config must reject daemon *startup*: the daemon exits
    // non-zero with the offending key on stderr and binds no socket. A
    // daemon that starts with a bad config and logs a warning is the
    // failure mode that requirement exists to prevent — the operator
    // believes a limit is in force and it is not.
    let config = crate::config::load()?;
    run_with_config(paths, config).await
}

/// [`run`] with the configuration supplied rather than discovered.
///
/// **Split out so the exit path has a caller a test can drive.** `run`
/// reads `$XDG_CONFIG_HOME/holdfast/config.toml` from the developer's real
/// home, so nothing in the workspace could call it — which left the
/// teardown at the bottom of this function unasserted, and it was
/// unlinking a *successor* daemon's socket. The config discovery stays
/// in `run` above, ahead of everything this function does, so
/// REQ-CFG-003's "reject startup before a socket is bound" ordering is
/// still structural rather than a comment.
pub(crate) async fn run_with_config(paths: RuntimePaths, config: Config) -> anyhow::Result<()> {
    // `bind_control` runs `paths.ensure_dir()`, which creates the log
    // directory `0700`. That ordering is load-bearing rather than
    // incidental: `Daemon::new` opens the audit log from `paths`, and
    // `with_audit_path` leaves a log it cannot open *disabled*.
    // Construct the daemon before the directory exists and the trail is
    // off for a reason that is nobody's fault — which is also why the
    // audit refusal below sits after this line and not before it. The
    // same ordering holds in `TestDaemon::start`, which binds first for
    // the same reason.
    let (listener, our_socket) = bind_control(&paths)?;
    write_pid_file(&paths)?;

    // The startup half of §19.1's sweep, run **before** `Daemon::new`
    // takes its audit-log handle. Rotating after that point renames the
    // file out from under an open descriptor; the periodic sweep the
    // reaper owns handles that case with `AuditLog::reopen`, and this
    // one avoids it by ordering. A sweep failure is not fatal — a daemon
    // that will not start because a log could not be renamed is a worse
    // outcome than one that runs and says so.
    if let Err(e) = paths.sweep_logs(LogRetention::from(&config), std::time::SystemTime::now()) {
        crate::diag!("clasp daemon: log rotation sweep failed: {e}");
    }

    let daemon = Daemon::with_config(paths.clone(), config);

    // **The §9.4 trail fails closed on this host.** `with_audit_path`
    // leaves the log disabled and records why; on every other host that
    // is the right answer, and on the daemon it is not. A root-owned
    // `audit.log` from one `sudo clasp` otherwise gave
    // a daemon that served every client on the box with no
    // `session_start`, no `redaction_disabled` — nothing — while
    // reporting perfect health, and the only trace was a line on stderr
    // that under `daemon run` goes wherever the launcher pointed it.
    //
    // REQ-CFG-003 is the precedent and the comparison that settles it:
    // an invalid *config* already refuses startup, on the reasoning that
    // an operator must not believe a limit is in force when it is not.
    // A trail that is silently not being written is the same failure
    // with more at stake, and it was getting the weaker treatment.
    //
    // **After `bind_control`, and it has to be.** `bind_control` runs
    // `ensure_dir`, which creates `logs/` `0700`; checking before that
    // would refuse every first run. So the socket and pid file exist by
    // now and are removed here — the same teardown the ordinary exit
    // path runs, because a refusal that leaves a bound socket behind is
    // a daemon every later `ensure_daemon` has to probe and clear.
    if let Some(why) = daemon.server.audit_open_error() {
        let why = why.to_string();
        // **Drop the listener first**, so no client can connect to a
        // daemon that has already decided not to serve. It is no longer
        // what makes the unlink below happen — the teardown compares the
        // socket's identity, which does not care who holds a descriptor
        // — but a refusing daemon must not be reachable while it winds
        // down, and the ordinary exit path gets that for free because
        // `serve_daemon` consumes the listener.
        drop(listener);
        remove_runtime_files_we_own(&paths, &our_socket);
        anyhow::bail!(
            "clasp daemon: refusing to start without the §9.4 audit trail: {why}. \
             Fix the ownership or permissions of that file, or point \
             HOLDFAST_RUNTIME_DIR at a directory this user owns."
        );
    }

    let sig_daemon = Arc::clone(&daemon);
    tokio::spawn(async move {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    crate::diag!("clasp daemon: cannot install SIGTERM handler: {e}");
                    return;
                }
            };
        term.recv().await;
        sig_daemon.shutdown();
    });

    serve_daemon(Arc::clone(&daemon), listener).await;

    // Anything still alive after `shutdown()` (or after a shutdown that
    // never ran, e.g. a bind error unwinding) dies here.
    daemon.shutdown();
    remove_runtime_files_we_own(&paths, &our_socket);
    Ok(())
}

/// §7.3's *"On exit: … removes sockets, removes PID file"* — under the
/// binder's lock, and only for the files this process still owns.
///
/// **Every other unlink of `control.sock` sits inside `bind.lock`**
/// (`bind_control_within`, both arms), and this is the only one that
/// runs while another process may legitimately be binding.
/// `bind_control`'s comment reasons about exactly this race and closes
/// it from the binding side; unlocked and unconditional, the teardown
/// reopened it from the other side, where the lock cannot see it:
///
/// 1. Daemon A's `serve` returns — a `daemon/stop`, a SIGTERM, §7.3's
///    client-less exit — so its listener is dropped and `socket_is_live`
///    is now false.
/// 2. A shim auto-spawns daemon B. B takes `bind.lock`, probes (dead),
///    unlinks the stale socket, binds a fresh one, chmods it, releases.
/// 3. A, still on its way out, unlinks **B's just-bound socket**. B
///    keeps serving — its listener fd is still open — on an unlinked
///    inode no `connect(2)` can ever reach again, and never learns.
/// 4. A deletes **B's** pid file too, so a later `daemon stop --force`
///    reads no pid and escalates to nothing, leaving an unreachable
///    daemon holding live PTY sessions that nothing can address.
///
/// The window is not instantaneous — the `shutdown()` above walks the
/// registry SIGKILLing sessions first — and the trigger, a
/// `clasp daemon stop` followed by anything that auto-spawns, is a
/// normal operator action.
///
/// So: take the binder's lock, and ask twice whether these files are
/// still ours. A pid file naming another process is somebody else's —
/// one comparison, and it makes the removal idempotent under any
/// interleaving. The socket is the same question and needs the same kind
/// of answer, which is [`OwnedSocket`].
///
/// **The socket half was `!socket_is_live` and that was wrong.** It asks
/// whether *anyone* is holding a descriptor on the socket, and answers
/// `true` for a descriptor that is not the owner's: an AF_UNIX listener
/// stays connectable while any process references it, and every `fork`
/// in this tree — `start_detached`, every PTY spawn — briefly gives a
/// child a copy of ours between `fork` and `exec`. Under a parallel test
/// suite that window is wide enough to hit roughly half of all runs, and
/// what it produced was §7.3's unlink being silently skipped for a
/// socket nobody was serving. The failure was benign in production and
/// fatal to the point of a gate: the two rows below this one were red
/// half the time for a reason neither of them is about.
///
/// Comparing identity is not a weaker check than liveness, it is a
/// different and tighter one. Liveness cannot distinguish our socket
/// from a successor's — both answer — and only the lock ordering made it
/// usable at all; identity distinguishes them directly, and keeps
/// working for a successor that has bound but has not yet been
/// connected to.
///
/// **Not the pid-file test, for the socket.** It looks equivalent and is
/// not: a successor binds and writes its pid file on two consecutive
/// lines with `bind.lock` released in between, so there is a window in
/// which the socket is the successor's while the pid file is still the
/// predecessor's. Reusing the pid comparison for the socket would unlink
/// the successor's socket in that window — precisely the C-5 defect this
/// function exists to prevent.
///
/// **Keep the removal.** §7.3 mandates it; the defect was that it was
/// unlocked and unconditional, not that it happened. Skipping the
/// cleanup when the lock cannot be taken — `acquire_bind` runs
/// `ensure_dir` first, which can fail — is the safe direction: it leaves
/// a stale socket file, which the next binder clears under this same
/// lock. Every way the identity comparison can be wrong points the same
/// way: an unreadable or unequal identity skips the unlink and leaves a
/// stale socket, and never removes a file that might be someone else's.
///
/// **`ours` is borrowed, not consumed, and that matters.** It carries the
/// pin that keeps its own inode number out of the allocator's hands; a
/// signature that took it by value would drop it here, at the exact
/// moment the comparison has just been made and the unlink is about to
/// run.
pub(crate) fn remove_runtime_files_we_own(paths: &RuntimePaths, ours: &OwnedSocket) {
    let Ok(_bind_lock) = super::spawn::DaemonLock::acquire_bind(paths) else {
        return;
    };
    if ours.still_at(&paths.control_sock()) {
        let _ = std::fs::remove_file(paths.control_sock());
    }
    if read_pid_file(paths) == Some(std::process::id()) {
        let _ = std::fs::remove_file(paths.pid_file());
    }
}

/// Write `holdfast.pid`, owner-only, like every other file this daemon
/// creates.
///
/// **Consistency, not exposure.** `bind.lock` and `holdfast.lock` are
/// created `0600` (`spawn.rs`), `control.sock` is chmodded `0600` and
/// then re-read and verified, and this one alone took the ambient umask.
/// Its contents are a pid and a version string — both of which `/proc`
/// and `clasp version` publish anyway — and it sits in a directory whose
/// `0700` is re-asserted by `ensure_owner_only(…, Writable::Refuse)` on
/// every `ensure_dir`, so the mode only matters in a world where the
/// directory guard has already failed. It is not verified afterwards for
/// that reason; the socket is, because the socket is the boundary.
///
/// **`.truncate(true)` is load-bearing and `std::fs::write` gave it for
/// free.** `OpenOptions` does not: without it, a shorter pid replacing a
/// longer one leaves the tail of the old line behind, and
/// `read_pid_file`'s `split_whitespace().next()` would parse the new pid
/// and never notice — so the defect would stay invisible until something
/// read the version field.
///
/// `mode` applies only when the file is *created*, so a `holdfast.pid`
/// inherited from an older, wider-umask build keeps its mode until it is
/// removed. §7.3's teardown removes it on every clean exit, and the
/// enclosing `0700` is the control that does not depend on this one.
fn write_pid_file(paths: &RuntimePaths) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PID_FILE_MODE)
        .open(paths.pid_file())?;
    writeln!(f, "{} {}", std::process::id(), env!("CARGO_PKG_VERSION"))
}

/// Read `holdfast.pid`. `None` if absent or unparseable.
pub fn read_pid_file(paths: &RuntimePaths) -> Option<u32> {
    let text = std::fs::read_to_string(paths.pid_file()).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// §9.1's admission decision, as one expression.
///
/// Extracted from `handle_connection` on purpose. Inline, the decision
/// was a three-armed `match` whose diagnostics were interleaved with its
/// verdict, and the `Err` arm — the one that must **fail closed** — could
/// be turned into `Err(_) => {}` with nothing in the workspace going red.
/// As a function it has one caller, three arms and a unit test that names
/// all three: `the_uid_gate_admits_only_the_owner_and_fails_closed`.
///
/// The `Err` arm answering `false` is the whole point. A daemon that
/// cannot read a peer's credentials knows nothing about that peer, and
/// "unknown" is not "ours".
fn peer_is_authorized(cred: &io::Result<peer::PeerCred>, our_uid: u32) -> bool {
    matches!(cred, Ok(c) if peer::is_authorized(c.uid, our_uid))
}

async fn handle_connection(daemon: Arc<Daemon>, mut stream: UnixStream) {
    // Credential check first, before a single frame is read. An
    // unauthorized peer gets no response at all: there is nothing to
    // negotiate, and a reply would confirm the daemon's existence.
    let cred = peer::peer_cred(&stream);
    if !peer_is_authorized(&cred, daemon.owner_uid) {
        // Diagnostics only, and after the verdict rather than inside it:
        // nothing below can change who is admitted.
        match &cred {
            Ok(c) => crate::diag!(
                "clasp daemon: refused a connection from uid {} (daemon runs as uid {})",
                c.uid,
                daemon.owner_uid
            ),
            Err(e) => crate::diag!("clasp daemon: cannot read peer credentials, refusing: {e}"),
        }
        return;
    }

    // The kind the peer declared in its handshake, on a connection whose
    // uid we just checked. This is the *only* source of caller identity
    // for the §9.4 audit record — see `mcp::caller`.
    let Some(client_kind) = do_handshake(&mut stream).await else {
        return;
    };

    // §7.3's window is "no clients have connected", and it is recorded
    // here — after the uid gate and after a handshake that was accepted
    // — so a refused peer cannot hold a daemon open indefinitely.
    daemon.note_client_connect();

    loop {
        let req: Request = match frame::read_frame(&mut stream).await {
            Ok(r) => r,
            Err(FrameError::Eof) => return,
            Err(FrameError::TooLarge { len }) => {
                let resp = Response::error(
                    0,
                    ErrorCode::FrameTooLarge,
                    format!("frame of {len} bytes exceeds {}", frame::MAX_FRAME_BYTES),
                );
                let _ = frame::write_frame(&mut stream, &resp).await;
                return;
            }
            Err(e) => {
                let resp = Response::error(0, ErrorCode::ProtocolViolation, e.to_string());
                let _ = frame::write_frame(&mut stream, &resp).await;
                return;
            }
        };

        // §18.3's one retriable code, and the only place that produces
        // it. A daemon that has been asked to stop is still holding
        // every connection it had — `shutdown()` ends the *accept* loop,
        // not the tasks already serving — so without this arm an
        // in-flight caller on another connection either gets served by a
        // daemon that is dismantling itself or, once the process
        // actually exits, gets `Eof`. `Eof` is indistinguishable from a
        // crash and `ClientError::retriable()` classifies it `false`, so
        // the reconnect that would have worked is never attempted.
        //
        // Checked **after** the read and before the dispatch, so the
        // `daemon/stop` that set the flag is itself dispatched normally
        // and answers its own caller with a `StopOutcome`.
        //
        // **The `return` below is part of the code's contract, not an
        // implementation detail of this arm.** There is no grace window
        // in which this connection carries another call: the client is
        // told to reconnect precisely because this socket is finished,
        // and `ErrorCode::closes_connection()` answers `true` for the
        // code so the client's pool declines to park it. When that
        // answered `false` the pool parked this socket and the invited
        // retry came back as `Eof`.
        if daemon.is_shutting_down() {
            let resp = Response::error(
                req.id,
                ErrorCode::DaemonShuttingDown,
                "the daemon is shutting down; reconnect and retry",
            );
            let _ = frame::write_frame(&mut stream, &resp).await;
            return;
        }

        let (resp, stop_after) = dispatch(&daemon, &req, client_kind).await;
        if !write_response(&mut stream, req.id, &resp).await {
            return;
        }
        if response_closes_connection(&resp) {
            return;
        }
        if stop_after {
            daemon.shutdown();
            return;
        }
    }
}

/// Write one response, and say whether the connection may carry another.
///
/// **An over-cap *response* used to be indistinguishable from a dead
/// peer.** This was `write_frame(..).is_err()`, which folded
/// [`FrameError::TooLarge`] in with EPIPE and returned: no error frame,
/// no log line, and no `frame_too_large` — that arm existed only on the
/// **read** side, for an oversized request. The caller saw `Eof`, which
/// `mcp::shim::map_client_error` reports as `daemon_unreachable` when
/// the daemon is in perfect health, and an operator had nothing at all
/// to go on.
///
/// Not reachable at shipped defaults — the worst case is a few MiB
/// against a 16 MiB cap — but reachable **through configuration alone**:
/// `output_buffer_bytes` and `resource_read_max_bytes` take only
/// `nonzero()`, with no ceiling and no cross-check against
/// [`frame::MAX_FRAME_BYTES`]. A `Config::validate` clause requiring
/// headroom under that cap is the other half of this fix and is still
/// owed; it turns a runtime failure into a named startup rejection.
///
/// **The refusal is safe to follow with a second frame**, and that is
/// why it can be sent at all: `frame::encode` runs to completion before
/// a single byte is written, so `TooLarge` means nothing reached the
/// socket and the stream is still frame-aligned. A codec that wrote the
/// prefix first could not do this.
///
/// The connection still closes — `frame_too_large` is one of
/// [`ErrorCode::closes_connection`]'s codes — but it closes *after*
/// saying why,
/// correlated to the request that provoked it, so `ControlClient` drops
/// that connection instead of parking it and the next call dials a fresh
/// one. The failure is one call, not the rest of the MCP session.
///
/// Generic over the writer so the refusal is testable without a socket:
/// the interesting value is 16 MiB, and a `Vec<u8>` sink measures it
/// without a kernel buffer in the way.
async fn write_response<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    id: u64,
    resp: &Response,
) -> bool {
    match frame::write_frame(w, resp).await {
        Ok(()) => true,
        Err(FrameError::TooLarge { len }) => {
            crate::diag!(
                "clasp daemon: the response to request {id} is {len} bytes, over the \
                 {}-byte frame limit; refusing it and closing the connection",
                frame::MAX_FRAME_BYTES
            );
            let refusal = Response::error(
                id,
                ErrorCode::FrameTooLarge,
                format!(
                    "the response to this request was {len} bytes, over the {}-byte limit; \
                     lower [limits] output_buffer_bytes or resource_read_max_bytes, or ask \
                     for fewer bytes",
                    frame::MAX_FRAME_BYTES
                ),
            );
            let _ = frame::write_frame(w, &refusal).await;
            false
        }
        Err(_) => false,
    }
}

/// Whether the response just written must be the last one on this
/// connection (§7.4, §18.3).
///
/// **Fails closed, and that is the whole reason it is a function.** The
/// decision has to come off the wire — a `Response` is four serialised
/// fields and carries no `ErrorCode` — so it goes back through
/// [`ErrorCode::from_wire`], which answers `None` for any code this
/// build does not know. Inline, that `None` was skipped by an
/// `if let Some(code)` and the connection **stayed open after a protocol
/// violation**: the one direction §7.4 does not permit.
///
/// `None` is unreachable from this build's own dispatcher — every
/// producer selects from `ErrorCode` — so treating it as closing costs
/// nothing today and is the only safe reading if a response is ever
/// built outside that enum. The asymmetry decides it: keeping a
/// connection open one frame too long after a mis-framing peer is a
/// protocol break, and closing one frame too early is a reconnect.
fn response_closes_connection(resp: &Response) -> bool {
    match resp.control_error() {
        None => false,
        Some(e) => ErrorCode::from_wire(&e.code).is_none_or(ErrorCode::closes_connection),
    }
}

/// Exchange the handshake.
///
/// `Some(kind)` is the peer's declared [`ClientKind`], which becomes the
/// connection's caller identity for §9.4. `None` means the connection
/// must close.
async fn do_handshake(stream: &mut UnixStream) -> Option<ClientKind> {
    do_handshake_within(stream, handshake::HANDSHAKE_TIMEOUT).await
}

/// [`do_handshake`] with the deadline supplied, so a test can observe
/// the timeout without paying [`handshake::HANDSHAKE_TIMEOUT`].
async fn do_handshake_within(
    stream: &mut UnixStream,
    deadline: std::time::Duration,
) -> Option<ClientKind> {
    // **The daemon's only deadline on this protocol.** `serve` spawns an
    // uncapped task per accepted connection, so without this a peer that
    // connects and sends nothing holds a task and a file descriptor
    // until the daemon dies — and, since Imp-19, is also counted as an
    // in-flight connection and would hold §7.3's client-less exit open
    // for as long as it stayed silent.
    //
    // Scoped to the first frame. Nothing past the handshake is bounded:
    // `wait_for_pattern` is 3600 s at its cap and a deadline that
    // reached it would cut off a legitimate call.
    let req: Request = match tokio::time::timeout(deadline, frame::read_frame(stream)).await {
        Ok(Ok(r)) => r,
        // A silent peer and a peer that hung up are the same outcome —
        // close, say nothing. There is no one to send a diagnostic to.
        Ok(Err(_)) | Err(_) => return None,
    };
    if req.method != method::METHOD_HANDSHAKE {
        // §7.4.1: "a connection that issues any other method first is
        // closed with ProtocolError { reason: no_handshake }".
        let resp = Response::error(
            req.id,
            ErrorCode::NoHandshake,
            format!(
                "expected {} first, got {}",
                method::METHOD_HANDSHAKE,
                req.method
            ),
        );
        let _ = frame::write_frame(stream, &resp).await;
        return None;
    }
    let params: HandshakeParams = match req.params_as() {
        Ok(p) => p,
        Err(e) => {
            let resp = Response::error(req.id, ErrorCode::BadParams, e.to_string());
            let _ = frame::write_frame(stream, &resp).await;
            return None;
        }
    };
    let data = handshake::evaluate(&params);
    let accepted = data.accepted;
    let details = if accepted {
        "handshake accepted".to_string()
    } else {
        data.reject_reason.clone().unwrap_or_default()
    };
    let resp = match Response::ok(req.id, &data, details) {
        Ok(r) => r,
        Err(e) => Response::error(req.id, ErrorCode::ProtocolViolation, e.to_string()),
    };
    if frame::write_frame(stream, &resp).await.is_err() {
        return None;
    }
    if accepted {
        Some(params.client_kind)
    } else {
        None
    }
}

/// The caller recorded for a request (§9.4).
///
/// `req` is taken and deliberately **not** consulted. The parameter is
/// here so that the guarantee is testable: `an_agent_cannot_influence_the
/// _recorded_caller` passes a request stuffed with every field an agent
/// might try — `surface`, `client_kind`, `caller` — and asserts the
/// answer is still the connection's. Make this function read `req` and
/// that test goes red, which is the whole point of the shape.
fn caller_for(connection: ClientKind, _req: &Request) -> Caller {
    Caller::from_client_kind(connection)
}

/// Route one request. The `bool` is "shut the daemon down after replying".
///
/// **Grouped rather than flat.** This was one `match` with four arms,
/// which is the right shape for a handful of methods and the wrong shape
/// for thirty; §5.5's three `resource/*` methods are where it crossed, so
/// they arrive as a group with their own function rather than as three
/// more arms with their bodies inline.
async fn dispatch(
    daemon: &Arc<Daemon>,
    req: &Request,
    client_kind: ClientKind,
) -> (Response, bool) {
    match req.method.as_str() {
        method::METHOD_RESOURCE_LIST
        | method::METHOD_RESOURCE_TEMPLATES_LIST
        | method::METHOD_RESOURCE_READ => {
            (dispatch_resource(daemon, req, client_kind).await, false)
        }
        method::METHOD_HANDSHAKE => (
            Response::error(
                req.id,
                ErrorCode::ProtocolViolation,
                "handshake already completed on this connection",
            ),
            false,
        ),
        method::METHOD_DAEMON_STATUS => (
            Response::ok(req.id, &daemon.status(), "ok")
                .unwrap_or_else(|e| Response::error(req.id, ErrorCode::BadParams, e.to_string())),
            false,
        ),
        method::METHOD_DAEMON_STOP => {
            // `force` and `timeout_secs` describe how hard to push the
            // *sessions*, and Task 16 makes them differentiate: `force:
            // false` is SIGTERM, wait `timeout_secs`, then SIGKILL;
            // `force: true` escalates immediately. The wire shape was
            // settled in Task 3 precisely so this needed no protocol
            // change.
            //
            // Parsed, not ignored: this used to be `unwrap_or_default()`,
            // which made `daemon/stop` the one method that answers `ok`
            // to structurally garbage params — and, worse, left
            // `StopParams`' wire names unpinned, because nothing could
            // observe whether the daemon had read them. Now that the
            // knobs act, a rename would silently stop forcing.
            let params: StopParams = match req.params_as() {
                Ok(p) => p,
                Err(e) => {
                    return (
                        Response::error(req.id, ErrorCode::BadParams, e.to_string()),
                        false,
                    )
                }
            };
            let terminated = if params.is_forced() {
                daemon.shutdown()
            } else {
                daemon.shutdown_graceful(params.grace()).await
            };
            let outcome = StopOutcome {
                stopped_at_unix_secs: unix_secs_now(),
                sessions_terminated: terminated,
            };
            (
                Response::ok(req.id, &outcome, "daemon stopping").unwrap_or_else(|e| {
                    Response::error(req.id, ErrorCode::BadParams, e.to_string())
                }),
                true,
            )
        }
        other => {
            // `req.tool_name()` rather than a second inline
            // `strip_prefix`: two spellings of one routing rule means
            // the tested one is not the shipped one, and `method.rs`'s
            // negative cases are what stop `daemon/status` reaching the
            // 0.0.2 `status` tool. Do not re-derive the strip here.
            let Some(tool) = req.tool_name() else {
                return (
                    Response::error(
                        req.id,
                        ErrorCode::UnknownMethod,
                        format!("no method {other}"),
                    ),
                    false,
                );
            };
            (dispatch_tool(daemon, req, tool, client_kind).await, false)
        }
    }
}

/// §7.4.1's three `resource/*` methods (§5.5).
///
/// Scoped to the connection's caller exactly as `dispatch_tool` is,
/// because `resource/read` reaches `Session::read_processed` and a
/// `?redact=false` fetch therefore writes a §9.4 `redaction_disabled`
/// entry from inside the read path. Outside the scope that entry would
/// read `client_kind: "in_process"` — §9.4's *"no control-protocol
/// connection existed"* — on the one transport where a connection
/// certainly did.
async fn dispatch_resource(
    daemon: &Arc<Daemon>,
    req: &Request,
    client_kind: ClientKind,
) -> Response {
    let who = caller_for(client_kind, req);
    let server = &daemon.server;
    let ok = |data: serde_json::Value| -> Response {
        Response::ok(req.id, &data, "ok")
            .unwrap_or_else(|e| Response::error(req.id, ErrorCode::BadParams, e.to_string()))
    };
    let call = async {
        match req.method.as_str() {
            method::METHOD_RESOURCE_LIST => ok(serde_json::json!({
                "resources": resources::list_resources(&server.registry),
            })),
            method::METHOD_RESOURCE_TEMPLATES_LIST => ok(serde_json::json!({
                "resourceTemplates": resources::list_resource_templates(),
            })),
            _ => {
                #[derive(Deserialize)]
                struct ReadParams {
                    uri: String,
                }
                let params: ReadParams = match req.params_as() {
                    Ok(p) => p,
                    Err(e) => return Response::error(req.id, ErrorCode::BadParams, e.to_string()),
                };
                match resources::read_resource(
                    &server.registry,
                    &server.processor,
                    &params.uri,
                    server.config.limits.resource_read_max_bytes,
                ) {
                    // §18.3's nearest catalogued code is `bad_params`, so
                    // a peer that knows only §18.3 still reads a
                    // well-formed error. The structured `data.code`
                    // travels in the message rather than being invented
                    // as a new control-protocol code, and
                    // `shim::rebuild_resource_error` decodes exactly this
                    // envelope back out.
                    //
                    // **`rpc_code`, because `bad_params` is not the
                    // diagnosis here either.** §5.5.2's validation faults
                    // really are `-32602 Invalid params`, but `resolve`
                    // answers `-32002 resource_not_found` for a session id
                    // that does not exist and for §5.5.6's unserved
                    // file shape — and dropping the code rewrote all
                    // three to `-32602`, telling an agent whose URI was
                    // perfectly well formed that it was malformed. Same
                    // field, same reason, as the tool path above.
                    Err(e) => Response::error_with_rpc_code(
                        req.id,
                        ErrorCode::BadParams,
                        serde_json::to_string(&serde_json::json!({
                            "message": e.message,
                            "data": e.data,
                        }))
                        .unwrap_or_else(|_| e.message.to_string()),
                        Some(e.code.0),
                    ),
                    Ok(result) => match serde_json::to_value(&result) {
                        Ok(v) => ok(v),
                        Err(e) => Response::error(req.id, ErrorCode::BadParams, e.to_string()),
                    },
                }
            }
        }
    };
    caller::with_caller(who, call).await
}

/// The control-protocol response for a tool that raised an MCP
/// **protocol** fault (§5.1) rather than returning an outcome.
///
/// §18.3 has no JSON-RPC codes, so the code on the wire is its nearest
/// catalogued row, `bad_params`, and a peer that knows only §18.3 still
/// reads a well-formed error.
///
/// **`bad_params` is the control-protocol code and not the diagnosis**,
/// and the two used to be conflated. Only `ErrorData::invalid_params` is
/// really the caller's fault; `envelope::from_error` maps
/// `HoldfastError::Pty | HoldfastError::Io` to `internal_error` from about a
/// dozen sites in `tools.rs`, and `tools.rs` maps a panicked write task
/// to `internal_error` with the comment *"a CLASP bug, not a session
/// outcome"*. Discarding `e.code` told the agent that `openpty failed`
/// was its own malformed argument — and told it something different
/// under `--no-daemon`, where the same fault stays `internal_error`.
/// `rpc_code` carries the real one across, and `mcp::shim::rebuild_error`
/// puts it back.
///
/// **`e.data` is still dropped, deliberately.** It is arbitrary
/// agent-visible JSON on a §9.4-audited surface; the code is an integer
/// and carries no content at all. Imp-13 is where the resource path's
/// structured `data` gets a route, and that route has to go through the
/// redactor.
///
/// A function rather than a `match` arm because it is the one place a
/// JSON-RPC code is chosen, and inline it could only be exercised
/// against whichever code a real tool happened to raise — one value, so
/// a mutation hardcoding that value survived.
fn tool_error_response(id: u64, e: &rmcp::ErrorData) -> Response {
    Response::error_with_rpc_code(
        id,
        ErrorCode::BadParams,
        e.message.to_string(),
        Some(e.code.0),
    )
}

async fn dispatch_tool(
    daemon: &Arc<Daemon>,
    req: &Request,
    tool: &str,
    client_kind: ClientKind,
) -> Response {
    let args: serde_json::Value = match method::from_cbor(&req.params) {
        Ok(v) => v,
        Err(e) => {
            return Response::error(
                req.id,
                ErrorCode::BadParams,
                format!("tool arguments are not a JSON-shaped object: {e}"),
            )
        }
    };
    // Scope the call to the caller derived from the connection, so the
    // §9.4 audit write inside the read path records who asked without
    // any tool handler having to pass it down.
    let who = caller_for(client_kind, req);
    let call = async {
        // Read back from *inside* the scope rather than trusting `who`.
        // Recording `who` here would still pass if the `with_caller`
        // wrapper below were removed, and a missing wrapper is precisely
        // the failure that would make every future audit entry read
        // `in_process`.
        #[cfg(test)]
        tests::record_observed_caller(caller::current());
        passthrough::call_tool(&daemon.server, tool, args).await
    };
    match caller::with_caller(who, call).await {
        None => Response::error(req.id, ErrorCode::UnknownMethod, format!("no tool {tool}")),
        Some(Err(e)) => tool_error_response(req.id, &e),
        Some(Ok(result)) => {
            let outcome = passthrough::result_to_outcome(&result);
            let details = outcome.details.clone();
            let status = outcome.status.clone();
            match method::to_cbor(&outcome.data) {
                Ok(data) => Response {
                    id: req.id,
                    status,
                    data,
                    details,
                },
                Err(e) => Response::error(req.id, ErrorCode::ProtocolViolation, e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    /// An over-cap **response** must be refused by name, not by hanging
    /// up.
    ///
    /// The write site folded [`FrameError::TooLarge`] in with EPIPE and
    /// returned: no frame, no log line, no `frame_too_large` — that arm
    /// existed only for an oversized *request*. The caller saw `Eof`,
    /// which the shim reports as `daemon_unreachable` about a daemon in
    /// perfect health.
    ///
    /// The second row is not decoration. Without it every assertion here
    /// is satisfied by a `write_response` that refuses **everything**,
    /// which would take the daemon down rather than one call.
    #[tokio::test]
    async fn an_oversized_response_is_refused_by_name_and_not_by_silence() {
        // Built here rather than provoked through a tool: the shipped
        // limits cannot reach 16 MiB, and the configurations that can —
        // `output_buffer_bytes`, `resource_read_max_bytes`, neither
        // bounded above — are exactly what this guard is for.
        let over = Response::ok(
            7,
            &method::CborValue::Bytes(vec![0u8; frame::MAX_FRAME_BYTES]),
            "a read that will not fit",
        )
        .expect("an oversized response still *builds*; it is the frame that refuses it");

        let mut sink: Vec<u8> = Vec::new();
        assert!(
            !write_response(&mut sink, 7, &over).await,
            "`frame_too_large` is one of §18.3's three closing codes"
        );

        // What the peer actually received. `read_frame` here rather than
        // an emptiness check: the refusal has to be a *well-formed*
        // frame, or the client desynchronises instead of being told.
        let resp: Response = frame::read_frame(&mut sink.as_slice())
            .await
            .expect("a diagnostic frame, not an empty stream");
        assert_eq!(
            resp.id, 7,
            "the refusal must correlate to the request that provoked it; \
             `id: 0` is the frame-layer form, and on a fresh connection it is \
             indistinguishable from a duplicate handshake reply"
        );
        let err = resp
            .control_error()
            .expect("a §7.4.1 error payload, not a truncated success");
        assert_eq!(
            err.code, "frame_too_large",
            "§18.3's name for this, spelled as a literal: the read side has \
             answered it since 0.0.5 and the write side answered nothing"
        );

        // And the ordinary response still goes out untouched.
        let ok = Response::ok(8, &method::CborValue::Text("hi".into()), "ok").unwrap();
        let mut sink: Vec<u8> = Vec::new();
        assert!(write_response(&mut sink, 8, &ok).await);
        let back: Response = frame::read_frame(&mut sink.as_slice()).await.unwrap();
        assert_eq!(back.id, 8);
        assert!(!back.is_error(), "{}", back.details);
    }

    /// Every field name an agent might reach for to relabel itself.
    fn forged_read_output(kind_it_wants_to_look_like: &str) -> Request {
        Request::new(
            1,
            "tool/read_output",
            &json!({
                "session": "sess_x",
                "since_cursor": 0,
                "redact": false,
                // None of these are read. If any ever were, the audit log
                // would be attacker-controlled where it matters most.
                "surface": "clasp_logs",
                "client_kind": kind_it_wants_to_look_like,
                "caller": kind_it_wants_to_look_like,
                "audit": { "client_kind": kind_it_wants_to_look_like },
            }),
        )
        .unwrap()
    }

    #[test]
    fn an_agent_cannot_influence_the_recorded_caller() {
        // The agent connects as `Shim` and asks to be recorded as a human
        // running `clasp logs --raw`. §9.4's whole value is that it
        // cannot: the answer comes from the authenticated connection.
        let req = forged_read_output("cli");
        assert_eq!(
            caller_for(ClientKind::Shim, &req),
            Caller::Agent,
            "the recorded caller must come from the connection, not the request"
        );
        // §9.4's spelling, carried from the handshake verbatim — not
        // `agent`, which would give one actor two names in one log.
        assert_eq!(caller::Caller::Agent.as_str(), "shim");
    }

    #[test]
    fn the_cli_cannot_dress_itself_up_as_an_agent_either() {
        // The guard is not agent-specific: it is that params are never
        // consulted, in either direction.
        let req = forged_read_output("shim");
        assert_eq!(caller_for(ClientKind::Cli, &req), Caller::Cli);
    }

    thread_local! {
        static OBSERVED: std::cell::Cell<Option<Caller>> =
            const { std::cell::Cell::new(None) };
    }

    /// Called by `dispatch_tool` from inside the caller scope.
    pub(super) fn record_observed_caller(c: Caller) {
        OBSERVED.with(|o| o.set(Some(c)));
    }

    /// Drive a real dispatch and report what the tool call saw.
    ///
    /// `#[tokio::test]` is current-thread, so the thread-local is the
    /// same one `dispatch_tool` writes.
    async fn observed_caller_for(kind: ClientKind) -> Option<Caller> {
        OBSERVED.with(|o| o.set(None));
        let dir = format!(
            "/tmp/holdfast-t-caller-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let paths = RuntimePaths::with_dir(&dir);
        paths.ensure_dir().unwrap();
        let daemon = Daemon::new(paths);
        let req = forged_read_output("cli");
        let (_resp, _stop) = dispatch(&daemon, &req, kind).await;
        let _ = std::fs::remove_dir_all(&dir);
        OBSERVED.with(|o| o.get())
    }

    #[tokio::test]
    async fn a_tool_call_runs_inside_the_connections_caller_scope() {
        // Guards the wiring, not just the derivation: without the
        // `with_caller` wrapper in `dispatch_tool` this reports
        // `InProcess` and every §9.4 entry would lose its subject.
        assert_eq!(
            observed_caller_for(ClientKind::Shim).await,
            Some(Caller::Agent)
        );
        assert_eq!(
            observed_caller_for(ClientKind::Cli).await,
            Some(Caller::Cli),
            "a CLI read must not be recorded as the agent's"
        );
    }

    #[test]
    fn every_client_kind_maps_through_the_connection() {
        let req = forged_read_output("cli");
        for (kind, expected) in [
            (ClientKind::Shim, Caller::Agent),
            (ClientKind::Cli, Caller::Cli),
            (ClientKind::UiBridge, Caller::UiBridge),
        ] {
            assert_eq!(caller_for(kind, &req), expected);
        }
    }

    #[test]
    fn the_uid_gate_admits_only_the_owner_and_fails_closed() {
        // All three arms of the one expression `handle_connection`
        // consults. The third is the one worth having a test for: an
        // `Err` that answered `true` — the shape `Err(_) => {}` takes in
        // the inline `match` this replaced — hands an unauthenticated
        // peer a full session surface, and no other test in the workspace
        // can see it.
        let us = peer::current_uid();
        let ours = peer::PeerCred {
            uid: us,
            gid: 0,
            pid: None,
        };
        let theirs = peer::PeerCred {
            uid: us.wrapping_add(1),
            gid: 0,
            pid: None,
        };
        assert!(peer_is_authorized(&Ok(ours), us));
        assert!(
            !peer_is_authorized(&Ok(theirs), us),
            "another user's connection must be refused"
        );
        assert!(
            !peer_is_authorized(&Err(io::Error::from(io::ErrorKind::PermissionDenied)), us),
            "an unreadable credential must fail closed, not open"
        );
    }

    /// A peer that connects and says nothing must be let go of.
    ///
    /// `serve` spawns an uncapped task per accepted connection and there
    /// was no deadline anywhere in `src/protocol/` or on this path, so a
    /// silent peer pinned a task and a file descriptor until the daemon
    /// died. The asymmetry that makes it worth fixing rather than
    /// accepting: `frame.rs` reasons about the analogous 16 MiB
    /// pre-allocation hazard **and writes down that it is accepted**,
    /// where this one was reasoned about nowhere in code, plan or spec.
    ///
    /// **The outer bound is a red test, not a hang.** Every failure here
    /// is something that does not return, and there is no `nextest.toml`
    /// in this repo to turn an unbounded wait into anything but a hung
    /// CI job — so the elapsed arm is `expect`ed and never matched as
    /// success.
    #[tokio::test]
    async fn a_peer_that_sends_no_handshake_is_let_go_of() {
        let (mut daemon_side, client_side) = UnixStream::pair().expect("socketpair");
        // `client_side` is held to the end on purpose. Dropping it would
        // EOF the daemon's read, `do_handshake` would return on its own,
        // and this row would be green against a daemon with no deadline
        // at all — which is exactly the state it exists to catch.
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            do_handshake_within(&mut daemon_side, Duration::from_millis(50)),
        )
        .await
        .expect(
            "a peer that connected and sent nothing held the connection open: \
             one task and one descriptor pinned until the daemon dies",
        );
        assert!(
            outcome.is_none(),
            "a peer that never handshaked must not be admitted"
        );
        drop(client_side);

        // The row above proves the mechanism at a deadline it was
        // handed; this pins the one `do_handshake` really passes. A
        // bound rather than an equality, so it is a claim about the
        // value — finite, and far below `wait_for_pattern`'s 30 s
        // default, which is the shortest call it must never be confused
        // with — instead of a second copy of the constant.
        assert!(handshake::HANDSHAKE_TIMEOUT >= Duration::from_secs(1));
        assert!(handshake::HANDSHAKE_TIMEOUT <= Duration::from_secs(10));
    }

    /// An MCP protocol fault keeps its JSON-RPC code across the socket.
    ///
    /// Three **distinct** codes, and that is the point of the row rather
    /// than thoroughness: over the wire only `invalid_params` is
    /// reachable from a real tool at this milestone, so a mapping that
    /// hardcoded `-32602` passed every end-to-end assertion in the tree
    /// while telling the agent that `openpty failed` was its own bad
    /// argument. `internal_error` is the code the ~dozen
    /// `HoldfastError::Pty | HoldfastError::Io` sites in `tools.rs` produce.
    #[test]
    fn a_tool_faults_json_rpc_code_survives_the_flattening_onto_bad_params() {
        for (built, expected) in [
            (rmcp::ErrorData::invalid_params("bad arg", None), -32602),
            (
                rmcp::ErrorData::internal_error("openpty failed", None),
                -32603,
            ),
            (
                rmcp::ErrorData::resource_not_found("no such uri", None),
                -32002,
            ),
        ] {
            let resp = tool_error_response(7, &built);
            let e = resp.control_error().expect("an error response");
            assert_eq!(resp.id, 7);
            // §18.3 is unchanged: a peer that knows only the catalogue
            // still reads a well-formed error.
            assert_eq!(e.code, ErrorCode::BadParams.as_str());
            assert!(!e.retriable);
            assert_eq!(
                e.rpc_code,
                Some(expected),
                "the tool's own code must reach the shim: {}",
                e.message
            );
            assert_eq!(e.message, built.message, "and so must its message");
        }
    }

    /// §7.4's "the caller must close the connection", including for a
    /// code this build cannot classify.
    ///
    /// The decision has to be recovered from the wire — `Response` is
    /// four serialised fields — and `ErrorCode::from_wire` answers
    /// `None` for anything outside §18.3, by design. The inline
    /// `if let Some(code)` this replaces **skipped** that `None` and
    /// left the connection open after a protocol violation, which is
    /// the one direction §7.4 does not permit. Nothing else in the
    /// workspace can see that arm: every response the dispatcher builds
    /// selects from `ErrorCode`, so the daemon round-trips its own
    /// strings and always resolves them.
    #[test]
    fn a_response_the_daemon_cannot_classify_closes_the_connection() {
        // The negatives first, or a function answering `true` to
        // everything would pass the closing cases and hang up on every
        // successful call.
        assert!(!response_closes_connection(
            &Response::ok(1, &json!({ "ok": true }), "ok").unwrap()
        ));
        for code in [
            ErrorCode::UnknownMethod,
            ErrorCode::BadParams,
            ErrorCode::LimitReached,
        ] {
            assert!(
                !response_closes_connection(&Response::error(1, code, "m")),
                "{} is a per-request fault and leaves the connection usable",
                code.as_str()
            );
        }
        // The closing rows, named rather than filtered through
        // `closes_connection()` — deriving the expectation from the
        // predicate under test would make this vacuous.
        //
        // `daemon_shutting_down` is one of them since I-1. This
        // dispatcher cannot reach it — the shutdown arm answers and
        // returns before `dispatch` runs — but the code's contract is
        // "the connection is over", and a daemon that ever emitted it
        // from a dispatch arm would have to hang up too.
        for code in [
            ErrorCode::FrameTooLarge,
            ErrorCode::NoHandshake,
            ErrorCode::ProtocolViolation,
            ErrorCode::DaemonShuttingDown,
        ] {
            assert!(
                response_closes_connection(&Response::error(1, code, "m")),
                "{} must be the last frame on this connection",
                code.as_str()
            );
        }
        // And the arm that had no coverage at all: a code outside
        // §18.3. Hand-built, because `Response::error` cannot produce
        // one.
        let payload = method::ControlError {
            code: "a_code_from_the_future".into(),
            message: "m".into(),
            retriable: false,
            rpc_code: None,
        };
        let unknown = Response {
            id: 1,
            status: "error".into(),
            data: method::to_cbor(&payload).unwrap(),
            details: "m".into(),
        };
        assert!(
            response_closes_connection(&unknown),
            "an unclassifiable error code must fail closed: staying open after a \
             protocol violation is the one outcome §7.4 forbids"
        );
    }

    /// The gate is *wired*, not merely correct.
    ///
    /// `the_uid_gate_admits_only_the_owner_and_fails_closed` proves the
    /// decision; on its own, deleting the call site leaves it green. This
    /// one drives a real `serve`/`handle_connection` over a real socket
    /// and asserts the connection dies before the handshake is answered.
    ///
    /// The trick that makes it possible: the test cannot become a second
    /// user, so it makes the *daemon* belong to one. `owner_uid` is
    /// state, so a daemon built for `current_uid() + 1` sees every
    /// ordinary local connection — including this test's — as foreign.
    #[tokio::test]
    async fn a_connection_from_a_foreign_uid_is_closed_before_the_handshake() {
        let dir = format!(
            "/tmp/holdfast-t-uidgate-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let paths = RuntimePaths::with_dir(&dir);
        let (listener, _) = bind_control(&paths).expect("bind control.sock");
        let daemon = Daemon::with_owner_uid(paths.clone(), peer::current_uid().wrapping_add(1));
        tokio::spawn(serve(Arc::clone(&daemon), listener));

        let mut stream = UnixStream::connect(paths.control_sock())
            .await
            .expect("connect");
        let req = Request::new(
            0,
            method::METHOD_HANDSHAKE,
            &HandshakeParams::current(ClientKind::Cli),
        )
        .unwrap();
        // The write may land or may race the close; either is fine, and
        // neither is the assertion.
        let _ = frame::write_frame(&mut stream, &req).await;

        // Bounded, because the failure this guards against is a daemon
        // that keeps the connection open — which as a bare `await` is a
        // hang rather than a red test.
        let answered = tokio::time::timeout(
            Duration::from_secs(5),
            frame::read_frame::<_, Response>(&mut stream),
        )
        .await;
        assert!(
            matches!(answered, Ok(Err(_))),
            "an unauthorized peer must be closed on without a reply; got {answered:?}"
        );
        // Without this the test would also pass against a daemon that
        // never ran: a socket nobody serves reads EOF too. The counter is
        // incremented in `serve` before the gate, so it proves the daemon
        // took this connection and then dropped it.
        assert_eq!(
            daemon.accepted_connections(),
            1,
            "the daemon must have accepted the connection before refusing it"
        );

        daemon.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------ §7.3's client-less exit (Task 16)

    fn scratch(tag: &str) -> RuntimePaths {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        RuntimePaths::with_dir(format!("/tmp/holdfast-d16-{tag}-{}", &unique[..8]))
    }

    struct Scratch(RuntimePaths);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.dir());
        }
    }

    /// The daemon must not serve without its §9.4 trail.
    ///
    /// `with_audit_path` leaves an unopenable log *disabled* and says so
    /// on stderr; that used to be the whole response, so a root-owned
    /// `audit.log` from one `sudo clasp` produced a
    /// daemon serving every client on the box while recording nothing,
    /// and reporting perfect health. REQ-CFG-003 already refuses startup
    /// for an invalid config knob; the trail was getting weaker
    /// treatment than a timeout.
    ///
    /// The obstruction is a **directory** at `audit.log`: it fails the
    /// same way for root, and it fails at the `open`, not at some
    /// earlier step that would make this a test of `ensure_dir`.
    ///
    /// **The pairing lives in
    /// `a_daemon_that_exits_removes_the_socket_and_pid_file_it_owns`**,
    /// which drives this same function to a serving daemon and a clean
    /// stop. A mutation that refused unconditionally passes everything
    /// below and goes red there, so it is not repeated here.
    ///
    /// Timeout on the call for this repo's usual reason: with no
    /// `nextest.toml`, a refusal that instead sat in `serve` would be a
    /// hung CI job rather than a red test.
    #[tokio::test]
    async fn the_daemon_refuses_to_serve_without_its_audit_trail() {
        let paths = scratch("auditclosed");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        std::fs::create_dir(paths.audit_log()).expect("the obstruction");

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            run_with_config(paths.clone(), Config::default()),
        )
        .await
        .expect("`run_with_config` never returned; it served instead of refusing")
        .expect_err("a daemon with no §9.4 trail must not serve");
        let text = err.to_string();
        assert!(
            text.contains("audit"),
            "the operator has to be told which of the startup checks refused: {text}"
        );

        // A refusal that leaves its socket bound is a daemon every later
        // `ensure_daemon` has to probe and clear, and a pid file naming
        // a process that has exited.
        assert!(
            !paths.control_sock().exists(),
            "the refusal left a bound socket behind"
        );
        assert!(
            !paths.pid_file().exists(),
            "the refusal left a pid file naming a process that is gone"
        );
    }

    fn configured(window: u64) -> Config {
        crate::config::parse_str(&format!("[daemon]\nidle_shutdown_after_secs = {window}\n"))
            .expect("loads")
    }

    fn mock_session(id: &str, clock: &Clock) -> Arc<crate::session::Session> {
        mock_session_idle(id, clock, 0)
    }

    fn mock_session_idle(
        id: &str,
        clock: &Clock,
        idle_timeout_secs: u64,
    ) -> Arc<crate::session::Session> {
        crate::session::Session::new(
            id.to_string(),
            None,
            "mock".into(),
            vec![],
            Arc::new(crate::pty::MockPty::new()),
            crate::session::SessionConfig {
                idle_timeout_secs,
                clock: clock.clone(),
                ..crate::session::SessionConfig::default()
            },
        )
    }

    /// Yield until `cond` holds, and give up rather than park.
    ///
    /// The loops below are woken by a hand, not by wall time, so there
    /// is nothing to sleep on — but a loop that never acts must be a
    /// **red** test rather than a hung one, and there is no
    /// `nextest.toml` in this repo to make that distinction for us.
    async fn yield_until(mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..500 {
            if cond() {
                return true;
            }
            tokio::task::yield_now().await;
        }
        cond()
    }

    fn backdate(path: &std::path::Path, by: Duration) {
        let f = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open for set_times");
        f.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now() - by))
            .expect("set mtime");
    }

    #[test]
    fn a_client_less_daemon_exits_after_the_configured_window() {
        let paths = scratch("clientless");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths, configured(86_400), clock.clone());

        assert!(!daemon.client_less_exit_due(), "not yet");
        clock.advance(Duration::from_secs(86_401));
        assert!(
            daemon.client_less_exit_due(),
            "REQ-D-006's second half was configured, documented and never armed"
        );
    }

    #[test]
    fn a_daemon_that_has_seen_a_client_does_not_exit_on_the_window() {
        // The pairing: a timer measured from process start kills a daemon
        // in continuous use and passes the row above perfectly.
        let paths = scratch("seen");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths, configured(86_400), clock.clone());

        clock.advance(Duration::from_secs(3600));
        daemon.note_client_connect();
        clock.advance(Duration::from_secs(82_801)); // 86 401 s from boot
        assert!(
            !daemon.client_less_exit_due(),
            "the window runs from the last connection, not from boot"
        );
        clock.advance(Duration::from_secs(3600));
        assert!(daemon.client_less_exit_due(), "and it still expires");
    }

    #[test]
    fn a_client_less_daemon_does_not_exit_while_a_session_is_live() {
        // **§7.3's `and`, and the arm that matters.** The client-less half
        // alone passes against an implementation that ignores sessions
        // entirely — and that implementation kills the long build nobody
        // is attached to, which is the case this feature exists for.
        let paths = scratch("livesession");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths, configured(86_400), clock.clone());

        let live = mock_session("sess_build", &clock);
        daemon.server.registry.insert(Arc::clone(&live)).unwrap();

        clock.advance(Duration::from_secs(86_401));
        assert!(
            !daemon.client_less_exit_due(),
            "a `sleep 86400` nobody attached to was about to be killed by \
             the idle-shutdown timer"
        );
        assert!(live.is_alive());

        // The pairing inside the pairing: once it exits, the window bites.
        live.signal(crate::pty::Signal::Kill).unwrap();
        assert!(
            daemon.client_less_exit_due(),
            "with every session exited and no client, the window applies"
        );
    }

    #[test]
    fn idle_shutdown_after_secs_zero_disables_the_client_less_exit() {
        let paths = scratch("zerowindow");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        // The config must **load**, which is the half Task 15's non-zero
        // rule would otherwise have taken.
        let config = configured(0);
        assert_eq!(config.daemon.idle_shutdown_after_secs, 0);
        let daemon = Daemon::with_config_and_clock(paths, config, clock.clone());

        clock.advance(Duration::from_secs(7 * 86_400));
        assert!(
            !daemon.client_less_exit_due(),
            "`0` was treated as \"exit immediately\", which is what a naive \
             `now - last >= 0` does and which kills every daemon at its \
             first scan"
        );
    }

    // ------------------------------------- daemon/stop escalation (Task 16)

    #[test]
    fn stop_defaults_its_grace_to_ten_seconds_not_the_reapers_five() {
        // Read off the resolved value rather than by timing the call: both
        // rows below drive an explicit value or a trapping child, and
        // neither observes the default. The reaper's 5 s is the number
        // that leaked into this default in an earlier revision.
        assert_eq!(StopParams::default().grace(), Duration::from_secs(10));
        assert_eq!(DEFAULT_STOP_GRACE_SECS, 10);
        assert_ne!(
            StopParams::default().grace(),
            crate::session::reaper::REAP_GRACE,
            "daemon/stop took the idle reaper's grace"
        );
        // And a caller's value wins, or the default is the only value.
        assert_eq!(
            StopParams {
                force: None,
                timeout_secs: Some(3)
            }
            .grace(),
            Duration::from_secs(3)
        );
        assert!(
            !StopParams::default().is_forced(),
            "§7.4.1: force defaults to false"
        );
    }

    #[tokio::test]
    async fn stop_without_force_sends_sigterm_first() {
        let paths = scratch("gracefulstop");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let daemon = Daemon::new(paths);

        let mock = Arc::new(crate::pty::MockPty::new());
        let s = crate::session::Session::new(
            "sess_graceful".into(),
            None,
            "mock".into(),
            vec![],
            Arc::clone(&mock) as Arc<dyn crate::pty::PtyBackend>,
            crate::session::SessionConfig::default(),
        );
        daemon.server.registry.insert(Arc::clone(&s)).unwrap();

        let terminated = daemon.shutdown_graceful(Duration::from_secs(10)).await;
        assert_eq!(terminated, 1);
        assert_eq!(
            mock.signals().first(),
            Some(&crate::pty::Signal::Terminate),
            "`force: false` must SIGTERM first; `force` still ignored is the \
             state this replaces"
        );
        assert!(!s.is_alive());
    }

    #[tokio::test]
    async fn stop_with_force_does_not_wait_for_the_grace_period() {
        // The pairing: escalating unconditionally makes `force` cosmetic,
        // and waiting unconditionally makes a forced stop cost the grace.
        let paths = scratch("forcedstop");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let daemon = Daemon::new(paths);

        let mock = Arc::new(crate::pty::MockPty::ignoring_terminate());
        let s = crate::session::Session::new(
            "sess_forced".into(),
            None,
            "mock".into(),
            vec![],
            Arc::clone(&mock) as Arc<dyn crate::pty::PtyBackend>,
            crate::session::SessionConfig::default(),
        );
        daemon.server.registry.insert(Arc::clone(&s)).unwrap();

        let started = Instant::now();
        let terminated = daemon.shutdown();
        assert_eq!(terminated, 1);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a forced stop waited out a grace it was told to skip"
        );
        assert_eq!(mock.signals(), vec![crate::pty::Signal::Kill]);
        assert!(!s.is_alive());
    }

    /// **A hang, not a red.** `shutdown_graceful` polled
    /// `Clock::sleep_until` on whatever clock the daemon holds, and on a
    /// hand that parks until someone calls `advance` — which, here,
    /// only the caller blocked in this `await` could do. It is reachable
    /// over the wire from `dispatch`'s `METHOD_DAEMON_STOP` arm, so
    /// `daemon/stop { force: false }` against a manual-clock daemon with
    /// one live session wedged `handle_connection`, the client's `call`
    /// and the suite. With no `nextest.toml` in this repo that is a hung
    /// CI job.
    ///
    /// The timeout **is** the evidence here, deliberately, because the
    /// defect being killed is a hang: elapsing means `shutdown_graceful`
    /// never returned. The signal assertion is what stops the fix being
    /// "just call `shutdown()`" — the SIGTERM-then-SIGKILL ordering a
    /// graceful stop promises has to survive the skipped poll.
    #[tokio::test]
    async fn a_graceful_stop_on_a_manual_clock_returns_instead_of_parking() {
        let paths = scratch("manualstop");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths, Config::default(), clock.clone());

        let mock = Arc::new(crate::pty::MockPty::ignoring_terminate());
        let s = crate::session::Session::new(
            "sess_manualstop".into(),
            None,
            "mock".into(),
            vec![],
            Arc::clone(&mock) as Arc<dyn crate::pty::PtyBackend>,
            crate::session::SessionConfig {
                clock: clock.clone(),
                ..crate::session::SessionConfig::default()
            },
        );
        daemon.server.registry.insert(Arc::clone(&s)).unwrap();

        let terminated = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.shutdown_graceful(Duration::from_secs(10)),
        )
        .await
        .expect("shutdown_graceful parked on a hand that nothing was moving");

        assert_eq!(terminated, 1);
        assert_eq!(
            mock.signals(),
            vec![crate::pty::Signal::Terminate, crate::pty::Signal::Kill],
            "skipping the poll must not skip the SIGTERM: a graceful stop that \
             goes straight to SIGKILL is `force: true` under another name"
        );
        assert!(!s.is_alive());
    }

    /// §7.2's bind is not atomic, and without a lock it unlinks a
    /// **live** daemon's socket.
    ///
    /// `bind_control` probes, removes and binds, and `server.rs` held no
    /// lock of any kind. Two `clasp daemon run` processes — or one
    /// started while another's `start_detached` had timed out at 2 s
    /// with its child still binding — can both read "dead", after which
    /// the second's `remove_file` takes out the first's just-bound
    /// socket. The first goes on serving live PTY sessions on an
    /// unlinked inode that no client can reach again.
    ///
    /// Driven by holding the lock from outside rather than by racing two
    /// threads: a race test that passes whenever the bad interleaving
    /// happens not to occur is not a test. The `!exists` assertion is
    /// what says the refusal landed *before* the window rather than
    /// inside it.
    // `tokio::net::UnixListener::bind` needs a reactor, so the
    // succeeding half below has to run inside one.
    #[tokio::test]
    async fn binding_the_control_socket_takes_the_bind_lock() {
        let paths = scratch("bindlock");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        let held = super::super::spawn::DaemonLock::acquire_bind(&paths)
            .expect("take the bind lock as the other daemon would");
        let refused = bind_control_within(&paths, Duration::from_millis(150))
            .expect_err("a second daemon entered the stale-socket window while the first held it");
        assert!(
            refused.raw_os_error().is_some(),
            "expected the contended flock's errno, got {refused:?}"
        );
        assert!(
            !paths.control_sock().exists(),
            "the refusal must land before the probe-and-unlink, not inside it"
        );

        // The pairing: a `bind_control` that answered `Err` for some
        // unrelated reason would satisfy the row above and never bind at
        // all. Once the holder is gone the same call must succeed.
        drop(held);
        let (listener, _) =
            bind_control(&paths).expect("the lock is free once the holder drops it");
        assert!(paths.control_sock().exists());
        drop(listener);
    }

    /// A **dangling** symlink at `control.sock` must not wedge the daemon
    /// permanently.
    ///
    /// The stale-socket sweep above was gated on `Path::exists()`, which
    /// is `fs::metadata` and follows the final symlink — so a link to a
    /// path that does not exist answered `false` and the sweep was
    /// skipped. `UnixListener::bind` does *not* follow that component: it
    /// found the link, got `EEXIST`, and the kernel reported
    /// `EADDRINUSE`. The operator was told "address in use" by a daemon
    /// that had nothing to stop, every later start failed the same way,
    /// and no path in the tree cleared it — `remove_runtime_files_we_own`
    /// is reached only by a daemon that got past `bind_control`. A guard
    /// that cannot reach its own sharp case.
    ///
    /// The premise rows are what make this more than "bind works": they
    /// pin that `exists()` really does answer `false` here, so a
    /// regression to it goes red rather than passing by accident.
    #[tokio::test]
    async fn a_dangling_symlink_at_the_control_socket_does_not_wedge_the_daemon() {
        use std::os::unix::fs::FileTypeExt;

        let paths = scratch("danglinglink");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        std::os::unix::fs::symlink(paths.dir().join("no-such-target"), paths.control_sock())
            .expect("plant the dangling link");
        assert!(
            !paths.control_sock().exists(),
            "the premise: `exists()` follows the link and answers false for a \
             dangling one, which is what skipped the sweep"
        );
        assert!(
            std::fs::symlink_metadata(paths.control_sock()).is_ok(),
            "the premise: the link itself is very much there, which is what \
             `bind` trips over"
        );

        let (listener, _) = bind_control(&paths)
            .expect("a dangling link must be cleared, not reported as `address in use` forever");
        assert!(
            std::fs::symlink_metadata(paths.control_sock())
                .expect("the socket")
                .file_type()
                .is_socket(),
            "the path must name this daemon's socket now, not the link"
        );
        drop(listener);
    }

    /// The sweep removes the **link**, never what the link points at.
    ///
    /// This is the property that makes widening the branch above safe,
    /// and it is the one that would be catastrophic to get wrong: the
    /// runtime directory is `0700`, so only the owner can plant a link
    /// there, but the owner is also who would lose the file. `remove_file`
    /// is `unlink(2)` and never follows a symlink — asserted here rather
    /// than assumed, because the widening is what starts routing
    /// *dangling* links into it and a future "tidy this up" that reached
    /// for `fs::canonicalize` or `metadata` first would be silent.
    ///
    /// A characterization row, honestly: a link with an existing target
    /// was already `exists() == true`, so this passed before the change
    /// too. It is the invariant, not the regression.
    #[tokio::test]
    async fn the_stale_socket_sweep_unlinks_the_symlink_and_not_its_target() {
        let paths = scratch("linktarget");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        let precious = paths.dir().join("id_rsa");
        std::fs::write(&precious, b"not a socket\n").expect("the link target");
        std::os::unix::fs::symlink(&precious, paths.control_sock()).expect("plant the link");

        let (listener, _) = bind_control(&paths).expect("bind over the link");

        assert_eq!(
            std::fs::read(&precious).expect("the target must still be there"),
            b"not a socket\n",
            "the sweep followed the link and unlinked its target instead"
        );
        drop(listener);
    }

    /// `holdfast.pid` is created owner-only, like every other file the
    /// daemon creates, rather than at the ambient umask.
    ///
    /// The mode is asserted against [`PID_FILE_MODE`] deliberately *not*
    /// by name: reading the same constant on both sides of the contract
    /// would leave the row green for any value, including `0o666`.
    #[test]
    fn the_pid_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let paths = scratch("pidmode");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        write_pid_file(&paths).expect("write holdfast.pid");

        let mode = std::fs::metadata(paths.pid_file())
            .expect("holdfast.pid")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "holdfast.pid was created at the ambient umask; every sibling in the \
             runtime directory is explicit about this"
        );
    }

    /// A rewrite truncates.
    ///
    /// `std::fs::write` truncated for free and `OpenOptions` does not, so
    /// this is the row that goes red if `.truncate(true)` is ever
    /// dropped. It cannot be `read_pid_file`, which takes
    /// `split_whitespace().next()` and would parse the new pid off the
    /// front of a torn line and report success — the defect would stay
    /// invisible until something read the version field.
    #[test]
    fn rewriting_the_pid_file_leaves_no_tail_of_the_previous_one() {
        let paths = scratch("pidtrunc");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        std::fs::write(paths.pid_file(), "4294967295 99.99.99-a-much-longer-line\n").unwrap();
        write_pid_file(&paths).expect("rewrite holdfast.pid");

        let text = std::fs::read_to_string(paths.pid_file()).expect("holdfast.pid");
        assert_eq!(
            text,
            format!("{} {}\n", std::process::id(), env!("CARGO_PKG_VERSION")),
            "the rewrite left the tail of the longer line behind"
        );
    }

    /// `daemon/status`'s uptime runs on the daemon's clock, like every
    /// other duration it reports.
    ///
    /// `started_at` is stamped from `clock.now()` under a comment saying
    /// it must be, because comparing a hand-driven `now` against a
    /// wall-clock origin measures the gap between two clocks. Reading it
    /// back with `Instant::elapsed()` reintroduced exactly that: under a
    /// manual clock the origin sits in the future, `duration_since`
    /// saturates, and a daemon that has been up for an hour reports zero.
    ///
    /// Identical under `Clock::system()`, so this is a test of the seam
    /// rather than of shipped behaviour — which is the point, since 0.0.6
    /// drives this daemon's timers from outside.
    #[test]
    fn the_reported_uptime_moves_with_the_daemons_own_clock() {
        let paths = scratch("uptimeclock");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths, Config::default(), clock.clone());

        assert_eq!(daemon.status().uptime_secs, 0, "the hand has not moved yet");

        clock.advance(Duration::from_secs(3600));

        assert_eq!(
            daemon.status().uptime_secs,
            3600,
            "the uptime read the wall clock while `started_at` was stamped from \
             the daemon's, so it saturated to zero"
        );
    }

    // ------------------------------------ the exit cleanup (§7.3, Imp C-5)

    /// §7.3's *"On exit: … removes sockets, removes PID file"*, driven
    /// through the daemon's own run-to-completion path.
    ///
    /// **This is the row that stops the C-5 fix being "delete the
    /// cleanup".** Its pair below asserts that a *successor's* files
    /// survive the teardown, and that assertion is satisfied perfectly by
    /// a teardown that removes nothing at all — which would leave every
    /// `clasp daemon stop` behind a stale socket and a pid file naming a
    /// dead process, i.e. the state `confirm_daemon_pid` exists to
    /// survive. It also pins the *wiring*: `run_with_config` is what
    /// production runs, so deleting the call from it goes red here rather
    /// than leaving a helper that nothing invokes.
    ///
    /// Timeouts throughout: every failure mode on this path is a daemon
    /// that does not stop, and with no `nextest.toml` in this repo a bare
    /// `await` on one is a hung CI job rather than a red test.
    #[tokio::test]
    async fn a_daemon_that_exits_removes_the_socket_and_pid_file_it_owns() {
        let paths = scratch("exitcleanup");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        let running = tokio::spawn(run_with_config(paths.clone(), Config::default()));
        assert!(
            yield_until(|| super::super::spawn::socket_is_live(&paths)).await,
            "the daemon never bound its control socket"
        );
        assert_eq!(
            read_pid_file(&paths),
            Some(std::process::id()),
            "the premise: this daemon wrote its own pid file, or the ownership \
             check below is deciding about a file that was never ours"
        );

        let client =
            crate::protocol::client::ControlClient::connect(&paths.control_sock(), ClientKind::Cli)
                .await
                .expect("connect to the daemon under test");
        let stopped: StopOutcome = tokio::time::timeout(
            Duration::from_secs(5),
            client.call(method::METHOD_DAEMON_STOP, &StopParams::default()),
        )
        .await
        .expect("daemon/stop never answered")
        .expect("daemon/stop failed");
        assert_eq!(stopped.sessions_terminated, 0);

        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the daemon never returned from `run` after daemon/stop")
            .expect("the daemon task panicked")
            .expect("`run` returned an error");

        assert!(
            !paths.control_sock().exists(),
            "§7.3: a daemon that exits removes its socket. Left behind, it is \
             the stale file every subsequent binder has to probe and clear"
        );
        assert!(
            !paths.pid_file().exists(),
            "§7.3: a daemon that exits removes its PID file. Left behind, it \
             names a dead pid the kernel is free to hand to anything"
        );
    }

    /// Imp C-5: the exit cleanup must not destroy a **successor's**
    /// socket and pid file.
    ///
    /// The sequence, all steps ordinary: daemon A's listener drops, so
    /// `socket_is_live` goes false; a shim auto-spawns daemon B, which
    /// takes `bind.lock`, clears the stale socket, binds a fresh one and
    /// writes its own pid file; and only then does A — whose
    /// `shutdown()` was still walking the registry SIGKILLing sessions —
    /// reach its unlinks. Unlocked and unconditional, they take out B's
    /// socket, leaving B serving live PTY sessions on an unlinked inode
    /// no `connect(2)` can reach, and they take out B's pid file, leaving
    /// `daemon stop --force` with nothing to escalate to.
    ///
    /// Staged rather than raced: a race test that passes whenever the bad
    /// interleaving happens not to occur is not a test. B's side of the
    /// window is simply already finished when A's teardown runs, which is
    /// exactly the interleaving the report describes.
    ///
    /// **A binds for real here**, rather than the teardown being called
    /// with no predecessor at all. Its identity is the thing under test:
    /// A must decline to unlink because the file at the path is no longer
    /// the file A created, and the only way to say that is to have A
    /// create one.
    #[tokio::test]
    async fn the_exit_cleanup_leaves_a_successor_daemons_socket_and_pid_file_alone() {
        let paths = scratch("exitsuccessor");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        // Daemon A: binds, learns which file is its own, and its listener
        // drops as `serve` returns. §7.3's exit has begun and its unlinks
        // have not run yet.
        let (a_listener, a_socket) = bind_control(&paths).expect("A binds its control socket");
        drop(a_listener);

        // Daemon B, through the real binder: lock, probe, unlink, bind,
        // chmod. Then its pid file, naming a process that is not us.
        let (b_listener, b_socket) =
            bind_control(&paths).expect("the successor binds its control socket");
        let b_pid = std::process::id().wrapping_add(1);
        std::fs::write(paths.pid_file(), format!("{b_pid} 9.9.9\n")).unwrap();

        // The premises. Without them the assertions below are about a
        // socket nobody was serving and a file nobody had claimed.
        assert!(
            super::super::spawn::socket_is_live(&paths),
            "the premise: B is listening before A tears down"
        );
        assert_eq!(read_pid_file(&paths), Some(b_pid));
        assert_ne!(b_pid, std::process::id());
        // The premise the identity comparison rests on, asserted rather
        // than assumed: B's bind produced a *different* file. Without
        // A's pin this row is not safe to assume at all — on ext4 the
        // successor is handed A's freed inode number 500 times out of
        // 500, measured — so this is where a pin that stopped working
        // would surface, on any filesystem that recycles.
        assert_ne!(
            a_socket.id, b_socket.id,
            "B rebound the same identity A had: the comparison below cannot \
             tell the two daemons' sockets apart"
        );

        // Daemon A's teardown, arriving late.
        remove_runtime_files_we_own(&paths, &a_socket);

        assert!(
            super::super::spawn::socket_is_live(&paths),
            "A unlinked B's just-bound socket: B goes on serving live PTY \
             sessions on an inode no `connect(2)` can reach again, and never \
             learns"
        );
        assert_eq!(
            read_pid_file(&paths),
            Some(b_pid),
            "A deleted B's pid file: `daemon stop --force` now reads no pid, \
             escalates to nothing, and an unreachable daemon keeps its sessions"
        );

        drop(b_listener);
    }

    /// The teardown must remove **its own** socket even while another
    /// descriptor keeps that socket answering.
    ///
    /// This is the row the parallel suite was failing on, made
    /// deterministic. `!socket_is_live` asked whether *anyone* holds a
    /// descriptor on `control.sock`, and an AF_UNIX listener answers
    /// `connect(2)` for as long as any process references it — so a
    /// child forked between `fork` and `exec` (mio sets `SOCK_CLOEXEC`,
    /// so that is the whole window) inherits the daemon's listener and
    /// makes the probe report a live daemon where none is serving. §7.3's
    /// unlink was then skipped and
    /// `the_daemon_refuses_to_serve_without_its_audit_trail` and
    /// `a_daemon_that_exits_removes_the_socket_and_pid_file_it_owns` went
    /// red — in about half of all default-parallelism `--workspace` runs
    /// on a 48-core box, and never at `--test-threads=1`.
    ///
    /// **A second descriptor in this process, not a fork.** The condition
    /// the bug needs is "a descriptor other than the owner's listener
    /// still references the socket"; `try_clone_to_owned` produces
    /// exactly that, with no dependence on scheduling, on load, or on
    /// forking from a multi-threaded test binary. The `socket_is_live`
    /// premise below is what proves the reproduction is faithful: it is
    /// the predicate the old code consulted, and it says `true`.
    ///
    /// Not a `#[tokio::test]` in name only — `UnixListener::bind` needs a
    /// reactor.
    #[tokio::test]
    async fn the_exit_cleanup_removes_its_own_socket_while_a_stray_descriptor_holds_it_open() {
        use std::os::fd::AsFd;

        let paths = scratch("straydescriptor");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        let (listener, our_socket) = bind_control(&paths).expect("bind control.sock");
        // The inherited copy. Taken before the listener drops, because
        // that is the order a `fork` gets it in.
        let stray = listener
            .as_fd()
            .try_clone_to_owned()
            .expect("a second descriptor on the listening socket");
        drop(listener);

        assert!(
            super::super::spawn::socket_is_live(&paths),
            "the premise: with the owner's listener closed and only a stray \
             descriptor left, the socket still answers `connect` — this is the \
             state the old `!socket_is_live` guard read as `a daemon is serving`"
        );

        remove_runtime_files_we_own(&paths, &our_socket);

        assert!(
            !paths.control_sock().exists(),
            "§7.3's unlink was skipped because an unrelated descriptor answered \
             for the socket: the file this daemon created and closed outlives it, \
             and every later binder has to probe and clear it"
        );

        drop(stray);
    }

    /// The pin is a **live reference to the inode**, not a no-op.
    ///
    /// `pin_inode` swallows its error by design — a daemon must not
    /// refuse to start because a defensive descriptor could not be
    /// opened — so a `pin_inode` that returned `None` every time would
    /// leave every other row in this file green while quietly restoring
    /// the inode-reuse hazard. This is the row that will not have it.
    ///
    /// It asserts the mechanism rather than the consequence, and that is
    /// deliberate: the consequence — "a successor cannot be handed this
    /// number" — is only observable on a filesystem that recycles inode
    /// numbers, and the scratch directory is `/tmp`, which is tmpfs on
    /// many machines and ext4 on the usual CI images. A row that could
    /// only pass vacuously half the time is worth less than one that
    /// checks, everywhere, that the thing preventing the recycling is
    /// actually held: `nlink == 0` says the last name is gone, and the
    /// descriptor still answering `fstat` with the same inode number says
    /// the inode is still ours and still out of the allocator's reach.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_bound_socket_holds_its_inode_open_after_the_path_is_gone() {
        use std::os::unix::fs::MetadataExt;

        let paths = scratch("inodepin");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();

        let (listener, ours) = bind_control(&paths).expect("bind control.sock");
        drop(listener);
        std::fs::remove_file(paths.control_sock()).expect("unlink the socket path");

        let pin = ours.pin.as_ref().expect(
            "`pin_inode` returned nothing: the identity comparison is back to \
             trusting an inode number the allocator may reissue",
        );
        let meta = pin.metadata().expect("fstat through the pin");
        assert_eq!(
            meta.nlink(),
            0,
            "the premise: the path is gone, so the pin is the only thing \
             keeping this inode from being freed"
        );
        assert_eq!(
            meta.ino(),
            ours.id.ino,
            "the pin is open on some other inode than the one recorded"
        );
    }

    #[tokio::test]
    async fn a_graceful_stop_escalates_a_child_that_ignores_sigterm() {
        // A trapping child is the case §4.4 names, and without the
        // escalation a graceful stop leaves it running forever.
        let paths = scratch("trapstop");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let daemon = Daemon::new(paths);

        let mock = Arc::new(crate::pty::MockPty::ignoring_terminate());
        let s = crate::session::Session::new(
            "sess_trapstop".into(),
            None,
            "mock".into(),
            vec![],
            Arc::clone(&mock) as Arc<dyn crate::pty::PtyBackend>,
            crate::session::SessionConfig::default(),
        );
        daemon.server.registry.insert(Arc::clone(&s)).unwrap();

        // A short explicit grace, so this row costs milliseconds rather
        // than the ten seconds the default would.
        let terminated = daemon.shutdown_graceful(Duration::from_millis(120)).await;
        assert_eq!(terminated, 1);
        assert_eq!(
            mock.signals(),
            vec![crate::pty::Signal::Terminate, crate::pty::Signal::Kill],
            "SIGTERM alone leaves a trapping child running forever"
        );
        assert!(!s.is_alive());
    }

    /// The daemon's clock has to reach the server, or
    /// `Daemon::with_clock` moves a hand that nothing downstream reads.
    ///
    /// This is the middle link of a three-part chain, and it was the
    /// broken one. `Clock::now_ms` keeps the reaper's comparison inside
    /// one clock; `mcp::tools`'s
    /// `a_session_is_stamped_from_the_servers_clock_and_not_from_wall_time`
    /// proves the server stamps every session it creates from its own;
    /// and this proves the daemon gives the server the hand it is itself
    /// reading. Revert `build` to `with_audit_path_and_config` and the
    /// server silently falls back to `Clock::system()`.
    #[test]
    fn the_daemons_clock_reaches_the_server_that_creates_its_sessions() {
        let paths = scratch("clockseam");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths, Config::default(), clock.clone());

        clock.advance(Duration::from_secs(3600));
        assert_eq!(
            daemon.server.clock.now_ms(),
            clock.now_ms(),
            "the server reads wall time while the daemon's hand is an hour \
             ahead, so every session it creates carries a deadline the reaper \
             evaluates against a different clock"
        );
        // The separator. Two `Clock::system()`s agree to the millisecond
        // as readily as one shared hand does, so the row above proves
        // nothing on its own — this is what says the clock under test
        // really has been displaced from wall time.
        assert!(
            daemon.server.clock.now_ms() - Clock::system().now_ms() > 3_000_000,
            "the clock being compared is not a hand at all"
        );
    }

    // ------------------------------- the periodic tick, actuated (Task 16)
    //
    // Everything above this line asserts a **predicate**. `reaper_loop`
    // was private and spawned from `run` alone, which no test in the
    // workspace calls, so deleting the spawn — or any single statement
    // inside the loop — left the entire workspace green while disabling
    // the idle reaper (§16.7), REQ-R-006's exit half, §7.3's client-less
    // exit and §19.1's retention sweep in production. These four rows
    // are the actuation.

    /// The spawn site itself, over a real socket.
    ///
    /// This is the row that goes red when `tokio::spawn(reaper_loop(…))`
    /// is deleted from [`serve_daemon`]: with no tick running, nothing
    /// ever evaluates §7.3's conjunction, the accept loop is never told
    /// to stop, and the `timeout` elapses. Every other §7.3 test asserts
    /// `client_less_exit_due()` and would stay green.
    ///
    /// The timeout is the evidence, because the failure mode is a daemon
    /// that runs forever.
    #[tokio::test]
    async fn the_daemon_starts_its_periodic_tick_and_the_client_less_window_stops_it() {
        let paths = scratch("tickexit");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let (listener, _) = bind_control(&paths).expect("bind control.sock");
        let daemon = Daemon::with_config_and_clock(paths, configured(3600), clock.clone());

        let served = tokio::spawn(serve_daemon(Arc::clone(&daemon), listener));
        // Let the tick reach its first park before the hand moves.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !served.is_finished(),
            "the daemon stopped before its window had expired"
        );

        clock.advance(Duration::from_secs(3601));
        tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the accept loop never stopped: nothing acted on §7.3's window")
            .expect("the serve task panicked");
        assert!(
            *daemon.shutdown_signalled().borrow(),
            "the accept loop returned without shutdown having been signalled"
        );
    }

    /// §7.3's exit must not fire underneath a client that is mid-connect.
    ///
    /// `last_client_connect` is stamped after the uid gate *and* after an
    /// accepted handshake — deliberately, so a refused peer cannot hold
    /// the daemon open — which leaves a connection that has been accepted
    /// and is still handshaking invisible to the conjunction. The
    /// probability argument runs the opposite way from the usual one:
    /// the exit only arms after 24 h of silence, so the connection that
    /// races it is the one *ending* the silence, which is the only
    /// connection that can.
    ///
    /// The client-side consequence is what makes it more than a lost
    /// connection: the EOF surfaces as `FrameError::Eof` and **not**
    /// `ClientError::Connect`, and `spawn::ensure_daemon` starts a
    /// replacement only for `Connect` — so `clasp mcp` reports
    /// `daemon_unreachable` against a daemon that was alive moments
    /// earlier, and starts nothing.
    ///
    /// The pairing at the bottom is what stops this passing against a
    /// daemon that never exits at all.
    #[tokio::test]
    async fn a_connection_mid_handshake_holds_off_the_client_less_exit() {
        let paths = scratch("inflight");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let (listener, _) = bind_control(&paths).expect("bind control.sock");
        let daemon = Daemon::with_config_and_clock(paths.clone(), configured(3600), clock.clone());
        let mut served = tokio::spawn(serve_daemon(Arc::clone(&daemon), listener));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        // A peer that has connected and not yet said anything. Held in
        // scope: dropping it here would end the connection and the row
        // would be green against a daemon that counts nothing.
        let peer = UnixStream::connect(paths.control_sock())
            .await
            .expect("connect to the daemon");
        assert!(
            yield_until(|| daemon.accepted_connections() == 1).await,
            "the accept loop never saw the connection, so the premise is untested"
        );
        assert_eq!(daemon.in_flight_connections(), 1);
        // The state the timestamp cannot see, named explicitly: without
        // this the row would also pass against a daemon that stamped
        // `last_client_connect` at accept, which is a different fix with
        // a different cost (a refused peer would hold the daemon open).
        assert!(
            daemon.last_client_connect().is_none(),
            "the handshake has not run, so nothing may have been stamped yet"
        );

        clock.advance(Duration::from_secs(3601));
        assert!(
            !daemon.client_less_exit_due(),
            "the connection ending 24 h of silence was invisible to §7.3's conjunction"
        );
        // And the actuation, not just the predicate: the tick has had the
        // hand moved past the window and must not have acted on it.
        assert!(
            tokio::time::timeout(Duration::from_millis(250), &mut served)
                .await
                .is_err(),
            "the daemon exited underneath a client that was still handshaking"
        );

        // **The pairing.** The connection is the only thing holding this
        // daemon open; with it gone the very next tick takes the exit.
        // Without this the row would be satisfied by a counter that is
        // never decremented — which would disable §7.3 outright.
        drop(peer);
        assert!(
            yield_until(|| daemon.in_flight_connections() == 0).await,
            "the count was never given back, so the exit is now disabled for good"
        );
        clock.advance(Duration::from_secs(3601));
        tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("with no connection and no session, §7.3's window must bite")
            .expect("the serve task panicked");
    }

    /// The idle reaper and REQ-R-006's exit half, both on the one tick.
    ///
    /// The two statements fail this row **distinguishably**, which is
    /// why the liveness assertion comes first: deleting
    /// `reaper.scan_once()` leaves the session alive and trips
    /// `yield_until`, while deleting the in-loop
    /// `poll_resource_list_changed()` leaves the session correctly
    /// reaped and times the `recv` out instead. Ordered the other way
    /// round, both mutations would land on the same assertion and the
    /// message would name the wrong cause for one of them.
    #[tokio::test]
    async fn the_periodic_tick_reaps_an_idle_session_and_announces_its_exit() {
        let paths = scratch("tickreap");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        // `0` disables §7.3's exit, so the loop stays up long enough to
        // be observed rather than shutting down on the same tick.
        let daemon = Daemon::with_config_and_clock(paths, configured(0), clock.clone());

        let s = mock_session_idle("sess_tickreap", &clock, 60);
        daemon.server.registry.insert(Arc::clone(&s)).unwrap();
        let mut events = daemon.server.resource_list_changed.subscribe();

        tokio::spawn(reaper_loop(Arc::clone(&daemon)));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        // The loop seeds its known set on entry, and seeding a registry
        // that already holds a session announces it. Drained here so the
        // assertion below is about the **exit** edge and cannot be
        // satisfied by that first pulse.
        while events.try_recv().is_ok() {}

        clock.advance(Duration::from_secs(61));
        assert!(
            yield_until(|| !s.is_alive()).await,
            "the tick never swept: an idle session outlived its timeout"
        );
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("the session exited and no list_changed pulse announced it")
            .expect("the resource-event channel closed");
        // §5.5.1's ruling survives the loop as well as the bare sweep.
        assert!(daemon.server.registry.get("sess_tickreap").is_ok());
    }

    /// §19.1's periodic half, and the `AuditLog::reopen` inside it.
    ///
    /// The only test in the tree that touched the reopen
    /// (`paths.rs`'s `the_daemon_keeps_writing_across_a_rotation`) calls
    /// `log.reopen()` **itself** — the repair path running before the
    /// assertion — so deleting the call site left it green. This one
    /// never calls it: the loop must, or `after` lands in an unlinked
    /// inode and the live file is not there to read.
    #[tokio::test]
    async fn the_periodic_tick_rotates_the_audit_log_and_keeps_writing_to_the_live_file() {
        let paths = scratch("ticksweep");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let clock = Clock::manual(Instant::now());
        let daemon = Daemon::with_config_and_clock(paths.clone(), configured(0), clock.clone());

        daemon
            .server
            .processor
            .audit
            .record("before", None, json!({}));
        backdate(&paths.audit_log(), Duration::from_secs(86_400));

        tokio::spawn(reaper_loop(Arc::clone(&daemon)));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(LOG_SWEEP_INTERVAL + Duration::from_secs(1));

        let rolled = || {
            std::fs::read_dir(paths.log_dir())
                .map(|d| {
                    d.filter_map(|e| e.ok())
                        .any(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
                })
                .unwrap_or(false)
        };
        assert!(
            yield_until(rolled).await,
            "the tick never ran §19.1's sweep: a daemon that outlives a day \
             never rotates and never retires anything"
        );

        daemon
            .server
            .processor
            .audit
            .record("after", None, json!({}));
        let live = std::fs::read_to_string(paths.audit_log())
            .expect("the live audit log is gone: the rotation was never followed by a reopen");
        assert!(
            live.contains("\"after\""),
            "the entry landed somewhere other than the current file: {live:?}"
        );
        assert!(
            !live.contains("\"before\""),
            "the pre-rotation entry belongs in the rotated file"
        );
    }

    /// Imp-5: the reopen must not be conditional on the sweep succeeding.
    ///
    /// `sweep_logs` rotates `audit.log` **first** and can then fail in
    /// any of four later steps. On that path the file has already been
    /// renamed out from under the daemon's descriptor, so a reopen gated
    /// on `Ok(sweep)` is skipped precisely when it is needed — and the
    /// daemon appends to an unlinked inode for the rest of its life
    /// while every file on disk looks correct.
    ///
    /// The premise is asserted rather than assumed: without the `Err`
    /// this row would exercise the ordinary success path and prove
    /// nothing about the error arm.
    #[test]
    fn a_sweep_that_fails_after_rotating_still_reopens_the_audit_log() {
        let paths = scratch("sweeperr");
        let _s = Scratch(paths.clone());
        paths.ensure_dir().unwrap();
        let daemon = Daemon::new(paths.clone());

        daemon
            .server
            .processor
            .audit
            .record("before", None, json!({}));
        backdate(&paths.audit_log(), Duration::from_secs(86_400));

        // A self-referential symlink: `rotate` reaches it through
        // `std::fs::metadata`, which follows links, so it answers ELOOP
        // — not `NotFound`, so it propagates as `Err` rather than being
        // absorbed as "no such log".
        std::os::unix::fs::symlink("daemon.log", paths.daemon_log()).unwrap();

        let failed = paths.sweep_logs(LogRetention::default(), std::time::SystemTime::now());
        assert!(
            failed.is_err(),
            "the premise: this sweep has to fail, or the error arm is untested"
        );
        assert!(
            !paths.audit_log().exists(),
            "the premise: the audit log has to have been rotated away *before* \
             the failure, or there is no unlinked inode to be stranded on"
        );

        daemon.sweep_and_reopen();
        daemon
            .server
            .processor
            .audit
            .record("after", None, json!({}));

        let live = std::fs::read_to_string(paths.audit_log()).expect(
            "the audit log was never reopened after a sweep that failed \
             downstream of the rotation: §9.4's trail has silently stopped",
        );
        assert!(live.contains("\"after\""), "got {live:?}");
        assert!(!live.contains("\"before\""));
    }
}
