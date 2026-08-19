//! Subcommand bodies. Parsing and printing live here; every piece of
//! state comes from `clasp-core` (spec §3.5).

use clasp_core::daemon::paths::RuntimePaths;
use clasp_core::daemon::{server, spawn};
// The `diag!` macro, not the module — every diagnostic below goes to
// stderr, and on `clasp daemon run` stderr is `daemon.log`, which §9.2
// lists as a redacted boundary. `println!` is left alone throughout:
// that is the subcommands' actual answer, and `clasp logs --raw` is
// specified to be unredacted.
use clasp_core::diag;
use clasp_core::mcp::shim::ShimServer;
use clasp_core::protocol::client::{ClientError, ControlClient};
use clasp_core::protocol::handshake::ClientKind;
use clasp_core::protocol::method;
use clasp_core::protocol::CborValue;
use rmcp::ServiceExt;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// §18.8 shim exit codes, in §18.8's row order — `0`, `1`, `2`, `64`.
/// `0` is `ExitCode::SUCCESS` and needs no constant of its own.
///
/// These are `const`s rather than an enum, so §18's preamble does not
/// bind them the way it binds `ErrorCode` — its rule is scoped to
/// *"where an implementation mirrors a table in this section as an
/// enum"*, and there is no declaration order on the wire and nothing
/// generates a schema from these. They are written in catalogue order regardless, for the same
/// reason Task 7's `isError` arm is — an insertion point a reader can
/// see. If a later milestone turns these into an enum, that enum is a
/// §18.8 mirror and the rule starts binding it.
pub const EXIT_FAILED: u8 = 1;
pub const EXIT_UNREACHABLE: u8 = 2;
pub const EXIT_USAGE: u8 = 64;

fn paths() -> anyhow::Result<RuntimePaths> {
    Ok(RuntimePaths::discover()?)
}

fn empty() -> CborValue {
    CborValue::Map(Vec::new())
}

async fn connect(kind: ClientKind) -> Result<ControlClient, ClientError> {
    let paths = RuntimePaths::discover().map_err(|source| ClientError::Connect {
        path: "runtime directory".into(),
        source,
    })?;
    ControlClient::connect(&paths.control_sock(), kind).await
}

/// `clasp mcp [--no-daemon]`
pub async fn mcp(no_daemon: bool) -> ExitCode {
    // Windows has no daemon at all (§3.3, §3.6); that arm lands in
    // 0.0.11. On Unix, `--no-daemon` is the documented escape hatch and
    // the shape the Windows build will reuse.
    if no_daemon {
        return match clasp_core::mcp::serve_stdio().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diag!("clasp mcp: {e}");
                ExitCode::from(EXIT_UNREACHABLE)
            }
        };
    }

    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("clasp mcp: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            diag!("clasp mcp: cannot locate my own binary: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };

    let client = match spawn::ensure_daemon(&paths, &exe, ClientKind::Shim).await {
        Ok(c) => c,
        Err(e) => {
            diag!("clasp mcp: daemon_unreachable: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };

    let service = match ShimServer::new(Arc::new(client))
        .serve(rmcp::transport::stdio())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            diag!("clasp mcp: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    if let Err(e) = service.waiting().await {
        diag!("clasp mcp: {e}");
        return ExitCode::from(EXIT_UNREACHABLE);
    }
    ExitCode::SUCCESS
}

/// `clasp daemon run` — foreground, for systemd/launchd and for the
/// process `daemon start` detaches.
pub async fn daemon_run() -> ExitCode {
    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("clasp daemon run: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    match server::run(paths).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diag!("clasp daemon run: {e}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// `clasp daemon start` — fork-and-detach, idempotent (§3.2).
pub fn daemon_start() -> ExitCode {
    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("clasp daemon start: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            diag!("clasp daemon start: cannot locate my own binary: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    match spawn::start_detached(&paths, &exe) {
        Ok(spawn::StartOutcome::AlreadyRunning { pid }) => {
            match pid {
                Some(p) => println!("daemon already running (pid {p})"),
                None => println!("daemon already running"),
            }
            ExitCode::SUCCESS
        }
        Ok(spawn::StartOutcome::Started { pid }) => {
            println!("daemon started (pid {pid})");
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag!("clasp daemon start: {e}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// How long `--force` waits for `daemon/stop` to answer before it stops
/// asking and starts signalling.
///
/// The RPC is still attempted on the force path — a daemon that *can*
/// answer terminates its sessions deliberately and reports how many,
/// which nothing else knows — but it is bounded, because the case
/// `--force` exists for is a daemon that accepts the connection and then
/// never replies. `ControlClient` has no timeout of its own (deliberate:
/// `clasp logs` may legitimately take a while), so an unbounded call
/// here would park `--force` in exactly the situation it is meant to
/// resolve. That is what `TestEnv::drop` was paying `CLI_TIMEOUT` for.
const FORCE_RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// How long `clasp daemon stop` **without** `--force` waits for the
/// graceful `daemon/stop` to answer before it gives up.
///
/// §3.2 bounds this call in as many words — *"`SIGTERM` to the daemon,
/// wait up to 10 seconds for clean shutdown … then return"* — and §18.8
/// gives exit code 1 for *"Operation failed: couldn't stop"*. So an
/// unbounded wait here is a divergence from normative prose, not a
/// missing nicety, and "the daemon accepts the connection and then never
/// replies" is exactly the state `--force` was already bounded for.
/// `ControlClient` has no deadline of its own past the handshake — a
/// legitimate `wait_for_pattern` runs to 3600 s — so the bound belongs
/// here.
///
/// **It is deliberately not [`FORCE_RPC_TIMEOUT`], and reusing that
/// would be a defect.** The daemon answers this method only *after* its
/// own grace has run: `shutdown_graceful` SIGTERMs every live session,
/// waits [`server::DEFAULT_STOP_GRACE_SECS`] — §3.2's ten — and then
/// SIGKILLs whatever is left. An interactive shell ignores SIGTERM
/// (§4.4) and therefore **always** reaches that escalation, so the full
/// grace is the *ordinary* duration of this call rather than its worst
/// case. A two-second bound would report failure on every stop that had
/// a shell to kill, while the daemon went on stopping correctly.
///
/// The five seconds on top cover the round trip and the SIGKILL sweep
/// that follows the grace. The daemon's grace is the floor and this must
/// stay strictly above it — see
/// `the_graceful_bound_leaves_room_for_the_daemons_own_grace`.
const STOP_RPC_TIMEOUT: Duration = Duration::from_secs(server::DEFAULT_STOP_GRACE_SECS as u64 + 5);

/// What the `daemon/stop` RPC did, kept separate from what `--force`
/// then does about it.
enum StopRpc {
    Stopped(server::StopOutcome),
    /// Nothing was listening on the control socket.
    NotRunning,
    /// Something was there and the call did not come back with an
    /// outcome — including the case where it did not come back at all.
    Failed(String),
}

async fn stop_rpc(force: bool, paths: Option<&RuntimePaths>) -> StopRpc {
    // No discoverable runtime directory means no socket to call on and
    // no `clasp.pid` to read, which is the same outcome as nothing
    // listening — and is what the old `connect()` reported too, since a
    // failed `discover()` was raised as `ClientError::Connect`.
    let Some(paths) = paths else {
        return StopRpc::NotRunning;
    };
    let client = match ControlClient::connect(&paths.control_sock(), ClientKind::Cli).await {
        Ok(c) => c,
        Err(ClientError::Connect { .. }) => return StopRpc::NotRunning,
        Err(e) => return StopRpc::Failed(e.to_string()),
    };
    let params = server::StopParams {
        force: Some(force),
        timeout_secs: None,
    };
    match client
        .call::<_, server::StopOutcome>(method::METHOD_DAEMON_STOP, &params)
        .await
    {
        Ok(outcome) => StopRpc::Stopped(outcome),
        Err(e) => StopRpc::Failed(e.to_string()),
    }
}

/// `clasp daemon stop [--force]` — idempotent; exit 0 when nothing was
/// running.
///
/// §3.2: *"`--force` makes the wait 0 and immediately escalates to
/// SIGKILL on the daemon."* The RPC alone cannot do that — `daemon/stop`
/// kills the *sessions* and asks the accept loop to stop, which a wedged
/// accept loop will not hear — so `--force` follows it with a signal to
/// the daemon process itself, whether the RPC answered, failed, or never
/// came back.
pub async fn daemon_stop(force: bool) -> ExitCode {
    let deadline = if force {
        FORCE_RPC_TIMEOUT
    } else {
        STOP_RPC_TIMEOUT
    };
    // `paths()` is resolved once, here, rather than twice inside. An
    // undiscoverable runtime directory means no socket and no
    // `clasp.pid`, and both halves below have to agree about that.
    ExitCode::from(daemon_stop_within(force, paths().ok(), deadline).await)
}

/// [`daemon_stop`] with the runtime directory resolved and the RPC
/// deadline supplied, returning §18.8's exit code as a `u8`.
///
/// Both seams exist for the same test: "the daemon accepts and never
/// replies" is the state this bound was written for, and driving it
/// through `daemon_stop` would mean discovering a real runtime directory
/// and waiting a real [`STOP_RPC_TIMEOUT`]. `u8` rather than `ExitCode`
/// because `ExitCode` cannot be compared, so a test could only assert on
/// its `Debug` formatting.
async fn daemon_stop_within(force: bool, paths: Option<RuntimePaths>, rpc_timeout: Duration) -> u8 {
    // **Both paths are bounded now.** `--force`'s bound was already here
    // because a daemon that accepts and never replies is the state
    // `--force` exists for; the graceful path had the same exposure with
    // nothing to catch it, and §3.2 bounds it too.
    let rpc = match tokio::time::timeout(rpc_timeout, stop_rpc(force, paths.as_ref())).await {
        Ok(rpc) => rpc,
        Err(_) => StopRpc::Failed(format!(
            "the daemon did not answer daemon/stop within {}s",
            rpc_timeout.as_secs()
        )),
    };

    if !force {
        return match rpc {
            StopRpc::Stopped(outcome) => {
                println!(
                    "daemon stopped ({} session(s) terminated)",
                    outcome.sessions_terminated
                );
                0
            }
            StopRpc::NotRunning => {
                println!("no daemon running");
                0
            }
            // §18.8's "Operation failed: couldn't stop". Without
            // `--force` there is nothing else to try — escalating on the
            // strength of a pid file is precisely what
            // `confirm_daemon_pid` refuses to do — so the elapse is the
            // verdict and the operator is told to reach for `--force`.
            StopRpc::Failed(e) => {
                diag!("clasp daemon stop: {e}");
                EXIT_FAILED
            }
        };
    }

    let escalation = match &paths {
        Some(p) => escalate_to_sigkill(p),
        // No runtime directory means no `clasp.pid` to read. The RPC arm
        // below already reports what it saw, which for an undiscoverable
        // directory is `NotRunning`.
        None => Escalation::Nothing,
    };

    match rpc {
        StopRpc::Stopped(outcome) => {
            println!(
                "daemon stopped ({} session(s) terminated)",
                outcome.sessions_terminated
            );
            if let Escalation::Killed(pid) = escalation {
                println!("SIGKILL sent to daemon pid {pid}");
            }
            // A `NotSignalled` here is not worth a warning: the daemon
            // answered, so the ordinary reason its pid no longer confirms
            // is that it has already dropped its listener and is on its
            // way out. The escalation declined was one nothing needed.
            0
        }
        // The RPC got nowhere, which is when `--force` has to earn its
        // name. A confirmed kill *is* the stop, so it exits 0 and the
        // RPC's complaint goes to stderr as diagnosis rather than as the
        // verdict.
        StopRpc::NotRunning => match escalation {
            Escalation::Killed(pid) => {
                println!("daemon killed (pid {pid})");
                0
            }
            Escalation::Nothing => {
                println!("no daemon running");
                0
            }
            Escalation::NotSignalled { pid, why } => {
                println!("no daemon running");
                diag!("clasp daemon stop: clasp.pid names pid {pid}, not signalled: {why}");
                0
            }
        },
        StopRpc::Failed(e) => {
            diag!("clasp daemon stop: {e}");
            match escalation {
                Escalation::Killed(pid) => {
                    println!("daemon killed (pid {pid})");
                    0
                }
                Escalation::Nothing => EXIT_FAILED,
                Escalation::NotSignalled { pid, why } => {
                    diag!("clasp daemon stop: clasp.pid names pid {pid}, not signalled: {why}");
                    EXIT_FAILED
                }
            }
        }
    }
}

/// The result of §3.2's `--force` escalation.
enum Escalation {
    /// SIGKILL was delivered to a pid confirmed to be this instance's
    /// daemon.
    Killed(u32),
    /// Nothing to signal: no `clasp.pid`, or the pid it names is gone.
    Nothing,
    /// `clasp.pid` named a live pid that was **not** signalled, because
    /// it could not be confirmed as this instance's daemon (or because
    /// the signal itself failed).
    NotSignalled { pid: u32, why: String },
}

/// SIGKILL the daemon process named by `clasp.pid`, if it is really it.
///
/// This does not reap the daemon's sessions. With the in-process PTY
/// backend they are its children, and what ends them is the master side
/// of each PTY closing as the daemon dies, which hangs up the terminal.
/// The deliberate teardown is the RPC's, and only a daemon that can
/// answer performs it — which is the trade `--force` makes.
fn escalate_to_sigkill(paths: &RuntimePaths) -> Escalation {
    let Some(pid) = server::read_pid_file(paths) else {
        return Escalation::Nothing;
    };
    // Signal 0 is the existence-and-permission check. A pid that is gone
    // — or belongs to another user, whom we could not signal anyway — is
    // nothing to escalate to, and asking first keeps the common case (a
    // daemon that answered and exited) off the `/proc` path entirely.
    // SAFETY: `kill` takes no pointers, and signal 0 sends nothing.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
        return Escalation::Nothing;
    }
    if let Err(why) = confirm_daemon_pid(paths, pid) {
        return Escalation::NotSignalled { pid, why };
    }
    // SAFETY: as above. SIGKILL cannot be caught or ignored, so a `0`
    // return means this pid is going away.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0 {
        Escalation::Killed(pid)
    } else {
        Escalation::NotSignalled {
            pid,
            why: format!("SIGKILL failed: {}", std::io::Error::last_os_error()),
        }
    }
}

/// Is `pid` this instance's daemon?
///
/// `Ok(())` only for a pid this can *positively* tie to the daemon of
/// the runtime directory being stopped. Everything else — including
/// "cannot tell" — is `Err(reason)`, because the two errors are not
/// symmetric: a false negative costs `--force` its escalation and prints
/// why, a false positive costs an unrelated process its life.
///
/// **What the evidence is, and what it is not.** `clasp.pid` on its own
/// establishes almost nothing about the *process*. It is written once at
/// startup and removed only on a clean exit, so a daemon that was
/// killed, panicked, or lost its machine leaves the file behind naming a
/// pid the kernel is then free to hand to anything. The version string
/// the file also carries does not close that: it records which clasp
/// *wrote* the file, which says nothing about who owns the pid now. What
/// the file does give is that the runtime directory is `0700`, so no
/// other user planted it — the hazard is recycling, not forgery.
///
/// So the confirmation is made against the live process, in two parts:
///
/// 1. It holds an open fd for a socket bound at *this* runtime
///    directory's `control.sock`. This is the instance-specific half:
///    a recycled pid does not hold our socket, and neither does a second
///    clasp daemon running under a different `CLASP_RUNTIME_DIR` — which
///    is the recycling case that would otherwise cost a live daemon its
///    sessions.
/// 2. Its argv contains `daemon run`. Corroboration; (1) is the
///    load-bearing half.
///
/// Both read `/proc`, so **off Linux this confirms nothing** and
/// `--force` stays what it was before this function existed: the RPC and
/// no escalation. macOS can get the same answer from
/// `sysctl(KERN_PROC_PID)` — **0.0.11's**, the platform milestone — and
/// not a silent fallback to "kill whatever holds that pid", which is the
/// one behaviour that would open the pid-reuse hazard this exists to
/// keep closed.
///
/// **This is a live divergence from §3.2 on a supported target**, and it
/// is now written down on both sides rather than only here: §3.2 carries
/// the platform qualifier and the 0.0.5 plan's *Decisions taken* carries
/// the row. It stands on the asymmetry above, not on convenience.
///
/// The residual false negative: a daemon that has dropped its listener
/// but has not yet exited reads as unconfirmed. That is the tail of a
/// *successful* cooperative shutdown, so the escalation it declines is
/// one that was not needed.
fn confirm_daemon_pid(paths: &RuntimePaths, pid: u32) -> Result<(), String> {
    if !Path::new("/proc/self/cmdline").exists() {
        return Err("no /proc on this platform, so the pid cannot be tied to a daemon".into());
    }
    let sock = paths.control_sock();
    if !holds_socket_bound_at(pid, &sock)? {
        return Err(format!(
            "pid {pid} holds no socket bound at {}",
            sock.display()
        ));
    }
    let argv = proc_argv(pid)?;
    if !argv.windows(2).any(|w| w[0] == "daemon" && w[1] == "run") {
        return Err(format!(
            "pid {pid} is not running `daemon run` (argv: {argv:?})"
        ));
    }
    Ok(())
}

fn proc_argv(pid: u32) -> Result<Vec<String>, String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|e| format!("cannot read /proc/{pid}/cmdline: {e}"))?;
    Ok(raw
        .split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect())
}

/// Does `pid` hold an open socket bound at `sock`?
///
/// `/proc/net/unix` maps a bound path to the inodes of the sockets on
/// it; `/proc/<pid>/fd` maps a process to the inodes it holds. Neither
/// alone names both ends, and the intersection is what ties a process to
/// a path.
fn holds_socket_bound_at(pid: u32, sock: &Path) -> Result<bool, String> {
    let table = std::fs::read_to_string("/proc/net/unix")
        .map_err(|e| format!("cannot read /proc/net/unix: {e}"))?;
    let sock = sock.to_string_lossy();
    let want: &str = &sock;
    let inodes: HashSet<&str> = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (inode, path) = unix_socket_row(line)?;
            (path == want).then_some(inode)
        })
        .collect();
    if inodes.is_empty() {
        return Ok(false);
    }
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|e| format!("cannot read /proc/{pid}/fd: {e}"))?;
    for entry in fds.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|i| i.strip_suffix(']'))
        else {
            continue;
        };
        if inodes.contains(inode) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `(inode, path)` from one `/proc/net/unix` row, or `None` for a socket
/// with no bound path — every connected client, including the connection
/// this process made a moment ago.
///
/// The columns are `Num RefCount Protocol Flags Type St Inode Path`, and
/// the path is taken as the whole remainder rather than as an eighth
/// whitespace-separated token: the kernel writes `sun_path` raw and
/// unescaped, so a runtime directory below a home directory with a space
/// in it would otherwise be compared against its own first word and
/// never match.
fn unix_socket_row(line: &str) -> Option<(&str, &str)> {
    let mut rest = line.trim_start();
    let mut inode = "";
    for column in 0..7 {
        let end = rest.find(char::is_whitespace)?;
        let (token, tail) = rest.split_at(end);
        if column == 6 {
            inode = token;
        }
        rest = tail.trim_start();
    }
    (!rest.is_empty()).then_some((inode, rest))
}

/// `clasp daemon status [--json]`
pub async fn daemon_status(as_json: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(ClientError::Connect { .. }) => {
            if as_json {
                println!("{}", json!({ "running": false }));
            } else {
                println!("clasp daemon down");
            }
            return ExitCode::from(EXIT_UNREACHABLE);
        }
        Err(e) => {
            diag!("clasp daemon status: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let status: server::DaemonStatus =
        match client.call(method::METHOD_DAEMON_STATUS, &json!({})).await {
            Ok(s) => s,
            Err(e) => {
                diag!("clasp daemon status: {e}");
                return ExitCode::from(EXIT_UNREACHABLE);
            }
        };
    if as_json {
        println!("{}", serde_json::to_string(&status).unwrap_or_default());
    } else {
        let s = status.uptime_secs;
        println!(
            "clasp daemon up — pid {}, uptime {}:{:02}:{:02}, sessions {} live + {} exited-retained, attach clients {}",
            status.pid,
            s / 3600,
            (s % 3600) / 60,
            s % 60,
            status.sessions_live,
            status.sessions_exited_retained,
            status.attach_clients,
        );
    }
    ExitCode::SUCCESS
}

/// `clasp list [--json]`
pub async fn list(as_json: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(e) => {
            diag!("clasp list: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let resp = match client.call_raw("tool/list_sessions", empty()).await {
        Ok(r) => r,
        Err(e) => {
            diag!("clasp list: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let data: Value = match method::from_cbor(&resp.data) {
        Ok(v) => v,
        Err(e) => {
            diag!("clasp list: malformed response: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    if as_json {
        println!("{}", serde_json::to_string(&data).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    let mut sessions = data["sessions"].as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        println!("no sessions");
        return ExitCode::SUCCESS;
    }
    // Newest first, then by id so the order is total and stable. The sort
    // lives here rather than in the tool because it is presentation:
    // `list_sessions` reports a registry backed by a `HashMap`, whose
    // iteration order would otherwise vary between two `clasp list` runs
    // that saw the same sessions (§3.5 puts formatting in this crate).
    sessions.sort_by(|a, b| {
        b["started_at_unix_secs"]
            .as_u64()
            .cmp(&a["started_at_unix_secs"].as_u64())
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    println!("ID                  NAME          STATE      PID      COMMAND");
    for s in sessions {
        println!(
            "{:<18}  {:<12}  {:<9}  {:<7}  {}",
            s["id"].as_str().unwrap_or("-"),
            s["name"].as_str().unwrap_or("-"),
            s["state"].as_str().unwrap_or("-"),
            s["pid"]
                .as_u64()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            s["command"].as_str().unwrap_or("-"),
        );
    }
    ExitCode::SUCCESS
}

/// `clasp logs <session> [--tail N] [--raw]`
pub async fn logs(session: &str, tail_lines: Option<usize>, raw: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(e) => {
            diag!("clasp logs: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    // §7.2: CLI commands ride the same control socket as the MCP tool
    // handlers. `clasp logs` is `read_output` with a human on the other
    // end, so it goes through `tool/read_output` rather than growing a
    // parallel method with its own bugs.
    let mut args = match tail_lines {
        Some(n) => json!({ "session": session, "tail_lines": n, "max_bytes": 256 * 1024 }),
        None => json!({ "session": session, "since_cursor": 0, "max_bytes": 256 * 1024 }),
    };
    if raw {
        // §3.2's `--raw` is "disable redaction, and audit-log that you
        // did". Both halves belong to the daemon: 0.0.3 put the
        // `redaction_disabled` audit write inside the read path itself
        // (§9.4), precisely so every transport inherits it instead of
        // having to remember. So the flag is one field on the existing
        // call, and the CLI does not get an audit obligation of its own.
        args["redact"] = json!(false);
    }
    let params = match method::to_cbor(&args) {
        Ok(p) => p,
        Err(e) => {
            diag!("clasp logs: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let resp = match client.call_raw("tool/read_output", params).await {
        Ok(r) => r,
        Err(e) => {
            diag!("clasp logs: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    if resp.status != "ok" {
        diag!("clasp logs: {} — {}", resp.status, resp.details);
        return ExitCode::from(EXIT_FAILED);
    }
    let data: Value = match method::from_cbor(&resp.data) {
        Ok(v) => v,
        Err(e) => {
            diag!("clasp logs: malformed response: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    print!("{}", data["output"].as_str().unwrap_or_default());
    ExitCode::SUCCESS
}

/// `clasp version`
pub fn version() -> ExitCode {
    println!(
        "clasp {} (build {}) protocol {}.{}",
        env!("CARGO_PKG_VERSION"),
        clasp_core::protocol::handshake::build_id(),
        clasp_core::protocol::PROTOCOL_MAJOR,
        clasp_core::protocol::PROTOCOL_MINOR,
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use clasp_core::protocol::frame;
    use clasp_core::protocol::handshake::{self, HandshakeData};
    use clasp_core::protocol::method::{Request, Response};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A short, unique `/tmp` runtime directory. `sockaddr_un.sun_path`
    /// cannot hold a path under the workspace's `target/`.
    fn scratch(tag: &str) -> RuntimePaths {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        RuntimePaths::with_dir(format!("/tmp/clasp-t-cmd-{tag}-{}-{n}", std::process::id()))
    }

    struct Scoped(RuntimePaths);
    impl Drop for Scoped {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.dir());
        }
    }

    /// A daemon that accepts, completes the handshake, and then answers
    /// **nothing**.
    ///
    /// The handshake has to succeed or the test would be measuring
    /// `ControlClient::connect`'s own deadline rather than the stop RPC's
    /// — a different bound, added for a different finding.
    fn wedged_daemon(paths: &RuntimePaths) -> tokio::task::JoinHandle<()> {
        // Bound **before** the spawn, so the socket exists by the time
        // this returns. Binding inside the task makes the connect below a
        // race, and losing it reports "no daemon running" — a green exit
        // 0 that has nothing to do with the property under test.
        let listener = tokio::net::UnixListener::bind(paths.control_sock()).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let Ok(hs) = frame::read_frame::<_, Request>(&mut stream).await else {
                        return;
                    };
                    let data = HandshakeData {
                        protocol_major: handshake::PROTOCOL_MAJOR,
                        protocol_minor: handshake::PROTOCOL_MINOR,
                        daemon_version: "wedged".into(),
                        build: "wedged".into(),
                        accepted: true,
                        reject_reason: None,
                    };
                    let resp = Response::ok(hs.id, &data, "handshake accepted").unwrap();
                    if frame::write_frame(&mut stream, &resp).await.is_err() {
                        return;
                    }
                    // Read the `daemon/stop` and never answer it. The
                    // stream is held for the life of this task: letting
                    // it drop would EOF the client's read, the call would
                    // return an error on its own, and the row would be
                    // green against a `daemon stop` with no bound at all.
                    let _ = frame::read_frame::<_, Request>(&mut stream).await;
                    std::future::pending::<()>().await;
                });
            }
        })
    }

    /// §3.2 bounds `clasp daemon stop`, and nothing bounded it.
    ///
    /// `--force`'s RPC was already capped by `FORCE_RPC_TIMEOUT`,
    /// precisely because "the daemon accepts the connection and then
    /// never replies" is a real state that path was written for. The
    /// graceful path had the same exposure with nothing to catch it, and
    /// `ControlClient` has no deadline of its own past the handshake — so
    /// the command hung, forever, against a divergence from §3.2's
    /// *"wait up to 10 seconds … then return"* and §18.8's exit code 1.
    ///
    /// **The outer bound is a red test, not a hang.** The failure mode
    /// here is a command that never returns, and there is no
    /// `nextest.toml` in this repo to turn that into anything but a hung
    /// CI job, so the elapsed arm is `expect`ed rather than matched as
    /// success.
    #[tokio::test]
    async fn a_graceful_stop_gives_up_on_a_daemon_that_never_answers() {
        let paths = scratch("wedged");
        let _scoped = Scoped(paths.clone());
        paths.ensure_dir().unwrap();
        let daemon = wedged_daemon(&paths);

        let code = tokio::time::timeout(
            Duration::from_secs(20),
            daemon_stop_within(false, Some(paths.clone()), Duration::from_millis(200)),
        )
        .await
        .expect(
            "`clasp daemon stop` never returned: §3.2 bounds the wait and §18.8 gives \
             it an exit code, so a hang is a divergence from normative prose",
        );
        assert_eq!(
            code, EXIT_FAILED,
            "§18.8: \"Operation failed: couldn't stop\" is exit 1"
        );
        daemon.abort();
    }

    /// The control. Without it the row above is satisfied by a
    /// `daemon stop` that reports failure unconditionally.
    #[tokio::test]
    async fn a_graceful_stop_against_an_absent_daemon_is_still_success() {
        let paths = scratch("absent");
        let _scoped = Scoped(paths.clone());
        paths.ensure_dir().unwrap();

        let code = tokio::time::timeout(
            Duration::from_secs(20),
            daemon_stop_within(false, Some(paths.clone()), Duration::from_millis(200)),
        )
        .await
        .expect("nothing to connect to must not wait for anything");
        assert_eq!(code, 0, "§3.2 makes `daemon stop` idempotent");
    }

    /// The bound the shipped command really passes must leave room for
    /// the grace the *daemon* takes before it answers.
    ///
    /// `shutdown_graceful` SIGTERMs every live session, waits
    /// `DEFAULT_STOP_GRACE_SECS`, and only then SIGKILLs and replies. An
    /// interactive shell ignores SIGTERM (§4.4) and therefore always
    /// reaches that escalation, so the full grace is the **ordinary**
    /// duration of this call. Reusing `FORCE_RPC_TIMEOUT` here — the
    /// obvious reading of "bound it like the force path" — would report
    /// failure on every stop that had a shell to kill, while the daemon
    /// went on stopping correctly.
    ///
    /// A strict inequality against the daemon's own constant, not a
    /// second copy of this one.
    #[test]
    fn the_graceful_bound_leaves_room_for_the_daemons_own_grace() {
        let grace = Duration::from_secs(u64::from(server::DEFAULT_STOP_GRACE_SECS));
        assert!(
            STOP_RPC_TIMEOUT > grace,
            "the CLI would give up at {STOP_RPC_TIMEOUT:?} on a stop the daemon \
             is entitled to spend {grace:?} on"
        );
        // And it is a bound rather than an absence of one.
        assert!(STOP_RPC_TIMEOUT <= grace * 3);
    }
}
