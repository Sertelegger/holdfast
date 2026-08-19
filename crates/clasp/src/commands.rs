//! Subcommand bodies. Parsing and printing live here; every piece of
//! state comes from `clasp-core` (spec §3.5).

use clasp_core::daemon::paths::RuntimePaths;
use clasp_core::daemon::{server, spawn};
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
                eprintln!("clasp mcp: {e}");
                ExitCode::from(EXIT_UNREACHABLE)
            }
        };
    }

    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("clasp mcp: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("clasp mcp: cannot locate my own binary: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };

    let client = match spawn::ensure_daemon(&paths, &exe, ClientKind::Shim).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("clasp mcp: daemon_unreachable: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };

    let service = match ShimServer::new(Arc::new(client))
        .serve(rmcp::transport::stdio())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("clasp mcp: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    if let Err(e) = service.waiting().await {
        eprintln!("clasp mcp: {e}");
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
            eprintln!("clasp daemon run: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    match server::run(paths).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("clasp daemon run: {e}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// `clasp daemon start` — fork-and-detach, idempotent (§3.2).
pub fn daemon_start() -> ExitCode {
    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("clasp daemon start: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("clasp daemon start: cannot locate my own binary: {e}");
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
            eprintln!("clasp daemon start: {e}");
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

async fn stop_rpc(force: bool) -> StopRpc {
    let client = match connect(ClientKind::Cli).await {
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
    if !force {
        return match stop_rpc(false).await {
            StopRpc::Stopped(outcome) => {
                println!(
                    "daemon stopped ({} session(s) terminated)",
                    outcome.sessions_terminated
                );
                ExitCode::SUCCESS
            }
            StopRpc::NotRunning => {
                println!("no daemon running");
                ExitCode::SUCCESS
            }
            StopRpc::Failed(e) => {
                eprintln!("clasp daemon stop: {e}");
                ExitCode::from(EXIT_FAILED)
            }
        };
    }

    let rpc = match tokio::time::timeout(FORCE_RPC_TIMEOUT, stop_rpc(true)).await {
        Ok(rpc) => rpc,
        Err(_) => StopRpc::Failed(format!(
            "the daemon did not answer daemon/stop within {}s",
            FORCE_RPC_TIMEOUT.as_secs()
        )),
    };

    let escalation = match paths() {
        Ok(p) => escalate_to_sigkill(&p),
        // No runtime directory means no `clasp.pid` to read. The RPC arm
        // below already reports what it saw, which for an undiscoverable
        // directory is `NotRunning`.
        Err(_) => Escalation::Nothing,
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
            ExitCode::SUCCESS
        }
        // The RPC got nowhere, which is when `--force` has to earn its
        // name. A confirmed kill *is* the stop, so it exits 0 and the
        // RPC's complaint goes to stderr as diagnosis rather than as the
        // verdict.
        StopRpc::NotRunning => match escalation {
            Escalation::Killed(pid) => {
                println!("daemon killed (pid {pid})");
                ExitCode::SUCCESS
            }
            Escalation::Nothing => {
                println!("no daemon running");
                ExitCode::SUCCESS
            }
            Escalation::NotSignalled { pid, why } => {
                println!("no daemon running");
                eprintln!("clasp daemon stop: clasp.pid names pid {pid}, not signalled: {why}");
                ExitCode::SUCCESS
            }
        },
        StopRpc::Failed(e) => {
            eprintln!("clasp daemon stop: {e}");
            match escalation {
                Escalation::Killed(pid) => {
                    println!("daemon killed (pid {pid})");
                    ExitCode::SUCCESS
                }
                Escalation::Nothing => ExitCode::from(EXIT_FAILED),
                Escalation::NotSignalled { pid, why } => {
                    eprintln!("clasp daemon stop: clasp.pid names pid {pid}, not signalled: {why}");
                    ExitCode::from(EXIT_FAILED)
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
/// `sysctl(KERN_PROC_PID)`, and that is a later milestone's work — not a
/// silent fallback to "kill whatever holds that pid", which is the one
/// behaviour that would open the pid-reuse hazard this exists to keep
/// closed.
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
            eprintln!("clasp daemon status: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let status: server::DaemonStatus =
        match client.call(method::METHOD_DAEMON_STATUS, &json!({})).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("clasp daemon status: {e}");
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
            eprintln!("clasp list: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let resp = match client.call_raw("tool/list_sessions", empty()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("clasp list: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let data: Value = match method::from_cbor(&resp.data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("clasp list: malformed response: {e}");
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
            eprintln!("clasp logs: {e}");
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
            eprintln!("clasp logs: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let resp = match client.call_raw("tool/read_output", params).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("clasp logs: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    if resp.status != "ok" {
        eprintln!("clasp logs: {} — {}", resp.status, resp.details);
        return ExitCode::from(EXIT_FAILED);
    }
    let data: Value = match method::from_cbor(&resp.data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("clasp logs: malformed response: {e}");
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
