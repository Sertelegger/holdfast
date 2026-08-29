//! Subcommand bodies. Parsing and printing live here; every piece of
//! state comes from `holdfast-core` (spec §3.5).

use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::{server, spawn};
// The `diag!` macro, not the module — every diagnostic below goes to
// stderr, and on `holdfast daemon run` stderr is `daemon.log`, which §9.2
// lists as a redacted boundary. `println!` is left alone throughout:
// that is the subcommands' actual answer, and `holdfast logs --raw` is
// specified to be unredacted.
use holdfast_core::diag;
use holdfast_core::mcp::shim::ShimServer;
use holdfast_core::protocol::client::{ClientError, ControlClient};
use holdfast_core::protocol::handshake::ClientKind;
use holdfast_core::protocol::method;
use holdfast_core::protocol::CborValue;
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
/// `128 + signo`, the status a shell reports for a signalled child.
///
/// `holdfast attach` **catches** `SIGTERM` and `SIGHUP` rather than
/// dying of them, because dying of them runs no destructors and leaves
/// the user's terminal in raw mode. Having caught them it reports what
/// a shell would have reported had it not, so nothing downstream loses
/// the distinction the catch was buying back.
/// The attach notice, as the bytes `diag!` is handed.
///
/// **Split out of the attach loop so a test can render it.** The layout is
/// cursor arithmetic — DECSC, `ESC[L`, DECRC and a trailing newline that
/// belongs to `diag::emit` — and an assertion that the byte stream contains
/// the bytes the code just wrote cannot see a cursor land on the wrong row.
/// `the_banner_lands_above_the_prompt_and_leaves_the_cursor_on_it` drives
/// this string through a real emulator instead.
///
/// `size` is `None` when `TIOCGWINSZ` failed or answered a zero dimension —
/// a pty nobody sized reports `0x0`, and a bar claiming the session is `0x0`
/// reads as a defect in the thing added to reassure the reader. Without a
/// width there is nothing to pad to, so the notice is printed as a sentence.
pub(crate) fn attach_banner(
    session: &str,
    size: Option<(u16, u16)>,
    stderr_is_terminal: bool,
) -> Option<String> {
    // **The policy lives here, not at the call site.** A guard written as a
    // bare `if` around the emit is a branch no test can reach without a
    // process whose stderr is not a terminal; as a parameter it is one
    // assertion. What stays outside is the capability query itself, which is
    // a single std call with nothing to get wrong.
    if !stderr_is_terminal {
        return None;
    }
    let cols = match size {
        Some((cols, rows)) if cols > 0 && rows > 0 => Some(cols as usize),
        _ => None,
    };
    let geometry = match size {
        Some((cols, rows)) if cols > 0 && rows > 0 => format!(" ({cols}x{rows})"),
        _ => String::new(),
    };
    let text = format!(" holdfast: attached to {session}{geometry} — Ctrl-B d to detach ");
    let body = match cols {
        Some(cols) => fit_to_width(&text, cols),
        None => text,
    };
    Some(format!(
        "\x1b7\r\x1b[L\x1b[48;5;61m\x1b[38;5;231m{body}\x1b[0m\x1b8"
    ))
}

/// Truncate or pad `s` so it occupies exactly `cols` display columns.
///
/// **Display columns, not `chars().count()`.** A session name is free-form
/// agent input with no length or charset validation, so the bar can be handed
/// text wider than the terminal — and a CJK name counts one `char` per two
/// columns. Either way the bar wraps onto the next row, and the next row is
/// the prompt `ESC[L` just made space for, so an over-wide bar destroys the
/// thing this whole sequence exists to preserve. Measured at 41 ASCII chars
/// and at 12 CJK chars on an 80-column terminal before this existed.
fn fit_to_width(s: &str, cols: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if UnicodeWidthStr::width(s) <= cols {
        let mut out = String::from(s);
        for _ in UnicodeWidthStr::width(s)..cols {
            out.push(' ');
        }
        return out;
    }
    let mut out = String::new();
    let mut w = 0usize;
    for ch in s.chars() {
        let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
        if w + cw > cols {
            break;
        }
        out.push(ch);
        w += cw;
    }
    // A wide char that would not fit leaves a column short of the edge.
    for _ in w..cols {
        out.push(' ');
    }
    out
}

/// How long the attach banner waits for the child's repaint before
/// printing anyway. Long enough for a shell to answer `SIGWINCH`, short
/// enough that a silent session is not left wondering.
const BANNER_AFTER_REPAINT: Duration = Duration::from_millis(400);

/// How long a `Resize` notice waits for the geometry to stop moving before
/// it is printed (GH #66).
///
/// **Coalesced rather than rate-limited, and the difference matters.** A
/// window drag delivers a `SIGWINCH` per frame, and each one reaches every
/// *other* attached client as a `Resize`; the report caught a drag printing
/// `107x56, 115x58, 104x55, …` — thirteen distinct widths — into a raw-mode
/// terminal. A rate limit would have printed one of those intermediate
/// sizes and then stopped, which is a number the session no longer has. A
/// debounce prints the geometry the drag actually settled on, once.
///
/// Shorter than [`BANNER_AFTER_REPAINT`] because this one is answering a
/// question the operator just asked with their mouse: at 150ms a release is
/// reported before the hand leaves the trackpad, while a drag at any
/// plausible frame rate keeps resetting it.
const RESIZE_SETTLE: Duration = Duration::from_millis(150);

pub const EXIT_SIGHUP: u8 = 128 + 1;
pub const EXIT_SIGTERM: u8 = 128 + 15;

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

/// `holdfast mcp [--no-daemon]`
pub async fn mcp(no_daemon: bool) -> ExitCode {
    // Windows has no daemon at all (§3.3, §3.6); that arm lands in
    // 0.0.11. On Unix, `--no-daemon` is the documented escape hatch and
    // the shape the Windows build will reuse.
    if no_daemon {
        return match holdfast_core::mcp::serve_stdio().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diag!("holdfast mcp: {e}");
                ExitCode::from(no_daemon_exit_code(&e))
            }
        };
    }

    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("holdfast mcp: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            diag!("holdfast mcp: cannot locate my own binary: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };

    let client = match spawn::ensure_daemon(&paths, &exe, ClientKind::Shim).await {
        Ok(c) => c,
        Err(e) => {
            diag!("holdfast mcp: daemon_unreachable: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };

    let service = match ShimServer::new(Arc::new(client))
        .serve(rmcp::transport::stdio())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            diag!("holdfast mcp: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    if let Err(e) = service.waiting().await {
        diag!("holdfast mcp: {e}");
        return ExitCode::from(EXIT_UNREACHABLE);
    }
    ExitCode::SUCCESS
}

/// §18.8's code for a `holdfast mcp --no-daemon` that stopped serving.
///
/// **A refused `config.toml` is "operation failed" (1), not "daemon
/// unreachable" (2).** `serve_stdio` now loads the same file the daemon
/// loads and refuses the same way (REQ-CFG-003), and this transport has
/// no daemon in it to be unreachable — reporting exit 2 would send an
/// operator looking for a process that was never meant to exist, past
/// the diagnostic that already names the offending key. `daemon run`
/// gives the identical refusal exit 1 ([`daemon_run`] below), and two
/// transports must not disagree about the same bytes on disk.
///
/// Everything else keeps exit 2: those are the transport failing —
/// `serve` or `waiting` on stdio — which is what §18.8's row is about
/// for this subcommand.
fn no_daemon_exit_code(e: &anyhow::Error) -> u8 {
    if e.downcast_ref::<holdfast_core::config::ConfigError>()
        .is_some()
    {
        EXIT_FAILED
    } else {
        EXIT_UNREACHABLE
    }
}

/// `holdfast daemon run` — foreground, for systemd/launchd and for the
/// process `daemon start` detaches.
pub async fn daemon_run() -> ExitCode {
    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("holdfast daemon run: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    match server::run(paths).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diag!("holdfast daemon run: {e}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// `holdfast daemon start` — fork-and-detach, idempotent (§3.2).
pub fn daemon_start() -> ExitCode {
    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("holdfast daemon start: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            diag!("holdfast daemon start: cannot locate my own binary: {e}");
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
            diag!("holdfast daemon start: {e}");
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
/// `holdfast logs` may legitimately take a while), so an unbounded call
/// here would park `--force` in exactly the situation it is meant to
/// resolve. That is what `TestEnv::drop` was paying `CLI_TIMEOUT` for.
const FORCE_RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// How long `holdfast daemon stop` **without** `--force` waits for the
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
    // no `holdfast.pid` to read, which is the same outcome as nothing
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

/// `holdfast daemon stop [--force]` — idempotent; exit 0 when nothing was
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
    // `holdfast.pid`, and both halves below have to agree about that.
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
                diag!("holdfast daemon stop: {e}");
                EXIT_FAILED
            }
        };
    }

    let escalation = match &paths {
        Some(p) => escalate_to_sigkill(p),
        // No runtime directory means no `holdfast.pid` to read. The RPC arm
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
                diag!("holdfast daemon stop: holdfast.pid names pid {pid}, not signalled: {why}");
                0
            }
        },
        StopRpc::Failed(e) => {
            diag!("holdfast daemon stop: {e}");
            match escalation {
                Escalation::Killed(pid) => {
                    println!("daemon killed (pid {pid})");
                    0
                }
                Escalation::Nothing => EXIT_FAILED,
                Escalation::NotSignalled { pid, why } => {
                    diag!(
                        "holdfast daemon stop: holdfast.pid names pid {pid}, not signalled: {why}"
                    );
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
    /// Nothing to signal: no `holdfast.pid`, or the pid it names is gone.
    Nothing,
    /// `holdfast.pid` named a live pid that was **not** signalled, because
    /// it could not be confirmed as this instance's daemon (or because
    /// the signal itself failed).
    NotSignalled { pid: u32, why: String },
}

/// SIGKILL the daemon process named by `holdfast.pid`, if it is really it.
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
/// **What the evidence is, and what it is not.** `holdfast.pid` on its own
/// establishes almost nothing about the *process*. It is written once at
/// startup and removed only on a clean exit, so a daemon that was
/// killed, panicked, or lost its machine leaves the file behind naming a
/// pid the kernel is then free to hand to anything. The version string
/// the file also carries does not close that: it records which holdfast
/// *wrote* the file, which says nothing about who owns the pid now. What
/// the file does give is that the runtime directory is `0700`, so no
/// other user planted it — the hazard is recycling, not forgery.
///
/// So the confirmation is made against the live process, in two parts:
///
/// 1. It holds an open fd for a socket bound at *this* runtime
///    directory's `control.sock`. This is the instance-specific half:
///    a recycled pid does not hold our socket, and neither does a second
///    holdfast daemon running under a different `HOLDFAST_RUNTIME_DIR` — which
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

/// `holdfast daemon status [--json]`
pub async fn daemon_status(as_json: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(ClientError::Connect { .. }) => {
            if as_json {
                println!("{}", json!({ "running": false }));
            } else {
                println!("holdfast daemon down");
            }
            return ExitCode::from(EXIT_UNREACHABLE);
        }
        Err(e) => {
            diag!("holdfast daemon status: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let status: server::DaemonStatus =
        match client.call(method::METHOD_DAEMON_STATUS, &json!({})).await {
            Ok(s) => s,
            Err(e) => {
                diag!("holdfast daemon status: {e}");
                return ExitCode::from(EXIT_UNREACHABLE);
            }
        };
    if as_json {
        println!("{}", serde_json::to_string(&status).unwrap_or_default());
    } else {
        let s = status.uptime_secs;
        println!(
            "holdfast daemon up — pid {}, uptime {}:{:02}:{:02}, sessions {} live + {} exited-retained, attach clients {}",
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

/// `holdfast list [--json]`
pub async fn list(as_json: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(e) => {
            diag!("holdfast list: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let resp = match client.call_raw("tool/list_sessions", empty()).await {
        Ok(r) => r,
        Err(e) => {
            diag!("holdfast list: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    let data: Value = match method::from_cbor(&resp.data) {
        Ok(v) => v,
        Err(e) => {
            diag!("holdfast list: malformed response: {e}");
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
    // iteration order would otherwise vary between two `holdfast list` runs
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

/// `holdfast logs <session> [--tail N] [--raw]`
pub async fn logs(session: &str, tail_lines: Option<usize>, raw: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(e) => {
            diag!("holdfast logs: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    // §7.2: CLI commands ride the same control socket as the MCP tool
    // handlers. `holdfast logs` is `read_output` with a human on the other
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
            diag!("holdfast logs: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let resp = match client.call_raw("tool/read_output", params).await {
        Ok(r) => r,
        Err(e) => {
            diag!("holdfast logs: {e}");
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    };
    if resp.status != "ok" {
        diag!("holdfast logs: {} — {}", resp.status, resp.details);
        return ExitCode::from(EXIT_FAILED);
    }
    let data: Value = match method::from_cbor(&resp.data) {
        Ok(v) => v,
        Err(e) => {
            diag!("holdfast logs: malformed response: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    print!("{}", data["output"].as_str().unwrap_or_default());
    ExitCode::SUCCESS
}

/// The §7.5 handshake `holdfast attach` sends, **in full**.
///
/// §7.5 spells out that its own example is elided: `client_kind`,
/// `client_version`, `protocol_major` and `protocol_minor` are *not*
/// optional and **only `role` is**, so an abbreviation here is a client
/// that cannot complete a handshake.
///
/// `role: Interactive` is REQ-SEC-008's first half: raw fidelity, no
/// redaction. A redacted password prompt would corrupt what the human
/// types back. `holdfast watch` sends the other pairing.
///
/// Note the constant path — `protocol::PROTOCOL_MAJOR`, **not**
/// `protocol::handshake::PROTOCOL_MAJOR`. It is the same path
/// [`version`] prints from, which is what makes
/// `holdfast_version_prints_the_protocol_the_sockets_speak` an assertion
/// about one number rather than two.
#[cfg(unix)]
fn attach_handshake(
    session: &str,
    mode: holdfast_core::attach::AttachMode,
    role: holdfast_core::attach::AttachRole,
) -> holdfast_core::attach::ClientFrame {
    holdfast_core::attach::ClientFrame::Attach {
        session: session.to_string(),
        mode,
        role,
        client_kind: ClientKind::Cli,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_major: holdfast_core::protocol::PROTOCOL_MAJOR,
        protocol_minor: holdfast_core::protocol::PROTOCOL_MINOR,
        terminal: terminal_identity(),
    }
}

/// Which terminal device this process's **keyboard** is, for `terminal_busy`
/// (GH #66).
///
/// `st_rdev` of fd 0, hex, from a plain `fstat`. That is the identity of
/// the *device*, so two processes sharing one terminal agree on it while
/// two terminals never collide — which is precisely the distinction the
/// daemon needs and the only one it makes, since it compares the string and
/// never parses it.
///
/// **fd 0 and not fd 1**, because the contention this answers is over
/// input: two clients reading one keyboard get alternate bytes from the
/// kernel and split the operator's `Ctrl-B d` between them. A client whose
/// output is redirected but whose stdin is still the terminal is exactly as
/// affected, and keying on stdout would miss it.
///
/// `None` when stdin is not a terminal — a pipe cannot be contended for in
/// this way, and `None` never matches `None` at the daemon.
#[cfg(unix)]
fn terminal_identity() -> Option<String> {
    use std::os::unix::io::AsRawFd;
    let stdin = std::io::stdin();
    if !std::io::IsTerminal::is_terminal(&stdin) {
        return None;
    }
    // SAFETY: `fstat` writes a `stat` and reads only the fd, which is
    // borrowed for the call.
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstat(stdin.as_raw_fd(), st.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let st = unsafe { st.assume_init() };
    Some(format!("rdev:{:#x}", st.st_rdev))
}

/// What the handshake settled on, or why it did not.
#[cfg(unix)]
enum Dialled {
    /// Attached. The stream's two halves, plus the geometry the session
    /// is currently at.
    Ok(
        tokio::net::unix::OwnedReadHalf,
        tokio::net::unix::OwnedWriteHalf,
    ),
    /// The daemon refused, or answered something unusable, and has
    /// already been reported. Carries the exit code.
    Refused(u8),
}

/// Connect to `attach.sock`, send the handshake, and check the answer —
/// including the half §7.5 makes the *client's* job.
///
/// **The client re-checks the major even though the daemon accepted**
/// (REQ-D-004a's third case). An older daemon that never heard of the
/// symmetry rule can accept a client it cannot understand, and the client
/// is the peer that can still tell. §7.5: *"there is no wire token for
/// that refusal"* — so the message below carries none, and the test
/// asserts that.
#[cfg(unix)]
async fn dial_attach(
    session: &str,
    mode: holdfast_core::attach::AttachMode,
    role: holdfast_core::attach::AttachRole,
    what: &str,
) -> Dialled {
    use holdfast_core::attach::{client_accepts_daemon, ServerFrame};
    use holdfast_core::protocol::frame;

    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            diag!("holdfast {what}: {e}");
            return Dialled::Refused(EXIT_UNREACHABLE);
        }
    };
    let sock = paths.attach_sock();
    let stream = match tokio::net::UnixStream::connect(&sock).await {
        Ok(s) => s,
        Err(e) => {
            diag!(
                "holdfast {what}: cannot reach the daemon at {}: {e}",
                sock.display()
            );
            return Dialled::Refused(EXIT_UNREACHABLE);
        }
    };
    let (mut rd, mut wr) = stream.into_split();

    if let Err(e) = frame::write_frame(&mut wr, &attach_handshake(session, mode, role)).await {
        diag!("holdfast {what}: could not send the attach handshake: {e}");
        return Dialled::Refused(EXIT_UNREACHABLE);
    }

    loop {
        let body = match frame::read_frame_body(&mut rd).await {
            Ok(b) => b,
            Err(e) => {
                diag!("holdfast {what}: the daemon closed the connection: {e}");
                return Dialled::Refused(EXIT_UNREACHABLE);
            }
        };
        let f = match holdfast_core::attach::decode_server_frame(&body) {
            Ok(f) => f,
            Err(e) => {
                diag!("holdfast {what}: undecodable frame from the daemon: {e}");
                return Dialled::Refused(EXIT_FAILED);
            }
        };
        match f {
            // §12.3's forward-compatibility seam, and it is live from the
            // first frame: a newer daemon may prepend a frame this build
            // has never heard of, and skipping it is what lets §7.8 land
            // additively (REQ-SURF-002).
            ServerFrame::Unknown { .. } => continue,
            ServerFrame::Attached {
                protocol_major,
                protocol_minor,
                ..
            } => {
                if !client_accepts_daemon(protocol_major) {
                    // **No wire reason token in this message**, on
                    // purpose: §7.5 gives this refusal none, because the
                    // peer that would have sent one is the peer that
                    // failed to check. And no further frame is sent —
                    // not even `Detach`.
                    diag!(
                        "holdfast {what}: this daemon accepted an attach it should have \
                         refused. It speaks attach protocol {protocol_major}.{protocol_minor} \
                         and this client speaks {}.{}. Upgrade whichever is older.",
                        holdfast_core::protocol::PROTOCOL_MAJOR,
                        holdfast_core::protocol::PROTOCOL_MINOR,
                    );
                    return Dialled::Refused(EXIT_FAILED);
                }
                return Dialled::Ok(rd, wr);
            }
            // §7.5's refusal. `message` is a whole sentence that *begins*
            // with the §18.4b token, so printing it verbatim is what lets
            // an operator tell `session_not_found` from
            // `protocol_too_old` — a bare "failed to attach" cannot.
            ServerFrame::AttachReject { message, .. } => {
                diag!("holdfast {what}: {message}");
                return Dialled::Refused(EXIT_FAILED);
            }
            ServerFrame::ProtocolError {
                reason, frame_kind, ..
            } => {
                match frame_kind {
                    Some(k) => diag!("holdfast {what}: protocol error: {reason} ({k})"),
                    None => diag!("holdfast {what}: protocol error: {reason}"),
                }
                return Dialled::Refused(EXIT_FAILED);
            }
            other => {
                diag!(
                    "holdfast {what}: the daemon answered {:?} before `Attached`",
                    other.tag()
                );
                return Dialled::Refused(EXIT_FAILED);
            }
        }
    }
}

/// Read whole frame bodies off the socket into a channel.
///
/// **A dedicated task and not a `select!` branch.** `read_frame_body`
/// reads a 4-byte prefix and then the body; cancelling it between the two
/// leaves the stream desynchronised for every frame after it, and a
/// `select!` cancels whichever branch did not win *every time round the
/// loop*. A channel receive is cancel-safe, so the framing lives here and
/// the loop only ever drops a `recv`.
#[cfg(unix)]
fn spawn_frame_reader(
    mut rd: tokio::net::unix::OwnedReadHalf,
) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        while let Ok(body) = holdfast_core::protocol::frame::read_frame_body(&mut rd).await {
            if tx.send(body).await.is_err() {
                return;
            }
        }
    });
    rx
}

/// Read the local terminal on a dedicated OS thread.
///
/// Not `tokio::io::stdin()`: that borrows the blocking pool for the life
/// of the process, and the runtime's shutdown grace then has a parked
/// `read` in it on every exit path. A plain thread is never joined and
/// costs nothing at exit, because returning from `main` ends the process
/// whatever its threads are doing.
#[cfg(unix)]
fn spawn_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });
    rx
}

/// Write bytes to the local terminal, unmodified.
///
/// `write_all` and not `print!`: the payload is a PTY's raw byte stream,
/// which is not UTF-8 in general (a `less` redraw and a `vim` session both
/// carry lone `0x9b`-style bytes), and it must not be reformatted.
#[cfg(unix)]
fn render(bytes: &[u8]) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bytes);
    let _ = out.flush();
}

/// `holdfast attach <session>` — §6.1 Layer 1.
///
/// Your terminal *becomes* the session: raw mode, full colour, full
/// keyboard, no redaction (`role: interactive`, REQ-SEC-008). Detach with
/// `Ctrl-B` then `d`; **the session keeps running** (§6.1: *"cleanly
/// disconnects without killing the session"*).
#[cfg(unix)]
pub async fn attach(session: &str) -> ExitCode {
    use holdfast_core::attach::{AttachMode, AttachRole, ClientFrame, ServerFrame};
    use holdfast_core::protocol::frame;
    use std::os::unix::io::AsRawFd;

    let (rd, mut wr) = match dial_attach(
        session,
        AttachMode::ReadWrite,
        AttachRole::Interactive,
        "attach",
    )
    .await
    {
        Dialled::Ok(rd, wr) => (rd, wr),
        Dialled::Refused(code) => return ExitCode::from(code),
    };

    // **The two signals that would otherwise skip the restore, and they
    // are installed before raw mode is taken.** `TermiosGuard`'s `Drop`
    // covers the normal path, `?` and a panic unwinding — but a process
    // terminated by a signal's *default* disposition runs no
    // destructors, and the user is left holding a shell with `ECHO` and
    // `ICANON` off, recoverable only by typing `stty sane` blind.
    // `pkill holdfast` is exactly what an operator reaches for, and a
    // keyboard `Ctrl-C` cannot get here at all — raw mode clears `ISIG`
    // — so an external kill is the whole of this hazard.
    //
    // **Above the guard, because installing them is what changes the
    // disposition.** Taking the terminal first left a window — two task
    // spawns and the `winch` registration wide — in which the terminal
    // was already raw and `SIGTERM` still meant *die without running
    // destructors*, which is the same defect and the same mute shell,
    // only narrower. Nothing here depends on `tty`, `frames`, `keys` or
    // `winch`, so the ordering costs nothing; a registration that fails
    // now also returns before the guard exists rather than after it.
    //
    // Created **once, above the loop**, like `winch` and not like
    // `watch`'s `ctrl_c()`: tokio's `register_listener` marks the
    // current version seen, so a listener constructed inside the loop
    // can be created after the broadcast and never see it.
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            diag!("holdfast attach: cannot install a SIGTERM handler: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            diag!("holdfast attach: cannot install a SIGHUP handler: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };

    // The controlling terminal. **The guard is taken before anything
    // else can fail**, and every exit path below — including a panic —
    // runs its `Drop`. A restore that has to be remembered on each path
    // is one that gets forgotten on exactly one of them, and the cost is
    // the user's shell left mute.
    let tty = std::io::stdin().as_raw_fd();
    let _raw = match crate::attach_tty::TermiosGuard::raw(tty) {
        Ok(g) => g,
        Err(e) => {
            diag!(
                "holdfast attach: this is not a terminal ({e}). `holdfast attach` needs \
                 one; use `holdfast watch` to follow a session from a pipe."
            );
            return ExitCode::from(EXIT_FAILED);
        }
    };

    let mut frames = spawn_frame_reader(rd);
    let mut keys = spawn_stdin_reader();
    let mut winch =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()) {
            Ok(s) => s,
            Err(e) => {
                diag!("holdfast attach: cannot watch for terminal resizes: {e}");
                return ExitCode::from(EXIT_FAILED);
            }
        };

    // One at startup, so the session reflows to *this* terminal
    // immediately rather than at the first time the user drags a window.
    if let Ok((cols, rows)) = crate::attach_tty::window_size(tty) {
        if frame::write_frame(&mut wr, &ClientFrame::Resize { cols, rows })
            .await
            .is_err()
        {
            return ExitCode::from(EXIT_UNREACHABLE);
        }
    }

    // **Say that the attach worked, but not yet.** Nothing else here
    // does: every other diagnostic in this function reports an error, an
    // exit, a detach, a resize or a secret request, and attach replays no
    // scrollback — only a pending `AwaitingSecret`. So attaching to a
    // session idling at a prompt rendered an empty pane, and when the
    // session is a shell wearing the operator's own prompt, an attached
    // terminal was indistinguishable from an unattached one (GH #67).
    //
    // **Printing it here, before the loop, does not work — measured.**
    // The startup `Resize` above raises `SIGWINCH` in the child, and a
    // shell repaints its prompt in response: `zsh` with a two-line
    // prompt emits `\r\r ESC[A ESC[A … ESC[J`, which is *erase from two
    // lines up to the end of the screen*. The banner sits inside that
    // region and is wiped before a human sees it. The first version of
    // this shipped that way and read as "the banner does nothing",
    // because the byte stream contained it and the screen did not.
    //
    // So it is held until after the first output frame has been
    // rendered, which is the repaint. The fallback timer covers a child
    // that answers `SIGWINCH` with silence — a program that ignores it,
    // or a session with nothing to redraw — so a quiet session still
    // gets told it is attached.
    // **Inserted above the prompt, not printed below it.**
    //
    // The first version wrote `\r\n` + text and restored the cursor with
    // DECSC/DECRC. That put the bar under the prompt, and the restore
    // landed a row off whenever the prompt sat on the last line: the
    // newline scrolled the screen, every absolute row moved up one, and
    // the saved position then named the bar's own line. The operator saw
    // the cursor sitting on the bar with no prompt under it.
    //
    // `ESC[L` avoids the newline entirely. At column zero it inserts a
    // blank line *at* the prompt's row, pushing the prompt and everything
    // below it down; the bar is written into the gap, so it lands above
    // the prompt.
    //
    // **`ESC8` alone puts the cursor back, with no compensating move —
    // and the trailing newline is what finishes the job.** The comment
    // here used to say the terminal adjusts the saved position when lines
    // are inserted above it. **That is false**, measured against vt100,
    // tmux 3.6, pyte and GNU screen: DECSC stores raw coordinates and
    // `ESC[L` never touches them, so `ESC8` lands the cursor *on the bar*.
    // What steps it down onto the prompt is the `\n` that `diag::emit`
    // appends with `writeln!`. That newline is therefore **load-bearing
    // layout**, not formatting, which is why it is named here and pinned
    // by `the_banner_lands_above_the_prompt_and_leaves_the_cursor_on_it`.
    // Switching the banner to a writer that does not append one puts the
    // cursor back on the bar, which is where the operator's next keystroke
    // would go.
    //
    // This also explains the `ESC[B` that an earlier revision added and
    // measured as overshooting: `ESC8` + `ESC[B` + the newline is two rows,
    // not one. The conclusion was right and the model behind it was wrong.
    //
    // `attach` is a pass-through and the child tracks its own cursor, so
    // leaving it anywhere else starts the child's next write in the wrong
    // column — which is the bug this replaces rather than a refinement of
    // it.
    //
    // **Known edge:** a prompt already on the last row is pushed off the
    // bottom by the insert. Nothing here can prevent that — making room
    // requires scrolling, and scrolling is what broke the first version.
    // The bar is a one-shot notice; a persistent one that owns a row is
    // GH #68, which needs `attach` to render rather than forward.
    //
    // Colour is SGR 256, background 61, padded to the terminal width so
    // it reads as a bar rather than a sentence.
    //
    // **Only onto a terminal.** `holdfast attach 2>err.txt` otherwise
    // writes DECSC, `ESC[L` and SGR into the file, and the reader of that
    // file gets escape bytes rather than a notice. The bar is decoration
    // on a human's screen; a redirected stderr has no screen to decorate.
    let mut banner = attach_banner(
        session,
        crate::attach_tty::window_size(tty).ok(),
        std::io::IsTerminal::is_terminal(&std::io::stderr()),
    );
    let banner_fallback = tokio::time::sleep(BANNER_AFTER_REPAINT);
    tokio::pin!(banner_fallback);

    // The geometry a `Resize` last reported, held until it stops moving —
    // see `RESIZE_SETTLE`. The timer is armed only while this is `Some`, so
    // an attach that never sees a resize never wakes for one.
    let mut pending_resize: Option<(u16, u16)> = None;
    let resize_settle = tokio::time::sleep(RESIZE_SETTLE);
    tokio::pin!(resize_settle);

    let mut detach = crate::attach_tty::DetachKey::default();
    // `Some` while an `AwaitingSecret` is outstanding: the request id to
    // answer, and the line being typed. While this is set, keystrokes go
    // into the line and **not** onto the wire as `Input` — which is what
    // keeps the value off the session's echo as well as off this terminal
    // (§9.5).
    let mut secret: Option<(String, crate::attach_tty::SecretLine)> = None;

    loop {
        tokio::select! {
            body = frames.recv() => {
                let Some(body) = body else {
                    // EOF with no `Detached` before it: the daemon died
                    // or the socket broke. Distinct from every clean
                    // ending, which returns from inside this match.
                    diag!("holdfast attach: the daemon closed the connection");
                    return ExitCode::from(EXIT_UNREACHABLE);
                };
                let f = match holdfast_core::attach::decode_server_frame(&body) {
                    Ok(f) => f,
                    Err(e) => {
                        diag!("holdfast attach: undecodable frame: {e}");
                        return ExitCode::from(EXIT_FAILED);
                    }
                };
                match f {
                    ServerFrame::Output { bytes, .. } => {
                        render(&bytes);
                        // After the repaint, not before it. See the
                        // banner's comment above the loop.
                        if let Some(b) = banner.take() {
                            diag!("{b}");
                        }
                    }
                    ServerFrame::SessionExited { code } => {
                        diag!("holdfast attach: the session exited ({code})");
                    }
                    ServerFrame::Detached { reason } => {
                        diag!("holdfast attach: detached ({reason})");
                        return ExitCode::SUCCESS;
                    }
                    ServerFrame::AwaitingSecret { request_id, prompt_text } => {
                        // On its own line, so it cannot be mistaken for
                        // part of whatever the child last drew.
                        render(b"\r\n");
                        render(prompt_text.as_bytes());
                        render(b"\r\n");
                        secret = Some((request_id, crate::attach_tty::SecretLine::default()));
                    }
                    ServerFrame::SecretRequestClosed { request_id, outcome } => {
                        if secret.as_ref().is_some_and(|(id, _)| *id == request_id) {
                            secret = None;
                            diag!("holdfast attach: secret request {outcome}");
                        }
                    }
                    // §17.5's binding approval, **reported and not
                    // answerable from this build**. Sending
                    // `ApproveBinding` needs an interactive affordance in
                    // raw mode, which is CLI work 0.0.7 does not do; the
                    // arm exists because the variant is additive on a
                    // §23.3 surface and an exhaustive match must cover
                    // it. Dropping the frame silently would leave a human
                    // watching a session stop with nothing said, so it is
                    // named — **binding, provider and the command line
                    // that would receive the credential**, which is all
                    // the frame carries (REQ-SEC-016).
                    //
                    // **The command line is the point of the line, not
                    // decoration** (GH #45): `prod-ssh` reads identically
                    // whether the session is `ssh prod-01` or `ssh
                    // prod-01 -o ProxyCommand=nc 127.0.0.1 2222`, and a
                    // human who cannot see which one it is has nothing to
                    // decide with. Already redacted **and stripped of
                    // control characters** by the daemon — without the
                    // second half an agent could erase this very line as
                    // it is drawn.
                    ServerFrame::BindingApprovalRequired {
                        binding_name,
                        command_line,
                        provider,
                        ..
                    } => {
                        diag!(
                            "holdfast attach: the session is waiting for approval to use the \
                             `{binding_name}` binding ({provider}) for `{command_line}`; this \
                             build cannot answer it"
                        );
                    }
                    // Another client resized the session. This terminal
                    // cannot be resized from here, so the view is simply
                    // reported rather than silently wrong — but **not on
                    // this frame** (GH #66). Held until the geometry
                    // settles, because a drag delivers one of these per
                    // frame and printing each was a flood the operator had
                    // to detach to escape.
                    ServerFrame::Resize { cols, rows } => {
                        pending_resize = Some((cols, rows));
                        resize_settle
                            .as_mut()
                            .reset(tokio::time::Instant::now() + RESIZE_SETTLE);
                    }
                    ServerFrame::ProtocolError { reason, frame_kind } => {
                        match frame_kind {
                            Some(k) => diag!("holdfast attach: protocol error: {reason} ({k})"),
                            None => diag!("holdfast attach: protocol error: {reason}"),
                        }
                    }
                    // §7.5's client-side skip. Not an error: this is the
                    // property that lets a newer daemon add a frame.
                    ServerFrame::Unknown { .. } => {}
                    ServerFrame::Attached { .. } | ServerFrame::AttachReject { .. } => {
                        diag!("holdfast attach: a second handshake frame arrived; ignoring it");
                    }
                }
            }
            chunk = keys.recv() => {
                let Some(chunk) = chunk else {
                    // Local stdin closed. Leave without killing the
                    // session, exactly as the detach key does.
                    let _ = frame::write_frame(&mut wr, &ClientFrame::Detach).await;
                    return ExitCode::SUCCESS;
                };
                // **§6.1's grammar runs first, and it runs during a
                // secret prompt too.** The order is the whole point: a
                // client that routed the chunk into `SecretLine` while a
                // prompt was up made `Ctrl-B d` unreachable, made
                // REQ-SEC-019's `Ctrl-C` unreachable, and then typed
                // `\x02d` into the child as the password when the user
                // pressed Enter trying to escape. A password prompt is
                // exactly where a human most needs to be able to leave.
                let (forward, detached) = detach.feed(&chunk);
                if !forward.is_empty() {
                    match secret.as_mut() {
                        // §9.5: while a prompt is outstanding the bytes
                        // are the *answer* and do not reach the session
                        // — which is what keeps the value off the
                        // session's echo as well as off this terminal.
                        Some((id, line)) => match line.feed(&forward) {
                            crate::attach_tty::SecretKeys::Pending => {}
                            crate::attach_tty::SecretKeys::Line(bytes) => {
                                let mut f =
                                    ClientFrame::SecretInput { request_id: id.clone(), bytes };
                                let sent = frame::write_frame(&mut wr, &f).await;
                                // **The frame still owns the cleartext**,
                                // and `ClientFrame` has no zeroing `Drop`
                                // — it is a wire type. `SecretLine` now
                                // *moves* its buffer here rather than
                                // cloning it, so this is the last copy
                                // this process holds that it can reach,
                                // and this is where it stops existing.
                                // (The CBOR encoder's own scratch and the
                                // kernel's socket buffer are outside
                                // anything a client can zero, exactly as
                                // `zero_bytes`'s own doc records for the
                                // daemon side.)
                                if let ClientFrame::SecretInput { bytes, .. } = &mut f {
                                    holdfast_core::attach::secret::zero_bytes(bytes);
                                }
                                secret = None;
                                render(b"\r\n");
                                if sent.is_err() {
                                    return ExitCode::from(EXIT_UNREACHABLE);
                                }
                            }
                            // REQ-SEC-019's abandon, spelled the way the
                            // spec spells it: **as ordinary `Input`**,
                            // not as a new client→server frame. The
                            // daemon closes the request when the child
                            // stops asking and fans out
                            // `SecretRequestClosed`; nothing here has to
                            // tell it. The local state is dropped now
                            // rather than on that reply, so the keyboard
                            // belongs to the session again immediately
                            // and the partial value stops existing.
                            crate::attach_tty::SecretKeys::Cancelled(bytes) => {
                                secret = None;
                                render(b"\r\n");
                                diag!("holdfast attach: secret entry abandoned");
                                let f = ClientFrame::Input { bytes };
                                if frame::write_frame(&mut wr, &f).await.is_err() {
                                    return ExitCode::from(EXIT_UNREACHABLE);
                                }
                            }
                        },
                        None => {
                            let f = ClientFrame::Input { bytes: forward };
                            if frame::write_frame(&mut wr, &f).await.is_err() {
                                return ExitCode::from(EXIT_UNREACHABLE);
                            }
                        }
                    }
                }
                if detached {
                    let _ = frame::write_frame(&mut wr, &ClientFrame::Detach).await;
                    render(b"\r\n");
                    return ExitCode::SUCCESS;
                }
            }
            // Returning, not re-raising: the `return` is what runs
            // `TermiosGuard::drop`, and the status is the shell's own
            // `128 + signo`, so a script can still tell a signalled
            // client (143/129) from a detach (0) from an unreachable
            // daemon (2). The session is left running, exactly as the
            // detach key leaves it — a signal to the *viewer* is not a
            // signal to the child.
            _ = sigterm.recv() => {
                let _ = frame::write_frame(&mut wr, &ClientFrame::Detach).await;
                render(b"\r\n");
                diag!("holdfast attach: SIGTERM — detaching; the session keeps running");
                return ExitCode::from(EXIT_SIGTERM);
            }
            _ = sighup.recv() => {
                // No `render`: `SIGHUP` says this terminal has already
                // gone away, so the only thing left worth doing is
                // telling the daemon and putting the termios back for
                // whoever inherits the fd.
                let _ = frame::write_frame(&mut wr, &ClientFrame::Detach).await;
                diag!("holdfast attach: SIGHUP — detaching; the session keeps running");
                return ExitCode::from(EXIT_SIGHUP);
            }
            // A child that met `SIGWINCH` with silence still gets to
            // tell the operator they are attached.
            _ = &mut banner_fallback, if banner.is_some() => {
                if let Some(b) = banner.take() {
                    diag!("{b}");
                }
            }
            // The geometry stopped moving: report where it landed, once.
            // Guarded on `is_some` so the timer is inert until a `Resize`
            // arms it — an unguarded elapsed `Sleep` is permanently ready
            // and would spin this loop.
            _ = &mut resize_settle, if pending_resize.is_some() => {
                if let Some((cols, rows)) = pending_resize.take() {
                    diag!("holdfast attach: the session is now {cols}x{rows}");
                }
            }
            _ = winch.recv() => {
                if let Ok((cols, rows)) = crate::attach_tty::window_size(tty) {
                    if frame::write_frame(&mut wr, &ClientFrame::Resize { cols, rows })
                        .await
                        .is_err()
                    {
                        return ExitCode::from(EXIT_UNREACHABLE);
                    }
                }
            }
        }
    }
}

/// Everything `holdfast watch` is able to put on the wire.
///
/// **One variant, by construction.** A watch client that sent a write
/// frame would not compile, which is a stronger statement than a test
/// that observes it not doing so today — and the frame it would most
/// plausibly grow is `Resize` on `SIGWINCH`, which looks harmless,
/// would be rejected `read_only_attach` anyway, and would therefore
/// leave no trace a client-side assertion could see.
#[cfg(unix)]
enum WatchOut {
    Detach,
}

#[cfg(unix)]
impl WatchOut {
    fn frame(self) -> holdfast_core::attach::ClientFrame {
        match self {
            Self::Detach => holdfast_core::attach::ClientFrame::Detach,
        }
    }
}

/// `holdfast watch <session>` — §6.1 Layer 2.
///
/// The same view as `holdfast attach`, **read-only and redacted**
/// (`mode: ReadOnly`, `role: Observer` — REQ-SEC-008's second half).
/// Detach with `Ctrl+C`.
///
/// **The two clients differ on the detach key deliberately.** A
/// read-only viewer has no reason to reserve a prefix key, because every
/// keystroke it could forward is one it is not allowed to send.
///
/// **And it takes no terminal.** No raw mode, no `termios` to restore, no
/// stdin: `Ctrl+C` arrives as `SIGINT`, which works from a pipe as well
/// as from a tty. The bytes it renders are a PTY's, already carrying
/// `\r\n`, so a cooked terminal displays them correctly.
#[cfg(unix)]
pub async fn watch(session: &str) -> ExitCode {
    use holdfast_core::attach::{AttachMode, AttachRole, ServerFrame};
    use holdfast_core::protocol::frame;

    let (rd, mut wr) =
        match dial_attach(session, AttachMode::ReadOnly, AttachRole::Observer, "watch").await {
            Dialled::Ok(rd, wr) => (rd, wr),
            Dialled::Refused(code) => return ExitCode::from(code),
        };

    let mut frames = spawn_frame_reader(rd);

    // Same coalescing as `attach`, for the same reason (GH #66): a watcher
    // receives a `Resize` per frame of somebody else's window drag, and it
    // has no keyboard to escape the flood with — only `Ctrl+C`, which ends
    // the session view entirely.
    let mut pending_resize: Option<(u16, u16)> = None;
    let resize_settle = tokio::time::sleep(RESIZE_SETTLE);
    tokio::pin!(resize_settle);

    loop {
        tokio::select! {
            body = frames.recv() => {
                let Some(body) = body else {
                    diag!("holdfast watch: the daemon closed the connection");
                    return ExitCode::from(EXIT_UNREACHABLE);
                };
                let f = match holdfast_core::attach::decode_server_frame(&body) {
                    Ok(f) => f,
                    Err(e) => {
                        diag!("holdfast watch: undecodable frame: {e}");
                        return ExitCode::from(EXIT_FAILED);
                    }
                };
                match f {
                    ServerFrame::Output { bytes, .. } => render(&bytes),
                    ServerFrame::SessionExited { code } => {
                        diag!("holdfast watch: the session exited ({code})");
                    }
                    ServerFrame::Detached { reason } => {
                        diag!("holdfast watch: detached ({reason})");
                        return ExitCode::SUCCESS;
                    }
                    // A watcher is told a secret is being asked for and
                    // **cannot answer it**: `SecretInput` is a write
                    // frame, refused `read_only_attach` by §7.5's table.
                    // Reported so the human knows why the session has
                    // stopped drawing, and nothing more.
                    ServerFrame::AwaitingSecret { .. } => {
                        diag!("holdfast watch: the session is waiting for a secret");
                    }
                    ServerFrame::SecretRequestClosed { .. } => {}
                    // A watcher is told an approval is pending and
                    // **cannot answer it in any build**: §18.4 rejects
                    // `ApproveBinding` from a `ReadOnly` client by name,
                    // *"an authorisation decision, not an observation"*.
                    // Reported for the same reason `AwaitingSecret` is,
                    // and with no more than the frame carries.
                    ServerFrame::BindingApprovalRequired {
                        binding_name,
                        command_line,
                        ..
                    } => {
                        diag!(
                            "holdfast watch: the session is waiting for approval to use the \
                             `{binding_name}` binding for `{command_line}`"
                        );
                    }
                    ServerFrame::Resize { cols, rows } => {
                        pending_resize = Some((cols, rows));
                        resize_settle
                            .as_mut()
                            .reset(tokio::time::Instant::now() + RESIZE_SETTLE);
                    }
                    ServerFrame::ProtocolError { reason, frame_kind } => {
                        match frame_kind {
                            Some(k) => diag!("holdfast watch: protocol error: {reason} ({k})"),
                            None => diag!("holdfast watch: protocol error: {reason}"),
                        }
                    }
                    ServerFrame::Unknown { .. } => {}
                    ServerFrame::Attached { .. } | ServerFrame::AttachReject { .. } => {
                        diag!("holdfast watch: a second handshake frame arrived; ignoring it");
                    }
                }
            }
            // The geometry stopped moving: report where it landed, once.
            _ = &mut resize_settle, if pending_resize.is_some() => {
                if let Some((cols, rows)) = pending_resize.take() {
                    diag!("holdfast watch: the session is now {cols}x{rows}");
                }
            }
            r = tokio::signal::ctrl_c() => {
                if let Err(e) = r {
                    diag!("holdfast watch: cannot watch for Ctrl+C: {e}");
                    return ExitCode::from(EXIT_FAILED);
                }
                // `Detach` and **not** the `0x03` byte. Forwarding it as
                // `Input` is the tempting reading of "Ctrl+C detaches",
                // and it is a write frame: §7.5 would refuse it
                // `read_only_attach` and the client would sit there.
                let _ = frame::write_frame(&mut wr, &WatchOut::Detach.frame()).await;
                return ExitCode::SUCCESS;
            }
        }
    }
}

/// §3.6 marks `holdfast watch` `✗` on Windows native **permanently**,
/// for the same reason as `holdfast attach`.
#[cfg(windows)]
pub async fn watch(_session: &str) -> ExitCode {
    diag!(
        "holdfast watch is not supported on Windows native (§3.6): there is \
         no daemon to attach to. Use WSL."
    );
    ExitCode::from(EXIT_USAGE)
}

/// §3.6 marks `holdfast attach` `✗` on Windows native **permanently** —
/// there is no daemon there to attach to.
///
/// The arm exists so `main.rs`'s unconditional match compiles on that
/// target: a `#[cfg(unix)]`-only function referenced by an unconditional
/// caller is a hard error under `windows-cross`, not a warning.
#[cfg(windows)]
pub async fn attach(_session: &str) -> ExitCode {
    diag!(
        "holdfast attach is not supported on Windows native (§3.6): there is \
         no daemon to attach to. Use WSL."
    );
    ExitCode::from(EXIT_USAGE)
}

/// `holdfast version`
pub fn version() -> ExitCode {
    println!(
        "holdfast {} (build {}) protocol {}.{}",
        env!("CARGO_PKG_VERSION"),
        holdfast_core::protocol::handshake::build_id(),
        holdfast_core::protocol::PROTOCOL_MAJOR,
        holdfast_core::protocol::PROTOCOL_MINOR,
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{attach_banner, fit_to_width};

    /// Render the row the cursor ends on, for the assertions below.
    fn row(p: &vt100::Parser, r: u16) -> String {
        p.screen().contents_between(r, 0, r, p.screen().size().1)
    }

    /// The bar goes **above** the prompt and the cursor ends **on** the
    /// prompt.
    ///
    /// **This is the test the feature shipped without, and its absence is
    /// why four commits of cursor arithmetic could not fail.** The existing
    /// integration assertion checks that the byte stream contains `ESC7` and
    /// `ESC8`, which is the code emitting what the code emits: deleting
    /// `ESC[L`, deleting the `\r`, or re-adding the `ESC[B` that an earlier
    /// revision was written to remove all left it green. Rendering is what
    /// separates "the bytes were sent" from "the cursor is in the right
    /// place".
    ///
    /// The trailing `\n` is fed deliberately: `diag::emit` writes with
    /// `writeln!`, and that newline is what steps the cursor off the bar and
    /// onto the prompt. See `attach_banner`.
    #[test]
    fn the_banner_lands_above_the_prompt_and_leaves_the_cursor_on_it() {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(b"an earlier line\r\nPROMPT> ");
        let (before_row, before_col) = p.screen().cursor_position();

        p.process(
            attach_banner("sess", Some((80, 24)), true)
                .unwrap()
                .as_bytes(),
        );
        p.process(b"\n");

        let (after_row, after_col) = p.screen().cursor_position();
        assert_eq!(
            (after_row, after_col),
            (before_row + 1, before_col),
            "the cursor should follow the prompt down one row, not sit on the bar"
        );
        assert!(
            row(&p, before_row).contains("attached to sess"),
            "the bar should occupy the prompt's old row, got: {:?}",
            row(&p, before_row)
        );
        assert!(
            row(&p, after_row).contains("PROMPT>"),
            "the prompt should survive, one row down; got: {:?}",
            row(&p, after_row)
        );
    }

    /// A stderr that is not a terminal gets no banner at all.
    ///
    /// `holdfast attach 2>err.txt` otherwise writes DECSC, `ESC[L` and SGR
    /// into the file. Before this the repo contained no `is_terminal`,
    /// `isatty` or `atty` call anywhere, so nothing distinguished a screen
    /// from a pipe.
    #[test]
    fn a_redirected_stderr_gets_no_escape_sequences() {
        assert_eq!(attach_banner("sess", Some((80, 24)), false), None);
        assert_eq!(attach_banner("sess", None, false), None);
        // And the terminal case still produces one, so the assertion above
        // is not passing because the builder returns `None` for everything.
        assert!(attach_banner("sess", Some((80, 24)), true).is_some());
    }

    /// A name wider than the terminal is truncated, not wrapped.
    ///
    /// An over-wide bar wraps onto the row `ESC[L` just made for the prompt
    /// and overwrites it, so the notice destroys the thing it exists beside.
    /// `name` is free-form agent input: `StartSessionArgs::name` has no
    /// length or charset validation.
    #[test]
    fn an_over_wide_bar_cannot_reach_the_prompts_row() {
        for name in ["x".repeat(200), "端末".repeat(60)] {
            let mut p = vt100::Parser::new(24, 80, 0);
            p.process(b"an earlier line\r\nPROMPT> ");
            let (before_row, _) = p.screen().cursor_position();

            p.process(
                attach_banner(&name, Some((80, 24)), true)
                    .unwrap()
                    .as_bytes(),
            );
            p.process(b"\n");

            assert!(
                row(&p, before_row + 1).contains("PROMPT>"),
                "a {}-column name wrapped the bar onto the prompt: {:?}",
                name.len(),
                row(&p, before_row + 1)
            );
        }
    }

    /// `fit_to_width` measures columns, not `char`s.
    ///
    /// The distinction is the whole bug: `chars().count()` reports 2 for
    /// `"端末"`, which occupies 4 columns.
    #[test]
    fn fit_to_width_counts_display_columns_not_chars() {
        use unicode_width::UnicodeWidthStr;
        assert_eq!(UnicodeWidthStr::width(fit_to_width("ab", 10).as_str()), 10);
        assert_eq!(
            UnicodeWidthStr::width(fit_to_width("端末", 10).as_str()),
            10
        );
        // Truncation lands on a column budget, never mid-character.
        assert_eq!(
            UnicodeWidthStr::width(fit_to_width("端末端末", 5).as_str()),
            5
        );
        assert_eq!(
            UnicodeWidthStr::width(fit_to_width(&"x".repeat(99), 7).as_str()),
            7
        );
    }

    use super::*;
    use holdfast_core::protocol::frame;
    use holdfast_core::protocol::handshake::{self, HandshakeData};
    use holdfast_core::protocol::method::{Request, Response};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A short, unique `/tmp` runtime directory. `sockaddr_un.sun_path`
    /// cannot hold a path under the workspace's `target/`.
    fn scratch(tag: &str) -> RuntimePaths {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        RuntimePaths::with_dir(format!(
            "/tmp/holdfast-t-cmd-{tag}-{}-{n}",
            std::process::id()
        ))
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

    /// §3.2 bounds `holdfast daemon stop`, and nothing bounded it.
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
            "`holdfast daemon stop` never returned: §3.2 bounds the wait and §18.8 gives \
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
