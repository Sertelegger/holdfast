// Every diagnostic this binary writes goes through `holdfast_core::diag!`,
// which redacts. `holdfast daemon run`'s stderr *is* `daemon.log` (§9.2
// lists it as a redacted boundary), and `holdfast mcp`'s stderr is what an
// MCP client surfaces as server logs, so both are output boundaries in
// §9.2's sense. `print_stdout` is deliberately **not** denied: `holdfast
// list`, `holdfast logs` and `holdfast daemon status` write their real answers
// there, and `holdfast logs --raw` is specified to be unredacted. They write
// it through [`out`] rather than `println!`, for the reason that module gives.
#![deny(clippy::print_stderr)]

/// The local terminal half of `holdfast attach`.
///
/// **Gated here rather than with an inner `#![cfg(unix)]`**, so the
/// `windows-cross` job sees a module that does not exist rather than one
/// that exists and is empty — and so this line and `commands`'s
/// `#[cfg(windows)]` refusal arms sit where a reader looking for the
/// platform boundary will find them together. §3.6 marks `holdfast
/// attach` and `holdfast watch` `✗` on Windows native permanently.
#[cfg(unix)]
mod attach_tty;
mod commands;

// Imports the module *and* the `diag!` macro — a `#[macro_export]` macro
// and a module of the same name live in different namespaces, and one
// `use` brings both.
use holdfast_core::diag;
use std::process::ExitCode;
use std::time::Duration;

/// **What the usage banner has to say on a platform that refuses most of
/// it.** Eight of the ten subcommands above are daemon-backed, and seven
/// of those eight answer every Windows build with a refusal (§3.6) — which
/// the operator otherwise discovers one subcommand at a time.
///
/// **The eighth is `daemon stop`, and the note has to say so rather than
/// round it off to `daemon *`.** It prints "no daemon running" and exits
/// 0, because §3.2 makes it idempotent and on this platform that is the
/// only case; the whole point is that a teardown script may run it
/// unconditionally. A banner that lumps it in with the refusals tells
/// that script's author the opposite of what the binary does, which is
/// the one reader this paragraph exists for. So: seven refuse, three
/// answer (`mcp`, `version`, `daemon stop`).
///
/// **"Ten" counts `USAGE`, not `run`'s match arms**, and since 0.0.10a
/// the two differ: `pty-worker` is dispatched and is deliberately not in
/// the banner (see its arm in [`run`]). The count above is about what an
/// operator is offered, so it is still ten — recorded here because a
/// reader who counts arms instead would otherwise read a stale number and
/// "fix" it.
///
/// Empty on Unix, so the banner there is unchanged byte for byte.
#[cfg(windows)]
const PLATFORM_NOTE: &str = "\
\nON WINDOWS NATIVE there is no daemon (§3.6), so seven of the ten
subcommands above refuse with exit 64 and change nothing: `daemon run`,
`daemon start`, `daemon status`, `list`, `logs`, `attach` and `watch`.
Three answer: `mcp` serves stdio in-process, so sessions live inside that
process and end with it; `version` prints; and `daemon stop` prints `no
daemon running` and exits 0, because §3.2 makes it idempotent and here that
is the only case — a teardown script may run it unconditionally.
What `list` and `logs` would have told you, a running `holdfast mcp` can:
the `list_sessions` and `read_output` tools. `daemon status --json` still
prints a JSON object saying there is no daemon, rather than nothing at
all. Use WSL for a daemon that outlives its client.\n";

#[cfg(not(windows))]
const PLATFORM_NOTE: &str = "";

const USAGE: &str = "\
HOLDFAST — Human-Observable Long-lived Daemon For Agent Shell Terminals

USAGE:
    holdfast mcp [--no-daemon]        Run the MCP server on stdio
    holdfast daemon run               Run the daemon in the foreground
    holdfast daemon start             Start a detached daemon (idempotent)
    holdfast daemon stop [--force]    Stop the daemon (idempotent)
    holdfast daemon status [--json]   Report daemon health
    holdfast list [--json]            List sessions
    holdfast logs <session> [--tail N] [--raw]
                                      Print a session's output
    holdfast attach <session> [--allow-echo]
                                      Take over the session's terminal
                                      (detach with Ctrl-B then d).
                                      --allow-echo submits secrets even
                                      when the child has not turned echo
                                      off, which lets it echo them into
                                      the session's output
    holdfast watch <session>          Follow a session read-only and
                                      redacted (detach with Ctrl+C)
    holdfast version                  Print version information

ENVIRONMENT:
    HOLDFAST_RUNTIME_DIR              Select a Holdfast instance: relocates the
                                      sockets, pid file, lock file and the
                                      daemon log

FILES:
    $XDG_CONFIG_HOME/holdfast/config.toml, else ~/.config/holdfast/config.toml
                                      Read by both transports, `mcp
                                      --no-daemon` included. Absent is the
                                      defaults; present and invalid refuses
                                      to start rather than starting on
                                      them. HOLDFAST_RUNTIME_DIR does not move
                                      it.
";

/// How long to wait for the blocking pool at exit.
///
/// `send_input` hands its PTY write to the blocking pool because the
/// master is a blocking fd (see `mcp::tools`). If a child stopped reading
/// its terminal that write is parked in the kernel, and Linux does *not*
/// wake it when the child dies, so the thread never returns. Dropping a
/// runtime waits for the blocking pool unconditionally, which would leave
/// the process hanging at exit long after it stopped serving.
///
/// This binds every subcommand, not just `mcp`. `daemon run` hosts the
/// same sessions and therefore the same parked writers — more of them,
/// since it outlives many shims — so it needs the bound at least as much.
///
/// **The population it covers grew with GH #201 and the bound did not
/// need to.** `holdfast_core::mcp::offload` put the output pipeline on
/// this pool, so an exit can now land on many in-flight scans as well as
/// on a few parked writers. That does not lengthen the wait — this is a
/// bound and not a sum — it only means more threads are abandoned in the
/// instant before exit. Abandoning a scan is also milder than abandoning
/// a write: `read_processed` holds the buffer lock for a memcpy and runs
/// every regex outside it, so all but a sliver of a scan's life is spent
/// holding nothing that a later call would have to wait for.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// Where a subcommand's answer goes, and what happens when nobody is
/// reading it any more (GH #218).
///
/// **Rust ignores `SIGPIPE`**: the runtime installs `SIG_IGN` before `main`,
/// so a write to a pipe whose reader has gone returns `EPIPE` instead of
/// ending the process the way it ends `cat`. `println!` answers `EPIPE` by
/// panicking, so `holdfast logs big | head -1` — the first thing an
/// operator does with a long log — printed a panic and a backtrace note and
/// exited 101, and `holdfast watch`, which discarded its write errors,
/// never exited at all.
///
/// **Dying of the signal, and only for stdout.** When stdout's reader has
/// gone this restores `SIGPIPE`'s default action and raises it, so the
/// process ends exactly as `cat` would — no message, and a status the
/// shell reports as 141 — which is the Unix convention for "the consumer
/// stopped listening" and what a script under `set -o pipefail` already
/// expects of every other producer. The alternative the issue offers,
/// `SIG_DFL` for the whole process at startup, is deliberately not taken:
/// these subcommands also write to the daemon's control socket, and a
/// daemon that dies mid-call would then kill the CLI silently with 141
/// instead of letting it say "daemon unreachable" and exit 2. Scoped to
/// the stdout write, a closed socket stays an error the caller reports.
///
/// `holdfast mcp` and `holdfast daemon run` never come here: the shim's
/// stdout is the MCP transport, owned by `rmcp`, and the daemon writes
/// nothing to stdout. Neither may die of a peer going away.
///
/// Any *other* write failure — `holdfast logs X > /dev/full` — is a real
/// failure and not a departed reader: it is said on stderr and exits 1
/// (§18.8), rather than panicking with 101.
pub(crate) mod out {
    use std::io::Write;

    /// Write `text` to stdout, and flush it.
    ///
    /// **Flushed on every call**, because an unflushed tail is written by
    /// the runtime's exit path, which ignores the error — so a reader that
    /// left during the last line would have been reported as success.
    pub(crate) fn text(text: &str) {
        bytes(text.as_bytes());
    }

    /// [`text`] with a newline, for the one-line answers.
    pub(crate) fn line(text: &str) {
        let mut buf = String::with_capacity(text.len() + 1);
        buf.push_str(text);
        buf.push('\n');
        bytes(buf.as_bytes());
    }

    /// Write raw bytes to stdout, unmodified, and flush them. `holdfast
    /// watch`'s payload is a PTY's byte stream, which is not UTF-8.
    pub(crate) fn bytes(b: &[u8]) {
        let mut out = std::io::stdout().lock();
        let written = out.write_all(b).and_then(|()| out.flush());
        drop(out);
        if let Err(e) = written {
            failed(&e);
        }
    }

    fn failed(e: &std::io::Error) -> ! {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            reader_gone();
        }
        holdfast_core::diag!("holdfast: cannot write to stdout: {e}");
        std::process::exit(i32::from(crate::commands::EXIT_FAILED))
    }

    #[cfg(unix)]
    fn reader_gone() -> ! {
        // SAFETY: `signal` and `raise` take no pointers. Restoring the
        // default action first is what makes the raise fatal — under the
        // runtime's `SIG_IGN` it would be discarded.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            libc::raise(libc::SIGPIPE);
        }
        // Reached only when the parent left `SIGPIPE` blocked, so the
        // signal is pending rather than delivered. The status is the one a
        // shell would have shown for the death.
        std::process::exit(128 + libc::SIGPIPE)
    }

    /// There is no `SIGPIPE` to die of. No message either way: a reader
    /// that left is not something the operator needs telling about.
    #[cfg(not(unix))]
    fn reader_gone() -> ! {
        std::process::exit(i32::from(crate::commands::EXIT_FAILED))
    }
}

fn usage_error(msg: &str) -> ExitCode {
    diag!("holdfast: {msg}\n\n{USAGE}{PLATFORM_NOTE}");
    ExitCode::from(commands::EXIT_USAGE)
}

fn main() -> ExitCode {
    // First statement in the process, and before the runtime exists: a
    // panic in the runtime builder, in a tokio worker, or in a blocking
    // pool thread all reach the same hook, and on `holdfast daemon run`
    // that hook's output is `daemon.log`. Installing it per-subcommand
    // would leave the two failures above it uncovered for no gain — see
    // `holdfast_core::diag::install_panic_hook` for why one site.
    diag::install_panic_hook();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            diag!("holdfast: could not start the async runtime: {e}");
            return ExitCode::from(commands::EXIT_UNREACHABLE);
        }
    };
    let code = rt.block_on(run());
    rt.shutdown_timeout(SHUTDOWN_GRACE);
    code
}

async fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|a| a == name);

    match args.first().map(String::as_str) {
        Some("mcp") => commands::mcp(flag("--no-daemon")).await,
        Some("daemon") => match args.get(1).map(String::as_str) {
            Some("run") => commands::daemon_run().await,
            Some("start") => commands::daemon_start(),
            Some("stop") => commands::daemon_stop(flag("--force")).await,
            Some("status") => commands::daemon_status(flag("--json")).await,
            Some(other) => usage_error(&format!("unknown `daemon` subcommand `{other}`")),
            None => usage_error("`daemon` needs one of run|start|stop|status"),
        },
        Some("list") => commands::list(flag("--json")).await,
        Some("logs") => {
            let Some(session) = args.get(1).filter(|a| !a.starts_with("--")) else {
                return usage_error("`logs` needs a session id or name");
            };
            let tail = match args.iter().position(|a| a == "--tail") {
                Some(i) => match args.get(i + 1).and_then(|n| n.parse::<usize>().ok()) {
                    Some(n) => Some(n),
                    None => return usage_error("`--tail` needs a number"),
                },
                None => None,
            };
            commands::logs(session, tail, flag("--raw")).await
        }
        Some("attach") => {
            let Some(session) = args.get(1).filter(|a| !a.starts_with("--")) else {
                return usage_error("`attach` needs a session id or name");
            };
            commands::attach(session, flag("--allow-echo")).await
        }
        Some("watch") => {
            let Some(session) = args.get(1).filter(|a| !a.starts_with("--")) else {
                return usage_error("`watch` needs a session id or name");
            };
            commands::watch(session).await
        }
        // **Dispatched, and deliberately absent from `USAGE` above.**
        // This workspace has no clap, so the plan's `hide = true` is this:
        // the arm exists, the banner does not mention it, and
        // `holdfast pty-worker --help` still answers. It is spawned by the
        // daemon once per session (milestone 0.0.10a) and is not a command
        // to run by hand; advertising it in the banner would make an
        // internal protocol endpoint look like a user surface.
        Some("pty-worker") => commands::pty_worker(&args[1..]).await,
        Some("version") => commands::version(),
        Some(other) => usage_error(&format!("unknown subcommand `{other}`")),
        None => {
            diag!("{USAGE}{PLATFORM_NOTE}");
            ExitCode::from(commands::EXIT_USAGE)
        }
    }
}
