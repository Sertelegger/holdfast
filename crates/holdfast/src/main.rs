// Every diagnostic this binary writes goes through `holdfast_core::diag!`,
// which redacts. `holdfast daemon run`'s stderr *is* `daemon.log` (§9.2
// lists it as a redacted boundary), and `holdfast mcp`'s stderr is what an
// MCP client surfaces as server logs, so both are output boundaries in
// §9.2's sense. `print_stdout` is deliberately **not** denied: `holdfast
// list`, `holdfast logs` and `holdfast daemon status` write their real answers
// there, and `holdfast logs --raw` is specified to be unredacted.
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
    holdfast attach <session>         Take over the session's terminal
                                      (detach with Ctrl-B then d)
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
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

fn usage_error(msg: &str) -> ExitCode {
    diag!("holdfast: {msg}\n\n{USAGE}");
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
            commands::attach(session).await
        }
        Some("version") => commands::version(),
        Some(other) => usage_error(&format!("unknown subcommand `{other}`")),
        None => {
            diag!("{USAGE}");
            ExitCode::from(commands::EXIT_USAGE)
        }
    }
}
