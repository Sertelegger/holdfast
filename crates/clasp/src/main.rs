mod commands;

use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
clasp — Claude's Live Agent Shell Proxy

USAGE:
    clasp mcp [--no-daemon]        Run the MCP server on stdio
    clasp daemon run               Run the daemon in the foreground
    clasp daemon start             Start a detached daemon (idempotent)
    clasp daemon stop [--force]    Stop the daemon (idempotent)
    clasp daemon status [--json]   Report daemon health
    clasp list [--json]            List sessions
    clasp logs <session> [--tail N] [--raw]
                                   Print a session's output
    clasp version                  Print version information

ENVIRONMENT:
    CLASP_RUNTIME_DIR              Select a CLASP instance: relocates the
                                   sockets, pid file, lock file and the
                                   daemon log
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
    eprintln!("clasp: {msg}\n\n{USAGE}");
    ExitCode::from(commands::EXIT_USAGE)
}

fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("clasp: could not start the async runtime: {e}");
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
        Some("version") => commands::version(),
        Some(other) => usage_error(&format!("unknown subcommand `{other}`")),
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(commands::EXIT_USAGE)
        }
    }
}
