use std::process::ExitCode;

const USAGE: &str = "\
clasp — Claude's Live Agent Shell Proxy

USAGE:
    clasp mcp        Run the MCP server on stdio
    clasp version    Print version information
";

fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("clasp: could not start the async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let code = rt.block_on(run());
    // `send_input` hands its write to the blocking pool because the PTY
    // master is a blocking fd (see `mcp::tools`). If a child stopped
    // reading its terminal, that write is parked in the kernel — and Linux
    // does *not* wake it when the child dies, so the thread never returns.
    // Dropping the runtime waits for the blocking pool unconditionally,
    // which would leave `clasp mcp` hanging at exit long after it stopped
    // serving. Bound the wait instead: the process is on its way out.
    rt.shutdown_timeout(std::time::Duration::from_millis(250));
    code
}

async fn run() -> ExitCode {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("mcp") => match clasp_core::mcp::serve_stdio().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("clasp mcp: {e}");
                ExitCode::from(2)
            }
        },
        Some("version") => {
            println!("clasp {} (protocol 1.0)", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("clasp: unknown subcommand `{other}`\n\n{USAGE}");
            ExitCode::from(64)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(64)
        }
    }
}
