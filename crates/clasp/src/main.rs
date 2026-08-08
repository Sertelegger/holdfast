use std::process::ExitCode;

const USAGE: &str = "\
clasp — Claude's Live Agent Shell Proxy

USAGE:
    clasp mcp        Run the MCP server on stdio
    clasp version    Print version information
";

#[tokio::main]
async fn main() -> ExitCode {
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
