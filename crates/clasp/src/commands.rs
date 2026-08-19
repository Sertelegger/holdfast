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
use std::process::ExitCode;
use std::sync::Arc;

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

/// `clasp daemon stop` — idempotent; exit 0 when nothing was running.
pub async fn daemon_stop(force: bool) -> ExitCode {
    let client = match connect(ClientKind::Cli).await {
        Ok(c) => c,
        Err(ClientError::Connect { .. }) => {
            println!("no daemon running");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("clasp daemon stop: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let params = server::StopParams {
        force: Some(force),
        timeout_secs: None,
    };
    match client
        .call::<_, server::StopOutcome>(method::METHOD_DAEMON_STOP, &params)
        .await
    {
        Ok(outcome) => {
            println!(
                "daemon stopped ({} session(s) terminated)",
                outcome.sessions_terminated
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("clasp daemon stop: {e}");
            ExitCode::from(EXIT_FAILED)
        }
    }
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
