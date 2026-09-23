//! Subcommand bodies. Parsing and printing live here; every piece of
//! state comes from `holdfast-core` (spec §3.5).

// `RuntimePaths` is gated here and NOT in `holdfast-core`, and the split is
// deliberate. The type stays cross-platform there because `audit`, `diag`,
// `config` and `mcp` all resolve log paths through it on every transport.
// This crate is the CLI, and every one of its remaining users — `daemon_*`,
// `list`, `logs`, `attach`, `watch` — is Unix-only, so on Windows the import
// itself is what goes unused.
#[cfg(unix)]
use holdfast_core::daemon::paths::RuntimePaths;
#[cfg(unix)]
use holdfast_core::daemon::{server, spawn};
// The `diag!` macro, not the module — every diagnostic below goes to
// stderr, and on `holdfast daemon run` stderr is `daemon.log`, which §9.2
// lists as a redacted boundary. `println!` is left alone throughout:
// that is the subcommands' actual answer, and `holdfast logs --raw` is
// specified to be unredacted.
use holdfast_core::diag;
#[cfg(unix)]
use holdfast_core::mcp::shim::ShimServer;
// The daemon's own vocabulary for `held_back_cause`, so `held_back_note`
// branches on the enum rather than on string literals kept in step by
// hand — see its doc comment.
#[cfg(unix)]
use holdfast_core::output::HeldBackCause;
#[cfg(unix)]
use holdfast_core::protocol::client::{ClientError, ControlClient};
#[cfg(unix)]
use holdfast_core::protocol::handshake::ClientKind;
#[cfg(unix)]
use holdfast_core::protocol::method;
#[cfg(unix)]
use holdfast_core::protocol::CborValue;
#[cfg(unix)]
use rmcp::ServiceExt;
#[cfg(unix)]
use serde_json::{json, Value};
#[cfg(unix)]
use std::collections::HashSet;
#[cfg(unix)]
use std::path::Path;
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

/// §18.8 shim exit codes, in §18.8's row order — `0`, `1`, `2`, `3`,
/// `64`.
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
/// **The view ended, and it was not all of the session** (GH #200).
///
/// A code of its own rather than `EXIT_FAILED`, and the argument is a
/// collision rather than a preference. `1` is already what `watch` and
/// `attach` return for every §18.4b refusal — `holdfast watch
/// no-such-session` exits 1 — so `holdfast watch build > log` returning
/// 1 would mean *either* "you named the wrong session and captured
/// nothing" *or* "you captured all but twelve bytes". Those have
/// opposite remedies and a script cannot tell them apart, which is the
/// same class of defect as the exit 0 this issue is about, one step
/// along: a status that cannot be branched on is a status that is not
/// being read.
///
/// `2` was the other candidate and is wrong on its own terms — it means
/// *"there should be a daemon and I could not reach it"*, and here the
/// daemon was present throughout and said so. §18.8 leaves 3–63
/// unassigned; this takes the first.
///
/// **`#[cfg(unix)]`, unlike its neighbours, because its only readers
/// are.** `watch` and `attach` are Unix-only surfaces (§3.3), so
/// `finish` and `left_cleanly` are both `#[cfg(unix)]` and nothing on
/// Windows can produce this status. An unconditional constant compiles
/// there as dead code and `-D warnings` fails the `windows-cross` and
/// `windows-native` jobs — which is what it did, after the same
/// `#[cfg]` split had already been fixed once in this branch for
/// `queue_ancillary`. `EXIT_FAILED`/`EXIT_UNREACHABLE`/`EXIT_USAGE`
/// stay unconditional because they have readers on both platforms.
#[cfg(unix)]
pub const EXIT_TRUNCATED: u8 = 3;
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
#[cfg(unix)]
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
    let text = attach_notice(session, size);
    let body = match cols {
        Some(cols) => fit_to_width(&text, cols),
        None => text,
    };
    Some(format!("\x1b7\r\x1b[L{NOTICE_COLOURS}{body}\x1b[0m\x1b8"))
}

/// The notice's colours, SGR 256: white on the bar's purple.
#[cfg(unix)]
const NOTICE_COLOURS: &str = "\x1b[48;5;61m\x1b[38;5;231m";

/// What `holdfast attach` says once it has joined — the words, without
/// the layout. [`attach_banner`] inserts them above the prompt when the
/// daemon sends no opening screen; [`paint_snapshot`] puts them on the top
/// row when it does (GH #235).
#[cfg(unix)]
fn attach_notice(session: &str, size: Option<(u16, u16)>) -> String {
    let geometry = match size {
        Some((cols, rows)) if cols > 0 && rows > 0 => format!(" ({cols}x{rows})"),
        _ => String::new(),
    };
    format!(" holdfast: attached to {session}{geometry} — Ctrl-B d to detach ")
}

/// `holdfast watch`'s notice that it connected, and how to leave (GH
/// #235).
///
/// The dogfood pass: *"Watch rendered 0 bytes and printed no 'watching…'
/// line, so there is no sign it connected."* Two shapes, because a watch
/// has two kinds of output:
///
/// * **stdout is a terminal**: the notice is the top row of the opening
///   screen [`paint_snapshot`] draws, on *stdout* — the screen it
///   decorates — and nowhere else, so it neither pushes the child's prompt
///   off the bottom nor sits where the child's next line lands;
/// * **stdout is not a terminal** (`holdfast watch s > log`): nothing is
///   painted and nothing may be written into the capture, so the notice
///   is a sentence on stderr, and only if stderr is a terminal a human is
///   reading.
///
/// `None` when neither is a terminal: a script needs no reassurance.
#[cfg(unix)]
pub(crate) fn watch_banner(
    session: &str,
    size: Option<(u16, u16)>,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> Option<WatchBanner> {
    let geometry = match size {
        Some((cols, rows)) if cols > 0 && rows > 0 => format!(" ({cols}x{rows})"),
        _ => String::new(),
    };
    if stdout_is_terminal {
        return Some(WatchBanner::OnScreen(format!(
            " holdfast: watching {session}{geometry} — Ctrl-C to stop "
        )));
    }
    if stderr_is_terminal {
        return Some(WatchBanner::Sentence(format!(
            "holdfast watch: watching {session}{geometry} — Ctrl-C to stop"
        )));
    }
    None
}

/// Where [`watch_banner`] goes.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WatchBanner {
    /// The words for the top row of the opening screen, on stdout.
    OnScreen(String),
    /// A line for stderr.
    Sentence(String),
}

/// §7.5's `ScreenSnapshot`, as the bytes that paint it on a terminal of
/// `local` size (GH #235). **Split out so a test can render it** through
/// a real emulator, for [`attach_banner`]'s reason: this is cursor
/// arithmetic, and an assertion that the stream contains the bytes the
/// code just wrote cannot see a row land in the wrong place.
///
/// * **The whole screen is repainted** — `ESC[H ESC[2J`, then each row at
///   its own absolute position — because the picture is a grid, and the
///   terminal it lands on holds whatever the human had there before.
/// * **The rows kept are the ones that matter when the terminal is
///   shorter than the session**: a window ending at the cursor or the
///   last row with text on it, whichever is lower, so the prompt the
///   child is waiting at is on screen rather than below it. Each row is
///   clipped to the local width in display columns (`fit_to_width`'s
///   reason: a CJK row is two columns a character).
/// * **The cursor goes where the child left it**, because the child's
///   next write lands there — a picture with the cursor anywhere else
///   has the live stream start in the wrong column.
/// * **The terminal's modes are left alone** — no alternate screen, no
///   hidden cursor — although the frame says whether the child is using
///   either. This client is a pass-through and restores nothing on the
///   way out but `termios`, so a mode it switched on at the join is a
///   mode `Ctrl-B d` leaves switched on: a human detaching from `vim`
///   would be returned to their shell inside the alternate screen, or
///   with no cursor. The fields are on the wire for a renderer that owns
///   its terminal — the web UI's — and a pass-through paints the picture
///   into whatever screen the human already has.
///
/// * **A `notice` takes the top row, and the picture the rows below it.**
///   That is where the client says it has joined and how to leave. The
///   older notice was a line *inserted above the prompt*, which was sound
///   while the terminal showed nothing of the session — and which, over a
///   picture whose prompt sits on the last row, pushes the prompt off the
///   bottom of the screen: the one line the human attached to see. The top
///   row is out of the way of the child's next write and of a prompt
///   repaint, and a full-screen program's first redraw simply paints over
///   it, which a one-shot notice can afford.
///
/// Plain text: the tool's grid has no attributes, and the child's own
/// repaints bring colour back as it redraws.
#[cfg(unix)]
pub(crate) fn paint_snapshot(
    lines: &[String],
    cursor: (u16, u16),
    local: Option<(u16, u16)>,
    notice: Option<&str>,
) -> Vec<u8> {
    let (cursor_row, cursor_col) = (cursor.0 as usize, cursor.1 as usize);
    let mut out = String::from("\x1b[0m\x1b[H\x1b[2J");
    let (width, height) = match local {
        Some((cols, rows)) if cols > 0 && rows > 0 => (Some(cols as usize), Some(rows as usize)),
        _ => (None, None),
    };
    // No room for a notice on a one-row terminal; the picture wins.
    let notice = notice.filter(|_| height.is_none_or(|h| h >= 2));
    let offset = usize::from(notice.is_some());
    if let Some(text) = notice {
        let body = match width {
            Some(w) => fit_to_width(text, w),
            None => text.to_string(),
        };
        out.push_str(&format!("\x1b[1;1H{NOTICE_COLOURS}{body}\x1b[0m"));
    }
    let height = height.map(|h| h - offset);
    if !lines.is_empty() {
        let last_text = lines
            .iter()
            .rposition(|l| !l.trim_end().is_empty())
            .unwrap_or(0);
        let bottom = last_text.max(cursor_row).min(lines.len() - 1);
        let top = match height {
            Some(h) => (bottom + 1).saturating_sub(h),
            None => 0,
        };
        for (i, line) in lines[top..=bottom].iter().enumerate() {
            // An empty row is already painted by the clear. A row with
            // text is written as the grid has it, trailing spaces
            // included — `Password: ` ends in one the child drew, and a
            // renderer that trimmed it would leave the cursor a column
            // away from the text in front of it.
            if line.trim_end().is_empty() {
                continue;
            }
            let text = match width {
                Some(w) => clip_to_width(line, w),
                None => line.clone(),
            };
            out.push_str(&format!("\x1b[{};1H{text}", i + 1 + offset));
        }
        let row = cursor_row.saturating_sub(top) + offset;
        let col = match width {
            Some(w) => cursor_col.min(w.saturating_sub(1)),
            None => cursor_col,
        };
        out.push_str(&format!("\x1b[{};{}H", row + 1, col + 1));
    }
    out.into_bytes()
}

/// `s` cut to at most `cols` display columns — [`fit_to_width`] without
/// the padding, because a painted row must not overwrite the cells past
/// its own text.
#[cfg(unix)]
fn clip_to_width(s: &str, cols: usize) -> String {
    use unicode_width::UnicodeWidthChar;
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
    out
}

/// The line `holdfast attach` draws when a secret is asked for (GH #236).
///
/// **Labelled, and never the prompt again.** The client used to render
/// `\r\n` + `prompt_text` + `\r\n`: when the child had drawn
/// `Password: ` itself, the human saw `Password:` twice with nothing
/// saying the second was Holdfast's, and when the agent had raised the
/// request its words were indistinguishable from the program's. So:
///
/// * `echo_drop` — the text *is* the line the child just drew, which is
///   on the screen above; repeating it is the duplicate, so it is not;
/// * `tool_call` — the text is the agent's description, shown and
///   **attributed to the agent**, because a person about to type a
///   credential is owed the difference between a program's prompt and a
///   claim about one;
/// * absent — a daemon older than 1.5 that cannot say — the text is
///   quoted neutrally rather than attributed to anybody.
///
/// §5.2 keeps an *adopting* call's text off the wire entirely (it would
/// let an agent relabel a prompt a human may already be typing into), so
/// an echo-raised request adopted by a tool call is still `echo_drop`
/// here and the agent's text is still not shown. That is specified, not
/// an omission.
///
/// The text arrives redacted and stripped of anything that can move the
/// cursor (`redact_for_display`), so quoting it cannot rewrite this line.
#[cfg(unix)]
pub(crate) fn secret_prompt_label(prompt_text: &str, raised_by: Option<&str>) -> String {
    let text = prompt_text.trim();
    let what = match raised_by {
        Some("echo_drop") => "the session is reading a secret at the prompt above".to_string(),
        _ if text.is_empty() => "the session is waiting for a secret".to_string(),
        Some("tool_call") => format!("the agent asks for a secret: “{text}”"),
        _ => format!("secret requested: “{text}”"),
    };
    format!(
        "\r\n[holdfast] {what} — type it here; it is not shown and goes only to the \
         session. Enter sends it, Ctrl-C abandons.\r\n"
    )
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
const RESIZE_SETTLE: Duration = Duration::from_millis(150);

#[cfg(unix)]
pub const EXIT_SIGHUP: u8 = 128 + 1;
#[cfg(unix)]
pub const EXIT_SIGTERM: u8 = 128 + 15;

#[cfg(unix)]
fn paths() -> anyhow::Result<RuntimePaths> {
    Ok(RuntimePaths::discover()?)
}

#[cfg(unix)]
fn empty() -> CborValue {
    CborValue::Map(Vec::new())
}

#[cfg(unix)]
async fn connect(kind: ClientKind) -> Result<ControlClient, ClientError> {
    let paths = RuntimePaths::discover().map_err(|source| ClientError::Connect {
        path: "runtime directory".into(),
        source,
    })?;
    ControlClient::connect(&paths.control_sock(), kind).await
}

/// The in-process half, which is `--no-daemon` on Unix and the *only*
/// transport on Windows (§3.3, §3.6). Extracted so both callers below run
/// exactly the same code rather than two copies that can drift.
async fn serve_in_process() -> ExitCode {
    match holdfast_core::mcp::serve_stdio().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diag!("holdfast mcp: {e}");
            ExitCode::from(no_daemon_exit_code(&e))
        }
    }
}

/// `holdfast mcp [--no-daemon]`
pub async fn mcp(no_daemon: bool) -> ExitCode {
    // On Unix, `--no-daemon` is the documented escape hatch and the shape
    // the Windows build reuses.
    if no_daemon {
        return serve_in_process().await;
    }

    mcp_hybrid().await
}

/// **Windows serves stdio rather than refusing, and says so once.**
///
/// §3.3/§3.6 make stdio the only transport there, so the useful answer to a
/// bare `holdfast mcp` is the in-process server — refusing would leave the
/// platform with no working MCP command at all. What it must not do is let
/// the operator believe they got hybrid mode: the difference is visible only
/// when the client exits and takes every session with it, which is exactly
/// the surprise §3.3 documents.
///
/// A paired function rather than a `#[cfg]` block inside [`mcp`], matching
/// `attach`/`watch` above. The block form needs an explicit `return` to
/// type-check once the Unix arm is compiled out, and clippy then reads that
/// `return` as needless on Windows and only on Windows — a lint fighting a
/// `#[cfg]`, which is a `#[allow]` waiting to happen.
#[cfg(windows)]
async fn mcp_hybrid() -> ExitCode {
    diag!(
        "holdfast mcp: hybrid mode is not available on Windows native \
         (§3.3, §3.6) — there is no daemon, so this is serving stdio \
         in-process. Sessions end when this process does. Use WSL for a \
         daemon that outlives the client."
    );
    serve_in_process().await
}

/// The hybrid path: auto-spawn a daemon (§7.3) and serve `ShimServer` over
/// stdio against it.
#[cfg(unix)]
async fn mcp_hybrid() -> ExitCode {
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
const STOP_RPC_TIMEOUT: Duration = Duration::from_secs(server::DEFAULT_STOP_GRACE_SECS as u64 + 5);

/// What the `daemon/stop` RPC did, kept separate from what `--force`
/// then does about it.
#[cfg(unix)]
enum StopRpc {
    Stopped(server::StopOutcome),
    /// Nothing was listening on the control socket.
    NotRunning,
    /// Something was there and the call did not come back with an
    /// outcome — including the case where it did not come back at all.
    Failed(String),
}

#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
    //
    // **`apply_holdback` on the `--tail` arm, and it is not decoration
    // (GH #169).** `tail_lines` alone is §4.1's per-call bypass, and this
    // surface is named a non-member of it, twice: *"the exemption covers
    // exactly those two arguments on the one tool that takes them, and
    // nothing else"*, and then, by name, *"`--raw` is that surface's
    // opt-in and it is audited; `--tail` is not an opt-in to anything."*
    // The distinction has to be carried by what the CLI **sends**: the
    // daemon may not recover it from `client_kind`, which is audit
    // attribution and never a redaction input (REQ-SEC-018).
    let mut args = match tail_lines {
        Some(n) => json!({
            "session": session,
            "tail_lines": n,
            "apply_holdback": true,
            "max_bytes": 256 * 1024,
        }),
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
    // §4.1's holdback can now shorten this read, so say so — on stderr,
    // because stdout is the log and this surface's point is that it
    // survives being piped somewhere. Silence here would read as "the
    // output ended", which is the one thing it does not mean.
    //
    // **Flush first.** `print!` goes through Rust's `LineWriter` and
    // `diag!` writes an unbuffered, locked stderr, so `holdfast logs X
    // 2>&1 | tail` spliced the note into the middle of the log text.
    // Ordering two streams is the writer's job, not the reader's.
    if data["held_back"] == json!(true) {
        let _ = std::io::Write::flush(&mut std::io::stdout());
        diag!("holdfast logs: {}", held_back_note(raw, &data));
    }
    ExitCode::SUCCESS
}

/// What `holdfast logs` says on stderr when the read came back
/// `held_back: true`.
///
/// **`held_back` is a disjunction, and one sentence described one of its
/// terms as if it were both.** `output/mod.rs` computes it as
/// `safety_end < w.cap_end`, and two independent rules lower
/// `safety_end`: §4.1's partial-secret holdback and REQ-O-008's
/// unfinished trailing escape. The note read *"a secret may still be
/// arriving (§4.1). Read again to pick up the rest."* for both — a
/// security claim on the case where it is false.
///
/// There were three. GH #14's window bound was the third, it moved with
/// neither `buffer.head` nor anything else, and this function's last
/// branch told the reader to *"read again"* against it — advice that
/// could never succeed, which is GH #195 on this surface. It is no
/// longer a holdback at all: such a read now makes full progress and the
/// region the window could not judge carries `[REDACTED:unresolved]`. So
/// there is no arm for it below, and every cause that remains is one a
/// retry can clear — with the single exception the second bullet names.
///
/// Two readings are decisively wrong and both are fixed here:
///
/// * **`--raw`.** `redact: false` makes `holdback_boundary` return
///   `w.head` *before* this field is computed, so §4.1's mechanism is
///   provably switched off — and the same read writes a
///   `redaction_disabled` row saying so. The only rule left that can
///   fire is REQ-O-008's, which is gated on `ansi == Strip` and not on
///   `redact`, and which requires a **live** child. Naming §4.1 there
///   asserts a protection that is not running.
/// * **A child that has exited.** §4.1: *"If a process stops mid-token,
///   the partial stays withheld — correct"*, and REQ-O-005 states the
///   consequence — quiescence does **not** release the holdback. So
///   nothing is "still arriving" and "read again" can never succeed.
///   §4.1 names the recourse in the same breath: the agent *"may take
///   the audited `redact: false` path if it genuinely needs the bytes"*,
///   which on this surface is `--raw` (§4.1:476, and it is audited).
///
/// **What it is told apart *by*, and what it used to be told apart by.**
/// This function inferred the cause from `state` and its own `--raw`,
/// because the daemon did not say. The daemon now answers exactly, in
/// `held_back_cause` beside `held_back`, so the inference is gone and
/// only the two qualifications that are this *surface's* own — `--raw`,
/// and REQ-O-005's ended session — are decided here.
///
/// The `state` branch survives on its own merits and is not a guess: it
/// qualifies `in_flight_secret`, which is REQ-O-005's case and the one
/// place where a transient cause is transient in name only.
///
/// The older reasoning, still true, about what will *not* serve:
/// `dropped_incomplete_escape` is unusable twice over — it is a
/// `ProcessedRead` field `mcp/tools.rs` never serialises, and it flags
/// the escape being *dropped*, the arm that does **not** set
/// `held_back`. `redactions` counts redactions inside the returned
/// bytes; a partial secret matches no rule by definition, so it is `{}`
/// in exactly the case of interest.
#[cfg(unix)]
fn held_back_note(raw: bool, data: &Value) -> &'static str {
    // **Through `HeldBackCause::from_wire`, and not a `match` on string
    // literals.** The daemon's vocabulary lives in
    // `output::HeldBackCause::as_str`; literals here would keep step
    // with it by hand, and a rename would leave every arm falling into
    // the catch-all — which prints the least specific wording for every
    // cause, with nothing red. Parsing into the enum makes the arms
    // below exhaustive, so a third cause is a compile error in this file
    // rather than a silent fallback.
    //
    // **An absent field and an unrecognised word are not the same
    // thing, and collapsing them makes this function assert something
    // it does not know.** An older daemon sends no cause at all, and
    // the arms below are entitled to guess from `state` the way this
    // function always did. A *newer* daemon sending a third cause is
    // saying the boundary is something this build has no name for, and
    // the guess is then a claim about a mechanism that did not exist
    // when this binary was compiled — printing *"the session has ended
    // with a partial secret in its tail"* at an operator who has no
    // partial secret and no ended session.
    //
    // So `Unknown` is its own case and routes to the hedged wording,
    // which names the possibilities rather than choosing one.
    enum Cause {
        Known(HeldBackCause),
        Unknown,
        Absent,
    }
    let cause = match data["held_back_cause"].as_str() {
        Some(w) => match HeldBackCause::from_wire(w) {
            Some(c) => Cause::Known(c),
            None => Cause::Unknown,
        },
        None => Cause::Absent,
    };
    // `Exited` and `Dead` are the two terminal states (`SessionState`);
    // an unknown spelling from a newer daemon reads as live, which is
    // the reading that advises a harmless retry.
    let ended = matches!(data["state"].as_str(), Some("Exited") | Some("Dead"));
    match cause {
        // The `raw` half is kept as a *guard on this arm* rather than as
        // a branch of its own below, because a current daemon always
        // sends a cause when `held_back` is true — so an arm reachable
        // only through the no-cause path would never print this, and the
        // sentence it carries is the accurate one: `redact: false` makes
        // `holdback_boundary` return `w.head` before `held_back` is
        // computed, so §4.1 is provably not what stopped the read.
        Cause::Known(HeldBackCause::IncompleteEscape) if raw => {
            "output stops short at an unfinished escape sequence \
             (REQ-O-008). Redaction is off on this read, so §4.1's \
             holdback is not what stopped it. Read again to pick up the \
             rest."
        }
        Cause::Known(HeldBackCause::IncompleteEscape) => {
            "output stops short at an unfinished escape sequence \
             (REQ-O-008), which is withheld only while the child is \
             alive to finish it. Read again to pick up the rest."
        }
        // REQ-O-005's case, and the only one a retry cannot clear: a
        // session that has stopped producing output produces no bytes to
        // move §4.1's boundary with.
        Cause::Known(HeldBackCause::InFlightSecret) if ended => {
            "output stops short, and stays that way: the session has \
             ended with a partial secret in its tail, which §4.1 keeps \
             withheld (REQ-O-005 — quiescence does not release it). \
             Reading again returns the same bytes; `--raw` is this \
             surface's audited opt-in."
        }
        Cause::Known(HeldBackCause::InFlightSecret) => {
            "output stops short: a secret may still be arriving in the \
             tail, so §4.1 is withholding from where it starts. Read \
             again to pick up the rest."
        }
        Cause::Absent if raw => {
            // `redact: false` makes `holdback_boundary` return `w.head`
            // before `held_back` is computed, so §4.1's mechanism is
            // provably switched off and the same read writes a
            // `redaction_disabled` row saying so. Kept as a branch
            // because it is still the right thing to print against a
            // daemon too old to send a cause.
            "output stops short at an unfinished escape sequence \
             (REQ-O-008). Redaction is off on this read, so §4.1's \
             holdback is not what stopped it. Read again to pick up the \
             rest."
        }
        Cause::Absent if ended => {
            "output stops short, and stays that way: the session has \
             ended with a partial secret in its tail, which §4.1 keeps \
             withheld (REQ-O-005 — quiescence does not release it). \
             Reading again returns the same bytes; `--raw` is this \
             surface's audited opt-in."
        }
        // Absent with nothing else to go on, and **`Unknown` too**: a
        // cause this build cannot name is a boundary it cannot describe,
        // so it says what it does know — that something is being
        // withheld and that retrying is the documented move — and names
        // no mechanism.
        Cause::Absent | Cause::Unknown => {
            "output stops short: the tail is not vouched for yet — a \
             secret may still be arriving, or an escape sequence is \
             unfinished (§4.1, REQ-O-008). Read again to pick up the \
             rest."
        }
    }
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

/// What a viewing client knows about how much of the session it was
/// actually shown (GH #200).
///
/// **Two states and not a `bool`, because the two are told differently.**
/// A gap has a size and the stream continued past it; a `slow_consumer`
/// ending has no size at all — everything from that instant on was
/// never queued, and the daemon has no count of what the child went on
/// to print. Collapsing them would mean either inventing a number for
/// the second or throwing away the one the first has.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truncation {
    /// Nothing was reported missing. **Not a claim that nothing was:**
    /// it is the absence of a report, which is exactly what this issue
    /// was about, and it is only as strong as the daemon's reporting.
    None,
    /// **At least** `n` bytes are missing from what was rendered, summed
    /// over every gap.
    ///
    /// A lower bound and not a total, for `observer` connections. The
    /// daemon counts the hole in the **raw** session stream — since GH
    /// #210, bytes the session's ring buffer evicted before this
    /// connection read them, measured from the stream offsets — and an
    /// observer renders the *redacted* stream — `StreamRedactor` can
    /// withhold on its own account, and its withholding window is not
    /// this number — and the redactor announces its own drops in band,
    /// with `[REDACTED:unresolved]` where the value was. Two mechanisms,
    /// two notices, neither one the other's total. For `interactive`
    /// there is no redactor and the two coincide. The CLI says *"at
    /// least"* for that reason; a hard total would be the same kind of
    /// over-claim this issue is about.
    Gap(u64),
}

#[cfg(unix)]
impl Truncation {
    fn saw_gap(&mut self, bytes: u64) {
        *self = match *self {
            Self::None => Self::Gap(bytes),
            Self::Gap(n) => Self::Gap(n.saturating_add(bytes)),
        };
    }
}

/// Tell the operator the stream skipped bytes, at the point it skipped
/// them.
///
/// **And that they are gone, which is new with GH #210.** A gap used to
/// be a broadcast drop, with the bytes still in the ring buffer, and this
/// line sent the operator to `holdfast logs` for them. A connection now
/// resumes from the ring whenever it falls behind, so the only hole left
/// is the part the ring had already evicted — which `holdfast logs`,
/// reading that same ring, does not have either. Saying otherwise would
/// send a person looking for bytes that no longer exist anywhere.
///
/// Through `diag!` and therefore stderr, **not** through [`render`]:
/// stdout is the session's own byte stream and a client that wrote its
/// own prose into it would corrupt every `holdfast watch > file`. It is
/// also why this is not rendered inline at the column the gap occurred
/// in, which would read better and would be the same mistake.
#[cfg(unix)]
fn report_gap(what: &str, bytes: u64) {
    diag!(
        "holdfast {what}: at least {bytes} bytes of output were dropped here and are not \
         shown — this view fell further behind than the session's output buffer reaches, \
         so they are gone"
    );
}

/// §7.5's `Detached`, rendered, and the exit status that goes with it.
///
/// **`slow_consumer` is not a success and this is the one place that is
/// decided.** Both clients returned `ExitCode::SUCCESS` for every value
/// of `reason`, so a view that had lost nine tenths of a build log
/// exited 0 and a script could not tell it from a clean detach. The
/// **The other two reasons are not a verdict on their own, and that is
/// the whole of the ordering here.** `session_exit` and
/// `daemon_shutdown` say the *session* ended or the daemon went away,
/// and neither is a statement about how much this client saw — so they
/// fall through to `left_cleanly`, which answers that question from the
/// gaps. An earlier revision of this comment stopped at *"still exit
/// 0"*, which is false the moment a gap has been reported, and a gap
/// does not end a stream: `Truncation` is sticky by design, so a
/// 12-byte hole early in a session that then exits cleanly is exit
/// `EXIT_TRUNCATED`. That is the intended answer — the operator's
/// capture really is missing twelve bytes — and it is written here
/// because the sentence it replaces read as a promise of 0.
///
/// **A `u8` rather than an `ExitCode`** so `attach` can tell a clean
/// ending from the others after a stall (GH #210); both callers convert
/// at the `return`.
///
/// `attach` no longer reaches the `slow_consumer` arm — it holds the
/// terminal instead ([`hold_after_stall`]) — so the sentence is
/// `watch`'s, and it now says what the reason means since GH #210: the
/// client stopped reading, not that it read too slowly.
#[cfg(unix)]
fn finish(what: &str, reason: &str, truncated: Truncation) -> u8 {
    if reason == "slow_consumer" {
        // No byte count: see `Truncation`. What is knowable is where to
        // get the rest, and the ring buffer has as much of it as it still
        // holds (REQ-O-005) — not necessarily all of it, after a stall
        // long enough to be detached for.
        diag!(
            "holdfast {what}: detached ({reason}) — this client stopped reading, and this \
             view is incomplete from here on; `holdfast logs` has the session's recent \
             output, as far back as its buffer reaches"
        );
        return EXIT_TRUNCATED;
    }
    diag!("holdfast {what}: detached ({reason})");
    left_cleanly(what, truncated)
}

/// The exit status for an ending that was nobody's failure — the client
/// detached, stdin closed, the session ended — **once a gap has already
/// been reported**.
///
/// [`EXIT_TRUNCATED`] carries the argument for the code itself. What is
/// worth saying here is the shape: this is the **only** place a gap can
/// reach the exit status, because `finish` answers `slow_consumer`
/// before it looks — so a row that pairs a gap with a `slow_consumer`
/// ending exercises none of this.
///
/// The paths that reach this with `Truncation::None` are unchanged and
/// still exit 0, which is what `mcp-smoke.sh` asserts of `Ctrl-B d` and
/// of `watch` under `SIGINT`.
#[cfg(unix)]
fn left_cleanly(what: &str, truncated: Truncation) -> u8 {
    match truncated {
        Truncation::None => 0,
        Truncation::Gap(n) => {
            diag!("holdfast {what}: at least {n} bytes of this session were never shown");
            EXIT_TRUNCATED
        }
    }
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
///
/// `allow_echo` is `--allow-echo`, and it sets `SecretInput.allow_echo`
/// on every secret this attachment submits (GH #137). The daemon
/// otherwise declines to write a credential into a child that has not
/// dropped `ECHO`, because the line discipline echoes it into the ring
/// buffer and `read_output` hands it back to the agent in the clear.
///
/// **A flag and not a key chord, which is a real limitation and is stated
/// rather than hidden.** The chord would be the better affordance — it is
/// answerable at the moment the prompt is in front of you, which is when
/// the terminal's behaviour is actually visible. Building one means an
/// interactive affordance in raw mode, which is the same CLI work
/// `ServerFrame::BindingApprovalRequired`'s arm declines to do below and
/// for the same reason. So the decision is declared for the attachment,
/// up front, by the person who knows which child they are attaching to.
#[cfg(unix)]
pub async fn attach(session: &str, allow_echo: bool) -> ExitCode {
    use holdfast_core::attach::{AttachMode, AttachRole};
    use std::os::unix::io::AsRawFd;

    let (mut rd, mut wr) = match dial_attach(
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

    let mut keys = spawn_stdin_reader();
    let mut winch =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()) {
            Ok(s) => s,
            Err(e) => {
                diag!("holdfast attach: cannot watch for terminal resizes: {e}");
                return ExitCode::from(EXIT_FAILED);
            }
        };

    // **Whether this view is a complete record of the session** (GH
    // #200). Set by an `OutputGap` and by nothing else: a
    // `slow_consumer` ending is the same fact stated as a termination,
    // and `attach` tracks that one separately, in `stalled` below. An
    // earlier version of this comment claimed both, and claiming both is
    // what hid the fact that the `Gap` arm of `left_cleanly` was reached
    // by no test at all — every row paired a gap with a `slow_consumer`
    // ending, so the early return answered them and the arm could have
    // been deleted green. Carried across a reattach: a gap is a fact
    // about what this process showed, not about one connection.
    let mut truncated = Truncation::None;
    // **Whether a stall cut this process's view short** (GH #210). A
    // `slow_consumer` detach loses everything the session printed while
    // this client was not reading, and a reattach shows the screen as it
    // now stands, not what scrolled past in between — so however the
    // attachment ends afterwards, the view was not all of the session,
    // and the exit status says so.
    let mut stalled = false;

    loop {
        match attach_connected(
            session,
            allow_echo,
            rd,
            wr,
            tty,
            &mut keys,
            &mut winch,
            &mut sigterm,
            &mut sighup,
            &mut truncated,
        )
        .await
        {
            AttachEnd::Exit(code) if code == 0 && stalled => {
                diag!(
                    "\rholdfast attach: this view missed what the session printed while it \
                     was detached; `holdfast logs` has as much of it as the session's buffer \
                     still holds"
                );
                return ExitCode::from(EXIT_TRUNCATED);
            }
            AttachEnd::Exit(code) => return ExitCode::from(code),
            AttachEnd::Stalled => {
                stalled = true;
                match hold_after_stall(tty, &mut keys, &mut sigterm, &mut sighup).await {
                    Held::Reattach => {
                        match dial_attach(
                            session,
                            AttachMode::ReadWrite,
                            AttachRole::Interactive,
                            "attach",
                        )
                        .await
                        {
                            Dialled::Ok(r, w) => (rd, wr) = (r, w),
                            Dialled::Refused(code) => return ExitCode::from(code),
                        }
                    }
                    Held::Leave => {
                        render(b"\r\n");
                        diag!(
                            "\rholdfast attach: left without reattaching; the session keeps \
                             running, and `holdfast logs` has its recent output, as far back \
                             as its buffer reaches"
                        );
                        return ExitCode::from(EXIT_TRUNCATED);
                    }
                    Held::Signalled(code) => return ExitCode::from(code),
                }
            }
        }
    }
}

/// How one attachment of `holdfast attach` ended.
#[cfg(unix)]
enum AttachEnd {
    /// Leave, with this status.
    Exit(u8),
    /// The daemon detached this client `slow_consumer` (GH #210): the
    /// terminal is held and the human asked what to do.
    Stalled,
}

/// One attachment of `holdfast attach`, from the handshake the caller
/// already completed to the ending — separated from [`attach`] so a
/// stall can end *this* and not the process (GH #210). The terminal, the
/// keyboard reader and the signal handlers belong to the process and are
/// lent; the socket and everything learned over it belong to the
/// attachment and are not carried into the next one.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn attach_connected(
    session: &str,
    allow_echo: bool,
    rd: tokio::net::unix::OwnedReadHalf,
    mut wr: tokio::net::unix::OwnedWriteHalf,
    tty: std::os::unix::io::RawFd,
    keys: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    winch: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
    sighup: &mut tokio::signal::unix::Signal,
    truncated: &mut Truncation,
) -> AttachEnd {
    use holdfast_core::attach::{ClientFrame, ServerFrame};
    use holdfast_core::protocol::frame;

    let mut frames = spawn_frame_reader(rd);

    // One at startup, so the session reflows to *this* terminal
    // immediately rather than at the first time the user drags a window.
    //
    // **Best effort, and returning `EXIT_UNREACHABLE` from a failure here
    // was GH #39.** This is the only frame the client sends that the user
    // did not ask for, and it goes out before a single frame past
    // `Attached` has been read — so a failure is `EPIPE` from a daemon
    // that closed *after* answering, which is not the same fact as a
    // daemon that cannot be reached.
    //
    // Attaching to an already-exited session is exactly that shape.
    // `forward_output` short-circuits on `!session.is_alive()`, so §7.5's
    // entire ending — `SessionExited` then `Detached { reason:
    // "session_exit" }` — is written and the socket closed while this
    // client is still installing two signal handlers, taking raw mode,
    // spawning two readers and registering `SIGWINCH`. The daemon is
    // entitled to win that race, and on a fast enough machine it wins it
    // every time. Returning from here then threw away a complete and
    // correct ending already sitting in this process's own receive
    // buffer, and did it **silently** — exit 2, an empty terminal, and no
    // diagnostic naming what went wrong.
    //
    // So the write is allowed to fail and the **reader** names the
    // ending: the loop below returns `SUCCESS` on `Detached` and
    // diagnoses a bare EOF as an unreachable daemon. That still covers a
    // daemon that is genuinely gone — a write half broken by a dead peer
    // is a read half that EOFs at once — so this cannot wait on a peer
    // that will never answer.
    if let Ok((cols, rows)) = crate::attach_tty::window_size(tty) {
        let _ = frame::write_frame(&mut wr, &ClientFrame::Resize { cols, rows }).await;
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
    // appends — since GH #66 by pushing `b'\n'` onto the buffer it writes
    // in one `write_all`, where it used to be `writeln!`'s. The mechanism
    // moved; the newline did not. That newline is therefore **load-bearing
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
    // The id of a request this client has already answered, held until the
    // daemon says what became of it (GH #137).
    //
    // **Without this the submitting human is the one person never told.**
    // `secret` is cleared the instant the frame goes out — it has to be,
    // or the keyboard stays captured — and the `SecretRequestClosed` arm
    // below is guarded on `secret` matching. So the client that answered
    // the prompt dropped the answer to its own question on the floor,
    // while every *other* attached client got it. That was survivable
    // while every close a submitter could provoke was `fulfilled`; a
    // daemon that can now decline the write makes it a silently discarded
    // credential, which is the defect the decline exists to prevent.
    let mut submitted: Option<String> = None;

    loop {
        tokio::select! {
            body = frames.recv() => {
                let Some(body) = body else {
                    // EOF with no `Detached` before it: the daemon died
                    // or the socket broke. Distinct from every clean
                    // ending, which returns from inside this match.
                    diag!("holdfast attach: the daemon closed the connection");
                    return AttachEnd::Exit(EXIT_UNREACHABLE);
                };
                let f = match holdfast_core::attach::decode_server_frame(&body) {
                    Ok(f) => f,
                    Err(e) => {
                        diag!("holdfast attach: undecodable frame: {e}");
                        return AttachEnd::Exit(EXIT_FAILED);
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
                    ServerFrame::OutputGap { bytes, .. } => {
                        truncated.saw_gap(bytes);
                        report_gap("attach", bytes);
                    }
                    ServerFrame::SessionExited { code } => {
                        diag!("holdfast attach: the session exited ({code})");
                    }
                    // **`slow_consumer` is not an ending for `attach`**
                    // (GH #210). The human is still at this keyboard,
                    // typing at a session they cannot see, and the two
                    // things this client could do next both deliver
                    // those keystrokes somewhere they were not meant for
                    // — the local shell if it exits, or the session, blind,
                    // if it reconnects. `attach` holds the terminal
                    // instead and asks; see `hold_after_stall`.
                    ServerFrame::Detached { reason } if reason == "slow_consumer" => {
                        return AttachEnd::Stalled;
                    }
                    ServerFrame::Detached { reason } => {
                        return AttachEnd::Exit(finish("attach", &reason, *truncated));
                    }
                    // **The session's screen as it stands** (GH #235),
                    // painted before the stream resumes where it ends.
                    // An idle session at its prompt used to render as an
                    // empty terminal until somebody pressed Enter.
                    // The notice rides on the picture's top row rather
                    // than being inserted above the prompt later, which
                    // over a painted screen pushes the prompt off the
                    // bottom — see `paint_snapshot`. Taken, so the older
                    // path below never prints a second one.
                    ServerFrame::ScreenSnapshot {
                        lines,
                        cursor_row,
                        cursor_col,
                        ..
                    } => {
                        let size = crate::attach_tty::window_size(tty).ok();
                        let notice = banner.take().map(|_| attach_notice(session, size));
                        render(&paint_snapshot(
                            &lines,
                            (cursor_row, cursor_col),
                            size,
                            notice.as_deref(),
                        ));
                    }
                    ServerFrame::AwaitingSecret {
                        request_id,
                        prompt_text,
                        raised_by,
                    } => {
                        // On its own line and labelled as Holdfast's, so
                        // it cannot be mistaken for the child drawing its
                        // prompt a second time (GH #236).
                        render(secret_prompt_label(&prompt_text, raised_by.as_deref()).as_bytes());
                        secret = Some((request_id, crate::attach_tty::SecretLine::default()));
                    }
                    ServerFrame::SecretRequestClosed { request_id, outcome } => {
                        // **Two matches, two different clears, and
                        // collapsing them tears down a live prompt.**
                        // The first version of this arm `if`-ed on either
                        // and then cleared both — so a close for the
                        // request this client *answered* (`submitted`)
                        // arriving after a **new** `AwaitingSecret` had
                        // raised took the mask off the new one. Every
                        // keystroke after that goes out as ordinary
                        // `Input`, unmasked, into the prompt the human
                        // thinks they are typing a password at.
                        //
                        // The window is real rather than theoretical: the
                        // close is broadcast from the daemon's ack task
                        // after the *writer thread* answers, while the
                        // next raise rides the echo-drop edge on a
                        // different task, and the writer blocks on a full
                        // PTY buffer — which `CLAUDE.md` records as the
                        // ordinary macOS case, not an edge one.
                        let answering = secret.as_ref().is_some_and(|(id, _)| *id == request_id);
                        let mine = answering || submitted.as_deref() == Some(request_id.as_str());
                        if answering {
                            secret = None;
                        }
                        if mine {
                            submitted = None;
                            // **The one outcome that gets a sentence
                            // rather than a token** (GH #137). Every other
                            // word here names something the human already
                            // knows they did or watched happen; this one
                            // names a thing Holdfast did *instead of* what
                            // they asked for, and `secret request
                            // not_echo_off` does not say that a password
                            // they typed was thrown away. The token stays
                            // in the line so it is still greppable and
                            // still matches the agent's
                            // `secret_cancelled.reason`.
                            if outcome == "not_echo_off" {
                                diag!(
                                    "holdfast attach: secret request not_echo_off — this \
                                     session's terminal is still echoing, so the value was \
                                     discarded and nothing was sent to the child. Re-attach \
                                     with `--allow-echo` to send it anyway, accepting that \
                                     the child will echo it into the session's output."
                                );
                            } else {
                                diag!("holdfast attach: secret request {outcome}");
                            }
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
                    return AttachEnd::Exit(left_cleanly("attach", *truncated));
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
                                let mut f = ClientFrame::SecretInput {
                                    request_id: id.clone(),
                                    bytes,
                                    allow_echo,
                                };
                                submitted = Some(id.clone());
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
                                    return AttachEnd::Exit(EXIT_UNREACHABLE);
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
                                // Nothing was submitted, so there is no
                                // close of this client's making to wait
                                // for; clearing it keeps a stale id from
                                // claiming the next request's close.
                                submitted = None;
                                render(b"\r\n");
                                diag!("holdfast attach: secret entry abandoned");
                                let f = ClientFrame::Input { bytes };
                                if frame::write_frame(&mut wr, &f).await.is_err() {
                                    return AttachEnd::Exit(EXIT_UNREACHABLE);
                                }
                            }
                        },
                        None => {
                            let f = ClientFrame::Input { bytes: forward };
                            if frame::write_frame(&mut wr, &f).await.is_err() {
                                return AttachEnd::Exit(EXIT_UNREACHABLE);
                            }
                        }
                    }
                }
                if detached {
                    let _ = frame::write_frame(&mut wr, &ClientFrame::Detach).await;
                    render(b"\r\n");
                    return AttachEnd::Exit(left_cleanly("attach", *truncated));
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
                return AttachEnd::Exit(EXIT_SIGTERM);
            }
            _ = sighup.recv() => {
                // No `render`: `SIGHUP` says this terminal has already
                // gone away, so the only thing left worth doing is
                // telling the daemon and putting the termios back for
                // whoever inherits the fd.
                let _ = frame::write_frame(&mut wr, &ClientFrame::Detach).await;
                diag!("holdfast attach: SIGHUP — detaching; the session keeps running");
                return AttachEnd::Exit(EXIT_SIGHUP);
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
                        return AttachEnd::Exit(EXIT_UNREACHABLE);
                    }
                }
            }
        }
    }
}

/// What the human chose after a stall — see [`hold_after_stall`].
#[cfg(unix)]
enum Held {
    Reattach,
    Leave,
    Signalled(u8),
}

/// **Hold the terminal after a `slow_consumer` detach, and let the human
/// say what happens next** (GH #210).
///
/// The dogfood pass found the hazard: *"a detach mid-takeover sends the
/// human's next keystrokes to their local shell"*. `holdfast attach` put
/// the terminal back and exited, so whatever the human was typing into the
/// session — a command, an answer to a prompt, a password — went to the
/// shell they had attached from instead.
///
/// **Held, rather than reconnected, and the choice is about keystrokes
/// in flight.** A client that reconnected by itself would deliver the
/// same keystrokes to the session instead — typed against a screen the
/// human has not seen for as long as the client was stalled, at a prompt
/// that may since have been replaced by another. A client that exits
/// delivers them to the local shell. Holding is the only one of the
/// three where nothing typed before the human has seen the current state
/// reaches either shell; the cost is one keypress, and `Enter` reattaches
/// with the screen repainted from scratch (GH #235) so the choice to type
/// again is an informed one.
///
/// Typed-ahead is discarded on the way in — both what the terminal had
/// queued (`tcflush`) and what the reader thread had already read — so a
/// key pressed before the notice was on screen is not taken as the
/// answer to it. A key already in flight between the two can still land;
/// the only keys that act are `Enter` and `Ctrl-B d`, and both are safe
/// to have pressed by accident — see the loop below for why no letter
/// does.
///
/// **Not done for `session_exit` or `daemon_shutdown`**: there is no
/// session to go back to, and returning the human to their shell is what
/// `ssh` and `tmux` do in the same position.
#[cfg(unix)]
async fn hold_after_stall(
    tty: std::os::unix::io::RawFd,
    keys: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    sigterm: &mut tokio::signal::unix::Signal,
    sighup: &mut tokio::signal::unix::Signal,
) -> Held {
    // SAFETY: `tcflush` takes the fd and a queue selector and touches no
    // memory of ours; a failure leaves typed-ahead in place, which the
    // drain below and the narrow key set above both bound.
    unsafe { libc::tcflush(tty, libc::TCIFLUSH) };
    while keys.try_recv().is_ok() {}

    // `\r` in front of each line: the terminal is still raw, so the
    // newline `diag!` appends moves down without returning, and a second
    // line would start where the first one ended.
    render(b"\r\n");
    diag!(
        "\rholdfast attach: this client stopped reading, so the daemon detached it \
         (slow_consumer). The session is still running."
    );
    diag!(
        "\rholdfast attach: nothing you type goes anywhere now — press Enter to reattach, \
         or Ctrl-B d to return to your shell."
    );

    // **Two keys act, and neither is a letter.** A human who has not read
    // the notice is typing a command: a letter that reattached would send
    // the rest of the word into the session, and one that left would
    // send it into the local shell — the hazard this exists to remove,
    // one keystroke late. `Enter` reattaches: the line it ends was typed
    // while held and goes nowhere, and what follows is typed at a freshly
    // painted screen. `Ctrl-B d` leaves, because it is how an attachment
    // is left and cannot be typed by accident.
    let mut detach = crate::attach_tty::DetachKey::default();
    loop {
        tokio::select! {
            chunk = keys.recv() => {
                let Some(chunk) = chunk else {
                    return Held::Leave;
                };
                let (pressed, detached) = detach.feed(&chunk);
                if detached {
                    return Held::Leave;
                }
                if pressed.iter().any(|&b| b == b'\r' || b == b'\n') {
                    diag!("\rholdfast attach: reattaching");
                    return Held::Reattach;
                }
            }
            _ = sigterm.recv() => {
                render(b"\r\n");
                diag!("\rholdfast attach: SIGTERM — leaving; the session keeps running");
                return Held::Signalled(EXIT_SIGTERM);
            }
            _ = sighup.recv() => {
                diag!("holdfast attach: SIGHUP — leaving; the session keeps running");
                return Held::Signalled(EXIT_SIGHUP);
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
    let stdout_is_terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let stderr_is_terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    // The local geometry, for clipping the opening screen — `TIOCGWINSZ`
    // on stdout, which is the terminal the screen is painted on.
    let local_size = || {
        use std::os::unix::io::AsRawFd;
        crate::attach_tty::window_size(std::io::stdout().as_raw_fd()).ok()
    };

    // Same coalescing as `attach`, for the same reason (GH #66): a watcher
    // receives a `Resize` per frame of somebody else's window drag, and it
    // has no keyboard to escape the flood with — only `Ctrl+C`, which ends
    // the session view entirely.
    let mut pending_resize: Option<(u16, u16)> = None;
    let resize_settle = tokio::time::sleep(RESIZE_SETTLE);
    tokio::pin!(resize_settle);

    // See `attach`'s copy: whether this view is a complete record (GH
    // #200). `watch` is the surface the issue was measured on and the
    // one a human is most likely to be reading as a record of what
    // happened.
    let mut truncated = Truncation::None;

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
                    // **The screen as it stands, then the notice that
                    // this is a watch** (GH #235). Painted only onto a
                    // terminal: `holdfast watch s > log` is a capture of
                    // what the session prints from here on, and a picture
                    // drawn into it would be bytes the session never
                    // printed. The notice goes where a human will see it
                    // — see `watch_banner` — and after the paint, which
                    // would otherwise clear it.
                    ServerFrame::ScreenSnapshot {
                        session: id,
                        cols,
                        rows,
                        lines,
                        cursor_row,
                        cursor_col,
                        ..
                    } => {
                        let size = if stdout_is_terminal {
                            local_size()
                        } else {
                            Some((cols, rows))
                        };
                        match watch_banner(&id, size, stdout_is_terminal, stderr_is_terminal) {
                            Some(WatchBanner::OnScreen(notice)) => render(&paint_snapshot(
                                &lines,
                                (cursor_row, cursor_col),
                                size,
                                Some(&notice),
                            )),
                            Some(WatchBanner::Sentence(line)) => diag!("{line}"),
                            None => {}
                        }
                    }
                    ServerFrame::OutputGap { bytes, .. } => {
                        truncated.saw_gap(bytes);
                        report_gap("watch", bytes);
                    }
                    ServerFrame::SessionExited { code } => {
                        diag!("holdfast watch: the session exited ({code})");
                    }
                    ServerFrame::Detached { reason } => {
                        return ExitCode::from(finish("watch", &reason, truncated));
                    }
                    // A watcher is told a secret is being asked for and
                    // **cannot answer it**: `SecretInput` is a write
                    // frame, refused `read_only_attach` by §7.5's table.
                    // Reported so the human knows why the session has
                    // stopped drawing — and, since GH #236, whose words
                    // the description is, for `attach`'s reason.
                    ServerFrame::AwaitingSecret {
                        prompt_text,
                        raised_by,
                        ..
                    } => match raised_by.as_deref() {
                        Some("tool_call") if !prompt_text.trim().is_empty() => diag!(
                            "holdfast watch: the agent asked for a secret (“{}”); only an \
                             attached client can answer it",
                            prompt_text.trim()
                        ),
                        _ => diag!(
                            "holdfast watch: the session is waiting for a secret; only an \
                             attached client can answer it"
                        ),
                    },
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
                return ExitCode::from(left_cleanly("watch", truncated));
            }
        }
    }
}

/// §3.6 marks `holdfast watch` `✗` on Windows native **permanently**,
/// for the same reason as `holdfast attach`.
///
/// [`Remedy::Wsl`] and not an MCP tool, even though `get_screen_state`
/// renders a session: `watch` is a surface for a *human* at a terminal,
/// and a tool call an agent makes is not a substitute for one.
#[cfg(windows)]
pub async fn watch(_session: &str) -> ExitCode {
    unsupported("watch", Remedy::Wsl)
}

/// §3.6 marks `holdfast attach` `✗` on Windows native **permanently** —
/// there is no daemon there to attach to.
///
/// The arm exists so `main.rs`'s unconditional match compiles on that
/// target: a `#[cfg(unix)]`-only function referenced by an unconditional
/// caller is a hard error under `windows-cross`, not a warning.
///
/// **It routes through [`unsupported`] rather than writing its own
/// sentence, and that is the point of the helper.** This arm and `watch`'s
/// each carried a hand-rolled copy of the refusal literal, while the CI job
/// that greps for that literal exercised only the helper's callers — so
/// rewording either copy left every job in the workflow green. There is now
/// exactly one place in this crate that prints the sentence.
#[cfg(windows)]
pub async fn attach(_session: &str, _allow_echo: bool) -> ExitCode {
    unsupported("attach", Remedy::Wsl)
}

// **The six `#[cfg(windows)]` arms below exist for `main.rs`'s benefit, and
// five of them are refusals rather than ports.** Every one of these
// subcommands is a client of, or is, the daemon — and §3.3/§3.6 give Windows
// native no daemon at all. `main.rs` dispatches them unconditionally, so a
// `#[cfg(unix)]`-only function with no counterpart is a hard error under
// `windows-cross` rather than a warning; that is the same reason `attach` and
// `watch` above have had arms since 0.0.6, and they now share this section's
// [`unsupported`] helper.
//
// **The sixth is `daemon stop`, which answers and exits 0** — see its own
// note below. Counting it among the refusals is the mistake `PLATFORM_NOTE`
// made, and it is the one an operator writing a teardown script pays for.
//
// `EXIT_USAGE` (64) and not `EXIT_UNREACHABLE` (2), matching `attach` and
// `watch`: 2 means "there should be a daemon and I could not reach it", which
// would send a Windows operator hunting for a process that is not supposed to
// exist. 64 is "you asked for something this build does not have".

/// §3.6: there is no daemon to run on Windows native.
#[cfg(windows)]
pub async fn daemon_run() -> ExitCode {
    unsupported("daemon run", Remedy::Wsl)
}

/// §3.6: there is no daemon to start on Windows native.
#[cfg(windows)]
pub fn daemon_start() -> ExitCode {
    unsupported("daemon start", Remedy::Wsl)
}

/// **`stop` is the one that succeeds, and it is not an inconsistency.**
///
/// §3.2 makes `daemon stop` idempotent: stopping a daemon that is not running
/// prints "no daemon running" and exits 0, pinned on Unix by
/// `stopping_a_daemon_that_is_not_running_succeeds`. On Windows native there
/// is never a daemon, so that is not an edge case here — it is the only case,
/// and the truthful answer to "stop the daemon" is that there is none and
/// nothing needs doing. Returning `EXIT_USAGE` would make this the single
/// subcommand whose Windows behaviour contradicts its own documented
/// contract, and would break a caller that reasonably treats `daemon stop` as
/// safe to run unconditionally in a teardown script.
///
/// The platform note still goes to stderr, so an operator who expected a
/// daemon learns there is none; the answer on stdout is the same sentence
/// Unix prints, because it is equally true.
#[cfg(windows)]
pub async fn daemon_stop(_force: bool) -> ExitCode {
    diag!(
        "holdfast daemon stop: there is no daemon on Windows native (§3.6). \
         Sessions live inside `holdfast mcp` and end with it. Use WSL for a \
         daemon that outlives the client."
    );
    println!("no daemon running");
    ExitCode::SUCCESS
}

/// §3.6: there is no daemon to report on Windows native.
///
/// **`--json` still prints a JSON object, and the refusal still goes to
/// stderr with exit [`EXIT_USAGE`].** The reasoning, since the alternative
/// (refuse and say `--json` is dead here) was the other honest option:
///
/// `--json` is a promise about *stdout*, made to a program. On Unix the
/// daemon-down path answers `{"running": false}` and exits 2; before this,
/// Windows answered with empty stdout, so the one caller that exists —
/// `.claude/commands/holdfast/doctor.md`, which runs `holdfast daemon status
/// --json` as its first step and has no Windows arm — got nothing to parse
/// and no way to tell "no daemon here, ever" from "the command is broken".
/// A flag whose contract holds on one platform and evaporates on another is
/// worse than one that never existed, because the caller has no reason to
/// check. Emitting the object costs nothing: it is the same shape Unix
/// emits when it is down, plus two fields that say the state is permanent.
///
/// The exit code stays 64 and does **not** become Unix's 2. 2 means "there
/// should be a daemon and I could not reach it", which would send a Windows
/// operator hunting for a process that is not supposed to exist — the whole
/// reason these arms chose 64 — and it must not fork on the presence of
/// `--json` either. So a `--json` caller reads the object; anyone reading
/// the code reads 64 and the sentence on stderr.
#[cfg(windows)]
pub async fn daemon_status(as_json: bool) -> ExitCode {
    if as_json {
        // `running: false` is exactly what the Unix down-path prints, so a
        // consumer that only knows that key needs no Windows arm.
        // `supported` and `reason` are additive, and are what distinguish a
        // daemon that is down from a platform that has none: only the first
        // is worth retrying or starting.
        println!(
            "{}",
            serde_json::json!({
                "running": false,
                "supported": false,
                "reason": "no daemon on Windows native (§3.6); sessions live \
                           inside `holdfast mcp` and end with it",
            })
        );
    }
    unsupported("daemon status", Remedy::Wsl)
}

/// §3.6: `list` reads the daemon's registry over the control socket, and
/// there is neither on Windows native. Sessions there live and die inside
/// the `holdfast mcp` process, so the MCP `list_sessions` tool is the
/// answer and this subcommand has nothing to enumerate.
#[cfg(windows)]
pub async fn list(_as_json: bool) -> ExitCode {
    unsupported("list", Remedy::McpTool("list_sessions"))
}

/// §3.6: `logs` reads a session's ring buffer out of the daemon, same as
/// `list`. The `read_output` tool is the in-process equivalent.
#[cfg(windows)]
pub async fn logs(_session: &str, _tail_lines: Option<usize>, _raw: bool) -> ExitCode {
    unsupported("logs", Remedy::McpTool("read_output"))
}

/// Where the operator is sent instead, which is **not** the same answer
/// for all seven callers.
///
/// The remedy was a per-command fact recorded only in the doc comments
/// above — `list`'s said "the MCP `list_sessions` tool is the answer",
/// `logs`'s said "`read_output` is the in-process equivalent" — while the
/// message every caller actually printed sent all of them to WSL. So an
/// operator was told to install a second operating system to enumerate
/// sessions the `holdfast mcp` in front of them could already list. This
/// enum is that knowledge moved from the comment into the argument.
#[cfg(windows)]
enum Remedy {
    /// The subcommand *is* the daemon, or drives one: `daemon run|start|
    /// status`, and the two human terminal surfaces. Nothing in this
    /// process can stand in for it, so the answer is a platform that has
    /// a daemon.
    Wsl,
    /// A `holdfast mcp` running here already answers the question, through
    /// the named MCP tool. True for `list` and `logs` specifically because
    /// the Unix bodies above are thin wrappers over `tool/list_sessions`
    /// and `tool/read_output` — the same calls, with a human on the end —
    /// and on this platform the sessions live inside the MCP process
    /// itself.
    McpTool(&'static str),
}

/// The one refusal message. **Seven** subcommands reach it — `daemon run`,
/// `daemon start`, `daemon status`, `list`, `logs`, `attach` and `watch` —
/// so it is what keeps them from drifting into seven wordings of the same
/// fact.
///
/// It said "six" through the commit that dropped `daemon stop` from the
/// callers, and separately `attach` and `watch` kept hand-rolled copies of
/// the sentence instead of calling this, which is how the count came to be
/// wrong in both directions at once. Both are fixed. The seven are named
/// above rather than left to a count, so a caller added or removed brings
/// a list to update with it.
///
/// **No other line in this crate emits the `Windows native` refusal
/// substring** — the arms above print it only by coming here. The
/// `windows-2022` CI job greps stderr for exactly that substring on every
/// one of the seven, so rewording it here turns seven cases red together,
/// which is the intent; rewording a *copy* turned none of them red, which
/// is what the copies cost.
///
/// stderr, via `diag!`, and never stdout: on this platform stdout is the
/// MCP JSON-RPC transport for `holdfast mcp` and the answer channel for
/// everything else.
#[cfg(windows)]
fn unsupported(what: &str, remedy: Remedy) -> ExitCode {
    // The tail is built separately rather than as a second `diag!` arm, so
    // the shared half above stays a single literal.
    let tail = match remedy {
        Remedy::Wsl => "there is no daemon. Sessions live inside `holdfast mcp` and end \
                        with it. Use WSL for a daemon that outlives the client."
            .to_string(),
        Remedy::McpTool(tool) => format!(
            "there is no daemon to ask. Sessions live inside `holdfast mcp` and end \
             with it, so the `{tool}` MCP tool is what answers this here — WSL is \
             only needed for a daemon that outlives the client."
        ),
    };
    diag!("holdfast {what} is not supported on Windows native (§3.6): {tail}");
    ExitCode::from(EXIT_USAGE)
}

/// What `holdfast pty-worker --help` prints.
///
/// **Hidden means absent from the banner, not undiagnosable.** The
/// subcommand is not in `USAGE` because no operator runs it — the daemon
/// does, once per session — but an operator who finds one in `ps` or in
/// `daemon.log` and asks it what it is deserves an answer, and the answer
/// is where the leak this task exists to prevent gets explained.
#[cfg(unix)]
const PTY_WORKER_USAGE: &str = "\
holdfast pty-worker --socket <path>

INTERNAL. Spawned by the daemon, one per session, to hold that session's
PTY in its own process (milestone 0.0.10a). It is deliberately absent from
`holdfast --help`: it is not a command to run by hand, and a worker started
without a daemon listening on <path> exits within seconds.

The session's command, arguments, working directory and environment are
NOT on this command line. They arrive over the socket, because
/proc/<pid>/cmdline is world-readable on Linux and `ps` shows an argv to
every local user everywhere, while a session's environment can carry
credentials.
";

/// `holdfast pty-worker --socket <path>` — the hidden subcommand (§3.1).
///
/// Nine lines over `pty::worker::child::run`, because §3.5 puts parsing
/// and printing here and state in `holdfast-core`. Everything this
/// process says goes to stderr through `diag!`, which the daemon drains
/// into `daemon.log`; the one exception is `--help`, which is an answer
/// to a human and therefore stdout.
#[cfg(unix)]
pub async fn pty_worker(args: &[String]) -> ExitCode {
    use holdfast_core::pty::worker::child::{self, Argv};
    match child::parse_argv(args) {
        Argv::Help => {
            print!("{PTY_WORKER_USAGE}");
            ExitCode::SUCCESS
        }
        Argv::Usage(why) => {
            diag!("holdfast pty-worker: {why}\n\n{PTY_WORKER_USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
        Argv::Run(socket) => match child::run(&socket).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                // The one place a worker's refusal becomes words. It
                // reaches `daemon.log` through the stderr pipe the daemon
                // drains, redacted like every other `diag!`, and it
                // carries the reason and no PTY byte.
                diag!("holdfast pty-worker: {e}");
                ExitCode::from(EXIT_FAILED)
            }
        },
    }
}

/// The Windows arm, and **deliberately not §3.6's refusal message**.
///
/// The seven subcommands that print "not supported on Windows native"
/// are ones an operator types; this is not one, and the `windows-2022`
/// job greps that substring across exactly those seven. 0.0.10a ships no
/// Windows worker — REQ-CFG-007 defaults Windows to `in_process` until
/// 0.0.11 — so nothing on this platform spawns one, and a human who
/// reaches here has typed a subcommand that was never for them.
#[cfg(not(unix))]
pub async fn pty_worker(_args: &[String]) -> ExitCode {
    diag!(
        "holdfast pty-worker is an internal subcommand and has no Windows implementation \
         in this release: Windows sessions use the in-process PTY backend."
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

// Unix-only for the same reason the subcommands above are: these rows drive
// `daemon_stop_within` against a wedged daemon on a real Unix socket, and
// exercise the attach banner. Neither exists on a target with no daemon.
#[cfg(all(test, unix))]
mod tests {
    use super::{attach_banner, fit_to_width, held_back_note};

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
    /// The trailing `\n` is fed deliberately: `diag::emit` appends one —
    /// `line.push(b'\n')` before a single `write_all`, since GH #66 — and
    /// that newline is what steps the cursor off the bar and onto the
    /// prompt. Deleting the push to "tidy" the emitter puts the cursor back
    /// on the bar, which is why both ends are named. See `attach_banner`.
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

    /// **`held_back_note` had no test at all, and the sentence it
    /// printed for GH #14's bound was advice that could never succeed**
    /// — the whole of GH #195 on this surface. That cause is gone, so
    /// what is left to pin is the property a reader acts on: the note
    /// tells them to read again exactly when reading again can work.
    ///
    /// Two directions, because either alone is satisfied by a constant.
    #[test]
    fn the_logs_note_tells_the_reader_to_retry_exactly_when_retrying_can_work() {
        use holdfast_core::output::HeldBackCause as Hb;

        // **Every spelling comes from `HeldBackCause::as_str`, never
        // from a literal here.** A literal would keep passing after a
        // rename while `held_back_note` fell into its catch-all — the
        // least specific wording for every cause, with nothing red. The
        // one literal below is deliberately a word the enum does not
        // have.
        let note = |cause: Option<Hb>, state: &str, raw: bool| {
            let mut d = serde_json::json!({ "state": state });
            if let Some(c) = cause {
                d["held_back_cause"] = serde_json::json!(c.as_str());
            }
            held_back_note(raw, &d)
        };

        // Every cause on a live session can clear, so every one of them
        // must advise the retry. Driven off `ALL` rather than a
        // hand-written list, so a third cause joins this loop by
        // existing.
        for cause in Hb::ALL {
            let live = note(Some(*cause), "Running", false);
            assert!(
                live.contains("Read again"),
                "{} can clear on a live session and must say so: {live}",
                cause.as_str()
            );
        }

        // REQ-O-005 qualifies exactly one of them: an in-flight secret
        // in a session that has ended is withheld for ever, and `--raw`
        // is this surface's audited opt-in.
        let dead = note(Some(Hb::InFlightSecret), "Exited", false);
        assert!(
            !dead.contains("Read again"),
            "a boundary nothing will move must not advise a retry: {dead}"
        );
        assert!(dead.contains("--raw"), "…and must name what does: {dead}");
        assert_eq!(dead, note(Some(Hb::InFlightSecret), "Dead", false));
        // …and the same cause on a live session says the opposite, so
        // the `state` qualifier is doing work rather than decorating.
        assert_ne!(dead, note(Some(Hb::InFlightSecret), "Running", false));

        // An older daemon sends no cause and a newer one may send a word
        // this build has never heard of. Neither may panic, and both get
        // the wording that advises a harmless retry — which is what this
        // function did for every case before the field existed.
        assert!(
            Hb::from_wire("a_cause_from_the_future").is_none(),
            "the fixture below has to be a word the enum does not have"
        );
        for unknown in [
            serde_json::Value::Null,
            serde_json::json!("a_cause_from_the_future"),
        ] {
            let d = serde_json::json!({ "state": "Running", "held_back_cause": unknown });
            let fallback = held_back_note(false, &d);
            assert!(fallback.contains("Read again"), "{fallback}");
        }

        // **A word this build has never heard of is not the same as no
        // word**, and the difference is a claim about a mechanism. A
        // newer daemon's third cause must not make this print a
        // description of one of the two causes it knows — on an *ended*
        // session the no-cause arm asserts *"a partial secret in its
        // tail"*, which would be a statement about a boundary this
        // binary has no name for.
        for state in ["Running", "Exited", "Dead"] {
            for raw in [true, false] {
                let future = held_back_note(
                    raw,
                    &serde_json::json!({
                        "state": state,
                        "held_back_cause": "a_cause_from_the_future",
                    }),
                );
                for named in ["partial secret", "escape sequence (REQ-O-008)"] {
                    assert!(
                        !future.contains(named),
                        "state {state} raw {raw}: an unrecognised cause named \
                         a mechanism this build cannot know is in play: {future}"
                    );
                }
                assert!(future.contains("Read again"), "{future}");
            }
        }
        // The field missing altogether is the older daemon, and reads
        // the same way.
        assert!(
            held_back_note(false, &serde_json::json!({ "state": "Running" }))
                .contains("Read again")
        );
        // …while an *ended* session with no cause keeps the wording it
        // had before the field existed, `--raw` and all.
        let old_dead = held_back_note(false, &serde_json::json!({ "state": "Exited" }));
        assert!(!old_dead.contains("Read again"), "{old_dead}");
        assert!(old_dead.contains("--raw"), "{old_dead}");
        // `--raw` keeps its own sentence on a daemon too old to answer,
        // because `redact: false` switches §4.1 off before `held_back`
        // is computed and naming §4.1 there asserts a protection that is
        // not running.
        assert!(note(None, "Running", true).contains("REQ-O-008"));

        // Every wire spelling round-trips, so `from_wire` cannot drift
        // from `as_str` and leave every arm above in the catch-all.
        for cause in Hb::ALL {
            assert_eq!(Hb::from_wire(cause.as_str()), Some(*cause));
        }
    }

    // ------------------------------------ GH #235: painting the opening screen

    fn grid(rows: &[&str], total: usize) -> Vec<String> {
        let mut v: Vec<String> = rows.iter().map(|r| r.to_string()).collect();
        v.resize(total, String::new());
        v
    }

    /// **The picture lands where it was, and the cursor where the child
    /// left it** — through a real emulator, over a terminal full of
    /// something else, because a byte-stream assertion cannot see a row
    /// land in the wrong place (GH #235).
    #[test]
    fn the_opening_screen_replaces_what_was_there_and_puts_the_cursor_back() {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(b"the human's own shell history\r\nmore of it\r\n$ ");
        let lines = grid(&["build output", "user@box $ "], 24);
        p.process(&paint_snapshot(&lines, (1, 11), Some((80, 24)), None));

        assert_eq!(row(&p, 0).trim_end(), "build output");
        assert_eq!(row(&p, 1).trim_end(), "user@box $");
        assert!(
            !p.screen().contents().contains("shell history"),
            "the terminal's previous contents survived the paint:\n{}",
            p.screen().contents()
        );
        assert_eq!(
            p.screen().cursor_position(),
            (1, 11),
            "the child's next write must land after its prompt"
        );
        assert!(!p.screen().hide_cursor());
    }

    /// **A terminal shorter than the session shows the rows around the
    /// cursor, not the top of the grid** — otherwise a 40-row session's
    /// prompt at row 35 is painted below a 24-row terminal's last line.
    /// And rows wider than the terminal are cut to it, in display columns.
    #[test]
    fn a_smaller_terminal_keeps_the_cursors_rows_and_clips_their_width() {
        // Text on every row down to the prompt's, and nothing below it —
        // a session that has scrolled its prompt near the bottom.
        let mut rows: Vec<String> = (0..40)
            .map(|i| {
                if i < 35 {
                    format!("row {i:02}")
                } else {
                    String::new()
                }
            })
            .collect();
        rows[35] = format!("{}PROMPT$ ", "端".repeat(50));
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(&paint_snapshot(&rows, (35, 108), Some((80, 24)), None));
        let bottom = row(&p, 23);
        assert!(
            bottom.starts_with('端'),
            "the cursor's row should be the last one painted: {bottom:?}"
        );
        assert!(
            !p.screen().contents().contains("row 00"),
            "rows far above the cursor were painted instead of the ones around it"
        );
        assert_eq!(
            p.screen().cursor_position().0,
            23,
            "the cursor must be on the prompt's row in the window"
        );
        assert!(
            p.screen().cursor_position().1 < 80,
            "the cursor was put past the terminal's last column"
        );
    }

    /// **The picture changes no terminal mode**, whatever the child's
    /// are: a pass-through that entered the alternate screen or hid the
    /// cursor at the join would leave both behind on `Ctrl-B d`, and the
    /// human back at their shell inside a screen with no scrollback, or
    /// with no cursor.
    #[test]
    fn the_picture_changes_no_terminal_mode() {
        let lines = grid(&["vim"], 24);
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(&paint_snapshot(&lines, (0, 0), Some((80, 24)), None));
        assert!(
            !p.screen().alternate_screen(),
            "the join entered the alternate screen"
        );
        assert!(!p.screen().hide_cursor(), "the join hid the human's cursor");
        assert_eq!(row(&p, 0).trim_end(), "vim");
    }

    /// **The join notice takes the top row, and the prompt stays on
    /// screen** (GH #235) — the case that made the older notice wrong over
    /// a painted screen: a session whose prompt is on its last row, joined
    /// from a terminal of the same size. Inserted above the prompt, the
    /// notice pushed the prompt off the bottom; on the top row it costs the
    /// session's first row instead, which is the one furthest from where
    /// the human is looking.
    #[test]
    fn the_join_notice_takes_the_top_row_and_the_prompt_stays_on_screen() {
        let mut lines: Vec<String> = (0..24).map(|i| format!("output {i:02}")).collect();
        lines[23] = "user@box $ ".into();
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(&paint_snapshot(
            &lines,
            (23, 11),
            Some((80, 24)),
            Some(" holdfast: attached to sess (80x24) — Ctrl-B d to detach "),
        ));
        assert!(row(&p, 0).contains("attached to sess"), "{:?}", row(&p, 0));
        assert_eq!(
            row(&p, 23).trim_end(),
            "user@box $",
            "the prompt was pushed off the screen by the notice"
        );
        assert_eq!(
            row(&p, 1).trim_end(),
            "output 01",
            "the rows below the notice shifted"
        );
        assert_eq!(
            p.screen().cursor_position(),
            (23, 11),
            "the child's next write must land after its prompt"
        );

        // And `watch`'s words ride the same row.
        let Some(WatchBanner::OnScreen(notice)) = watch_banner("sess", Some((80, 24)), true, true)
        else {
            panic!("a terminal stdout gets an on-screen notice");
        };
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(&paint_snapshot(
            &lines,
            (23, 11),
            Some((80, 24)),
            Some(&notice),
        ));
        assert!(row(&p, 0).contains("watching sess"), "{:?}", row(&p, 0));
        assert_eq!(row(&p, 23).trim_end(), "user@box $");
    }

    /// Into a capture, the notice is a sentence on stderr — or nothing,
    /// when nobody is reading stderr either.
    #[test]
    fn the_watch_notice_never_goes_into_a_capture() {
        assert_eq!(
            watch_banner("sess", Some((80, 24)), false, true),
            Some(WatchBanner::Sentence(
                "holdfast watch: watching sess (80x24) — Ctrl-C to stop".into()
            ))
        );
        assert_eq!(watch_banner("sess", Some((80, 24)), false, false), None);
    }

    // ---------------------------------- GH #236: whose words the prompt is

    /// **The child's own prompt is not repeated; an agent's description
    /// is attributed; an unknown source is quoted neutrally** — and every
    /// form says it is Holdfast's line (GH #236).
    #[test]
    fn the_secret_line_says_whose_words_it_is_and_never_repeats_the_childs() {
        let child = secret_prompt_label("Password: ", Some("echo_drop"));
        assert!(child.contains("[holdfast]"));
        assert!(
            !child.contains("Password"),
            "the child's prompt is already on screen; printing it again is the duplicate: \
             {child:?}"
        );
        let agent = secret_prompt_label("deploy key passphrase", Some("tool_call"));
        assert!(
            agent.contains("the agent asks for a secret: “deploy key passphrase”"),
            "{agent:?}"
        );
        let unknown = secret_prompt_label("Password: ", None);
        assert!(
            unknown.contains("secret requested: “Password:”"),
            "{unknown:?}"
        );
        assert!(
            !unknown.contains("agent"),
            "text of unknown provenance was attributed to the agent: {unknown:?}"
        );
        // An empty agent text is not rendered as empty quotes.
        let empty = secret_prompt_label("", Some("tool_call"));
        assert!(!empty.contains("“”"), "{empty:?}");
    }
}
