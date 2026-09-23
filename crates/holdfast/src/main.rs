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
                                      Print everything the session's
                                      buffer still holds. --tail N prints
                                      only the last N lines; --raw turns
                                      redaction off, and is audited
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

`holdfast help <subcommand>` or `holdfast <subcommand> --help` describes one
subcommand; `holdfast --version` is `holdfast version`.

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

/// A usage error at the top level: the whole banner, on stderr, exit 64.
fn usage_error(msg: &str) -> ExitCode {
    diag!("holdfast: {msg}\n\n{USAGE}{PLATFORM_NOTE}");
    ExitCode::from(commands::EXIT_USAGE)
}

/// A usage error inside one subcommand: that subcommand's own help, not
/// all of it (GH #233).
fn usage_error_in(path: &[&str], msg: &str) -> ExitCode {
    let help = help_text(path).unwrap_or_else(|| format!("{USAGE}{PLATFORM_NOTE}"));
    diag!("holdfast: {msg}\n\n{}", help.trim_end());
    ExitCode::from(commands::EXIT_USAGE)
}

/// One subcommand's entry in [`USAGE`], parsed out of the banner itself.
///
/// **The banner is the grammar (GH #233).** The parser used to be
/// `args.iter().any(|a| a == name)` per flag, so a flag nothing asked about
/// — `list --jsn`, `logs big --tial 5` — was silently dropped and the
/// command ran without it, exit 0. It now accepts exactly what each entry's
/// synopsis declares and refuses the rest. Reading that declaration out of
/// the banner, rather than keeping a second table beside it, is what stops
/// the two from drifting: a flag the banner does not document is a flag
/// the binary refuses, and a flag the banner documents cannot be missing
/// from the parser. `every_handler_reads_only_what_its_entry_declares`
/// pins the other direction.
///
/// The synopsis grammar is the banner's own: words after `holdfast` up to
/// the first bracket are the subcommand path, `<name>` is a required
/// positional, `[--flag]` a switch and `[--flag VALUE]` an option. The
/// synopsis ends at the first run of two spaces, where the description
/// column starts.
#[derive(Debug)]
struct Entry {
    /// `["daemon", "stop"]`.
    path: Vec<&'static str>,
    switches: Vec<&'static str>,
    options: Vec<&'static str>,
    /// Every one is required; none of today's subcommands has an optional
    /// positional.
    positionals: Vec<&'static str>,
    /// The entry's banner lines, verbatim, continuation lines included.
    lines: Vec<&'static str>,
}

fn entries() -> Vec<Entry> {
    let section = USAGE
        .split_once("USAGE:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("USAGE has a USAGE: section");
    let mut all: Vec<Entry> = Vec::new();
    for line in section.lines() {
        let body = line.trim_start();
        let indent = line.len() - body.len();
        let Some(synopsis) = body.strip_prefix("holdfast ").filter(|_| indent == 4) else {
            // A continuation line belongs to the entry above it.
            if let Some(last) = all.last_mut() {
                last.lines.push(line);
            }
            continue;
        };
        let synopsis = synopsis.split("  ").next().unwrap_or_default();
        let mut e = Entry {
            path: Vec::new(),
            switches: Vec::new(),
            options: Vec::new(),
            positionals: Vec::new(),
            lines: vec![line],
        };
        let mut words = synopsis.split(' ');
        while let Some(w) = words.next() {
            if let Some(flag) = w.strip_prefix('[') {
                match flag.strip_suffix(']') {
                    Some(switch) => e.switches.push(switch),
                    None => {
                        e.options.push(flag);
                        // The value's metavariable, `N]`.
                        words.next();
                    }
                }
            } else if w.starts_with('<') {
                e.positionals.push(w);
            } else {
                assert!(
                    e.switches.is_empty() && e.options.is_empty() && e.positionals.is_empty(),
                    "USAGE entry {line:?} has a bare word after its arguments"
                );
                e.path.push(w);
            }
        }
        all.push(e);
    }
    all
}

/// The help for one subcommand, or for a group of them (`daemon`): every
/// entry whose path starts with `path`. `None` when nothing does.
fn help_text(path: &[&str]) -> Option<String> {
    let lines: Vec<&str> = entries()
        .into_iter()
        .filter(|e| e.path.starts_with(path))
        .flat_map(|e| e.lines)
        .collect();
    (!lines.is_empty()).then(|| {
        format!(
            "USAGE:\n{}\n\n`holdfast --help` lists every subcommand, the environment and the files.\n",
            lines.join("\n")
        )
    })
}

/// What a subcommand's arguments said, checked against its [`Entry`].
#[derive(Debug, Default)]
struct Args {
    /// Every flag the entry declares, so a handler asking about one it
    /// does not is caught — see [`Args::switch`].
    declared: Vec<&'static str>,
    switches: Vec<&'static str>,
    options: Vec<(&'static str, String)>,
    positionals: Vec<String>,
}

impl Args {
    fn switch(&self, name: &str) -> bool {
        debug_assert!(
            self.declared.contains(&name),
            "a handler reads `{name}`, which its USAGE entry does not declare"
        );
        self.switches.contains(&name)
    }

    fn option(&self, name: &str) -> Option<&str> {
        debug_assert!(
            self.declared.contains(&name),
            "a handler reads `{name}`, which its USAGE entry does not declare"
        );
        self.options
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    fn positional(&self, i: usize) -> String {
        self.positionals.get(i).cloned().unwrap_or_default()
    }
}

#[derive(Debug)]
enum Parsed {
    Help,
    Run(Args),
}

/// Check `args` — everything after the subcommand path — against `e`.
///
/// Flags may come before or after the positionals (`logs --raw big` used
/// to say `logs` needs a session), `--flag=value` is the same as `--flag
/// value`, and `--` ends the flags, for a session whose name begins with a
/// dash. `--help`/`-h` anywhere before `--` asks for the help, whatever
/// else is on the line: someone who typed it wants the help.
fn parse(e: &Entry, args: &[String]) -> Result<Parsed, String> {
    if args
        .iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        return Ok(Parsed::Help);
    }
    let cmd = e.path.join(" ");
    let mut out = Args {
        declared: e.switches.iter().chain(&e.options).copied().collect(),
        ..Args::default()
    };
    let mut flags_done = false;
    let mut rest = args.iter();
    while let Some(a) = rest.next() {
        if !flags_done && a == "--" {
            flags_done = true;
            continue;
        }
        if !flags_done && a.len() > 1 && a.starts_with('-') {
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (a.as_str(), None),
            };
            if let Some(&switch) = e.switches.iter().find(|s| **s == name) {
                if inline.is_some() {
                    return Err(format!("`{switch}` takes no value"));
                }
                if !out.switches.contains(&switch) {
                    out.switches.push(switch);
                }
            } else if let Some(&option) = e.options.iter().find(|o| **o == name) {
                if out.options.iter().any(|(n, _)| *n == option) {
                    return Err(format!("`{option}` is given more than once"));
                }
                let value = match inline {
                    Some(v) => v.to_string(),
                    None => rest
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("`{option}` needs a value"))?,
                };
                out.options.push((option, value));
            } else {
                return Err(format!("`holdfast {cmd}` has no flag `{name}`"));
            }
            continue;
        }
        if out.positionals.len() == e.positionals.len() {
            return Err(format!("`holdfast {cmd}` takes no argument `{a}`"));
        }
        out.positionals.push(a.clone());
    }
    if let Some(missing) = e.positionals.get(out.positionals.len()) {
        let what = match *missing {
            "<session>" => "a session id or name",
            other => other,
        };
        return Err(format!("`{cmd}` needs {what}"));
    }
    Ok(Parsed::Run(out))
}

/// One invocation, decided and not yet run — so the decision is testable
/// without a daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cmd {
    Mcp { no_daemon: bool },
    DaemonRun,
    DaemonStart,
    DaemonStop { force: bool },
    DaemonStatus { json: bool },
    List { json: bool },
    Logs { session: String, tail: Option<usize>, raw: bool },
    Attach { session: String, allow_echo: bool },
    Watch { session: String },
    Version,
}

fn plan(path: &[&str], a: &Args) -> Result<Cmd, String> {
    Ok(match path {
        ["mcp"] => Cmd::Mcp {
            no_daemon: a.switch("--no-daemon"),
        },
        ["daemon", "run"] => Cmd::DaemonRun,
        ["daemon", "start"] => Cmd::DaemonStart,
        ["daemon", "stop"] => Cmd::DaemonStop {
            force: a.switch("--force"),
        },
        ["daemon", "status"] => Cmd::DaemonStatus {
            json: a.switch("--json"),
        },
        ["list"] => Cmd::List {
            json: a.switch("--json"),
        },
        ["logs"] => Cmd::Logs {
            session: a.positional(0),
            tail: match a.option("--tail") {
                None => None,
                Some(n) => Some(
                    n.parse::<usize>()
                        .map_err(|_| "`--tail` needs a number".to_string())?,
                ),
            },
            raw: a.switch("--raw"),
        },
        ["attach"] => Cmd::Attach {
            session: a.positional(0),
            allow_echo: a.switch("--allow-echo"),
        },
        ["watch"] => Cmd::Watch {
            session: a.positional(0),
        },
        ["version"] => Cmd::Version,
        other => {
            // An entry in the banner with no arm here. Unreachable while
            // `every_entry_in_the_banner_has_a_handler` is green.
            return Err(format!(
                "`holdfast {}` is in the usage banner and has no handler",
                other.join(" ")
            ));
        }
    })
}

async fn execute(cmd: Cmd) -> ExitCode {
    match cmd {
        Cmd::Mcp { no_daemon } => commands::mcp(no_daemon).await,
        Cmd::DaemonRun => commands::daemon_run().await,
        Cmd::DaemonStart => commands::daemon_start(),
        Cmd::DaemonStop { force } => commands::daemon_stop(force).await,
        Cmd::DaemonStatus { json } => commands::daemon_status(json).await,
        Cmd::List { json } => commands::list(json).await,
        Cmd::Logs { session, tail, raw } => commands::logs(&session, tail, raw).await,
        Cmd::Attach {
            session,
            allow_echo,
        } => commands::attach(&session, allow_echo).await,
        Cmd::Watch { session } => commands::watch(&session).await,
        Cmd::Version => commands::version(),
    }
}

/// `holdfast help [<subcommand>…]`, `holdfast --help`, `holdfast -h`.
///
/// **stdout and exit 0**, because help that was asked for is the answer
/// and not a usage error. REQ-A-002's stated verification is `holdfast
/// --help`, and it used to exit 64 as `unknown subcommand `--help``.
async fn help(topic: &[String]) -> ExitCode {
    let topic: Vec<&str> = topic.iter().map(String::as_str).collect();
    match topic.as_slice() {
        [] | ["--help" | "-h"] => {
            out::text(&format!("{USAGE}{PLATFORM_NOTE}"));
            ExitCode::SUCCESS
        }
        // Hidden from the banner, not from a direct question: its own
        // parser answers `--help`, and this is the same answer.
        ["pty-worker"] => commands::pty_worker(&["--help".to_string()]).await,
        path => match help_text(path) {
            Some(text) => {
                out::text(&text);
                ExitCode::SUCCESS
            }
            None => usage_error(&format!("no subcommand `{}`", path.join(" "))),
        },
    }
}

async fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<String> = match args.first().map(String::as_str) {
        None => {
            diag!("{USAGE}{PLATFORM_NOTE}");
            return ExitCode::from(commands::EXIT_USAGE);
        }
        Some("--help" | "-h" | "help") => return help(&args[1..]).await,
        // Spellings of the subcommand, so the rest of the line is held to
        // `holdfast version`'s grammar: `holdfast -V --json` is refused
        // exactly as `holdfast version --json` is.
        Some("--version" | "-V") => std::iter::once("version".to_string())
            .chain(args[1..].iter().cloned())
            .collect(),
        // **Dispatched, and deliberately absent from `USAGE` above.**
        // This workspace has no clap, so the plan's `hide = true` is this:
        // the arm exists, the banner does not mention it, and
        // `holdfast pty-worker --help` still answers. It is spawned by the
        // daemon once per session (milestone 0.0.10a) and is not a command
        // to run by hand; advertising it in the banner would make an
        // internal protocol endpoint look like a user surface. Its argv is
        // `holdfast-core`'s to parse (`pty::worker::child::parse_argv`).
        Some("pty-worker") => return commands::pty_worker(&args[1..]).await,
        Some(_) => args,
    };

    let all = entries();
    // The longest path the arguments begin with. No two entries share a
    // prefix at the same length, so there is never a tie.
    let found = all
        .iter()
        .filter(|e| e.path.len() <= args.len() && e.path.iter().zip(&args).all(|(p, a)| p == a))
        .max_by_key(|e| e.path.len());
    let Some(entry) = found else {
        return unresolved(&all, &args);
    };
    let parsed = match parse(entry, &args[entry.path.len()..]) {
        Ok(Parsed::Run(a)) => a,
        Ok(Parsed::Help) => {
            out::text(&help_text(&entry.path).unwrap_or_default());
            return ExitCode::SUCCESS;
        }
        Err(msg) => return usage_error_in(&entry.path, &msg),
    };
    match plan(&entry.path, &parsed) {
        Ok(cmd) => execute(cmd).await,
        Err(msg) => usage_error_in(&entry.path, &msg),
    }
}

/// The first word names no entry: a group with its verb missing or wrong
/// (`daemon`, `daemon frobnicate`, `daemon --help`), or nothing at all.
fn unresolved(all: &[Entry], args: &[String]) -> ExitCode {
    let first = args[0].as_str();
    let verbs: Vec<&str> = all
        .iter()
        .filter(|e| e.path.len() > 1 && e.path[0] == first)
        .map(|e| e.path[1])
        .collect();
    if verbs.is_empty() {
        return if first.starts_with('-') {
            usage_error(&format!("no flag `{first}` before a subcommand"))
        } else {
            usage_error(&format!("unknown subcommand `{first}`"))
        };
    }
    match args.get(1).map(String::as_str) {
        Some("--help" | "-h") => {
            out::text(&help_text(&[first]).unwrap_or_default());
            ExitCode::SUCCESS
        }
        None => usage_error_in(
            &[first],
            &format!("`{first}` needs one of {}", verbs.join("|")),
        ),
        Some(other) => usage_error_in(
            &[first],
            &format!("unknown `{first}` subcommand `{other}`"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn entry(path: &[&str]) -> Entry {
        entries()
            .into_iter()
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("no USAGE entry for {path:?}"))
    }

    /// Parse and plan, the way `run` does, minus the running.
    fn decide(path: &[&str], rest: &[&str]) -> Result<Cmd, String> {
        match parse(&entry(path), &argv(rest))? {
            Parsed::Run(a) => plan(path, &a),
            Parsed::Help => Err("help".into()),
        }
    }

    /// **The banner's grammar, read back.** A literal on purpose: the
    /// point is a second pair of eyes on what the banner declares, which a
    /// value derived from `entries()` would only restate.
    #[test]
    fn the_banner_declares_the_subcommands_and_flags_the_binary_has() {
        // (path, switches, options, positionals)
        type Row = (String, Vec<&'static str>, Vec<&'static str>, Vec<&'static str>);
        let got: Vec<Row> = entries()
            .into_iter()
            .map(|e| (e.path.join(" "), e.switches, e.options, e.positionals))
            .collect();
        let want: Vec<Row> = vec![
            ("mcp".into(), vec!["--no-daemon"], vec![], vec![]),
            ("daemon run".into(), vec![], vec![], vec![]),
            ("daemon start".into(), vec![], vec![], vec![]),
            ("daemon stop".into(), vec!["--force"], vec![], vec![]),
            ("daemon status".into(), vec!["--json"], vec![], vec![]),
            ("list".into(), vec!["--json"], vec![], vec![]),
            ("logs".into(), vec!["--raw"], vec!["--tail"], vec!["<session>"]),
            ("attach".into(), vec!["--allow-echo"], vec![], vec!["<session>"]),
            ("watch".into(), vec![], vec![], vec!["<session>"]),
            ("version".into(), vec![], vec![], vec![]),
        ];
        assert_eq!(got, want);
    }

    /// Every entry reaches a handler, and every flag a handler reads is
    /// one its entry declares — the `debug_assert!` in [`Args::switch`]
    /// and [`Args::option`] fires here if not.
    #[test]
    fn every_handler_reads_only_what_its_entry_declares() {
        for e in entries() {
            let mut rest: Vec<String> = e.switches.iter().map(|s| s.to_string()).collect();
            for o in &e.options {
                rest.push(o.to_string());
                rest.push("1".into());
            }
            rest.extend(e.positionals.iter().map(|_| "x".to_string()));
            let Parsed::Run(a) = parse(&e, &rest).expect("its own synopsis parses") else {
                panic!("{:?} parsed as help", e.path)
            };
            plan(&e.path, &a).unwrap_or_else(|m| panic!("{:?}: {m}", e.path));
        }
    }

    /// GH #233: an undeclared flag is refused, not dropped.
    #[test]
    fn an_unknown_flag_is_refused_rather_than_ignored() {
        for (path, rest, flag) in [
            (&["list"][..], &["--jsn"][..], "--jsn"),
            (&["logs"][..], &["big", "--tial", "5"][..], "--tial"),
            (&["logs"][..], &["big", "-t", "5"][..], "-t"),
            (&["daemon", "stop"][..], &["--forse"][..], "--forse"),
            (&["mcp"][..], &["--no-deamon"][..], "--no-deamon"),
            (&["version"][..], &["--json"][..], "--json"),
        ] {
            let err = decide(path, rest).expect_err("an unknown flag must be refused");
            assert!(err.contains(flag), "{path:?} {rest:?}: {err}");
        }
    }

    #[test]
    fn flags_may_come_before_the_session_and_take_either_spelling() {
        let want = Cmd::Logs {
            session: "big".into(),
            tail: Some(5),
            raw: true,
        };
        for rest in [
            &["big", "--tail", "5", "--raw"][..],
            &["--raw", "big", "--tail", "5"][..],
            &["--tail=5", "--raw", "big"][..],
            &["--raw", "--tail", "5", "--", "big"][..],
        ] {
            assert_eq!(decide(&["logs"], rest), Ok(want.clone()), "{rest:?}");
        }
        // `--` makes a dash-led session name reachable.
        assert_eq!(
            decide(&["watch"], &["--", "-odd-name"]),
            Ok(Cmd::Watch {
                session: "-odd-name".into()
            })
        );
    }

    #[test]
    fn positionals_are_counted_both_ways() {
        let missing = decide(&["logs"], &["--raw"]).expect_err("no session");
        assert!(missing.contains("session id or name"), "{missing}");
        let extra = decide(&["logs"], &["big", "bigger"]).expect_err("two sessions");
        assert!(extra.contains("bigger"), "{extra}");
        let stray = decide(&["list"], &["something"]).expect_err("list takes none");
        assert!(stray.contains("something"), "{stray}");
    }

    #[test]
    fn option_values_are_checked() {
        for rest in [&["big", "--tail"][..], &["big", "--tail", "many"][..]] {
            assert!(decide(&["logs"], rest).is_err(), "{rest:?}");
        }
        assert!(decide(&["logs"], &["big", "--tail", "1", "--tail", "2"]).is_err());
        assert!(decide(&["logs"], &["big", "--raw=yes"]).is_err());
    }

    #[test]
    fn help_is_help_wherever_it_is_asked_for() {
        for rest in [&["--help"][..], &["-h"][..], &["big", "--tial", "--help"][..]] {
            assert!(
                matches!(parse(&entry(&["logs"]), &argv(rest)), Ok(Parsed::Help)),
                "{rest:?}"
            );
        }
        // …except after `--`, where it is a session name.
        assert_eq!(
            decide(&["watch"], &["--", "--help"]),
            Ok(Cmd::Watch {
                session: "--help".into()
            })
        );
    }

    /// A group's help is its members' lines; a leaf's is its own; neither
    /// carries another subcommand's.
    #[test]
    fn help_text_is_scoped_to_what_was_asked_about() {
        let daemon = help_text(&["daemon"]).expect("daemon is a group");
        for verb in ["run", "start", "stop", "status"] {
            assert!(daemon.contains(&format!("holdfast daemon {verb}")), "{daemon}");
        }
        assert!(!daemon.contains("holdfast list"), "{daemon}");

        let stop = help_text(&["daemon", "stop"]).expect("daemon stop");
        assert!(stop.contains("holdfast daemon stop [--force]"), "{stop}");
        assert!(!stop.contains("holdfast daemon status"), "{stop}");

        let logs = help_text(&["logs"]).expect("logs");
        assert!(logs.contains("--tail N"), "{logs}");
        // Continuation lines travel with their entry.
        assert!(logs.contains("audited"), "{logs}");
        assert!(!logs.contains("holdfast attach"), "{logs}");

        assert!(help_text(&["nonsense"]).is_none());
        assert!(help_text(&["pty-worker"]).is_none(), "hidden from the banner");
    }
}
