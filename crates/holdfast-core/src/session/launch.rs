//! Where a new session's process starts, and from what environment
//! (GH #229, GH #239).
//!
//! ## The defect this exists for (GH #229)
//!
//! A daemon is shared by every MCP client on the machine and outlives
//! all of them. It used to start every session from **its own** working
//! directory and **its own** environment — which were those of whichever
//! client happened to spawn it. So an agent working in project B that
//! omitted `cwd` ran `git`, `cargo` or `rm` in project A, with project
//! A's `CLAUDE_PROJECT_DIR`, and another Claude session's
//! `CLAUDE_CODE_SESSION_ID`, in its environment. Reproduced with two
//! shims launched from two directories: the second shell printed the
//! first's directory and the first's project. The tool schema called
//! that default *"the directory the Holdfast server itself was started
//! in"*, which an agent reads as its own project.
//!
//! `holdfast mcp --no-daemon` never had the bug, and it is the reference
//! for the fix: there the server *is* the process the client launched,
//! so a session inherits the client's directory and environment by
//! construction. Hybrid mode now does the same thing on purpose. The
//! shim — the one process in the hybrid path that *is* the client's —
//! attaches its own working directory and environment to every
//! `start_session` under [`CLIENT_PARAM`], and the daemon starts the
//! session from those rather than from itself.
//!
//! ## Why the whole environment, rather than scrubbing a list
//!
//! The obvious smaller fix — delete `CLAUDE_PROJECT_DIR` and friends from
//! the daemon's environment — fixes the variables it names and none of
//! the ones it does not, and the ones it does not are the same class.
//! Read off the MCP servers Claude Code had running on the machine this
//! was written on: `SSH_AUTH_SOCK` pointing at one VS Code remote
//! window's agent socket (dead the moment that window closes, taking
//! `git push` in every later session with it), `VSCODE_GIT_IPC_HANDLE`
//! naming that window's askpass, `CLAUDE_CODE_MESSAGING_TOKEN` belonging
//! to one Claude session, `CLAUDE_JOB_DIR` present in some and absent in
//! others — and, on any machine using `direnv` or `mise`, whatever
//! per-project variables the spawning shell had exported. A deny-list
//! enumerates the ways a client's environment can differ, and there is
//! no complete list. The session's environment is its **caller's**, which
//! is the one rule that needs no list, and the rule `--no-daemon` already
//! follows.
//!
//! The values travel over the control socket, never over MCP, so §5.2's
//! *"inherited values never traverse MCP"* holds exactly as it did: none
//! of this reaches the agent's transcript, and `session_start`'s
//! `env_keys` still records only the keys the call itself supplied.
//!
//! ## What does **not** take the client's context: profile sessions
//!
//! A `profile` session (§9.6) runs a program the **operator** wrote, and
//! GH #55 made its environment and working directory the operator's too:
//! an agent-chosen `PATH` repoints a literal `program`, an agent-chosen
//! `LD_PRELOAD` captures the credential out of an absolute one, and a
//! relative `program` resolves against the working directory. The client
//! context is not agent-*typed*, but it is agent-*reachable* — any
//! process of this uid can speak the control protocol and put anything
//! under [`CLIENT_PARAM`] — so a profile session ignores it and keeps the
//! daemon's own environment and directory, as before.
//!
//! **Not agent-typed is a property the daemon enforces, not one it
//! assumes.** A shim older than the key forwards an agent's `arguments`
//! verbatim, so an agent that typed `@client` into `start_session` had
//! it read as a launch context: its `env` replaced the session's, and
//! `session_start`'s `env_keys` recorded none of it. The daemon now takes
//! the key only from a peer whose protocol has it (1.5). An older shim's
//! is refused: in a `profile` call as the unknown argument it is, and in
//! any other with the whole call (`daemon::server::older_peer_start_refusal`).
//!
//! ## What is still scrubbed, and why that is a fallback
//!
//! A daemon-hosted session that has **no** client environment — a
//! `profile` session, or a request from a 1.5 peer that sent none — still
//! starts from the daemon's own environment. For those, the variables
//! Claude Code marks its children with ([`names_the_spawning_client`])
//! are removed, because they describe the process that spawned the
//! daemon and are guaranteed wrong for anyone else. That is the narrow
//! list the paragraph above argues against as a *fix*; as a fallback for
//! the paths the fix cannot reach, it is strictly better than nothing.
//! A shim that predates the key is not one of those paths: its
//! `start_session` is refused unless it names a `profile`
//! (`daemon::server::older_peer_start_refusal`).
//!
//! ## Defaults every session gets (GH #239, GH #252)
//!
//! [`PAGER_DEFAULTS`], `PWD` set to the directory the session really
//! starts in, and the shell-history policy of [`history_defaults`]. All
//! are applied after the inherited environment and before the call's own
//! `env`, so a caller that sets any of them wins.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;

/// The `tool/start_session` params key the shim carries its own launch
/// context under.
///
/// **Not a tool argument**: the daemon removes it before the arguments
/// reach the handler (`daemon::server::dispatch_tool`), and `@` makes it a
/// name no `StartSessionArgs` field can ever have. An MCP client that
/// supplies it gets it overwritten by the shim, and under `--no-daemon`,
/// where nothing removes it, `start_session`'s closed arguments refuse it.
///
/// **Taken only from a shim that sends one.** A shim older than protocol
/// 1.5 forwards the agent's arguments verbatim, so from one the key is
/// the agent's text. Such a shim's `start_session` is refused whole unless
/// it names a `profile` (`daemon::server::older_peer_start_refusal`); in a
/// profile call the daemon leaves the key in the arguments, and the tool
/// refuses it the same way (`daemon::server::Peer::sends_launch_context`).
///
/// Declared in `protocol::method`, which is where the wire-shape record
/// reads the control protocol's tokens from.
pub const CLIENT_PARAM: &str = crate::protocol::method::CLIENT_PARAM;

/// The one tool whose control-protocol params may carry [`CLIENT_PARAM`].
///
/// The shim tags `tool/start_session` alone, and `start_session` is the
/// only handler that reads the context, so the daemon takes the key from
/// that call and no other. **On every other tool it is left in the
/// arguments**, where GH #219's closed argument types refuse it by name —
/// the answer `--no-daemon` gives, where nothing strips it. Taken from
/// every call, it was the one key the daemon path accepted in silence on
/// eleven tools whose advertised schemas say `additionalProperties:
/// false`.
pub const CLIENT_PARAM_TOOL: &str = "start_session";

/// What the calling `holdfast mcp` process knows about itself that a
/// shared daemon cannot: where it is, and what its environment is.
///
/// **Unknown fields are ignored, not refused**, and that is a wire
/// promise rather than leniency. A daemon outlives the shims that talk to
/// it — by its idle window, and since GH #231 by being restarted rather
/// than abandoned — so a later shim will send this to a daemon of this
/// release. A field it adds must cost that daemon nothing but the field;
/// a refusal would fail every `start_session` it forwards, and no restart
/// would help, because the daemon is not lost.
/// `a_later_shims_context_is_read_for_what_this_daemon_knows` pins it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientLaunch {
    /// The shim's working directory — the directory its MCP client
    /// launched it in, which for Claude Code is the project.
    ///
    /// **Absent when the shim could not read it**: `getcwd(2)` fails once
    /// the directory has been removed, and a path that is not UTF-8 has
    /// no JSON spelling. A daemon must not read absence as "use your
    /// own" — see [`StartDir::ClientUnknown`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The shim's environment, whole.
    ///
    /// **Entries that are not valid UTF-8 are not carried**: the control
    /// protocol's params are JSON-shaped, and a lossy conversion would
    /// hand the session a value nobody set. A session started through
    /// the shim therefore lacks exactly those variables, where
    /// `--no-daemon` would have them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
}

impl ClientLaunch {
    /// This process's own context — what the shim attaches to every
    /// `start_session` it forwards.
    ///
    /// Read per call rather than once: it costs one `getcwd` and one copy
    /// of an environment of a few kilobytes, against a call that is about
    /// to fork a process, and it cannot go stale.
    pub fn of_this_process() -> Self {
        Self {
            cwd: std::env::current_dir()
                .ok()
                .and_then(|p| p.into_os_string().into_string().ok()),
            env: Some(
                std::env::vars_os()
                    .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                    .collect(),
            ),
        }
    }
}

/// Who is hosting the session being started — the fact that decides what
/// its process may inherit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// No control protocol: `holdfast mcp --no-daemon`, and Windows. This
    /// process **is** the one the client launched, so its own directory
    /// and environment are the client's.
    InProcess,
    /// A daemon, serving a control-protocol request — which carried the
    /// calling shim's context if the shim is new enough to send one.
    Daemon { client: Option<ClientLaunch> },
}

tokio::task_local! {
    static HOSTED: Option<ClientLaunch>;
}

/// Run `fut` as a daemon serving a request that carried `client`.
///
/// `daemon::server::dispatch_tool` scopes every tool call with this, the
/// same way it scopes `mcp::caller` and `request::RequestContext`,
/// because `#[tool]` generates the handler signatures and none of them
/// can take another parameter.
pub async fn hosted_by_daemon<F: Future>(client: Option<ClientLaunch>, fut: F) -> F::Output {
    HOSTED.scope(client, fut).await
}

/// The host of the current task. [`Host::InProcess`] outside any
/// [`hosted_by_daemon`] scope, which is what an in-process server is.
pub fn host() -> Host {
    HOSTED
        .try_with(|client| Host::Daemon {
            client: client.clone(),
        })
        .unwrap_or(Host::InProcess)
}

/// Take [`CLIENT_PARAM`] out of a tool call's arguments.
///
/// Removed whether or not it parses, so a malformed context can never
/// reach a handler as an argument. `Err` carries the reason it did not
/// parse; absent is `Ok(None)`.
pub fn take_client_param(
    args: &mut serde_json::Value,
) -> std::result::Result<Option<ClientLaunch>, String> {
    let Some(raw) = args.as_object_mut().and_then(|m| m.remove(CLIENT_PARAM)) else {
        return Ok(None);
    };
    serde_json::from_value(raw)
        .map(Some)
        .map_err(|e| format!("`{CLIENT_PARAM}` is not a launch context: {e}"))
}

/// Where a session with no `cwd` of its own starts (GH #229).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartDir<'a> {
    /// This process's own directory. Right in-process, where this process
    /// is the client's; right for a `profile` session, whose directory is
    /// the operator's (GH #55); and the fallback for a 1.5 peer that sent
    /// no context. A shim too old to say where it is does not reach it:
    /// its `start_session` is refused unless it names a `profile`
    /// (`daemon::server::older_peer_start_refusal`).
    Own,
    /// The calling client's directory, as its shim stated it.
    Client(&'a str),
    /// **The client said where it was and could not say where it is** —
    /// its shim sent a context with no directory. That is a directory
    /// removed since the shim started (`getcwd` fails), or one whose path
    /// is not UTF-8. Starting in [`StartDir::Own`] instead is GH #229
    /// exactly — a session in whichever project spawned the daemon — so
    /// the caller is refused and told to pass `cwd`.
    ClientUnknown,
}

impl Host {
    /// Where a session with no `cwd` of its own starts. See [`StartDir`].
    pub fn start_dir(&self, profile: bool) -> StartDir<'_> {
        match self {
            Self::Daemon {
                client: Some(ClientLaunch { cwd, .. }),
            } if !profile => cwd
                .as_deref()
                .map_or(StartDir::ClientUnknown, StartDir::Client),
            _ => StartDir::Own,
        }
    }

    /// Which of [`Host::base_env`]'s three arms a session takes, as
    /// `session_start.env_base` records it (plan §3.1, E4).
    ///
    /// The same match as `base_env`'s, arm for arm;
    /// `env_base_names_the_arm_base_env_takes` holds the two together
    /// over every host shape, so a change to one that skips the other
    /// fails there rather than in an operator's reading of the trail.
    pub fn env_base(&self, profile: bool) -> crate::audit::EnvBase {
        use crate::audit::EnvBase;
        match self {
            Self::InProcess => EnvBase::InProcess,
            Self::Daemon {
                client: Some(ClientLaunch { env: Some(_), .. }),
            } if !profile => EnvBase::Client,
            Self::Daemon { .. } => EnvBase::Daemon,
        }
    }

    /// The environment a session's child starts from, before the
    /// defaults and the call's own `env`.
    ///
    /// `None` means inherit this process's environment unchanged, and it
    /// is the answer exactly when this process is the client's own
    /// ([`Host::InProcess`]). `own` is this process's environment, passed
    /// in rather than read so the rule can be tested without mutating a
    /// test process's environment.
    pub fn base_env(
        &self,
        profile: bool,
        own: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Option<Vec<(OsString, OsString)>> {
        match self {
            Self::InProcess => None,
            Self::Daemon {
                client: Some(ClientLaunch { env: Some(env), .. }),
            } if !profile => Some(
                env.iter()
                    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                    .collect(),
            ),
            Self::Daemon { .. } => Some(
                own.into_iter()
                    .filter(|(k, _)| !k.to_str().is_some_and(names_the_spawning_client))
                    .collect(),
            ),
        }
    }
}

/// Whether an environment variable identifies the **client process** that
/// spawned the daemon, rather than the user or the machine — so a
/// daemon-hosted session must not inherit it from the daemon.
///
/// `CLAUDECODE` and the `CLAUDE_` family are how Claude Code marks its
/// children: which session, which project, which configuration directory,
/// which plugin root, which messaging socket and token. Every one of them
/// is wrong for every client but the one that spawned the daemon. See the
/// module doc for why this is a fallback and not the fix.
pub fn names_the_spawning_client(key: &str) -> bool {
    key == "CLAUDECODE" || key.starts_with("CLAUDE_")
}

/// Pagers, off (GH #239).
///
/// A pager waits for a keystroke, and an agent reading a session's output
/// does not send one. `git log` and `git diff` run `less` with git's
/// default `LESS=FRX`: the `X` keeps it off the alternate screen, so the
/// session reads `Executing` rather than `Fullscreen`, and a
/// `wait_for_pattern` runs to its deadline with the first screen of the
/// log on the tail and `:` as its last line. `cat` is the value every one
/// of these tools documents as "no pager", and git treats it as exactly
/// that rather than spawning it.
///
/// - `PAGER`: the generic fallback — `git`, `man`, `psql`, `systemctl`
///   and most others read it when nothing more specific is set.
/// - `GIT_PAGER`: git's own, which **outranks `core.pager`** — so a user
///   whose git config pipes through `delta` or `less -S` is covered too,
///   which `PAGER` alone would not be.
/// - `MANPAGER`: outranks `PAGER` for `man`, and is commonly set.
/// - `SYSTEMD_PAGER`: outranks `PAGER` for `systemctl` and `journalctl`.
///
/// A caller that wants a pager sets one in `start_session`'s `env`.
pub const PAGER_DEFAULTS: [(&str, &str); 4] = [
    ("PAGER", "cat"),
    ("GIT_PAGER", "cat"),
    ("MANPAGER", "cat"),
    ("SYSTEMD_PAGER", "cat"),
];

/// Where a session's shell keeps its command history (GH #252).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History<'a> {
    /// Nowhere: `[terminal] shell_history_file = "none"`, the default.
    Discard,
    /// A file of the session's own under the daemon's state directory:
    /// `shell_history_file = "per_session"`.
    File(&'a str),
}

/// The variable that carries a session's history file past the shell's rc
/// files, which run after the environment is read and may assign
/// `HISTFILE` themselves. The integration snippet (`detect::shell`)
/// assigns it back; empty means nowhere.
pub const HISTFILE_CARRIER: &str = "HOLDFAST_HISTFILE";

/// zsh's `HISTORY_IGNORE`: a pattern matching the line Holdfast types into
/// zsh, which names the variable carrying the snippet, and nothing a user
/// is likely to type. See [`history_defaults`].
pub const ZSH_HISTORY_IGNORE: &str = "*HOLDFAST_ZSH_INTEGRATION*";

/// History a session's other interactive programs would keep under
/// `$HOME`, switched off (GH #252). Each measured through a PTY with a
/// fresh `HOME`, against a control run without it that wrote the file:
///
/// | Variable | Program, version measured |
/// |---|---|
/// | `MYSQL_HISTFILE=/dev/null` | MariaDB client 15.1 (10.11) and Oracle `mysql` 8.0 |
/// | `MARIADB_HISTFILE=/dev/null` | MariaDB client 15.2 (11.4.7 and 11.8.3) |
/// | `PSQL_HISTORY=/dev/null` | psql 16 |
/// | `NODE_REPL_HISTORY=` (empty) | node 22, 24 and 26 |
/// | `TS_NODE_HISTORY=` (one space) | ts-node 10.9.2 on node 22, 24 and 26 |
/// | `SQLITE_HISTORY=` (empty) | sqlite3 3.45, readline and libedit builds |
/// | `PYTHON_HISTORY=/dev/null` | Python 3.13, PyREPL and basic REPL |
/// | `SHELL_SESSIONS_DISABLE=1` | macOS Terminal's per-session history; not measured |
///
/// **Python 3.12 and older ignore `PYTHON_HISTORY`** and still write
/// `~/.python_history` (measured on 3.12.3); nothing in the environment
/// reaches them. An empty `PYTHON_HISTORY` would not do either: 3.13 reads
/// an empty value as unset. sqlite3 finds its default file through the
/// password database rather than `$HOME`, so a session's own `HOME` does
/// not move it, and only the variable keeps it off disk.
///
/// **Both `mysql` variables**, because MariaDB 11 reads
/// `MARIADB_HISTFILE` first and 10.x only `MYSQL_HISTFILE`: a
/// `MARIADB_HISTFILE` the client's environment carries would otherwise
/// beat the other (11.4.7 wrote it, measured). **An empty `node` value and
/// not `/dev/null`**: node 24 and later truncate the history file as they
/// open it, which fails on a device, and print *Could not open history
/// file* at every REPL start (measured on 24.21 and 26.10; 22 is silent).
/// Empty costs one *Persistent history support disabled* notice, on an
/// up-arrow before any line is entered. **A space for ts-node**, which
/// ignores `NODE_REPL_HISTORY` and reads `TS_NODE_HISTORY ||
/// ~/.ts_node_repl_history`, so an empty value is its default file
/// (measured); node trims the space to the empty value that turns
/// persistence off.
///
/// **Not `/dev/null` for sqlite3**, because libedit's history save
/// `fchmod`s the file it wrote to `0600`: as root that would take
/// `/dev/null` itself from `0666` to `0600` (measured on a pty device this
/// uid owns, standing in for it: `crw-rw-rw-` became `crw-------`). An
/// empty name opens nothing, and both builds stay silent. psql and both
/// `mysql` clients compare their value with the null device and write
/// nothing to it, so libedit never reaches it through them.
///
/// **[`NULL_DEVICE`] is `nul` on Windows**, where a native program opens
/// `/dev/null` as `\dev\null` on the current drive: a real file wherever
/// that directory exists (PyREPL wrote one, measured on a stand-in). The
/// `mysql` value is compared as a string by both clients, so it stays.
///
/// `SHELL_SESSIONS_DISABLE` is Apple's documented off switch for
/// `/etc/zshrc_Apple_Terminal`, which saves each Terminal window's history
/// under `~/.zsh_sessions/` whatever `HISTFILE` says. A session inherits
/// `TERM_PROGRAM=Apple_Terminal` and `TERM_SESSION_ID` from a client
/// started in Terminal (GH #229), so it is set everywhere; nothing else
/// reads it. **It does not reach `/etc/bashrc_Apple_Terminal`**, which a
/// login bash sources: that one checks for a file,
/// `~/.bash_sessions_disable`, and no variable turns it off.
pub const CLIENT_HISTORY_DEFAULTS: [(&str, &str); 8] = [
    ("MYSQL_HISTFILE", "/dev/null"),
    ("MARIADB_HISTFILE", "/dev/null"),
    ("PSQL_HISTORY", NULL_DEVICE),
    ("NODE_REPL_HISTORY", ""),
    ("TS_NODE_HISTORY", " "),
    ("SQLITE_HISTORY", ""),
    ("PYTHON_HISTORY", NULL_DEVICE),
    ("SHELL_SESSIONS_DISABLE", "1"),
];

/// The null device, as a native program names it. `nul` is the spelling
/// psql compares its history file with on Windows; the name is not
/// case-sensitive there.
#[cfg(not(windows))]
pub const NULL_DEVICE: &str = "/dev/null";
/// The null device, as a native program names it. `nul` is the spelling
/// psql compares its history file with on Windows; the name is not
/// case-sensitive there.
#[cfg(windows)]
pub const NULL_DEVICE: &str = "nul";

/// The shell-history policy, as environment (GH #252).
///
/// Without one, a session's shell wrote the agent's commands — and any
/// secret admitted at a readline prompt, and Holdfast's integration
/// snippet — into the operator's own history file: on `exit`, on EOF, on
/// the `SIGHUP` a graceful `terminate` or a daemon crash delivers, and
/// after every command for common bash and zsh configurations.
///
/// - **`HISTFILE=/dev/null`**, not an empty `HISTFILE`, and one value for
///   bash and zsh because a bash session can start a zsh. Measured on
///   bash 5.2.21 and zsh 5.9: both save nothing to disk under either
///   value, but an rc that assigns conditionally (`[ -z "$HISTFILE" ] &&
///   HISTFILE=…`) keeps `/dev/null` and replaces the empty string, zsh
///   prints *failed to write history file* at every exit when an rc set
///   `SAVEHIST` and left `HISTFILE` empty, and bash prints *history: :
///   cannot create* at every prompt when an rc's `PROMPT_COMMAND` runs
///   `history -a`. bash never writes through a temporary file beside a
///   `HISTFILE` that is not a regular file: as uid 0 in a user namespace,
///   with the real `/dev/null` bind-mounted into a writable directory,
///   its exit, `SIGHUP`, `history -w`, `history -a` and `HISTFILESIZE=1`
///   left it a character device with nothing created beside it, as did
///   zsh's exit and `SIGHUP` under `SAVEHIST` with its default
///   `append_history`, `inc_append_history`, `share_history` and
///   `no_hist_save_by_copy`.
///
///   **zsh with `SAVEHIST` set has two exceptions of its own, and the
///   snippet is what closes them.** Before it saves, zsh locks by creating
///   `/dev/null.LOCK`: as any user but root that fails, and zsh prints
///   *locking failed for /dev/null: permission denied* at every exit, EOF
///   and `exec zsh` under an rc that sets `SAVEHIST` — macOS's
///   `/etc/zshrc` and oh-my-zsh do. As root it succeeds, and under
///   `unsetopt append_history` zsh's default `hist_save_by_copy` writes
///   `/dev/null.new` and renames it over `/dev/null`, leaving a regular
///   `0666` file of the agent's commands (simulated as uid 0 in a user
///   namespace). So the snippet's `/dev/null` branch also sets `SAVEHIST=0`,
///   under which zsh saves nothing, and unsets `hist_save_by_copy` for an
///   rc re-sourced later that sets `SAVEHIST` again. `exec zsh` and a
///   nested zsh run their rc with neither, so the message comes back there,
///   and as root they replace `/dev/null` as before; SECURITY.md registers
///   both.
/// - **[`HISTFILE_CARRIER`]**, for the snippet, whose own `HISTFILE`
///   assignment is what overrides an rc file that hard-sets one. It
///   carries a `HISTFILE` the call set itself, so that choice survives
///   the snippet the way the call's choice of every other default does.
/// - **`fish_history=`**, an empty session name: fish keeps nothing on
///   disk under it (measured on 3.7.0, 4.0.2 and 4.9.3) and prints no
///   banner. A fish Holdfast spawns itself also gets
///   `detect::shell::FISH_HISTORY_INIT`, which re-asserts it after
///   config.fish and makes any fish started inside the session save
///   nothing. A call whose own `env` sets a non-empty `fish_history` gets
///   neither: that fish starts as a plain fish with the call's value in its
///   environment, which a config.fish that sets `fish_history` overrides.
///   What still reaches disk is a fish started inside a bash or zsh
///   session, or through a wrapper Holdfast does not recognise (`env
///   fish`), whose config.fish sets `fish_history`; a fish started inside
///   a fish session writes nothing but still reads the history its
///   config.fish names.
/// - **`HISTORY_IGNORE`**, [`ZSH_HISTORY_IGNORE`]. zsh's
///   `inc_append_history` and `share_history` write a line when it is
///   entered, before it runs, so the line Holdfast types reached the rc's
///   history file whenever `hist_ignore_space` was off (measured). The
///   pattern matches only a line that names the snippet's carrier: the
///   typed line does, and the snippet it evaluates never enters the
///   history list. So a history file zsh rewrites keeps every other line
///   (measured).
///
/// - **[`CLIENT_HISTORY_DEFAULTS`]**, for the REPLs and database clients
///   that keep a history file of their own, in either mode: they are not
///   the shell history a per-session file records.
///
/// With shell integration off only this environment applies, so an rc
/// file that assigns `HISTFILE` itself wins for bash and zsh.
pub fn history_defaults(
    history: History<'_>,
    explicit: &[(String, String)],
) -> Vec<(String, String)> {
    let set_by_caller = |key: &str| {
        explicit
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let file = match history {
        History::Discard => None,
        History::File(path) => Some(path),
    };
    let carried = set_by_caller("HISTFILE").or(file).unwrap_or("");
    [
        ("HISTFILE", file.unwrap_or("/dev/null")),
        (HISTFILE_CARRIER, carried),
        ("fish_history", ""),
        ("HISTORY_IGNORE", ZSH_HISTORY_IGNORE),
    ]
    .into_iter()
    .chain(CLIENT_HISTORY_DEFAULTS)
    .filter(|(k, _)| set_by_caller(k).is_none())
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// The variables Holdfast sets for every session — [`PAGER_DEFAULTS`],
/// `PWD` naming `cwd`, and [`history_defaults`] — minus any the call's own
/// `env` sets.
///
/// **`PWD`, because the inherited one names somebody else's directory.**
/// A shell re-derives it when it disagrees with the real working
/// directory, so `bash` never showed the problem; a script reading
/// `$PWD`, or `os.environ["PWD"]`, got the directory of whichever process
/// the environment came from. Set to the canonical directory the child
/// is spawned in, which is also what a shell would compute.
///
/// Returned in a fixed order, so the child's environment and anything
/// derived from it compare between runs.
pub fn session_defaults(
    cwd: Option<&str>,
    history: History<'_>,
    explicit: &[(String, String)],
) -> Vec<(String, String)> {
    let set_by_caller = |key: &str| explicit.iter().any(|(k, _)| k == key);
    let mut out: Vec<(String, String)> = PAGER_DEFAULTS
        .iter()
        .filter(|(k, _)| !set_by_caller(k))
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    if let Some(cwd) = cwd {
        if !set_by_caller("PWD") {
            out.push(("PWD".to_string(), cwd.to_string()));
        }
    }
    out.extend(history_defaults(history, explicit));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    fn client(cwd: &str, env: &[(&str, &str)]) -> ClientLaunch {
        ClientLaunch {
            cwd: Some(cwd.into()),
            env: Some(
                env.iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            ),
        }
    }

    /// The daemon's own environment, as the spawning project left it.
    fn spawner() -> Vec<(OsString, OsString)> {
        os(&[
            ("PATH", "/a/bin"),
            ("CLAUDE_PROJECT_DIR", "/a"),
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "sess-a"),
            ("ONLY_IN_A", "leak"),
        ])
    }

    /// GH #229's rule, all four hosts at once, because each row is the
    /// negative for another: a `base_env` that always forwarded would
    /// pass the command row and fail the profile row, one that never did
    /// would pass the profile row and fail the command row.
    #[test]
    fn a_command_session_starts_from_its_callers_environment_and_nothing_else() {
        let b = client("/b", &[("PATH", "/b/bin"), ("CLAUDE_PROJECT_DIR", "/b")]);
        let hosted = Host::Daemon {
            client: Some(b.clone()),
        };

        // A command session: the caller's environment **whole**, and
        // nothing of the daemon's — `ONLY_IN_A` is the variable an
        // overlay would have leaked, which is why this is a replacement.
        let base = hosted
            .base_env(false, spawner())
            .expect("a daemon replaces");
        assert_eq!(
            base,
            os(&[("CLAUDE_PROJECT_DIR", "/b"), ("PATH", "/b/bin")]),
            "a command session must start from exactly its caller's environment"
        );

        // A profile session in the same daemon, from the same caller:
        // the daemon's environment (GH #55), minus Claude Code's marks.
        let profile = hosted.base_env(true, spawner()).expect("a daemon replaces");
        assert_eq!(
            profile,
            os(&[("PATH", "/a/bin"), ("ONLY_IN_A", "leak")]),
            "a profile session keeps the operator's environment and loses only the \
             spawning client's identity"
        );

        // A shim that predates the context: the same fallback.
        let old_shim = Host::Daemon { client: None };
        assert_eq!(old_shim.base_env(false, spawner()), Some(profile));

        // In-process, the process environment is the client's own, and
        // is inherited untouched — `CLAUDE_PROJECT_DIR` included, because
        // there it is right.
        assert_eq!(Host::InProcess.base_env(false, spawner()), None);
    }

    /// `session_start.env_base` names the arm `base_env` took, for every
    /// host shape `base_env` distinguishes — the two are separate matches,
    /// and this is what keeps them one decision. Each shape is checked
    /// against what `base_env` actually returned, not against a second
    /// copy of the rule.
    #[test]
    fn env_base_names_the_arm_base_env_takes() {
        use crate::audit::EnvBase;
        let with_env = client("/b", &[("PATH", "/b/bin")]);
        let cwd_only = ClientLaunch {
            cwd: Some("/b".into()),
            env: None,
        };
        let shapes = [
            (Host::InProcess, false),
            (Host::InProcess, true),
            (
                Host::Daemon {
                    client: Some(with_env.clone()),
                },
                false,
            ),
            (
                Host::Daemon {
                    client: Some(with_env),
                },
                true,
            ),
            (
                Host::Daemon {
                    client: Some(cwd_only),
                },
                false,
            ),
            (Host::Daemon { client: None }, false),
            (Host::Daemon { client: None }, true),
        ];
        let daemon_own: Vec<(OsString, OsString)> = spawner()
            .into_iter()
            .filter(|(k, _)| !k.to_str().is_some_and(names_the_spawning_client))
            .collect();
        let mut seen = Vec::new();
        for (host, profile) in shapes {
            let base = host.base_env(profile, spawner());
            let named = host.env_base(profile);
            let arm = match &base {
                None => EnvBase::InProcess,
                Some(env) if *env == daemon_own => EnvBase::Daemon,
                Some(_) => EnvBase::Client,
            };
            assert_eq!(
                named, arm,
                "{host:?} profile={profile}: the record names another arm"
            );
            seen.push(named);
        }
        for each in EnvBase::ALL {
            assert!(
                seen.contains(&each),
                "no host shape reaches `{}`",
                each.as_str()
            );
        }
    }

    #[test]
    fn only_a_command_session_in_a_daemon_takes_the_callers_directory() {
        let hosted = Host::Daemon {
            client: Some(client("/b", &[])),
        };
        assert_eq!(hosted.start_dir(false), StartDir::Client("/b"));
        assert_eq!(
            hosted.start_dir(true),
            StartDir::Own,
            "a profile's directory is the operator's (GH #55)"
        );
        assert_eq!(
            Host::Daemon { client: None }.start_dir(false),
            StartDir::Own
        );
        assert_eq!(Host::InProcess.start_dir(false), StartDir::Own);
    }

    /// **A context with no directory is not an old shim.** The shim sends
    /// one whenever it can, so its absence from a context that is there
    /// means the shim could not read its own directory — removed, or not
    /// UTF-8 — and falling back to this process's is GH #229. Found by
    /// review, end to end: a shim whose project was deleted started its
    /// session in the project that had spawned the daemon.
    #[test]
    fn a_client_that_could_not_say_where_it_is_is_not_given_the_daemons_directory() {
        let lost = Host::Daemon {
            client: Some(ClientLaunch {
                cwd: None,
                env: Some(BTreeMap::new()),
            }),
        };
        assert_eq!(lost.start_dir(false), StartDir::ClientUnknown);
        assert_eq!(
            lost.start_dir(true),
            StartDir::Own,
            "a profile never took the client's directory, known or not"
        );
    }

    /// The pairing that keeps the scrub honest: a predicate that matched
    /// everything would pass every row above that expects a removal.
    #[test]
    fn only_claude_codes_own_marks_are_scrubbed() {
        for key in [
            "CLAUDECODE",
            "CLAUDE_PROJECT_DIR",
            "CLAUDE_CODE_SESSION_ID",
            "CLAUDE_CONFIG_DIR",
        ] {
            assert!(names_the_spawning_client(key), "{key}");
        }
        for key in [
            "PATH",
            "HOME",
            "SSH_AUTH_SOCK",
            "CLAUDE",
            "MY_CLAUDE_THING",
            "claude_project_dir",
        ] {
            assert!(!names_the_spawning_client(key), "{key}");
        }
    }

    #[test]
    fn a_context_is_taken_out_of_the_arguments_whether_or_not_it_parses() {
        let mut args = serde_json::json!({
            "command": "bash",
            CLIENT_PARAM: { "cwd": "/b", "env": { "A": "1" } },
        });
        let taken = take_client_param(&mut args).expect("a well-formed context");
        assert_eq!(taken, Some(client("/b", &[("A", "1")])));
        assert_eq!(args, serde_json::json!({ "command": "bash" }));

        let mut malformed = serde_json::json!({ "command": "bash", CLIENT_PARAM: 7 });
        assert!(take_client_param(&mut malformed).is_err());
        assert_eq!(
            malformed,
            serde_json::json!({ "command": "bash" }),
            "a context that does not parse must still never reach the handler"
        );

        let mut absent = serde_json::json!({ "command": "bash" });
        assert_eq!(take_client_param(&mut absent), Ok(None));
    }

    /// **The forward-compatibility half of the wire.** A daemon of this
    /// release will be sent contexts by later shims; a field it does not
    /// know is dropped and the rest is read. Found by review: the struct
    /// was first written with `deny_unknown_fields`, which would have
    /// turned any later field into a `bad_params` on every `start_session`.
    #[test]
    fn a_later_shims_context_is_read_for_what_this_daemon_knows() {
        let mut args = serde_json::json!({
            "command": "bash",
            CLIENT_PARAM: {
                "cwd": "/b",
                "env": { "A": "1" },
                "umask": 18,
                "shell": { "path": "/bin/zsh" },
            },
        });
        assert_eq!(
            take_client_param(&mut args),
            Ok(Some(client("/b", &[("A", "1")]))),
            "a field this daemon does not know must not cost the ones it does"
        );
        assert_eq!(args, serde_json::json!({ "command": "bash" }));
    }

    /// The scope is the whole of what makes a host a daemon — including
    /// a daemon serving a shim too old to send a context, which must not
    /// read as in-process (that would inherit the spawner's environment
    /// unscrubbed).
    #[tokio::test]
    async fn the_scope_is_what_makes_a_host_a_daemon() {
        assert_eq!(host(), Host::InProcess);
        let inside = hosted_by_daemon(Some(client("/b", &[])), async { host() }).await;
        assert_eq!(
            inside,
            Host::Daemon {
                client: Some(client("/b", &[]))
            }
        );
        let old_shim = hosted_by_daemon(None, async { host() }).await;
        assert_eq!(old_shim, Host::Daemon { client: None });
    }

    /// GH #239: every default applies, and the caller's own `env` wins
    /// over each one individually.
    #[test]
    fn the_callers_env_outranks_every_default() {
        let all = session_defaults(Some("/b"), History::Discard, &[]);
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };
        assert_eq!(
            all,
            pairs(&[
                ("PAGER", "cat"),
                ("GIT_PAGER", "cat"),
                ("MANPAGER", "cat"),
                ("SYSTEMD_PAGER", "cat"),
                ("PWD", "/b"),
                ("HISTFILE", "/dev/null"),
                ("HOLDFAST_HISTFILE", ""),
                ("fish_history", ""),
                ("HISTORY_IGNORE", "*HOLDFAST_ZSH_INTEGRATION*"),
                ("MYSQL_HISTFILE", "/dev/null"),
                ("MARIADB_HISTFILE", "/dev/null"),
                ("PSQL_HISTORY", NULL_DEVICE),
                ("NODE_REPL_HISTORY", ""),
                ("TS_NODE_HISTORY", " "),
                ("SQLITE_HISTORY", ""),
                ("PYTHON_HISTORY", NULL_DEVICE),
                ("SHELL_SESSIONS_DISABLE", "1"),
            ])
        );
        let explicit = pairs(&[
            ("GIT_PAGER", "less"),
            ("PWD", "/elsewhere"),
            ("fish_history", "work"),
            ("PYTHON_HISTORY", "/tmp/py"),
        ]);
        let keys: Vec<String> = session_defaults(Some("/b"), History::Discard, &explicit)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            [
                "PAGER",
                "MANPAGER",
                "SYSTEMD_PAGER",
                "HISTFILE",
                "HOLDFAST_HISTFILE",
                "HISTORY_IGNORE",
                "MYSQL_HISTFILE",
                "MARIADB_HISTFILE",
                "PSQL_HISTORY",
                "NODE_REPL_HISTORY",
                "TS_NODE_HISTORY",
                "SQLITE_HISTORY",
                "SHELL_SESSIONS_DISABLE"
            ]
        );
        // No directory, no `PWD` to set.
        assert!(!session_defaults(None, History::Discard, &[])
            .iter()
            .any(|(k, _)| k == "PWD"));
    }

    /// GH #252: a session history file is both `HISTFILE` and what the
    /// snippet re-applies, and a `HISTFILE` the call set itself is carried
    /// instead, so the snippet does not undo the caller's choice.
    #[test]
    fn the_history_file_is_carried_past_the_rc_files() {
        let get = |v: &[(String, String)], key: &str| {
            v.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };
        let per_session = history_defaults(History::File("/s/h/sess_1.history"), &[]);
        assert_eq!(
            get(&per_session, "HISTFILE").as_deref(),
            Some("/s/h/sess_1.history")
        );
        assert_eq!(
            get(&per_session, HISTFILE_CARRIER).as_deref(),
            Some("/s/h/sess_1.history")
        );
        let own = vec![("HISTFILE".to_string(), "/tmp/mine".to_string())];
        for history in [History::Discard, History::File("/s/h/sess_1.history")] {
            let d = history_defaults(history, &own);
            assert_eq!(get(&d, "HISTFILE"), None, "the call's HISTFILE stands");
            assert_eq!(get(&d, HISTFILE_CARRIER).as_deref(), Some("/tmp/mine"));
        }
    }
}
