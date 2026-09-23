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
//! the key only from a peer whose protocol has it (1.5), and an older
//! shim's is refused as the unknown argument it is.
//!
//! ## What is still scrubbed, and why that is a fallback
//!
//! A daemon-hosted session that has **no** client environment — a
//! `profile` session, or a request from a shim that predates this — still
//! starts from the daemon's own environment. For those, the variables
//! Claude Code marks its children with ([`names_the_spawning_client`])
//! are removed, because they describe the process that spawned the
//! daemon and are guaranteed wrong for anyone else. That is the narrow
//! list the paragraph above argues against as a *fix*; as a fallback for
//! the paths the fix cannot reach, it is strictly better than nothing.
//!
//! ## Defaults every session gets (GH #239)
//!
//! [`PAGER_DEFAULTS`], and `PWD` set to the directory the session really
//! starts in. Both are applied after the inherited environment and before
//! the call's own `env`, so a caller that sets any of them wins.

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
/// the agent's text; the daemon leaves it in the arguments and the tool
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
    /// the operator's (GH #55); and the pre-GH-#229 behaviour for a shim
    /// too old to say where it is, which is the best a daemon can do.
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

/// The variables Holdfast sets for every session — [`PAGER_DEFAULTS`], and
/// `PWD` naming `cwd` — minus any the call's own `env` sets.
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
pub fn session_defaults(cwd: Option<&str>, explicit: &[(String, String)]) -> Vec<(String, String)> {
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
        let all = session_defaults(Some("/b"), &[]);
        assert_eq!(
            all,
            vec![
                ("PAGER".to_string(), "cat".to_string()),
                ("GIT_PAGER".to_string(), "cat".to_string()),
                ("MANPAGER".to_string(), "cat".to_string()),
                ("SYSTEMD_PAGER".to_string(), "cat".to_string()),
                ("PWD".to_string(), "/b".to_string()),
            ]
        );
        let explicit = vec![
            ("GIT_PAGER".to_string(), "less".to_string()),
            ("PWD".to_string(), "/elsewhere".to_string()),
        ];
        let keys: Vec<String> = session_defaults(Some("/b"), &explicit)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, ["PAGER", "MANPAGER", "SYSTEMD_PAGER"]);
        // No directory, no `PWD` to set.
        assert!(!session_defaults(None, &[]).iter().any(|(k, _)| k == "PWD"));
    }
}
