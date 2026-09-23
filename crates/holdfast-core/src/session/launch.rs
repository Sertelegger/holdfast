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
//! ## What every session is told
//!
//! `PWD`, set to the directory the session really starts in — applied
//! after the inherited environment and before the call's own `env`, so a
//! caller that sets it wins.

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
/// supplies it gets it overwritten by the shim, and under `--no-daemon`
/// nothing reads it at all.
pub const CLIENT_PARAM: &str = "@client";

/// What the calling `holdfast mcp` process knows about itself that a
/// shared daemon cannot: where it is, and what its environment is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientLaunch {
    /// The shim's working directory — the directory its MCP client
    /// launched it in, which for Claude Code is the project.
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

impl Host {
    /// The calling client's working directory, when it applies: a
    /// `command` session in a daemon, from a shim that sent one.
    ///
    /// `None` means *"use this process's own"*, which is right
    /// in-process and is the pre-GH-#229 behaviour for everything else.
    pub fn client_cwd(&self, profile: bool) -> Option<&str> {
        match self {
            Self::Daemon {
                client: Some(ClientLaunch { cwd: Some(cwd), .. }),
            } if !profile => Some(cwd),
            _ => None,
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

/// The variables Holdfast sets for every session — `PWD` naming `cwd` —
/// minus any the call's own `env` sets.
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
    let mut out: Vec<(String, String)> = Vec::new();
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
        assert_eq!(hosted.client_cwd(false), Some("/b"));
        assert_eq!(
            hosted.client_cwd(true),
            None,
            "a profile's directory is the operator's (GH #55)"
        );
        assert_eq!(Host::Daemon { client: None }.client_cwd(false), None);
        assert_eq!(Host::InProcess.client_cwd(false), None);
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

    /// `PWD` names the directory the child runs in, unless the call's own
    /// `env` set one.
    #[test]
    fn the_callers_env_outranks_every_default() {
        assert_eq!(
            session_defaults(Some("/b"), &[]),
            vec![("PWD".to_string(), "/b".to_string())]
        );
        let explicit = vec![("PWD".to_string(), "/elsewhere".to_string())];
        assert!(session_defaults(Some("/b"), &explicit).is_empty());
        // No directory, no `PWD` to set.
        assert!(session_defaults(None, &[]).is_empty());
    }
}
