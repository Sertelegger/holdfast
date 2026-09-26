//! What a session's process starts from — its directory and its
//! environment — on each of the hosts that can start one (GH #229,
//! GH #239).
//!
//! These drive `start_session` itself, with real children, rather than
//! `session::launch`'s pure rules: those have their own rows, and what
//! is asserted here is that the handler *applies* them — that the
//! directory the child really runs in, and the environment it really
//! sees, are the ones the rules chose. A handler that computed the right
//! base environment and then spawned without it would pass every unit
//! row and fail every row here.
//!
//! **A daemon is simulated with `session::launch::hosted_by_daemon`**,
//! which is the scope `daemon::server::dispatch_tool` wraps every tool
//! call in. The real daemon, reached through two real shims, is
//! `crates/holdfast/tests/session_context.rs`; this file is the row that
//! can put a `profile` session beside a `command` one in the same scope.
//!
//! Unix-only: every child here is `/bin/sh`.
#![cfg(unix)]

use holdfast_core::mcp::tools::StartSessionArgs;
use holdfast_core::mcp::HoldfastServer;
use holdfast_core::session::launch::{hosted_by_daemon, ClientLaunch};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// What every probe prints, on one line: the directory it runs in and the
/// variables under test. `[…]` so an empty value is visible, and no `{`,
/// which a profile would read as a slot.
///
/// **Not `$PWD`**, which a shell re-derives from the real directory when
/// the inherited one disagrees — so a probe that printed it would pass
/// whether or not Holdfast set it. `PWD` has its own row below, read by a
/// program that takes its environment as given.
const PROBE: &str = "printf 'PROBE_OUT d=[%s] mark=[%s] home=[%s] path=[%s]\\n' \
     \"$(pwd -P)\" \"$MARK\" \"$HOME\" \"$PATH\"; sleep 30";

fn body(r: &rmcp::model::CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// A directory of its own, canonical, so it compares with what the
/// handler canonicalises and `pwd -P` prints.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let unique = uuid_ish();
        let dir = std::env::temp_dir().join(format!("holdfast-launch-{tag}-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir.canonicalize().unwrap())
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn uuid_ish() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    )
}

/// The one line the probe printed, parsed into its fields.
///
/// Polled off the session's own buffer, bounded. A `sh -c` argument is
/// not echoed, so the only `PROBE_OUT ` line there can be is the one the
/// child printed; it is taken once it is whole (ends in `]`).
fn probe_line(server: &HoldfastServer, id: &str) -> BTreeMap<String, String> {
    let session = server.registry.get(id).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = String::from_utf8_lossy(&session.read_from(0, 1 << 20).bytes).to_string();
        if let Some(line) = text.lines().find(|l| l.contains("PROBE_OUT ")) {
            if line.trim_end().ends_with(']') {
                return parse(line);
            }
        }
        assert!(
            Instant::now() < deadline,
            "the probe never printed its line; buffer: {text:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn parse(line: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = line.split("PROBE_OUT ").nth(1).unwrap_or_default();
    while let Some(eq) = rest.find("=[") {
        let key = rest[..eq].trim().to_string();
        let after = &rest[eq + 2..];
        let end = after.find(']').expect("a closing bracket");
        out.insert(key, after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}

async fn start(server: &HoldfastServer, args: StartSessionArgs) -> String {
    let r = server.start_session(Parameters(args)).await.unwrap();
    let b = body(&r);
    assert_eq!(b["status"], "ok", "{b}");
    b["data"]["session_id"].as_str().unwrap().to_string()
}

fn probe_command() -> StartSessionArgs {
    StartSessionArgs {
        command: Some("/bin/sh".into()),
        args: vec!["-c".into(), PROBE.into()],
        ..Default::default()
    }
}

fn kill_all(server: &HoldfastServer) {
    for s in server.registry.all() {
        let _ = s.signal(holdfast_core::pty::Signal::Kill);
    }
}

/// The calling client, as a shim would describe itself: its own
/// directory, and an environment that differs from this process's in
/// three deliberate ways — a variable only it has (`MARK`), a `PATH`
/// only it has, and **no `HOME`**, which this process certainly has.
fn a_client_in(dir: &str) -> ClientLaunch {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    env.insert("MARK".into(), "from-the-client".into());
    env.insert(
        "PATH".into(),
        format!("{}:/client-only-bin", std::env::var("PATH").unwrap()),
    );
    ClientLaunch {
        cwd: Some(dir.into()),
        env: Some(env),
    }
}

/// **GH #229, at the handler.** A `command` session with no `cwd`,
/// started in a daemon on behalf of a client somewhere else, runs where
/// the *client* is and sees the *client's* environment — and nothing of
/// the daemon's.
///
/// `home=[]` is the half an overlay would fail: the daemon (this test
/// process) has `HOME` and the client did not send one, so a child that
/// saw it inherited the daemon's environment underneath the client's.
/// Three GH #229 variables, three ways to be wrong.
#[tokio::test]
async fn a_command_session_in_a_daemon_starts_where_its_caller_is() {
    assert!(
        std::env::var_os("HOME").is_some(),
        "the row below proves replacement by the absence of a HOME this process has"
    );
    let project_b = Scratch::new("b");
    let server = HoldfastServer::new();

    let id = hosted_by_daemon(
        Some(a_client_in(project_b.path())),
        start(&server, probe_command()),
    )
    .await;
    let seen = probe_line(&server, &id);
    kill_all(&server);

    assert_eq!(
        seen["d"],
        project_b.path(),
        "the session ran in the daemon's directory, not its caller's: {seen:?}"
    );
    assert_eq!(seen["mark"], "from-the-client", "{seen:?}");
    assert!(
        seen["path"].ends_with(":/client-only-bin"),
        "the child's PATH must be the caller's: {seen:?}"
    );
    assert_eq!(
        seen["home"], "",
        "the daemon's own environment leaked in underneath the caller's: {seen:?}"
    );
}

/// The response says where the session is, and it must say the same
/// thing the child does — the one field an agent can check.
#[tokio::test]
async fn the_reported_cwd_is_the_callers_directory() {
    let project_b = Scratch::new("reported");
    let server = HoldfastServer::new();
    let r = hosted_by_daemon(
        Some(a_client_in(project_b.path())),
        server.start_session(Parameters(probe_command())),
    )
    .await
    .unwrap();
    kill_all(&server);
    assert_eq!(body(&r)["data"]["cwd"], project_b.path());
}

/// An explicit `cwd` still wins over the caller's directory — the
/// context is a *default*, and an agent that named a directory named it.
#[tokio::test]
async fn an_explicit_cwd_outranks_the_callers_directory() {
    let project_b = Scratch::new("default");
    let elsewhere = Scratch::new("explicit");
    let server = HoldfastServer::new();
    let id = hosted_by_daemon(
        Some(a_client_in(project_b.path())),
        start(
            &server,
            StartSessionArgs {
                cwd: Some(elsewhere.path().into()),
                ..probe_command()
            },
        ),
    )
    .await;
    let seen = probe_line(&server, &id);
    kill_all(&server);
    assert_eq!(seen["d"], elsewhere.path(), "{seen:?}");
}

/// A client whose own directory has gone is refused rather than fallen
/// back from: the fallback is this process's directory, which is GH #229
/// exactly — a session in somebody else's project.
///
/// **This row is the shim that did read a directory**, which the daemon
/// then cannot find: removed between the two, or a platform whose
/// `getcwd` still answers for a removed directory. On Linux a shim in a
/// removed directory reads none at all, which is the next row.
#[tokio::test]
async fn a_caller_whose_directory_is_gone_is_told_so_rather_than_moved() {
    let gone = Scratch::new("gone");
    let path = gone.path().to_string();
    drop(gone);
    let server = HoldfastServer::new();
    let err = hosted_by_daemon(
        Some(a_client_in(&path)),
        server.start_session(Parameters(probe_command())),
    )
    .await
    .expect_err("a session must not silently start somewhere else");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("pass `cwd`"), "{}", err.message);
    assert!(
        server.registry.all().is_empty(),
        "a refused call must not have started anything"
    );
}

/// **A caller that could not say where it is** — a context with no
/// `cwd`, which is what the shim sends when `getcwd` fails, as it does on
/// Linux once the directory has been removed. Found by review: the
/// handler read that absence as "use your own", so a client whose project
/// had been deleted started in whichever project spawned the daemon, and
/// was told `ok`. The same client can still name a directory.
#[tokio::test]
async fn a_caller_that_could_not_read_its_directory_is_refused_rather_than_moved() {
    let lost = || ClientLaunch {
        cwd: None,
        ..a_client_in("/unused")
    };
    let server = HoldfastServer::new();
    let err = hosted_by_daemon(
        Some(lost()),
        server.start_session(Parameters(probe_command())),
    )
    .await
    .expect_err("a session must not silently start in the daemon's directory");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("pass `cwd`"), "{}", err.message);
    assert!(
        server.registry.all().is_empty(),
        "a refused call must not have started anything"
    );

    let named = Scratch::new("named");
    let id = hosted_by_daemon(
        Some(lost()),
        start(
            &server,
            StartSessionArgs {
                cwd: Some(named.path().into()),
                ..probe_command()
            },
        ),
    )
    .await;
    let seen = probe_line(&server, &id);
    kill_all(&server);
    assert_eq!(seen["d"], named.path(), "{seen:?}");
}

/// **The GH #55 half.** A `profile` session in the same daemon, for the
/// same caller, takes **neither** the caller's directory nor its
/// environment: the operator wrote that process, and the context under
/// `@client` is reachable by anything that can speak the control
/// protocol. It keeps this process's directory and environment, exactly
/// as it did before GH #229.
#[tokio::test]
async fn a_profile_session_keeps_the_operators_directory_and_environment() {
    let project_b = Scratch::new("profile");
    let mut cfg = holdfast_core::config::parse_str("").unwrap();
    cfg.security.profiles = vec![holdfast_core::config::SessionProfile {
        name: "probe".into(),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), PROBE.into()],
        vars: BTreeMap::new(),
        env: BTreeMap::new(),
        cwd: None,
    }];
    cfg.validate()
        .expect("an operator could write this profile");
    let server = HoldfastServer::with_audit_path_and_config(None, &cfg);

    let id = hosted_by_daemon(
        Some(a_client_in(project_b.path())),
        start(
            &server,
            StartSessionArgs {
                profile: Some("probe".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    let seen = probe_line(&server, &id);
    kill_all(&server);

    let here = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(
        seen["d"],
        here.to_str().unwrap(),
        "a profile session took the caller's directory (GH #55): {seen:?}"
    );
    assert_eq!(
        seen["mark"], "",
        "a profile session took the caller's environment (GH #55): {seen:?}"
    );
    assert_eq!(
        seen["home"],
        std::env::var("HOME").unwrap(),
        "a profile session keeps the daemon's environment: {seen:?}"
    );
}

/// In-process there is no daemon and no context: the process *is* the
/// client's, and its environment is inherited as it always was.
#[tokio::test]
async fn in_process_a_session_inherits_this_processs_environment() {
    let server = HoldfastServer::new();
    let id = start(&server, probe_command()).await;
    let seen = probe_line(&server, &id);
    kill_all(&server);
    let here = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(seen["d"], here.to_str().unwrap(), "{seen:?}");
    assert_eq!(seen["home"], std::env::var("HOME").unwrap(), "{seen:?}");
}

/// `PWD` names the directory the child really runs in — on both hosts,
/// and over an inherited value that names somewhere else.
///
/// Read by `/usr/bin/env`, which prints its environment exactly as it
/// was handed it. A shell would not do: it re-derives `PWD` when the
/// inherited one disagrees with `.`, which is why `bash` never showed
/// the stale value and a script reading `$PWD` from Python did.
#[tokio::test]
async fn the_child_is_told_the_directory_it_really_runs_in() {
    let project_b = Scratch::new("pwd");
    let elsewhere = Scratch::new("pwd-explicit");
    let server = HoldfastServer::new();
    let env_dump = |cwd: Option<&str>| StartSessionArgs {
        command: Some("/usr/bin/env".into()),
        cwd: cwd.map(String::from),
        ..Default::default()
    };

    // In a daemon: the caller's environment says it is somewhere else.
    let mut client = a_client_in(project_b.path());
    client
        .env
        .as_mut()
        .unwrap()
        .insert("PWD".into(), "/not/where/it/runs".into());
    let hosted = hosted_by_daemon(Some(client), start(&server, env_dump(None))).await;

    // In-process, with an explicit `cwd` away from this process's own —
    // so the inherited `PWD` (this test's) is the wrong one there too.
    let in_process = start(&server, env_dump(Some(elsewhere.path()))).await;

    for (id, want) in [(hosted, project_b.path()), (in_process, elsewhere.path())] {
        let session = server.registry.get(&id).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let text = loop {
            let text = String::from_utf8_lossy(&session.read_from(0, 1 << 20).bytes).to_string();
            if !session.is_alive() && session.reader_finished() {
                break text;
            }
            assert!(Instant::now() < deadline, "env never finished: {text:?}");
            std::thread::sleep(Duration::from_millis(25));
        };
        let pwd: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim_end().strip_prefix("PWD="))
            .collect();
        assert_eq!(pwd, [want], "the child was handed the wrong PWD: {text:?}");
    }
}

/// **GH #239.** Every session is handed a pager that does not wait, and
/// the one git honours over its own config is among them.
///
/// `git var GIT_PAGER` prints the pager git *would* run, resolved through
/// its whole precedence chain, without running it or needing a
/// repository — so `-c core.pager=less` stands in for a user whose git
/// config sets one. `PAGER=cat` alone does not beat that (`core.pager`
/// outranks `PAGER`); only `GIT_PAGER` does, which is why a fix that set
/// `PAGER` and stopped would fail here and pass a check of the variable.
#[tokio::test]
async fn every_session_gets_pagers_that_do_not_wait() {
    let server = HoldfastServer::new();
    let script = "printf 'PROBE_OUT git=[%s] pager=[%s] man=[%s] systemd=[%s]\\n' \
                  \"$(git -c core.pager=less var GIT_PAGER)\" \"$PAGER\" \"$MANPAGER\" \
                  \"$SYSTEMD_PAGER\"; sleep 30";
    let id = start(
        &server,
        StartSessionArgs {
            command: Some("/bin/sh".into()),
            args: vec!["-c".into(), script.into()],
            ..Default::default()
        },
    )
    .await;
    let seen = probe_line(&server, &id);
    kill_all(&server);
    assert_eq!(
        seen["git"], "cat",
        "git would page through something that waits: {seen:?}"
    );
    assert_eq!(seen["pager"], "cat", "{seen:?}");
    assert_eq!(seen["man"], "cat", "{seen:?}");
    assert_eq!(seen["systemd"], "cat", "{seen:?}");
}

/// The pairing: the defaults are defaults. A caller that asks for a pager
/// gets the one it asked for, each variable on its own.
#[tokio::test]
async fn a_caller_that_sets_a_pager_gets_that_pager() {
    let server = HoldfastServer::new();
    let script = "printf 'PROBE_OUT git=[%s] pager=[%s] man=[%s]\\n' \
                  \"$(git -c core.pager=less var GIT_PAGER)\" \"$PAGER\" \"$MANPAGER\"; sleep 30";
    let mut env = HashMap::new();
    env.insert("GIT_PAGER".to_string(), "more".to_string());
    env.insert("PAGER".to_string(), "less -R".to_string());
    let id = start(
        &server,
        StartSessionArgs {
            command: Some("/bin/sh".into()),
            args: vec!["-c".into(), script.into()],
            env: Some(env),
            ..Default::default()
        },
    )
    .await;
    let seen = probe_line(&server, &id);
    kill_all(&server);
    assert_eq!(seen["git"], "more", "{seen:?}");
    assert_eq!(seen["pager"], "less -R", "{seen:?}");
    assert_eq!(
        seen["man"], "cat",
        "a default the caller did not override stays: {seen:?}"
    );
}
