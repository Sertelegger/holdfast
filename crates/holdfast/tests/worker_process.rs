//! `holdfast pty-worker`, driven as a **real process** against a real
//! `WorkerSocket` (§3.1, §4.1, §7.3, milestone 0.0.10a Task 3).
//!
//! # Why these rows are here and not in `holdfast-core/tests/worker_protocol.rs`
//!
//! The plan puts Task 3's table in that file. **The tree does not allow
//! it**, and the reason is Cargo's rather than anybody's judgement:
//! `CARGO_BIN_EXE_holdfast` is set for the integration tests *of the
//! package that declares the binary*, and `holdfast-core` declares none.
//! Every row below spawns the real binary, so every row below needs that
//! variable, so every row below lives in this crate. The alternative —
//! deriving `target/<profile>/holdfast` from `current_exe()` in the other
//! crate — is the path guessing `attach_cli.rs`'s own comment says this
//! project does not do.
//!
//! `worker_protocol.rs`'s deferred block names the rows it owed to Task 3
//! and now points here for them, rather than being left to say they are
//! still owed.
//!
//! # What "drive the worker directly" means, and why it is not `start_session`
//!
//! Task 3's table is written against `start_session`. **A session cannot
//! use a worker until Task 4 builds `SubprocessPty` and Task 12 teaches
//! the one construction site to choose a backend**, so every row here
//! binds its own `WorkerSocket`, spawns `holdfast pty-worker` against it,
//! and asserts on *that* process. Every assertion survives the
//! translation with its substance intact: a worker's `/proc/<pid>/cmdline`
//! is the same argv whether the spawn was reached through `start_session`
//! or through `spawn::start_worker`, and `start_worker` is the code
//! `start_session` will call.
//!
//! What does **not** survive is enumerated, because §11.2's rule is that
//! an exclusion is enumerated or it is not an exclusion:
//!
//! * the §18.1 status string. `a_build_mismatch_refuses_the_link…` below
//!   asserts the error maps to `HoldfastError::Pty`, which is the variant
//!   `start_session` turns into `status: "spawn_failed"` without
//!   inspecting — the mapping, not the string. The string is produced by
//!   `mcp::tools`, which has no worker to fail at until **Task 12**.
//!
//! # Every wait here is bounded and every elapsed arm fails
//!
//! This milestone's characteristic failure is a test that hangs rather
//! than one that fails: every operation gained a "the peer never answers"
//! arm that an fd read did not have. `.config/nextest.toml`'s
//! `terminate-after` names a hang at 300 s instead of taking the job down
//! anonymously, which changes what a hang costs and not whether one is
//! acceptable. So: no `.await` on a worker round trip without
//! [`tokio::time::timeout`], no `matches!(x, Ok(Err(_)) | Err(_))` around
//! an awaited call — it accepts a timeout as a pass — and every worker is
//! killed on the way out by `WorkerProcess`'s `Drop`, pass or fail.
//!
//! # `/proc` is Linux-only, and **there is still no macOS job**
//!
//! Checked rather than assumed, because this task was dispatched on the
//! belief that one had landed: every `runs-on:` in `.github/workflows/`
//! is `ubuntu-24.04` except a single `windows-2022`. So the split below
//! is written for the developer machine and for whenever 0.0.11 or later
//! adds the job — not for a job that exists today.
//!
//! Two rows read `/proc`. Each `/proc` assertion is
//! `#[cfg(target_os = "linux")]` and each is **paired with a portable
//! `ps` assertion**, so on a non-Linux Unix the row still asserts
//! something rather than silently becoming a no-op — which is the
//! failure mode `CLAUDE.md`'s macOS section is about, and it costs a
//! wrong diagnosis whether or not CI is watching. Writing a macOS
//! `sysctl`/`KERN_PROCARGS2` path instead would be code **no job in this
//! repository exercises**, which the same section explains is worse than
//! an honest gap.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::protocol::frame::{self, LENGTH_PREFIX_BYTES};
use holdfast_core::protocol::method::CborValue;
use holdfast_core::pty::worker::frames::{
    encode_frame, read_frame, DaemonFrame, LinkFrame, WorkerFrame, WORKER_PROTOCOL_TAG,
};
use holdfast_core::pty::worker::socket::WorkerSocket;
use holdfast_core::pty::worker::spawn::{
    handshake, start_worker, HandshakeError, WorkerHandshake, WorkerProcess, WORKER_LOG_PREFIX,
    WORKER_SOCKET_FLAG, WORKER_SUBCOMMAND,
};
use holdfast_core::pty::PtySpawnConfig;
use holdfast_core::HoldfastError;

/// The binary under test. Cargo sets it for a package with a `[[bin]]`,
/// so there is no path guessing and no `target/debug` hardcoded anywhere.
const BIN: &str = env!("CARGO_BIN_EXE_holdfast");

/// The one deadline for a peer that should have answered immediately.
///
/// Deliberately larger than the daemon's own 5 s accept and handshake
/// deadlines, so a row that hits *this* one has caught an unbounded wait
/// rather than raced a busy machine past a bound that fired correctly.
const DEADLINE: Duration = Duration::from_secs(20);

/// A session id in the shape `session::new_session_id` emits.
///
/// The socket path is derived from it, and it is spelled out rather than
/// generated so a fixture cannot vary how close these rows run to
/// `sun_path`'s 108 bytes.
const SESSION_ID: &str = "sess_0123456789ab";

/// The deadline used **inside** a re-executed child, and it is
/// deliberately shorter than [`DEADLINE`].
///
/// A parent that waits exactly as long as its child does reports its own
/// timeout first, and the child's assertion — the one that names what
/// actually went wrong — never gets written. Measured while
/// mutation-testing the stderr row: with both at 20 s the row reddened
/// with `the child exited within the deadline: Elapsed(())` and said
/// nothing about the marker.
const CHILD_DEADLINE: Duration = Duration::from_secs(8);

// ------------------------------------------------------------ fixtures

/// A token that appears in exactly one process's argv on this machine.
///
/// The pid and the counter together survive `--test-threads`, nextest's
/// process-per-test, and two checkouts of this repository running the
/// suite at once — all three of which have produced a false "no leftover
/// process" in this project before.
fn unique_token(tag: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "HOLDFAST-CHILD-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// A child that stays up until it is retired, carrying `token` in its own
/// argv so the process table can be asked whether it exists.
///
/// `sh -c` without `exec`, deliberately: `exec sleep` would replace the
/// shell and take the token off the argv with it, and the whole point of
/// the token is that a *live* process carries it.
fn long_lived(token: &str) -> PtySpawnConfig {
    PtySpawnConfig {
        command: "/bin/sh".to_string(),
        // **`; :` and not a trailing comment, because a shell may `exec`
        // the token away.** `sh -c '<one simple command>'` is exactly the
        // case a shell optimises by `exec`ing rather than forking — the
        // process replaces its argv with `sleep 60`, and the token that
        // `any_process_matching` looks for goes with it. Linux `/bin/sh`
        // is dash and does not do it here; macOS `/bin/sh` is bash and
        // does, so the child existed under an argv nothing was searching
        // for and the control arm reported "never produced a child".
        //
        // A second command after `sleep 60` removes the optimisation's
        // precondition: the shell must survive the sleep to run it, so it
        // stays alive holding the whole `-c` string — token included — in
        // its own argv. Verified on dash: the token is visible either way
        // there, which is why this was invisible until a BSD job existed.
        args: vec!["-c".to_string(), format!("sleep 60; : {token}")],
        cwd: None,
        env: Vec::new(),
        cols: 80,
        rows: 24,
    }
}

/// Whether any process on this machine has `token` in its argv.
///
/// `ps -eo args=` rather than `pgrep -f`: `pgrep` is not on every Unix
/// this project claims, and `ps -o args` is POSIX. **Not `-o comm=`** —
/// that omits arguments, so matching a command line against it never hits
/// (`CLAUDE.md`'s macOS section, where it has already cost a wrong
/// diagnosis).
fn any_process_matching(token: &str) -> bool {
    // **`-A -ww`, not `-eo`, and both halves are load-bearing on BSD.**
    // `-e` lists only processes with a controlling terminal there, and the
    // worker is spawned with null stdio — so on macOS it was invisible and
    // this returned `false` for a child that existed. `-ww` stops `ps`
    // clamping the argv column to the terminal width, which would cut the
    // token this matches on. `tests/daemon_cli.rs` already spells it this
    // way for the same reason; this file diverged from it.
    let out = Command::new("ps")
        .args(["-A", "-ww", "-o", "args="])
        .output()
        .expect("ps -A -ww -o args=");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        // The `ps` invocation itself cannot match — it carries `args=`
        // and not the token — but a shell that ran one might, so the
        // match is on the token alone and the fixture is what keeps it
        // unique.
        .any(|l| l.contains(token))
}

/// One process's argv, as `ps` reports it. Empty when the process is gone.
fn ps_args(pid: u32) -> String {
    // `-ww` for the same reason as above: naming the pid avoids the
    // controlling-terminal filter, but not the width clamp on the argv.
    let out = Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "args="])
        .output()
        .expect("ps -ww -p <pid> -o args=");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `/proc/<pid>/stat`'s `pgrp` and `session` fields (5 and 6).
///
/// Parsed after the **last** `)`, because field 2 is the executable name
/// in parentheses and it may itself contain spaces and parentheses —
/// splitting the whole line on whitespace is the classic way to read
/// field 5 out of the wrong place.
#[cfg(target_os = "linux")]
fn proc_stat_groups(pid: u32) -> (i32, i32) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap_or_else(|e| panic!("/proc/{pid}/stat: {e}"));
    let tail = &stat[stat.rfind(')').expect("comm is parenthesised") + 1..];
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // `tail` starts at field 3 (state), so pgrp and session are [2] and [3].
    (
        fields[2].parse().expect("pgrp"),
        fields[3].parse().expect("session"),
    )
}

/// A bound socket, a spawned worker, and the completed handshake.
struct Booted {
    stream: UnixStream,
    started: WorkerHandshake,
    worker: WorkerProcess,
    // Both are dropped last on purpose: the socket unlinks itself on
    // `Drop` and the directory takes the runtime tree with it, and doing
    // either before the worker has been killed would race the worker's
    // own teardown.
    _sock: WorkerSocket,
    _dir: tempfile::TempDir,
}

/// Bind, spawn, accept, handshake — the whole daemon-side sequence, under
/// one deadline whose elapsed arm fails.
async fn boot(cfg: &PtySpawnConfig) -> Booted {
    let dir = tempfile::tempdir().expect("a private runtime directory");
    let paths = RuntimePaths::with_dir(dir.path());
    // Bind **before** spawn. The other way round is the readiness race
    // §7.3 spent a subsection eliminating for the daemon itself.
    let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind the worker socket");
    let worker = start_worker(Path::new(BIN), sock.path()).expect("spawn holdfast pty-worker");

    let mut stream = tokio::time::timeout(DEADLINE, sock.accept_worker(worker.pid()))
        .await
        .expect("the accept resolved within the test's own deadline")
        .expect("the worker connected");
    let started = tokio::time::timeout(DEADLINE, handshake(&mut stream, SESSION_ID, cfg))
        .await
        .expect("the handshake resolved within the test's own deadline")
        .expect("the handshake succeeded");

    Booted {
        stream,
        started,
        worker,
        _sock: sock,
        _dir: dir,
    }
}

/// Read one frame under [`DEADLINE`], failing the test if it elapses.
async fn next_frame(stream: &mut UnixStream) -> WorkerFrame {
    tokio::time::timeout(DEADLINE, read_frame::<_, WorkerFrame>(stream))
        .await
        .expect("a frame arrived within the deadline")
        .expect("the frame decoded")
}

/// Send one daemon frame.
async fn send(stream: &mut UnixStream, frame: &DaemonFrame) {
    let bytes = encode_frame(frame).expect("a daemon frame encodes");
    tokio::time::timeout(DEADLINE, stream.write_all(&bytes))
        .await
        .expect("the write completed within the deadline")
        .expect("the write succeeded");
}

/// Assert that a read returned "the peer has gone", in either of the two
/// shapes a closed Unix socket produces.
///
/// **`Eof` is not the only one, and assuming it was cost a wrong red.**
/// A peer that closes while unread bytes are still queued for it makes
/// the *next* read report `ECONNRESET` rather than a clean end of stream
/// — which is exactly what a worker that has already refused the link
/// does when the test writes one more frame at it. Both are "the link is
/// closed"; neither is "the worker answered".
///
/// **A timeout is not accepted here and cannot reach here**: every caller
/// awaits under `tokio::time::timeout` whose elapsed arm `expect`s, so a
/// worker that simply never answered fails before this function is
/// called. That is the `matches!(x, Ok(Err(_)) | Err(_))` shape this
/// milestone bans, kept out by construction rather than by care.
fn assert_link_closed(what: Result<WorkerFrame, frame::FrameError>) {
    match what {
        Err(frame::FrameError::Eof) => {}
        Err(frame::FrameError::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("the worker answered a link it should have refused: {other:?}"),
    }
}

/// Wait for the worker to exit, failing rather than hanging.
async fn wait_exit(worker: &mut WorkerProcess, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = worker.try_wait().expect("try_wait on the worker") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the worker at {} was still running after {within:?}; it should have exited",
            worker.pid()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Poll `path` until it contains `needle`, bounded. Returns the contents.
///
/// The bound is the row's, and its elapsed arm **panics**: a poll for a
/// line a crashed child will never write is the hang this milestone is
/// most afraid of.
fn wait_for_text(path: &Path, needle: &str, within: Duration) -> String {
    let deadline = Instant::now() + within;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "{} never contained {needle:?} within {within:?}; it holds:\n{text}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ----------------------------------------------- the spawn config's path

/// The key and the value are separate assertions because they leak
/// separately: a `--env KEY=VALUE` argv leaks both, and a `--env-keys`
/// argv leaks only the name — which is still §9.2's `env_keys` escaping
/// onto a world-readable surface it was never audited onto.
const LEAK_KEY: &str = "HOLDFAST_TEST_ARGV_LEAK_KEY";
const LEAK_VALUE: &str = "ghp_TESTVALUEdeadbeef0123456789";

#[tokio::test]
async fn the_spawn_config_never_appears_on_the_workers_command_line() {
    let cfg = PtySpawnConfig {
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            // The child echoes the variable back, which is the pairing:
            // without it this row passes against a worker that drops
            // `env` entirely and therefore leaks nothing because it
            // carries nothing.
            format!("printf 'GOT[%s]\\n' \"${LEAK_KEY}\"; sleep 60"),
        ],
        cwd: None,
        env: vec![(LEAK_KEY.to_string(), LEAK_VALUE.to_string())],
        cols: 80,
        rows: 24,
    };
    let mut booted = boot(&cfg).await;
    let worker_pid = booted.worker.pid();

    // --- the negative: neither the value nor the key name is on the argv

    // Portable half. Runs on macOS, where `/proc` does not exist.
    let args = ps_args(worker_pid);
    // The pairing for *this* assertion: an empty `ps` line satisfies
    // "does not contain the secret" for a process that has already died.
    assert!(
        args.contains(WORKER_SUBCOMMAND) && args.contains(WORKER_SOCKET_FLAG),
        "ps did not report the worker's argv at all, so the assertions below \
         would hold against nothing: {args:?}"
    );
    assert!(
        !args.contains(LEAK_VALUE),
        "the spawn config's value is on the worker's command line: {args}"
    );
    assert!(
        !args.contains(LEAK_KEY),
        "the spawn config's key name is on the worker's command line: {args}"
    );

    // Linux half: `/proc/<pid>/cmdline` is world-readable, which is the
    // surface this row exists for. NUL-separated, so it is read as bytes
    // and searched as one string.
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read(format!("/proc/{worker_pid}/cmdline"))
            .expect("/proc/<worker>/cmdline is readable");
        let cmdline = String::from_utf8_lossy(&raw).replace('\0', " ");
        assert!(
            cmdline.contains(WORKER_SUBCOMMAND) && cmdline.contains(WORKER_SOCKET_FLAG),
            "read an empty cmdline, so nothing below asserts anything: {cmdline:?}"
        );
        assert!(
            !cmdline.contains(LEAK_VALUE),
            "the spawn config's value is in /proc/{worker_pid}/cmdline: {cmdline}"
        );
        assert!(
            !cmdline.contains(LEAK_KEY),
            "the spawn config's key name is in /proc/{worker_pid}/cmdline: {cmdline}"
        );

        // And the same mistake one directory along. Putting the session's
        // `env` on the *worker's* environment instead of its argv moves
        // the leak from `cmdline` to `environ` and fixes nothing.
        let environ = std::fs::read(format!("/proc/{worker_pid}/environ"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
            .unwrap_or_default();
        assert!(
            !environ.contains(LEAK_VALUE) && !environ.contains(LEAK_KEY),
            "the spawn config is in /proc/{worker_pid}/environ"
        );
    }

    // --- the positive: the child nevertheless got the variable

    let want = format!("GOT[{LEAK_VALUE}]");
    let mut seen = Vec::new();
    let echoed = tokio::time::timeout(DEADLINE, async {
        loop {
            match read_frame::<_, WorkerFrame>(&mut booted.stream).await {
                Ok(WorkerFrame::Output { bytes }) => {
                    seen.extend_from_slice(&bytes);
                    if String::from_utf8_lossy(&seen).contains(&want) {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => panic!("the link died before the child echoed: {e}"),
            }
        }
    })
    .await;
    assert!(
        echoed.is_ok(),
        "the child never echoed {want:?}, so the argv assertions above hold \
         against a worker that may simply have dropped `env`. Saw: {:?}",
        String::from_utf8_lossy(&seen)
    );
}

// ----------------------------------------------------- the build check

const WRONG_BUILD: &str = "0.0.0-wrong";

#[tokio::test]
async fn a_build_mismatch_refuses_the_link_and_reports_spawn_failed() {
    // --- Arm A: a stub worker presents the wrong build to the daemon.
    //
    // This process is the stub, which is legitimate here in a way it was
    // not for the peer check: the daemon's build comparison reads a
    // *frame*, not a credential, so any peer can present one.
    let dir = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::with_dir(dir.path());
    let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind");
    let token = unique_token("mismatch-a");
    let cfg = long_lived(&token);

    let path = sock.path().to_path_buf();
    let ((accepted, _), mut stub) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(
            async {
                let s = sock
                    .accept_worker(std::process::id())
                    .await
                    .expect("the stub is accepted");
                (s, ())
            },
            async {
                let mut c = UnixStream::connect(&path).await.expect("the stub connects");
                let bytes = encode_frame(&WorkerFrame::Ready {
                    build: WRONG_BUILD.to_string(),
                })
                .expect("Ready encodes");
                c.write_all(&bytes).await.expect("the stub writes Ready");
                c
            }
        )
    })
    .await
    .expect("the stub handshake resolved within the deadline");
    let mut accepted = accepted;

    let err = tokio::time::timeout(DEADLINE, handshake(&mut accepted, SESSION_ID, &cfg))
        .await
        .expect("the handshake resolved within the deadline")
        .expect_err("a wrong build must be refused");
    assert!(
        matches!(&err, HandshakeError::BuildMismatch { ours, theirs }
                 if ours == WORKER_PROTOCOL_TAG && theirs == WRONG_BUILD),
        "expected a named build mismatch, got {err:?}"
    );

    // **`spawn_failed`-shaped.** REQ-SPTY-001 adds no `Status` value for a
    // refused worker: `start_session` maps a backend construction `Err` to
    // `Status::SpawnFailed` without inspecting it, and `Pty` is the
    // variant `InProcessPty::spawn` returns for every one of its own
    // failures. A conversion producing anything else would still reach
    // `spawn_failed` today and would diverge the moment something matched.
    let mapped = HoldfastError::from(err);
    assert!(
        matches!(mapped, HoldfastError::Pty(_)),
        "a refused handshake must arrive as the same variant a failed \
         InProcessPty::spawn does, got {mapped:?}"
    );

    // The link closed, and **no `Spawn` was sent** — so the stub's next
    // read is EOF rather than a config it could have acted on.
    drop(accepted);
    let after = tokio::time::timeout(DEADLINE, read_frame::<_, DaemonFrame>(&mut stub))
        .await
        .expect("the stub's read resolved within the deadline");
    assert!(
        matches!(after, Err(frame::FrameError::Eof)),
        "the daemon sent something after refusing the build: {after:?}"
    );
    assert!(
        !any_process_matching(&token),
        "a child was created for a link the daemon refused"
    );
    drop(sock);

    // --- Arm B: the daemon presents the wrong build to a real worker.
    //
    // Written frame by frame rather than through `handshake_as`, because
    // that helper refuses at the worker's `Ready` and therefore never
    // reaches the `Hello` this arm is about. The worker's own check is
    // the one under test.
    let dir = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::with_dir(dir.path());
    let sock = WorkerSocket::bind(&paths, SESSION_ID).expect("bind");
    let token = unique_token("mismatch-b");
    let cfg = long_lived(&token);
    let mut worker = start_worker(Path::new(BIN), sock.path()).expect("spawn the worker");
    let mut stream = tokio::time::timeout(DEADLINE, sock.accept_worker(worker.pid()))
        .await
        .expect("the accept resolved within the deadline")
        .expect("the worker connected");

    let ready = next_frame(&mut stream).await;
    assert!(
        matches!(&ready, WorkerFrame::Ready { build } if build == WORKER_PROTOCOL_TAG),
        "the worker's first frame is its build, got {ready:?}"
    );
    send(
        &mut stream,
        &DaemonFrame::Hello {
            build: WRONG_BUILD.to_string(),
            session_id: SESSION_ID.to_string(),
        },
    )
    .await;

    // **And a `Spawn` right behind it, which is what makes this arm
    // falsifiable.** Without it, a worker whose build check had been
    // deleted would sit waiting for a config that never came, hit its own
    // `WORKER_HELLO_TIMEOUT`, exit non-zero and close the link — passing
    // every assertion below for the wrong reason. Measured: deleting the
    // check left this row green until this frame was added. With it, a
    // worker that does not check the build spawns the child and answers
    // `Started`, and both of those are visible.
    //
    // The write may itself fail, because a *correct* worker has already
    // closed the socket by now — so the error is deliberately not
    // asserted on. What is asserted is what the worker did.
    let bytes = encode_frame(&DaemonFrame::Spawn { cfg }).expect("Spawn encodes");
    let _ = tokio::time::timeout(DEADLINE, stream.write_all(&bytes))
        .await
        .expect("the write resolved within the deadline");

    // The worker closes the link rather than acting on either frame.
    assert_link_closed(
        tokio::time::timeout(DEADLINE, read_frame::<_, WorkerFrame>(&mut stream))
            .await
            .expect("the worker's response resolved within the deadline"),
    );
    let status = wait_exit(&mut worker, DEADLINE).await;
    assert!(
        !status.success(),
        "a worker that refused the handshake exited 0, which a daemon reads as \
         a clean shutdown: {status}"
    );
    assert!(
        !any_process_matching(&token),
        "the worker forked a child before it had checked the daemon's build"
    );
    drop(sock);

    // --- Arm C: the pairing. The same fixture with the right build DOES
    // produce a child, so the two absences above can distinguish a
    // refusal from a fixture that never forks.
    let token = unique_token("mismatch-c");
    let cfg = long_lived(&token);
    let booted = boot(&cfg).await;
    assert!(booted.started.child_pid > 0);
    let deadline = Instant::now() + DEADLINE;
    while !any_process_matching(&token) {
        assert!(
            Instant::now() < deadline,
            "the control arm never produced a child, so the two refusal arms \
             above assert nothing"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ------------------------------------------------------ Started's groups

#[tokio::test]
async fn started_reports_the_childs_real_pgid_and_sid() {
    let token = unique_token("groups");
    let booted = boot(&long_lived(&token)).await;
    let child_pid = booted.started.child_pid;
    let worker_pid = booted.worker.pid();

    // `portable-pty` `setsid`s the child, so all three of these are the
    // same number — which is exactly why the comparison must come from
    // the kernel and not from the frame compared against itself.
    assert_eq!(
        booted.started.pgid,
        Some(child_pid as i32),
        "the child is its own process-group leader"
    );
    assert_eq!(
        booted.started.sid,
        Some(child_pid as i32),
        "the child is its own session leader"
    );

    #[cfg(target_os = "linux")]
    {
        let (pgrp, session) = proc_stat_groups(child_pid);
        assert_eq!(
            booted.started.pgid,
            Some(pgrp),
            "Started's pgid is not the one /proc/{child_pid}/stat reports"
        );
        assert_eq!(
            booted.started.sid,
            Some(session),
            "Started's sid is not the one /proc/{child_pid}/stat reports"
        );

        // **The separating assertion.** `getpgid(0)`/`getsid(0)` — the
        // worker's own groups instead of the child's — is the plausible
        // typo, and it is the only mutation of this pair that a happy
        // path can see: the child *is* its own leader, so hard-coding
        // `pgid = child_pid` produces the right answer by accident and
        // no assertion in a successful spawn can tell the two apart.
        // That is recorded here rather than left as an unfalsifiable
        // claim in a doc comment.
        let (worker_pgrp, worker_session) = proc_stat_groups(worker_pid);
        assert_ne!(
            booted.started.pgid,
            Some(worker_pgrp),
            "Started reported the worker's own process group, not the child's"
        );
        assert_ne!(
            booted.started.sid,
            Some(worker_session),
            "Started reported the worker's own session, not the child's"
        );
    }

    // Portable half, so this row still asserts something on macOS.
    // `pgid` is a POSIX `ps` format keyword; there is no portable one for
    // the session id, which is why the sid arm above is Linux-only.
    let out = Command::new("ps")
        .arg("-p")
        .arg(child_pid.to_string())
        .arg("-o")
        .arg("pgid=")
        .output()
        .expect("ps -p <child> -o pgid=");
    let reported: i32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|e| {
            panic!(
                "ps reported no pgid for the child at {child_pid}: {e} ({:?})",
                String::from_utf8_lossy(&out.stdout)
            )
        });
    assert_eq!(
        booted.started.pgid,
        Some(reported),
        "Started's pgid is not the one ps reports for the child"
    );
}

// ------------------------------------------------- the standard streams

/// Set on the re-executed child.
const STREAMS_CHILD_ENV: &str = "HOLDFAST_TEST_WORKER_STREAMS_CHILD";
/// Where the child's own fd 2 has been redirected — the `daemon.log`
/// stand-in, since `diag::emit` writes to this process's stderr and
/// `holdfast daemon run`'s stderr *is* `daemon.log` (§9.2).
const ERR_LOG_ENV: &str = "HOLDFAST_TEST_WORKER_ERR_LOG";
const OUT_LOG_ENV: &str = "HOLDFAST_TEST_WORKER_OUT_LOG";
const CHILD_TEST: &str = "the_child_that_spawns_a_worker_writing_to_both_streams";
const STDOUT_MARKER: &str = "WORKER-STDOUT-MARKER-ZZQ";
const STDERR_MARKER: &str = "WORKER-STDERR-MARKER-ZZQ";

#[tokio::test]
async fn the_workers_stderr_reaches_daemon_log_and_its_stdout_reaches_nothing() {
    if std::env::var_os(STREAMS_CHILD_ENV).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out_log = dir.path().join("stdout.log");
    let err_log = dir.path().join("stderr.log");

    // **A re-executed child, because the assertion is about fds 1 and 2.**
    // `diag::emit` writes to `std::io::stderr()` directly and deliberately
    // bypasses libtest's capture, so the only way to read what the daemon
    // would have logged is to *be* a process whose fd 2 is a file. That is
    // `diag`'s own
    // `nothing_reaches_daemon_log_unredacted_not_even_a_panic` idiom.
    let child = Command::new(std::env::current_exe().expect("this test binary's path"))
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(STREAMS_CHILD_ENV, "1")
        .env(OUT_LOG_ENV, &out_log)
        .env(ERR_LOG_ENV, &err_log)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(
            std::fs::File::create(&out_log).expect("create the stdout log"),
        ))
        .stderr(std::process::Stdio::from(
            std::fs::File::create(&err_log).expect("create the stderr log"),
        ))
        .spawn()
        .expect("re-exec this test binary");

    let status = tokio::time::timeout(
        DEADLINE,
        tokio::task::spawn_blocking(move || {
            let mut child = child;
            child.wait()
        }),
    )
    .await
    .expect("the child exited within the deadline")
    .expect("the blocking join")
    .expect("the child's status");

    let out = std::fs::read_to_string(&out_log).unwrap_or_default();
    let err = std::fs::read_to_string(&err_log).unwrap_or_default();
    assert!(
        status.success(),
        "the child failed: {status}\n--- fd 1 ---\n{out}\n--- fd 2 ---\n{err}"
    );

    // The stderr marker reached the log, **behind the drain's prefix**.
    // The prefix is what separates this from an inherited stderr, which
    // would deliver the same bytes to the same fd with nothing in front
    // of them — the single-character mutation that a bare "the marker
    // arrived" assertion cannot see.
    assert!(
        err.contains(STDERR_MARKER),
        "the worker's stderr never reached the log:\n{err}"
    );
    assert!(
        err.lines()
            .any(|l| l.contains(STDERR_MARKER) && l.contains(WORKER_LOG_PREFIX)),
        "the stderr marker arrived without the drain's prefix, which is what an \
         inherited (rather than drained) stderr looks like:\n{err}"
    );

    // The stdout marker reached nothing: not the log, not fd 1, and — by
    // construction, since both are files this test owns — nowhere a human
    // or a terminal could see it.
    assert!(
        !out.contains(STDOUT_MARKER),
        "the worker's stdout was not nulled; it reached fd 1:\n{out}"
    );
    assert!(
        !err.contains(STDOUT_MARKER),
        "the worker's stdout was redirected onto the daemon's log:\n{err}"
    );

    // And the real binary's own diagnostic makes the same trip, so this
    // row is not only about a shell-script fixture: a worker that cannot
    // connect says so, and the daemon is what records it.
    assert!(
        err.lines()
            .any(|l| l.contains(WORKER_LOG_PREFIX) && l.contains("worker link")),
        "the real worker's connect failure never reached the log:\n{err}"
    );
}

/// The other half of the row above; a no-op unless re-entered as a child,
/// so the ordinary suite runs it and it costs nothing.
#[tokio::test]
async fn the_child_that_spawns_a_worker_writing_to_both_streams() {
    let Some(err_log) = std::env::var_os(ERR_LOG_ENV) else {
        return;
    };
    let err_log = PathBuf::from(err_log);

    // A fixture that writes to both streams, because the *real* worker
    // cannot: this milestone's constraint 8 forbids it any `print!` at
    // all, and `source_guards.rs` enforces that. So the stdout half is
    // asserted against a stand-in whose argv is the one `start_worker`
    // builds, and the stderr half is asserted twice — once here and once
    // against the real binary below.
    let dir = tempfile::tempdir().expect("scratch");
    let fixture = dir.path().join("noisy-worker.sh");
    std::fs::write(
        &fixture,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{STDOUT_MARKER}'\nprintf '%s\\n' '{STDERR_MARKER}' >&2\n"
        ),
    )
    .expect("write the fixture");
    std::fs::set_permissions(
        &fixture,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("make the fixture executable");

    // No socket is bound: this fixture ignores its argv and the row is
    // about the three streams, not about the link.
    let mut noisy = start_worker(&fixture, Path::new("/nonexistent/holdfast.sock"))
        .expect("spawn the noisy fixture");
    wait_exit(&mut noisy, CHILD_DEADLINE).await;

    // The real binary, refusing a socket that is not there. Its
    // diagnostic is produced by `commands::pty_worker`'s error arm, which
    // is the path a wedged install actually takes.
    let mut real = start_worker(Path::new(BIN), Path::new("/nonexistent/holdfast.sock"))
        .expect("spawn the real worker");
    let status = wait_exit(&mut real, CHILD_DEADLINE).await;
    assert!(
        !status.success(),
        "a worker that could not connect exited 0: {status}"
    );

    // The drain runs on its own thread and nothing here can join it, so
    // the wait is on the *observable*: the line appearing in the file
    // this process's fd 2 points at. Bounded, and its elapsed arm panics.
    wait_for_text(&err_log, STDERR_MARKER, CHILD_DEADLINE);
    wait_for_text(&err_log, "worker link", CHILD_DEADLINE);
}

// ------------------------------------------------------------- the help

#[test]
fn the_worker_is_absent_from_help() {
    // `holdfast --help` is not a flag this binary models — it falls
    // through to the usage error — but it prints the banner, which is the
    // surface under test. Both streams are read, because the banner goes
    // to stderr and a future one might not.
    for args in [vec!["--help"], vec![]] {
        let out = Command::new(BIN)
            .args(&args)
            .output()
            .expect("run holdfast");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("holdfast mcp"),
            "the banner did not print for {args:?}, so the assertion below \
             holds against nothing:\n{text}"
        );
        assert!(
            !text.contains(WORKER_SUBCOMMAND),
            "the internal worker subcommand is advertised in the banner for \
             {args:?}:\n{text}"
        );
    }

    // Hidden means absent from the banner, not undiagnosable.
    let out = Command::new(BIN)
        .arg(WORKER_SUBCOMMAND)
        .arg("--help")
        .output()
        .expect("run holdfast pty-worker --help");
    assert!(
        out.status.success(),
        "`holdfast pty-worker --help` failed: {}",
        out.status
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(WORKER_SUBCOMMAND) && text.contains(WORKER_SOCKET_FLAG),
        "`holdfast pty-worker --help` printed no usage:\n{text}"
    );
}

// ---------------------------- the two rows Task 1 deferred to this task

/// The ceiling this row asserts against. **Not `PTY_READ_BUF`**: an
/// assertion written against the buffer constant is satisfied by any
/// change to the constant and is therefore a tautology. 128 KiB is twice
/// the buffer and three orders of magnitude below `MAX_FRAME_BYTES`,
/// which is the claim being made — that the 16 MiB cap is unreachable on
/// this link rather than load-bearing on it.
///
/// **What actually bounds an `Output` frame is the tty's kernel buffer,
/// not `PTY_READ_BUF`** — measured while mutation-testing this row.
/// Raising the read buffer from 64 KiB to 1 MiB left the largest observed
/// frame unchanged, because one `read(2)` on a pty master returns only
/// what the line discipline has queued. The mutation that *does* redden
/// this row is coalescing several reads into one frame, which is the
/// implementation change that would genuinely put a large frame on the
/// wire; the constant is a ceiling on the buffer, not on the frame.
const NEAR_CAP: usize = 128 * 1024;

#[tokio::test]
async fn the_worker_never_constructs_a_frame_near_the_cap() {
    // `yes` because it is the cheapest way to make a PTY produce output
    // faster than a reader can want it — which is the condition under
    // which a worker that coalesced reads, or grew a frame per drain
    // rather than per read, would construct a large one.
    let cfg = PtySpawnConfig {
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "exec yes holdfast".to_string()],
        cwd: None,
        env: Vec::new(),
        cols: 80,
        rows: 24,
    };
    let mut booted = boot(&cfg).await;

    // Read the **wire** rather than the decoded frame: the encoded size
    // is what the cap is about, and `read_frame` throws the length prefix
    // away. `read_frame_body` is `read_frame` stopping one step short, so
    // this is the same codec and not a second one.
    let mut max = 0usize;
    let mut outputs = 0usize;
    let until = Instant::now() + Duration::from_secs(2);
    let observed = tokio::time::timeout(DEADLINE, async {
        while Instant::now() < until {
            let body = frame::read_frame_body(&mut booted.stream)
                .await
                .expect("the worker kept the link up while producing output");
            let wire = body.len() + LENGTH_PREFIX_BYTES;
            if matches!(
                WorkerFrame::decode_body(&body).expect("the frame decodes"),
                WorkerFrame::Output { .. }
            ) {
                outputs += 1;
                max = max.max(wire);
            }
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "the 2 s sampling window did not close within the test's deadline"
    );

    // The pairing: a worker that sent nothing would satisfy "no frame was
    // large" perfectly. `yes` at 80x24 produces megabytes in two seconds,
    // so both floors are far below anything a working link produces.
    assert!(
        outputs > 8,
        "only {outputs} Output frame(s) in 2 s of `yes`; this row asserted \
         nothing about frame size"
    );
    assert!(
        max > 1024,
        "the largest observed Output frame was {max} bytes, which is not a \
         PTY under load"
    );
    assert!(
        max < NEAR_CAP,
        "an Output frame reached {max} bytes, within reach of \
         MAX_FRAME_BYTES; the cap is supposed to be unreachable on this link"
    );

    send(&mut booted.stream, &DaemonFrame::Shutdown).await;

    // **Keep draining while it winds down.** A peer that stops reading a
    // socket it has just asked to close deadlocks the worker against its
    // own backpressure: the outbound queue fills, `link_out` parks on a
    // socket send buffer nobody is emptying, and the worker never reaches
    // its exit. That is a hang in the *test*, not a bug in the worker —
    // the daemon that will own this link drains it for the session's life
    // — and it is the exact shape this milestone's constraint 4 is about.
    // Measured while mutation-testing this row: at a larger read buffer
    // the undrained version wedged for the full 20 s and reported the
    // worker as "still running", which says nothing about frame sizes.
    let drained = tokio::time::timeout(DEADLINE, async {
        while frame::read_frame_body(&mut booted.stream).await.is_ok() {}
    })
    .await;
    assert!(
        drained.is_ok(),
        "the worker kept the link open for {DEADLINE:?} after Shutdown"
    );
    wait_exit(&mut booted.worker, DEADLINE).await;
}

/// What the child prints, and what must not come back inside a `Fault`.
const PTY_MARKER: &str = "PTY-OUTPUT-MARKER-Q4W";
/// A credential in a second `PtySpawnConfig`'s `env`.
///
/// This is the payload that is actually **in scope** at a reachable fault
/// site: the protocol-violation arm has the whole offending
/// [`DaemonFrame`] in hand, and a `{:?}` of it prints the config's `env`
/// verbatim. §9.2 records only `env_keys` for exactly this reason.
const CFG_SECRET: &str = "ghp_FAULTLEAKdeadbeef0123456789";
/// A recognisable payload inside a frame the worker cannot decode.
const BAD_FRAME_MARKER: &str = "UNDECODABLE-BODY-MARKER-Q4W";

/// A child that says `PTY_MARKER` and then stays up, so the worker's read
/// buffer is holding the marker at the moment the fault is raised.
fn talkative() -> PtySpawnConfig {
    PtySpawnConfig {
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            format!("printf '%s\\n' '{PTY_MARKER}'; sleep 60"),
        ],
        cwd: None,
        env: Vec::new(),
        cols: 80,
        rows: 24,
    }
}

/// Read frames until a `Fault` arrives, skipping the ordinary traffic a
/// dying session produces.
///
/// Bounded, with the elapsed arm failing: a worker that answered a
/// protocol violation by doing nothing at all would otherwise park this
/// loop rather than redden it.
async fn next_fault(stream: &mut UnixStream) -> String {
    tokio::time::timeout(DEADLINE, async {
        loop {
            match read_frame::<_, WorkerFrame>(stream).await {
                Ok(WorkerFrame::Fault { message }) => return message,
                // A retired child's last output and its `Exited` may
                // overtake nothing, but they may certainly arrive first.
                Ok(WorkerFrame::Output { .. } | WorkerFrame::Exited { .. }) => {}
                Ok(other) => panic!("unexpected frame while waiting for a Fault: {other:?}"),
                Err(e) => panic!("the link closed before any Fault arrived: {e}"),
            }
        }
    })
    .await
    .expect("a Fault arrived within the deadline")
}

/// Read output frames until `needle` has been seen, so the "does not
/// contain" assertions afterwards are separated from the degenerate case
/// of a session that emitted nothing.
async fn await_marker(stream: &mut UnixStream, needle: &str) {
    let mut seen = Vec::new();
    let found = tokio::time::timeout(DEADLINE, async {
        loop {
            match read_frame::<_, WorkerFrame>(stream).await {
                Ok(WorkerFrame::Output { bytes }) => {
                    seen.extend_from_slice(&bytes);
                    if String::from_utf8_lossy(&seen).contains(needle) {
                        return;
                    }
                }
                Ok(other) => panic!("unexpected frame before the child spoke: {other:?}"),
                Err(e) => panic!("the link closed before the child spoke: {e}"),
            }
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "the child never emitted {needle:?}, so every assertion that follows \
         would hold against a worker that had never seen the string at all. \
         Saw: {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// # The read-path fault arm is **unreachable in this tree**, measured
///
/// The mutation this row is written against —
/// `Fault { message: format!("read failed on {:?}", buf) }` in the PTY
/// read loop — cannot be reddened by any behaviour, because the loop's
/// `Err` arm cannot be reached. Two measurements, both taken while
/// writing this row rather than assumed:
///
/// * `portable-pty` 0.9.0 maps the master's `EIO` — the slave has closed,
///   i.e. the child is gone — onto `Ok(0)` so that `Read::read_to_end`
///   terminates gracefully (`unix.rs:94`). So a dead child produces EOF
///   and never an error.
/// * A `write(2)` on a master whose slave is closed **succeeds** on Linux
///   (probed: `pty.openpty()`, close the slave, `os.write` returns 5).
///   Only the read errors, and portable-pty has already swallowed that.
///   So the *writer* task's fault arm is unreachable for the same reason.
///
/// That is reported rather than worked around, and it changes what this
/// row can be. What it asserts instead is the same property at the two
/// fault sites an ordinary session **can** reach, and the second of them
/// has a genuine credential in scope — which makes it the arm that kills
/// a real mutation rather than the arm that names one:
///
/// | Arm | Fault site | Payload in scope | Mutation it kills |
/// |---|---|---|---|
/// | 1 | an undecodable `DaemonFrame` | the serde error | quoting the frame body into the message |
/// | 2 | a second `Spawn` after the handshake | the whole `DaemonFrame`, **including `cfg.env`** | `format!("{other:?} …")`, which prints every credential in the config |
///
/// Both arms also assert the PTY marker's absence, which is the property
/// the unreachable arm is about. No mutation can break that assertion
/// today; it is the guard that will be there when the arm becomes
/// reachable — a `SubprocessPty` on a platform whose pty reads report
/// errors, which is exactly what 0.0.11 adds.
#[tokio::test]
async fn a_fault_frame_carries_no_pty_bytes() {
    // --- Arm 1: a frame the worker cannot decode.
    let mut booted = boot(&talkative()).await;
    await_marker(&mut booted.stream, PTY_MARKER).await;

    // A well-formed CBOR map with a `type` this build does not know, and
    // a recognisable payload beside it. The *worker* direction is strict
    // by design (`frames.rs`'s asymmetry): the side that acts has no safe
    // answer to an instruction it cannot read, so this is a decode error
    // and not a skip.
    let body = frame::encode(&CborValue::Map(vec![
        (
            CborValue::Text("type".into()),
            CborValue::Text("Nonsense".into()),
        ),
        (
            CborValue::Text("payload".into()),
            CborValue::Text(BAD_FRAME_MARKER.into()),
        ),
    ]))
    .expect("a small map encodes");
    tokio::time::timeout(DEADLINE, booted.stream.write_all(&body))
        .await
        .expect("the write completed within the deadline")
        .expect("the write succeeded");

    let fault = next_fault(&mut booted.stream).await;
    // A message that said nothing would satisfy every "does not contain"
    // below, so what it must contain is asserted first.
    assert!(
        fault.contains("undecodable daemon frame"),
        "the Fault named no operation: {fault:?}"
    );
    assert!(
        !fault.contains(BAD_FRAME_MARKER),
        "the Fault message quotes the body it could not decode: {fault:?}"
    );
    assert!(
        !fault.contains(PTY_MARKER),
        "the Fault message carries the child's output: {fault:?}"
    );
    wait_exit(&mut booted.worker, DEADLINE).await;

    // --- Arm 2: a second `Spawn`, which puts a whole `PtySpawnConfig` —
    // `env` and all — in scope at the fault site. This is the arm with a
    // credential to leak, and therefore the arm a mutation can be
    // injected into.
    let mut booted = boot(&talkative()).await;
    await_marker(&mut booted.stream, PTY_MARKER).await;
    let mut second = talkative();
    second.env = vec![("API_KEY".to_string(), CFG_SECRET.to_string())];
    send(&mut booted.stream, &DaemonFrame::Spawn { cfg: second }).await;

    let fault = next_fault(&mut booted.stream).await;
    assert!(
        fault.contains("protocol violation") && fault.contains("Spawn"),
        "the Fault named neither the violation nor the frame: {fault:?}"
    );
    assert!(
        !fault.contains(CFG_SECRET),
        "the Fault message carries the offending config's environment — the \
         surface §9.2 records only `env_keys` for: {fault:?}"
    );
    assert!(
        !fault.contains("API_KEY"),
        "the Fault message carries the offending config's env *keys*: {fault:?}"
    );
    assert!(
        !fault.contains(PTY_MARKER),
        "the Fault message carries the child's output: {fault:?}"
    );

    // The worker retires the child and exits rather than carrying on
    // after a protocol violation, so a violated link leaves no process.
    wait_exit(&mut booted.worker, DEADLINE).await;
}
