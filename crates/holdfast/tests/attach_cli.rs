//! `holdfast attach` and `holdfast watch`, driven as **real processes on
//! a real PTY** (spec §6.1, §7.5, §11.2).
//!
//! Everything else in this milestone tests the daemon's side of the
//! attach protocol over `attach.sock`. This file tests the *client*: raw
//! mode and its restoration, the detach-key grammar, `SIGWINCH`, the
//! no-echo secret read, and the two refusals §7.5 makes the client's own
//! job. None of those are observable from a socket — they are properties
//! of a terminal — so the test gives the client a terminal and reads what
//! it draws.
//!
//! **The daemon here is in-process and the client is not.** A subprocess
//! daemon would need a session created over `holdfast mcp`, which is the
//! smoke script's job (Task 13) and buys nothing here; an in-process
//! `Daemon` lets a test choose the backend, queue exact bytes, and read
//! the PTY back. The binary under test is the real one, spawned with
//! `HOLDFAST_RUNTIME_DIR` pointed at this test's private directory.
#![cfg(unix)]

use holdfast_core::attach::{
    decode_client_frame, AttachMode, AttachRole, ClientDecode, ClientFrame, ServerFrame,
};
use holdfast_core::daemon::attach_server;
use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::server::{self, Daemon};
use holdfast_core::protocol::frame;
use holdfast_core::protocol::handshake::{PROTOCOL_MAJOR, PROTOCOL_MINOR};
use holdfast_core::pty::{InProcessPty, MockPty, PtyBackend, PtySpawnConfig};
use holdfast_core::session::{new_session_id, Session, SessionConfig};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The binary this test drives. Cargo sets it for a package that has a
/// `[[bin]]`, so there is no path guessing and no `target/debug`
/// hardcoded anywhere.
const BIN: &str = env!("CARGO_BIN_EXE_holdfast");

fn scratch_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    // Short, and under `/tmp`: `sockaddr_un.sun_path` cannot hold a path
    // under the workspace's `target/`.
    PathBuf::from(format!(
        "/tmp/holdfast-cli-{tag}-{}-{n}",
        std::process::id()
    ))
}

// --------------------------------------------------------- the daemon

/// A daemon serving both sockets inside this test's process.
struct TestDaemon {
    daemon: Arc<Daemon>,
    paths: RuntimePaths,
}

impl TestDaemon {
    async fn start(tag: &str) -> Self {
        let paths = RuntimePaths::with_dir(scratch_dir(tag));
        let (control, _c) = server::bind_control(&paths).expect("bind control.sock");
        let (attach, _a) = attach_server::bind_attach(&paths).expect("bind attach.sock");
        let daemon = Daemon::new(paths.clone());
        tokio::spawn(server::serve(Arc::clone(&daemon), control));
        tokio::spawn(attach_server::serve_attach(Arc::clone(&daemon), attach));
        tokio::task::yield_now().await;
        Self { daemon, paths }
    }

    fn session(&self, name: Option<&str>) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            name.map(String::from),
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(256 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        (s, pty)
    }

    /// A session on a **real** PTY running a real shell — the only way to
    /// observe `stty size` and a termios `ECHO` drop.
    fn real_session(&self, command: &str, args: &[&str]) -> Arc<Session> {
        let mut cfg = PtySpawnConfig::new(command);
        cfg.args = args.iter().map(|a| (*a).to_string()).collect();
        let pty = InProcessPty::spawn(&cfg).expect("spawn a real child");
        let s = Session::new(
            new_session_id(),
            None,
            command.into(),
            cfg.args.clone(),
            Arc::new(pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(256 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        s
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.daemon.shutdown();
        for _ in 0..20 {
            match std::fs::remove_dir_all(self.paths.dir()) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }
}

// ------------------------------------------------------- the terminal

/// A `holdfast` subcommand running on a PTY this test owns.
struct Term {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Term {
    fn spawn(dir: &std::path::Path, args: &[&str], cols: u16, rows: u16) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let mut cmd = CommandBuilder::new(BIN);
        for a in args {
            cmd.arg(a);
        }
        cmd.env("HOLDFAST_RUNTIME_DIR", dir);
        // A short, predictable environment: the client inherits nothing
        // that could put a pager or a locale in the way.
        cmd.env("TERM", "xterm-256color");
        let child = pair.slave.spawn_command(cmd).expect("spawn the client");
        // **The slave is dropped and the master is kept.** Holding the
        // slave open would keep the master readable forever after the
        // child exits, so `wait_for` could never distinguish "still
        // drawing" from "gone".
        drop(pair.slave);

        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    return;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let writer = pair.master.take_writer().expect("take writer");
        Self {
            master: pair.master,
            child,
            writer,
            seen,
        }
    }

    fn type_keys(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("write to the pty");
        self.writer.flush().expect("flush the pty");
    }

    fn snapshot(&self) -> Vec<u8> {
        self.seen.lock().unwrap().clone()
    }

    /// Everything drawn so far, once `needle` appears. Fails on a
    /// deadline rather than hanging: there is no `nextest.toml` in this
    /// repo, so a bare loop is a hung CI job and not a red row.
    fn wait_for(&self, needle: &[u8], secs: u64) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let seen = self.snapshot();
            if contains(&seen, needle) {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "{:?} never appeared within {secs}s. Seen so far:\n{}",
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&self.snapshot())
        );
    }

    fn wait_exit(&mut self, secs: u64) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.exit_code(),
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("try_wait: {e}"),
            }
        }
        let _ = self.child.kill();
        panic!(
            "the client never exited within {secs}s. Seen:\n{}",
            String::from_utf8_lossy(&self.snapshot())
        );
    }

    fn master_fd(&self) -> RawFd {
        self.master
            .as_raw_fd()
            .expect("a unix pty master has a file descriptor")
    }

    fn resize(&self, cols: u16, rows: u16) {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize the pty");
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The pty's line-discipline settings.
///
/// **Read from the *master* fd**, which on Linux answers with the same
/// `termios` the slave carries — there is one line discipline per pair.
/// That is what lets this read the settings while the client owns the
/// slave, and the `ECHO`-is-off assertion *during* the attach is what
/// proves this is really observing the client rather than a constant.
fn termios_of(fd: RawFd) -> libc::termios {
    // SAFETY: `tcgetattr` writes a `termios` through the pointer.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(fd, &mut t) },
        0,
        "tcgetattr on the pty master"
    );
    t
}

/// Every field of a `termios`, flattened so two can be compared. `libc`
/// derives no `PartialEq`, and comparing only `c_lflag` would miss a
/// client that restored the local flags and left `ISIG` or `OPOST` off.
///
/// Widened through `u64::from` rather than an `as` cast: `tcflag_t` is
/// `u32` on Linux and `u64` on macOS, and `as` would be a no-op cast on
/// one of them — which `-D warnings` rejects.
fn termios_fields(t: &libc::termios) -> (u64, u64, u64, u64, Vec<u8>) {
    (
        u64::from(t.c_iflag),
        u64::from(t.c_oflag),
        u64::from(t.c_cflag),
        u64::from(t.c_lflag),
        t.c_cc.to_vec(),
    )
}

fn echo_on(t: &libc::termios) -> bool {
    t.c_lflag & libc::ECHO != 0
}

fn icanon_on(t: &libc::termios) -> bool {
    t.c_lflag & libc::ICANON != 0
}

/// Wait until the client is really attached, by making the session draw
/// something and watching for it.
///
/// Every keystroke test needs this: writing into the master before the
/// client has finished its handshake sends the bytes into a process that
/// is not reading yet, and the row then fails for a reason that has
/// nothing to do with what it is testing.
///
/// **The marker is re-queued until it lands, and a single one would not
/// do.** §4.3's fan-out is a live broadcast with no replay — *"attach
/// clients that are only rendering live bytes do not attempt replay"* —
/// so a marker queued before the client subscribed is simply gone, and
/// the wait would then time out on a client that attached perfectly well.
fn wait_until_attached(term: &Term, pty: &Arc<MockPty>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        pty.queue_output(b"READY-MARKER\r\n");
        let stop = Instant::now() + Duration::from_millis(250);
        while Instant::now() < stop {
            if contains(&term.snapshot(), b"READY-MARKER") {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    panic!(
        "the client never attached. Seen:\n{}",
        String::from_utf8_lossy(&term.snapshot())
    );
}

/// `holdfast <args>` with no terminal at all, for the rows that assert on
/// an exit code and a diagnostic.
///
/// Every refusal below happens **before** raw mode is taken — the client
/// dials, handshakes, and only then touches the terminal — so these rows
/// need no pty, and not giving them one keeps stderr separate from
/// stdout, which a pty merges.
fn run_plain(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(BIN)
        .args(args)
        .env("HOLDFAST_RUNTIME_DIR", dir)
        .output()
        .expect("run the client")
}

// ------------------------------------------------------- stub daemons

/// A directory with an `attach.sock` this test serves itself.
///
/// Two of §7.5's client-side rules are about a daemon that is **wrong** —
/// one that refuses with a reason the client must reproduce, and one that
/// accepts an attach it should have refused. Neither is reachable from a
/// correct daemon, so the peer is hand-written.
struct StubDaemon {
    paths: RuntimePaths,
    /// Every client frame the stub received, in order.
    got: Arc<Mutex<Vec<ClientFrame>>>,
}

impl StubDaemon {
    /// Serve exactly one connection, replying with `reply` after the
    /// handshake and then keeping the socket open until `hold` elapses.
    async fn start(tag: &str, reply: Option<ServerFrame>, hold: Duration) -> Self {
        let paths = RuntimePaths::with_dir(scratch_dir(tag));
        paths.ensure_dir().expect("ensure the runtime dir");
        let listener =
            tokio::net::UnixListener::bind(paths.attach_sock()).expect("bind the stub socket");
        let got: Arc<Mutex<Vec<ClientFrame>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&got);
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            // The handshake, recorded.
            let Ok(body) = frame::read_frame_body(&mut stream).await else {
                return;
            };
            if let ClientDecode::Frame(f) = decode_client_frame(&body) {
                sink.lock().unwrap().push(f);
            }
            if let Some(reply) = reply {
                if frame::write_frame(&mut stream, &reply).await.is_err() {
                    return;
                }
            }
            // Keep reading, so anything the client sends *after* the
            // reply is recorded rather than lost to a closed socket —
            // "sends no further frames" is only assertable if a further
            // frame would have been seen.
            let until = tokio::time::Instant::now() + hold;
            loop {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    return;
                }
                match tokio::time::timeout(left, frame::read_frame_body(&mut stream)).await {
                    Ok(Ok(b)) => {
                        if let ClientDecode::Frame(f) = decode_client_frame(&b) {
                            sink.lock().unwrap().push(f);
                        }
                    }
                    Ok(Err(_)) => return,
                    Err(_) => return,
                }
            }
        });
        Self { paths, got }
    }

    fn frames(&self) -> Vec<ClientFrame> {
        self.got.lock().unwrap().clone()
    }
}

impl Drop for StubDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.paths.dir());
    }
}

// ------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_renders_session_output_on_the_local_terminal() {
    let d = TestDaemon::start("render").await;
    let (s, pty) = d.session(Some("rendersess"));

    let term = Term::spawn(d.paths.dir(), &["attach", &s.id], 80, 24);
    wait_until_attached(&term, &pty);

    pty.queue_output(b"ZZTOP\r\n");
    term.wait_for(b"ZZTOP", 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ctrl_b_then_d_detaches_and_leaves_the_session_running() {
    // §6.1: *"cleanly disconnects without killing the session."* Both
    // halves, because a client that killed the session on the way out
    // still exits 0.
    let d = TestDaemon::start("detach").await;
    let (_s, pty) = d.session(Some("keepalive"));

    let mut term = Term::spawn(d.paths.dir(), &["attach", "keepalive"], 80, 24);
    wait_until_attached(&term, &pty);

    term.type_keys(&[0x02, 0x64]);
    assert_eq!(term.wait_exit(10), 0, "the detach key must exit 0");

    let listed = run_plain(d.paths.dir(), &["list"]);
    let text = String::from_utf8_lossy(&listed.stdout).to_string();
    assert!(
        text.contains("keepalive"),
        "the session did not survive the detach:\n{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ctrl_b_then_any_other_key_is_forwarded_as_two_bytes() {
    // **The pairing.** Without it, "any `Ctrl-B` detaches" passes the row
    // above, and every `Ctrl-B` a user typed for `backward-char` would
    // vanish into the client.
    let d = TestDaemon::start("prefixpass").await;
    let (_s, pty) = d.session(Some("prefixsess"));

    let mut term = Term::spawn(d.paths.dir(), &["attach", "prefixsess"], 80, 24);
    wait_until_attached(&term, &pty);

    term.type_keys(&[0x02, b'x']);

    // Asserted on what reached the PTY, not on an echo: the mock does not
    // echo, and the point is that *both* bytes were forwarded, in order.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut written = Vec::new();
    while Instant::now() < deadline {
        written = pty.written();
        if contains(&written, &[0x02, b'x']) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        contains(&written, &[0x02, b'x']),
        "Ctrl-B followed by another key must forward both bytes, in order; \
         the pty saw {written:?}"
    );
    // And the client is still attached — it did not detach on the prefix.
    pty.queue_output(b"STILL-HERE\r\n");
    term.wait_for(b"STILL-HERE", 10);
    term.type_keys(&[0x02, 0x64]);
    assert_eq!(term.wait_exit(10), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_terminal_is_restored_after_detach() {
    // The single most common attach-client bug: a restore that is only on
    // the happy path, or not at all, leaves the user's shell mute.
    let d = TestDaemon::start("restore").await;
    let (_s, pty) = d.session(Some("restoresess"));

    let mut term = Term::spawn(d.paths.dir(), &["attach", "restoresess"], 80, 24);
    let fd = term.master_fd();
    let before = termios_of(fd);
    assert!(
        echo_on(&before) && icanon_on(&before),
        "fixture: cooked pty"
    );

    wait_until_attached(&term, &pty);

    // **During**, and this is what stops the row passing vacuously: if
    // `tcgetattr` on the master could not see the client's change, the
    // "after" comparison would hold no matter what the client did.
    let during = termios_of(fd);
    assert!(
        !echo_on(&during) && !icanon_on(&during),
        "the client never put the terminal into raw mode, so the restore \
         assertion below would pass against a client that does nothing"
    );

    term.type_keys(&[0x02, 0x64]);
    assert_eq!(term.wait_exit(10), 0);

    let after = termios_of(fd);
    assert!(
        echo_on(&after) && icanon_on(&after),
        "ECHO/ICANON were not restored: the user's shell is left mute"
    );
    assert_eq!(
        termios_fields(&before),
        termios_fields(&after),
        "the terminal was not restored byte for byte"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_terminal_is_restored_when_the_daemon_dies() {
    // The same guard on the *unhappy* path. A `Drop`-based restore covers
    // it; a restore written at the end of the happy path does not.
    //
    // The daemon is a stub that hangs up rather than a real one that is
    // signalled: from the client's side those are the same event — the
    // socket EOFs with no `Detached` before it — and the stub makes the
    // moment it happens the test's rather than a scheduler's.
    let stub = StubDaemon::start(
        "daemondies",
        Some(ServerFrame::Attached {
            session_id: "sess_stub01".into(),
            name: None,
            cols: 80,
            rows: 24,
            state: "Running".into(),
            exit_code: None,
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        }),
        Duration::from_millis(400),
    )
    .await;

    let mut term = Term::spawn(stub.paths.dir(), &["attach", "sess_stub01"], 80, 24);
    let fd = term.master_fd();
    let before = termios_of(fd);

    // Wait for raw mode to actually be in force before the socket goes,
    // or "restored" is indistinguishable from "never changed".
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && echo_on(&termios_of(fd)) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!echo_on(&termios_of(fd)), "the client never went raw");

    // The stub's `hold` elapses and it drops the connection.
    let code = term.wait_exit(10);
    assert_ne!(
        code, 0,
        "a daemon that vanished mid-attach is not a clean detach"
    );
    let after = termios_of(fd);
    assert!(echo_on(&after) && icanon_on(&after));
    assert_eq!(termios_fields(&before), termios_fields(&after));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_resize_reaches_the_child() {
    // **Unequal dimensions, deliberately.** A square terminal cannot tell
    // `Resize { cols, rows }` from `Resize { rows, cols }`, and the
    // transposition is the likelier bug of the two this row covers.
    let d = TestDaemon::start("resize").await;
    let s = d.real_session("bash", &["--norc", "--noprofile"]);

    let mut term = Term::spawn(d.paths.dir(), &["attach", &s.id], 80, 24);
    // The shell has to be up before the resize, or `stty` runs against
    // whatever geometry the spawn used.
    term.type_keys(b"echo SHELL-UP\n");
    term.wait_for(b"SHELL-UP", 15);

    term.resize(132, 43);
    term.type_keys(b"stty size\n");
    let seen = term.wait_for(b"43 132", 15);
    assert!(
        contains(&seen, b"43 132"),
        "the child never saw 43 rows by 132 columns"
    );

    term.type_keys(&[0x02, 0x64]);
    assert_eq!(term.wait_exit(10), 0);
    let _ = s.signal(holdfast_core::pty::Signal::Kill);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_does_not_redact() {
    // REQ-SEC-008's first half. `holdfast attach` is `role: interactive`
    // and a redacted password prompt would corrupt what the human types
    // back. Paired with `watch_redacts_by_default` — the two together are
    // the requirement.
    const GH_TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    let d = TestDaemon::start("raw").await;
    let (s, pty) = d.session(None);

    let term = Term::spawn(d.paths.dir(), &["attach", &s.id], 80, 24);
    wait_until_attached(&term, &pty);

    pty.queue_output(format!("token={GH_TOKEN}\r\n").as_bytes());
    let seen = term.wait_for(GH_TOKEN.as_bytes(), 10);
    assert!(
        !contains(&seen, b"[REDACTED:"),
        "an interactive attach must not redact"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_prompt_is_read_without_echo_and_never_rendered() {
    // §9.5. Three claims in one run, because each is satisfiable without
    // the others: the client *shows* the prompt, the typed bytes are
    // **not** echoed to the terminal, and the child **receives** them.
    // The child transforms what it read and prints the transform, so
    // "it arrived" is asserted on the child's own output — a client that
    // threw the value away satisfies both absence claims.
    //
    // `stty -echo` and not `read -s`: rev. 36's ICANON rung means a
    // fixture whose shell also clears ICANON does not classify as
    // `AwaitingSecret`. The fixture prints its prompt because the edge is
    // computed per read chunk.
    const PROBE: &str = "hunter2";
    let d = TestDaemon::start("secret").await;
    let s = d.real_session(
        "sh",
        &[
            "-c",
            "stty -echo; printf 'Password: '; read x; stty echo; \
             printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"",
        ],
    );

    let mut term = Term::spawn(d.paths.dir(), &["attach", &s.id], 80, 24);
    term.wait_for(b"Password: ", 15);

    term.type_keys(b"hunter2\r");
    let seen = term.wait_for(b"got=HUNTER2", 15);

    assert!(
        !contains(&seen, PROBE.as_bytes()),
        "the secret was echoed to the local terminal:\n{}",
        String::from_utf8_lossy(&seen)
    );
    let _ = s.signal(holdfast_core::pty::Signal::Kill);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_against_an_unknown_session_exits_with_the_reject_message() {
    let d = TestDaemon::start("nosuch").await;
    let out = run_plain(d.paths.dir(), &["attach", "no-such-session"]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(out.status.code(), Some(1), "stderr was:\n{err}");
    assert!(
        err.contains("session_not_found"),
        "a bare \"failed to attach\" tells an operator nothing:\n{err}"
    );
    // The pairing with the row below: this failure must not also print
    // the version tokens.
    assert!(!err.contains("protocol_too_old"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_reports_protocol_too_old_distinctly_from_session_not_found() {
    // REQ-D-004a's client-side arm, and §18.4b's named regression seen
    // from the client: *"a three-arm match with a catch-all compiles,
    // runs, and reports a stale client as some generic failure."*
    //
    // The daemon is hand-served, because a daemon one major ahead of this
    // client cannot be built from these constants.
    // Built the way the daemon builds it, one major ahead, on one
    // unbroken line: a `\`-continuation here would be the same expression
    // as the thing under test.
    let sentence = format!(
        "protocol_too_old — daemon speaks attach protocol {}.x; upgrade the client, or stop the daemon.",
        PROTOCOL_MAJOR + 1
    );
    let stub = StubDaemon::start(
        "tooold",
        Some(ServerFrame::AttachReject {
            reason: "protocol_too_old".into(),
            message: sentence.clone(),
        }),
        Duration::from_secs(2),
    )
    .await;

    let out = run_plain(stub.paths.dir(), &["attach", "whatever"]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(out.status.code(), Some(1), "stderr was:\n{err}");
    assert!(
        err.contains(&sentence),
        "the whole §7.5 sentence must reach the operator, not a summary of it:\n{err}"
    );
    assert!(
        !err.contains("session_not_found"),
        "a stale client must not be reported as a missing session:\n{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_refuses_a_daemon_that_leniently_accepted_it() {
    // REQ-D-004a's third case, and the only reason `Attached` carries
    // `protocol_major` at all: an older daemon that never heard of the
    // symmetry rule can accept a client it cannot understand, and the
    // client is the peer that can still tell.
    let stub = StubDaemon::start(
        "lenient",
        Some(ServerFrame::Attached {
            session_id: "sess_stub01".into(),
            name: None,
            cols: 80,
            rows: 24,
            state: "Running".into(),
            exit_code: None,
            protocol_major: PROTOCOL_MAJOR + 1,
            protocol_minor: 0,
        }),
        Duration::from_secs(2),
    )
    .await;

    let out = run_plain(stub.paths.dir(), &["attach", "sess_stub01"]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_ne!(out.status.code(), Some(0), "stderr was:\n{err}");
    assert!(
        err.contains("protocol"),
        "the client must say why it refused:\n{err}"
    );
    // §7.5: *"there is no wire token for that refusal"* — the peer that
    // would have sent one is the peer that failed to check. A message
    // carrying one would invite an operator to grep the wrong catalogue.
    for token in [
        "session_not_found",
        "protocol_too_new",
        "protocol_too_old",
        "limit_reached",
    ] {
        assert!(
            !err.contains(token),
            "the refusal quoted the wire token {token}:\n{err}"
        );
    }
    // And it sent **nothing** after the handshake — not even `Detach`.
    let sent = stub.frames();
    assert_eq!(
        sent.len(),
        1,
        "the client kept talking to a daemon it had refused: {sent:?}"
    );
    assert!(matches!(sent[0], ClientFrame::Attach { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_attach_handshake_carries_every_non_optional_field() {
    // §7.5 spells out that its own example is elided. An abbreviated
    // handshake is a client that cannot attach at all — and the four
    // fields below are exactly the ones a reader is most likely to think
    // are optional, because the spec's example omits them.
    let stub = StubDaemon::start("fullhs", None, Duration::from_millis(300)).await;
    let _ = run_plain(stub.paths.dir(), &["attach", "sess_x"]);

    let sent = stub.frames();
    assert_eq!(sent.len(), 1, "{sent:?}");
    match &sent[0] {
        ClientFrame::Attach {
            session,
            mode,
            role,
            client_kind,
            client_version,
            protocol_major,
            protocol_minor,
        } => {
            assert_eq!(session, "sess_x");
            // REQ-SEC-008's first half, on the wire: `holdfast attach` is
            // read-write **and** interactive. The pairing is the point —
            // the two fields are orthogonal (§7.5), and `holdfast watch`
            // sends the other one.
            assert_eq!(*mode, AttachMode::ReadWrite);
            assert_eq!(*role, AttachRole::Interactive);
            assert_eq!(
                *client_kind,
                holdfast_core::protocol::handshake::ClientKind::Cli
            );
            assert!(!client_version.is_empty());
            assert_eq!(*protocol_major, PROTOCOL_MAJOR);
            assert_eq!(*protocol_minor, PROTOCOL_MINOR);
        }
        other => panic!("the first frame must be Attach, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn holdfast_version_prints_the_protocol_the_sockets_speak() {
    // REQ-D-004a's version-aliasing clause, asserted where no unit test
    // can reach it: the **printed string** against the **wire**. An
    // assertion inside `attach::handshake` would compare each constant
    // with itself.
    let d = TestDaemon::start("version").await;
    let (s, _pty) = d.session(None);

    let printed = run_plain(d.paths.dir(), &["version"]);
    let line = String::from_utf8_lossy(&printed.stdout).to_string();
    // `holdfast X.Y.Z (build B) protocol M.N` — the `(build …)` field is
    // between the version and the protocol, so the parser must tolerate
    // it rather than take a fixed word index.
    let tail = line
        .split("protocol ")
        .nth(1)
        .unwrap_or_else(|| panic!("no `protocol X.Y` in {line:?}"))
        .trim();
    let (major, minor) = tail
        .split_once('.')
        .unwrap_or_else(|| panic!("malformed protocol field {tail:?}"));

    // The wire's answer, from a live daemon.
    let mut c = tokio::net::UnixStream::connect(d.paths.attach_sock())
        .await
        .expect("connect attach.sock");
    frame::write_frame(
        &mut c,
        &ClientFrame::Attach {
            session: s.id.clone(),
            mode: AttachMode::ReadOnly,
            role: AttachRole::Observer,
            client_kind: holdfast_core::protocol::handshake::ClientKind::Cli,
            client_version: "test".into(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        },
    )
    .await
    .expect("write the handshake");
    let body = tokio::time::timeout(Duration::from_secs(5), frame::read_frame_body(&mut c))
        .await
        .expect("no frame within 5s")
        .expect("a frame body");
    let ServerFrame::Attached {
        protocol_major,
        protocol_minor,
        ..
    } = holdfast_core::attach::decode_server_frame(&body).expect("decode")
    else {
        panic!("expected Attached");
    };

    assert_eq!(
        (
            major.parse::<u32>().expect("major"),
            minor.parse::<u32>().expect("minor")
        ),
        (protocol_major, protocol_minor),
        "`holdfast version` prints a protocol the sockets do not speak"
    );
}
