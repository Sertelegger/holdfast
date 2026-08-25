//! `request_secret_input` end to end: the tool on one side, a real
//! `attach.sock` client on the other (§5.2, §9.5, REQ-SEC-010a).
//!
//! **Why the negative assertions here are not vacuous, and how to keep
//! them that way.** §9.2 names the trap by hand: *"the secret is absent
//! from the log"* passes trivially against an implementation that never
//! produced a secret at all. Every absence assertion in this file is
//! therefore paired with two controls, and a change that drops either
//! has silently deleted the assertion it sits beside:
//!
//! 1. **Positive control — the value arrived.** The child reads it and
//!    prints a *transform* of it, so arrival is asserted on the child's
//!    own output rather than on our having sent something.
//! 2. **Leak-detector control — the harness would have caught a leak.**
//!    The same byte string, sent to the same session as an ordinary
//!    `Input` frame, **must** show up in the ring buffer. If that ever
//!    passes by absence, every assertion beside it means nothing.
//!
//! The fixture is `sh -c 'stty -echo; …'` everywhere, and never
//! `read -s`: rev. 36's classification has an **ICANON** rung, so a shell
//! that clears ICANON as well does not classify as `AwaitingSecret` at
//! all — and `sh` is `dash` on most CI images, where `read -s` does not
//! exist and neither fails loudly nor disables echo. The fixture also
//! **prints its prompt**, because the `AwaitingSecret` edge is computed
//! per read chunk: a child that drops `ECHO` and writes nothing raises no
//! request until its next byte of output.
//!
//! # The seven surfaces 0.0.7 added or inherited
//!
//! Every one of these is a place the value could reach and must not
//! (REQ-SEC-004). The right-hand column is the row that asserts absence
//! **over the whole surface** — not field by field, because a field-by-field
//! check covers only the fields whoever wrote it thought of, which is how
//! a secret once shipped in `prompt.last_line` while four other fields of
//! the same response were being asserted redacted.
//!
//! | # | Surface | Asserted by |
//! |---|---|---|
//! | 1 | the `request_secret_input` **MCP response** (`secret_provided` and `secret_cancelled`) | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`], [`the_response_carries_a_length_and_not_a_value`] |
//! | 2 | the `secret_input_request` and `secret_input_resolved` audit lines | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] |
//! | 3 | the `binding_resolved` and `binding_approval` audit lines | `binding_approval` here; `binding_resolved` in `secret::binding::tests::a_keychain_resolved_secret_reaches_none_of_them_either`, because a `binding_resolved` line needs a provider that answers and this target cannot reach one |
//! | 4 | the `BindingApprovalRequired` broadcast frame | **Not here.** `secret::binding::tests::a_keychain_resolved_secret_reaches_none_of_them_either` and `…::the_approval_surface_carries_no_reference_and_no_value`, both of which sweep every frame their client saw |
//! | 5 | the §9.5 buffer notice | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] phase A, which writes one and then sweeps the buffer it landed in |
//! | 6 | `daemon.log`, including any provider-failure context | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] captures fd 2 across both its phases, from before the first call to after the last assertion that could leak; the **provider-failure** half is `secret::provider::tests::a_failing_providers_stderr_and_reference_reach_no_log` |
//! | 7 | the ring buffer, a second attached client's `Output` stream, and any other `read_output` response — unchanged from 0.0.6 | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] |
//!
//! **Two of the seven are swept somewhere other than this file — the
//! keychain half of surface 3, and the whole of surface 4 — and each is
//! elsewhere for its own reason. Stated precisely, because a coverage
//! table that overstates is worse than one that omits: this task is an
//! argument that the absence set is complete, and the argument is only
//! as good as the table.**
//!
//! * **Surface 3's keychain half is forced out.** A `binding_resolved`
//!   line is written only when a provider *answers*, the only provider a
//!   test may run is a script the test itself wrote (REQ-TST-007 / Global
//!   Constraint 12), and the type that runs one — `ScriptProvider` — is
//!   `#[cfg(test)]`, which an integration target cannot see. Every row
//!   that resolves a real value therefore lives in `secret::binding`'s
//!   own test module. Writing a `binding_resolved`-shaped absence here
//!   would assert about a line this target cannot cause to exist, which
//!   is the vacuity this whole file is organised against.
//! * **Surface 4 is not swept here at all**, and
//!   [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] does
//!   not sweep it despite driving the frame:
//!   [`next_binding_approval`] destructures the three fields the row
//!   asserts on and **discards the frame**, and [`stream_until`]
//!   accumulates only `Output`, so the later stream sweeps do not reach
//!   it either. A sweep here would also be the vacuous kind — on the tool
//!   path the approval is raised **before** anything has resolved, so at
//!   that moment no value exists to be absent from it. The rows that
//!   sweep it do so over *every* frame their client saw, on **both sides**
//!   of the decision, which is the shape that is not vacuous.
//!
//! # §11's secret scenarios, mapped
//!
//! The scenarios are §11.2's and §11.4's, read at rev. 49, plus one row
//! from **§11.3** — the Windows-runner assertion, which the brief
//! requires named here and which belongs to no other subsection. Each
//! cell cites a section and not a line number: §11 is a bulleted list
//! whose lines move whenever anything above them is edited, and a line
//! number in a test file is a citation that goes stale without anything
//! going red.
//!
//! A scenario this milestone does **not** implement names the milestone
//! that owns it, so a mechanical sweep finds a row rather than a gap.
//!
//! | §11 scenario | Implemented by |
//! |---|---|
//! | §11.2 `wait_for_pattern("Enter password")` then `request_secret_input` end to end, typed bytes in no response or log | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] |
//! | §11.2 `mode` and `role` are independent (REQ-SEC-008a) | **0.0.6's**, in `tests/attach_protocol.rs`: `the_role_is_read_from_the_frame_not_inferred_from_the_mode`, `the_same_bytes_reach_an_interactive_client_raw_and_an_observer_redacted`, `both_attach_audit_rows_carry_the_role` |
//! | §11.2 Secret-request adoption (REQ-SEC-010a) | [`a_tool_call_adopts_an_echo_raised_request`], [`an_adopted_request_keeps_the_prompt_it_was_raised_with`], [`a_second_caller_collides_and_the_first_still_completes`] |
//! | §11.2 Audit-log redaction of a secret-shaped command line | **0.0.3's**, `session_start`'s own redaction |
//! | §11.2 `request_secret_input` via CLI attach, **echo-off** child | [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`] |
//! | §11.2 `request_secret_input` via CLI attach, **echo-on** child (documented caveat) | [`the_documented_echo_on_leak_is_asserted_not_assumed`] |
//! | §11.2 `request_secret_input` via **web UI** | **0.0.10** — there is no bridge, no WebSocket and no masked input field yet |
//! | §11.2 no-client-attached path: notice written, client attaches mid-window, request completes | [`the_notice_appears_in_the_buffer_when_nobody_is_attached`], [`a_client_attaching_mid_window_can_still_answer`] |
//! | §11.2 `prompt_text` redaction and the length cap | [`a_secret_shaped_prompt_text_is_redacted_in_the_audit_log`], [`the_512_cap_is_bytes_not_characters`] |
//! | §11.2 `append_newline` semantics, all four cases | `attach::secret::tests::the_trailing_newline_is_normalised_exactly_once`, and [`the_cap_is_measured_before_normalisation`] for the boundary |
//! | §11.2 Session-recording round trip, and REQ-AF-003 | **0.0.9** — there is no recorder. 0.0.6 named the assertion; this milestone strengthens the property it rests on (the `Serialize`/`Clone` compile guard) and does not discharge it |
//! | §11.2 Notification payload hygiene | **0.0.9** — §5.8.3's sinks do not exist |
//! | §11.2 Binding approval flow (approve, deny, expire, ReadOnly rejection) | [`approve_binding_from_a_readonly_client_is_rejected`] here; approve/deny/expire in `secret::binding`'s test module, where a provider can run. The `GET /api/binding-approvals` half is **0.0.10's** |
//! | §11.4 Concurrent secret requests | [`a_second_caller_collides_and_the_first_still_completes`] |
//! | §11.4 Adoption is not `concurrent_request_pending` | [`a_tool_call_adopts_an_echo_raised_request`], in this same file, as §11.4 requires |
//! | §11.4 The agent cannot aim a secret (adversarial) | [`a_wrong_request_id_writes_nothing_and_the_right_one_still_works`] here; `secret::binding::tests::no_agent_argument_reaches_a_provider_lookup` for the binding half |
//! | §11.4 Web secret endpoint `request_id` binding (`409 conflict`) | **0.0.10** — `SecretSlots::matches_outstanding` is exported for it to call; the HTTP rendering is not written |
//! | §11.3 Windows `not_supported_on_platform` on a **Windows runner** | **0.0.11** — [`an_unsupported_platform_returns_before_allocating_anything`] asserts the same code path on Unix through a forced capability, which is the Unix half and not the runner assertion |

use holdfast_core::attach::frames::{
    decode_server_frame, ApprovalDecision, ClientFrame, ServerFrame,
};
use holdfast_core::attach::{AttachMode, AttachRole};
use holdfast_core::clock::Clock;
use holdfast_core::config::{Config, DaemonConfig, SecretBinding, SecurityConfig};
use holdfast_core::daemon::attach_server;
use holdfast_core::daemon::paths::RuntimePaths;
use holdfast_core::daemon::server::{self, Daemon};
use holdfast_core::mcp::tools::{ReadOutputArgs, RequestSecretInputArgs, SendInputArgs};
use holdfast_core::platform::Capabilities;
use holdfast_core::protocol::frame;
use holdfast_core::protocol::handshake::{ClientKind, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use holdfast_core::pty::{InProcessPty, MockPty, PtyBackend, PtySpawnConfig, Signal};
use holdfast_core::secret::{
    command_line, keychain_step_runs, resolve, select, ArgvProvider, ProviderError, SecretProvider,
};
use holdfast_core::session::{new_session_id, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;

/// A value that matches **no** built-in redaction rule, so an absence
/// assertion over it cannot pass because a redactor got there first.
const PROBE: &str = "hunter2";

/// The one echo-off fixture, spelled the same way in every row. It
/// prints a prompt (so the edge fires), reads with echo off, and prints
/// a *transform* of what it read (so arrival is assertable without the
/// value ever being printed).
const ECHO_OFF_FIXTURE: &str = "stty -echo; printf 'Password: '; read x; stty echo; \
     printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"";

/// A child that drops `ECHO`, prints its prompt — and then restores echo
/// **without ever reading**. `user_cancelled`'s only producer (Q6): §7.5's
/// client-frame catalogue carries no cancellation frame, so the echo-off
/// condition clearing is the only signal there is.
///
/// The trailing `printf` is load-bearing, for the same reason
/// `ECHO_OFF_FIXTURE` prints its prompt: the classification is computed
/// per read chunk, so a child that restores echo and then writes nothing
/// leaves the session sitting in `AwaitingSecret` until its next byte of
/// output. The `sleep 3` is a margin over the plan's `1`, which is not
/// enough time for a test to attach, observe the raise, place a call and
/// see its waiter register before the window it is measuring has closed.
const ABANDONED_READ_FIXTURE: &str =
    "stty -echo; printf 'Password: '; sleep 3; stty echo; printf 'gave-up\\n'; sleep 30";

/// The **transform**, on its own, so the echo-on fixtures below can be
/// pinned to [`ECHO_OFF_FIXTURE`] rather than re-typed beside it.
///
/// Global Constraint 14 governs the echo-**off** spelling and says nothing
/// about an echo-on one; §11.2 asks for a *"`read line; echo $line`
/// style"* child and fixes no text. So the echo-on fixtures are derived
/// from the echo-off one by substitution, and
/// [`the_echo_on_fixtures_are_the_echo_off_one_with_the_stty_calls_removed`]
/// asserts the derivation actually removed something — a `replace` that
/// silently matched nothing would leave an echo-**off** child standing in
/// for the documented caveat, and the caveat row would then assert the
/// opposite of what it claims.
const TRANSFORM: &str = "printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"";

/// §11.2's documented-caveat child: the same read, the same transform, and
/// **no `stty`** — so the line discipline echoes what is written to it.
fn echo_on_fixture() -> String {
    let out = ECHO_OFF_FIXTURE
        .replace("stty -echo; ", "")
        .replace("stty echo; ", "");
    assert!(
        !out.contains("stty") && out.contains(TRANSFORM),
        "the echo-on derivation missed: {out}"
    );
    out
}

/// The same child, in a loop, for the one row that has to send the same
/// bytes to **one** session three different ways.
///
/// No prompt and no `stty`: the leak detector's third path raises its
/// request from the *tool call*, not from an echo drop, so nothing here
/// needs to reach `AwaitingSecret`. `while read x` and not `while :`,
/// because a loop that ignores EOF spins on a closed master.
fn echo_on_loop_fixture() -> String {
    assert!(
        ECHO_OFF_FIXTURE.contains(TRANSFORM),
        "the transform is no longer shared with the echo-off fixture"
    );
    format!("while read x; do {TRANSFORM}; done")
}

struct TestDaemon {
    daemon: Arc<Daemon>,
    paths: RuntimePaths,
}

impl TestDaemon {
    async fn start(tag: &str) -> Self {
        Self::start_with(tag, Clock::system()).await
    }

    async fn start_with(tag: &str, clock: Clock) -> Self {
        Self::spawn(tag, |paths| Daemon::with_clock(paths, clock)).await
    }

    /// A daemon carrying an operator's `[security]` — the rows below that
    /// are about §9.6's bindings need one, and every other row here wants
    /// the stock config with no bindings at all.
    async fn start_with_config(tag: &str, config: Config) -> Self {
        Self::spawn(tag, |paths| {
            Daemon::with_config_and_clock(paths, config, Clock::system())
        })
        .await
    }

    /// A daemon whose server reports the capabilities it is given rather
    /// than the ones it was compiled for (§3.6).
    ///
    /// **A daemon and not a bare `HoldfastServer::with_capabilities`**:
    /// the negative half of the platform assertion needs a real attached
    /// client, which needs a socket, which needs a daemon — and a bare
    /// server built with `None` for its audit path carries a **disabled**
    /// log, against which "no `secret_input_request` line" is true of
    /// every implementation there could be.
    async fn start_unsupported(tag: &str) -> Self {
        Self::spawn(tag, |paths| {
            Daemon::with_capabilities(
                paths,
                Capabilities {
                    out_of_band_secret_input: false,
                },
            )
        })
        .await
    }

    async fn spawn(tag: &str, make: impl FnOnce(RuntimePaths) -> Arc<Daemon>) -> Self {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let paths = RuntimePaths::with_dir(PathBuf::from(format!(
            "/tmp/holdfast-secrets-{tag}-{}",
            &unique[..8]
        )));
        let (control, _c) = server::bind_control(&paths).expect("bind control.sock");
        let (attach, _a) = attach_server::bind_attach(&paths).expect("bind attach.sock");
        let daemon = make(paths.clone());
        tokio::spawn(server::serve(Arc::clone(&daemon), control));
        tokio::spawn(attach_server::serve_attach(Arc::clone(&daemon), attach));
        for _ in 0..200 {
            if UnixStream::connect(paths.attach_sock()).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::task::yield_now().await;
        Self { daemon, paths }
    }

    /// A session on a real PTY. Every row here needs one: echo comes from
    /// the tty and not from us, and `AwaitingSecret` is a termios fact.
    fn shell_running(&self, script: &str) -> Arc<Session> {
        let mut cfg = PtySpawnConfig::new("sh");
        cfg.args = vec!["-c".to_string(), script.to_string()];
        let pty = InProcessPty::spawn(&cfg).expect("spawn a real shell");
        let s = Session::new(
            new_session_id(),
            None,
            "sh".into(),
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

    /// A session on a backend that produces **no output at all** unless a
    /// test queues some — for the one row whose subject is
    /// `last_activity_ms`, which the reader thread also stamps.
    fn quiet_session(&self) -> Arc<Session> {
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::new(MockPty::new()) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(64 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        s
    }

    /// [`quiet_session`](Self::quiet_session), plus a handle on the mock
    /// itself — for the one row whose subject is *when* the writer thread
    /// is inside `write`, which needs `MockPty::on_write`.
    fn mock_session(&self) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(64 * 1024),
        );
        self.daemon
            .server
            .registry
            .insert(Arc::clone(&s))
            .expect("register");
        (s, pty)
    }

    async fn dial(&self) -> UnixStream {
        UnixStream::connect(self.paths.attach_sock())
            .await
            .expect("connect attach.sock")
    }

    /// Call the tool, exactly as the daemon would.
    async fn call(&self, args: RequestSecretInputArgs) -> CallToolResult {
        self.daemon
            .server
            .request_secret_input(Parameters(args))
            .await
            .expect("request_secret_input")
    }

    /// `read_output`, the surface the agent actually reads a session
    /// through, from an explicit cursor.
    ///
    /// **The cursor is a parameter and not a hardcoded `0`, and that is a
    /// mutation result rather than a preference.** With `0` the response
    /// is the whole buffer, so a leak-detector path asserting *"these
    /// bytes reach a `read_output` response"* is satisfied by bytes an
    /// **earlier** path put there. Measured during Task 13's mutation
    /// ladder: with `send_input` injected to drop its payload entirely,
    /// the detector's second path stayed green.
    async fn read_output_since(&self, session: &str, since_cursor: u64) -> Value {
        body(
            &self
                .daemon
                .server
                .read_output(Parameters(ReadOutputArgs {
                    session: session.to_string(),
                    since_cursor: Some(since_cursor),
                    ..Default::default()
                }))
                .await
                .expect("read_output"),
        )
    }

    /// The whole buffer — for the rows that **sweep** a response rather
    /// than assert something arrived in it.
    async fn read_output(&self, session: &str) -> Value {
        self.read_output_since(session, 0).await
    }

    /// `send_input` — §16.4 step 4's parenthetical, the write a
    /// well-behaved agent does **not** make during `AwaitingSecret`
    /// (REQ-SEC-011). The leak detector makes it on purpose.
    async fn send_input(&self, session: &str, data: &str) -> Value {
        body(
            &self
                .daemon
                .server
                .send_input(Parameters(SendInputArgs {
                    session: session.to_string(),
                    data: data.to_string(),
                    ..Default::default()
                }))
                .await
                .expect("send_input"),
        )
    }

    /// The same call, for the rows whose subject is the **refusal**.
    ///
    /// Every bound on the arguments is a protocol error and not a status
    /// (§5.1): an input-schema violation is `invalid_params`, the shape
    /// `read_output`'s cursor rule already uses. `secret_cancelled`
    /// describes a request that was raised and did not complete, which
    /// none of these is.
    async fn try_call(&self, args: RequestSecretInputArgs) -> Result<CallToolResult, String> {
        self.daemon
            .server
            .request_secret_input(Parameters(args))
            .await
            .map_err(|e| format!("{e:?}"))
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

fn attach_frame(session: &str, mode: AttachMode) -> ClientFrame {
    ClientFrame::Attach {
        session: session.to_string(),
        mode,
        role: AttachRole::Interactive,
        client_kind: ClientKind::Cli,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
    }
}

async fn send(s: &mut UnixStream, f: &ClientFrame) {
    frame::write_frame(s, f).await.expect("write client frame");
}

/// One server frame, or a failed test — **never a hang.** The workspace
/// has no `nextest.toml`, so a bare `await` on a daemon that stopped
/// answering is a hung CI job rather than a red row.
async fn recv(s: &mut UnixStream) -> ServerFrame {
    let body = tokio::time::timeout(Duration::from_secs(10), frame::read_frame_body(s))
        .await
        .expect("no frame arrived within 10s")
        .expect("a frame body");
    decode_server_frame(&body).expect("a decodable server frame")
}

async fn attach_ok(d: &TestDaemon, session: &str, mode: AttachMode) -> UnixStream {
    let mut c = d.dial().await;
    send(&mut c, &attach_frame(session, mode)).await;
    match recv(&mut c).await {
        ServerFrame::Attached { .. } => c,
        other => panic!("expected Attached, got {other:?}"),
    }
}

/// The next `AwaitingSecret`, skipping the child's output.
async fn next_awaiting_secret(c: &mut UnixStream, secs: u64) -> (String, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match recv(c).await {
            ServerFrame::AwaitingSecret {
                request_id,
                prompt_text,
            } => return (request_id, prompt_text),
            ServerFrame::Output { .. } | ServerFrame::Resize { .. } => {}
            other => panic!("expected AwaitingSecret, got {other:?}"),
        }
    }
    panic!("no AwaitingSecret arrived");
}

/// The next `SecretRequestClosed`, skipping the child's output.
async fn next_secret_closed(c: &mut UnixStream, secs: u64) -> (String, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match recv(c).await {
            ServerFrame::SecretRequestClosed {
                request_id,
                outcome,
            } => return (request_id, outcome),
            ServerFrame::Output { .. }
            | ServerFrame::Resize { .. }
            | ServerFrame::AwaitingSecret { .. } => {}
            other => panic!("expected SecretRequestClosed, got {other:?}"),
        }
    }
    panic!("no SecretRequestClosed arrived");
}

/// Accumulate `Output` until `needle` shows up, returning **everything**
/// seen — the negative half of every assertion here needs the whole
/// stream, not the last frame.
async fn stream_until(c: &mut UnixStream, needle: &[u8], secs: u64) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut acc: Vec<u8> = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let body = match tokio::time::timeout(
            deadline - tokio::time::Instant::now(),
            frame::read_frame_body(&mut *c),
        )
        .await
        {
            Ok(Ok(b)) => b,
            _ => break,
        };
        match decode_server_frame(&body).expect("a decodable server frame") {
            ServerFrame::Output { bytes, .. } => acc.extend_from_slice(&bytes),
            ServerFrame::AwaitingSecret { .. } | ServerFrame::SecretRequestClosed { .. } => {}
            // **The child is gone, so no more `Output` is coming — return
            // what arrived and let the caller's own assertion say what is
            // missing.** Frames are ordered, so a needle the child really
            // printed has already been accumulated by the time this
            // arrives; reaching here means the needle was never produced.
            // Panicking instead reported "the helper saw an unexpected
            // frame" for what, at every *presence*-asserting call site, is
            // a failure of the row's own subject — measured during Task
            // 13's mutation ladder on every injection that stopped the
            // value reaching the child.
            //
            // **It is a weakening at one call site and only one**, and it
            // is named rather than glossed:
            // `an_oversize_submission_is_rejected_without_reaching_the_child`
            // is this helper's single absence-only caller, and there an
            // early `SessionExited` turns what used to be a loud panic
            // into a silent pass. Nothing regresses today — that child
            // sits blocked at `read x` for the whole 2 s window and the
            // row's `secret_cancelled` / `too_large` assertions run before
            // this helper is called at all — but a future absence-only
            // caller over a child that *can* exit needs its own liveness
            // assertion rather than this helper's panic.
            ServerFrame::SessionExited { .. } => break,
            other => panic!("expected Output, got {other:?}"),
        }
        if acc.windows(needle.len()).any(|w| w == needle) {
            return acc;
        }
    }
    acc
}

/// Block until the tool call has really registered its waiter.
///
/// **Read-only, deliberately.** Polling with `raise_or_adopt` would
/// *adopt* — the poller becomes the waiter, the call it was waiting for
/// collides, and the test measures something it created. That is what
/// `has_waiter` exists for.
async fn await_waiter(d: &TestDaemon, session_id: &str, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !d
        .daemon
        .server
        .attach_hub()
        .secrets()
        .has_waiter(session_id)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} never registered a waiter"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Run the tool call on its own task, so the test can go on to answer it.
///
/// Every row that both calls the tool and drives a client needs this: the
/// call blocks until the request resolves, and the thing that resolves it
/// is the test.
fn spawn_call(
    d: &TestDaemon,
    args: RequestSecretInputArgs,
) -> tokio::task::JoinHandle<CallToolResult> {
    let server = d.daemon.server.clone();
    tokio::spawn(async move {
        server
            .request_secret_input(Parameters(args))
            .await
            .expect("request_secret_input")
    })
}

/// Join a spawned call **with a ceiling**, so a deadline that never fires
/// is a red row rather than a hung job.
///
/// The ceiling is deliberately far above every `timeout_secs` these rows
/// pass and far below the 120 s default: a call that ignored its argument
/// and took the default would hit this and fail, which is the whole point
/// of the rows that measure elapsed time.
async fn joined(call: tokio::task::JoinHandle<CallToolResult>, what: &str) -> Value {
    let r = tokio::time::timeout(Duration::from_secs(25), call)
        .await
        .unwrap_or_else(|_| panic!("{what} never returned; its deadline did not fire"))
        .expect("the call");
    body(&r)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn body(r: &CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// The **whole** tool result, serialised — `content[0]`'s text mirror
/// included, not just `structuredContent`.
///
/// A sweep over `structuredContent` alone covers the half of the response
/// somebody remembered to look at. Both halves cross the MCP wire, and the
/// mirror is generated from the envelope rather than written by hand,
/// which is exactly the sort of derived surface a new field arrives on
/// without anybody deciding it should.
fn whole_result(r: &CallToolResult) -> String {
    serde_json::to_string(r).expect("a tool result serialises")
}

/// fd 2, into a file, from [`start`](Self::start) to
/// [`finish`](Self::finish) — the only way to reach `daemon.log`'s content
/// from an integration target.
///
/// **It does not cover a row's whole runtime**, and the caller decides
/// what it does cover: the seven-surface row starts it after its daemon
/// and its session are already up, because nothing before that point can
/// hold a value that does not exist yet.
///
/// `diag::emit` writes through `std::io::stderr()` deliberately, to bypass
/// libtest's capture, and the shipped daemon's `daemon.log` **is** its fd
/// 2. So the surface is reachable here only by redirecting the descriptor.
///
/// **This is the one row in this target that does it, and a second one
/// cannot simply be added beside it.** The redirect is process-wide while
/// it is up, and libtest runs this file's rows on threads of one process:
/// two overlapping captures would each restore the other's saved
/// descriptor. `secret::provider`'s `with_captured_stderr` carries the
/// same warning for the library target, which is a different process.
/// Whoever needs a second one moves both to the subprocess idiom
/// `diag.rs` already uses.
///
/// The restore is a `Drop` and not a statement after the call, so a row
/// that panics does not leave every other row's stderr pointing at a file
/// that is about to be deleted.
struct StderrCapture {
    path: PathBuf,
    saved: std::os::raw::c_int,
    file: Option<std::fs::File>,
}

impl StderrCapture {
    fn start(paths: &RuntimePaths, tag: &str) -> Self {
        use std::os::unix::io::AsRawFd;

        let path = paths.dir().join(format!("{tag}-stderr.log"));
        let file = std::fs::File::create(&path).expect("create the capture file");
        let saved = unsafe { libc::dup(2) };
        assert!(saved >= 0, "dup(2) failed");
        assert!(
            unsafe { libc::dup2(file.as_raw_fd(), 2) } >= 0,
            "dup2 onto fd 2 failed"
        );
        Self {
            path,
            saved,
            file: Some(file),
        }
    }

    /// Restore fd 2 and hand back everything that was written to it.
    fn finish(mut self) -> String {
        self.restore();
        std::fs::read_to_string(&self.path).expect("read the capture")
    }

    fn restore(&mut self) {
        if let Some(file) = self.file.take() {
            unsafe {
                libc::dup2(self.saved, 2);
                libc::close(self.saved);
            }
            drop(file);
        }
    }
}

impl Drop for StderrCapture {
    fn drop(&mut self) {
        self.restore();
    }
}

/// The ordinary call these rows make: everything defaulted except the
/// session and the deadline being measured.
fn secret_args(session: &str, timeout_secs: u32) -> RequestSecretInputArgs {
    RequestSecretInputArgs {
        session: session.to_string(),
        prompt_text: "a credential".into(),
        timeout_secs: Some(timeout_secs),
        ..Default::default()
    }
}

/// Every audit line of one kind, parsed, for **one** session.
///
/// Read before the `TestDaemon` drops: `Drop` removes the whole runtime
/// directory, log and all. `unwrap_or_default` on the read, because the
/// file does not exist until something has been recorded — which for a
/// negative row is exactly the case under test.
fn audit_entries(d: &TestDaemon, session_id: &str, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(d.paths.audit_log())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["kind"] == kind && e["session_id"] == session_id)
        .collect()
}

/// The two §9.4 secret kinds for one session, **in the order they were
/// written** — which is the half a per-kind filter throws away.
fn secret_audit_kinds(d: &TestDaemon, session_id: &str) -> Vec<String> {
    std::fs::read_to_string(d.paths.audit_log())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["session_id"] == session_id)
        .filter_map(|e| e["kind"].as_str().map(str::to_string))
        .filter(|k| k.starts_with("secret_input_"))
        .collect()
}

/// The `reason` on a `secret_cancelled` response — and an assertion that
/// it *is* one, so a row collecting reasons cannot quietly collect a
/// `secret_provided`.
fn cancelled_reason(payload: &Value) -> String {
    assert_eq!(
        payload["status"], "secret_cancelled",
        "expected a cancellation, got {payload}"
    );
    payload["data"]["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("a secret_cancelled with no reason: {payload}"))
        .to_string()
}

// =================================================== the leak detector
//
// **This runs before every absence assertion in this file, and its result
// is the licence for them.** An assertion that a surface does not contain
// the secret passes trivially against a system that never produced one —
// a buffer nothing writes to, a comparison that never matches, a probe
// misspelled in both places. So the same byte string is first sent to one
// session three ways that are all *supposed* to leak, and each is asserted
// to.
//
// "Runs first" is literal rather than a hope about libtest's ordering:
// [`run_leak_detector`] is a function, [`the_leak_detector_sees_every_path_that_is_supposed_to_leak`]
// is it on its own, and [`a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`]
// calls it before it asserts anything. It runs on a daemon and a session
// of its own, so the bytes it deliberately spills cannot reach the
// surfaces the row beside it is sweeping.

/// How many times `needle` appears in `hay`.
///
/// A **count** and not a `contains`, because the detector sends one probe
/// three times to one session: after the first path the buffer already
/// holds it, and `contains` would then be true of the second and third
/// whether or not they wrote anything at all.
fn occurrences(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// The three paths, one session, one byte string — asserted to leak.
///
/// | Path | Must appear in |
/// |---|---|
/// | `Input { bytes }` from an attached ReadWrite client, echo **on** | the ring buffer, and a second attached client's `Output` stream |
/// | `send_input(data: …)` | a `read_output` response |
/// | a `SecretInput` to an **echo-on** child (§11.2's documented-caveat fixture) | the ring buffer — because the *child* echoed it, which is the limitation Holdfast cannot defend against |
///
/// **If any of these ever passes by absence, stop**: the detector is
/// broken and nothing else in this file means anything.
async fn run_leak_detector(tag: &str) {
    let d = TestDaemon::start(tag).await;
    let s = d.shell_running(&echo_on_loop_fixture());

    let mut typist = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut watcher = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;

    assert_eq!(
        occurrences(&buffered(&s), PROBE.as_bytes()),
        0,
        "the session already held the probe before the detector wrote it"
    );

    // ---- path 1: an ordinary `Input` frame.
    send(
        &mut typist,
        &ClientFrame::Input {
            bytes: format!("{PROBE}\n").into_bytes(),
        },
    )
    .await;
    let seen = stream_until(&mut typist, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, PROBE.as_bytes()),
        "path 1 saw nothing on the submitting client's own stream: the harness \
         could not have caught a leak"
    );
    let watched = stream_until(&mut watcher, b"got=HUNTER2", 20).await;
    assert!(
        contains(&watched, PROBE.as_bytes()),
        "path 1 did not reach a second attached client, so every 'not broadcast \
         to another client' assertion in this file is about a stream nothing \
         writes to"
    );
    let after_one = occurrences(&buffered(&s), PROBE.as_bytes());
    assert!(
        after_one > 0,
        "path 1 did not reach the ring buffer, so every 'not in the buffer' \
         assertion in this file is about a buffer nothing writes to:\n{}",
        String::from_utf8_lossy(&buffered(&s))
    );

    // ---- path 2: `send_input`, the call §16.4 step 4's parenthetical says
    // a well-behaved agent does *not* make (REQ-SEC-011). It is used here
    // on purpose: it is the agent-facing write path, and `read_output` is
    // the agent-facing read path, so the pair is the one round trip an
    // agent could actually perform.
    //
    // **The cursor is sampled before the write, so the response contains
    // path 2's bytes and nothing path 1 left behind.** Read from `0` this
    // assertion is green against a `send_input` that discards its payload
    // outright — measured, on this row, during Task 13's mutation ladder.
    let cursor = s.buffer_head();
    let wrote = d.send_input(&s.id, PROBE).await;
    assert_eq!(
        wrote["status"], "ok",
        "the detector's own send_input failed: {wrote}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rendered = d.read_output_since(&s.id, cursor).await.to_string();
        if rendered.contains(PROBE) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "path 2 is absent from a read_output response taken from the cursor \
             its own write started at, so every 'absent from a read_output \
             response' assertion is about a response that carries \
             nothing:\n{rendered}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // ---- path 3: a real `SecretInput`, to a child that echoes.
    //
    // The request is raised by the **tool call**: this child never drops
    // ECHO, so no echo-drop raise is coming and none is needed.
    let call = spawn_call(&d, secret_args(&s.id, 20));
    let (request_id, _) = next_awaiting_secret(&mut typist, 20).await;
    let before_three = occurrences(&buffered(&s), PROBE.as_bytes());
    send(
        &mut typist,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        joined(call, "the detector's secret call").await["status"],
        "secret_provided"
    );
    // The buffer is written by the reader thread, so the write's ack is
    // not the echo's arrival.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while occurrences(&buffered(&s), PROBE.as_bytes()) <= before_three {
        assert!(
            tokio::time::Instant::now() < deadline,
            "path 3 did not reach the ring buffer. Either the write never \
             happened, or an echo-on child stopped echoing — and REQ-TST-006's \
             documented limitation is asserted against exactly this:\n{}",
            String::from_utf8_lossy(&buffered(&s))
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let _ = s.signal(Signal::Kill);
}

/// [`run_leak_detector`] on its own, so a broken harness is one red row
/// with a name rather than a confusing failure inside an absence test.
#[tokio::test]
async fn the_leak_detector_sees_every_path_that_is_supposed_to_leak() {
    run_leak_detector("leakdetector").await;
}

/// The derivation in [`echo_on_fixture`] and [`echo_on_loop_fixture`],
/// asserted rather than assumed.
///
/// A `replace` that matched nothing would hand
/// [`the_documented_echo_on_leak_is_asserted_not_assumed`] an
/// echo-**off** child, and that row would then assert the opposite of
/// what its name claims while staying green.
#[test]
fn the_echo_on_fixtures_are_the_echo_off_one_with_the_stty_calls_removed() {
    assert!(ECHO_OFF_FIXTURE.contains("stty -echo;"));
    let on = echo_on_fixture();
    assert!(!on.contains("stty"), "{on}");
    assert!(on.contains("read x"), "{on}");
    assert!(on.contains(TRANSFORM), "{on}");
    assert!(on.contains("printf 'Password: '"), "{on}");
    let looped = echo_on_loop_fixture();
    assert!(!looped.contains("stty"), "{looped}");
    assert!(looped.starts_with("while read x; do "), "{looped}");
    assert!(looped.contains(TRANSFORM), "{looped}");
}

// ======================================= the seven surfaces, all absent

/// **Six of the module header's seven surfaces, swept whole, for a value
/// the agent asked for and a human typed.**
///
/// **Six and not seven, and the arithmetic is stated rather than
/// implied.** This row sweeps surfaces **1, 2, 3's `binding_approval`
/// half, 5, 6 and 7**. It *drives* surface 4 — `require_confirm` really
/// does put a `BindingApprovalRequired` on both clients here — but it
/// does not sweep it: [`next_binding_approval`] destructures the three
/// fields asserted below and discards the frame, and [`stream_until`]
/// accumulates only `Output`. A sweep here would be the vacuous kind
/// anyway, because on the tool path the approval is raised *before*
/// anything has resolved and there is no value yet to be absent from it.
/// Surface 4, and surface 3's `binding_resolved` half, are swept by
/// `secret::binding::tests::a_keychain_resolved_secret_reaches_none_of_them_either`
/// over every frame its client saw on both sides of the decision.
///
/// Two phases on **one** session, because the surfaces pull in opposite
/// directions:
///
/// * **Phase A, with nobody attached.** The call times out unanswered, so
///   §9.5's buffer notice is written (surface 5) and a
///   `secret_input_request` / `secret_input_resolved` pair is logged
///   (surface 2). Nothing is submitted yet; the notice simply has to be in
///   the buffer that gets swept at the end.
/// * **Phase B, with two clients attached.** `require_confirm` raises a
///   `BindingApprovalRequired`, a human approves it (surface 3's
///   `binding_approval`), `wincred` resolves nothing on every platform so
///   the call falls through to the human-prompt path, and the human
///   answers it (surfaces 1 and 7).
///
/// **The positive controls, without which all of the above is satisfied by
/// an implementation that throws the value away:**
///
/// 1. [`run_leak_detector`] first, which is the licence for every absence
///    below;
/// 2. the child's own `got=HUNTER2` — a *transform* of what it read, so
///    arrival is asserted on the child's output rather than on our having
///    sent something;
/// 3. `bytes_written`, which is the count the agent is given in place of
///    the value;
/// 4. a witness per swept surface that the surface is **non-empty and of
///    the expected shape** — the notice is in the buffer, the four audit
///    kinds are on the log in order, both `binding_approval` lines are
///    there, both client streams carry `got=HUNTER2`, the `read_output`
///    response carries the child's prompt, and fd 2 caught a
///    daemon-written line.
///
/// **The `daemon.log` witness is a real diagnostic, provoked on purpose.**
/// [`leak_canary_binding`] carries an uncompilable `match_command`, which
/// `secret::binding::pattern_matches` answers by writing the binding's
/// *name* to `daemon.log` and declining to match. It is first in
/// configured order, so it costs nothing but the line it exists to
/// produce. Without it the fd-2 capture could be empty and "the value is
/// not in `daemon.log`" would be a claim about a file nothing wrote to.
#[tokio::test]
async fn a_tool_submitted_secret_reaches_none_of_the_seven_surfaces() {
    run_leak_detector("sevensurfaces-detector").await;

    let d = TestDaemon::start_with_config("sevensurfaces", canary_and_confirming_config()).await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    let capture = StderrCapture::start(&d.paths, "sevensurfaces");

    // ---- phase A: nobody attached, so §9.5's notice is written.
    assert_eq!(
        cancelled_reason(&joined(spawn_call(&d, secret_args(&s.id, 8)), "phase A").await),
        "timeout"
    );
    assert_eq!(
        notice_count(&s),
        1,
        "the §9.5 notice was never written, so sweeping the buffer for it \
         proves nothing:\n{}",
        String::from_utf8_lossy(&buffered(&s))
    );

    // ---- phase B: two clients, an approval, and a human's answer.
    let mut typist = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let mut watcher = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;

    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            session: s.id.clone(),
            prompt_text: "the deploy user's sudo password".into(),
            timeout_secs: Some(30),
            ..Default::default()
        },
    );

    // Surface 4, on both clients: §9.2's role split is about output, so an
    // observer is *shown* the approval and merely may not answer it.
    let (approval_id, binding_name, provider) = next_binding_approval(&mut typist, 20).await;
    assert_eq!(binding_name, "prod-shell");
    assert_eq!(provider, "wincred");
    let (observed, _, _) = next_binding_approval(&mut watcher, 20).await;
    assert_eq!(observed, approval_id);

    send(
        &mut typist,
        &ClientFrame::ApproveBinding {
            approval_id,
            decision: ApprovalDecision::Approve,
        },
    )
    .await;

    let request_id = await_fall_through(&d, &s.id).await;
    send(
        &mut typist,
        &ClientFrame::SecretInput {
            request_id: request_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    // Positive control 2 — the child transformed what it read.
    let seen = stream_until(&mut typist, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );
    let watched = stream_until(&mut watcher, b"got=HUNTER2", 20).await;
    assert!(
        contains(&watched, b"got=HUNTER2"),
        "the second client's stream carries nothing, so sweeping it proves \
         nothing: {}",
        String::from_utf8_lossy(&watched)
    );

    let result = call.await.expect("the waiting call");
    let payload = body(&result);

    // ---- surface 1: the MCP response, whole.
    //
    // The **whole** `CallToolResult` and not just `structuredContent`:
    // `content[0]`'s text mirror is on the wire too, and a field-by-field
    // check is how a secret once shipped in a field nobody was looking at.
    assert_eq!(payload["status"], "secret_provided", "{payload}");
    assert_eq!(
        payload["data"]["request_id"], request_id,
        "the tool answered against an id nobody broadcast"
    );
    assert_eq!(
        payload["data"]["bytes_written"],
        (PROBE.len() + 1) as u64,
        "seven bytes plus the appended newline"
    );
    let whole = whole_result(&result);
    assert!(
        !whole.contains(PROBE),
        "the value reached the MCP response: {whole}"
    );

    // ---- surface 7: the ring buffer, and both clients' streams.
    //
    // The buffer is read raw rather than through `read_output`, which
    // redacts — a redacted read would pass whether or not it was there.
    // The `read_output` response is swept beside it, because that is the
    // surface the agent actually reads.
    assert!(
        !contains(&seen, PROBE.as_bytes()),
        "the value came back on the submitting client's own stream"
    );
    assert!(
        !contains(&watched, PROBE.as_bytes()),
        "§9.2: the value was broadcast to another attached client"
    );
    let buf = buffered(&s);
    assert!(
        !contains(&buf, PROBE.as_bytes()),
        "the value reached the ring buffer: {}",
        String::from_utf8_lossy(&buf)
    );
    // **The raw sweep above is the redactor-independent one; this one is
    // not, and the difference is why both are here.** `read_output`
    // redacts, so an absence assertion over its response is an assertion
    // about a *redacted* rendering of the buffer.
    //
    // **For `PROBE` specifically the two are equivalent, and that is
    // measured rather than assumed**: `generic-secret-assignment`'s value
    // group is `[^\s"';,)]{8,}` and `hunter2` is seven bytes, so
    // `redact_str(rules, "Password: hunter2")` comes back unchanged. The
    // assertion below is a real one for this value.
    //
    // What the raw sweep buys is the *general* case: any leaked string of
    // eight or more bytes from that class, landing after a `password`-ish
    // label, comes back `[REDACTED:generic]` and passes here. A future
    // change to `PROBE` would silently move this row into that class, and
    // the raw read one statement earlier is what stops that mattering.
    //
    // The same rule is why the witness is the child's **prompt** and not
    // its `got=` transform: `got=HUNTER2` *is* eleven bytes of that class,
    // so measured, `Password: got=HUNTER2` is redacted whole — and a
    // `got=HUNTER2` witness here was green only because §9.5's notice
    // happened to sit between the two.
    let read_body = d.read_output(&s.id).await;
    assert!(
        read_body["data"]["output"]
            .as_str()
            .is_some_and(|o| o.contains("Password: ")),
        "the read_output response carries none of this session's output, so \
         sweeping it proves nothing:\n{read_body}"
    );
    let read = read_body.to_string();
    assert!(
        !read.contains(PROBE),
        "the value reached a read_output response:\n{read}"
    );

    // ---- surfaces 2 and 3: the audit log, whole, with the four kinds
    // this flow actually produces named beside it.
    let audit = std::fs::read_to_string(d.paths.audit_log()).unwrap_or_default();
    assert_eq!(
        secret_audit_kinds(&d, &s.id),
        vec![
            "secret_input_request",
            "secret_input_resolved",
            "secret_input_request",
            "secret_input_resolved",
        ],
        "the two §9.4 secret kinds are not on the log, so sweeping it for the \
         value proves nothing:\n{audit}"
    );
    let approvals = audit_entries(&d, &s.id, "binding_approval");
    assert_eq!(
        approvals.len(),
        2,
        "phase A's expiry and phase B's approval are both binding_approval \
         lines; without them surface 3 is a kind nothing wrote:\n{audit}"
    );
    assert_eq!(approvals[1]["outcome"], "approved");
    assert!(
        !audit.contains(PROBE),
        "the value reached the audit log:\n{audit}"
    );

    // ---- surface 6: `daemon.log`.
    let log = capture.finish();
    assert!(
        log.contains("`leak-canary` has an uncompilable match_command"),
        "fd 2 caught no daemon diagnostic at all, so sweeping it for the value \
         proves nothing:\n{log}"
    );
    assert!(
        !log.contains(PROBE),
        "the value reached the daemon's diagnostic stream:\n{log}"
    );

    let _ = s.signal(Signal::Kill);
}

/// §5.2's answer to the agent is a **count**, and the schema has nowhere
/// to put anything else.
///
/// `bytes_written` is asserted against the length that was actually
/// written rather than against a literal, in both `append_newline`
/// directions — a response returning the value "for confirmation" is
/// caught by the sweep, and a response returning a *wrong* count is caught
/// by the arithmetic.
#[tokio::test]
async fn the_response_carries_a_length_and_not_a_value() {
    for (append_newline, extra) in [(true, 1usize), (false, 0)] {
        let d = TestDaemon::start(&format!("lengthonly{}", usize::from(append_newline))).await;
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

        let call = spawn_call(
            &d,
            RequestSecretInputArgs {
                session: s.id.clone(),
                prompt_text: "a credential".into(),
                append_newline: Some(append_newline),
                timeout_secs: Some(20),
                ..Default::default()
            },
        );
        let (request_id, _) = next_awaiting_secret(&mut c, 20).await;
        send(
            &mut c,
            &ClientFrame::SecretInput {
                request_id,
                bytes: PROBE.as_bytes().to_vec(),
            },
        )
        .await;

        let result = tokio::time::timeout(Duration::from_secs(25), call)
            .await
            .expect("the call never returned")
            .expect("the call");
        let payload = body(&result);
        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert_eq!(
            payload["data"]["bytes_written"],
            (PROBE.len() + extra) as u64,
            "append_newline={append_newline}: the count is not the written length"
        );
        assert!(
            !whole_result(&result).contains(PROBE),
            "append_newline={append_newline}: the response carried the value"
        );
        let _ = s.signal(Signal::Kill);
    }
}

/// REQ-TST-006, extended from 0.0.6's frame path to the **tool** path:
/// **this is the documented limitation; if this assertion changes, update
/// §5.2 and §9.5.**
///
/// A child that does not disable echo gets the same treatment from
/// Holdfast — the value is in no log and in no MCP response — and the
/// value **does** reach the ring buffer, because the *child* echoed it.
/// Holdfast cannot defend against that and does not claim to.
///
/// The row exists so the limitation cannot drift unnoticed in either
/// direction: a future change that silently started capturing would break
/// the two absences, and one that started claiming a protection Holdfast
/// does not provide would break the presence.
#[tokio::test]
async fn the_documented_echo_on_leak_is_asserted_not_assumed() {
    let d = TestDaemon::start("echoonleak").await;
    let s = d.shell_running(&echo_on_fixture());
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    // Nothing raises a request here on its own: the child never drops
    // ECHO, which is the whole point of the fixture. The tool call raises.
    let call = spawn_call(&d, secret_args(&s.id, 20));
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    let result = tokio::time::timeout(Duration::from_secs(25), call)
        .await
        .expect("the call never returned")
        .expect("the call");
    let payload = body(&result);
    assert_eq!(payload["status"], "secret_provided", "{payload}");

    // The child read it — asserted on its transform, so this holds even
    // for a line discipline that echoed nothing.
    let seen = stream_until(&mut c, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );

    // **The limitation.** The child echoed it, so it is in the buffer.
    let buf = buffered(&s);
    assert!(
        contains(&buf, PROBE.as_bytes()),
        "an echo-on child's secret did NOT reach the ring buffer. Either the \
         fixture stopped echoing — in which case this row no longer asserts \
         REQ-TST-006's caveat — or Holdfast started capturing, in which case \
         §5.2 and §9.5 need updating rather than this assertion:\n{}",
        String::from_utf8_lossy(&buf)
    );

    // **And Holdfast's own behaviour is identical.** Nothing it writes
    // carries the value: not the response, not the audit log.
    assert!(
        !whole_result(&result).contains(PROBE),
        "the value reached the MCP response"
    );
    let audit = std::fs::read_to_string(d.paths.audit_log()).unwrap_or_default();
    assert_eq!(
        secret_audit_kinds(&d, &s.id),
        vec!["secret_input_request", "secret_input_resolved"],
        "the audit log holds no line for this call, so sweeping it proves \
         nothing:\n{audit}"
    );
    assert!(
        !audit.contains(PROBE),
        "the value reached the audit log:\n{audit}"
    );

    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------- raise, adopt, collide

#[tokio::test]
async fn a_tool_call_on_a_vacant_slot_raises_and_broadcasts() {
    let d = TestDaemon::start("raise").await;
    // `cat`, not the echo-off fixture: the slot must be **vacant** when
    // the call arrives, so nothing may have raised one already.
    let s = d.shell_running("cat");
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "a token for the registry".into(),
                timeout_secs: Some(1),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    let (broadcast_id, prompt) = next_awaiting_secret(&mut c, 20).await;
    assert!(broadcast_id.starts_with("secreq_"), "{broadcast_id}");
    assert_eq!(prompt, "a token for the registry");

    // **The two ids are compared to each other.** Returning a fresh id to
    // the agent while broadcasting another is two ids for one request,
    // and no single-side assertion can see it.
    let payload = body(&call.await.expect("the call"));
    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(
        payload["data"]["request_id"], broadcast_id,
        "the agent's id and the client's id are different requests"
    );
    let _ = s.signal(Signal::Kill);
}

/// REQ-SEC-010a, end to end, and §16.4 steps 3–7 are exactly this.
#[tokio::test]
async fn a_tool_call_adopts_an_echo_raised_request() {
    let d = TestDaemon::start("adopt").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    // The echo drop raises first, with no call behind it.
    let (raised_id, raised_prompt) = next_awaiting_secret(&mut c, 20).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "a completely different label".into(),
                timeout_secs: Some(30),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });
    await_waiter(&d, &s.id, "the adopting call").await;

    // Answer it, and assert the call **completes** against the raised id.
    //
    // **The id alone is not enough, and asserting only the id is a test
    // that cannot fail.** Measured: with adoption removed — collide on
    // any occupied slot rather than on one with a waiter — the refusal
    // carries `request_id: <the raised id>` too, because §9.4 binds a
    // colliding call to the request it collided with. An id-only
    // assertion is green against the exact mutation this row exists to
    // kill. The outcome is what separates them.
    //
    // **Exactly one `AwaitingSecret` for the whole flow**, checked while
    // the request is still open — an adopting call must not re-announce
    // a request a human may already be typing into.
    let second = tokio::time::timeout(Duration::from_millis(500), recv(&mut c)).await;
    if let Ok(ServerFrame::AwaitingSecret { request_id, .. }) = second {
        panic!("the adopting call re-broadcast the request it adopted: {request_id}");
    }

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: raised_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = body(&call.await.expect("the call"));
    assert_eq!(
        payload["status"], "secret_provided",
        "the call refused or re-allocated instead of adopting; REQ-SEC-010a makes \
         adoption the ordinary case, not an edge case"
    );
    assert_ne!(
        payload["data"]["reason"], "concurrent_request_pending",
        "adoption became a collision"
    );
    assert_eq!(
        payload["data"]["request_id"], raised_id,
        "the adopting call answered against an id nobody broadcast"
    );

    // The raised prompt is the child's own line, redacted; it may
    // legitimately be empty (REQ-O-013), so nothing here asserts it is
    // not.
    let _ = raised_prompt;
    let _ = s.signal(Signal::Kill);
}

/// The adopting call's `prompt_text` must not replace the raised one.
///
/// Asserted through a **second client attaching after adoption**: a
/// same-client assertion cannot see this, because that client already has
/// the original frame. The late attacher's replay is what does.
#[tokio::test]
async fn an_adopted_request_keeps_the_prompt_it_was_raised_with() {
    let d = TestDaemon::start("adoptprompt").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut first = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, raised_prompt) = next_awaiting_secret(&mut first, 20).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "AGENT SUPPLIED LABEL".into(),
                timeout_secs: Some(10),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    // Attach late, while the call is still waiting, and read the replay.
    let mut late = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    let (replayed_id, replayed_prompt) = next_awaiting_secret(&mut late, 20).await;
    assert_eq!(replayed_id, raised_id);
    assert_eq!(
        replayed_prompt, raised_prompt,
        "the adopting call rewrote the prompt a human may already be typing into"
    );
    assert_ne!(
        replayed_prompt, "AGENT SUPPLIED LABEL",
        "the agent relabelled the request"
    );

    send(
        &mut first,
        &ClientFrame::SecretInput {
            request_id: raised_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        body(&call.await.expect("the call"))["status"],
        "secret_provided"
    );
    let _ = s.signal(Signal::Kill);
}

/// `concurrent_request_pending` is a **second-caller** condition, and the
/// first caller's request is untouched.
#[tokio::test]
async fn a_second_caller_collides_and_the_first_still_completes() {
    let d = TestDaemon::start("collide").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let first = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "the first caller".into(),
                timeout_secs: Some(30),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });

    // Wait until the first call is really waiting, or the "second" caller
    // is the first one and this row is about nothing.
    await_waiter(&d, &s.id, "the first call").await;

    let second = body(
        &d.call(RequestSecretInputArgs {
            session: s.id.clone(),
            prompt_text: "the second caller".into(),
            timeout_secs: Some(30),
            ..Default::default()
        })
        .await,
    );
    assert_eq!(second["status"], "secret_cancelled");
    assert_eq!(second["data"]["reason"], "concurrent_request_pending");
    assert_eq!(
        second["data"]["request_id"], request_id,
        "the collision reported an id that is not the request it collided with"
    );

    // **The first caller goes on to complete.** Closing the request on
    // collision is the mutation that turns a race into data loss, and
    // only this half can see it.
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = body(&first.await.expect("the first call"));
    assert_eq!(
        payload["status"], "secret_provided",
        "the second caller cancelled the first"
    );
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------------------ the id check

/// §18.4: a `SecretInput` naming no outstanding request leaves the
/// connection open and writes **nothing** — and the child is still
/// blocked afterwards, which is what proves it.
#[tokio::test]
async fn a_wrong_request_id_writes_nothing_and_the_right_one_still_works() {
    let d = TestDaemon::start("wrongid").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    // The named authority agrees with the wire, in both directions.
    let slots = d.daemon.server.attach_hub().secrets();
    assert!(slots.matches_outstanding(&s.id, &request_id));
    assert!(!slots.matches_outstanding(&s.id, "secreq_notours"));

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: "secreq_notours".into(),
            bytes: b"WRONGVALUE".to_vec(),
        },
    )
    .await;
    match recv(&mut c).await {
        ServerFrame::ProtocolError { reason, frame_kind } => {
            assert_eq!(reason, "unknown_request_id");
            assert_eq!(frame_kind.as_deref(), Some("SecretInput"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }

    // The connection is still usable and the child is still blocked: the
    // correct id, immediately afterwards, still works.
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut c, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the refused submission left the request unanswerable: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !contains(&seen, b"WRONGVALUE"),
        "the refused submission was written to the child anyway"
    );
    let _ = s.signal(Signal::Kill);
}

// ----------------------------------------------------------- the deadline

/// §5.2, on a hand rather than a wall clock: an **unadopted** request has
/// no deadline of its own, because `timeout_secs` is an argument of the
/// *tool*.
///
/// **The pairing is what makes the first half mean anything.** In the
/// same test, an *adopted* request given the same advance does close —
/// so the clock demonstrably drives deadlines, and the assertion above is
/// not green because nothing is wired to it.
#[tokio::test]
async fn an_unadopted_request_has_no_deadline_and_an_adopted_one_does() {
    let clock = Clock::manual(std::time::Instant::now());
    let d = TestDaemon::start_with("nodeadline", clock.clone()).await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut c, 20).await;

    // Five minutes, in microseconds. Nobody called the tool.
    clock.advance(Duration::from_secs(300));
    tokio::task::yield_now().await;
    assert!(
        d.daemon
            .server
            .attach_hub()
            .secrets()
            .matches_outstanding(&s.id, &raised_id),
        "a raise with no call was given the tool's deadline, which §5.2 forbids in as \
         many words"
    );
    let quiet = tokio::time::timeout(Duration::from_millis(300), recv(&mut c)).await;
    if let Ok(frame) = quiet {
        assert!(
            !matches!(frame, ServerFrame::SecretRequestClosed { .. }),
            "an unadopted request closed on a clock nobody asked it to read"
        );
    }

    // The pairing: adopt it, advance the same amount, and it closes.
    let server = d.daemon.server.clone();
    let id = s.id.clone();
    let call = tokio::spawn(async move {
        server
            .request_secret_input(Parameters(RequestSecretInputArgs {
                session: id,
                prompt_text: "now with a caller".into(),
                timeout_secs: Some(120),
                ..Default::default()
            }))
            .await
            .expect("request_secret_input")
    });
    // Wait for the call to be parked on the clock before moving the hand,
    // or the advance lands before the sleep is registered and the test
    // hangs rather than failing.
    await_waiter(&d, &s.id, "the adopting call").await;
    clock.advance(Duration::from_secs(300));

    let payload = body(
        &tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect("the adopted call did not answer when its deadline passed")
            .expect("the call"),
    );
    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "timeout");
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------ max_secret_bytes

/// The cap applies to the **received** bytes, and it applies *before*
/// anything is copied.
#[tokio::test]
async fn an_oversize_submission_is_rejected_without_reaching_the_child() {
    let d = TestDaemon::start("toolarge").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(16),
            ..secret_args(&s.id, 20)
        },
    );
    await_waiter(&d, &s.id, "the capped call").await;

    let oversize = "0123456789abcdefg";
    assert_eq!(oversize.len(), 17, "the fixture must exceed the cap by one");
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: request_id.clone(),
            bytes: oversize.as_bytes().to_vec(),
        },
    )
    .await;

    let payload = joined(call, "the over-cap call").await;
    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "too_large");
    assert_eq!(payload["data"]["request_id"], request_id);

    // **The child's silence is the assertion.** The status alone is green
    // against a write-then-reject implementation, which answers
    // `too_large` having already typed the value into a program that was
    // at that moment reading one.
    let seen = stream_until(&mut c, b"got=", 2).await;
    assert!(
        !contains(&seen, b"got="),
        "the child completed its read, so the over-cap value was written: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !contains(&seen, oversize.as_bytes()),
        "the refused value came back on the wire"
    );
    let _ = s.signal(Signal::Kill);
}

/// Normalisation strips a trailing newline and may append one, so
/// `bytes_written` can differ from the received length by one in either
/// direction. Checking the wrong one puts the boundary where the client's
/// newline habit put it.
///
/// **Both halves in one run, one byte of cap apart**, because either half
/// alone is green against a constant.
#[tokio::test]
async fn the_cap_is_measured_before_normalisation() {
    let d = TestDaemon::start("prenorm").await;

    // Seven bytes received, six after the strip. A `bytes_written` check
    // admits this; the received-length check refuses it.
    let over = d.shell_running(ECHO_OFF_FIXTURE);
    let mut co = attach_ok(&d, &over.id, AttachMode::ReadWrite).await;
    let (over_id, _) = next_awaiting_secret(&mut co, 20).await;
    let over_call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(6),
            ..secret_args(&over.id, 20)
        },
    );
    await_waiter(&d, &over.id, "the six-byte call").await;
    send(
        &mut co,
        &ClientFrame::SecretInput {
            request_id: over_id,
            bytes: b"secret\n".to_vec(),
        },
    )
    .await;
    let refused = joined(over_call, "the six-byte call").await;
    assert_eq!(
        cancelled_reason(&refused),
        "too_large",
        "seven bytes were measured after the strip, not as received"
    );

    // The pairing: one byte of cap higher, the identical submission.
    let under = d.shell_running(ECHO_OFF_FIXTURE);
    let mut cu = attach_ok(&d, &under.id, AttachMode::ReadWrite).await;
    let (under_id, _) = next_awaiting_secret(&mut cu, 20).await;
    let under_call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(7),
            ..secret_args(&under.id, 20)
        },
    );
    await_waiter(&d, &under.id, "the seven-byte call").await;
    send(
        &mut cu,
        &ClientFrame::SecretInput {
            request_id: under_id,
            bytes: b"secret\n".to_vec(),
        },
    )
    .await;
    let allowed = joined(under_call, "the seven-byte call").await;
    assert_eq!(
        allowed["status"], "secret_provided",
        "a cap of exactly the received length refused it, so the boundary is off by one"
    );
    assert_eq!(
        allowed["data"]["bytes_written"], 7,
        "six bytes after the strip plus the appended newline"
    );
    let seen = stream_until(&mut cu, b"got=SECRET", 20).await;
    assert!(
        contains(&seen, b"got=SECRET"),
        "the accepted value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );

    let _ = over.signal(Signal::Kill);
    let _ = under.signal(Signal::Kill);
}

// -------------------------------------------------- the call's own window

/// §5.2: the window is the **tool call's**, measured in wall time here
/// because the thing under test is that the argument was read at all.
#[tokio::test]
async fn a_call_that_nobody_answers_times_out_at_its_own_deadline() {
    let d = TestDaemon::start("owndeadline").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let _ = next_awaiting_secret(&mut c, 20).await;

    let t0 = std::time::Instant::now();
    let payload = joined(spawn_call(&d, secret_args(&s.id, 2)), "the two-second call").await;
    let elapsed = t0.elapsed();

    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "timeout");
    assert!(
        elapsed >= Duration::from_secs(2),
        "the call returned before its own deadline: {elapsed:?}"
    );
    // `joined`'s 25 s ceiling is the other half: an implementation that
    // ignored the argument and took the 120 s default never returns
    // inside it, and the panic names that.
    assert!(
        elapsed < Duration::from_secs(20),
        "the call ignored timeout_secs and used the default: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.2: *"On adoption, the adopting call's `timeout_secs` window starts
/// at that call and not at the raise."*
///
/// The discriminator is the **lower** bound. A timer started at the raise
/// has already burnt three seconds of a two-second window, so it returns
/// `timeout` almost instantly — which looks like a fast deadline rather
/// than a wrong one, and only an elapsed-time floor separates them.
#[tokio::test]
async fn the_adopting_calls_window_starts_at_the_call() {
    let d = TestDaemon::start("adoptwindow").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut c, 20).await;

    tokio::time::sleep(Duration::from_secs(3)).await;

    let t0 = std::time::Instant::now();
    let payload = joined(spawn_call(&d, secret_args(&s.id, 2)), "the adopting call").await;
    let elapsed = t0.elapsed();

    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(payload["data"]["reason"], "timeout");
    assert_eq!(
        payload["data"]["request_id"], raised_id,
        "the adopting call answered against an id nobody broadcast"
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "the window was measured from the raise, not from the call: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.2: *"There is no separate `no_client_attached` reason."* Rev. 6
/// removed the short-circuit; §7.8.4 argues at length against putting it
/// back.
#[tokio::test]
async fn no_client_attached_still_waits_the_full_window() {
    let d = TestDaemon::start("noclient").await;
    let s = d.shell_running("cat");

    let t0 = std::time::Instant::now();
    let payload = joined(spawn_call(&d, secret_args(&s.id, 3)), "the unattended call").await;
    let elapsed = t0.elapsed();

    assert_eq!(payload["status"], "secret_cancelled");
    assert_eq!(
        payload["data"]["reason"], "timeout",
        "a reason outside §18.1's four, invented for a condition §5.2 refuses to name"
    );
    assert!(
        elapsed >= Duration::from_secs(3),
        "the call short-circuited because nothing was attached: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// **The pairing for the row above**, and what makes waiting the right
/// behaviour rather than merely the specified one: the window is long
/// enough for somebody to arrive and answer.
#[tokio::test]
async fn a_client_attaching_mid_window_can_still_answer() {
    let d = TestDaemon::start("lateclient").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    // Nothing attached, so nothing raised: the call itself finds a vacant
    // slot. `SessionEvent` is consumed per connection, so with no client
    // the echo drop raises nothing.
    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the unattended call").await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut late = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (replayed_id, _) = next_awaiting_secret(&mut late, 20).await;

    send(
        &mut late,
        &ClientFrame::SecretInput {
            request_id: replayed_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = joined(call, "the call the late client answered").await;
    assert_eq!(
        payload["status"], "secret_provided",
        "a wait that never re-checks for clients cannot be answered by one that arrives"
    );
    assert_eq!(payload["data"]["request_id"], replayed_id);
    let seen = stream_until(&mut late, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the value never reached the child: {}",
        String::from_utf8_lossy(&seen)
    );
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------- the other two resolutions

/// `user_cancelled`'s only producer (Q6): the echo-off condition clears
/// with no value written.
#[tokio::test]
async fn the_child_abandoning_its_read_cancels_the_call() {
    let d = TestDaemon::start("abandoned").await;
    let s = d.shell_running(ABANDONED_READ_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call on an abandoned read").await;

    let payload = joined(call, "the abandoned call").await;
    assert_eq!(
        cancelled_reason(&payload),
        "user_cancelled",
        "mapping the echo restore onto `timeout` makes `user_cancelled` unreachable \
         and leaves a reason in the schema no response produces"
    );
    assert_eq!(payload["data"]["request_id"], raised_id);

    let (closed_id, outcome) = next_secret_closed(&mut c, 20).await;
    assert_eq!(closed_id, raised_id);
    assert_eq!(
        outcome, "cancelled",
        "§7.5's frame outcome, which is not the tool status"
    );
    let _ = s.signal(Signal::Kill);
}

/// **The A/B pairing for the row above, and I-1.**
///
/// `user_cancelled`'s only producer was `attach::conn::forward_events` —
/// **one task per attach connection**, `abort()`ed with it. So the same
/// child gave two different answers depending on whether a human happened
/// to be watching. Driven by the concurrency review:
///
/// ```text
/// attached:   status=secret_cancelled reason=user_cancelled after 2.0s
/// unattended: status=secret_cancelled reason=timeout        after 10.0s
/// ```
///
/// Every existing `user_cancelled` row attaches a client first, so the
/// suite could not see it. This one attaches nothing, and the elapsed
/// bound is the discriminator: with no second observer the call sits out
/// its **whole** 20-second window and answers `timeout`.
///
/// Nothing is raised by the echo drop here — `SessionEvent` had exactly
/// one consumer and it is per connection — so the call itself allocates
/// the request, which is the unattended shape §9.5's rung-3 notice exists
/// for.
#[tokio::test]
async fn an_unattended_child_that_abandons_its_read_cancels_the_call_too() {
    let d = TestDaemon::start("unattendedabandon").await;
    let s = d.shell_running(ABANDONED_READ_FIXTURE);

    let t0 = std::time::Instant::now();
    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the unattended call on an abandoned read").await;
    let payload = joined(call, "the unattended abandoned call").await;
    let elapsed = t0.elapsed();

    assert_eq!(
        cancelled_reason(&payload),
        "user_cancelled",
        "with nobody attached the echo restore had no observer, so the call waited \
         out its whole window and reported a timeout for a child that gave up: \
         {payload}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the answer arrived at the deadline rather than at the echo restore, which \
         is the same defect wearing the right reason: {elapsed:?}"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.1: a session that exits under a waiting call answers `session_died`
/// with the code, not `timeout` two minutes later.
#[tokio::test]
async fn a_session_that_exits_mid_wait_returns_session_died() {
    let d = TestDaemon::start("diedmidwait").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let _ = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call that outlives its session").await;

    let _ = s.signal(Signal::Kill);
    let payload = joined(call, "the call on a dead session").await;
    assert_eq!(
        payload["status"], "session_died",
        "the call sat out its window for a child that was already gone: {payload}"
    );
    assert!(
        payload["data"]["exit_code"].is_number(),
        "§5.1 wants the code, and `null` tells an operator nothing: {payload}"
    );
}

/// **C-1 / GH #38: the read loop is a future somebody else may drop, and
/// dropping it must not strand the call it was answering.**
///
/// `attach::conn::run` polls `read_loop` as the last branch of a `biased`
/// `select!`, so the loop is dropped **where it stands** the moment
/// `shutdown.changed()` fires or the output forwarder returns — a
/// `daemon/stop`, a SIGTERM, §7.3's client-less exit, a dead socket, or a
/// client that stopped draining its queue. Its `SecretInput` arm is the
/// one place that holds a taken `RaisedRequest` across an await, and the
/// taken request carries the only `oneshot::Sender` the waiting tool call
/// has.
///
/// Dropping it unanswered used to produce all four of these at once: the
/// tool task **panicked** (`await_secret`'s `Err` arm fell through to a
/// second poll of a completed receiver — `called after complete`), the
/// queued write still reached the child, the frame body was left
/// unzeroed, and no `SecretRequestClosed` was broadcast.
///
/// **The arrangement, and why each step is a fact rather than a wait.**
/// The write is parked *inside* `MockPty::write` by a hook the test
/// releases, so "the arm is past `close_secret` and the acknowledgement is
/// outstanding" is observed (`entered`, plus an empty slot) rather than
/// slept for. The connection is then ended by `Daemon::shutdown`, the
/// `biased`-first branch, and the test waits for the hub to
/// **unregister** the client — which `run` does only after its `select!`
/// has resolved, i.e. only once `read_loop` has actually been dropped.
/// Only then is the write released. So the drop strictly precedes the
/// acknowledgement, in every scheduling order.
///
/// The answer must still be `secret_provided` with the real count: the
/// bytes did reach the child, and telling the agent anything else about a
/// credential that landed is the second of C-1's four consequences.
#[tokio::test]
async fn a_connection_dropped_mid_submission_still_answers_the_waiting_call() {
    let d = TestDaemon::start("cancelsafe").await;
    let (s, pty) = d.mock_session();
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call whose connection is about to go").await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    // The writer thread parks here; nothing else does.
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        pty.on_write(move || {
            entered.store(true, std::sync::atomic::Ordering::SeqCst);
            while !release.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(2));
            }
        });
    }

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: request_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    // The arm has taken the slot and its write is on the fd. Both halves
    // are asserted: the flag says the writer is inside `write`, and the
    // empty slot says the request left the hub before it got there.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !entered.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the submission never reached the writer thread"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        d.daemon
            .server
            .attach_hub()
            .secrets()
            .outstanding(&s.id)
            .is_none(),
        "the arm parked without taking the slot; the arrangement is not the one C-1 is about"
    );

    // End the connection under it — `biased`, so this branch wins.
    d.daemon.shutdown();
    while !d.daemon.server.attach_hub().clients_of(&s.id).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the connection never ended, so the read loop was never dropped"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    release.store(true, std::sync::atomic::Ordering::SeqCst);
    let payload = joined(call, "the call whose connection went away").await;
    assert_eq!(
        payload["status"], "secret_provided",
        "the submitting connection was dropped and the call was not told what became of \
         its request: {payload}"
    );
    assert_eq!(
        payload["data"]["bytes_written"],
        serde_json::json!(PROBE.len() + 1),
        "the count is the writer thread's, not a guess made where the drop happened: {payload}"
    );
    assert!(
        contains(&pty.written(), PROBE.as_bytes()),
        "the value never reached the child, so `secret_provided` would be the wrong answer"
    );
}

// --------------------------------------------- the four, all in one run

/// **Every reason driven for real, in one run, against an exhaustive
/// match.**
///
/// Not a set assembled from what the other rows happened to observe —
/// that form is green whenever the suite is green. Each arm below drives
/// its own arrangement, and the comparison is against a `match` over
/// [`CancelReason`], so a fifth variant fails to **compile** here until
/// something in this test emits it.
#[tokio::test]
async fn every_secret_cancelled_reason_is_reachable() {
    use holdfast_core::secret::CancelReason;
    use std::collections::BTreeSet;

    let expected: BTreeSet<&str> = CancelReason::ALL
        .iter()
        .map(|r| match r {
            CancelReason::UserCancelled => "user_cancelled",
            CancelReason::Timeout => "timeout",
            CancelReason::TooLarge => "too_large",
            CancelReason::ConcurrentRequestPending => "concurrent_request_pending",
        })
        .collect();

    let d = TestDaemon::start("allreasons").await;
    let mut observed: BTreeSet<String> = BTreeSet::new();

    // too_large — an over-cap submission.
    {
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let (id, _) = next_awaiting_secret(&mut c, 20).await;
        let call = spawn_call(
            &d,
            RequestSecretInputArgs {
                max_secret_bytes: Some(1),
                ..secret_args(&s.id, 20)
            },
        );
        await_waiter(&d, &s.id, "the over-cap call").await;
        send(
            &mut c,
            &ClientFrame::SecretInput {
                request_id: id,
                bytes: b"AB".to_vec(),
            },
        )
        .await;
        observed.insert(cancelled_reason(&joined(call, "the over-cap call").await));
        let _ = s.signal(Signal::Kill);
    }

    // timeout — an elapsed deadline.
    {
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let _ = next_awaiting_secret(&mut c, 20).await;
        observed.insert(cancelled_reason(
            &joined(spawn_call(&d, secret_args(&s.id, 2)), "the timing-out call").await,
        ));
        let _ = s.signal(Signal::Kill);
    }

    // user_cancelled — echo restored with no read.
    {
        let s = d.shell_running(ABANDONED_READ_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let _ = next_awaiting_secret(&mut c, 20).await;
        let call = spawn_call(&d, secret_args(&s.id, 20));
        await_waiter(&d, &s.id, "the abandoned call").await;
        observed.insert(cancelled_reason(&joined(call, "the abandoned call").await));
        let _ = s.signal(Signal::Kill);
    }

    // concurrent_request_pending — a second caller.
    {
        let s = d.shell_running(ECHO_OFF_FIXTURE);
        let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
        let (id, _) = next_awaiting_secret(&mut c, 20).await;
        let first = spawn_call(&d, secret_args(&s.id, 20));
        await_waiter(&d, &s.id, "the first call").await;
        observed.insert(cancelled_reason(&body(
            &d.call(secret_args(&s.id, 20)).await,
        )));
        // Release the first caller rather than leaving it parked for its
        // whole window while the rest of the test runs.
        send(
            &mut c,
            &ClientFrame::SecretInput {
                request_id: id,
                bytes: PROBE.as_bytes().to_vec(),
            },
        )
        .await;
        assert_eq!(
            joined(first, "the first call").await["status"],
            "secret_provided",
            "the colliding call resolved the request it collided with"
        );
        let _ = s.signal(Signal::Kill);
    }

    let observed: BTreeSet<&str> = observed.iter().map(String::as_str).collect();
    assert_eq!(
        observed, expected,
        "a `secret_cancelled` reason the schema declares and nothing produces — \
         REQ-T-017's defect one level down, in a `reason` rather than a `status`"
    );
}

// ------------------------------------------------------- Q1's re-raise

/// **Q1.** §5.2 makes the deadline close the *request*, not merely the
/// call — but the raise is edge-triggered on the transition *into*
/// `AwaitingSecret`, so closing it while the child is still sitting at its
/// echo-off prompt removes the human's only affordance and nothing will
/// ever put it back.
///
/// **The pairing is the second half**, and without it this row is green
/// against an implementation that re-raises unconditionally: on a session
/// that is *not* awaiting a secret, the same timeout must raise nothing.
#[tokio::test]
async fn a_caller_timeout_re_raises_while_the_child_is_still_asking() {
    let d = TestDaemon::start("reraise").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (first_id, _) = next_awaiting_secret(&mut c, 20).await;

    let payload = joined(spawn_call(&d, secret_args(&s.id, 2)), "the timing-out call").await;
    assert_eq!(cancelled_reason(&payload), "timeout");
    assert_eq!(payload["data"]["request_id"], first_id);

    let (closed_id, outcome) = next_secret_closed(&mut c, 20).await;
    assert_eq!(closed_id, first_id);
    assert_eq!(outcome, "timeout", "§7.5's third outcome");

    // A **fresh** request, with a fresh id — sequential, never
    // concurrent — and the human can still answer it.
    let (again_id, _) = next_awaiting_secret(&mut c, 20).await;
    assert_ne!(
        again_id, first_id,
        "the re-raise reused the id of a request it had just closed"
    );
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: again_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut c, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the re-raised request could not be answered: {}",
        String::from_utf8_lossy(&seen)
    );
    let _ = s.signal(Signal::Kill);

    // The pairing: a child that is **not** at an echo-off prompt. Its
    // timeout closes the request and raises nothing.
    let plain = d.shell_running("cat");
    let mut pc = attach_ok(&d, &plain.id, AttachMode::ReadWrite).await;
    let call = spawn_call(&d, secret_args(&plain.id, 2));
    let (raised_id, _) = next_awaiting_secret(&mut pc, 20).await;
    assert_eq!(
        cancelled_reason(&joined(call, "the plain call").await),
        "timeout"
    );
    let (plain_closed, _) = next_secret_closed(&mut pc, 20).await;
    assert_eq!(plain_closed, raised_id);
    let quiet = tokio::time::timeout(Duration::from_millis(500), recv(&mut pc)).await;
    if let Ok(ServerFrame::AwaitingSecret { request_id, .. }) = quiet {
        panic!("a session that is not awaiting a secret was handed one anyway: {request_id}");
    }
    let _ = plain.signal(Signal::Kill);
}

// ------------------------------------------------------ §9.4's two kinds

/// Both entries, per call, in order.
#[tokio::test]
async fn a_completed_call_writes_exactly_one_request_and_one_resolved_line() {
    let d = TestDaemon::start("auditpair").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call").await;
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: request_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(joined(call, "the call").await["status"], "secret_provided");

    assert_eq!(
        secret_audit_kinds(&d, &s.id),
        vec![
            "secret_input_request".to_string(),
            "secret_input_resolved".to_string()
        ],
        "the resolved line was written on the raise, so the trail carries a \
         resolution for a request that had not resolved"
    );
    let req = audit_entries(&d, &s.id, "secret_input_request");
    let res = audit_entries(&d, &s.id, "secret_input_resolved");
    assert_eq!(req.len(), 1);
    assert_eq!(res.len(), 1);
    assert_eq!(req[0]["request_id"], request_id);
    assert_eq!(
        res[0]["request_id"], request_id,
        "the two lines describe different requests"
    );
    let _ = s.signal(Signal::Kill);
}

/// §5.2: *"A raised request that no call ever adopts produces **no**
/// `secret_input_request` entry."*
///
/// **The pairing is what stops this being an assertion about an empty
/// file.** In the same run, on the same daemon and the same log, a
/// completed call on a second session writes one of each — so an audit
/// path that was never wired up at all fails here rather than passing the
/// zero-assertion perfectly.
#[tokio::test]
async fn an_unadopted_raise_writes_no_audit_line_at_all() {
    let d = TestDaemon::start("unadopted").await;

    // A human answers an echo-drop raise with no tool call anywhere.
    let lone = d.shell_running(ECHO_OFF_FIXTURE);
    let mut lc = attach_ok(&d, &lone.id, AttachMode::ReadWrite).await;
    let (raised_id, _) = next_awaiting_secret(&mut lc, 20).await;
    send(
        &mut lc,
        &ClientFrame::SecretInput {
            request_id: raised_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut lc, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the human's submission never landed, so this row asserts nothing: {}",
        String::from_utf8_lossy(&seen)
    );

    // The pairing, on the same log.
    let called = d.shell_running(ECHO_OFF_FIXTURE);
    let mut cc = attach_ok(&d, &called.id, AttachMode::ReadWrite).await;
    let (call_id, _) = next_awaiting_secret(&mut cc, 20).await;
    let call = spawn_call(&d, secret_args(&called.id, 20));
    await_waiter(&d, &called.id, "the call").await;
    send(
        &mut cc,
        &ClientFrame::SecretInput {
            request_id: call_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(joined(call, "the call").await["status"], "secret_provided");

    assert_eq!(
        secret_audit_kinds(&d, &called.id).len(),
        2,
        "the audit path is not wired up at all, which passes the zero-assertion \
         below perfectly"
    );
    assert!(
        secret_audit_kinds(&d, &lone.id).is_empty(),
        "the entries are written per raise instead of per call: {:?}",
        secret_audit_kinds(&d, &lone.id)
    );

    let _ = lone.signal(Signal::Kill);
    let _ = called.signal(Signal::Kill);
}

/// **Both directions in one test**, because a constant passes whichever
/// single direction is asserted.
#[tokio::test]
async fn raised_by_distinguishes_adoption_from_a_cold_call() {
    let d = TestDaemon::start("raisedby").await;

    // Adopted: the echo drop raised it, so the request is `echo_drop`
    // however the call arrived.
    let adopted = d.shell_running(ECHO_OFF_FIXTURE);
    let mut ac = attach_ok(&d, &adopted.id, AttachMode::ReadWrite).await;
    let (adopted_id, _) = next_awaiting_secret(&mut ac, 20).await;
    let call = spawn_call(&d, secret_args(&adopted.id, 20));
    await_waiter(&d, &adopted.id, "the adopting call").await;
    send(
        &mut ac,
        &ClientFrame::SecretInput {
            request_id: adopted_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        joined(call, "the adopting call").await["status"],
        "secret_provided"
    );

    // Cold: a session that never dropped echo, so the call raised it.
    let cold = d.shell_running("cat");
    let cold_payload = joined(spawn_call(&d, secret_args(&cold.id, 2)), "the cold call").await;
    assert_eq!(cold_payload["status"], "secret_cancelled");

    assert_eq!(
        audit_entries(&d, &adopted.id, "secret_input_request")[0]["raised_by"],
        "echo_drop",
        "an adopting call reported itself as the raiser"
    );
    assert_eq!(
        audit_entries(&d, &cold.id, "secret_input_request")[0]["raised_by"],
        "tool_call",
        "§5.2's mismatch record: a call that raised the slot is by construction a \
         call that arrived with no echo-drop raise outstanding"
    );

    let _ = adopted.signal(Signal::Kill);
    let _ = cold.signal(Signal::Kill);
}

/// Absent, not `0` and not `null` — an operator reading `0` cannot tell
/// it from a zero-length secret.
#[tokio::test]
async fn bytes_written_is_present_only_on_secret_provided() {
    let d = TestDaemon::start("byteswritten").await;

    let timed_out = d.shell_running("cat");
    assert_eq!(
        cancelled_reason(
            &joined(
                spawn_call(&d, secret_args(&timed_out.id, 2)),
                "the timing-out call"
            )
            .await
        ),
        "timeout"
    );

    // The pairing: a resolution that *does* carry it.
    let provided = d.shell_running(ECHO_OFF_FIXTURE);
    let mut pc = attach_ok(&d, &provided.id, AttachMode::ReadWrite).await;
    let (id, _) = next_awaiting_secret(&mut pc, 20).await;
    let call = spawn_call(&d, secret_args(&provided.id, 20));
    await_waiter(&d, &provided.id, "the call").await;
    send(
        &mut pc,
        &ClientFrame::SecretInput {
            request_id: id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(joined(call, "the call").await["status"], "secret_provided");

    let cancelled = &audit_entries(&d, &timed_out.id, "secret_input_resolved")[0];
    assert_eq!(cancelled["outcome"], "timeout");
    assert!(
        cancelled.get("bytes_written").is_none(),
        "a cancelled resolution carried a byte count: {cancelled}"
    );
    let ok = &audit_entries(&d, &provided.id, "secret_input_resolved")[0];
    assert_eq!(
        ok["outcome"], "secret_provided",
        "§9.4's outcome is the **tool status**, not §7.5's frame outcome"
    );
    assert_eq!(
        ok["bytes_written"],
        (PROBE.len() + 1) as u64,
        "the count is missing from the one resolution that must carry it"
    );

    let _ = timed_out.signal(Signal::Kill);
    let _ = provided.signal(Signal::Kill);
}

/// The **effective** values, after defaults are applied.
///
/// **Both halves**, because the omitted-argument case alone cannot tell a
/// resolved default from a hardcoded `120`.
#[tokio::test]
async fn the_effective_timeout_is_logged_not_the_argument() {
    let d = TestDaemon::start("effective").await;

    // Omitted: the call must still resolve fast, so a human answers it.
    let defaulted = d.shell_running(ECHO_OFF_FIXTURE);
    let mut dc = attach_ok(&d, &defaulted.id, AttachMode::ReadWrite).await;
    let (default_id, _) = next_awaiting_secret(&mut dc, 20).await;
    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            session: defaulted.id.clone(),
            prompt_text: "a credential".into(),
            ..Default::default()
        },
    );
    await_waiter(&d, &defaulted.id, "the defaulted call").await;
    send(
        &mut dc,
        &ClientFrame::SecretInput {
            request_id: default_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        joined(call, "the defaulted call").await["status"],
        "secret_provided"
    );

    // Stated, and deliberately not the default.
    let stated = d.shell_running(ECHO_OFF_FIXTURE);
    let mut sc = attach_ok(&d, &stated.id, AttachMode::ReadWrite).await;
    let (stated_id, _) = next_awaiting_secret(&mut sc, 20).await;
    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            max_secret_bytes: Some(64),
            ..secret_args(&stated.id, 30)
        },
    );
    await_waiter(&d, &stated.id, "the stated call").await;
    send(
        &mut sc,
        &ClientFrame::SecretInput {
            request_id: stated_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        joined(call, "the stated call").await["status"],
        "secret_provided"
    );

    let defaulted_line = &audit_entries(&d, &defaulted.id, "secret_input_request")[0];
    assert_eq!(
        defaulted_line["timeout_secs"], 120,
        "the raw Option was recorded, so the most common call shape logs `null`"
    );
    assert_eq!(defaulted_line["max_secret_bytes"], 4096);
    let stated_line = &audit_entries(&d, &stated.id, "secret_input_request")[0];
    assert_eq!(
        stated_line["timeout_secs"], 30,
        "a hardcoded default, which the omitted-argument half alone cannot see"
    );
    assert_eq!(stated_line["max_secret_bytes"], 64);

    let _ = defaulted.signal(Signal::Kill);
    let _ = stated.signal(Signal::Kill);
}

/// `concurrent_request_pending` exists in the audit vocabulary and in no
/// frame vocabulary, which is why the two must not be unified.
#[tokio::test]
async fn a_collision_logs_concurrent_request_pending_and_no_frame() {
    let d = TestDaemon::start("collisionaudit").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let first = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the first call").await;
    let second = body(&d.call(secret_args(&s.id, 20)).await);
    assert_eq!(second["data"]["reason"], "concurrent_request_pending");

    // **No `SecretRequestClosed` for the collision.** Checked while the
    // first caller's request is still open, so any frame arriving here is
    // the collision's.
    let quiet = tokio::time::timeout(Duration::from_millis(500), recv(&mut c)).await;
    if let Ok(ServerFrame::SecretRequestClosed {
        request_id,
        outcome,
        ..
    }) = quiet
    {
        panic!("the collision closed a request on the wire: {request_id} / {outcome}");
    }

    let resolved = audit_entries(&d, &s.id, "secret_input_resolved");
    assert_eq!(
        resolved.len(),
        1,
        "the collision wrote no resolution, or wrote somebody else's"
    );
    assert_eq!(resolved[0]["outcome"], "concurrent_request_pending");
    assert_eq!(
        resolved[0]["request_id"], request_id,
        "§9.4 binds a colliding call to the request it collided with"
    );
    // Two calls, two request lines — per call, not per request.
    assert_eq!(audit_entries(&d, &s.id, "secret_input_request").len(), 2);

    // And the first caller still completes.
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        joined(first, "the first call").await["status"],
        "secret_provided"
    );
    let _ = s.signal(Signal::Kill);
}

// ------------------------------------------------------- prompt_text

/// A GitHub PAT, 40 characters, matching `\bgh[pousr]_[0-9A-Za-z]{36,}`
/// — the `github-token` rule of the shipped default rule set, whose
/// `kind` is `github`.
const SHAPED_TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

/// §9.5, §9.2, REQ-SEC-005.
///
/// `AuditLog::record` redacts every string it is handed, so this is
/// automatic — and it is asserted end to end **anyway**, because
/// "automatic" is a claim about a function this task does not own, and
/// because building the line by concatenation outside `record` would walk
/// straight past it.
#[tokio::test]
async fn a_secret_shaped_prompt_text_is_redacted_in_the_audit_log() {
    let d = TestDaemon::start("promptaudit").await;
    let s = d.shell_running("cat");
    let payload = joined(
        spawn_call(
            &d,
            RequestSecretInputArgs {
                prompt_text: format!("key is {SHAPED_TOKEN}"),
                ..secret_args(&s.id, 2)
            },
        ),
        "the shaped-prompt call",
    )
    .await;
    assert_eq!(cancelled_reason(&payload), "timeout");

    let line = &audit_entries(&d, &s.id, "secret_input_request")[0];
    assert_eq!(
        line["prompt_text"], "key is [REDACTED:github]",
        "the field was written before it reached the redactor"
    );
    let whole = std::fs::read_to_string(d.paths.audit_log()).expect("the audit log");
    assert!(
        !whole.contains(SHAPED_TOKEN),
        "the token survived somewhere else in the trail:\n{whole}"
    );
    let _ = s.signal(Signal::Kill);
}

/// **The pairing**, and it is the half that keeps the field useful: a
/// redactor applied so broadly that `prompt_text` becomes unreadable
/// means an operator cannot see what an agent asked for, which is the
/// reason §9.5 logs it at all.
#[tokio::test]
async fn a_plain_english_prompt_text_survives_the_redactor_intact() {
    let d = TestDaemon::start("promptplain").await;
    let s = d.shell_running("cat");
    let payload = joined(
        spawn_call(
            &d,
            RequestSecretInputArgs {
                prompt_text: "sudo password for deploy-user".into(),
                ..secret_args(&s.id, 2)
            },
        ),
        "the plain-prompt call",
    )
    .await;
    assert_eq!(cancelled_reason(&payload), "timeout");

    assert_eq!(
        audit_entries(&d, &s.id, "secret_input_request")[0]["prompt_text"],
        "sudo password for deploy-user"
    );
    let _ = s.signal(Signal::Kill);
}

/// §9.2's table names only the audit surface; redacting the broadcast as
/// well costs one call, keeps one rule for the string, and stops a human
/// being shown a secret-shaped value in the modal they are about to type
/// into. It cannot affect REQ-SEC-010a's byte-identity assertion, because
/// both sides of that comparison are post-redaction.
#[tokio::test]
async fn the_broadcast_prompt_text_is_redacted() {
    let d = TestDaemon::start("promptcast").await;

    // `cat`, so the slot is vacant and this call is the one that raises —
    // only a raising call broadcasts its own text.
    let shaped = d.shell_running("cat");
    let mut sc = attach_ok(&d, &shaped.id, AttachMode::ReadWrite).await;
    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            prompt_text: format!("paste {SHAPED_TOKEN} here"),
            ..secret_args(&shaped.id, 3)
        },
    );
    let (_, prompt) = next_awaiting_secret(&mut sc, 20).await;
    assert_eq!(
        prompt, "paste [REDACTED:github] here",
        "the token was broadcast to every attached client"
    );
    assert_eq!(
        cancelled_reason(&joined(call, "the shaped call").await),
        "timeout"
    );

    // The pairing: a prompt with nothing secret-shaped in it arrives
    // verbatim, so this row cannot pass against a broadcast that redacts
    // everything to a constant.
    let plain = d.shell_running("cat");
    let mut pc = attach_ok(&d, &plain.id, AttachMode::ReadWrite).await;
    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            prompt_text: "the deploy user's sudo password".into(),
            ..secret_args(&plain.id, 3)
        },
    );
    let (_, plain_prompt) = next_awaiting_secret(&mut pc, 20).await;
    assert_eq!(plain_prompt, "the deploy user's sudo password");
    assert_eq!(
        cancelled_reason(&joined(call, "the plain call").await),
        "timeout"
    );

    let _ = shaped.signal(Signal::Kill);
    let _ = plain.signal(Signal::Kill);
}

/// REQ-SEC-010a, the exact split — **and two opposite mutations, both
/// killed by this one test**, which is why it asserts both fields in one
/// run: logging the raised text means an operator can no longer see what
/// the agent asked for, and broadcasting the agent's means a human sees
/// the prompt change under their cursor.
///
/// The broadcast half is read at a client that attaches **after** the
/// adoption. A client that was already there holds the original frame and
/// could not see a replacement; the late attacher's replay can.
#[tokio::test]
async fn an_adopting_calls_prompt_text_is_logged_and_not_broadcast() {
    let d = TestDaemon::start("adoptsplit").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut first = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (raised_id, raised_prompt) = next_awaiting_secret(&mut first, 20).await;

    let call = spawn_call(
        &d,
        RequestSecretInputArgs {
            prompt_text: "AGENT SUPPLIED LABEL".into(),
            ..secret_args(&s.id, 20)
        },
    );
    await_waiter(&d, &s.id, "the adopting call").await;

    let mut late = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    let (replayed_id, replayed_prompt) = next_awaiting_secret(&mut late, 20).await;
    assert_eq!(replayed_id, raised_id);
    assert_eq!(
        replayed_prompt, raised_prompt,
        "the adopting call replaced the prompt a human may already be typing into"
    );
    assert_ne!(
        replayed_prompt, "AGENT SUPPLIED LABEL",
        "the agent relabelled a request it did not raise"
    );

    send(
        &mut first,
        &ClientFrame::SecretInput {
            request_id: raised_id.clone(),
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(
        joined(call, "the adopting call").await["status"],
        "secret_provided"
    );

    let logged = &audit_entries(&d, &s.id, "secret_input_request")[0];
    assert_eq!(
        logged["request_id"], raised_id,
        "the entry names a request the adopting call did not adopt"
    );
    assert_eq!(
        logged["prompt_text"], "AGENT SUPPLIED LABEL",
        "the raised text was logged, so an operator cannot see what the agent asked for"
    );
    assert_ne!(
        logged["prompt_text"], replayed_prompt,
        "the two surfaces carry the same string, so one of the two rules is not \
         being applied"
    );
    let _ = s.signal(Signal::Kill);
}

/// §9.5 says **bytes**. A `chars().count()` cap admits 512 three-byte
/// code points — 1536 bytes — into a field broadcast to every attached
/// client and written to the audit log.
///
/// Task 3 pins this against the schema; this pins it against a real call,
/// which is where a cap could be re-decided in a second place.
#[tokio::test]
async fn the_512_cap_is_bytes_not_characters() {
    let d = TestDaemon::start("promptcap").await;
    let s = d.shell_running("cat");

    // 171 three-byte code points: 513 bytes, 171 characters. A character
    // cap waves it through.
    let wide = "\u{4f60}".repeat(171);
    assert_eq!(wide.len(), 513);
    assert_eq!(wide.chars().count(), 171);
    let refused = d
        .try_call(RequestSecretInputArgs {
            prompt_text: wide,
            ..secret_args(&s.id, 2)
        })
        .await
        .expect_err("513 bytes must be refused whole, not truncated");
    assert!(
        refused.contains("513") && refused.contains("512"),
        "the refusal does not name the bound it applied: {refused}"
    );

    // **The pairing**, one byte under, and it must get past the cap: a
    // rejection of everything passes the half above perfectly. It goes on
    // to raise, so the audit line proves it was not merely a different
    // error.
    let ok = joined(
        spawn_call(
            &d,
            RequestSecretInputArgs {
                prompt_text: "a".repeat(512),
                ..secret_args(&s.id, 2)
            },
        ),
        "the 512-byte call",
    )
    .await;
    assert_eq!(cancelled_reason(&ok), "timeout");
    assert_eq!(
        audit_entries(&d, &s.id, "secret_input_request")[0]["prompt_text"],
        "a".repeat(512),
        "the accepted prompt was truncated somewhere; §18.5 refuses a body whole \
         rather than clipping it, and nothing here truncates"
    );
    let _ = s.signal(Signal::Kill);
}

// -------------------------------------------- §9.5's buffer notice

/// A child at a `sudo`-shaped prompt, so the row about the detector has
/// something recognisable to assert `prompt.last_line` against.
const SUDO_PROMPT_FIXTURE: &str = "stty -echo; printf '[sudo] password for ada: '; \
     read x; stty echo; printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"";

/// Everything this session's buffer holds right now, raw.
///
/// Raw, and not through `read_output`: that surface redacts, and a
/// redacted read would pass whether or not the bytes were there.
fn buffered(s: &Session) -> Vec<u8> {
    s.buffer_slice(s.buffer_tail(), s.buffer_head())
}

fn notice_count(s: &Session) -> usize {
    let buf = buffered(s);
    buf.windows(b"[holdfast]".len())
        .filter(|w| *w == b"[holdfast]")
        .count()
}

/// The id is the actionable half — a notice that names the session by an
/// internal index, or omits it, tells a human nothing they can act on.
#[tokio::test]
async fn the_notice_appears_in_the_buffer_when_nobody_is_attached() {
    let d = TestDaemon::start("notice").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    assert_eq!(
        cancelled_reason(&joined(spawn_call(&d, secret_args(&s.id, 2)), "the call").await),
        "timeout"
    );

    let buf = buffered(&s);
    let want = holdfast_core::secret::buffer_notice(&s.id);
    assert!(
        contains(&buf, &want),
        "the notice is not in the buffer, or not byte-for-byte §5.2's line \
         with this session's own id in it:\n{}",
        String::from_utf8_lossy(&buf)
    );
    assert!(
        contains(&buf, s.id.as_bytes()) && s.id.starts_with("sess_"),
        "the canonical session id is what `holdfast attach` takes"
    );
    let _ = s.signal(Signal::Kill);
}

/// **The pairing.** Written unconditionally, it puts Holdfast's chatter
/// into every ordinary secret flow — including the one where a human is
/// already looking at the prompt.
#[tokio::test]
async fn no_notice_is_written_when_a_client_is_already_attached() {
    let d = TestDaemon::start("noticeattached").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let _ = next_awaiting_secret(&mut c, 20).await;

    assert_eq!(
        cancelled_reason(&joined(spawn_call(&d, secret_args(&s.id, 2)), "the call").await),
        "timeout"
    );
    assert_eq!(
        notice_count(&s),
        0,
        "a notice was written while somebody was watching:\n{}",
        String::from_utf8_lossy(&buffered(&s))
    );
    let _ = s.signal(Signal::Kill);
}

/// §9.5 says the **output buffer**. Written through the PTY path instead,
/// against a child that is at that moment reading a secret, it submits
/// `[holdfast] awaiting secret input…` **as the secret**.
///
/// **The digest is the only observable that separates the two.** The
/// obvious form of this row — "assert the buffer holds no second copy of
/// the notice" — cannot fail: the correct implementation puts one copy
/// there by injection, and the broken one puts one there (or none, under
/// `stty -echo`) by the child. So the child's own transform of what it
/// read is the assertion.
#[tokio::test]
async fn the_notice_does_not_reach_the_child() {
    let d = TestDaemon::start("noticechild").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    // Nothing attached, so the notice is written; the call then times out
    // with the child still blocked on its read.
    assert_eq!(
        cancelled_reason(&joined(spawn_call(&d, secret_args(&s.id, 2)), "the call").await),
        "timeout"
    );
    assert_eq!(notice_count(&s), 1, "the notice was not written at all");

    // Now answer the re-raised request for real, and read what the child
    // says it got.
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (again_id, _) = next_awaiting_secret(&mut c, 20).await;
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id: again_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let seen = stream_until(&mut c, b"got=HUNTER2", 20).await;
    assert!(
        contains(&seen, b"got=HUNTER2"),
        "the child read something other than the submitted value: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !contains(&seen, b"got=[HOLDFAST]"),
        "the notice was typed into the child as its secret"
    );
    let _ = s.signal(Signal::Kill);
}

/// The notice must not become the session's last logical line. That line
/// is what a keychain binding's `match_prompt` matches against (Task 10),
/// what `status` reports, and what a later `AwaitingSecret` broadcasts —
/// so a notice that changes it silently disables an operator's
/// configuration.
#[tokio::test]
async fn the_notice_does_not_change_the_prompt_the_detector_reports() {
    let d = TestDaemon::start("noticeprompt").await;
    let s = d.shell_running(SUDO_PROMPT_FIXTURE);

    // Wait for the child's prompt to reach the detector before measuring,
    // or this row compares two empty strings.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !s
        .prompt_last_line_redacted()
        .ends_with("password for ada: ")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the detector never saw the prompt: {:?}",
            s.prompt_last_line_redacted()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let before = s.prompt_last_line_redacted();

    assert_eq!(
        cancelled_reason(&joined(spawn_call(&d, secret_args(&s.id, 2)), "the call").await),
        "timeout"
    );
    assert_eq!(notice_count(&s), 1, "the notice was not written at all");
    assert_eq!(
        s.prompt_last_line_redacted(),
        before,
        "the notice was fed to the detector and became the prompt a binding matches"
    );
    let _ = s.signal(Signal::Kill);
}

/// REQ-S-006: Holdfast's own text is not a ReadWrite input or output
/// event. A session that keeps itself alive by announcing that it is
/// stuck is a session that never reaps.
#[tokio::test]
async fn the_notice_does_not_extend_the_idle_deadline() {
    let d = TestDaemon::start("noticeidle").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    // Let the child go quiet first, so the stamp under test is not being
    // moved by its own output.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = (s.last_activity_ms(), s.idle_deadline_ms());

    assert_eq!(
        cancelled_reason(&joined(spawn_call(&d, secret_args(&s.id, 2)), "the call").await),
        "timeout"
    );
    assert_eq!(notice_count(&s), 1, "the notice was not written at all");
    assert_eq!(
        (s.last_activity_ms(), s.idle_deadline_ms()),
        before,
        "the notice bumped activity, which makes a stuck session immortal"
    );
    let _ = s.signal(Signal::Kill);
}

/// One notice per **request**, and a second request gets its own.
///
/// **The second half is not optional**: a counter hoisted to the session
/// would leave a re-raised request silently unannounced, and "one notice
/// for two sequential calls" would contradict the re-raise rule under
/// which the second call adopts a *different* request.
#[tokio::test]
async fn only_one_notice_is_written_per_request() {
    let d = TestDaemon::start("noticeonce").await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);

    // A raises with nothing attached and begins waiting.
    let a = spawn_call(&d, secret_args(&s.id, 3));
    await_waiter(&d, &s.id, "caller A").await;
    assert_eq!(notice_count(&s), 1, "A's request was not announced");

    // B collides while A is still waiting.
    let b = body(&d.call(secret_args(&s.id, 3)).await);
    assert_eq!(b["data"]["reason"], "concurrent_request_pending");
    assert_eq!(
        notice_count(&s),
        1,
        "the collision put a second identical line into the buffer the agent \
         reads back:\n{}",
        String::from_utf8_lossy(&buffered(&s))
    );

    // A's deadline expires, which re-raises a **fresh** request; C adopts
    // that one, and a second notice is correct.
    assert_eq!(cancelled_reason(&joined(a, "caller A").await), "timeout");
    let c = spawn_call(&d, secret_args(&s.id, 3));
    await_waiter(&d, &s.id, "caller C").await;
    assert_eq!(
        notice_count(&s),
        2,
        "the re-raised request was left silently unannounced — a counter hoisted \
         to the session rather than kept on the request:\n{}",
        String::from_utf8_lossy(&buffered(&s))
    );
    assert_eq!(cancelled_reason(&joined(c, "caller C").await), "timeout");
    let _ = s.signal(Signal::Kill);
}

// -------------------------------------------- not_supported_on_platform

/// §5.2: *"On Windows native, `request_secret_input` returns
/// `not_supported_on_platform` **before allocating a `request_id`**."*
///
/// **The two negative assertions are the ones that catch a check placed
/// after the raise; the status alone does not.** A prompt broadcast to a
/// human on a platform that cannot answer it is the harm, and it is
/// invisible to any assertion about the agent's response.
#[tokio::test]
async fn an_unsupported_platform_returns_before_allocating_anything() {
    let d = TestDaemon::start_unsupported("unsupported").await;
    // `cat` and **not** the echo-off fixture, which would confound this
    // measurement rather than strengthen it: an attached client raises a
    // request off the echo drop all on its own (§8.3), so an outstanding
    // request would prove nothing about the tool. With echo on, anything
    // in the slot could only have been put there by the call.
    let s = d.shell_running("cat");
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    let r = d.call(secret_args(&s.id, 20)).await;
    assert_eq!(body(&r)["status"], "not_supported_on_platform");
    assert_eq!(
        r.is_error,
        Some(true),
        "§18.1 puts this status in the error column"
    );

    // Nothing was raised, so nothing could have been broadcast — which is
    // §5.2's "before allocating a `request_id`" asserted directly.
    assert!(
        d.daemon
            .server
            .attach_hub()
            .outstanding_secret(&s.id)
            .is_none(),
        "a request_id was allocated on a platform that cannot answer it"
    );
    let quiet = tokio::time::timeout(Duration::from_millis(500), recv(&mut c)).await;
    if let Ok(ServerFrame::AwaitingSecret { request_id, .. }) = quiet {
        panic!("a human was shown a prompt nobody can answer: {request_id}");
    }
    assert!(
        audit_entries(&d, &s.id, "secret_input_request").is_empty(),
        "an entry was written for a request that was never raised"
    );
    // The pairing that stops the line above being an assertion about an
    // empty file: this daemon's trail is live and has other kinds in it.
    let whole = std::fs::read_to_string(d.paths.audit_log()).unwrap_or_default();
    assert!(
        whole.contains("attach_connect"),
        "the audit log is disabled, so the absence assertion above is vacuous:\n{whole}"
    );
    let _ = s.signal(Signal::Kill);
}

/// Ordering the checks the other way tells an agent its platform is the
/// problem when its argument was.
#[tokio::test]
async fn session_not_found_still_outranks_the_capability_check() {
    let d = TestDaemon::start_unsupported("unsupportedbadid").await;
    assert_eq!(
        body(&d.call(secret_args("sess_nosuchsession", 20)).await)["status"],
        "session_not_found"
    );

    // The pairing: with a *real* session on the same daemon, the same
    // call does report the platform — so the row above is about ordering
    // and not about the capability being ignored.
    let s = d.shell_running("cat");
    assert_eq!(
        body(&d.call(secret_args(&s.id, 20)).await)["status"],
        "not_supported_on_platform"
    );
    let _ = s.signal(Signal::Kill);
}

/// **The pairing for the whole group.** A check inverted or stuck on
/// makes every row above pass and the tool useless.
#[tokio::test]
async fn the_tool_works_when_the_capability_is_present() {
    let d = TestDaemon::start("supported").await;
    assert!(
        Capabilities::default().out_of_band_secret_input,
        "this test asserts the default is on; on a platform where it is not, \
         it would be asserting the same thing as the rows above"
    );
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    let (request_id, _) = next_awaiting_secret(&mut c, 20).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    await_waiter(&d, &s.id, "the call").await;
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    assert_eq!(joined(call, "the call").await["status"], "secret_provided");
    let _ = s.signal(Signal::Kill);
}

// ============================================================ §9.6's five
//
// **Only the argv row is here, and the rest moved into the library.**
// Review I-2: `resolve_with(&dyn SecretProvider, &str, …)` and
// `ScriptProvider::new(name, path)` are between them a signature meaning
// *"spawn this program with this argument as a secret provider"*, inside
// the one module whose premise (REQ-SEC-012's structural half) is that no
// such signature exists — and `holdfast-core` has no `publish = false`.
// They are `pub(crate)` now, which an integration target cannot see, so
// every row that injects a script fixture lives in
// `secret::provider`'s own `#[cfg(test)] mod tests`. That is the price of
// the narrowing and it is the right way round: the seam is reachable from
// exactly one crate and the published API is `resolve(&SecretBinding, …)`
// alone.
//
// The row below stays because it **executes nothing** — it needs only
// `ArgvProvider`, the `SecretProvider` trait and the public `resolve`,
// none of which can start a process on their own.
//
// **No test anywhere runs a credential store, and none can be made to.**
// REQ-TST-007 / Global Constraint 12: `secret-tool`, `security`, `pass`
// and `op` are tools this project neither pins nor installs, and none is
// present on a runner.

/// `[security]` with one knob moved. Built in Rust rather than from a
/// TOML fixture on purpose: `keychain_provider_timeout_secs` has no
/// §10.2 line to copy (it is one of 0.0.7's three additive keys, Q4), and
/// `config.rs`'s own default-fold test already pins that it loads and
/// defaults to 10.
fn provider_limits(secs: u32) -> SecurityConfig {
    SecurityConfig {
        keychain_provider_timeout_secs: secs,
        ..SecurityConfig::default()
    }
}

/// §9.6's own example reference, and the one both attribute-addressed
/// templates are pinned against.
const ATTR_REFERENCE: &str = "service=holdfast,account=prod-ssh";

/// **Four exact vectors, executing nothing.**
///
/// `wincred` is the fifth and has no argv to compare: Windows Credential
/// Manager is a `CredReadW` call rather than a program, and its body is
/// 0.0.11's. It is asserted here as *refused*, which is the only claim
/// this milestone can make about it honestly.
///
/// The `-w` on `security` is the reason this row pins the argv exactly
/// rather than checking that it starts with `security`: without it,
/// `find-generic-password` prints the item's **metadata** instead of the
/// password. That is a resolution that succeeds, injects the wrong bytes
/// and looks correct in every log — and no behavioural test on Linux
/// could ever see it.
#[test]
fn each_provider_builds_the_argv_the_plan_pins() {
    assert_eq!(
        ArgvProvider::SecretService.argv(ATTR_REFERENCE).unwrap(),
        vec![
            "secret-tool",
            "lookup",
            "service",
            "holdfast",
            "account",
            "prod-ssh"
        ],
        "the secret-tool template"
    );
    assert_eq!(
        ArgvProvider::Keychain.argv(ATTR_REFERENCE).unwrap(),
        vec![
            "security",
            "find-generic-password",
            "-s",
            "holdfast",
            "-a",
            "prod-ssh",
            "-w"
        ],
        "the security template — note the trailing -w"
    );
    assert_eq!(
        ArgvProvider::Pass.argv("work/db").unwrap(),
        vec!["pass", "show", "work/db"],
        "the pass template"
    );
    assert_eq!(
        ArgvProvider::OnePassword.argv("op://v/i/f").unwrap(),
        vec!["op", "read", "op://v/i/f"],
        "the op template"
    );

    // The fifth, and the two negatives that stop the four above from
    // being satisfied by a builder that accepts anything.
    assert_eq!(
        ArgvProvider::WinCred.argv(ATTR_REFERENCE),
        Err(ProviderError::NotImplemented {
            provider: "wincred".to_string()
        }),
        "wincred has no argv in this build and must say so rather than \
         resolving nothing quietly"
    );
    assert_eq!(
        ArgvProvider::Keychain.argv("work/db"),
        Err(ProviderError::MalformedReference {
            provider: "keychain".to_string()
        }),
        "a path-shaped reference is not two keychain attributes"
    );

    // And the config spellings, which are what `binding_resolved` and
    // `BindingApprovalRequired` put on the wire — a re-spelling here is a
    // re-spelling in an audit log and in an approval dialog.
    assert_eq!(
        ArgvProvider::ALL.map(|p| p.as_str()),
        [
            "secret-service",
            "keychain",
            "pass",
            "onepassword",
            "wincred"
        ]
    );

    // The binding-shaped entry point, driven only where it cannot reach a
    // spawn: a `resolve` naming a real provider would run whatever is
    // installed on the runner, which Global Constraint 12 forbids.
    let unknown = SecretBinding {
        name: "deploy".into(),
        match_command: "ssh *".into(),
        match_prompt: "password:".into(),
        provider: "1password".into(),
        reference: "op://v/i/f".into(),
        max_uses: None,
        require_confirm: false,
    };
    // `SecretBytes` has no `PartialEq` — and must not gain one, which is
    // why this compares the error rather than the `Result`.
    let refused = resolve(&unknown, &provider_limits(10), true)
        .expect_err("a near-miss spelling must not resolve");
    assert_eq!(
        refused,
        ProviderError::UnknownProvider("1password".to_string()),
        "the config spelling is `onepassword`, and a near miss must be a \
         refusal rather than a silent fall-through"
    );
}

// ======================================================= §9.6's bindings
//
// **Only the rows that execute nothing are here**, for the reason the
// provider block above gives: `ScriptProvider` is `#[cfg(test)]` and
// `resolve_with` is `pub(crate)` (review I-2), so every behavioural row —
// the ones that need a provider to actually run, and therefore a script
// the test itself wrote (REQ-TST-007) — lives in `secret::binding`'s own
// `#[cfg(test)] mod tests`. What is left here is the operator-facing
// half: the block as §9.6 publishes it, loaded rather than read by eye,
// driven through the public matcher.

/// §9.6's `[[security.secret_bindings]]` block and §10.2's
/// `secret_provider` line, **copied from the current spec text** and
/// loaded as a `Config` before anything is asserted about it (Global
/// Constraint 15).
///
/// §10.2 is *"the most copied block in the document and the least
/// swept"*, and rev. 49 makes an unknown key a load error — so a
/// remembered fixture no longer merely drifts from the document, it fails
/// to parse, and the failure looks like a bug in whatever the row was
/// about. This one is parsed first and asserted second.
const SPEC_BINDING_BLOCK: &str = r#"
[security]
secret_provider = "prompt"

[[security.secret_bindings]]
name            = "prod-ssh"
match_command   = "^ssh\\s+(\\S+@)?prod-0[12]\\b"
match_prompt    = "(?i)password"
provider        = "secret-service"
reference       = "service=holdfast,account=prod-ssh"
max_uses        = 20
require_confirm = false
"#;

/// The block an operator actually writes, selecting the session it names
/// and no other — through the **public** surface of `secret::binding`.
///
/// Nothing here runs a provider. `provider = "secret-service"` is matched
/// and never executed, which is what lets this row run on a machine with
/// no credential store (Global Constraint 12).
#[test]
fn the_published_binding_block_loads_and_selects_the_session_it_names() {
    let cfg = holdfast_core::config::parse_str(SPEC_BINDING_BLOCK)
        .expect("§9.6's published binding block must load as a Config");
    let bindings = &cfg.security.secret_bindings;
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].name, "prod-ssh");
    assert_eq!(bindings[0].max_uses, Some(20));

    // **The published example leaves §5.2's step 1 off**, and that is the
    // shipped posture rather than an oversight: `secret_provider` is
    // `prompt`, so no binding in this file is ever probed and no provider
    // subprocess is ever spawned.
    assert!(
        !keychain_step_runs(&cfg.security.secret_provider),
        "the published example now enables the credential store by default"
    );

    // The same file with that one key moved — the only difference — does
    // probe. Without this pairing the assertion above is satisfied by a
    // `keychain_step_runs` that answers `false` to everything.
    let enabled = holdfast_core::config::parse_str(&SPEC_BINDING_BLOCK.replace(
        r#"secret_provider = "prompt""#,
        r#"secret_provider = "both""#,
    ))
    .expect("the same block in `both` mode must load too");
    assert!(keychain_step_runs(&enabled.security.secret_provider));

    // The session §9.6's own pattern is written for.
    let named = command_line("ssh", &["user@prod-01".to_string()]);
    assert_eq!(named, "ssh user@prod-01");
    assert_eq!(
        select(bindings, &named, "[sudo] password for ada:").map(|b| b.name.as_str()),
        Some("prod-ssh"),
    );

    // Three negatives, each separating the row above from a different
    // degenerate matcher.
    assert!(
        select(
            bindings,
            &command_line("ssh", &["user@staging".to_string()]),
            "password:"
        )
        .is_none(),
        "a matcher that matches every session is a credential store handed to all of them"
    );
    assert!(
        select(bindings, &named, "$ ").is_none(),
        "`match_prompt` was ignored: the block selects on the command line alone"
    );
    assert!(
        select(bindings, &named, "").is_none(),
        "an empty prompt line satisfied a binding that carries a `match_prompt` \
         (REQ-O-013)"
    );
    // And the empty set, so `select` is not answering `Some` from
    // somewhere other than the slice it was handed.
    assert!(select(&[], &named, "password:").is_none());
}

/// §10.2's `[security]` knobs for §9.6, **copied from the current spec
/// text** and loaded as a `Config` before anything is asserted about them
/// (Global Constraint 15).
///
/// The three keys and their comments are the document's, verbatim,
/// including the `--` that stands in for an em dash there. Rev. 49 makes
/// an unknown key a load error, so a remembered fixture fails to parse
/// rather than merely drifting — which is why this is parsed first and
/// read second.
const SPEC_AUTOFILL_BLOCK: &str = r#"
[security]
# Secret resolution (§9.6): "prompt" (ask a human), "keychain" (resolve
# from the OS credential store via an operator-configured binding), or
# "both" (try keychain, fall back to prompting).
secret_provider = "prompt"
# When true, a detected echo-off prompt (§8.3 AwaitingSecret) with a
# matching binding is filled automatically with no agent tool call.
# Off by default: silent credential injection is opt-in per deployment.
autofill_on_echo_off = false
# When true, dangerous-command confirmation requires a code (shown only
# via trusted UI surfaces -- web UI dashboard or `holdfast confirm` CLI) in
# addition to the agent-held token. Agent never receives the code.
# Default false: relies on the MCP client's tool-call permission UI.
strict_confirmation = false
"#;

/// **REQ-SEC-014's config half, read off the published example rather
/// than off a snippet somebody typed.**
///
/// The shipped posture cannot autofill for **two independent reasons** —
/// the knob is off and the mode is `prompt` — and each is asserted with
/// the minimal edit that flips it, so neither absence is evidence of a
/// parser that answers `false` to everything.
///
/// This is also the row §9.6's *runtime* mode check defers to. A daemon
/// with `autofill_on_echo_off = true` and `secret_provider = "prompt"`
/// does not exist, because the pair is refused at load; the check inside
/// the daemon is defence in depth for a `SecurityConfig` built in Rust,
/// and this is the only place the rule is reachable from a config file.
#[test]
fn the_published_security_block_ships_with_autofill_off() {
    let cfg = holdfast_core::config::parse_str(SPEC_AUTOFILL_BLOCK)
        .expect("§10.2's [security] block must load as a Config");
    assert!(
        !cfg.security.autofill_on_echo_off,
        "REQ-SEC-014: silent credential injection is opt-in per deployment, not \
         inherited"
    );
    assert!(
        !keychain_step_runs(&cfg.security.secret_provider),
        "the published example now enables the credential store by default"
    );

    // The pairing for the knob: the same file with that one line flipped
    // loads, and reads `true`. Without it the assertion above is satisfied
    // by a loader that answers `false` whatever the file says.
    let on = SPEC_AUTOFILL_BLOCK
        .replace(
            "autofill_on_echo_off = false",
            "autofill_on_echo_off = true",
        )
        .replace(
            r#"secret_provider = "prompt""#,
            r#"secret_provider = "both""#,
        );
    let enabled =
        holdfast_core::config::parse_str(&on).expect("the opted-in spelling must load too");
    assert!(enabled.security.autofill_on_echo_off);
    assert!(keychain_step_runs(&enabled.security.secret_provider));

    // And the pair the loader refuses: opting in while leaving the mode at
    // `prompt` asks for an autofill from a credential store the same file
    // forbids reading. The error names the key, or an operator cannot act
    // on it.
    let contradiction = SPEC_AUTOFILL_BLOCK.replace(
        "autofill_on_echo_off = false",
        "autofill_on_echo_off = true",
    );
    let err = holdfast_core::config::parse_str(&contradiction)
        .expect_err(
            "`autofill_on_echo_off = true` with `secret_provider = \"prompt\"` must be refused",
        )
        .to_string();
    assert!(
        err.contains("autofill_on_echo_off"),
        "the refusal does not name the key an operator has to change: {err}"
    );
}

// ------------------------------- §17.5 over the socket (§7.5, §18.4)
//
// **These three rows are here and not in the library target because the
// thing under test is the *wire*: the decode, the ReadOnly gate, and the
// `frame_kind` on a refusal.** None of them needs a provider to produce a
// value — the two that let an approval through drive a provider that
// refuses without spawning anything — so none of them needs the
// `#[cfg(test)]` script fixture that forces `secret::binding`'s rows into
// the library. The behavioural half of §17.5 (approve, deny, expire,
// supersede) lives there, where a provider can run.

/// A binding that always matches this file's sessions and, once
/// approved, resolves **nothing** — deterministically and on every
/// platform.
///
/// `wincred` is not a way of skipping the provider: it is §9.6's fifth
/// spelling, and `ArgvProvider::argv` answers it `NotImplemented` on
/// every target without starting a process. That is exactly what
/// Global Constraint 12 / REQ-TST-007 require of a row that must not
/// depend on a credential store being installed — the alternative,
/// `secret-service` or `pass`, would resolve on a developer's laptop and
/// fall through on CI, which is a row whose outcome depends on the
/// machine.
fn confirming_binding() -> SecretBinding {
    SecretBinding {
        name: "prod-shell".to_string(),
        // Every session here is `sh -c <script>` (see `shell_running`).
        match_command: "^sh\\b".to_string(),
        match_prompt: String::new(),
        provider: "wincred".to_string(),
        reference: "op://vault/prod-db/password".to_string(),
        max_uses: None,
        require_confirm: true,
    }
}

fn confirming_config() -> Config {
    Config {
        security: SecurityConfig {
            // §5.2's step 1 does not run at all under the default
            // `prompt`; without this line every row below would fall
            // straight through and assert nothing.
            secret_provider: "keychain".to_string(),
            secret_bindings: vec![confirming_binding()],
            ..SecurityConfig::default()
        },
        daemon: DaemonConfig::default(),
        ..Config::default()
    }
}

/// A binding whose only job is to make the daemon write one line to
/// `daemon.log` on the secret path.
///
/// `match_command` is an unclosed group, which `regex::Regex::new` refuses
/// and `secret::binding::pattern_matches` answers by naming the binding in
/// a diagnostic and **declining to match**. That is the whole contract:
/// it never selects, never spends a use and never spawns anything, and it
/// is what stops `a_tool_submitted_secret_reaches_none_of_the_seven_surfaces`
/// sweeping an empty capture for the value.
///
/// **`Config::validate` would reject this at load and that is correct.**
/// A daemon built from a `Config` value in Rust does not run the
/// validator, which is the one way to reach the branch — and the branch is
/// reachable in production too, because §10.2's example is loaded by
/// operators who may add a binding a later regex-crate version stops
/// compiling.
fn leak_canary_binding() -> SecretBinding {
    SecretBinding {
        name: "leak-canary".to_string(),
        match_command: "(".to_string(),
        match_prompt: String::new(),
        provider: "wincred".to_string(),
        reference: "op://vault/never-read/password".to_string(),
        max_uses: None,
        require_confirm: false,
    }
}

/// [`confirming_config`] with the canary **first** in configured order.
///
/// First, because §9.6 probes in configured order and this one never
/// matches: it emits its diagnostic and hands the probe on to
/// `prod-shell`, which is what the row is actually about.
fn canary_and_confirming_config() -> Config {
    let mut c = confirming_config();
    c.security.secret_bindings = vec![leak_canary_binding(), confirming_binding()];
    c
}

/// The next frame matching `pred`, skipping the child's output.
async fn next_matching(
    c: &mut UnixStream,
    secs: u64,
    what: &str,
    pred: impl Fn(&ServerFrame) -> bool,
) -> ServerFrame {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let f = recv(c).await;
        if pred(&f) {
            return f;
        }
        assert!(
            matches!(
                f,
                ServerFrame::Output { .. }
                    | ServerFrame::Resize { .. }
                    | ServerFrame::AwaitingSecret { .. }
                    | ServerFrame::SecretRequestClosed { .. }
                    | ServerFrame::BindingApprovalRequired { .. }
            ),
            "waiting for {what} and got {f:?}"
        );
    }
    panic!("no {what} arrived");
}

async fn next_binding_approval(c: &mut UnixStream, secs: u64) -> (String, String, String) {
    match next_matching(c, secs, "BindingApprovalRequired", |f| {
        matches!(f, ServerFrame::BindingApprovalRequired { .. })
    })
    .await
    {
        ServerFrame::BindingApprovalRequired {
            approval_id,
            binding_name,
            provider,
            ..
        } => (approval_id, binding_name, provider),
        _ => unreachable!(),
    }
}

async fn next_protocol_error(c: &mut UnixStream, secs: u64) -> (String, Option<String>) {
    match next_matching(c, secs, "ProtocolError", |f| {
        matches!(f, ServerFrame::ProtocolError { .. })
    })
    .await
    {
        ServerFrame::ProtocolError { reason, frame_kind } => (reason, frame_kind),
        _ => unreachable!(),
    }
}

/// Write an `ApproveBinding` by hand, so `decision` can be something the
/// enum cannot express — the same instrument `attach_protocol.rs`'s
/// `write_raw_signal` uses on §18.4c's other closed set.
async fn write_raw_approve(
    s: &mut UnixStream,
    approval_id: &str,
    decision: ciborium::value::Value,
) {
    let value = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("type".into()),
            ciborium::value::Value::Text("ApproveBinding".into()),
        ),
        (
            ciborium::value::Value::Text("approval_id".into()),
            ciborium::value::Value::Text(approval_id.into()),
        ),
        (ciborium::value::Value::Text("decision".into()), decision),
    ]);
    frame::write_frame(s, &value)
        .await
        .expect("write raw ApproveBinding");
}

/// Wait for the fall-through and hand back the `request_id` a human
/// would answer.
///
/// **Read off the hub rather than off a fresh `AwaitingSecret` frame**,
/// and the reason is §5.2's ordinary shape: the echo-off child has
/// already raised a request, `attach::conn` broadcast it when this client
/// attached, and the falling-through call therefore **adopts** — which is
/// exactly the case where §7.5 forbids a second broadcast (*"an adopting
/// call must not re-announce a request a human may already be typing
/// into"*). A row waiting for a second frame here would be waiting for a
/// frame the protocol says must not be sent. That the broadcast *does*
/// happen when the call raises the request itself is asserted in
/// `secret::binding::tests::denying_falls_through_to_the_human_prompt`,
/// where nothing raised one first.
async fn await_fall_through(d: &TestDaemon, session_id: &str) -> String {
    await_waiter(d, session_id, "the fall-through to the prompt path").await;
    d.daemon
        .attach_hub()
        .secrets()
        .outstanding(session_id)
        .expect("a request is outstanding once a call is waiting on one")
        .request_id
}

fn approval_pending(d: &TestDaemon, session_id: &str) -> bool {
    d.daemon
        .attach_hub()
        .approvals()
        .outstanding(session_id)
        .is_some()
}

/// REQ-SEC-017's second clause, and §18.4's row by name: *"any frame but
/// `Detach` from a `ReadOnly` client, **including `ApproveBinding**`"*.
///
/// The mutation is dropping the frame silently, which leaves the human
/// staring at a button that did nothing. **The follow-up is what proves
/// the request survived**: after two refusals the approval is still
/// pending, a ReadWrite client's decision is taken, and the call goes on
/// to complete through the fall-through.
#[tokio::test]
async fn approve_binding_from_a_readonly_client_is_rejected() {
    let d = TestDaemon::start_with_config("roapprove", confirming_config()).await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut ro = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    let mut rw = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    let (approval_id, binding_name, provider) = next_binding_approval(&mut rw, 10).await;
    assert_eq!(binding_name, "prod-shell");
    assert_eq!(provider, "wincred");
    // An observer is *shown* the approval — §9.2's role split is about
    // output, not about attention — and simply may not answer it.
    let (observed, _, _) = next_binding_approval(&mut ro, 10).await;
    assert_eq!(observed, approval_id);

    for attempt in 1..=2 {
        send(
            &mut ro,
            &ClientFrame::ApproveBinding {
                approval_id: approval_id.clone(),
                decision: ApprovalDecision::Approve,
            },
        )
        .await;
        let (reason, kind) = next_protocol_error(&mut ro, 10).await;
        assert_eq!(reason, "read_only_attach", "attempt {attempt}");
        // A `reason`-only assertion passes against an implementation that
        // cannot name the frame at all.
        assert_eq!(kind.as_deref(), Some("ApproveBinding"), "attempt {attempt}");
        assert!(
            approval_pending(&d, &s.id),
            "a ReadOnly client's decision was applied (attempt {attempt})"
        );
    }
    // Two round trips completed on the same connection, which is §18.4's
    // *"closes: no"* asserted rather than assumed.

    // And a ReadWrite client's decision **is** taken: the request the
    // ReadOnly frames could not touch is still there to be answered.
    send(
        &mut rw,
        &ClientFrame::ApproveBinding {
            approval_id: approval_id.clone(),
            decision: ApprovalDecision::Approve,
        },
    )
    .await;
    // `wincred` resolves nothing on any platform, so the approved call
    // falls through to the human — which is the request a human can now
    // answer.
    let request_id = await_fall_through(&d, &s.id).await;
    assert!(
        !approval_pending(&d, &s.id),
        "the approval was not consumed"
    );
    send(
        &mut rw,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;

    let payload = joined(call, "the approved call").await;
    assert_eq!(payload["status"], "secret_provided", "{payload}");

    let lines = audit_entries(&d, &s.id, "binding_approval");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["outcome"], "approved");
    assert_eq!(
        lines[0]["decided_by"], "cli",
        "decided_by is the deciding connection's handshake client_kind, never the frame's"
    );

    let _ = s.signal(Signal::Kill);
}

/// §18.4's closed-enum rule on the second field that has one:
/// `decision: "maybe"` is `protocol_violation`, **no part of the frame is
/// applied**, and the connection stays open.
///
/// The mutation is a permissive deserialiser that maps anything
/// non-`"approve"` onto deny — which silently converts a typo into an
/// authorisation decision. `Signal.sig` is the standing precedent
/// (§18.4c) and this row is written against it deliberately.
#[tokio::test]
async fn a_decision_outside_the_two_values_is_a_protocol_violation() {
    let d = TestDaemon::start_with_config("baddecision", confirming_config()).await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    let call = spawn_call(&d, secret_args(&s.id, 20));
    let (approval_id, _, _) = next_binding_approval(&mut c, 10).await;

    for bad in [
        ciborium::value::Value::Text("maybe".into()),
        ciborium::value::Value::Text("Approve".into()),
        ciborium::value::Value::Text(String::new()),
        ciborium::value::Value::Bool(true),
    ] {
        write_raw_approve(&mut c, &approval_id, bad.clone()).await;
        let (reason, kind) = next_protocol_error(&mut c, 10).await;
        assert_eq!(reason, "protocol_violation", "for decision {bad:?}");
        assert_eq!(
            kind.as_deref(),
            Some("ApproveBinding"),
            "the refusal did not name the frame, for decision {bad:?}"
        );
        assert!(
            approval_pending(&d, &s.id),
            "a decision outside the two values was applied: {bad:?}"
        );
    }
    // Nothing was decided and nothing was resolved.
    assert!(audit_entries(&d, &s.id, "binding_approval").is_empty());
    assert!(audit_entries(&d, &s.id, "binding_resolved").is_empty());

    // **The pairing**: the same frame with a catalogued value *is*
    // applied, so the four refusals above are about the value and not
    // about a handler that refuses every `ApproveBinding`.
    send(
        &mut c,
        &ClientFrame::ApproveBinding {
            approval_id: approval_id.clone(),
            decision: ApprovalDecision::Deny,
        },
    )
    .await;
    let request_id = await_fall_through(&d, &s.id).await;
    assert!(!approval_pending(&d, &s.id));
    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = joined(call, "the denied call").await;
    assert_eq!(payload["status"], "secret_provided", "{payload}");
    let lines = audit_entries(&d, &s.id, "binding_approval");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["outcome"], "denied");

    let _ = s.signal(Signal::Kill);
}

/// REQ-C-005 / REQ-S-006 extended to the new frame: an `ApproveBinding`
/// **rejected** from a ReadOnly client does not extend the session's idle
/// deadline.
///
/// The mutation is bumping activity before the ReadOnly check rather than
/// after — which would let any observer keep any session alive
/// indefinitely by sending a frame it is not allowed to send.
///
/// **The pairing is in the same test**: an ordinary `Input` frame from a
/// ReadWrite client on the same session *does* move the stamp, so the row
/// cannot pass against a harness that could not observe a bump at all.
///
/// (Renamed from the plan's `the_readonly_ack_does_not_bump_activity`:
/// nothing here acks anything, and §7.8.3's `AttentionAck` — the frame
/// that name belongs to — is post-v0.1.0.)
#[tokio::test]
async fn a_rejected_approve_binding_does_not_bump_activity() {
    let d = TestDaemon::start_with_config("roactivity", confirming_config()).await;
    // **A `MockPty` and not a real shell, and this is the one row here
    // that needs one.** `Session`'s reader thread stamps activity once
    // per output chunk, so *any* byte the child or the tty produces moves
    // the stamp for a reason that has nothing to do with a frame — and
    // the negative assertion below cannot tell that apart from the defect
    // it is written to catch. A backend that produces nothing unless a
    // test queues it removes the whole class. `attach_protocol.rs`'s
    // `signal_wire_names_are_the_three_documented_values` makes the same
    // `last_activity_ms` assertion on the same kind of backend, for the
    // same reason. (Measured: the first spelling used
    // `sh -c 'sleep 30'` and flaked once in a loaded full-workspace run.)
    let s = d.quiet_session();
    let mut ro = attach_ok(&d, &s.id, AttachMode::ReadOnly).await;
    let mut rw = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let before = s.last_activity_ms();
    send(
        &mut ro,
        &ClientFrame::ApproveBinding {
            approval_id: "appr_nothing_here".into(),
            decision: ApprovalDecision::Approve,
        },
    )
    .await;
    let (reason, kind) = next_protocol_error(&mut ro, 10).await;
    assert_eq!(reason, "read_only_attach");
    assert_eq!(kind.as_deref(), Some("ApproveBinding"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        s.last_activity_ms(),
        before,
        "a rejected ApproveBinding extended the idle deadline"
    );

    // The pairing: the same session, a frame that *is* allowed.
    send(
        &mut rw,
        &ClientFrame::Input {
            bytes: b"x".to_vec(),
        },
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while s.last_activity_ms() <= before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "an accepted Input did not move the stamp either, so the row above asserts \
             nothing"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let _ = s.signal(Signal::Kill);
}

/// An `ApproveBinding` whose `approval_id` names nothing outstanding is
/// **answered**, and by name.
///
/// **This is the one behaviour §18.4 does not spell out, and it is
/// recorded rather than repaired from this lane (Global Constraint 16).**
/// The table's `unknown_request_id` row reads *"`SecretInput.request_id`
/// doesn't match the current outstanding prompt"*, because `SecretInput`
/// was its only producer when it was written. The condition here is the
/// same one — the id you named is not the outstanding one — and
/// `frame_kind` is exactly what distinguishes the two producers, which is
/// what that field exists for. The two alternatives are both worse:
/// inventing a sixth `reason` on a §23.3 surface, or answering nothing at
/// all, which leaves a human whose approval expired one second ago
/// pressing a button that says nothing back.
///
/// **The pairing is what makes the refusal about the id**: the same
/// client, the same frame kind, with the id that *is* outstanding, is
/// accepted silently and consumes the approval.
#[tokio::test]
async fn an_approve_binding_naming_no_outstanding_approval_is_refused_by_name() {
    let d = TestDaemon::start_with_config("staleapproval", confirming_config()).await;
    let s = d.shell_running(ECHO_OFF_FIXTURE);
    let mut c = attach_ok(&d, &s.id, AttachMode::ReadWrite).await;

    // Nothing is pending yet, so every id is unknown.
    assert!(!approval_pending(&d, &s.id));
    for attempt in 1..=2 {
        send(
            &mut c,
            &ClientFrame::ApproveBinding {
                approval_id: "appr_never_existed".into(),
                decision: ApprovalDecision::Approve,
            },
        )
        .await;
        let (reason, kind) = next_protocol_error(&mut c, 10).await;
        assert_eq!(reason, "unknown_request_id", "attempt {attempt}");
        assert_eq!(kind.as_deref(), Some("ApproveBinding"), "attempt {attempt}");
    }
    // Two round trips on one connection: §18.4's *"closes: no"*.

    // The pairing: a real approval, the real id, and no `ProtocolError`.
    let call = spawn_call(&d, secret_args(&s.id, 20));
    let (approval_id, _, _) = next_binding_approval(&mut c, 10).await;
    let before = s.last_activity_ms();
    send(
        &mut c,
        &ClientFrame::ApproveBinding {
            approval_id: approval_id.clone(),
            decision: ApprovalDecision::Approve,
        },
    )
    .await;
    let request_id = await_fall_through(&d, &s.id).await;
    assert!(!approval_pending(&d, &s.id), "the real id was refused too");
    // §4.1: a human deciding at the keyboard is activity, or a session
    // idle-reaps out from under the approval they just gave. Stamped on
    // the arm that landed a decision and on no other.
    assert!(
        s.last_activity_ms() >= before,
        "an accepted decision moved the stamp backwards"
    );

    send(
        &mut c,
        &ClientFrame::SecretInput {
            request_id,
            bytes: PROBE.as_bytes().to_vec(),
        },
    )
    .await;
    let payload = joined(call, "the approved call").await;
    assert_eq!(payload["status"], "secret_provided", "{payload}");
    // And the accepted frame produced no refusal of its own: the only
    // `ProtocolError`s on this connection were the two above.
    let lines = audit_entries(&d, &s.id, "binding_approval");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["outcome"], "approved");

    let _ = s.signal(Signal::Kill);
}
