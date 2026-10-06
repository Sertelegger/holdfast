//! Per-session counters, and the one `session_stats` audit line each
//! session gets (plan §4.9).
//!
//! **Counts, never content.** Every counter here is a number or a
//! closed-vocabulary name; nothing a read returned, no command line and
//! no environment value is held or written. That is what lets the line
//! stand on a host whose redaction rules miss something.
//!
//! **Cheap on the read path.** Each read adds a handful of relaxed
//! atomic operations to work that has just run every redaction rule over
//! its window. No lock is taken here; the line itself is built once.
//!
//! ## When the line is written, and why once
//!
//! When the session stops being live, which the code reaches four ways:
//!
//! 1. **The child is gone** — it exited, `terminate` or `interrupt`
//!    ended it, an attached client's `Signal` did, or the idle reaper
//!    did. `SessionRegistry`'s sweep then retires it, from
//!    `start_session`'s reservation, from `insert`, or from the daemon's
//!    periodic tick (`daemon::server::reaper_loop`, which runs it right
//!    after the reaper), and writes the line once the registry's lock is
//!    released.
//! 2. **The daemon stops** — `Daemon::shutdown` and
//!    `Daemon::shutdown_graceful` write it for every session that has
//!    none yet, live or not, after signalling them.
//! 3. **`holdfast mcp --no-daemon` exits** — `mcp::serve_stdio` does the
//!    same once its transport closes, since its sessions die with it.
//! 4. **The `Session` is dropped any other way** — `Drop`, the backstop.
//!
//! A flag makes those one write: whichever comes first writes, and the
//! rest find it taken. A session built without an audit handle (most
//! tests) writes nothing.
//!
//! **A read of a session after its line is written is not in it.** The
//! registry keeps an exited session readable (§5.5.1); a `holdfast logs`
//! of it an hour later is a read of a record, not of the session's life.
//! The sweep runs at the latest one daemon tick after the exit, so reads
//! that follow an exit closely are counted.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use super::launch::{History, HISTFILE_CARRIER};
use super::Session;
use crate::audit::{
    AuditLog, HistoryPolicy, RawRead, RawReadCounts, ReadAnchor, ReadCounts, RedactionMode,
    SessionStatsRecord, WaitCounts,
};
use crate::detect::shell::detect_shell;
use crate::mcp::resources::RESOURCE_READ_TOOL;
use crate::output::redact::{marker, UNRESOLVED_KIND};
use crate::output::{OutputProcessor, ProcessedRead, ReadRequest};
use crate::screen::ScreenCapture;

/// The `tool` `read_output` passes on its `ReadRequest` — the literal at
/// its `caller::audit_surface` call.
const READ_OUTPUT_TOOL: &str = "read_output";

/// Which surface served a read — `session_stats.reads`' keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSurface {
    Cursor,
    Tail,
    Resource,
    Screen,
}

/// How a wait ended — `session_stats.waits`' keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// A pattern wait whose match was returned.
    Matched,
    /// A pattern-less wait that saw the session stop executing.
    Idle,
    /// The deadline elapsed first.
    Timeout,
    /// The child had exited.
    SessionDied,
}

/// The variables GH #252's policy yields to when the call's own `env`
/// sets them (`launch::history_defaults` drops its default for each).
pub const HISTORY_YIELDS_TO: [&str; 3] = ["HISTFILE", HISTFILE_CARRIER, "fish_history"];

/// What `session_stats.history_policy` says for a session started under
/// `history` with the call's or profile's own `explicit` environment.
///
/// [`HistoryPolicy::Caller`] whenever `explicit` names one of
/// [`HISTORY_YIELDS_TO`], whatever its value: the policy steps aside for
/// the name, so the record does too. Otherwise the configured mode.
pub fn history_policy(history: History<'_>, explicit: &[(String, String)]) -> HistoryPolicy {
    if explicit
        .iter()
        .any(|(k, _)| HISTORY_YIELDS_TO.contains(&k.as_str()))
    {
        return HistoryPolicy::Caller;
    }
    match history {
        History::Discard => HistoryPolicy::Discard,
        History::File(_) => HistoryPolicy::PerSession,
    }
}

/// Whether a processed read's text carries an `[REDACTED:unresolved]`.
pub fn shows_unresolved(read: &ProcessedRead) -> bool {
    read.redactions.get(UNRESOLVED_KIND).is_some_and(|n| *n > 0)
}

/// One session's counters. Held by [`Session`]; reached through
/// [`Session::stats`].
///
/// The API the later 0.0.9 PRs call:
/// - the known-values PR (K, #253) calls
///   [`SessionStats::set_known_values_registered`] once it has
///   registered the session's values;
/// - the `complete_only` PR (C) adds `RedactionMode::CompleteOnly` and
///   routes it through [`SessionStats::note_raw`], which counts it under
///   `raw_reads.complete_only` and hands back `prior_unresolved` for its
///   `redaction_disabled` line, exactly as `redact: false` does here.
#[derive(Debug)]
pub struct SessionStats {
    /// Where the line goes, or `None` for a session that writes none.
    audit: Option<Arc<AuditLog>>,
    history_policy: HistoryPolicy,
    /// The session's clock at construction, in its milliseconds.
    started_ms: i64,
    /// The session's clock when its exit was first observed; 0 until then.
    ended_ms: AtomicI64,
    known_values_registered: AtomicU64,
    reads_cursor: AtomicU64,
    reads_tail: AtomicU64,
    reads_resource: AtomicU64,
    reads_screen: AtomicU64,
    reads_held_back: AtomicU64,
    max_bytes_withheld: AtomicU64,
    bytes_returned: AtomicU64,
    raw_false: AtomicU64,
    /// Never incremented until `RedactionMode` has a `CompleteOnly` (C).
    raw_complete_only: AtomicU64,
    waits_matched: AtomicU64,
    waits_timeout: AtomicU64,
    waits_idle: AtomicU64,
    waits_session_died: AtomicU64,
    /// Whether the most recent masked read showed an `unresolved` marker.
    last_masked_unresolved: AtomicBool,
    /// Taken by the one call that writes the line.
    recorded: AtomicBool,
}

impl SessionStats {
    pub(crate) fn new(
        audit: Option<Arc<AuditLog>>,
        history_policy: HistoryPolicy,
        started_ms: i64,
    ) -> Self {
        Self {
            audit,
            history_policy,
            started_ms,
            ended_ms: AtomicI64::new(0),
            known_values_registered: AtomicU64::new(0),
            reads_cursor: AtomicU64::new(0),
            reads_tail: AtomicU64::new(0),
            reads_resource: AtomicU64::new(0),
            reads_screen: AtomicU64::new(0),
            reads_held_back: AtomicU64::new(0),
            max_bytes_withheld: AtomicU64::new(0),
            bytes_returned: AtomicU64::new(0),
            raw_false: AtomicU64::new(0),
            raw_complete_only: AtomicU64::new(0),
            waits_matched: AtomicU64::new(0),
            waits_timeout: AtomicU64::new(0),
            waits_idle: AtomicU64::new(0),
            waits_session_died: AtomicU64::new(0),
            last_masked_unresolved: AtomicBool::new(false),
            recorded: AtomicBool::new(false),
        }
    }

    /// The known-values PR's (K, #253) one call: how many values the
    /// session's matcher holds once registration is done. A count; the
    /// values never reach this type.
    pub fn set_known_values_registered(&self, n: u64) {
        self.known_values_registered.store(n, Ordering::Relaxed);
    }

    pub fn history_policy(&self) -> HistoryPolicy {
        self.history_policy
    }

    /// Count one read: its surface, the raw bytes it handed over, and
    /// what it withheld. `withheld` is the gap a held-back byte-stream
    /// read left before the buffer's head; the grid passes 0.
    pub(crate) fn note_read(
        &self,
        surface: ReadSurface,
        raw_bytes: u64,
        held_back: bool,
        withheld: u64,
    ) {
        let counter = match surface {
            ReadSurface::Cursor => &self.reads_cursor,
            ReadSurface::Tail => &self.reads_tail,
            ReadSurface::Resource => &self.reads_resource,
            ReadSurface::Screen => &self.reads_screen,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.bytes_returned.fetch_add(raw_bytes, Ordering::Relaxed);
        if held_back {
            self.reads_held_back.fetch_add(1, Ordering::Relaxed);
            self.max_bytes_withheld
                .fetch_max(withheld, Ordering::Relaxed);
        }
    }

    /// A masked read finished: remember whether it showed an
    /// `unresolved` marker, for the next raw read's `prior_unresolved`.
    pub(crate) fn note_masked(&self, unresolved: bool) {
        self.last_masked_unresolved
            .store(unresolved, Ordering::Relaxed);
    }

    /// Count one read that was not fully masked, and return
    /// `prior_unresolved` for its `redaction_disabled` line. It does not
    /// move that flag: a raw read is not a masked one.
    pub fn note_raw(&self, mode: RedactionMode) -> bool {
        let counter = match mode {
            RedactionMode::False => &self.raw_false,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.last_masked_unresolved.load(Ordering::Relaxed)
    }

    pub(crate) fn note_wait(&self, result: WaitResult) {
        let counter = match result {
            WaitResult::Matched => &self.waits_matched,
            WaitResult::Idle => &self.waits_idle,
            WaitResult::Timeout => &self.waits_timeout,
            WaitResult::SessionDied => &self.waits_session_died,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The first observation of the child's exit, on the session's clock.
    /// Later observations leave it alone.
    pub(crate) fn latch_end(&self, now_ms: i64) {
        let _ = self
            .ended_ms
            .compare_exchange(0, now_ms, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Claim the one write. `true` exactly once.
    fn claim_record(&self) -> bool {
        !self.recorded.swap(true, Ordering::AcqRel)
    }

    pub fn recorded(&self) -> bool {
        self.recorded.load(Ordering::Acquire)
    }
}

impl Session {
    /// This session's counters, for the PRs that add to them.
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// The accounting of one `read_processed`: its counts, and §9.4's
    /// `redaction_disabled` line when it was not masked. `head` is the
    /// buffer's head in the snapshot the read was judged against.
    ///
    /// **`redaction_disabled` is written here, inside the read, and not
    /// by each transport** — the property `mcp::resources` relies on to
    /// have no audit call of its own.
    ///
    /// Only `read_output` and `resources/read` are counted as reads.
    /// `wait_for_pattern`'s text runs through the same pipeline twice per
    /// response, and [`Session::account_wait`] counts the wait instead.
    pub(crate) fn account_read(
        &self,
        req: &ReadRequest,
        read: &ProcessedRead,
        head: u64,
        processor: &OutputProcessor,
    ) {
        let surface = match req.tool {
            READ_OUTPUT_TOOL if req.start.is_tail() => Some(ReadSurface::Tail),
            READ_OUTPUT_TOOL => Some(ReadSurface::Cursor),
            RESOURCE_READ_TOOL => Some(ReadSurface::Resource),
            _ => None,
        };
        if let Some(surface) = surface {
            self.stats.note_read(
                surface,
                read.bytes_returned as u64,
                read.held_back,
                head.saturating_sub(read.cursor),
            );
        }
        let mode = (!req.options.redact).then_some(RedactionMode::False);
        match mode {
            None if surface.is_some() => self.stats.note_masked(shows_unresolved(read)),
            None => {}
            Some(mode) => {
                let prior_unresolved = self.stats.note_raw(mode);
                processor.audit.record_redaction_disabled(
                    Some(&self.id),
                    &RawRead {
                        tool: req.tool,
                        client_kind: req.client_kind,
                        mode,
                        start: if req.start.is_tail() {
                            ReadAnchor::Tail
                        } else {
                            ReadAnchor::Cursor
                        },
                        bytes_returned: read.bytes_returned as u64,
                        prior_unresolved,
                    },
                );
            }
        }
    }

    /// The accounting of one `get_screen_state`: a `screen` read, and
    /// `redaction_disabled` with `start: "screen"` when `redact` was
    /// false. `tool` and `client_kind` were sampled by the caller before
    /// the capture left its task.
    pub fn account_screen_read(
        &self,
        redact: bool,
        capture: &ScreenCapture,
        tool: &'static str,
        client_kind: &'static str,
        audit: &AuditLog,
    ) {
        let unresolved_marker = marker(UNRESOLVED_KIND);
        let (text_bytes, held_back, unresolved) = match capture {
            ScreenCapture::Full(g) => (
                g.lines.iter().map(String::len).sum::<usize>()
                    + g.title.as_ref().map_or(0, String::len),
                g.held_back,
                g.lines
                    .iter()
                    .chain(g.title.iter())
                    .any(|l| l.contains(&unresolved_marker)),
            ),
            ScreenCapture::Delta(d) => (
                d.diff.len(),
                d.held_back,
                d.diff.contains(&unresolved_marker),
            ),
        };
        self.stats.note_read(ReadSurface::Screen, 0, held_back, 0);
        if redact {
            self.stats.note_masked(unresolved);
            return;
        }
        let mode = RedactionMode::False;
        let prior_unresolved = self.stats.note_raw(mode);
        audit.record_redaction_disabled(
            Some(&self.id),
            &RawRead {
                tool,
                client_kind,
                mode,
                start: ReadAnchor::Screen,
                bytes_returned: text_bytes as u64,
                prior_unresolved,
            },
        );
    }

    /// The accounting of one wait. `text_unresolved` is whether the text
    /// the wait returned (`output_since_start`, `match.text`) showed an
    /// `unresolved` marker, or `None` when it returned no text.
    pub fn account_wait(&self, result: WaitResult, text_unresolved: Option<bool>) {
        self.stats.note_wait(result);
        if let Some(unresolved) = text_unresolved {
            self.stats.note_masked(unresolved);
        }
    }

    /// The `session_stats` line as it would be written now.
    pub fn stats_record(&self) -> SessionStatsRecord {
        let s = &self.stats;
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        // A child that is gone and that nothing has observed yet ends
        // here, through the latch every other observer uses — so this
        // line and anything that asks later agree on when it ended. The
        // sweep that retires a session does not reliably observe it: it
        // asks only to sort, and a sort of one asks nothing.
        if !self.backend.is_alive() {
            self.latch_exit_time();
        }
        let ended_ms = match s.ended_ms.load(Ordering::Relaxed) {
            0 => self.clock.now_ms(),
            t => t,
        };
        SessionStatsRecord {
            shell: detect_shell(&self.command, &self.args).map(|sh| sh.as_str()),
            duration_ms: ended_ms.saturating_sub(s.started_ms).max(0) as u64,
            history_policy: s.history_policy,
            known_values_registered: load(&s.known_values_registered),
            bytes_produced: self.buffer_head(),
            bytes_returned: load(&s.bytes_returned),
            reads: ReadCounts {
                cursor: load(&s.reads_cursor),
                tail: load(&s.reads_tail),
                resource: load(&s.reads_resource),
                screen: load(&s.reads_screen),
            },
            reads_held_back: load(&s.reads_held_back),
            max_bytes_withheld: load(&s.max_bytes_withheld),
            redactions: self.redaction_stats(),
            raw_reads: RawReadCounts {
                redact_false: load(&s.raw_false),
                complete_only: load(&s.raw_complete_only),
            },
            waits: WaitCounts {
                matched: load(&s.waits_matched),
                timeout: load(&s.waits_timeout),
                idle: load(&s.waits_idle),
                session_died: load(&s.waits_session_died),
            },
        }
    }

    /// Write this session's `session_stats` line, unless it has one.
    /// Returns whether this call wrote it. See the module doc for every
    /// caller and why one write is all any of them can cause.
    pub fn record_stats(&self) -> bool {
        let Some(audit) = self.stats.audit.as_ref() else {
            return false;
        };
        if !self.stats.claim_record() {
            return false;
        }
        audit.record_session_stats(&self.id, &self.stats_record());
        true
    }
}

/// The backstop: a session that reaches its end by a path none of the
/// retire sites covers still gets its line.
impl Drop for Session {
    fn drop(&mut self) {
        self.record_stats();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::caller;
    use crate::mcp::tools::{
        GetScreenStateArgs, ReadOutputArgs, TerminateArgs, WaitForPatternArgs,
    };
    use crate::mcp::HoldfastServer;
    use crate::pty::{MockPty, PtyBackend};
    use crate::session::{new_session_id, SessionConfig};
    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::model::CallToolResult;
    use serde_json::Value;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// 39 characters: one short of the github rule's minimum, so only
    /// §4.1's holdback protects it. The same fixture `mcp::tools` uses.
    const IN_FLIGHT: &str = "ghp_0123456789abcdefghijABCDEFGHIJ01234";

    /// A private key whose `-----END` never arrives: the read masks its
    /// body as `[REDACTED:unresolved]`, the marker `prior_unresolved` is
    /// about. Shaped like `output`'s own `pem_longer_than` fixture.
    fn unterminated_key() -> String {
        let mut body = Vec::new();
        for i in 0..64 {
            let mut line = format!("KEYBODY{i:06}");
            while line.len() < 64 {
                line.push_str("MIIEowIBAAKCAQEAy8Dbv8prpJ");
            }
            line.truncate(64);
            body.push(line);
        }
        format!(
            "$ cat chain.pem\n-----BEGIN RSA PRIVATE KEY-----\n{}\n",
            body.join("\n")
        )
    }

    fn server_logging_to(path: &Path) -> HoldfastServer {
        HoldfastServer::with_audit_path(Some(path.to_path_buf()))
    }

    /// A mock-backed session that reports to `server`'s trail, the way
    /// `start_session` builds one, registered and returned with its pty.
    fn audited_session(server: &HoldfastServer, name: &str) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let session = Session::new(
            new_session_id(),
            Some(name.to_string()),
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                audit: Some(Arc::clone(&server.processor.audit)),
                ..SessionConfig::with_buffer_capacity(256 * 1024)
            },
        );
        server
            .registry
            .insert(Arc::clone(&session))
            .expect("registry insert");
        (session, pty)
    }

    fn entries(path: &Path, kind: &str) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).expect("one JSON object a line"))
            .filter(|e| e["kind"] == kind)
            .collect()
    }

    fn data(r: &CallToolResult) -> Value {
        r.structured_content.clone().expect("a structured envelope")["data"].clone()
    }

    async fn settle(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !pred() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(pred(), "timed out waiting for {what}");
    }

    async fn read(server: &HoldfastServer, args: ReadOutputArgs) -> Value {
        data(
            &server
                .read_output(Parameters(args))
                .await
                .expect("read_output"),
        )
    }

    async fn screen(server: &HoldfastServer, id: &str, redact: Option<bool>) -> Value {
        data(
            &server
                .get_screen_state(Parameters(GetScreenStateArgs {
                    session: id.to_string(),
                    redact,
                    ..Default::default()
                }))
                .await
                .expect("get_screen_state"),
        )
    }

    async fn wait(server: &HoldfastServer, id: &str, pattern: Option<&str>, secs: u64) -> Value {
        let r = server
            .wait_for_pattern(Parameters(WaitForPatternArgs {
                session: id.to_string(),
                pattern: pattern.map(str::to_string),
                timeout_secs: Some(secs),
                since_cursor: Some(0),
                ..Default::default()
            }))
            .await
            .expect("wait_for_pattern");
        r.structured_content.expect("a structured envelope")
    }

    fn held(v: &Value) -> u64 {
        u64::from(v["held_back"] == true)
    }

    #[test]
    fn the_history_policy_is_the_mode_unless_the_call_names_what_it_yields_to() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };
        let file = History::File("/state/history/s.history");
        assert_eq!(
            history_policy(History::Discard, &[]),
            HistoryPolicy::Discard
        );
        assert_eq!(history_policy(file, &[]), HistoryPolicy::PerSession);
        // Each name the policy steps aside for, under both modes, and an
        // empty value counts: the policy yields to the name.
        for name in HISTORY_YIELDS_TO {
            for mode in [History::Discard, file] {
                assert_eq!(
                    history_policy(mode, &env(&[("PATH", "/bin"), (name, "")])),
                    HistoryPolicy::Caller,
                    "{name} under {mode:?}"
                );
            }
        }
        // A neighbour of those names is not one of them.
        assert_eq!(
            history_policy(
                History::Discard,
                &env(&[("HISTSIZE", "0"), ("PSQL_HISTORY", "x")])
            ),
            HistoryPolicy::Discard
        );
    }

    /// **Plan §4.9, end to end through the tools: one session's life of
    /// reads and waits becomes exactly one `session_stats` line, and each
    /// count on it is the one its surface caused.**
    ///
    /// Every expected number is taken from the responses the tools gave,
    /// not from a second model of the pipeline, so the row pins the
    /// accounting rather than the redactor. The arrangement is chosen so
    /// that each surface is reached, each `redaction_disabled` field takes
    /// both of its values somewhere, and both kinds of held-back read
    /// occur.
    #[tokio::test]
    async fn a_sessions_life_of_reads_and_waits_becomes_one_line_of_counts() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let started = Instant::now();
        let (s, pty) = audited_session(&server, "life");
        let id = s.id.clone();
        let cursor_read = |redact: Option<bool>| ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            redact,
            ..Default::default()
        };

        pty.queue_output(b"$ echo hi\nhi\n");
        settle("the clean output", || s.buffer_head() == 13).await;

        // A clean masked read, then a raw one: nothing came before it.
        let r1 = read(&server, cursor_read(None)).await;
        let r2 = read(&server, cursor_read(Some(false))).await;

        // A resource read of the same clean bytes: all of them.
        let head_at_resource = s.buffer_head();
        let uri = format!("holdfast://session/{id}/buffer?since_cursor=0");
        let (parsed, target) =
            crate::mcp::resources::prepare(&server.registry, &uri).expect("resource uri");
        crate::mcp::resources::read_prepared(
            &target,
            &server.processor,
            &parsed,
            &uri,
            1024 * 1024,
            caller::audit_surface(RESOURCE_READ_TOOL),
        );

        // A key that never ends: the masked read shows `unresolved`, and
        // the raw tail read after it says so.
        let key = unterminated_key();
        pty.queue_output(key.as_bytes());
        settle("the key", || s.buffer_head() == 13 + key.len() as u64).await;
        let r3 = read(&server, cursor_read(None)).await;
        assert!(
            r3["redactions"]["unresolved"].as_u64() >= Some(1),
            "the arrangement must show a marker, or `prior_unresolved` pins nothing: {r3}"
        );
        let r4 = read(
            &server,
            ReadOutputArgs {
                session: id.clone(),
                tail_bytes: Some(64),
                redact: Some(false),
                ..Default::default()
            },
        )
        .await;

        // A partial still arriving: the cursor read withholds it, the
        // grid masks it, and the raw grid after that has a marker before it.
        pty.queue_output(format!("\r\nsee {IN_FLIGHT}").as_bytes());
        let head_with_partial = 13 + key.len() as u64 + 6 + IN_FLIGHT.len() as u64;
        settle("the partial", || s.buffer_head() == head_with_partial).await;
        let r5 = read(&server, cursor_read(None)).await;
        assert_eq!(r5["held_back"], true, "the partial must be withheld: {r5}");
        let g1 = screen(&server, &id, None).await;
        assert_eq!(
            g1["held_back"], true,
            "the grid must mask the partial: {g1}"
        );
        let g2 = screen(&server, &id, Some(false)).await;

        // Three waits: one that matches, one that runs out, and one that
        // finds the child gone.
        let w1 = wait(&server, &id, Some("echo hi"), 5).await;
        assert_eq!(w1["status"], "ok", "{w1}");
        let w2 = wait(&server, &id, Some("NEVER_PRINTED"), 1).await;
        assert_eq!(w2["status"], "timeout", "{w2}");
        pty.exit(0);
        let w3 = wait(&server, &id, None, 5).await;
        assert_eq!(w3["status"], "session_died", "{w3}");

        assert!(
            entries(&log, "session_stats").is_empty(),
            "a line was written while the session was still live"
        );
        assert_eq!(server.registry.retire_exited(), 1);
        let lines = entries(&log, "session_stats");
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert_eq!(line["session_id"], id.as_str());

        let byte_reads = [&r1, &r2, &r3, &r4, &r5];
        let bytes: u64 = byte_reads
            .iter()
            .map(|r| r["bytes_returned"].as_u64().unwrap())
            .sum::<u64>()
            + head_at_resource;
        assert_eq!(line["bytes_returned"], bytes);
        assert_eq!(line["bytes_produced"], head_with_partial);
        assert_eq!(
            line["reads"],
            serde_json::json!({"cursor": 4, "tail": 1, "resource": 1, "screen": 2})
        );
        let held_back: u64 = [&r1, &r2, &r3, &r4, &r5, &g1, &g2]
            .iter()
            .map(|r| held(r))
            .sum();
        assert_eq!(line["reads_held_back"], held_back);
        assert_eq!(
            line["max_bytes_withheld"],
            head_with_partial - r5["cursor"].as_u64().unwrap()
        );
        assert_eq!(
            line["raw_reads"],
            serde_json::json!({"false": 3, "complete_only": 0})
        );
        assert_eq!(
            line["waits"],
            serde_json::json!({"matched": 1, "timeout": 1, "idle": 0, "session_died": 1})
        );
        let mut tally = s.redaction_stats();
        tally.entry(UNRESOLVED_KIND.to_string()).or_insert(0);
        assert_eq!(line["redactions"], serde_json::json!(tally));
        assert!(line["redactions"]["unresolved"].as_u64() >= Some(1));
        assert_eq!(line["shell"], "bash");
        assert_eq!(line["history_policy"], "none");
        assert_eq!(line["known_values_registered"], 0);
        // The session times itself on wall-clock milliseconds and this
        // test on a monotonic clock, so the ceiling has a little slack;
        // what it rules out is a duration from the wrong origin.
        let duration = line["duration_ms"].as_u64().unwrap();
        let ceiling = started.elapsed().as_millis() as u64 + 50;
        assert!(
            (1000..=ceiling).contains(&duration),
            "the one-second timeout is inside the session's life, and the life is \
             inside this test: {duration} ms, ceiling {ceiling} ms"
        );

        // Counts and names only: nothing the session printed is on it.
        let text = std::fs::read_to_string(&log).unwrap();
        let stats_line = text.lines().find(|l| l.contains("session_stats")).unwrap();
        for content in ["echo hi", "KEYBODY", "ghp_", "chain.pem"] {
            assert!(
                !stats_line.contains(content),
                "`{content}` reached the line"
            );
        }

        // The three raw reads, each with what it was and what came before.
        let raw = entries(&log, "redaction_disabled");
        assert_eq!(raw.len(), 3, "{raw:?}");
        assert_eq!(
            (
                raw[0]["start"].as_str(),
                raw[0]["prior_unresolved"].as_bool()
            ),
            (Some("cursor"), Some(false)),
            "the first raw read followed a clean one"
        );
        assert_eq!(raw[0]["bytes_returned"], r2["bytes_returned"]);
        assert_eq!(
            (
                raw[1]["start"].as_str(),
                raw[1]["prior_unresolved"].as_bool()
            ),
            (Some("tail"), Some(true)),
            "the raw tail read followed a read that showed a marker"
        );
        assert_eq!(raw[1]["bytes_returned"], r4["bytes_returned"]);
        assert_eq!(raw[2]["tool"], "get_screen_state");
        assert_eq!(
            (
                raw[2]["start"].as_str(),
                raw[2]["prior_unresolved"].as_bool()
            ),
            (Some("screen"), Some(true)),
            "the raw grid followed a masked grid"
        );
        let grid_text: u64 = g2["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().len() as u64)
            .sum::<u64>()
            + g2["title"].as_str().map_or(0, |t| t.len() as u64);
        assert_eq!(raw[2]["bytes_returned"], grid_text);
        for r in &raw {
            assert_eq!(r["mode"], "false");
        }

        // **Exactly one**: every other way to the line finds it taken.
        assert_eq!(server.registry.retire_exited(), 0);
        assert_eq!(server.registry.record_remaining_stats(), 0);
        assert!(!s.record_stats());
        drop(target);
        drop(s);
        drop(server);
        assert_eq!(entries(&log, "session_stats").len(), 1);
    }

    /// **Retire path 1, from `start_session`'s side.** A child that has
    /// exited is retired by the next reservation's sweep, which is the
    /// first thing `start_session` does to the registry, and its line is
    /// written then — not while it was live, and not twice.
    #[tokio::test]
    async fn an_exited_session_is_written_by_the_next_start_sessions_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, pty) = audited_session(&server, "exits");
        assert!(server.registry.reserve(None).is_ok());
        assert!(
            entries(&log, "session_stats").is_empty(),
            "written while live"
        );

        pty.exit(0);
        let claim = server.registry.reserve(None).expect("a slot");
        drop(claim);
        let lines = entries(&log, "session_stats");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["session_id"], s.id.as_str());
        let _ = server.registry.reserve(None);
        assert_eq!(entries(&log, "session_stats").len(), 1);
    }

    /// **Retire path 1, through `terminate`.** The tool ends the child;
    /// the sweep that follows writes the line.
    #[tokio::test]
    async fn a_terminated_session_gets_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, _pty) = audited_session(&server, "terminated");
        let r = server
            .terminate(Parameters(TerminateArgs {
                session: s.id.clone(),
                force: None,
                timeout_secs: None,
            }))
            .await
            .expect("terminate");
        assert_eq!(r.structured_content.expect("an envelope")["status"], "ok");
        assert!(!s.is_alive());
        assert_eq!(server.registry.retire_exited(), 1);
        let lines = entries(&log, "session_stats");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["session_id"], s.id.as_str());
        assert_eq!(lines[0]["reads"]["cursor"], 0, "terminate is not a read");
    }

    /// **Retire path 4, the backstop.** A session that reaches its end
    /// by no retire site at all — dropped out of a registry nobody swept —
    /// still writes its line, once.
    #[test]
    fn a_session_dropped_without_a_retire_still_gets_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, _pty) = audited_session(&server, "dropped");
        let id = s.id.clone();
        assert!(server.registry.remove(&id).is_some());
        assert!(entries(&log, "session_stats").is_empty());
        drop(s);
        let lines = entries(&log, "session_stats");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["session_id"], id.as_str());
    }

    /// **And a session built without a trail writes nothing**, wherever it
    /// ends — the default every hand-built session in this crate takes.
    #[test]
    fn a_session_with_no_audit_handle_writes_no_line() {
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::new(MockPty::new()) as Arc<dyn PtyBackend>,
            SessionConfig::default(),
        );
        assert!(!s.record_stats());
        assert!(
            !s.stats().recorded(),
            "nothing was claimed, because nothing can be written"
        );
    }

    /// **Exactly one, under contention.** Every retire path can race
    /// another — a daemon stopping while its tick sweeps — so the claim
    /// is one atomic swap, and this is what says it is.
    #[test]
    fn concurrent_writers_produce_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, _pty) = audited_session(&server, "raced");
        let wrote: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| usize::from(s.record_stats())))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(wrote, 1);
        assert_eq!(entries(&log, "session_stats").len(), 1);
    }

    /// The known-values PR's one call reaches the line, and nothing else
    /// does: until it is made, the field is present at zero.
    #[test]
    fn known_values_registered_is_a_count_set_through_the_stats_handle() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, _pty) = audited_session(&server, "known");
        assert_eq!(s.stats_record().known_values_registered, 0);
        s.stats().set_known_values_registered(3);
        assert!(s.record_stats());
        assert_eq!(
            entries(&log, "session_stats")[0]["known_values_registered"],
            3
        );
    }

    /// A pattern-less wait that sees the session at a prompt is `idle`,
    /// not `matched`: the two answer different questions.
    #[tokio::test]
    async fn a_pattern_less_wait_that_reaches_a_prompt_counts_as_idle() {
        let server = HoldfastServer::new();
        let (s, pty) = audited_session(&server, "idle");
        pty.queue_output(b"user@host:~$ ");
        settle("the prompt", || s.buffer_head() == 13).await;
        let w = wait(&server, &s.id, None, 5).await;
        assert_eq!(w["status"], "ok", "{w}");
        assert_eq!(w["data"]["reached"], true, "{w}");
        let record = s.stats_record();
        assert_eq!(
            record.waits,
            WaitCounts {
                idle: 1,
                ..WaitCounts::default()
            }
        );
    }

    /// A raw grid sent as a diff records the diff's length: the bytes the
    /// response carried, not the grid's.
    #[tokio::test]
    async fn a_raw_screen_diff_records_the_length_of_the_diff() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, pty) = audited_session(&server, "diff");
        pty.queue_output(b"line one\r\n");
        settle("the first line", || s.buffer_head() == 10).await;
        let first = screen(&server, &s.id, Some(false)).await;
        let revision = first["screen_revision"].as_u64().expect("a revision");
        pty.queue_output(b"line two\r\n");
        settle("the second line", || s.buffer_head() == 20).await;
        let delta = data(
            &server
                .get_screen_state(Parameters(GetScreenStateArgs {
                    session: s.id.clone(),
                    diff_from: Some(revision),
                    redact: Some(false),
                }))
                .await
                .expect("get_screen_state"),
        );
        let diff = delta["diff"].as_str().expect("a diff, not a full grid");
        let raw = entries(&log, "redaction_disabled");
        assert_eq!(raw.len(), 2);
        assert_eq!(raw[1]["start"], "screen");
        assert_eq!(raw[1]["bytes_returned"], diff.len() as u64);
        assert_eq!(s.stats_record().reads.screen, 2);
    }

    /// `session_start.env_base` on the row a real `start_session` writes,
    /// for each of the three hosts — the in-process server, a daemon
    /// serving a shim that sent its environment, and one serving a request
    /// that sent none — and `session_stats.history_policy` for a call
    /// whose own `env` named `HISTFILE`.
    #[tokio::test]
    async fn session_start_names_where_the_environment_came_from() {
        use crate::mcp::tools::StartSessionArgs;
        use crate::session::launch::{hosted_by_daemon, ClientLaunch};
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let cwd = dir.path().to_string_lossy().into_owned();
        let start = |env: Option<std::collections::HashMap<String, String>>| StartSessionArgs {
            command: Some("cat".into()),
            env,
            cwd: Some(cwd.clone()),
            ..Default::default()
        };

        server
            .start_session(Parameters(start(None)))
            .await
            .expect("in-process start");
        let client = ClientLaunch {
            cwd: Some(cwd.clone()),
            env: Some([("PATH".to_string(), "/usr/bin:/bin".to_string())].into()),
        };
        hosted_by_daemon(
            Some(client),
            server.start_session(Parameters(start(Some(
                [("HISTFILE".to_string(), "/dev/null".to_string())].into(),
            )))),
        )
        .await
        .expect("client-hosted start");
        hosted_by_daemon(None, server.start_session(Parameters(start(None))))
            .await
            .expect("daemon-hosted start");

        let started = entries(&log, "session_start");
        let bases: Vec<&str> = started
            .iter()
            .map(|e| e["env_base"].as_str().expect("env_base on every row"))
            .collect();
        assert_eq!(bases, ["in_process", "client", "daemon"]);

        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
        assert_eq!(server.registry.record_remaining_stats(), 3);
        let stats = entries(&log, "session_stats");
        let policy_of = |id: &Value| {
            stats
                .iter()
                .find(|e| e["session_id"] == *id)
                .map(|e| e["history_policy"].clone())
                .expect("a line for every session")
        };
        assert_eq!(policy_of(&started[0]["session_id"]), "none");
        assert_eq!(policy_of(&started[1]["session_id"]), "caller");
        assert_eq!(policy_of(&started[2]["session_id"]), "none");
        assert!(
            stats.iter().all(|e| e["shell"].is_null()),
            "`cat` is no shell"
        );
    }

    /// A wait's text is a masked read the caller saw, so it moves
    /// `prior_unresolved` like one: a clean `output_since_start` after a
    /// read that showed a marker clears it for the raw read that follows.
    #[tokio::test]
    async fn a_waits_text_is_the_masked_read_a_raw_read_follows() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, pty) = audited_session(&server, "waited");
        let key = unterminated_key();
        pty.queue_output(key.as_bytes());
        settle("the key", || s.buffer_head() == key.len() as u64).await;
        let masked = read(
            &server,
            ReadOutputArgs {
                session: s.id.clone(),
                since_cursor: Some(0),
                ..Default::default()
            },
        )
        .await;
        assert!(
            masked["redactions"]["unresolved"].as_u64() >= Some(1),
            "{masked}"
        );

        let after_key = s.buffer_head();
        pty.queue_output(b"$ echo CLEAN\nCLEAN\n");
        settle("the clean line", || s.buffer_head() > after_key + 18).await;
        let w = server
            .wait_for_pattern(Parameters(WaitForPatternArgs {
                session: s.id.clone(),
                pattern: Some("CLEAN\\n".into()),
                since_cursor: Some(after_key),
                timeout_secs: Some(5),
                ..Default::default()
            }))
            .await
            .expect("wait_for_pattern")
            .structured_content
            .expect("an envelope");
        assert_eq!(w["status"], "ok", "{w}");
        assert!(
            !w.to_string().contains("REDACTED:unresolved"),
            "the wait's text must be clean for this row to mean anything: {w}"
        );

        read(
            &server,
            ReadOutputArgs {
                session: s.id.clone(),
                since_cursor: Some(after_key),
                redact: Some(false),
                ..Default::default()
            },
        )
        .await;
        let raw = entries(&log, "redaction_disabled");
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw[0]["prior_unresolved"], false,
            "the wait's clean text came between the marker and the raw read"
        );
    }

    /// `max_bytes_withheld` is the widest gap one held-back read left
    /// before the buffer's head, not the gaps added up: a read retried
    /// against the same partial is the same hold, seen twice.
    #[tokio::test]
    async fn max_bytes_withheld_is_the_widest_hold_and_not_their_sum() {
        let server = HoldfastServer::new();
        let (s, pty) = audited_session(&server, "withheld");
        let bytes = format!("$ cat note\r\nsee {IN_FLIGHT}");
        pty.queue_output(bytes.as_bytes());
        let head = bytes.len() as u64;
        settle("the partial", || s.buffer_head() == head).await;
        let first = read(
            &server,
            ReadOutputArgs {
                session: s.id.clone(),
                since_cursor: Some(0),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(first["held_back"], true, "{first}");
        let stopped = first["cursor"].as_u64().unwrap();
        assert!(
            stopped < head,
            "the read must stop short of the head: {first}"
        );
        let second = read(
            &server,
            ReadOutputArgs {
                session: s.id.clone(),
                since_cursor: Some(stopped),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(second["held_back"], true, "{second}");
        assert_eq!(second["cursor"].as_u64(), Some(stopped), "{second}");

        let record = s.stats_record();
        assert_eq!(record.reads_held_back, 2);
        assert_eq!(record.max_bytes_withheld, head - stopped);
    }
}
