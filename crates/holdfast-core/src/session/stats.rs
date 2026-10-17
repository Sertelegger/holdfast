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
//! **The agent's activity, with the operator's kept apart.** The field
//! week's questions are about what an agent did, so `reads`, `raw_reads`,
//! `waits`, the held-back figures and `prior_unresolved` count only calls
//! whose `client_kind` is the agent's (`shim`, `in_process`). A human's
//! `holdfast logs` page is a `read_output` call too, and lands in
//! `operator_reads` instead. See [`Party`].
//!
//! ## When the line is written, and why once
//!
//! When the session leaves the registry, or the process that holds it
//! ends. The code reaches that four ways:
//!
//! 1. **The registry evicts its record.** A session whose child is gone
//!    is retired into the completed records by `SessionRegistry`'s sweep,
//!    which latches when it ended and leaves it readable (§5.5.1). The
//!    line waits until the retention bounds push that record out, so
//!    a read of a finished session's output, which is the read most
//!    likely to show a marker, is still counted on it. The sweep
//!    runs from `start_session`'s reservation, from `insert`, and from
//!    the daemon's periodic tick, and writes once the registry's lock is
//!    released.
//! 2. **The daemon stops** — `Daemon::shutdown` and
//!    `Daemon::shutdown_graceful` write it for every session that has
//!    none yet, live or retired, after signalling them.
//! 3. **`holdfast mcp --no-daemon` ends**, by its client closing stdin or
//!    by `SIGTERM`, `SIGHUP` or `SIGINT` — `mcp::serve_until` does the
//!    same, since its sessions die with it.
//! 4. **The `Session` is dropped any other way** — `Drop`, the backstop.
//!
//! A flag makes those one write: whichever comes first writes, and the
//! rest find it taken. A session built without an audit handle (most
//! tests) writes nothing.
//!
//! **What is lost, and when.** A process that dies without running any of
//! those (`SIGKILL`, a crash) writes no line for any session it held, live
//! or retired.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use super::launch::{History, HISTFILE_CARRIER};
use super::Session;
use crate::audit::{
    AuditLog, HistoryPolicy, RawRead, RawReadCounts, ReadAnchor, ReadCounts, RedactionMode,
    SessionStatsRecord, WaitCounts,
};
use crate::detect::shell::{detect_shell, Shell};
use crate::mcp::caller::{AuditSurface, Caller};
use crate::mcp::resources::RESOURCE_READ_TOOL;
use crate::output::redact::{marker, UNRESOLVED_KIND};
use crate::output::{OutputProcessor, ProcessedRead, ReadRequest};
use crate::screen::ScreenCapture;

/// The `tool` `read_output` passes on its `ReadRequest` — the literal at
/// its `caller::audit_surface` call.
const READ_OUTPUT_TOOL: &str = "read_output";

/// The variable fish reads its history session from.
const FISH_HISTORY: &str = "fish_history";

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

/// Whose call it was, from §9.4's `client_kind`.
///
/// **Attribution, and only for the counts.** It picks which counters a
/// call lands in and never what a read returns: nothing that reads it
/// reaches the redaction pipeline, which is REQ-SEC-018's rule for
/// `client_kind` (`mcp::caller`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// `shim`, and `in_process`: `holdfast mcp --no-daemon` and Windows,
    /// where only the MCP server runs, or a daemon call with no caller
    /// scope, which §9.4 spells apart and which is not a human's.
    Agent,
    /// `cli` (`holdfast logs`) and `ui-bridge`: a human at a terminal or
    /// a browser.
    Operator,
}

impl Party {
    pub fn of(client_kind: &str) -> Self {
        if [Caller::Cli, Caller::UiBridge]
            .iter()
            .any(|c| c.as_str() == client_kind)
        {
            Self::Operator
        } else {
            Self::Agent
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Agent => 0,
            Self::Operator => 1,
        }
    }
}

/// What `session_stats.history_policy` says for a session running
/// `shell` (`None` for a command Holdfast does not recognise as one),
/// started under `history` with the call's or profile's own `explicit`
/// environment.
///
/// [`HistoryPolicy::Caller`] when `explicit` sets a variable that the
/// policy steps aside for and that this shell reads:
/// - bash and zsh: `HISTFILE` or [`HISTFILE_CARRIER`], whatever the value,
///   which `launch::history_defaults` then leaves alone;
/// - fish: a non-empty `fish_history`, for which
///   `detect::shell::history_spawn_args` drops fish's history init (an
///   empty one is Holdfast's own default restated, and the init still
///   runs);
/// - any other command: either, since a shell it starts reads the
///   environment it was given.
///
/// Otherwise the configured mode, which is what the shell got.
pub fn history_policy(
    history: History<'_>,
    shell: Option<Shell>,
    explicit: &[(String, String)],
) -> HistoryPolicy {
    let names = |key: &str| explicit.iter().any(|(k, _)| k == key);
    let posix = names("HISTFILE") || names(HISTFILE_CARRIER);
    let fish = explicit
        .iter()
        .any(|(k, v)| k == FISH_HISTORY && !v.is_empty());
    let yielded = match shell {
        Some(Shell::Bash | Shell::Zsh) => posix,
        Some(Shell::Fish) => fish,
        None => posix || fish,
    };
    if yielded {
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

/// When the session's child was first seen gone, on the session's own
/// clock; 0 until then.
///
/// Shared with the session's reader thread, which sees the exit when the
/// pty closes, so the end does not wait for something to ask. Every other
/// observer (`state`, `exited_at_secs`, the registry's sweep) latches it
/// too, and the first one wins.
#[derive(Debug, Clone, Default)]
pub(crate) struct EndLatch(Arc<AtomicI64>);

impl EndLatch {
    pub(crate) fn latch(&self, now_ms: i64) {
        let _ = self
            .0
            .compare_exchange(0, now_ms, Ordering::Relaxed, Ordering::Relaxed);
    }

    fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// One session's counters. Held by [`Session`]; reached through
/// [`Session::stats`].
///
/// The API the later 0.0.9 PRs call:
/// - the known-values PR (K, #253) calls
///   [`SessionStats::set_known_values_registered`] each time its matcher
///   grows;
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
    end: EndLatch,
    known_values_registered: AtomicU64,
    reads_cursor: AtomicU64,
    reads_tail: AtomicU64,
    reads_resource: AtomicU64,
    reads_screen: AtomicU64,
    reads_held_back: AtomicU64,
    max_bytes_withheld: AtomicU64,
    bytes_returned: AtomicU64,
    /// Agent reads whose response showed an `[REDACTED:unresolved]`.
    reads_unresolved: AtomicU64,
    /// Reads by a human, every surface; none of the counters above.
    operator_reads: AtomicU64,
    raw_false: AtomicU64,
    /// Never incremented until `RedactionMode` has a `CompleteOnly` (C).
    raw_complete_only: AtomicU64,
    waits_matched: AtomicU64,
    waits_timeout: AtomicU64,
    waits_idle: AtomicU64,
    waits_session_died: AtomicU64,
    /// Whether each party's most recent masked read showed an
    /// `unresolved` marker, indexed by [`Party::index`]: a human's
    /// `holdfast logs` does not answer for what the agent saw.
    last_masked_unresolved: [AtomicBool; 2],
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
            end: EndLatch::default(),
            known_values_registered: AtomicU64::new(0),
            reads_cursor: AtomicU64::new(0),
            reads_tail: AtomicU64::new(0),
            reads_resource: AtomicU64::new(0),
            reads_screen: AtomicU64::new(0),
            reads_held_back: AtomicU64::new(0),
            max_bytes_withheld: AtomicU64::new(0),
            bytes_returned: AtomicU64::new(0),
            reads_unresolved: AtomicU64::new(0),
            operator_reads: AtomicU64::new(0),
            raw_false: AtomicU64::new(0),
            raw_complete_only: AtomicU64::new(0),
            waits_matched: AtomicU64::new(0),
            waits_timeout: AtomicU64::new(0),
            waits_idle: AtomicU64::new(0),
            waits_session_died: AtomicU64::new(0),
            last_masked_unresolved: [AtomicBool::new(false), AtomicBool::new(false)],
            recorded: AtomicBool::new(false),
        }
    }

    /// The known-values PR's (K, #253) call: how many values the
    /// session's matcher holds, **in total**, each time it grows — at
    /// spawn and at each later registration. A running total rather than
    /// an increment, so two call sites cannot double-count a value, and
    /// kept at its maximum, so a caller holding an older total cannot
    /// lower it. A count; the values never reach this type.
    pub fn set_known_values_registered(&self, total: u64) {
        self.known_values_registered
            .fetch_max(total, Ordering::Relaxed);
    }

    pub fn history_policy(&self) -> HistoryPolicy {
        self.history_policy
    }

    /// The latch the reader thread shares.
    pub(crate) fn end_latch(&self) -> EndLatch {
        self.end.clone()
    }

    /// Count one read by `party`: its surface, the raw bytes it handed
    /// over, what it withheld, and whether it showed an `unresolved`
    /// marker. `withheld` is the gap a held-back byte-stream read left
    /// before the buffer's head; the grid passes 0. A human's read counts
    /// once, in `operator_reads`, and in nothing else.
    pub(crate) fn note_read(
        &self,
        party: Party,
        surface: ReadSurface,
        raw_bytes: u64,
        held_back: bool,
        withheld: u64,
        unresolved: bool,
    ) {
        if party == Party::Operator {
            self.operator_reads.fetch_add(1, Ordering::Relaxed);
            return;
        }
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
        if unresolved {
            self.reads_unresolved.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A masked read by `party` finished: remember whether it showed an
    /// `unresolved` marker, for that party's next raw read.
    pub(crate) fn note_masked(&self, party: Party, unresolved: bool) {
        self.last_masked_unresolved[party.index()].store(unresolved, Ordering::Relaxed);
    }

    /// Count one read by `party` that was not fully masked, and return
    /// `prior_unresolved` for its `redaction_disabled` line: whether the
    /// same party's most recent masked read showed a marker. It does not
    /// move that flag, since a raw read is not a masked one. A human's
    /// raw read is on its `redaction_disabled` line and in
    /// `operator_reads`, not in `raw_reads`.
    pub fn note_raw(&self, party: Party, mode: RedactionMode) -> bool {
        let counter = match mode {
            RedactionMode::False => &self.raw_false,
        };
        if party == Party::Agent {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.last_masked_unresolved[party.index()].load(Ordering::Relaxed)
    }

    /// Count one wait by `party`. A human's wait is counted nowhere: no
    /// operator surface waits today, and `waits` is the agent's.
    pub(crate) fn note_wait(&self, party: Party, result: WaitResult) {
        if party == Party::Operator {
            return;
        }
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
        self.end.latch(now_ms);
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
        let party = Party::of(req.client_kind);
        let surface = match req.tool {
            READ_OUTPUT_TOOL if req.start.is_tail() => Some(ReadSurface::Tail),
            READ_OUTPUT_TOOL => Some(ReadSurface::Cursor),
            RESOURCE_READ_TOOL => Some(ReadSurface::Resource),
            _ => None,
        };
        let unresolved = shows_unresolved(read);
        if let Some(surface) = surface {
            self.stats.note_read(
                party,
                surface,
                read.bytes_returned as u64,
                read.held_back,
                head.saturating_sub(read.cursor),
                unresolved,
            );
        }
        let mode = (!req.options.redact).then_some(RedactionMode::False);
        match mode {
            None if surface.is_some() => self.stats.note_masked(party, unresolved),
            None => {}
            Some(mode) => {
                let prior_unresolved = self.stats.note_raw(party, mode);
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
    /// `redaction_disabled` with `start: "screen"` when `mode` says the
    /// grid was not fully masked (`None` is the default, masked grid).
    /// `surface` was sampled by the caller before the capture left its
    /// task.
    pub fn account_screen_read(
        &self,
        mode: Option<RedactionMode>,
        capture: &ScreenCapture,
        surface: AuditSurface,
        audit: &AuditLog,
    ) {
        let party = Party::of(surface.client_kind);
        let unresolved_marker = marker(UNRESOLVED_KIND);
        // A marker in a raw grid is the child's own text: the redactor
        // put none there.
        let marks = match mode {
            None => true,
            Some(RedactionMode::False) => false,
        };
        let (text_bytes, held_back, unresolved) = match capture {
            ScreenCapture::Full(g) => (
                g.lines.iter().map(String::len).sum::<usize>()
                    + g.title.as_ref().map_or(0, String::len),
                g.held_back,
                marks
                    && g.lines
                        .iter()
                        .chain(g.title.iter())
                        .any(|l| l.contains(&unresolved_marker)),
            ),
            ScreenCapture::Delta(d) => (
                d.diff.len(),
                d.held_back,
                marks && d.diff.contains(&unresolved_marker),
            ),
        };
        self.stats
            .note_read(party, ReadSurface::Screen, 0, held_back, 0, unresolved);
        let Some(mode) = mode else {
            self.stats.note_masked(party, unresolved);
            return;
        };
        let prior_unresolved = self.stats.note_raw(party, mode);
        audit.record_redaction_disabled(
            Some(&self.id),
            &RawRead {
                tool: surface.tool,
                client_kind: surface.client_kind,
                mode,
                start: ReadAnchor::Screen,
                bytes_returned: text_bytes as u64,
                prior_unresolved,
            },
        );
    }

    /// The accounting of one wait by `client_kind`. `text_unresolved` is
    /// whether the text the wait returned (`output_since_start`,
    /// `match.text`) showed an `unresolved` marker, or `None` when it
    /// returned no text.
    pub fn account_wait(
        &self,
        client_kind: &str,
        result: WaitResult,
        text_unresolved: Option<bool>,
    ) {
        let party = Party::of(client_kind);
        self.stats.note_wait(party, result);
        if let Some(unresolved) = text_unresolved {
            self.stats.note_masked(party, unresolved);
        }
    }

    /// The `session_stats` line as it would be written now.
    pub fn stats_record(&self) -> SessionStatsRecord {
        let s = &self.stats;
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        // A child that is gone and that nothing has observed yet ends
        // here, through the latch every other observer uses. The reader
        // thread and the sweep that retires a session normally got there
        // first; this covers a record written before either has run.
        if !self.backend.is_alive() {
            self.latch_exit_time();
        }
        let ended_ms = match s.end.get() {
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
            reads_unresolved: load(&s.reads_unresolved),
            operator_reads: load(&s.operator_reads),
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
    use crate::clock::Clock;
    use crate::mcp::caller;
    use crate::mcp::tools::{
        GetScreenStateArgs, ReadOutputArgs, TerminateArgs, WaitForPatternArgs,
    };
    use crate::mcp::HoldfastServer;
    use crate::pty::{MockPty, PtyBackend};
    use crate::session::launch::history_defaults;
    use crate::session::registry::{Retention, SessionRegistry};
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

    fn mock_config(server: &HoldfastServer) -> SessionConfig {
        SessionConfig {
            audit: Some(Arc::clone(&server.processor.audit)),
            ..SessionConfig::with_buffer_capacity(256 * 1024)
        }
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
            mock_config(server),
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

    /// `read_output` as `holdfast logs` sends it: the same tool, from a
    /// `cli` connection.
    async fn read_as_cli(server: &HoldfastServer, args: ReadOutputArgs) -> Value {
        data(
            &caller::with_caller(caller::Caller::Cli, server.read_output(Parameters(args)))
                .await
                .expect("read_output"),
        )
    }

    fn from(id: &str, cursor: u64, redact: Option<bool>) -> ReadOutputArgs {
        ReadOutputArgs {
            session: id.to_string(),
            since_cursor: Some(cursor),
            redact,
            ..Default::default()
        }
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

    fn shows_marker(v: &Value) -> bool {
        v.to_string().contains("[REDACTED:unresolved]")
    }

    /// The `prior_unresolved` of each `redaction_disabled` line so far.
    fn priors(log: &Path) -> Vec<bool> {
        entries(log, "redaction_disabled")
            .iter()
            .map(|e| e["prior_unresolved"].as_bool().expect("a bool"))
            .collect()
    }

    /// A session that has printed an unterminated key, after a masked
    /// read of it was clean, so the agent's flag is `false` and the next
    /// surface to show the marker is the only thing that can set it.
    async fn key_after_a_clean_read(
        server: &HoldfastServer,
        name: &str,
    ) -> (Arc<Session>, Arc<MockPty>, u64) {
        let (s, pty) = audited_session(server, name);
        pty.queue_output(b"$ echo hi\nhi\n");
        settle("the clean line", || s.buffer_head() == 13).await;
        let clean = read(server, from(&s.id, 0, None)).await;
        assert!(!shows_marker(&clean), "{clean}");
        let key = unterminated_key();
        pty.queue_output(key.as_bytes());
        let head = 13 + key.len() as u64;
        settle("the key", || s.buffer_head() == head).await;
        (s, pty, head)
    }

    /// **GH #252's yield, per shell, judged by the code that applies the
    /// policy rather than by a list beside it.** For each shell and each
    /// environment, `caller` is expected exactly when that environment
    /// changes what the shell is given: bash and zsh read what
    /// `launch::history_defaults` leaves of `HISTFILE` and its carrier,
    /// fish reads what `detect::shell::history_spawn_args` puts ahead of
    /// its arguments, and an unrecognised command passes the environment
    /// to any shell it starts, so it is either.
    #[test]
    fn the_history_policy_yields_only_to_a_variable_the_sessions_shell_reads() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };
        let envs = [
            env(&[]),
            env(&[("PATH", "/bin")]),
            env(&[("HISTFILE", "/tmp/mine")]),
            env(&[("HISTFILE", "")]),
            env(&[(HISTFILE_CARRIER, "/tmp/mine")]),
            env(&[(FISH_HISTORY, "work")]),
            env(&[(FISH_HISTORY, "")]),
            env(&[("HISTSIZE", "0"), ("PSQL_HISTORY", "x")]),
        ];
        let holdfasts = history_defaults(History::Discard, &[]);
        let posix_changed = |e: &[(String, String)]| {
            let given = history_defaults(History::Discard, e);
            ["HISTFILE", HISTFILE_CARRIER].iter().any(|name| {
                let pick = |set: &[(String, String)]| {
                    set.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
                };
                pick(&given) != pick(&holdfasts)
            })
        };
        let fish_changed = |e: &[(String, String)]| {
            crate::detect::shell::history_spawn_args("fish", &[], e)
                != crate::detect::shell::history_spawn_args("fish", &[], &[])
        };
        let mut caller_seen = [false; 3];
        for e in &envs {
            for (shell, expected) in [
                (Some(Shell::Bash), posix_changed(e)),
                (Some(Shell::Zsh), posix_changed(e)),
                (Some(Shell::Fish), fish_changed(e)),
                (None, posix_changed(e) || fish_changed(e)),
            ] {
                for (mode, configured) in [
                    (History::Discard, HistoryPolicy::Discard),
                    (History::File("/state/s.history"), HistoryPolicy::PerSession),
                ] {
                    let got = history_policy(mode, shell, e);
                    let want = if expected {
                        HistoryPolicy::Caller
                    } else {
                        configured
                    };
                    assert_eq!(got, want, "{shell:?} under {mode:?} with {e:?}");
                    if expected {
                        caller_seen[match shell {
                            Some(Shell::Bash | Shell::Zsh) => 0,
                            Some(Shell::Fish) => 1,
                            None => 2,
                        }] = true;
                    }
                }
            }
        }
        assert_eq!(
            caller_seen, [true; 3],
            "every shell reaches `caller` from some environment, or a row above pins nothing"
        );
        // The rows the reviews named, as literals: a name the shell does
        // not read is no yield.
        let bash_fish = history_policy(
            History::Discard,
            Some(Shell::Bash),
            &env(&[(FISH_HISTORY, "x")]),
        );
        assert_eq!(bash_fish, HistoryPolicy::Discard);
        let fish_hist = history_policy(
            History::Discard,
            Some(Shell::Fish),
            &env(&[("HISTFILE", "/x")]),
        );
        assert_eq!(fish_hist, HistoryPolicy::Discard);
        let fish_empty = history_policy(
            History::Discard,
            Some(Shell::Fish),
            &env(&[(FISH_HISTORY, "")]),
        );
        assert_eq!(fish_empty, HistoryPolicy::Discard);
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
        let cursor_read = |redact: Option<bool>| from(&id, 0, redact);

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

        // Retired, and still read: the line waits for the record to go.
        assert_eq!(server.registry.retire_exited(), 1);
        assert!(
            entries(&log, "session_stats").is_empty(),
            "a line was written while the session was still readable"
        );
        assert_eq!(server.registry.record_remaining_stats(), 1);
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
        // The masked reads that showed a marker. The resource read was of
        // the clean bytes, and a raw read shows none the redactor put there.
        let unresolved: u64 = [&r1, &r3, &r5, &g1]
            .iter()
            .map(|r| u64::from(shows_marker(r)))
            .sum();
        assert!(unresolved >= 1, "the arrangement shows no marker");
        assert_eq!(line["reads_unresolved"], unresolved);
        assert_eq!(line["operator_reads"], 0);
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

    /// **Retire path 1: the line waits for eviction, so a read of a
    /// finished session is on it.** The next `start_session`'s sweep
    /// retires the exited child; the agent then reads the finished
    /// command's output, raw — the read most likely to follow a marker —
    /// and that read is counted. The line is written when the retention
    /// bound pushes the record out, here by a second session finishing
    /// past a one-record bound, and not twice.
    #[tokio::test]
    async fn a_finished_sessions_line_is_written_at_eviction_with_its_late_reads_on_it() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let mut server = server_logging_to(&log);
        server.registry = Arc::new(SessionRegistry::with_retention(
            8,
            Retention {
                max_records: 1,
                max_bytes: u64::MAX,
            },
        ));
        let (first, first_pty) = audited_session(&server, "first");
        first_pty.queue_output(b"$ make\nok\n");
        settle("the output", || first.buffer_head() == 10).await;
        first_pty.exit(0);
        drop(server.registry.reserve(None).expect("a slot"));
        assert!(
            server.registry.get(&first.id).is_ok(),
            "the retired record is still readable"
        );
        assert!(
            entries(&log, "session_stats").is_empty(),
            "written at retire, before the read below could be counted"
        );

        read(&server, from(&first.id, 0, Some(false))).await;
        assert_eq!(entries(&log, "redaction_disabled").len(), 1);

        let (second, second_pty) = audited_session(&server, "second");
        second_pty.exit(0);
        assert_eq!(server.registry.retire_exited(), 1);
        let lines = entries(&log, "session_stats");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["session_id"], first.id.as_str());
        assert_eq!(
            lines[0]["reads"]["cursor"], 1,
            "the late read: {}",
            lines[0]
        );
        assert_eq!(lines[0]["raw_reads"]["false"], 1);
        assert_eq!(lines[0]["bytes_returned"], 10);

        assert_eq!(server.registry.retire_exited(), 0);
        assert_eq!(
            server.registry.record_remaining_stats(),
            1,
            "the second's line"
        );
        assert_eq!(entries(&log, "session_stats").len(), 2);
        drop(second);
    }

    /// **Retire path 1, through `terminate`.** The tool ends the child;
    /// the sweep that follows retires it, and a stop writes its line.
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
        assert_eq!(server.registry.record_remaining_stats(), 1);
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

    /// **The end is the exit the reader thread saw, not the next call
    /// that asks.** Under `--no-daemon` nothing ticks, so a session
    /// nobody looks at after its child exits is next observed when the
    /// line is written, which may be hours later. On a manual clock: five
    /// seconds of life, then an hour in which nothing asks.
    #[tokio::test]
    async fn duration_ends_at_the_exit_the_reader_saw_however_late_the_line_is() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let clock = Clock::manual(Instant::now());
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig {
                clock: clock.clone(),
                ..mock_config(&server)
            },
        );
        clock.advance(Duration::from_secs(5));
        pty.exit(0);
        // `end.get` asks nobody: `state()` or `exited_at_secs()` here would
        // be the observation this row is about not needing.
        settle("the reader to see the exit", || s.stats.end.get() != 0).await;
        clock.advance(Duration::from_secs(3600));
        assert!(s.record_stats());
        assert_eq!(entries(&log, "session_stats")[0]["duration_ms"], 5_000);
    }

    /// A child that has exited while something it started still holds
    /// the pty open and writing, so the reader thread never sees an end.
    #[derive(Debug)]
    struct HeldOpen(Arc<MockPty>);

    impl PtyBackend for HeldOpen {
        fn write(&self, data: &[u8]) -> crate::Result<()> {
            self.0.write(data)
        }
        fn read(&self, buf: &mut [u8]) -> crate::Result<usize> {
            std::thread::sleep(Duration::from_millis(20));
            buf[0] = b'.';
            Ok(1)
        }
        fn signal(&self, sig: crate::pty::Signal) -> crate::Result<()> {
            self.0.signal(sig)
        }
        fn resize(&self, cols: u16, rows: u16) -> crate::Result<()> {
            self.0.resize(cols, rows)
        }
        fn is_alive(&self) -> bool {
            self.0.is_alive()
        }
        fn exit_code(&self) -> Option<i32> {
            self.0.exit_code()
        }
        fn pid(&self) -> Option<u32> {
            self.0.pid()
        }
    }

    /// **And when the reader cannot see the exit, the sweep that retires
    /// the session does.** A background job holding the pty keeps the
    /// reader reading after the shell is gone; the retire is then the
    /// first observation, and the record, written at eviction or at a
    /// stop an hour later, ends there.
    #[test]
    fn duration_ends_at_the_retire_when_the_reader_never_sees_the_exit() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let clock = Clock::manual(Instant::now());
        let child = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            None,
            "bash".into(),
            vec![],
            Arc::new(HeldOpen(Arc::clone(&child))) as Arc<dyn PtyBackend>,
            SessionConfig {
                clock: clock.clone(),
                ..mock_config(&server)
            },
        );
        server.registry.insert(Arc::clone(&s)).unwrap();
        clock.advance(Duration::from_secs(5));
        child.exit(0);
        assert_eq!(server.registry.retire_exited(), 1);
        clock.advance(Duration::from_secs(3600));
        assert_eq!(server.registry.record_remaining_stats(), 1);
        assert_eq!(entries(&log, "session_stats")[0]["duration_ms"], 5_000);
    }

    /// The known-values PR's call reaches the line, and nothing else
    /// does: until it is made, the field is present at zero. It takes the
    /// matcher's running total, so a later call with an older, smaller
    /// total cannot lower it.
    #[test]
    fn known_values_registered_is_the_largest_total_reported() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, _pty) = audited_session(&server, "known");
        assert_eq!(s.stats_record().known_values_registered, 0);
        s.stats().set_known_values_registered(3);
        s.stats().set_known_values_registered(5);
        s.stats().set_known_values_registered(4);
        assert!(s.record_stats());
        assert_eq!(
            entries(&log, "session_stats")[0]["known_values_registered"],
            5
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

    /// A **pattern** wait that finds the child gone is `session_died`, from
    /// the pattern path's own mapping rather than the pattern-less one.
    #[tokio::test]
    async fn a_pattern_wait_on_a_dead_session_counts_as_session_died() {
        let server = HoldfastServer::new();
        let (s, pty) = audited_session(&server, "dead");
        pty.exit(0);
        let w = wait(&server, &s.id, Some("NEVER_PRINTED"), 5).await;
        assert_eq!(w["status"], "session_died", "{w}");
        assert_eq!(
            s.stats_record().waits,
            WaitCounts {
                session_died: 1,
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

    /// A raw full grid's size counts its window title as well as its rows:
    /// both are text the response handed over.
    #[tokio::test]
    async fn a_raw_grid_counts_its_title_in_bytes_returned() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, pty) = audited_session(&server, "titled");
        let bytes = b"\x1b]0;a-window-title\x07line one\r\n";
        pty.queue_output(bytes);
        settle("the line", || s.buffer_head() == bytes.len() as u64).await;
        let g = screen(&server, &s.id, Some(false)).await;
        let title = g["title"].as_str().expect("the grid carries the title");
        assert_eq!(title, "a-window-title");
        let rows: u64 = g["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().len() as u64)
            .sum();
        assert_eq!(
            entries(&log, "redaction_disabled")[0]["bytes_returned"],
            rows + title.len() as u64
        );
    }

    /// `session_start.env_base` on the row a real `start_session` writes,
    /// for each of the three hosts — the in-process server, a daemon
    /// serving a shim that sent its environment, and one serving a request
    /// that sent none — and for a **profile** session under a shim that
    /// sent its environment, which runs on the daemon's (`base_env`'s
    /// `profile` arm). And `session_stats.history_policy` for a call whose
    /// own `env` named `HISTFILE`.
    #[tokio::test]
    async fn session_start_names_where_the_environment_came_from() {
        use crate::config::SessionProfile;
        use crate::mcp::tools::StartSessionArgs;
        use crate::session::launch::{hosted_by_daemon, ClientLaunch};
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let mut config = crate::config::parse_str("").expect("the shipped default");
        config.security.profiles = vec![SessionProfile {
            name: "say-hi".into(),
            program: "echo".into(),
            args: vec!["hi".into()],
            vars: Default::default(),
            env: Default::default(),
            cwd: None,
        }];
        config.validate().expect("a profile an operator could load");
        let server = HoldfastServer::with_audit_path_and_config(Some(log.clone()), &config);
        let cwd = dir.path().to_string_lossy().into_owned();
        let start = |env: Option<std::collections::HashMap<String, String>>| StartSessionArgs {
            command: Some("cat".into()),
            env,
            cwd: Some(cwd.clone()),
            ..Default::default()
        };
        let client = || ClientLaunch {
            cwd: Some(cwd.clone()),
            env: Some([("PATH".to_string(), "/usr/bin:/bin".to_string())].into()),
        };

        server
            .start_session(Parameters(start(None)))
            .await
            .expect("in-process start");
        hosted_by_daemon(
            Some(client()),
            server.start_session(Parameters(start(Some(
                [("HISTFILE".to_string(), "/dev/null".to_string())].into(),
            )))),
        )
        .await
        .expect("client-hosted start");
        hosted_by_daemon(None, server.start_session(Parameters(start(None))))
            .await
            .expect("daemon-hosted start");
        hosted_by_daemon(
            Some(client()),
            server.start_session(Parameters(StartSessionArgs {
                profile: Some("say-hi".into()),
                ..Default::default()
            })),
        )
        .await
        .expect("profile start");

        let started = entries(&log, "session_start");
        let bases: Vec<&str> = started
            .iter()
            .map(|e| e["env_base"].as_str().expect("env_base on every row"))
            .collect();
        assert_eq!(bases, ["in_process", "client", "daemon", "daemon"]);
        assert_eq!(started[3]["profile"], "say-hi");

        for s in server.registry.all() {
            let _ = s.signal(crate::pty::Signal::Kill);
        }
        assert_eq!(server.registry.record_remaining_stats(), 4);
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
            "`cat` and `echo` are no shell"
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
        let masked = read(&server, from(&s.id, 0, None)).await;
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
        assert!(!shows_marker(&w), "the wait's text must be clean: {w}");

        read(&server, from(&s.id, after_key, Some(false))).await;
        assert_eq!(
            priors(&log),
            [false],
            "the wait's clean text came between the marker and the raw read"
        );
    }

    /// **The other direction, from each surface that is not a cursor
    /// read**: a pattern wait's `output_since_start`, its `match.text`
    /// alone, a masked grid and a masked resource read, each showing a
    /// marker after a clean read, set `prior_unresolved` for the raw read
    /// that follows. One session per surface, so no row inherits the flag
    /// from another.
    #[tokio::test]
    async fn every_masked_surface_that_shows_a_marker_sets_prior_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);

        // A pattern wait whose context reaches the key.
        let (s, _pty, head) = key_after_a_clean_read(&server, "context").await;
        let w = server
            .wait_for_pattern(Parameters(WaitForPatternArgs {
                session: s.id.clone(),
                pattern: Some("echo hi".into()),
                since_cursor: Some(0),
                timeout_secs: Some(5),
                ..Default::default()
            }))
            .await
            .expect("wait_for_pattern")
            .structured_content
            .expect("an envelope");
        assert!(shows_marker(&w["data"]["output_since_start"]), "{w}");
        read(&server, from(&s.id, head, Some(false))).await;

        // A pattern wait whose context stops short of the key and whose
        // match is inside it, so only `match.text` shows the marker.
        let (s, _pty, head) = key_after_a_clean_read(&server, "match").await;
        let w = server
            .wait_for_pattern(Parameters(WaitForPatternArgs {
                session: s.id.clone(),
                pattern: Some("(?s)-----BEGIN RSA PRIVATE KEY-----.*KEYBODY000003".into()),
                since_cursor: Some(0),
                max_bytes: Some(8),
                timeout_secs: Some(5),
            }))
            .await
            .expect("wait_for_pattern")
            .structured_content
            .expect("an envelope");
        assert_eq!(w["status"], "ok", "{w}");
        assert!(
            !shows_marker(&w["data"]["output_since_start"]) && shows_marker(&w["data"]["match"]),
            "only the match text may show the marker here: {w}"
        );
        read(&server, from(&s.id, head, Some(false))).await;

        // A masked grid.
        let (s, _pty, head) = key_after_a_clean_read(&server, "grid").await;
        let g = screen(&server, &s.id, None).await;
        assert!(shows_marker(&g), "{g}");
        read(&server, from(&s.id, head, Some(false))).await;

        // A masked resource read.
        let (s, _pty, head) = key_after_a_clean_read(&server, "resource").await;
        let uri = format!("holdfast://session/{}/buffer?since_cursor=0", s.id);
        let (parsed, target) =
            crate::mcp::resources::prepare(&server.registry, &uri).expect("resource uri");
        let r = crate::mcp::resources::read_prepared(
            &target,
            &server.processor,
            &parsed,
            &uri,
            1024 * 1024,
            caller::audit_surface(RESOURCE_READ_TOOL),
        );
        assert!(
            serde_json::to_string(&r)
                .unwrap()
                .contains("[REDACTED:unresolved]"),
            "the resource read must show the marker"
        );
        read(&server, from(&s.id, head, Some(false))).await;

        assert_eq!(priors(&log), [true; 4]);
    }

    /// **A human's reads are not the agent's.** `holdfast logs` and
    /// `holdfast logs --raw` reach the daemon as `read_output` from a `cli`
    /// connection: they land in `operator_reads` and nowhere else, and
    /// what they show does not move the agent's `prior_unresolved`. The
    /// operator's own raw read answers for the operator's own masked one.
    #[tokio::test]
    async fn an_operators_reads_are_counted_apart_from_the_agents() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let server = server_logging_to(&log);
        let (s, _pty, head) = key_after_a_clean_read(&server, "watched").await;

        // The operator sees the marker, then reads raw, and a wait from
        // the same connection is not the agent's either.
        assert!(shows_marker(
            &read_as_cli(&server, from(&s.id, 0, None)).await
        ));
        read_as_cli(&server, from(&s.id, 0, Some(false))).await;
        let w = caller::with_caller(caller::Caller::Cli, wait(&server, &s.id, Some("hi"), 5)).await;
        assert_eq!(w["status"], "ok", "{w}");
        // The agent, whose last masked read was clean, reads raw.
        read(&server, from(&s.id, head, Some(false))).await;

        let raw = entries(&log, "redaction_disabled");
        let who: Vec<(&str, bool)> = raw
            .iter()
            .map(|e| {
                (
                    e["client_kind"].as_str().unwrap(),
                    e["prior_unresolved"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(who, [("cli", true), ("in_process", false)]);

        let record = s.stats_record();
        assert_eq!(record.operator_reads, 2);
        assert_eq!(
            record.reads,
            ReadCounts {
                cursor: 2,
                ..ReadCounts::default()
            },
            "the agent's clean read and its raw one"
        );
        assert_eq!(record.raw_reads.redact_false, 1);
        assert_eq!(record.reads_unresolved, 0, "only the operator saw a marker");
        assert_eq!(record.waits, WaitCounts::default());
    }

    /// The party is read off §9.4's `client_kind` spellings, all four.
    #[test]
    fn the_party_behind_each_client_kind() {
        for (caller, party) in [
            (caller::Caller::Agent, Party::Agent),
            (caller::Caller::InProcess, Party::Agent),
            (caller::Caller::Cli, Party::Operator),
            (caller::Caller::UiBridge, Party::Operator),
        ] {
            assert_eq!(Party::of(caller.as_str()), party, "{caller:?}");
        }
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
        let first = read(&server, from(&s.id, 0, None)).await;
        assert_eq!(first["held_back"], true, "{first}");
        let stopped = first["cursor"].as_u64().unwrap();
        assert!(
            stopped < head,
            "the read must stop short of the head: {first}"
        );
        let second = read(&server, from(&s.id, stopped, None)).await;
        assert_eq!(second["held_back"], true, "{second}");
        assert_eq!(second["cursor"].as_u64(), Some(stopped), "{second}");

        let record = s.stats_record();
        assert_eq!(record.reads_held_back, 2);
        assert_eq!(record.max_bytes_withheld, head - stopped);
    }
}
