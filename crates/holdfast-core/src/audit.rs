//! Append-only JSON-lines audit log (spec §9.4).
//!
//! **Every string that reaches this log goes through the redactor first.**
//! That is not a convention the callers have to remember: `record` walks
//! the payload and redacts it, so an audit line cannot carry a secret even
//! when the session it describes has redaction disabled (§9.4, REQ-O-010).

use crate::daemon::paths::open_log_append;
use crate::output::redact::redact_str;
use crate::output::rules::RuleSet;
use parking_lot::Mutex;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
enum Sink {
    /// No audit file configured; `record` is a no-op. Used by tests and
    /// by callers that have not opened a log yet.
    Disabled,
    File(File),
}

#[derive(Debug)]
pub struct AuditLog {
    rules: Arc<RuleSet>,
    sink: Mutex<Sink>,
    path: Option<PathBuf>,
    /// Running count of `redact: false` reads, reported in the
    /// `redaction_disabled` entry as `redact_false_count_so_far`.
    redact_false_count: AtomicU64,
    /// Writes that failed. The daemon must not die because a log file
    /// filled up, but the failure must be countable.
    write_errors: AtomicU64,
}

impl AuditLog {
    pub fn disabled(rules: Arc<RuleSet>) -> Self {
        Self {
            rules,
            sink: Mutex::new(Sink::Disabled),
            path: None,
            redact_false_count: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        }
    }

    /// Open (or create) an audit log at `path`, appending.
    ///
    /// Owner-only, via [`open_log_append`] — **not** a bare
    /// `OpenOptions`. This constructor is what `serve_stdio` reaches
    /// with no `RuntimePaths` and no `ensure_dir` behind it, so on the
    /// stdio transport it is the *only* thing standing between
    /// `~/.holdfast/logs/audit.log` and `0644`.
    pub fn to_path(path: impl AsRef<Path>, rules: Arc<RuleSet>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = open_log_append(&path)?;
        Ok(Self {
            rules,
            sink: Mutex::new(Sink::File(file)),
            path: Some(path),
            redact_false_count: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Re-open the log at its configured path, replacing the handle.
    ///
    /// This exists for one caller: the §19.1 rotation sweep, which
    /// renames `audit.log` out from under a daemon that has held it open
    /// since start-up. Without a reopen, every subsequent `record` lands
    /// in an **unlinked inode** — every file on disk looks correct and
    /// §9.4's trail silently stops. A disabled log stays disabled: there
    /// is no path to reopen and inventing one would turn the
    /// audit-disabled test constructor into a writer.
    ///
    /// Through the same [`open_log_append`] as [`AuditLog::to_path`],
    /// which is the whole point of there being one opener: a rotation
    /// **re-creates** this file, so a `reopen` that set no mode would
    /// hand the trail back to every local user once a day, undoing even
    /// a `chmod` somebody had applied by hand.
    pub fn reopen(&self) -> std::io::Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let file = open_log_append(path)?;
        *self.sink.lock() = Sink::File(file);
        Ok(())
    }

    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// Count a dropped entry, and say so the *first* time.
    ///
    /// **The open fails closed; the writes do not, and that asymmetry is
    /// deliberate but was silent.** Refusing to start without a trail is
    /// cheap — nothing is running yet. Aborting a daemon mid-flight
    /// because one `write_all` returned `ENOSPC` would take every live
    /// PTY session with it, which is the one thing this tool exists to
    /// avoid, so a dropped entry is survivable in a way a missing log is
    /// not.
    ///
    /// What was not defensible is that nothing said so. The counter had
    /// no non-test reader, so the daemon would refuse to start without a
    /// trail and then run for days with one that had silently stopped.
    /// Now the transition to "not recording" is announced.
    ///
    /// **The full-disk case belongs here, and four comments used to
    /// claim it belonged at the open.** [`AuditLog::to_path`] opens
    /// append-or-create, so on a full disk with an existing `audit.log`
    /// the *open succeeds* and `ENOSPC` arrives at `write_all` — this
    /// branch. The same condition takes opposite branches depending only
    /// on whether the file was already there, which is why citing it as
    /// the thing the startup refusal catches was wrong. What that
    /// refusal does catch is the root-owned `audit.log` left by one
    /// `sudo holdfast`, and those comments now say only that.
    ///
    /// **Once, not per entry.** A full disk fails every subsequent write
    /// too, and a line per dropped entry would bury the first one — the
    /// only one carrying the cause — under thousands of copies, in a
    /// `daemon.log` sitting on the same full disk. `fetch_add` returns
    /// the previous value, so this fires on the 0 -> 1 edge only;
    /// `write_errors()` carries the running total for anyone who wants
    /// the magnitude.
    fn note_write_failure(&self, why: &str) {
        if self.write_errors.fetch_add(1, Ordering::Relaxed) == 0 {
            crate::diag!("holdfast: the audit trail has stopped recording: {why}");
        }
    }

    /// Redact every string in a JSON payload, however deeply nested —
    /// **keys included, not just values.**
    ///
    /// GH #23: this used to clone map keys untouched while walking values
    /// at any depth, so a caller-supplied string that landed in a *key*
    /// position reached the log unredacted — a hole in the file-header
    /// invariant ("every string that reaches this log goes through the
    /// redactor first") that no shipped call path demonstrated yet, but
    /// that 0.0.7 Tasks 9-13's richer per-call audit shapes were expected
    /// to open. Fixed by redacting the key on the same walk as the value,
    /// rather than by refusing a key that is not on some fixed allow-list:
    /// a refusal would turn a caller passing an unanticipated field name
    /// into a runtime failure on the security-logging path, which is a
    /// worse failure mode than a code-authored key silently surviving a
    /// no-op redaction (fixed names like `"command"` or `"tool"` match no
    /// secret-shaped pattern and pass through `redact_str` unchanged).
    pub fn redact_value(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => Value::String(redact_str(&self.rules, s)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.redact_value(v)).collect())
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (redact_str(&self.rules, k), self.redact_value(v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Append one entry. `fields` supplies the per-`kind` extras from the
    /// §9.4 table; `ts` and `kind` are added here.
    ///
    /// **`kind` and `session_id` are redacted too, not just the walked
    /// `fields`.** Both are `&str` today, not `&'static str`, and every
    /// current call site happens to pass either a string literal (`kind`)
    /// or an id minted by `new_session_id()` (a UUID fragment, never
    /// caller-influenced) — so as of this commit neither can carry a
    /// secret. But the file-header invariant is "every string that
    /// reaches this log goes through the redactor first", not "every
    /// string that reaches this log via a path we have audited today", and
    /// GH #23 exists precisely because that distinction was being lost
    /// silently across milestones. Routing both through `redact_str` costs
    /// nothing observable — neither value matches a secret-shaped pattern
    /// — and means this invariant does not need re-litigating every time a
    /// new call site is added.
    pub fn record(&self, kind: &str, session_id: Option<&str>, fields: Value) {
        let mut line: Map<String, Value> = match self.redact_value(&fields) {
            Value::Object(map) => map,
            other => {
                let mut m = Map::new();
                m.insert("fields".into(), other);
                m
            }
        };
        line.insert("ts".into(), Value::String(now_rfc3339()));
        line.insert("kind".into(), Value::String(redact_str(&self.rules, kind)));
        if let Some(id) = session_id {
            line.insert(
                "session_id".into(),
                Value::String(redact_str(&self.rules, id)),
            );
        }
        let mut text = match serde_json::to_string(&Value::Object(line)) {
            Ok(t) => t,
            Err(e) => {
                self.note_write_failure(&format!("cannot serialise a {kind} entry: {e}"));
                return;
            }
        };
        text.push('\n');

        let mut sink = self.sink.lock();
        if let Sink::File(file) = &mut *sink {
            if let Err(e) = file.write_all(text.as_bytes()) {
                self.note_write_failure(&format!("cannot append a {kind} entry: {e}"));
            }
        }
    }

    /// `redaction_disabled` (§9.4): someone asked for raw bytes.
    ///
    /// **Two facts, not one.** `tool` is the mechanism that read
    /// (`read_output`, `resource_read`, `get_screen_state`);
    /// `client_kind` is the accountable party (`shim`, `cli`,
    /// `ui-bridge`, `in_process` — the three handshake values verbatim,
    /// hyphen included, so the log joins across event kinds).
    /// A human running `holdfast logs --raw` and an agent calling
    /// `read_output(redact: false)` both go through `read_output`, so
    /// one string cannot tell them apart — and the whole value of this
    /// entry is telling them apart.
    ///
    /// Both are `&'static str` on purpose: they name things compiled
    /// into this binary, so they can only come from literals at the
    /// call site, never from a request body. 0.0.5 derives
    /// `client_kind` from the authenticated control connection
    /// (`crate::mcp::caller::audit_surface`); until then every caller
    /// really is in-process.
    ///
    /// `client_kind` is audit attribution and nothing else. Nothing in
    /// the read path may branch on it to decide whether to redact
    /// (§9.4, REQ-SEC-018); §7.5's `Attach.role` is the only field that
    /// selects raw versus redacted output.
    pub fn record_redaction_disabled(
        &self,
        session_id: Option<&str>,
        tool: &'static str,
        client_kind: &'static str,
    ) {
        let count = self.redact_false_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.record(
            "redaction_disabled",
            session_id,
            serde_json::json!({
                "tool": tool,
                "client_kind": client_kind,
                "redact_false_count_so_far": count,
            }),
        );
    }

    /// `truncated_at_tail` (§9.4): a forensic record of the context-rule
    /// blind spot documented in §4.1 — a secret's context prefix may have
    /// rolled out of the ring buffer before the value was read.
    pub fn record_truncated_at_tail(
        &self,
        session_id: &str,
        tool: &str,
        since_cursor: u64,
        buffer_tail: u64,
    ) {
        self.record(
            "truncated_at_tail",
            Some(session_id),
            serde_json::json!({
                "tool": tool,
                "since_cursor": since_cursor,
                "buffer_tail": buffer_tail,
            }),
        );
    }

    /// `session_terminate` with `reason: "attach_signal"` (§9.4,
    /// REQ-D-008): a session that ended because a human at an attached
    /// client sent a §7.5 `Signal` frame, rather than one that ended on
    /// its own.
    ///
    /// **The `attach_signal` case only, deliberately.** §9.4's
    /// `session_terminate` has six reasons and this milestone can reach
    /// exactly one of them; the other five (`agent_terminate`,
    /// `agent_interrupt`, `child_exit`, `idle_reap`, `daemon_shutdown`)
    /// have **no writer anywhere in the tree** at this commit, and
    /// inventing their call sites from here would be five cross-milestone
    /// edits made by the task least able to judge them. A typed writer
    /// rather than a bare `record` so the reason cannot be spelled two
    /// ways.
    ///
    /// `signal` is one of `int`/`term`/`kill` — the §18.4c wire spelling,
    /// which is what Holdfast *sent*. §4.4's known limitation makes that
    /// the only record of how the session ended: `portable-pty` maps
    /// death-by-signal onto `exit_code: 1`, indistinguishable from a
    /// child that ran `exit 1`.
    ///
    /// `force` is `false`: it belongs to the `terminate` **tool**, which
    /// escalates on a timeout. §18.4c is explicit that `Signal` does not,
    /// so the field is present (the shape is one shape) and always
    /// answers that this was not the escalating operation.
    pub fn record_session_terminate_attach_signal(
        &self,
        session_id: &str,
        signal: &str,
        exit_code: Option<i32>,
    ) {
        self.record(
            "session_terminate",
            Some(session_id),
            serde_json::json!({
                "reason": "attach_signal",
                "exit_code": exit_code,
                "force": false,
                "signal": signal,
            }),
        );
    }

    /// §9.4's `attach_connect`.
    ///
    /// **Written after a successful `Attached`, never for a rejected
    /// attach** — a reject is not a connection, and logging at accept
    /// time would make the trail count probes.
    ///
    /// `client_kind` is the handshake token from a **uid-checked**
    /// connection, recorded verbatim; a client does not get to name
    /// itself into a different privilege, because there is no privilege
    /// attached to the field at all. §9.4 is explicit that it *"must
    /// never become a redaction switch"* — what decides whether this
    /// connection saw raw bytes is `role`, which is why `role` is on this
    /// row and on the disconnect row beside it.
    ///
    /// **`ClientKind::Shim` is accepted and recorded as `"shim"`** even
    /// though §9.4's column enumerates only `"cli" | "ui-bridge"`. The
    /// column is the *expected* set, not a validator, and refusing a
    /// connection over an attribution field would make the log's honesty
    /// a connectivity requirement.
    pub fn record_attach_connect(
        &self,
        session_id: &str,
        client_kind: &str,
        mode: &str,
        role: &str,
        peer_pid: Option<i32>,
        peer_uid: u32,
    ) {
        self.record(
            "attach_connect",
            Some(session_id),
            serde_json::json!({
                "client_kind": client_kind,
                "mode": mode,
                "role": role,
                "peer_pid": peer_pid,
                "peer_uid": peer_uid,
            }),
        );
    }

    /// §9.4's `attach_disconnect`.
    ///
    /// **`role` is on this row too, and that is spec text.** The two
    /// entries share no connection identifier, so without it *"did this
    /// client receive raw output, and for how long?"* means pairing
    /// connects to disconnects by ordering and hoping. REQ-SEC-008a's
    /// verification ends *"both audit rows carry the role"*.
    ///
    /// `reason` is one of the **four** §9.4 values — `client_detach`,
    /// `slow_consumer`, `daemon_shutdown`, `session_exit`. Note that
    /// `Detached.reason` on the wire carries only **three**:
    /// `client_detach` is deliberately not a wire value, because §7.5's
    /// answer to "who is told?" is *"the client sent `Detach`; there is
    /// nobody left to tell."* The two sets differ on purpose and
    /// `a_client_initiated_detach_sends_no_detached_frame` is what keeps
    /// them apart.
    pub fn record_attach_disconnect(
        &self,
        session_id: &str,
        client_kind: &str,
        mode: &str,
        role: &str,
        reason: &str,
        duration_secs: f64,
    ) {
        self.record(
            "attach_disconnect",
            Some(session_id),
            serde_json::json!({
                "client_kind": client_kind,
                "mode": mode,
                "role": role,
                "reason": reason,
                "duration_secs": duration_secs,
            }),
        );
    }

    pub fn redact_false_count(&self) -> u64 {
        self.redact_false_count.load(Ordering::Relaxed)
    }
}
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    fn log_in(dir: &Path) -> AuditLog {
        let rules = Arc::new(RuleSet::builtin().unwrap());
        AuditLog::to_path(dir.join("audit.log"), rules).unwrap()
    }

    fn lines(log: &AuditLog) -> Vec<Value> {
        let text = std::fs::read_to_string(log.path().unwrap()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
            .collect()
    }

    #[test]
    fn an_entry_carries_ts_kind_and_session_id() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record("session_start", Some("sess_abc"), json!({"pid": 4242}));
        let entries = lines(&log);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "session_start");
        assert_eq!(entries[0]["session_id"], "sess_abc");
        assert_eq!(entries[0]["pid"], 4242);
        let ts = entries[0]["ts"].as_str().unwrap();
        assert!(
            ts.len() >= 20 && ts.ends_with('Z') && ts.contains('T'),
            "ts must be RFC 3339 UTC, got {ts:?}"
        );
    }

    #[test]
    fn entries_append_rather_than_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record("daemon_start", None, json!({"pid": 1}));
        log.record("daemon_stop", None, json!({"reason": "explicit"}));
        let entries = lines(&log);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["kind"], "daemon_start");
        assert_eq!(entries[1]["kind"], "daemon_stop");
        assert!(
            entries[0].get("session_id").is_none(),
            "daemon-wide entries carry no session id"
        );
    }

    /// REQ-O-010 / §9.4: audit lines never carry an unredacted secret.
    #[test]
    fn a_secret_in_a_field_is_redacted_and_its_context_survives() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record(
            "session_start",
            Some("sess_abc"),
            json!({ "command": "curl", "args": ["-H", format!("Authorization: token {SECRET}")] }),
        );
        let raw = std::fs::read_to_string(log.path().unwrap()).unwrap();
        assert!(!raw.contains(SECRET), "the secret reached the audit log");
        // The absence check alone would pass against a log that wrote
        // nothing at all, so assert the rest of the entry survived.
        let entries = lines(&log);
        assert_eq!(entries[0]["command"], "curl");
        assert_eq!(entries[0]["args"][0], "-H");
        assert_eq!(
            entries[0]["args"][1],
            "Authorization: token [REDACTED:github]"
        );
    }

    #[test]
    fn redaction_reaches_arbitrarily_nested_strings() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record(
            "panic",
            None,
            json!({ "context": { "excerpt": [{"line": format!("export TOKEN={SECRET}")}] } }),
        );
        let raw = std::fs::read_to_string(log.path().unwrap()).unwrap();
        assert!(!raw.contains(SECRET));
        let entries = lines(&log);
        assert_eq!(
            entries[0]["context"]["excerpt"][0]["line"],
            "export TOKEN=[REDACTED:github]"
        );
    }

    /// GH #23 / mutation P-A: `redact_value` walked values at any depth
    /// but cloned map **keys** untouched, so a secret-shaped string in a
    /// key position reached the log verbatim.
    ///
    /// **Paired deliberately.** `sibling` carries the identical secret in
    /// a *value* position at the same depth, and that field is asserted
    /// redacted too — proving this harness can tell a real redaction from
    /// one that never ran, so the key-position assertion below is not an
    /// absence check that would pass against a `redact_value` that does
    /// nothing at all. Before the fix, `sibling` alone caught P-A; the
    /// key assertion is what P-A demonstrated missing.
    #[test]
    fn a_secret_shaped_key_is_redacted_like_the_identical_secret_in_a_sibling_value() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        let mut fields = Map::new();
        fields.insert(SECRET.to_string(), json!("harmless"));
        fields.insert("sibling".to_string(), json!(SECRET));
        log.record("panic", None, Value::Object(fields));

        let raw = std::fs::read_to_string(log.path().unwrap()).unwrap();
        assert!(
            !raw.contains(SECRET),
            "the secret reached the audit log, in a key or a value"
        );

        let entries = lines(&log);
        let obj = entries[0].as_object().unwrap();

        // The control: the same string in a value position is redacted,
        // which is already true today and is what makes the next
        // assertion meaningful rather than accidental.
        assert_eq!(obj["sibling"], "[REDACTED:github]");

        // The defect: the same string in a key position must be
        // rewritten by the redactor too, not carried through untouched.
        assert!(
            !obj.contains_key(SECRET),
            "the secret survived as a raw map key"
        );
        assert_eq!(
            obj.get("[REDACTED:github]"),
            Some(&json!("harmless")),
            "the key must be rewritten by the redactor (not dropped), and \
             the value it maps to must survive unchanged"
        );
    }

    /// `kind` and `session_id` are inserted after `redact_value` returns,
    /// so they are not covered by the walk over `fields` at all. Every
    /// call site today passes either a string literal (`kind`) or a
    /// `new_session_id()` UUID fragment (`session_id`), neither of which
    /// can carry a secret — but the file-header invariant is "every
    /// string that reaches this log goes through the redactor first", not
    /// "every string reachable from an audited call site today", so both
    /// are routed through the same redactor as `fields` rather than
    /// argued exempt.
    #[test]
    fn kind_and_session_id_are_redacted_like_every_other_string_on_the_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record(SECRET, Some(SECRET), json!({}));
        let raw = std::fs::read_to_string(log.path().unwrap()).unwrap();
        assert!(
            !raw.contains(SECRET),
            "the secret reached the audit log via kind or session_id"
        );
        let entries = lines(&log);
        assert_eq!(entries[0]["kind"], "[REDACTED:github]");
        assert_eq!(entries[0]["session_id"], "[REDACTED:github]");
    }

    /// `record`'s other arm. A `fields` value that is not an object is
    /// wrapped under `fields` rather than dropped — and it is redacted on
    /// the way, because the redaction runs *before* the shape test. Only
    /// the object arm was exercised, so a wrapper that skipped the
    /// redactor, or dropped the payload entirely, was invisible.
    #[test]
    fn a_non_object_payload_is_wrapped_and_still_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record("panic", None, json!(format!("died holding {SECRET}")));
        let raw = std::fs::read_to_string(log.path().unwrap()).unwrap();
        assert!(!raw.contains(SECRET), "the secret reached the audit log");
        let entries = lines(&log);
        assert_eq!(entries[0]["kind"], "panic");
        assert_eq!(entries[0]["fields"], "died holding [REDACTED:github]");
    }

    /// §9.4 records the mechanism and the accountable party separately.
    /// `holdfast logs --raw` is not a third mechanism: it is `read_output`
    /// performed on behalf of a `cli` client, which is exactly the
    /// distinction a single `surface` string could not make.
    ///
    /// Kills "collapse the two back into one field": the two entries
    /// share a `tool` and differ only in `client_kind`, so an
    /// implementation that writes either one alone cannot tell them
    /// apart. The `shim` / `cli` literals are §9.4's spelling verbatim
    /// (rev. 35 rejected `agent`), so this also kills a re-spelling.
    #[test]
    fn redaction_disabled_entries_name_the_tool_and_the_caller_and_count_up() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record_redaction_disabled(Some("sess_a"), "read_output", "shim");
        log.record_redaction_disabled(Some("sess_a"), "read_output", "cli");
        let entries = lines(&log);
        assert_eq!(entries[0]["kind"], "redaction_disabled");
        assert_eq!(entries[0]["session_id"], "sess_a");
        assert_eq!(entries[0]["tool"], "read_output");
        assert_eq!(entries[0]["client_kind"], "shim");
        assert_eq!(entries[0]["redact_false_count_so_far"], 1);
        // Same mechanism, different accountable party — the distinction
        // a single `surface` string could not make.
        assert_eq!(entries[1]["tool"], "read_output");
        assert_eq!(entries[1]["client_kind"], "cli");
        assert_eq!(entries[1]["redact_false_count_so_far"], 2);
        assert_eq!(log.redact_false_count(), 2);
    }

    #[test]
    fn truncated_at_tail_entries_record_the_gap() {
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path());
        log.record_truncated_at_tail("sess_a", "read_output", 10, 4096);
        let entries = lines(&log);
        assert_eq!(entries[0]["kind"], "truncated_at_tail");
        // §9.4 gives this kind three extra fields, not two. `tool` is what
        // says *which* read path hit the gap, and the session id is what
        // says whose buffer it was — neither is inferable from the
        // offsets, and neither was asserted.
        assert_eq!(entries[0]["session_id"], "sess_a");
        assert_eq!(entries[0]["tool"], "read_output");
        // Two numbers a transposition would swap, so they are different.
        assert_eq!(entries[0]["since_cursor"], 10);
        assert_eq!(entries[0]["buffer_tail"], 4096);
    }

    #[test]
    fn a_disabled_log_writes_nothing_and_does_not_fail() {
        let rules = Arc::new(RuleSet::builtin().unwrap());
        let log = AuditLog::disabled(rules);
        log.record("session_start", Some("sess_a"), json!({"pid": 1}));
        assert!(log.path().is_none());
        assert_eq!(log.write_errors(), 0);
    }

    /// A full disk must not take the daemon down, and a silent failure is
    /// worse than a loud one — so the write error is swallowed and
    /// *counted*, and `holdfast doctor` (0.0.12) reads the count.
    ///
    /// `/dev/full` is the only portable way to make `write_all` fail on
    /// demand; it is Linux-only, and this is the one arm of `record` that
    /// nothing else can reach. Paired with the ordinary path, so a
    /// counter stuck at 1 fails as loudly as one stuck at 0.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_write_that_fails_is_counted_and_does_not_panic() {
        let rules = Arc::new(RuleSet::builtin().unwrap());
        let full = match AuditLog::to_path("/dev/full", Arc::clone(&rules)) {
            Ok(log) => log,
            // A container without /dev/full: the arm is unreachable here,
            // and skipping is honest where inventing a pass is not.
            Err(_) => return,
        };
        assert_eq!(full.write_errors(), 0, "nothing has been written yet");
        full.record("daemon_start", None, json!({"pid": 1}));
        assert_eq!(full.write_errors(), 1, "ENOSPC must be counted");
        full.record("daemon_stop", None, json!({"reason": "explicit"}));
        assert_eq!(full.write_errors(), 2, "and counted per write");

        // The separator: the same two calls against a real file count
        // nothing, so this pins the *failure* rather than "record always
        // increments".
        let dir = tempfile::tempdir().unwrap();
        let ok = log_in(dir.path());
        ok.record("daemon_start", None, json!({"pid": 1}));
        ok.record("daemon_stop", None, json!({"reason": "explicit"}));
        assert_eq!(ok.write_errors(), 0);
    }

    /// The asymmetry itself, which four comments used to describe
    /// backwards.
    ///
    /// `with_audit_path`'s refusal is an *open-time* guarantee, and
    /// `to_path` opens append-or-create — so on a full disk with an
    /// existing `audit.log` the open succeeds and the failure arrives at
    /// `write_all` instead. Those comments cited a full disk as the
    /// thing startup refused, which inverted it: the same condition
    /// takes opposite branches depending only on whether the file was
    /// already there.
    ///
    /// This asserts the branch, not the counter — `a_write_that_fails_is
    /// _counted_and_does_not_panic` owns the counting. If someone later
    /// makes `to_path` probe writability at open, this row goes red and
    /// that is the conversation worth having, not a silent divergence
    /// from the comments again.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_disk_is_not_caught_by_the_open_that_claims_to_catch_it() {
        let rules = Arc::new(RuleSet::builtin().unwrap());
        let Ok(full) = AuditLog::to_path("/dev/full", Arc::clone(&rules)) else {
            // No /dev/full here, so the premise is unavailable rather
            // than false. Skipping beats inventing a pass.
            return;
        };
        // The open succeeded against a sink that cannot accept a byte.
        assert_eq!(
            full.write_errors(),
            0,
            "the open reported success and nothing has been attempted yet"
        );
        full.record("daemon_start", None, json!({"pid": 1}));
        assert_eq!(
            full.write_errors(),
            1,
            "the failure lands on the write, which is the fail-open path"
        );
    }

    #[test]
    fn reopening_the_same_path_appends_to_the_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = log_in(dir.path());
            log.record("daemon_start", None, json!({"pid": 1}));
        }
        let log = log_in(dir.path());
        log.record("daemon_start", None, json!({"pid": 2}));
        let entries = lines(&log);
        assert_eq!(entries.len(), 2, "a restart must not truncate the trail");
        assert_eq!(entries[0]["pid"], 1);
        assert_eq!(entries[1]["pid"], 2);
    }

    /// **The audit trail is owner-only, on the transport nobody tested.**
    ///
    /// `serve_stdio` opens this log through `to_path` with no
    /// `RuntimePaths` and no `ensure_dir` ahead of it, so on a machine
    /// that had never run the daemon `~/.holdfast/logs/audit.log` was
    /// created `0644` and any local user could read the command line,
    /// the cwd and the env-var key set of everything the agent had run.
    /// The daemon path was fine, because `bind_control` → `ensure_dir`
    /// had already made the directory `0700` — one transport enforcing
    /// the milestone's own non-negotiable and the other not.
    ///
    /// Both creation sites are exercised, because both create the file:
    /// `to_path` at start-up, and `reopen` after §19.1 renames it away
    /// once a day. The `reopen` half is the one a `chmod` by hand could
    /// not survive.
    ///
    /// The umask is forced (see [`ForcedUmask`]) so this measures what
    /// the code set rather than what the developer's shell masked off,
    /// and the `naive` control is what proves the forcing took: it
    /// creates a file the way the defective code did and asserts it
    /// comes out `0644`. Delete the mode from `open_log_append` and the
    /// two audit assertions redden while the control stays green.
    #[test]
    fn the_audit_log_is_owner_only_when_it_is_created_and_when_it_is_reopened() {
        use crate::daemon::paths::ForcedUmask;
        use std::os::unix::fs::PermissionsExt;

        fn mode_of(path: &Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        let dir = tempfile::tempdir().unwrap();
        let _umask = ForcedUmask::loose();

        let naive = dir.path().join("naive").join("audit.log");
        std::fs::create_dir_all(naive.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&naive)
            .unwrap();
        assert_eq!(
            mode_of(&naive),
            0o644,
            "the control did not come out world-readable, so this test could \
             not have told a set mode from an ambient one"
        );

        let path = dir.path().join("logs").join("audit.log");
        let log = AuditLog::to_path(&path, Arc::new(RuleSet::builtin().unwrap())).unwrap();
        log.record("session_start", Some("sess_a"), json!({"pid": 1}));
        assert_eq!(
            mode_of(&path),
            0o600,
            "every local user can read the agent's command lines"
        );
        assert_eq!(
            mode_of(path.parent().unwrap()),
            0o700,
            "the directory holding the trail lists its contents to anyone"
        );

        // The rotation half: §19.1 renames the file away, so `reopen`
        // creates a fresh one and gets to choose its mode all over again.
        std::fs::rename(&path, dir.path().join("logs").join("audit.log.rolled")).unwrap();
        log.reopen().expect("reopen after rotation");
        log.record("session_start", Some("sess_b"), json!({"pid": 2}));
        assert_eq!(
            mode_of(&path),
            0o600,
            "a rotation re-created the trail world-readable, undoing even a \
             chmod applied by hand"
        );
        // Not an empty file whose mode happens to be right: the reopen
        // has to have actually landed the entry here.
        assert!(std::fs::read_to_string(&path).unwrap().contains("sess_b"));
    }

    /// §9.4's path now has exactly one spelling, and this row is what
    /// says so (GH #72).
    ///
    /// It used to assert `audit_path_under_home`, a second computation of
    /// `$HOME/.holdfast/logs/audit.log` living here rather than in
    /// `RuntimePaths`. Two spellings kept in step by matching string
    /// literals in two files is how a daemon and a shim came to disagree
    /// about where the audit trail was — read once as a missing trail and
    /// filed as a security finding (GH #63) when the real log was
    /// elsewhere with 19 entries in it.
    ///
    /// The empty-`$HOME` rule that lived only here moved with it: `HOME=""`
    /// joins to a *relative* `.holdfast/logs/audit.log`, and an audit trail
    /// written into the process's working directory is worse than none,
    /// because it reads as evidence of absence.
    #[test]
    fn the_audit_path_has_one_spelling_and_no_home_yields_none() {
        use crate::daemon::paths::RuntimePaths;
        assert_eq!(
            RuntimePaths::resolve(None, None, Some("/home/u".into()), false, false)
                .unwrap()
                .audit_log(),
            std::path::PathBuf::from("/home/u/.holdfast/logs/audit.log"),
        );
        assert!(
            RuntimePaths::resolve(None, None, None, false, false).is_err(),
            "no $HOME, no guess"
        );
        assert!(
            RuntimePaths::resolve(None, None, Some("".into()), false, false).is_err(),
            "an empty $HOME must not become a relative path"
        );
    }
}
