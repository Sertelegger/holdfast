//! Command history derived from OSC 133 markers (spec §5.2
//! `get_command_history`, §8.5).
//!
//! Only tier 1 can produce this: `C` opens a command's output span, `D`
//! closes it and carries the exit code. Without shell integration the ring
//! stays empty and the tool reports `unavailable`.

use super::scanner::{Osc133, Osc133Event};
use std::collections::VecDeque;

/// Default `command_history_max_entries` (spec §4.2).
pub const DEFAULT_MAX_ENTRIES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEntry {
    /// Monotonic per session; never reused, so it survives ring eviction.
    pub index: u64,
    /// **Best-effort, and never the command of record.** This is
    /// reconstructed from the terminal *echo* between the OSC 133 `B` and `C`
    /// markers — the bytes the line editor happened to paint — not from
    /// anything the shell reports about what it ran. It is wrong in two
    /// measured ways.
    ///
    /// A command longer than the terminal width is captured **truncated to
    /// its tail**: 125 characters typed at 80 columns yields 47, with the
    /// leading 78 silently gone. The line editor's wrap redraw emits `\r`
    /// followed by `\x1b[K`, which is a *within-line reposition*; a scanner
    /// with no grid and no cursor cannot distinguish that from a fresh line,
    /// so it discards everything before it. That is not a defect in the
    /// capture rules and must not be fixed there — modelling it is exactly
    /// the cursor arithmetic tier A is defined not to do (tier B, 0.0.4).
    ///
    /// Truncation is the dangerous half, because a tail *looks like a whole
    /// command*. A consumer sees something plausible and gets no signal that
    /// the front of the line is missing, so any caller presenting this value
    /// has to say it is approximate.
    ///
    /// Non-ASCII bytes are also recorded as Latin-1 rather than decoded
    /// UTF-8 (`echo café` → `echo cafÃ©`), because the capture maps each
    /// byte to a codepoint. That one is a genuine bug, fixable one layer
    /// down in the scanner's capture buffer; it is loudly wrong rather than
    /// quietly wrong, and it changes no detection decision.
    pub command: String,
    /// **`None` does not mean "still running".** `D` may arrive with no
    /// code at all — the shell reports the command finished and says
    /// nothing about how — and a code outside `i32` (`D;99999999999`)
    /// parses to `None` too. Both are indistinguishable here from a
    /// command that has not finished. Use `output_end_cursor` to tell
    /// them apart; it is the only field that can.
    pub exit_code: Option<i32>,
    pub started_at_unix_ms: i64,
    pub duration_ms: Option<u64>,
    /// Absolute offset of the command's first output byte.
    pub output_start_cursor: u64,
    /// Absolute offset just past its last output byte.
    ///
    /// **This, and only this, is the "has it finished" field.** `None`
    /// means no `D` has closed this entry — which is *usually* "still
    /// running", but is permanent for an orphaned entry: a `D` only ever
    /// closes the newest open command, so a `C` that arrives before its
    /// predecessor's `D` (a nested shell, or a `D` lost to a truncated
    /// write) leaves the older one open for the life of the session.
    /// A consumer that renders `None` as "running" will show a
    /// long-finished command as running indefinitely, so it should say
    /// "not known to have finished" instead.
    pub output_end_cursor: Option<u64>,
}

#[derive(Debug)]
pub struct CommandHistory {
    entries: VecDeque<CommandEntry>,
    max_entries: usize,
    next_index: u64,
    evicted: bool,
    active: bool,
    /// The integration line CLASP typed at session start, armed until the
    /// first `OutputStart` is processed (§8.5.1 rule 5, REQ-DM-009).
    ///
    /// Before rev. 36 the injection line stayed out of the history because
    /// it ran before `PS0`/`preexec` existed and emitted no `C`. **That
    /// reasoning fails the instant another emitter is installed** — the
    /// user's `PS0` marks the snippet's own command line, and the snippet
    /// then appears as the session's first entry carrying its whole text.
    /// Measured on fish 4.8.1, where it did exactly that.
    ///
    /// Armed for exactly one `OutputStart`, matched or not: the injection
    /// line is the first thing typed, so a later command whose echo happens
    /// to be a suffix of the snippet cannot reach this.
    injection_line: Option<String>,
    /// Set when an `OutputStart` was suppressed, so the `CommandDone` that
    /// would have closed it cannot close an unrelated entry instead.
    ///
    /// **Defensive, and measured to be unobservable, which is stated
    /// rather than implied.** The injection line is the first thing
    /// written to the PTY, so at the moment its `D` arrives there is never
    /// an open entry for that `D` to close — including on the verbatim
    /// fish 4.0.2 capture below. Removing this field leaves the whole
    /// workspace green, so **no test here can distinguish its presence
    /// from its absence** and none pretends to. It is kept because the
    /// "nothing is open" property is an invariant of *where*
    /// `set_injection_line` is called, not of this ring, and a later caller
    /// arming it elsewhere would silently close somebody else's entry.
    suppress_next_done: bool,
    /// Whether any `B` has arrived in this session, which is what decides
    /// whether an *empty* capture means "the capture was lost" or "there
    /// was never a span to capture from". See `apply`.
    seen_command_start: bool,
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

impl CommandHistory {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.max(1),
            next_index: 0,
            evicted: false,
            active: false,
            injection_line: None,
            suppress_next_done: false,
            seen_command_start: false,
        }
    }

    /// Tell the ring which line CLASP itself typed (§8.5.1 rule 5).
    ///
    /// Set before the line is written, never after: the reader thread is
    /// already running, so a snippet that produced its `C` first would be
    /// recorded.
    pub fn set_injection_line(&mut self, line: String) {
        self.injection_line = Some(line);
    }

    /// True once any OSC 133 marker has been seen, i.e. shell integration
    /// is working for this session.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Total commands ever recorded, including evicted ones.
    pub fn total(&self) -> u64 {
        self.next_index
    }

    /// True when the ring has dropped at least one entry.
    pub fn truncated_at_tail(&self) -> bool {
        self.evicted
    }

    /// Entries with `index >= since_index`, newest last, at most `limit`.
    pub fn entries(&self, since_index: u64, limit: usize) -> Vec<CommandEntry> {
        let matching: Vec<&CommandEntry> = self
            .entries
            .iter()
            .filter(|e| e.index >= since_index)
            .collect();
        let start = matching.len().saturating_sub(limit);
        matching[start..].iter().map(|e| (*e).clone()).collect()
    }

    /// Fold one marker into the history. `now_ms` is the wall clock at the
    /// moment the bytes arrived.
    pub fn apply(&mut self, event: &Osc133Event, now_ms: i64) {
        self.active = true;
        match &event.marker {
            Osc133::OutputStart { command } => {
                if let Some(line) = self.injection_line.take() {
                    // Matched against the line CLASP itself typed, never
                    // against incidental content. The capture is a *suffix*
                    // of what was typed — §5.2 documents the echo capture
                    // truncating to its tail at the terminal width — so
                    // `ends_with` is the right test and equality would
                    // silently stop matching at narrow widths.
                    let matched =
                        !command.is_empty() && line.trim_end().ends_with(command.as_str());
                    // **The suffix test alone is not enough, and this is
                    // measured rather than anticipated.** On a foreign
                    // emitter that supplies no `B` — fish 4.0.2, measured
                    // on a live PTY — nothing ever arms the echo capture,
                    // so the injection line's `C` carries an *empty*
                    // command and there is no text to compare. Left at the
                    // suffix test, the snippet became entry 0 of every such
                    // session with `command: ""` and `exit_code: 0`, which
                    // is REQ-DM-009's "never an entry" failing in the one
                    // arrangement the requirement was written for.
                    //
                    // The second clause identifies the line CLASP typed
                    // from the session's *structure* rather than from its
                    // content, which is what §8.5.1 rule 5 permits: the
                    // injection line is the first thing written to the PTY
                    // and the agent does not hold the session until after
                    // it, so nothing of the user's can precede it — and a
                    // `B`-less first `C` is the structural absence a
                    // partial foreign emitter creates, not a capture that
                    // was lost. With no foreign emitter CLASP's own `PS1`
                    // has already emitted `B` by the first `C`, so this
                    // cannot reach a user command there.
                    //
                    // Residual, bounded at one entry: if the snippet fails
                    // to install *and* a `B`-less foreign emitter is
                    // present, the user's first command is suppressed. That
                    // is a session whose integration is already broken.
                    let never_had_a_span = command.is_empty() && !self.seen_command_start;
                    if matched || never_had_a_span {
                        self.suppress_next_done = true;
                        return;
                    }
                }
                // The output span starts just past the `C` marker.
                self.push(CommandEntry {
                    index: self.next_index,
                    command: command.clone(),
                    exit_code: None,
                    started_at_unix_ms: now_ms,
                    duration_ms: None,
                    output_start_cursor: event.end,
                    output_end_cursor: None,
                });
                self.next_index += 1;
            }
            Osc133::CommandDone { exit_code } => {
                if self.suppress_next_done {
                    // The `C` this `D` belongs to was CLASP's own install
                    // line and was suppressed, so there is no entry for it
                    // to close — and without this it would close whatever
                    // entry happened to be open instead.
                    self.suppress_next_done = false;
                    return;
                }
                // A `D` with no open entry is normal exactly once: the
                // command that *installed* the integration ran before
                // `PS0`/`preexec` existed, so it emitted no `C`. Ignoring
                // it is what keeps CLASP's own injection out of the
                // agent's history.
                //
                // Known limitation, measured and asserted in
                // `osc133_markers_survive_shell_nesting`: when an
                // integrated shell is launched *from* an integrated shell,
                // the inner shell's first `D` is emitted before it has run
                // anything — and there *is* an open entry, the parent's
                // still-running `bash` command. OSC 133 carries no nesting
                // information, so that `D` is indistinguishable from the
                // parent's command finishing and closes it early with the
                // wrong exit code and a truncated output span. Terminal
                // emulators consuming OSC 133 have the same limitation;
                // fixing it needs a signal the protocol does not carry.
                //
                // `back_mut` only, deliberately: a `D` closes the newest
                // open command and never reaches past it. That leaves an
                // entry orphaned when a `C` arrives before its
                // predecessor's `D`, and orphaned means orphaned — no
                // later `D` can ever close it. Walking back to find one
                // would be worse: it would attach an exit code and an
                // output span to whichever command happened to be open,
                // and OSC 133 carries nothing to say which that is.
                // Documented on `output_end_cursor`, where a consumer
                // reads it.
                if let Some(open) = self
                    .entries
                    .back_mut()
                    .filter(|e| e.output_end_cursor.is_none())
                {
                    open.exit_code = *exit_code;
                    // The output ends where the `D` sequence begins.
                    open.output_end_cursor = Some(event.start);
                    // `max(0)` before the cast, not after. `now_ms` comes
                    // from the *wall* clock, which steps backwards — NTP,
                    // a VM resuming, a container's clock being set — and
                    // the subtraction is signed while `duration_ms` is
                    // not, so 100 ms backwards would otherwise surface to
                    // the agent as 18446744073709551516 ms.
                    open.duration_ms =
                        Some(now_ms.saturating_sub(open.started_at_unix_ms).max(0) as u64);
                }
            }
            Osc133::CommandStart => self.seen_command_start = true,
            Osc133::PromptStart => {}
        }
    }

    fn push(&mut self, entry: CommandEntry) {
        self.entries.push_back(entry);
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
            self.evicted = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::scanner::ModeScanner;

    /// Drive the history the way the reader thread does: scan bytes, then
    /// fold every marker the scanner reports.
    fn replay(bytes: &[u8], max_entries: usize) -> CommandHistory {
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(max_entries);
        let mut t = 1_000i64;
        for ev in sc.feed(bytes, 0, None) {
            h.apply(&ev, t);
            t += 10;
        }
        h
    }

    const ONE_COMMAND: &[u8] =
        b"\x1b]133;A\x07$ \x1b]133;B\x07echo hi\r\n\x1b]133;C\x07hi\r\n\x1b]133;D;0\x07";

    #[test]
    fn a_command_is_recorded_with_its_exit_code_and_span() {
        let h = replay(ONE_COMMAND, 100);
        assert!(h.is_active());
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].index, 0);
        assert_eq!(e[0].command, "echo hi");
        assert_eq!(e[0].exit_code, Some(0));
        assert_eq!(e[0].duration_ms, Some(10));

        // The span must cover exactly the command's output, so a
        // read_output over it returns "hi\r\n" and nothing else.
        let span = &ONE_COMMAND
            [e[0].output_start_cursor as usize..e[0].output_end_cursor.unwrap() as usize];
        assert_eq!(span, b"hi\r\n");
    }

    /// One full fish prompt-command-done cycle, byte for byte off a real
    /// PTY (fish 3.7.0, Ubuntu 24.04), because the defect it pins was
    /// invisible to every hand-written stream in this file.
    ///
    /// `get_command_history` reported `command: ""` for **every** entry of
    /// **every** fish session while the exit code, span and duration beside
    /// it were all correct — so the shape of the entry looked healthy and
    /// only the one best-effort field was empty. `command` being
    /// best-effort licenses a *truncated* or mis-decoded value, not an
    /// absent one on a supported shell.
    ///
    /// The cause is in the scanner (`capture_return`): fish's editor
    /// repaints with `\r` plus a cursor-forward and submits with one final
    /// `\r` that nothing is written over.
    #[test]
    fn a_measured_fish_session_records_the_command_that_was_typed() {
        let h = replay(
            b"\x1b]133;A\x07root@host /# \x1b]133;B\x07\x1b[K\r\x1b[21Cecho \
              \r\x1b[26Chello\r\x1b[31C\x1b[10Decho hello\r\x1b[31C\r\n\
              \x1b[30m\x1b(B\x1b[m\x1b]133;C\x07hello\r\n\x1b]133;D;0\x07",
            100,
        );
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].command, "echo hello", "fish entry lost its command");
        // The rest of the entry, so a fix that filled `command` in by
        // breaking the span would not read as a pass.
        assert_eq!(e[0].exit_code, Some(0));
        assert!(e[0].output_end_cursor.is_some());
    }

    /// Two whole prompt-command-done cycles, byte for byte off a real PTY
    /// (**fish 4.0.2**, `debian:trixie`, 2026-08-14), with CLASP's shipped
    /// snippet installed and fish's own OSC 133 marking left on. This is
    /// §8.5.1's collision at a real shell, and the only place in the
    /// workspace where the yielding rule meets one.
    ///
    /// **The letters divide the way §8.5.1 says they must**, which is why
    /// the capture is worth 800 bytes of source. fish 4.0.2 emits
    /// `A;special_key=1`, `C;cmdline_url=…` and `D;<code>` — and, measured
    /// here, **never `B`**. So `A`, `C` and `D` go foreign and CLASP's
    /// tagged copies of them are discarded, while CLASP's `B;holdfast=1` is
    /// **kept**, because fish supplies none to yield to. That kept `B` is
    /// the only thing that arms the echo capture, so it is what gives
    /// `command` its `B..C` span. A whole-*source* rule would have
    /// discarded it along with the rest and left `command: ""` for every
    /// entry on every fish 4.0–4.2 session — the same loss declining costs
    /// there, reached by a different route.
    ///
    /// **REQ-DM-010, asserted as one value rather than as three columns.**
    /// Separating them is the whole hazard: applying the `\r` overwrite
    /// eagerly empties `command` for every entry while leaving the codes
    /// and spans correct, and deleting `\r` handling makes zsh's
    /// first-keystroke redraw report `eecho hello` while everything else
    /// still lines up. Either repair passes a suite that checks one column
    /// at a time, so the entries here are compared whole.
    ///
    /// Verbatim, escapes and all. The only thing not asserted from it is
    /// the container hostname in the prompt text, which sits between `A`
    /// and `B` and is therefore never captured.
    const FISH_402_COLLISION: &[u8] =
    b"\x1b]0;/\x07\x1b[30m\x1b(B\x1b[m\x1b]133;A;special_key=1\x07\
     \x1b]133;A;holdfast=1\x07root\x1b(B\x1b[m@75952eda0e7a\x1b(B\x1b\
     [m /\x1b(B\x1b[m\x1b(B\x1b[m# \x1b]133;B;holdfast=1\x07\x1b[K\
     \x0d\x1b[21C\x1b[?2004h\x1b[>4;1m\x1b[=5u\x1b=echo \x0d\x1b\
     [26Chello\x0d\x1b[31C\x1b[10Decho hello\x0d\x1b[31C\x0d\x0a\
     \x1b[30m\x1b(B\x1b[m\x1b]133;C;cmdline_url=echo%20hello\x07\
     \x1b[?2004l\x1b[>4;0m\x1b[=0u\x1b>\x1b]133;C;holdfast=1\x07\x1b\
     ]0;echo hello /\x07\x1b[30m\x1b(B\x1b[m\x0dhello\x0d\x0a\x1b\
     ]133;D;0\x07\x1b]133;D;0;holdfast=1\x07\x1b[?25h\x1b[2m\xe2\x8f\
     \x8e\x1b(B\x1b[m                                          \
     \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x0d\xe2\x8f\x8e \x0d\
     \x1b[K\x1b]0;/\x07\x1b[30m\x1b(B\x1b[m\x1b]133;A;special_k\
     ey=1\x07\x1b]133;A;holdfast=1\x07root\x1b(B\x1b[m@75952eda0e7\
     a\x1b(B\x1b[m /\x1b(B\x1b[m\x1b(B\x1b[m# \x1b]133;B;\
     holdfast=1\x07\x1b[K\x0d\x1b[21C\x1b[?2004h\x1b[>4;1m\x1b[=5u\x1b=s\
     h \x0d\x1b[24C-c \x0d\x1b[27C\"exit \x0d\x1b[33C42\"\x0d\x1b\
     [36C\x1b[15Dsh -c \"exit 42\"\x0d\x1b[36C\x0d\x0a\x1b[30m\x1b\
     (B\x1b[m\x1b]133;C;cmdline_url=sh%20-c%20%22exit%2042%22\x07\
     \x1b[?2004l\x1b[>4;0m\x1b[=0u\x1b>\x1b]133;C;holdfast=1\x07\x1b\
     ]0;sh -c \"exit 42\" /\x07\x1b[30m\x1b(B\x1b[m\x0d\x1b]133\
     ;D;42\x07\x1b]133;D;42;holdfast=1\x07";

    #[test]
    fn a_real_fish_4_0_2_collision_cycle_reports_command_exit_code_and_span_together() {
        let h = replay(FISH_402_COLLISION, 100);
        let e = h.entries(0, 50);
        // One entry per command, not two. Under the shipped ring this
        // capture produced four — each command opening one entry on the
        // foreign `C` and another on CLASP's, the first orphaned with the
        // text and the second closed with the code.
        assert_eq!(e.len(), 2, "one entry per command: {e:?}");

        assert_eq!(
            e.iter().map(|x| x.command.as_str()).collect::<Vec<_>>(),
            vec!["echo hello", "sh -c \"exit 42\""],
            "the kept `B` did not give the capture its span"
        );
        assert_eq!(
            e.iter().map(|x| x.exit_code).collect::<Vec<_>>(),
            vec![Some(0), Some(42)]
        );
        // The span, read back out of the same bytes — the third column,
        // so a repair that filled `command` in by moving a cursor lands
        // here rather than passing.
        let span = &FISH_402_COLLISION
            [e[0].output_start_cursor as usize..e[0].output_end_cursor.expect("closed") as usize];
        let text = String::from_utf8_lossy(span);
        assert!(
            text.contains("hello\r\n"),
            "the output span missed the command's own output: {text:?}"
        );
        assert!(
            !text.contains("exit 42"),
            "the span ran into the next command: {text:?}"
        );
        // **A measured consequence of yielding, asserted rather than
        // asserted away.** The span opens just past the *foreign* `C` and
        // closes at the *foreign* `D`, so CLASP's own `C;holdfast=1` — which
        // the yielding rule discarded as an **event** — is still inside it
        // as **bytes**. Discarding a marker keeps it out of the detector
        // and the ring; it cannot take it out of the session's raw buffer,
        // which is what a cursor addresses. An agent reading this span back
        // gets that escape with the output. Harmless (0.0.3's read-path
        // stripper removes it, and `command_history_cursors_bound_exactly_
        // one_commands_output` pins the no-collision case where no such
        // sequence appears at all) — but it is a difference between a
        // colliding session and an ordinary one, and it is here so that it
        // is a recorded fact rather than a surprise.
        assert!(
            span.windows(6).any(|w| w == b"\x1b]133;"),
            "expected CLASP's discarded marker bytes inside the span: {text:?}"
        );
        for x in &e {
            assert!(x.duration_ms.is_some(), "unfinished entry: {x:?}");
        }
    }

    /// REQ-DM-010's third shell and its second: **real bash 5.3 and zsh
    /// 5.9 cycles, replayed byte-identically**, because the carriage-return
    /// rule is over all three shells and a future change to it would
    /// otherwise be measured only against fish.
    ///
    /// Both were captured on this host through a real PTY with the shipped
    /// snippet installed, and each carries its shell's own line-editor
    /// noise. zsh's is the one that matters: `e\x08echo hello` is the
    /// first-keystroke redraw, and it is the stream that reports
    /// `eecho hello` if `\r`/backspace handling is deleted rather than
    /// deferred — the mirror of the fish direction, and the reason
    /// REQ-DM-010 is pinned from both sides. zsh's `%`-padding row and its
    /// trailing `\r` are kept verbatim rather than trimmed, since trimming
    /// is what would remove the very bytes the rule acts on.
    const BASH_53_CYCLES: &[u8] = b"\x1b[?2004h\x1b]133;A;holdfast=1\x07bash-5.3$ \x1b]133;B;\
        holdfast=1\x07echo hello\x0d\x0a\x1b[?2004l\x0d\x1b]133;C;holdfast=1\
        \x07hello\x0d\x0a\x1b]133;D;0;holdfast=1\x07\x1b[?2004h\x1b]1\
        33;A;holdfast=1\x07bash-5.3$ \x1b]133;B;holdfast=1\x07(exit 42)\x0d\
        \x0a\x1b[?2004l\x0d\x1b]133;C;holdfast=1\x07\x1b]133;D;42;\
        holdfast=1\x07";
    const ZSH_59_CYCLES: &[u8] =
        b"\x0d\x1b[0m\x1b[27m\x1b[24m\x1b[J\x1b]133;A;holdfast=1\x07dev\
        % \x1b]133;B;holdfast=1\x07\x1b[K\x1b[?2004he\x08echo hello\x1b\
        [?2004l\x0d\x0d\x0a\x1b]133;C;holdfast=1\x07hello\x0d\x0a\x1b\
        [1m\x1b[7m%\x1b[27m\x1b[1m\x1b[0m                         \
        \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x0d\
        \x20\x0d\x1b]133;D;0;holdfast=1\x07\x0d\x1b[0m\x1b[27m\x1b[24m\x1b\
        [J\x1b]133;A;holdfast=1\x07dev% \x1b]133;B;holdfast=1\x07\x1b[K\x1b\
        [?2004h(\x08(exit 42)\x1b[?2004l\x0d\x0d\x0a\x1b]133;C;\
        holdfast=1\x07\x1b[1m\x1b[7m%\x1b[27m\x1b[1m\x1b[0m             \
        \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
        \x20\x20\x20\x20\x20\x20\x20\x20\x0d \x0d\x1b]133;D;42;holdfast=1\x07";

    #[test]
    fn real_bash_and_zsh_cycles_replay_unchanged_under_the_carriage_return_rule() {
        for (shell, raw) in [("bash 5.3", BASH_53_CYCLES), ("zsh 5.9", ZSH_59_CYCLES)] {
            let h = replay(raw, 100);
            let e = h.entries(0, 50);
            assert_eq!(e.len(), 2, "{shell}: {e:?}");
            // The whole entry, all three columns at once — a repair that
            // fills `command` in by breaking the span, or one that keeps
            // the spans while emptying `command`, fails exactly here.
            assert_eq!(
                e.iter().map(|x| x.command.as_str()).collect::<Vec<_>>(),
                vec!["echo hello", "(exit 42)"],
                "{shell}: the line editor's redraw reached the capture"
            );
            assert_eq!(
                e.iter().map(|x| x.exit_code).collect::<Vec<_>>(),
                vec![Some(0), Some(42)],
                "{shell}"
            );
            let span = &raw[e[0].output_start_cursor as usize
                ..e[0].output_end_cursor.expect("closed") as usize];
            let text = String::from_utf8_lossy(span);
            assert!(text.contains("hello\r\n"), "{shell}: span {text:?}");
            assert!(
                !span.windows(6).any(|w| w == b"\x1b]133;"),
                "{shell}: with no foreign emitter no marker belongs in the \
                 span — {text:?}"
            );
        }
    }

    /// The other half of the same capture, at the scanner: fish 4.0.2
    /// emits no `B` of its own, so `mixed` is not a constructed state.
    #[test]
    fn the_real_fish_4_0_2_collision_reports_a_mixed_marker_source() {
        let mut sc = ModeScanner::new();
        sc.feed(FISH_402_COLLISION, 0, None);
        assert_eq!(
            sc.osc133_source(),
            Some(crate::detect::Osc133Source::Mixed),
            "fish supplied no `B`, so `B` is still CLASP's"
        );
    }

    #[test]
    fn nonzero_exit_codes_are_kept() {
        let h = replay(
            b"\x1b]133;C\x07\x1b]133;D;42\x07\x1b]133;C\x07\x1b]133;D;1\x07",
            100,
        );
        let e = h.entries(0, 50);
        assert_eq!(
            e.iter().map(|x| x.exit_code).collect::<Vec<_>>(),
            vec![Some(42), Some(1)]
        );
    }

    #[test]
    fn a_running_command_has_no_end_cursor_yet() {
        let h = replay(b"\x1b]133;C\x07building...", 100);
        let e = h.entries(0, 50);
        assert_eq!(e[0].output_end_cursor, None);
        assert_eq!(e[0].exit_code, None);
        assert_eq!(e[0].duration_ms, None);
    }

    #[test]
    fn the_injection_command_produces_no_entry() {
        // Measured on bash and zsh: the line that installs the integration
        // runs before PS0/preexec exists, so the first marker of the
        // session is a bare `D`. It must not fabricate a history entry.
        let h = replay(b"\x1b]133;D;0\x07\x1b]133;A\x07$ \x1b]133;B\x07", 100);
        assert!(
            h.is_active(),
            "a marker was seen, so integration is working"
        );
        assert!(h.entries(0, 50).is_empty(), "bare D invented an entry");
        assert_eq!(h.total(), 0);
    }

    /// REQ-DM-009, §8.5.1 rule 5 — the *other* arrangement, and it is not
    /// the same test twice.
    ///
    /// `the_injection_command_produces_no_entry` above covers the case with
    /// no foreign emitter, where the snippet stays out because it emits no
    /// `C` at all. **That reasoning stops holding the moment another
    /// emitter is installed:** the user's own `PS0`/`preexec` marks the
    /// snippet's command line, a real `C` arrives carrying the snippet's
    /// echoed text, and — measured on fish 4.8.1 — the snippet became the
    /// session's first `get_command_history` entry. The two arrangements
    /// reach the same outcome by different routes and only one of them is
    /// today's behaviour, so both are required.
    ///
    /// The markers here are **untagged and therefore foreign** (§8.5.1
    /// rule 2), which is what makes this the foreign-emitter arrangement
    /// rather than a restatement of the row above.
    #[test]
    fn the_injection_command_produces_no_entry_when_a_foreign_emitter_marks_it() {
        let snippet =
            "if [ -z \"${HOLDFAST_SHELL_INTEGRATION-}\" ]; then HOLDFAST_SHELL_INTEGRATION=1; fi";
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(100);
        h.set_injection_line(snippet.to_string());
        let mut raw = Vec::new();
        // The foreign emitter's prompt, then the snippet's own echoed
        // command line between `B` and `C`, then its completion.
        raw.extend_from_slice(b"\x1b]133;A\x07$ \x1b]133;B\x07");
        raw.extend_from_slice(snippet.as_bytes());
        raw.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
        // And one ordinary command after it.
        raw.extend_from_slice(b"\x1b]133;A\x07$ \x1b]133;B\x07echo hi\r\n\x1b]133;C\x07hi\r\n");
        raw.extend_from_slice(b"\x1b]133;D;0\x07");
        let mut t = 1_000i64;
        for ev in sc.feed(&raw, 0, None) {
            h.apply(&ev, t);
            t += 10;
        }
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 1, "the install line became a history entry: {e:?}");
        assert_eq!(e[0].command, "echo hi");
        assert_eq!(e[0].exit_code, Some(0));
        assert!(
            e[0].output_end_cursor.is_some(),
            "the suppressed `D` closed the wrong entry"
        );
        assert!(
            h.is_active(),
            "a marker was seen, so integration is working"
        );
    }

    /// The suffix half of §8.5.1 rule 5, which nothing else separates from
    /// an equality test.
    ///
    /// The rule is written over a *suffix* because §5.2 documents the echo
    /// capture truncating to its tail at the terminal width: 125 characters
    /// typed at 80 columns are captured as the last 47. CLASP's snippets
    /// are 300-500 characters, so at any real width the capture is **always**
    /// a tail and never the whole line — which means an implementation
    /// spelled `line.trim_end() == command` suppresses the injection line
    /// at no terminal width anybody uses, while passing every fixture whose
    /// snippet happens to be short enough to fit.
    #[test]
    fn the_injection_line_is_matched_as_a_suffix_and_not_as_an_equality() {
        let snippet = "if [ -z \"${HOLDFAST_SHELL_INTEGRATION-}\" ]; then \
                       HOLDFAST_SHELL_INTEGRATION=1; PS0='mark'; PS1='mark'; fi";
        // What an 80-column terminal leaves of it: the tail, with the front
        // of the line overwritten by the line editor's wrap redraw.
        let captured = "PS0='mark'; PS1='mark'; fi";
        assert!(
            snippet.ends_with(captured) && snippet != captured,
            "the fixture must be a proper suffix, or it proves nothing"
        );
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(100);
        h.set_injection_line(snippet.to_string());
        let mut raw = Vec::new();
        raw.extend_from_slice(b"\x1b]133;A\x07$ \x1b]133;B\x07");
        raw.extend_from_slice(captured.as_bytes());
        raw.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
        raw.extend_from_slice(b"\x1b]133;A\x07$ \x1b]133;B\x07echo hi\r\n\x1b]133;C\x07hi\r\n");
        raw.extend_from_slice(b"\x1b]133;D;0\x07");
        let mut t = 1_000i64;
        for ev in sc.feed(&raw, 0, None) {
            h.apply(&ev, t);
            t += 10;
        }
        let e = h.entries(0, 50);
        assert_eq!(
            e.len(),
            1,
            "a truncated capture of the install line became an entry: {e:?}"
        );
        assert_eq!(e[0].command, "echo hi");
    }

    /// The third arrangement, and the one that was **measured wrong before
    /// it was written**: a foreign emitter that supplies no `B`.
    ///
    /// fish 4.0.2 emits `A;special_key=1`, `C;cmdline_url=…` and
    /// `D;<code>` and never `B` (measured on a live PTY; the marker shapes
    /// here are that capture's, and `FISH_402_COLLISION` above is the
    /// verbatim proof that `B` is missing — `mixed` is only reachable
    /// because CLASP's `B` had nothing to yield to). Nothing arms the echo
    /// capture before the snippet installs itself, so the injection line's
    /// `C` carries an **empty** command and the suffix test in §8.5.1 rule
    /// 5 has no text to compare.
    ///
    /// Driven against the real 4571-byte capture, the suffix test alone
    /// left the snippet as entry 0 with `command: ""` and `exit_code: 0`,
    /// ahead of the three real commands — REQ-DM-009's "never an entry"
    /// failing on precisely the shell the requirement was written for. So
    /// the rule identifies the line by the session's structure as well: a
    /// first `C` that no `B` ever preceded.
    #[test]
    fn the_injection_command_produces_no_entry_when_the_foreign_emitter_supplies_no_b() {
        let snippet =
            "if not set -q HOLDFAST_SHELL_INTEGRATION; set -g HOLDFAST_SHELL_INTEGRATION 1; end";
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(100);
        h.set_injection_line(snippet.to_string());
        let mut raw = Vec::new();
        // fish's own prompt: `A`, and no `B` at all.
        raw.extend_from_slice(b"\x1b]133;A;special_key=1\x07root@host /# ");
        // The snippet is typed and echoed, and fish marks it — with no `B`
        // the capture was never armed, so this `C` carries nothing.
        raw.extend_from_slice(snippet.as_bytes());
        raw.extend_from_slice(b"\r\n\x1b]133;C;cmdline_url=if%20not\x1b\\");
        raw.extend_from_slice(b"\x1b]133;D;0\x1b\\");
        // Now the snippet is installed, so CLASP's tagged `B` arrives and
        // gives the next command its span.
        raw.extend_from_slice(b"\x1b]133;A;special_key=1\x07\x1b]133;A;holdfast=1\x07$ ");
        raw.extend_from_slice(b"\x1b]133;B;holdfast=1\x07echo hi\r\n");
        raw.extend_from_slice(b"\x1b]133;C;cmdline_url=echo%20hi\x1b\\hi\r\n");
        raw.extend_from_slice(b"\x1b]133;D;0\x1b\\");
        let mut t = 1_000i64;
        for ev in sc.feed(&raw, 0, None) {
            h.apply(&ev, t);
            t += 10;
        }
        let e = h.entries(0, 50);
        assert_eq!(
            e.len(),
            1,
            "the install line became an entry with no command text: {e:?}"
        );
        assert_eq!(e[0].command, "echo hi");
        assert_eq!(e[0].exit_code, Some(0));
        assert!(
            e[0].output_end_cursor.is_some(),
            "the suppressed `D` closed the wrong entry"
        );
    }

    /// The negative that separates the row above from a ring that drops
    /// **any** `C` with an empty capture.
    ///
    /// Same empty capture, same first `OutputStart` — and a `B` in front of
    /// it, which is what a session with no foreign emitter always has by
    /// the time its first command runs, because CLASP's own `PS1` emits
    /// one. This entry must survive with its empty text: `command` is
    /// documented best-effort and an empty one is a *lossy capture*, not a
    /// reason to hide that a command ran at all.
    #[test]
    fn a_command_whose_capture_came_out_empty_is_still_an_entry() {
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(100);
        h.set_injection_line("some snippet text".to_string());
        let raw = b"\x1b]133;A;holdfast=1\x07$ \x1b]133;B;holdfast=1\x07\x1b]133;C;holdfast=1\x07\
                    out\r\n\x1b]133;D;7;holdfast=1\x07";
        let mut t = 1_000i64;
        for ev in sc.feed(raw, 0, None) {
            h.apply(&ev, t);
            t += 10;
        }
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 1, "a lossy capture cost the whole entry: {e:?}");
        assert_eq!(e[0].command, "");
        assert_eq!(e[0].exit_code, Some(7));
    }

    /// The negative that bounds the suppression: it is armed for exactly
    /// one `OutputStart`, so it can never become an open-ended filter on
    /// the user's own commands.
    ///
    /// `fi` is deliberately a suffix of every POSIX snippet CLASP types.
    /// Without the one-shot bound, a session in which the user later runs
    /// anything ending in `fi` silently loses that command from the
    /// history — and the entry that vanishes is a real one.
    #[test]
    fn only_the_first_command_can_be_the_injection_line() {
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(100);
        h.set_injection_line("fi".to_string());
        let raw = b"\x1b]133;A\x07$ \x1b]133;B\x07echo one\r\n\x1b]133;C\x07one\r\n\
                    \x1b]133;D;0\x07\x1b]133;A\x07$ \x1b]133;B\x07fi\r\n\x1b]133;C\x07\
                    \x1b]133;D;2\x07";
        let mut t = 1_000i64;
        for ev in sc.feed(raw, 0, None) {
            h.apply(&ev, t);
            t += 10;
        }
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 2, "the suppression outlived the injection line");
        assert_eq!(
            e.iter().map(|x| x.command.as_str()).collect::<Vec<_>>(),
            vec!["echo one", "fi"]
        );
        assert_eq!(
            e.iter().map(|x| x.exit_code).collect::<Vec<_>>(),
            vec![Some(0), Some(2)]
        );
    }

    #[test]
    fn a_finished_command_is_told_from_a_running_one_by_its_end_cursor_alone() {
        // `exit_code: None` is ambiguous by construction: `D` may carry no
        // code, and a code outside `i32` parses to `None` as well. Both
        // shapes leave a *finished* command looking field-for-field like a
        // running one except for `output_end_cursor`, so a consumer that
        // keys "is it done" off the exit code is wrong in both.
        for raw in [
            &b"\x1b]133;C\x07out\x1b]133;D\x07"[..],
            // Overflows parse::<i32> and degrades silently to None.
            &b"\x1b]133;C\x07out\x1b]133;D;99999999999\x07"[..],
        ] {
            let h = replay(raw, 100);
            let e = &h.entries(0, 50)[0];
            assert_eq!(e.exit_code, None, "{raw:?}");
            assert!(
                e.output_end_cursor.is_some(),
                "{raw:?}: a finished command reads as still running"
            );
            assert!(e.duration_ms.is_some(), "{raw:?}");
        }

        // The contrast, in the same test so the discriminator is the
        // assertion rather than a fact stated in a comment: a genuinely
        // running command differs in exactly that one field.
        let h = replay(b"\x1b]133;C\x07building", 100);
        let e = &h.entries(0, 50)[0];
        assert_eq!(e.exit_code, None);
        assert_eq!(e.output_end_cursor, None);
    }

    #[test]
    fn a_completion_only_ever_closes_the_newest_open_command() {
        // Two `C`s with no `D` between them — a nested shell, or a `D`
        // lost to a truncated write. `D` closes `entries.back()` and never
        // reaches past it, so entry 0 stays open for the life of the
        // session and *no* later `D` can close it. That is the safer
        // choice (OSC 133 carries nothing that says which command a `D`
        // belongs to, so reaching back would attach an exit code to a
        // guess) but it was neither documented nor asserted, and it is a
        // different sequence from the nesting case that is.
        let h = replay(b"\x1b]133;C\x07a\x1b]133;C\x07b\x1b]133;D;0\x07", 100);
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 2);
        assert_eq!(
            e[0].output_end_cursor, None,
            "the orphan was closed after all"
        );
        assert!(e[1].output_end_cursor.is_some());

        // And a second `D` does not walk back to it either — it is
        // dropped, exactly like the injection command's bare `D`.
        let mut bytes = b"\x1b]133;C\x07a\x1b]133;C\x07b\x1b]133;D;0\x07".to_vec();
        bytes.extend_from_slice(b"\x1b]133;D;7\x07");
        let h = replay(&bytes, 100);
        let e = h.entries(0, 50);
        assert_eq!(e[0].output_end_cursor, None, "the stray D reached back");
        assert_eq!(e[0].exit_code, None);
        assert_eq!(
            e[1].exit_code,
            Some(0),
            "the stray D reopened a closed entry"
        );
    }

    #[test]
    fn a_backwards_wall_clock_cannot_produce_an_absurd_duration() {
        // `duration_ms` is unsigned and computed from a *wall* clock, so a
        // clock that steps backwards between `C` and `D` — NTP, a VM
        // resuming, a container's clock being set — makes the signed
        // subtraction negative and the cast enormous. Unclamped, 100 ms
        // backwards reports 18446744073709551516 ms to the agent.
        let mut sc = ModeScanner::new();
        let mut h = CommandHistory::new(100);
        let evs = sc.feed(b"\x1b]133;C\x07out\x1b]133;D;0\x07", 0, None);
        h.apply(&evs[0], 1_000);
        h.apply(&evs[1], 900);
        assert_eq!(h.entries(0, 50)[0].duration_ms, Some(0));
    }

    #[test]
    fn a_second_completion_does_not_reopen_a_finished_entry() {
        let mut bytes = ONE_COMMAND.to_vec();
        bytes.extend_from_slice(b"\x1b]133;D;9\x07");
        let h = replay(&bytes, 100);
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 1);
        assert_eq!(
            e[0].exit_code,
            Some(0),
            "the stray D overwrote the real code"
        );
    }

    #[test]
    fn the_ring_evicts_oldest_and_reports_truncation() {
        let mut bytes = Vec::new();
        for i in 0..5 {
            bytes.extend_from_slice(b"\x1b]133;B\x07cmd");
            bytes.push(b'0' + i);
            bytes.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
        }
        // A cap of 3 against 5 commands, not 2. At 2, an implementation that
        // *clears the whole ring* on overflow lands on the same final two
        // entries as one that drops a single entry at a time, so nothing
        // below can tell them apart. At 3 they diverge: dropping one at a
        // time keeps three, clearing keeps one.
        let h = replay(&bytes, 3);
        assert!(h.truncated_at_tail());
        assert_eq!(h.total(), 5);
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 3, "the ring dropped more than it overflowed by");
        // Indices are monotonic across eviction, so a cursor-style
        // `since_index` still works after the ring wraps.
        assert_eq!(e.iter().map(|x| x.index).collect::<Vec<_>>(), vec![2, 3, 4]);
        assert_eq!(e[0].command, "cmd2");

        // A zero cap is clamped to one, not honoured literally — otherwise
        // every entry is evicted by the push that adds it and the history
        // is permanently empty.
        let h = replay(&bytes, 0);
        let e = h.entries(0, 50);
        assert_eq!(e.len(), 1, "a zero cap swallowed the whole ring");
        assert_eq!(e[0].index, 4);
    }

    #[test]
    fn since_index_and_limit_select_a_window() {
        let mut bytes = Vec::new();
        for i in 0..5 {
            bytes.extend_from_slice(b"\x1b]133;B\x07cmd");
            bytes.push(b'0' + i);
            bytes.extend_from_slice(b"\r\n\x1b]133;C\x07\x1b]133;D;0\x07");
        }
        let h = replay(&bytes, 100);
        // The other half of the eviction pair: nothing was dropped here, so
        // nothing may report that it was. `truncated_at_tail` tells the
        // agent its history has holes; a flag that is always on says every
        // history is incomplete.
        assert!(
            !h.truncated_at_tail(),
            "reported a truncation that never happened"
        );
        assert_eq!(
            h.entries(3, 50).iter().map(|e| e.index).collect::<Vec<_>>(),
            vec![3, 4]
        );
        // `limit` keeps the newest, not the oldest.
        assert_eq!(
            h.entries(0, 2).iter().map(|e| e.index).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn a_session_with_no_markers_is_inactive() {
        let h = replay(b"$ ls\r\nfile\r\n$ ", 100);
        assert!(!h.is_active());
        assert!(h.entries(0, 50).is_empty());
    }
}
