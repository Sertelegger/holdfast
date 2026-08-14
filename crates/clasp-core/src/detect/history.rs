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
        }
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
            Osc133::PromptStart | Osc133::CommandStart => {}
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
