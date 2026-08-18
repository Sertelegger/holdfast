//! The tiered classifier (spec §8.3, §8.4) and the state it needs.

use super::patterns::PatternSet;
use super::scanner::{ModeScanner, Osc133Event, Osc133Source};
use crate::pty::LineDiscipline;
use std::time::Instant;

/// Default `settle_threshold_ms` (spec §4.2).
pub const DEFAULT_SETTLE_THRESHOLD_MS: u64 = 250;

/// What the session is doing right now (spec §18.2a). Orthogonal to
/// `SessionState`, which answers whether the session exists at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionMode {
    AtPrompt,
    Executing,
    AwaitingSecret,
    Fullscreen,
    Exited,
}

impl InteractionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtPrompt => "AtPrompt",
            Self::Executing => "Executing",
            Self::AwaitingSecret => "AwaitingSecret",
            Self::Fullscreen => "Fullscreen",
            Self::Exited => "Exited",
        }
    }
}

/// Which mechanism produced `interaction_mode`, so the agent can tell a
/// measurement from a guess (spec §18.2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionTier {
    Semantic,
    TerminalMode,
    Heuristic,
}

impl DetectionTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::TerminalMode => "terminal_mode",
            Self::Heuristic => "heuristic",
        }
    }
}

/// Everything a prompt-bearing response reports (spec §5.4, §18.2a).
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub interaction_mode: InteractionMode,
    pub detection_tier: DetectionTier,
    pub confidence: f32,
    pub quiescent_score: f32,
    pub pattern_score: f32,
    /// Always 0.0 until Tier-B tracking lands in 0.0.4 (§8.6 T3c). Present
    /// now so the response shape does not change when it becomes real.
    pub cursor_score: f32,
    pub reason: String,
    pub last_line: String,
    /// Whether `last_line` lost bytes off its front to the scanner's
    /// `TAIL_LINE_MAX` bound (§4.1's 512-byte tail).
    ///
    /// **This is not an MCP field and must not become one.** It travels
    /// only as far as `mcp::detection`, which needs it to decide whether
    /// the line can be *reported* (§9.2): a front-truncated line has lost
    /// the leading literal both redaction mechanisms anchor on, so
    /// "no rule matched" no longer means "no secret is present".
    ///
    /// Nothing in the classifier reads it. `pattern_score` below is scored
    /// from `last_line` as it stands, which is what it has always been —
    /// the truncation happens in the scanner, upstream of every score.
    pub last_line_truncated: bool,
    pub title: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub settle_threshold_ms: u64,
    pub patterns: PatternSet,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            settle_threshold_ms: DEFAULT_SETTLE_THRESHOLD_MS,
            patterns: PatternSet::defaults(),
        }
    }
}

#[derive(Debug)]
pub struct PromptDetector {
    scanner: ModeScanner,
    config: DetectionConfig,
    last_output: Instant,
}

impl Default for PromptDetector {
    fn default() -> Self {
        Self::new(DetectionConfig::default())
    }
}

impl PromptDetector {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            scanner: ModeScanner::new(),
            config,
            last_output: Instant::now(),
        }
    }

    /// Feed one chunk of raw PTY output. `base` is the absolute offset of
    /// `bytes[0]`. Returns the OSC 133 markers it carried, for the command
    /// history to consume.
    pub fn feed(&mut self, bytes: &[u8], base: u64, foreground: Option<i32>) -> Vec<Osc133Event> {
        self.feed_at(bytes, base, foreground, Instant::now())
    }

    /// `feed` with an injected clock, so quiescence can be tested without
    /// sleeping.
    pub fn feed_at(
        &mut self,
        bytes: &[u8],
        base: u64,
        foreground: Option<i32>,
        now: Instant,
    ) -> Vec<Osc133Event> {
        // A zero-length chunk is not output, and must not restart the
        // settle clock. The session reader never feeds one — it treats
        // `Ok(0)` as "nothing yet" and loops without calling here — but
        // the guard belongs with the rule rather than with its one caller:
        // a backend that reported empty reads would give a session that
        // *never settles*, so its prompt is never reported and the agent
        // waits on a shell that is sitting idle.
        if bytes.is_empty() {
            return Vec::new();
        }
        self.last_output = now;
        self.scanner.feed(bytes, base, foreground)
    }

    /// Whose OSC 133 markers this session is using (§18.2a, §8.5.1).
    /// `None` until the first marker arrives.
    pub fn osc133_source(&self) -> Option<Osc133Source> {
        self.scanner.osc133_source()
    }

    pub fn snapshot(
        &mut self,
        alive: bool,
        line: LineDiscipline,
        foreground: Option<i32>,
        cursor: Option<f32>,
    ) -> Detection {
        self.snapshot_at(alive, line, foreground, cursor, Instant::now())
    }

    /// Classify, per spec §8.3/§8.4.
    ///
    /// Ordering note (a spec ambiguity resolved here, deliberately): §8.1
    /// gives T1 priority over T2, but §8.3's T2 ladder checks alt-screen
    /// and echo *first*. Applying T1 blanketly misclassifies anything
    /// launched from an integrated shell — a pager, a REPL, or a `sudo`
    /// password prompt all sit inside one OSC 133 `C..D` span, so T1 alone
    /// answers `Executing` and the agent never learns a secret is wanted.
    /// The tiers are not in conflict there: T1 says *a command is
    /// running*, T2 says *what kind of thing it is doing*. So the ladder
    /// is: liveness, then alt-screen, then T1's prompt state, then
    /// echo-off, then bracketed paste, then T1/T2 "executing", then T3.
    /// Verified against every row of the §8.7 matrix.
    pub fn snapshot_at(
        &mut self,
        alive: bool,
        line: LineDiscipline,
        foreground: Option<i32>,
        cursor: Option<f32>,
        now: Instant,
    ) -> Detection {
        let modes = self.scanner.modes();
        let last_line = self.scanner.last_line();
        let title = self.scanner.title().map(str::to_owned);

        let quiescent_score = self.quiescent_score(now);
        let pattern_score = self.config.patterns.score(&last_line);
        // `None` is Tier B off, which is the ordinary case for a
        // line-oriented session; `max(pattern, cursor)` then degenerates
        // to `pattern`, which is the correct answer rather than a
        // leftover. The stability gate lives in `screen::cursor`, so an
        // unstable cursor arrives here as 0.0 already.
        let cursor_score = cursor.unwrap_or(0.0);

        // Availability, not current value: a program that has never driven
        // a terminal mode (`dash`) cannot be classified by one, and must
        // fall through to T3 rather than be read as "not at a prompt".
        //
        // Availability is stated **per signal**, not per tier (§8.3), and
        // since rev. 37 it is **scoped**: a record belongs to the program
        // that emitted the signal and licenses its rung only while that
        // program still holds the terminal. Which signals confer it is
        // unchanged:
        //
        // - **bracketed paste** licenses the T2 executing rung below, and
        //   only that rung. That rung infers *prompt mode is off, therefore
        //   not at a prompt*, which is valid exactly for a program known to
        //   signal its prompts with bracketed paste — off means
        //   not-at-a-prompt precisely because on is what it does at a
        //   prompt.
        // - **alternate screen** licenses nothing. Observing it says a
        //   child took the whole screen and later gave it back; it supports
        //   no inference about whether the shell now holding the tty
        //   signals its prompts at all. The `Fullscreen` rung reads
        //   alt-screen's *current* value and so needs no availability
        //   notion — and therefore no scope either.
        // - **termios `ECHO`/`ICANON`** likewise: readable is not observed.
        //   `dash` has a perfectly readable `ECHO` and it is *on* at a
        //   `dash` prompt, so a T2 answer there would be actively wrong.
        //
        // **Three instances of one cause, and scope is the fix for the
        // cause.** The count is three — §8.3's, and this comment said
        // *four* while enumerating the same three, which is the discrepancy
        // rev. 42 asked to be settled. Through rev. 27 this read
        // `saw_bracketed_paste || saw_alt_screen`, and one alt-screen toggle
        // marked a session T2-available for life — the executing rung then
        // answered `Executing` at every later live prompt of a shell driving
        // no terminal modes at all, with `pattern_score: 0.60` contradicting
        // it in the same payload and §8.4 telling the agent to wait. That is
        // one. Rev. 28 narrowed the *signal list* and the identical failure
        // re-entered through the one signal it had just finished arguing
        // was legitimate (§8.7 row 7b) — two — and `saw_osc133` was found
        // unpinned in the T1 dimension by the 0.0.2 final review — three.
        // Each was treated as a defect in one flag. It was not: the defect
        // is that the licence outlived its subject. Narrowing the list a
        // **fourth** time would have been the same move a fourth time, and
        // the fourth instance would have arrived through whichever signal
        // is added next.
        //
        // **Both executing rungs are scoped by the one rule**, because
        // both have the same shape. The T2 rung infers *prompt mode is
        // off, therefore this program is not at a prompt* — a claim about
        // a program. The T1 rung infers *a `C` arrived with no `D` since,
        // therefore a command is running* — true of the shell that emitted
        // the markers, used to answer a question about whatever the shell
        // launched. In both the premise names a program, the old rule
        // tracked a session, and every child a shell launches sat in the
        // gap. The T1 *prompt-marker* rung is scoped by the same rule and
        // is unaffected in practice: `A`/`B` last means no `C` has
        // arrived, means no command is running, means the emitting shell
        // *is* the foreground program — so §8.5's nesting property
        // survives, markers from a shell inside `ssh` being owned by
        // `ssh`'s group.
        //
        // **The two residuals, measured and accepted.** `set +m` (job
        // control off) and `exec` both keep the process group while the
        // program behind it changes, so the child inherits the record.
        // Both require the terminal itself to be unable to distinguish the
        // programs — one foreground group, a different program behind it —
        // so no cheaper signal separates them.
        //
        // **The cost, stated rather than left to be found.** Every
        // external command now classifies through T3: `Executing` /
        // `semantic` / 0.00 and `Executing` / `terminal_mode` / 0.00
        // become `Executing` / `heuristic`. The mode and the agent's
        // action are unchanged; what changes is that the answer is
        // labelled a guess, which is what it is. Withdrawing a licence can
        // only move an answer *down* the ladder, and that is the price of
        // not answering `Executing` deterministically at a live prompt —
        // a wrong deterministic `Executing` is unrecoverable, since §8.4
        // tells the agent to wait and nothing in the session can clear it.
        //
        // See the `availability` test module for the rows that pin this on
        // both axes: signal membership (REQ-PD-015) and scope
        // (REQ-PD-026).

        /// §8.3's scope rule, in one place because it applies to both
        /// executing rungs, to the T1 prompt-marker rung, and to the
        /// exited tier.
        ///
        /// A licence is withheld **only when owner and holder are both
        /// known and differ**. Absence is not a change: an unknown owner
        /// or an unknown holder reproduces the pre-rev.-37 session-scoped
        /// answer exactly, never a third one, which is what covers ConPTY
        /// and every failed ioctl (REQ-PD-025).
        fn licensed(observed: bool, owner: Option<i32>, holder: Option<i32>) -> bool {
            observed && !matches!((owner, holder), (Some(o), Some(h)) if o != h)
        }

        let t1 = licensed(modes.saw_osc133, modes.osc133_owner, foreground);
        let t2_prompt_mode = licensed(
            modes.saw_bracketed_paste,
            modes.bracketed_paste_owner,
            foreground,
        );
        let session_tier = if t1 {
            DetectionTier::Semantic
        } else if t2_prompt_mode {
            DetectionTier::TerminalMode
        } else {
            DetectionTier::Heuristic
        };
        let at_marker = matches!(self.scanner.last_marker(), Some(b'A') | Some(b'B'));

        // §8.3's echo rung, and the two flags are tri-state independently.
        //
        //   echo          icanon        rung
        //   Some(false)   Some(true)    fires   — a genuine secret prompt
        //   Some(false)   None          fires   — identical to pre-rev.-36
        //   Some(false)   Some(false)   skipped — readline's shape
        //   None/Some(true) any         skipped, as before
        //
        // A program that wants a secret *line* turns echo off and stays
        // canonical, because it wants the kernel's line discipline to
        // assemble the line. A line editor turns echo off and leaves
        // canonical mode, because it draws the characters itself.
        //
        // Measured, and the reason the conjunct exists: a CPython 3.12
        // `>>> ` prompt is `ECHO off / ICANON off` with no bracketed paste
        // — PyREPL, which drives the paste, landed in 3.13 — so before
        // rev. 36 this rung answered `AwaitingSecret` / 0.95 at an
        // ordinary REPL prompt, and §8.4 tells the agent that means call
        // `request_secret_input`.
        //
        // `ICANON` is strictly better and it is **not sufficient**.
        // `read -s -n 1` reports `ECHO off / ICANON off` — the readline
        // shape — while being a genuine secret prompt, because a
        // single-character read leaves canonical mode by construction. It
        // now falls past this rung (§8.7 row 8, REQ-PD-022), and rev. 37's
        // scoping does not rescue it either: `read` is a **builtin**, so
        // the shell keeps the foreground group and the T2 executing rung's
        // premise really does hold. What the change buys is that the
        // false-positive class shrinks from *every echo-off readline
        // prompt* to *nothing measured*; what it does not buy is a
        // complete `AwaitingSecret` signal, and §8.4 says so where an agent
        // acting on the mode will meet it.
        let (interaction_mode, detection_tier, confidence, reason) = if !alive {
            (
                InteractionMode::Exited,
                session_tier,
                0.0,
                "child has exited".to_string(),
            )
        } else if modes.alt_screen {
            (
                InteractionMode::Fullscreen,
                DetectionTier::TerminalMode,
                0.0,
                "alternate screen is active".to_string(),
            )
        } else if t1 && at_marker {
            (
                InteractionMode::AtPrompt,
                DetectionTier::Semantic,
                1.0,
                "osc 133 prompt marker with no command started since".to_string(),
            )
        } else if line.echo == Some(false)
            && line.canonical != Some(false)
            && !modes.bracketed_paste
        {
            (
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
                "echo disabled without leaving canonical mode, \
                 and no bracketed paste"
                    .to_string(),
            )
        } else if modes.bracketed_paste {
            (
                InteractionMode::AtPrompt,
                DetectionTier::TerminalMode,
                0.95,
                "bracketed paste is enabled".to_string(),
            )
        } else if t1 {
            (
                InteractionMode::Executing,
                DetectionTier::Semantic,
                0.0,
                "osc 133 output marker with no completion since".to_string(),
            )
        } else if t2_prompt_mode {
            (
                InteractionMode::Executing,
                DetectionTier::TerminalMode,
                0.0,
                "this program signals its prompts with bracketed paste, \
                 and it is disabled"
                    .to_string(),
            )
        } else {
            let evidence = pattern_score.max(cursor_score);
            let confidence = quiescent_score * evidence;
            let mode = if confidence >= 0.5 {
                InteractionMode::AtPrompt
            } else {
                InteractionMode::Executing
            };
            (
                mode,
                DetectionTier::Heuristic,
                confidence,
                format!(
                    "no deterministic signal; quiescent {quiescent_score:.2} \
                     x max(pattern {pattern_score:.2}, cursor {cursor_score:.2})"
                ),
            )
        };

        Detection {
            interaction_mode,
            detection_tier,
            confidence,
            // Exiting zeroes the scores: nothing about a dead child's last
            // line is evidence that it wants input (§8.3).
            quiescent_score: if alive { quiescent_score } else { 0.0 },
            pattern_score: if alive { pattern_score } else { 0.0 },
            cursor_score,
            reason,
            last_line,
            last_line_truncated: self.scanner.last_line_truncated(),
            title,
        }
    }

    fn quiescent_score(&self, now: Instant) -> f32 {
        let threshold = self.config.settle_threshold_ms.max(1);
        let elapsed = now.saturating_duration_since(self.last_output).as_millis() as f64;
        ((elapsed / threshold as f64) as f32).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::patterns::PromptPattern;
    use std::time::Duration;

    /// A detector plus the two instants its tests need: `start`, which
    /// every `feed` below is stamped with, and `settled`, far enough past
    /// it that the session reads fully quiescent.
    ///
    /// Both are fixed. `feed` used to stamp with `Instant::now()` and
    /// `settled` was ten seconds past a *separately* sampled `now`, so the
    /// interval these tests measure was really "however long the test took
    /// plus ten seconds" — the same live-clock dependence that let a
    /// detector with a frozen `last_output` answer every assertion in
    /// `quiescence_gates_the_heuristic` identically.
    fn detector() -> (PromptDetector, Instant, Instant) {
        let start = Instant::now();
        (
            PromptDetector::default(),
            start,
            start + Duration::from_secs(10),
        )
    }

    fn feed(d: &mut PromptDetector, at: Instant, bytes: &[u8]) {
        d.feed_at(bytes, 0, None, at);
    }

    /// A readable line discipline. `ld(false, false)` is readline's shape
    /// — echo off, canonical off — and `ld(false, true)` is a secret
    /// prompt's.
    fn ld(echo: bool, canonical: bool) -> LineDiscipline {
        LineDiscipline {
            echo: Some(echo),
            canonical: Some(canonical),
        }
    }

    // ---- the §8.7 measurement matrix, replayed as byte streams ----
    //
    // The mode/echo values in each row are the ones measured against real
    // PTYs in the spike and re-measured in the 0.0.2 integration suite.

    #[test]
    fn matrix_idle_bash_prompt() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004hbash-5.3$ ");
        // §8.2's table row 1: an idle bash prompt is `ECHO off / ICANON
        // off` — readline's shape. It answers at the bracketed-paste rung
        // either way, which is what makes the row insensitive to the
        // conjunct rather than lucky.
        let s = d.snapshot_at(true, ld(false, false), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.95);
    }

    /// §8.7 row 2 — `sleep 2`, at rev. 37's values.
    ///
    /// **Flipped, not relaxed.** Through rev. 36 this row answered
    /// `Executing` / `terminal_mode` / 0.00 and the fixture passed `None`
    /// for both the owner and the holder, which is the *unknown* arm —
    /// correct under the old rule and blind to the new one. bash drove the
    /// paste; `sleep` is its own process group and holds the terminal, so
    /// the licence bash earned says nothing about it and the answer is a
    /// guess. Same mode, same action for the agent, honest tier.
    ///
    /// `Some(100)` / `Some(200)` are the measured shape of that transition
    /// (a real bash launching an external command was sampled at
    /// `3708113 → 3708114`); the values themselves only have to differ.
    #[test]
    fn matrix_during_a_running_command() {
        let (mut d, start, now) = detector();
        d.feed_at(b"\x1b[?2004h\x1b[?2004lsleep 2\r\n", 0, Some(100), start);
        let s = d.snapshot_at(true, ld(true, true), Some(200), None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
        assert_eq!(s.detection_tier, DetectionTier::Heuristic);
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn matrix_getpass_prompt() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"Password: ");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        // §8.4's number, and the one that matters most of the four: it is
        // what an agent thresholds on before calling request_secret_input,
        // so a silent drop to 0.10 stops that tool from ever firing.
        assert_eq!(s.confidence, 0.95);
    }

    #[test]
    fn matrix_bash_read_s_prompt() {
        let (mut d, start, now) = detector();
        // A `read -s` runs inside a shell that has already used bracketed
        // paste; the mode is off while the command runs.
        feed(&mut d, start, b"\x1b[?2004h\x1b[?2004lPassword: ");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
    }

    #[test]
    fn matrix_real_ssh_password_prompt() {
        // §8.7's fifth row, and the one the spike called out specially:
        // `ssh` is not readline and prints its own prompt, so this row is
        // the evidence that the `AwaitingSecret` rung generalises past
        // `getpass()` and bash's `read -s`. It ran under a shell that had
        // already driven bracketed paste (`Seen BrktPst: yes`), which the
        // stream below reproduces.
        let (mut d, start, now) = detector();
        feed(
            &mut d,
            start,
            b"\x1b[?2004h\x1b[?2004lssh prod-01\r\njane@prod-01's password: ",
        );
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.95);
    }

    #[test]
    fn matrix_python_repl_prompt() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h>>> ");
        // §8.7 row 6, PyREPL: `ECHO off / ICANON off` with bracketed paste
        // **on**. Answers at the bracketed-paste rung either way.
        let s = d.snapshot_at(true, ld(false, false), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    /// The §8.7 row the matrix does not carry — and the one CI found by
    /// running the acceptance suite on a host the author's box does not
    /// resemble.
    ///
    /// Every §8.7 row is a *readline* session, so every one of them has
    /// bracketed paste on at its prompt and the echo rung is never reached
    /// there. This is the same readline prompt with bracketed paste
    /// **absent**: the classic readline REPL (`PYTHON_BASIC_REPL=1`, and
    /// every CPython before 3.13), a `psql` built against a readline whose
    /// `enable-bracketed-paste` is off, anything using `editline`. Before
    /// rev. 36 §8.3's rung read `echo == Some(false) && !bracketed_paste`
    /// and answered `AwaitingSecret` — at an ordinary REPL prompt, at the
    /// 0.95 §8.4 tells the agent to answer by calling
    /// `request_secret_input`.
    ///
    /// **The termios state is what separates the two, and the detector is
    /// now handed it.** Measured on this host (`tcgetattr` on the master
    /// fd, one sample per scenario):
    ///
    /// ```text
    /// bash idle prompt                ECHO off / ICANON off
    /// python3 -q (PyREPL, 3.13/3.14)  ECHO off / ICANON off
    /// python3 -q PYTHON_BASIC_REPL=1  ECHO off / ICANON off
    /// getpass()                       ECHO off / ICANON ON
    /// bash read -s                    ECHO off / ICANON ON
    /// bash read -s -n 1               ECHO off / ICANON off   (the false negative)
    /// ```
    ///
    /// A line editor turns echo off and *leaves* canonical mode because it
    /// is drawing the characters itself; a shell that wants a whole secret
    /// line turns echo off and *stays* canonical.
    ///
    /// **This test was written to be flipped, and this is the flip.** The
    /// rung now consults `ICANON` (REQ-PD-020), so half 1's answer is the
    /// T3 answer its own tail already scores — `AtPrompt` / `heuristic` /
    /// 0.9, the value that used to sit inertly in `pattern_score`
    /// contradicting the payload it arrived in. Halves 2 and 3 do not
    /// move, and that is what makes the flip mean something: half 2 is the
    /// pair, differing from half 1 in `ICANON` and in nothing else, so a
    /// rung that stopped firing altogether would take half 1 to the right
    /// answer *and* half 2 to the wrong one. Half 3 separates both from
    /// the degenerate case where the tail alone carries the answer.
    ///
    /// `read -s -n 1` measures `off/off` while being a genuine secret
    /// prompt and therefore moves *with* half 1. That is REQ-PD-022's
    /// point rather than a regression: `ICANON` is a strictly better
    /// discriminator and not a sufficient one.
    #[test]
    fn matrix_echo_off_at_a_prompt_shaped_tail_with_no_bracketed_paste() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b">>> ");
        let s = d.snapshot_at(true, ld(false, false), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::Heuristic);
        assert!((s.confidence - 0.9).abs() < 1e-6, "{}", s.confidence);
        // 0.90 is `quiescent_score 1.0 x pattern_score 0.9`. This
        // assertion predates the flip and used to contradict the answer
        // beside it; it now corroborates it.
        assert!((s.pattern_score - 0.9).abs() < 1e-6, "{}", s.pattern_score);

        // The genuine secret prompt, unmoved. This is the pair: the two
        // halves differ in `ICANON` (off vs ON, measured above) and in
        // nothing else, so a rung that stopped firing at all would take
        // half 1 to the right answer and this one to the wrong one.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"Password: ");
        let secret = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(secret.interaction_mode, InteractionMode::AwaitingSecret);
        assert_eq!(secret.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(secret.confidence, 0.95);

        // The negative that separates both from the degenerate case: with
        // echo *on* the same tail is a T3 answer, so the rung above is
        // genuinely deciding these rows rather than the tail carrying them.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b">>> ");
        let echoing = d.snapshot_at(true, ld(true, true), None, None, now);
        assert_eq!(echoing.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(echoing.detection_tier, DetectionTier::Heuristic);
        assert!(
            (echoing.confidence - 0.9).abs() < 1e-6,
            "{}",
            echoing.confidence
        );
    }

    #[test]
    fn matrix_inside_a_tui() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?1049h:");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Fullscreen);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        // Zero, and deliberately so: §8.4 reports Fullscreen as a *fact*
        // about the terminal, not as a graded belief about a prompt, and
        // the agent has nothing to act on. Left unpinned, 0.0 could become
        // 1.0 without a single test noticing.
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn matrix_dash_prompt_falls_through_to_the_heuristic() {
        // `dash` drives no terminal mode and leaves ECHO on, so the T2
        // ladder would answer `Executing` at a live prompt. Availability
        // gating is what stops it (§8.6).
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"$ ");
        let s = d.snapshot_at(true, ld(true, true), None, None, now);
        assert_eq!(s.detection_tier, DetectionTier::Heuristic);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert!((s.confidence - 0.6).abs() < 1e-6, "{}", s.confidence);
    }

    /// One row of the §8.7 matrix as `the_8_7_matrix_…` walks it:
    /// `(row, stream, line discipline, owner at scan, holder at classify,
    /// mode, tier, confidence)`.
    ///
    /// A named alias rather than the tuple inline because
    /// `clippy::type_complexity` is a hard error here; the field order is
    /// the same as the table's columns.
    type MatrixRow = (
        &'static str,
        &'static [u8],
        LineDiscipline,
        Option<i32>,
        Option<i32>,
        InteractionMode,
        DetectionTier,
        f32,
    );

    /// The §8.7 matrix at rev. 37, **every** row, at mode, tier **and**
    /// confidence, with the foreground group each row was measured with.
    ///
    /// The individual `matrix_*` tests above assert the rows they are named
    /// for; this one asserts that no *other* row moved. That is REQ-PD-004's
    /// "and nothing else in the §8.7 matrix", and no per-row test can express
    /// it — a per-row test is a fixed point, and "nothing else fires" is a
    /// property of the whole table.
    ///
    /// Row 8 is a **wrong answer asserted as present** (REQ-PD-022): a
    /// genuine secret prompt the ladder does not label, because
    /// `read -s -n 1` is a builtin — it keeps the shell's group, so rev. 37's
    /// scoping does not touch it, and it leaves canonical mode, so the echo
    /// rung does not fire. It answers `Executing` deterministically at a
    /// prompt that cannot proceed without a secret. Asserted at what the
    /// ladder answers so a rewrite of the rung has to edit an assertion to
    /// change the limit.
    #[test]
    fn the_8_7_matrix_classifies_every_row_and_awaiting_secret_fires_on_exactly_three() {
        let rows: &[MatrixRow] = &[
            (
                "1 idle bash prompt",
                b"\x1b[?2004hbash-5.3$ ",
                ld(false, false),
                Some(100),
                Some(100),
                InteractionMode::AtPrompt,
                DetectionTier::TerminalMode,
                0.95,
            ),
            (
                "2 during sleep 2 — external command, own group",
                b"\x1b[?2004h\x1b[?2004lsleep 2\r\n",
                ld(true, true),
                Some(100),
                Some(200),
                InteractionMode::Executing,
                DetectionTier::Heuristic,
                0.0,
            ),
            (
                "3 getpass()",
                b"Password: ",
                ld(false, true),
                Some(100),
                Some(200),
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
            ),
            (
                "4 bash read -s — builtin, shell's group",
                b"\x1b[?2004h\x1b[?2004lPassword: ",
                ld(false, true),
                Some(100),
                Some(100),
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
            ),
            (
                "5 real ssh password prompt",
                b"\x1b[?2004h\x1b[?2004lssh prod-01\r\njane@prod-01's password: ",
                ld(false, true),
                Some(100),
                Some(200),
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
            ),
            (
                "6 PyREPL, bracketed paste on",
                b"\x1b[?2004h>>> ",
                ld(false, false),
                Some(200),
                Some(200),
                InteractionMode::AtPrompt,
                DetectionTier::TerminalMode,
                0.95,
            ),
            (
                "7 readline REPL, session is the REPL",
                b">>> ",
                ld(false, false),
                Some(200),
                Some(200),
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
            ),
            (
                "7b the same REPL launched from bash",
                b"\x1b[?2004h\x1b[?2004lpython3 -q\r\n>>> ",
                ld(false, false),
                Some(100),
                Some(200),
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
            ),
            (
                "8 bash read -s -n 1 — builtin, shell's group",
                b"\x1b[?2004h\x1b[?2004lread -s -n 1 -p 'Key: ' k\r\nKey: ",
                ld(false, false),
                Some(100),
                Some(100),
                InteractionMode::Executing,
                DetectionTier::TerminalMode,
                0.0,
            ),
            (
                "9 inside less",
                b"\x1b[?1049h:",
                ld(false, false),
                Some(100),
                Some(200),
                InteractionMode::Fullscreen,
                DetectionTier::TerminalMode,
                0.0,
            ),
        ];
        let mut fired = Vec::new();
        let mut by_row = std::collections::BTreeMap::new();
        for (row, bytes, line, owner, holder, mode, tier, confidence) in rows {
            let (mut d, start, now) = detector();
            d.feed_at(bytes, 0, *owner, start);
            let s = d.snapshot_at(true, *line, *holder, None, now);
            assert_eq!(s.interaction_mode, *mode, "row {row}");
            assert_eq!(s.detection_tier, *tier, "row {row}");
            assert!(
                (s.confidence - *confidence).abs() < 1e-6,
                "row {row}: {}",
                s.confidence
            );
            if s.interaction_mode == InteractionMode::AwaitingSecret {
                fired.push(*row);
            }
            by_row.insert(*row, (s.interaction_mode, s.detection_tier, s.confidence));
        }
        // REQ-PD-004: `getpass()`, `read -s`, a real `ssh` prompt — and
        // nothing else in the matrix. Soundness, not completeness: row 8 is
        // a genuine secret prompt and is deliberately not among them.
        assert_eq!(
            fired.len(),
            3,
            "AwaitingSecret fires on exactly three rows: {fired:?}"
        );

        // REQ-PD-026's acceptance criterion, and it is a *property*, not a
        // value: rows 7 and 7b are the same program at the same prompt,
        // sampled identically on every signal, differing only in what the
        // session observed earlier. Any rule under which they disagree is
        // reading session history where the premise names a program.
        // Asserted alongside the values above, never instead of them — an
        // equality assertion alone passes if both regress together.
        assert_eq!(
            by_row["7 readline REPL, session is the REPL"],
            by_row["7b the same REPL launched from bash"],
            "rows 7 and 7b must answer identically"
        );
    }

    // ---- tier precedence ----

    #[test]
    fn echo_alone_is_not_a_secret_prompt() {
        // The spike's finding: ECHO is *off* at an ordinary readline
        // prompt. A classifier keyed on ECHO alone would report
        // AwaitingSecret for every prompt in the matrix.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004hbash-5.3$ ");
        assert_eq!(
            d.snapshot_at(true, ld(false, true), None, None, now)
                .interaction_mode,
            InteractionMode::AtPrompt
        );
    }

    #[test]
    fn a_password_prompt_inside_an_integrated_shell_still_reports_awaiting_secret() {
        // Regression guard for the tier-ordering decision. `sudo` runs
        // inside one OSC 133 C..D span, so a T1-first classifier answers
        // `Executing` and the agent never calls request_secret_input.
        let (mut d, start, now) = detector();
        feed(
            &mut d,
            start,
            b"\x1b]133;A\x07$ \x1b]133;B\x07sudo id\r\n\x1b]133;C\x07",
        );
        feed(&mut d, start, b"\x1b[?2004l[sudo] password for alice: ");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn a_repl_inside_an_integrated_shell_reports_at_prompt() {
        let (mut d, start, now) = detector();
        feed(
            &mut d,
            start,
            b"\x1b]133;A\x07$ \x1b]133;B\x07python3\r\n\x1b]133;C\x07",
        );
        feed(&mut d, start, b"\x1b[?2004h>>> ");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        // The tier is what makes this AtPrompt the *right* AtPrompt: the
        // REPL is recognised by its own bracketed paste, not by the shell's
        // stale OSC 133 marker. Without this line the test also passes when
        // the T1 prompt rung is widened to fire on a `C` marker, which is
        // the opposite reading of the same bytes.
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn a_pager_inside_an_integrated_shell_reports_fullscreen() {
        let (mut d, start, now) = detector();
        feed(
            &mut d,
            start,
            b"\x1b]133;A\x07$ \x1b]133;B\x07less f\r\n\x1b]133;C\x07",
        );
        feed(&mut d, start, b"\x1b[?1049h");
        assert_eq!(
            d.snapshot_at(true, ld(false, true), None, None, now)
                .interaction_mode,
            InteractionMode::Fullscreen
        );
    }

    #[test]
    fn osc133_prompt_markers_give_full_confidence() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b]133;A\x07bash-5.3$ \x1b]133;B\x07");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::Semantic);
        assert_eq!(s.confidence, 1.0);
    }

    #[test]
    fn an_integrated_prompt_is_at_prompt_before_the_command_line_marker() {
        // §8.3 spells the T1 prompt state as "the last marker is A **or**
        // B", and only the B half was exercised: every other T1 test feeds
        // `A … B` and lands on B. Narrowing the rule to B alone therefore
        // left the whole suite green while breaking the single most common
        // state in the product — a shell that has drawn its prompt and is
        // waiting for readline to signal `B`.
        //
        // What it degrades to is the point. With no `A` rung the classifier
        // falls through to the echo rung, where readline's already-off ECHO
        // reads as AwaitingSecret at 0.95: §8.7 finding 1's false positive,
        // telling the agent to prompt a human for a password at an idle
        // prompt.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b]133;A\x07bash-5.3$ ");
        let s = d.snapshot_at(true, ld(false, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::Semantic);
        assert_eq!(s.confidence, 1.0);
    }

    #[test]
    fn osc133_output_markers_report_executing_at_zero_confidence() {
        let (mut d, start, now) = detector();
        feed(
            &mut d,
            start,
            b"\x1b]133;A\x07$ \x1b]133;B\x07make\r\n\x1b]133;C\x07building",
        );
        let s = d.snapshot_at(true, ld(true, true), None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
        assert_eq!(s.detection_tier, DetectionTier::Semantic);
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn a_completed_command_is_not_yet_a_prompt() {
        // Between `D` and the next `A` the shell is between commands. It
        // must not read as AtPrompt: the prompt has not been drawn.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b]133;C\x07out\r\n\x1b]133;D;0\x07");
        assert_eq!(
            d.snapshot_at(true, ld(true, true), None, None, now)
                .interaction_mode,
            InteractionMode::Executing
        );
    }

    // ---- T3 combiner ----

    #[test]
    fn quiescence_gates_the_heuristic() {
        let mut d = PromptDetector::default();
        let start = Instant::now();
        d.feed_at(b">>> ", 0, None, start);

        // Immediately after output: not settled, so no confidence at all
        // however prompt-shaped the tail is.
        let s = d.snapshot_at(true, ld(true, true), None, None, start);
        assert_eq!(s.quiescent_score, 0.0);
        assert!((s.pattern_score - 0.9).abs() < 1e-6);
        assert_eq!(s.confidence, 0.0);

        // Half the settle threshold: half the score.
        let s = d.snapshot_at(
            true,
            ld(true, true),
            None,
            None,
            start + Duration::from_millis(125),
        );
        assert!(
            (s.quiescent_score - 0.5).abs() < 0.01,
            "{}",
            s.quiescent_score
        );
        assert!((s.confidence - 0.45).abs() < 0.01, "{}", s.confidence);

        // Past the threshold: saturated.
        let s = d.snapshot_at(
            true,
            ld(true, true),
            None,
            None,
            start + Duration::from_millis(400),
        );
        assert_eq!(s.quiescent_score, 1.0);
        assert!((s.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn output_restarts_the_quiescence_clock() {
        // The one rule `quiescence_gates_the_heuristic` cannot pin. That
        // test feeds microseconds after the detector is constructed, so a
        // detector whose clock never leaves its construction time answers
        // every one of its assertions identically — the millisecond
        // truncation hides the difference. Only a second chunk arriving
        // *later* separates a live clock from a frozen one.
        //
        // Frozen, every session older than the settle threshold reads as
        // fully settled and T3 degenerates to the pattern score alone: a
        // build log whose tail happens to end in `>` is then reported
        // AtPrompt at 0.5 while output is still streaming, which is the
        // exact false positive quiescence exists to prevent.
        let mut d = PromptDetector::default();
        let start = Instant::now();
        d.feed_at(b"building\r\n>>> ", 0, None, start);
        let settled = start + Duration::from_millis(400);
        assert_eq!(
            d.snapshot_at(true, ld(true, true), None, None, settled)
                .quiescent_score,
            1.0
        );

        // More output lands at the instant we were about to call it settled.
        d.feed_at(b"linking\r\n>>> ", 13, None, settled);
        let s = d.snapshot_at(true, ld(true, true), None, None, settled);
        assert_eq!(
            s.quiescent_score, 0.0,
            "output did not restart the settle timer"
        );
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn the_heuristic_decides_at_exactly_the_threshold_not_above_it() {
        // §8.4's cut is `>= 0.5`, and real input lands *bit-exactly* on it:
        // the bundled `>\s*$` rule scores 0.5, a settled session scores
        // 1.0, and 1.0 * 0.5 is 0.5 with no rounding in f32. So `>=` vs
        // `>` is not a boundary nicety — it silently reclassifies every
        // generic `>` continuation prompt on every non-readline program,
        // in the one tier that has no corroborating signal to fall back on.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"> ");
        let s = d.snapshot_at(true, ld(true, true), None, None, now);
        assert_eq!(s.pattern_score, 0.5);
        assert_eq!(s.quiescent_score, 1.0);
        assert_eq!(s.confidence, 0.5, "the product must be exact, not near");
        assert_eq!(
            s.interaction_mode,
            InteractionMode::AtPrompt,
            "a confidence exactly at the threshold must act, not wait"
        );
    }

    #[test]
    fn an_empty_chunk_does_not_restart_the_quiescence_clock() {
        // The mirror of `output_restarts_the_quiescence_clock`. Output
        // restarts the clock; the *absence* of output must not. Polled
        // often enough by a backend that returns empty reads, a session
        // that restarts on every poll never reaches the settle threshold,
        // so T3 confidence stays 0 and a shell sitting at a prompt is
        // reported `Executing` for as long as anyone keeps asking.
        let mut d = PromptDetector::default();
        let start = Instant::now();
        d.feed_at(b"$ ", 0, None, start);
        let settled = start + Duration::from_millis(400);
        assert_eq!(
            d.snapshot_at(true, ld(true, true), None, None, settled)
                .quiescent_score,
            1.0
        );

        let events = d.feed_at(b"", 2, None, settled);
        assert!(events.is_empty());
        assert_eq!(
            d.snapshot_at(true, ld(true, true), None, None, settled)
                .quiescent_score,
            1.0,
            "an empty read was counted as output"
        );
    }

    #[test]
    fn a_settled_but_unrecognised_tail_scores_zero_confidence() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"linking target/debug/clasp");
        let s = d.snapshot_at(true, ld(true, true), None, None, now);
        assert_eq!(s.quiescent_score, 1.0);
        assert_eq!(s.pattern_score, 0.0);
        assert_eq!(s.confidence, 0.0);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
    }

    #[test]
    fn the_cursor_sub_signal_is_reported_and_combines_by_max() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"$ ");
        let s = d.snapshot_at(true, ld(true, true), None, None, now);
        assert_eq!(
            s.cursor_score, 0.0,
            "Tier B off must contribute nothing at all"
        );
        // max(pattern, cursor) must still pick the pattern up.
        assert!((s.confidence - s.pattern_score).abs() < 1e-6);

        // The half that was unreachable before Tier B: a cursor score
        // above the pattern score must win the `max`, and be reported.
        // Kills `let cursor_score = 0.0;` and `min(...)` alike — with the
        // placeholder still in place this asserts 0.9 and gets 0.85.
        let s = d.snapshot_at(true, ld(true, true), None, Some(0.9), now);
        assert_eq!(s.cursor_score, 0.9);
        assert!((s.confidence - s.quiescent_score * 0.9).abs() < 1e-6);
        // …and below the pattern score it must lose it, so the assertion
        // above cannot be satisfied by "cursor always wins".
        let s = d.snapshot_at(true, ld(true, true), None, Some(0.1), now);
        assert!((s.confidence - s.quiescent_score * s.pattern_score).abs() < 1e-6);
    }

    #[test]
    fn session_patterns_change_the_heuristic_score() {
        let cfg = DetectionConfig {
            settle_threshold_ms: 250,
            patterns: PatternSet::build(
                &[PromptPattern {
                    regex: r"ready>\s*$".into(),
                    score: 0.95,
                }],
                false,
            )
            .unwrap(),
        };
        let mut d = PromptDetector::new(cfg);
        let now = Instant::now() + Duration::from_secs(10);
        d.feed_at(b"ready> ", 0, None, Instant::now());
        let s = d.snapshot_at(true, ld(true, true), None, None, now);
        assert!((s.pattern_score - 0.95).abs() < 1e-6);
        assert_eq!(s.detection_tier, DetectionTier::Heuristic);
    }

    #[test]
    fn settle_threshold_is_honoured_per_session() {
        let cfg = DetectionConfig {
            settle_threshold_ms: 1000,
            ..Default::default()
        };
        let mut d = PromptDetector::new(cfg);
        let start = Instant::now();
        d.feed_at(b">>> ", 0, None, start);
        let s = d.snapshot_at(
            true,
            ld(true, true),
            None,
            None,
            start + Duration::from_millis(250),
        );
        assert!(
            (s.quiescent_score - 0.25).abs() < 0.01,
            "a 1000 ms threshold must not settle in 250 ms: {}",
            s.quiescent_score
        );
    }

    // ---- exit and reporting ----

    #[test]
    fn an_exited_child_forces_exited_and_zero_scores() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004hbash-5.3$ ");
        let s = d.snapshot_at(false, LineDiscipline::UNKNOWN, None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Exited);
        assert_eq!(s.confidence, 0.0);
        assert_eq!(s.quiescent_score, 0.0);
        assert_eq!(s.pattern_score, 0.0);
        // Exiting zeroes the *scores*, not the record of how well this
        // session could be detected: the tier it had reached is reported
        // as it stands rather than collapsing to the fallback.
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn scores_and_last_line_are_reported_at_every_tier() {
        // §8.4 requires the corroborating signals in *every* response, not
        // just the one the answering tier happened to use — that is what
        // lets an agent see a T1 `AtPrompt` disagreeing with a
        // pattern_score of 0 and treat it as worth a second look. Named
        // "every tier" and exercising one, the test left both suppressing
        // pattern_score and blanking last_line alive at the other two.
        //
        // The same prompt line reaches each tier by a different route, so
        // the expected scores are identical across the three rows and only
        // `detection_tier` moves.
        //
        // The line-discipline column is not decoration: with echo off the
        // T2 rung answers AwaitingSecret before T3 is ever consulted, so
        // the heuristic row has to be a session whose echo is *on* — which
        // is exactly what a `dash` prompt looks like (§8.7).
        for (bytes, line, tier) in [
            (
                &b"\x1b]133;A\x07alice@host:~$ \x1b]133;B\x07"[..],
                ld(false, true),
                DetectionTier::Semantic,
            ),
            (
                &b"\x1b[?2004halice@host:~$ "[..],
                ld(false, true),
                DetectionTier::TerminalMode,
            ),
            (
                &b"alice@host:~$ "[..],
                ld(true, true),
                DetectionTier::Heuristic,
            ),
        ] {
            let (mut d, start, now) = detector();
            feed(&mut d, start, bytes);
            let s = d.snapshot_at(true, line, None, None, now);
            assert_eq!(s.detection_tier, tier, "{bytes:?}");
            assert_eq!(s.last_line, "alice@host:~$ ", "{bytes:?}");
            assert!(
                (s.pattern_score - 0.85).abs() < 1e-6,
                "{bytes:?}: corroborating scores must be reported whichever \
                 tier answers, got {}",
                s.pattern_score
            );
            assert_eq!(s.quiescent_score, 1.0, "{bytes:?}");
            assert_eq!(
                s.cursor_score, 0.0,
                "Tier B contributes nothing when it is off: {bytes:?}"
            );
        }
    }

    #[test]
    fn the_window_title_is_reported() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b]0;make -j8\x07\x1b[?2004h$ ");
        assert_eq!(
            d.snapshot_at(true, ld(false, true), None, None, now)
                .title
                .as_deref(),
            Some("make -j8")
        );
    }

    #[test]
    fn a_backend_that_cannot_sample_echo_never_reports_awaiting_secret() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h\x1b[?2004lPassword: ");
        let s = d.snapshot_at(true, LineDiscipline::UNKNOWN, None, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
    }

    /// §8.3's echo rung across both flags' tri-state, with the §8.7 row
    /// each cell corresponds to named in the failure message.
    ///
    /// The second row is the requirement, not filler: REQ-PD-021 says an
    /// unreadable `ICANON` must reproduce the pre-rev.-36 classification
    /// **exactly** — degrade to today's answer, never to a third path —
    /// which is why the conjunct is spelled `!= Some(false)` and not
    /// `== Some(true)`. A two-valued `icanon` axis cannot fail on that
    /// rule and is the one shape this test must not have.
    #[test]
    fn the_echo_rung_crosses_both_flags_tri_state() {
        /// `(echo, canonical, mode, tier, confidence, which §8.7 row)`.
        type Row = (
            Option<bool>,
            Option<bool>,
            InteractionMode,
            DetectionTier,
            f32,
            &'static str,
        );
        let rows: &[Row] = &[
            (
                Some(false),
                Some(true),
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
                "getpass/read -s/ssh: echo off, canonical on — §8.7 rows 3,4,5",
            ),
            (
                Some(false),
                None,
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
                "ICANON unreadable: REQ-PD-021, the pre-rev.-36 answer exactly",
            ),
            (
                Some(false),
                Some(false),
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
                "readline with no bracketed paste: §8.7 row 7",
            ),
            (
                Some(true),
                Some(true),
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
                "echo on: never this rung",
            ),
            (
                Some(true),
                Some(false),
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
                "echo on, canonical off: still never this rung",
            ),
            (
                None,
                Some(true),
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
                "no line discipline: ConPTY today",
            ),
            (
                None,
                None,
                InteractionMode::AtPrompt,
                DetectionTier::Heuristic,
                0.9,
                "LineDiscipline::UNKNOWN",
            ),
        ];
        for (echo, canonical, mode, tier, confidence, what) in rows {
            let (mut d, start, now) = detector();
            // `>>> ` scores 0.9 in the T3 table, so every row that falls
            // past the rung lands on one number and a row that stopped
            // falling past it shows as a different tier, not just a
            // different mode.
            feed(&mut d, start, b">>> ");
            let s = d.snapshot_at(
                true,
                LineDiscipline {
                    echo: *echo,
                    canonical: *canonical,
                },
                None,
                None,
                now,
            );
            assert_eq!(s.interaction_mode, *mode, "{what}");
            assert_eq!(s.detection_tier, *tier, "{what}");
            assert!(
                (s.confidence - *confidence).abs() < 1e-6,
                "{what}: {}",
                s.confidence
            );
        }
    }

    /// REQ-PD-025's owner/holder cross, arm by arm.
    ///
    /// **The three unknown arms are asserted separately and not in
    /// aggregate.** An aggregate assertion cannot distinguish "unknown
    /// degrades to the rev.-36 answer" from "unknown withholds
    /// everything", and the second is a behaviour change on the one
    /// platform nobody has measured.
    #[test]
    fn a_licence_is_withheld_only_when_owner_and_holder_are_both_known_and_differ() {
        // (owner at scan time, holder at classification, licensed?, what)
        let arms: &[(Option<i32>, Option<i32>, bool, &str)] = &[
            (
                Some(100),
                Some(100),
                true,
                "same program still holds the terminal",
            ),
            (
                Some(100),
                Some(200),
                false,
                "a different program holds it now",
            ),
            (
                None,
                Some(200),
                true,
                "owner unknown: rev.-36 answer, not a third path",
            ),
            (
                Some(100),
                None,
                true,
                "holder unknown: rev.-36 answer — ConPTY, or a reaped child",
            ),
            (None, None, true, "both unknown: rev.-36 answer"),
        ];
        for (owner, holder, licensed, what) in arms {
            let (mut d, start, now) = detector();
            // bash drives bracketed paste, then turns it off to run
            // something. The T2 executing rung is the one under test.
            d.feed_at(b"\x1b[?2004h\x1b[?2004lsleep 2\r\n", 0, *owner, start);
            let s = d.snapshot_at(true, ld(true, true), *holder, None, now);
            // The **mode** is the same either way — that is the point of
            // the narrowing, and asserting only the mode would make this
            // test unfalsifiable. The tier is what moves.
            assert_eq!(s.interaction_mode, InteractionMode::Executing, "{what}");
            assert_eq!(s.confidence, 0.0, "{what}");
            assert_eq!(
                s.detection_tier,
                if *licensed {
                    DetectionTier::TerminalMode
                } else {
                    DetectionTier::Heuristic
                },
                "{what}"
            );
        }
    }

    /// The owner is re-recorded on every transition, not only the first.
    ///
    /// Without this a REPL that drives bracketed paste at its own prompt
    /// after being launched from bash would carry bash's owner for its
    /// whole life and would never be licensed again — §8.7 availability
    /// row 4c, the case the rung's premise is literally true of.
    #[test]
    fn a_new_program_driving_the_signal_re_arms_the_licence_for_itself() {
        let (mut d, start, now) = detector();
        d.feed_at(b"\x1b[?2004h\x1b[?2004l", 0, Some(100), start); // bash
        d.feed_at(b"\x1b[?2004h\x1b[?2004l", 0, Some(200), start); // the REPL
        let s = d.snapshot_at(true, ld(true, true), Some(200), None, now);
        assert_eq!(
            s.detection_tier,
            DetectionTier::TerminalMode,
            "the REPL drove the signal itself and still holds the terminal"
        );
    }

    #[test]
    fn a_faked_bracketed_paste_fools_tier_2_as_documented() {
        // Spec §8.8: CLASP does not defend against a hostile child. This
        // asserts the limitation so it cannot change silently.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h");
        assert_eq!(
            d.snapshot_at(true, ld(true, true), None, None, now)
                .interaction_mode,
            InteractionMode::AtPrompt,
            "documented limitation: a program printing \\x1b[?2004h is believed"
        );
    }

    /// §11.1 `detector::availability` — the §8.3 availability rule, pinned
    /// in **both** directions on **both** axes (REQ-PD-011, REQ-PD-015,
    /// REQ-PD-026).
    ///
    /// **The observation is sticky; the licence is scoped. Those are two
    /// facts and conflating them breaks two rules at once.** `saw_*` is a
    /// per-signal record: observed once, never un-observed, and correctly
    /// so — REQ-PD-016's exited tier reads it *after* the child has been
    /// reaped, so a flag that cleared itself would have nothing left to
    /// report. What rev. 37 narrowed is not that record but what it
    /// *licenses*: a record belongs to the program that emitted the signal
    /// and licenses its rung only while that program still holds the
    /// terminal (`licensed`, above). Scoping the flag as well as the licence
    /// would break the exited-tier rule and the ConPTY degradation
    /// together.
    ///
    /// Which signals confer a licence at all is unchanged and is the other
    /// axis. Bracketed paste licenses the T2 executing rung — *prompt mode
    /// is off, therefore not at a prompt* is valid only for a program known
    /// to signal its prompts that way. Observing the alternate screen says a
    /// child took the screen and gave it back; it licenses nothing about
    /// whether the program now holding the tty signals its prompts at all.
    ///
    /// **Why this module exists as a module.** The rule was previously
    /// unpinned in *both* directions: the entire 0.0.2 suite passed with
    /// and without the `|| saw_alt_screen` disjunct, so two implementations
    /// that classify a live `dash` prompt differently both satisfied the
    /// text. A rule that only fails one way is half-pinned. **Since rev. 37
    /// there are two axes, and REQ-PD-015 and REQ-PD-026 are separate
    /// obligations: satisfying one does not satisfy the other.** Four
    /// mutations, and each names the rows it must redden and the rows it
    /// must leave alone:
    ///
    /// | Axis | Injection | Red | Green |
    /// |---|---|---|---|
    /// | signal membership — remove | `t2_prompt_mode = false` | **4a**, **4c** | 1, 2, 3, 4b, 5, 6 |
    /// | signal membership — add | `licensed(saw_bracketed_paste \|\| saw_alt_screen, …)` | **2**, **3**, independently | 1, 4a, 4b, 4c, 5, 6 |
    /// | scope — widen (the rev.-36 behaviour) | `licensed` ignores owner and holder | **4b**, **6**, independently | 1, 2, 3, 4a, 4c, 5 |
    /// | scope — narrow | `licensed` is false whenever the holder is known | **4a**, **4c** | 1, 2, 3, 4b, 5, 6 |
    ///
    /// The narrow direction is the one rev. 28 left unpinned and the one
    /// most easily missed: an implementation that clears availability on
    /// every classification makes **both** executing rungs unreachable
    /// while still satisfying every row that expects a heuristic answer.
    ///
    /// Rows 2 and 3 exist as a pair, and so do 4b and 6, because one of
    /// each is a shell and one is not — if a mutation reddens only one of a
    /// pair, the two have collapsed into one assertion made twice and the
    /// other must be re-derived.
    ///
    /// Rows 1 and 5 must not move under any of the four. Row 1 is the
    /// baseline `dash` prompt the availability gate was introduced (rev.
    /// 23) to protect; row 5 reads alt-screen's *current* value at the
    /// `Fullscreen` rung, which sits earlier in the ladder and is untouched
    /// by any change to availability.
    ///
    /// **`ld(true, true)` on rows 1–4c is load-bearing, not a default.**
    /// `dash` leaves `ECHO` **on** at its prompt — the measured fact that
    /// makes it a T3 case and the reason a readable `ECHO` confers no
    /// availability. With `ld(false, _)` these rows would route through the
    /// echo rung or its neighbours and would stop testing availability at
    /// all. Row 5 is a pager's shape and row 6 is a readline child's; both
    /// answer above or below the availability rung regardless, and their
    /// docstrings say which.
    mod availability {
        use super::*;

        /// Assert the session *history* a row's byte stream is supposed to
        /// establish, before asking what the classifier makes of it.
        ///
        /// These rows differ from one another only in that history —
        /// rows 1 and 2 end on byte-identical prompts — so a stream that
        /// silently stops establishing it degrades into another row that
        /// is already covered and keeps passing. A mistyped `\x1b[?1049h`
        /// turns row 2 back into row 1, which satisfies every assertion
        /// row 2 makes about the *answer*. This is the guard that makes
        /// the row name mean something.
        ///
        /// Argument order is `(bracketed paste seen, alt screen seen, alt
        /// screen now, osc 133 seen, bracketed-paste owner)`. The first
        /// four are `bool`, so a transposition compiles; what stops it is
        /// that no two rows below carry the same values, and the failure
        /// names the field.
        ///
        /// `saw_osc133` is the *third* tier-gating flag and the one
        /// REQ-PD-016's exited matrix keys on. Without it here, that
        /// matrix's OSC-133 row and its never-observed row are, as far as
        /// this guard can tell, the same stream.
        ///
        /// **The recorded owner is here for rev. 37's rows 4a/4b/4c**,
        /// which differ from one another only in who owned the signal and
        /// who holds the terminal now. Without it, 4c — the REPL that drove
        /// the paste *itself* — establishes the same history as 4a and the
        /// three collapse into one assertion made three times. The holder
        /// is not history and is not asserted here: it is the argument each
        /// row passes to `snapshot_at`, in plain sight at the call.
        fn assert_history(
            d: &PromptDetector,
            saw_bp: bool,
            saw_alt: bool,
            alt_now: bool,
            saw_osc133: bool,
            bp_owner: Option<i32>,
        ) {
            let m = d.scanner.modes();
            assert_eq!(
                m.saw_bracketed_paste, saw_bp,
                "observed-bracketed-paste history"
            );
            assert_eq!(m.saw_alt_screen, saw_alt, "observed-alt-screen history");
            assert_eq!(m.alt_screen, alt_now, "alternate screen right now");
            assert_eq!(m.saw_osc133, saw_osc133, "observed-osc-133 history");
            assert_eq!(
                m.bracketed_paste_owner, bp_owner,
                "the program that drove the bracketed-paste signal"
            );
        }

        /// Row 1 — `dash`, no terminal mode ever seen, sitting at `$ `.
        /// The case that always worked, asserted so the fix cannot buy
        /// rows 2 and 3 at its expense.
        ///
        /// **The rung expected to answer is T3.** `dash` drives no terminal
        /// mode and leaves `ECHO` on, which is why `ld(true, true)` here is
        /// the measured state rather than a filler.
        #[test]
        fn row_1_dash_that_never_saw_a_mode_answers_at_prompt_via_t3() {
            let (mut d, start, now) = detector();
            d.feed_at(b"$ ", 0, Some(100), start);
            assert_history(&d, false, false, false, false, None);

            let s = d.snapshot_at(true, ld(true, true), Some(100), None, now);
            assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert!((s.confidence - 0.60).abs() < 1e-6, "{}", s.confidence);
        }

        /// Row 2 — the *same* `dash` prompt as row 1, after `less` entered
        /// and left the alternate screen. This is the rev.-27 defect: one
        /// alt-screen toggle marked the session T2-available for life, and
        /// the T2 executing rung then answered `Executing` / `terminal_mode`
        /// / `0.00` at a live prompt — while `pattern_score: 0.60` sat in
        /// the same payload contradicting it. §8.4 tells the agent that
        /// `Executing` at `terminal_mode` is deterministic and to wait, so
        /// the agent waited at a prompt nothing in the session could ever
        /// clear.
        ///
        /// **The rung expected to answer is T3**, and the owner and holder
        /// are the same group throughout: nothing about the *scope* axis is
        /// under test here, which is what makes this row a clean witness for
        /// the signal-membership axis alone.
        #[test]
        fn row_2_dash_after_less_entered_and_left_the_alt_screen_still_answers_via_t3() {
            let (mut d, start, now) = detector();
            d.feed_at(b"\x1b[?1049h(END)\x1b[?1049l\r\n$ ", 0, Some(100), start);
            assert_history(&d, false, true, false, false, None);

            let s = d.snapshot_at(true, ld(true, true), Some(100), None, now);
            assert_eq!(
                s.interaction_mode,
                InteractionMode::AtPrompt,
                "a live `dash` prompt, reported as a running command"
            );
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert!((s.confidence - 0.60).abs() < 1e-6, "{}", s.confidence);
            // The self-contradiction the old answer shipped with. Pinned
            // because it is the cheapest signal that the disjunct is back:
            // a `terminal_mode` `Executing` beside a 0.60 pattern score.
            assert!((s.pattern_score - 0.60).abs() < 1e-6, "{}", s.pattern_score);
        }

        /// Row 3 — a bespoke CLI that alt-screened once and now prompts.
        /// Same defect as row 2, but with no shell involved at all and a
        /// different pattern row carrying the answer, so the two rows fail
        /// the add-alt-screen mutation independently rather than as one
        /// duplicated assertion.
        ///
        /// **The rung expected to answer is T3**, and as in row 2 the owner
        /// and holder never differ.
        #[test]
        fn row_3_a_bespoke_cli_that_alt_screened_once_and_now_prompts_answers_via_t3() {
            let (mut d, start, now) = detector();
            d.feed_at(
                b"\x1b[?1049h drawing \x1b[?1049l\r\nEnter a value: ",
                0,
                Some(100),
                start,
            );
            assert_history(&d, false, true, false, false, None);

            let s = d.snapshot_at(true, ld(true, true), Some(100), None, now);
            assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert!((s.confidence - 0.80).abs() < 1e-6, "{}", s.confidence);
        }

        /// Row 4a — bash, bracketed paste seen then disabled, a **builtin**
        /// running. The group does not change across a builtin (measured),
        /// so bash really is still the program at the terminal and the
        /// rung's premise — *this program signals its prompts with
        /// bracketed paste, and it is off* — is literally true of it.
        ///
        /// **The rung expected to answer is the T2 executing rung.** This is
        /// the row that breaks if the signal is *removed* from the rule, and
        /// also the row that breaks if the licence is withdrawn with no
        /// foreground change. It is one of the two rows on which the whole
        /// remaining reach of that rung rests.
        #[test]
        fn row_4a_bash_running_a_builtin_answers_executing_via_t2() {
            let (mut d, start, now) = detector();
            d.feed_at(
                b"\x1b[?2004h\x1b[?2004lread -r answer\r\n",
                0,
                Some(100),
                start,
            );
            assert_history(&d, true, false, false, false, Some(100));

            let s = d.snapshot_at(true, ld(true, true), Some(100), None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Executing);
            assert_eq!(
                s.detection_tier,
                DetectionTier::TerminalMode,
                "removing bracketed paste from the availability rule — or \
                 withdrawing the licence with no foreground change — drops \
                 this row to the heuristic tier while leaving its mode \
                 (`Executing`) and its confidence (0.00) untouched — the \
                 tier is the only field that catches either direction"
            );
            assert_eq!(s.confidence, 0.0);
        }

        /// Row 4b — the same bash, running an **external** command. The
        /// reach rev. 37 gives up: `sleep` is its own process group, so the
        /// licence bash earned says nothing about it.
        ///
        /// **The rung expected to answer is T3.** This is the row that
        /// breaks if the licence is widened back to the session — the
        /// rev.-36 behaviour, which is a *passing* test today and must
        /// become a failing one (REQ-PD-026). Its pair is row 6: one is a
        /// shell's child that is still executing, the other is a shell's
        /// child sitting at its own prompt, and a mutation that reddens only
        /// one of the two has found them collapsed into a single assertion.
        ///
        /// The mode (`Executing`) and the confidence (0.00) are identical to
        /// row 4a's — a settled `sleep` scores nothing on the T3 table
        /// either — so the tier is again the only field that moves.
        #[test]
        fn row_4b_bash_running_an_external_command_answers_executing_via_t3() {
            let (mut d, start, now) = detector();
            d.feed_at(b"\x1b[?2004h\x1b[?2004lsleep 2\r\n", 0, Some(100), start);
            assert_history(&d, true, false, false, false, Some(100));

            let s = d.snapshot_at(true, ld(true, true), Some(200), None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Executing);
            assert_eq!(
                s.detection_tier,
                DetectionTier::Heuristic,
                "the licence stops at the program that earned it: bash's \
                 bracketed paste says nothing about the command it launched"
            );
            assert_eq!(s.confidence, 0.0);
        }

        /// Row 4c — a REPL that drove bracketed paste **itself**, now
        /// running its own computation. Measured: such a program keeps its
        /// own group throughout, so the record it armed is still its own.
        ///
        /// **The rung expected to answer is the T2 executing rung**, and
        /// this row is why the owner is re-recorded on *every* transition
        /// rather than only the first: launched from bash, the REPL's own
        /// `\x1b[?2004h` has to overwrite bash's ownership or the row can
        /// never be licensed again.
        #[test]
        fn row_4c_a_repl_running_its_own_computation_answers_executing_via_t2() {
            let (mut d, start, now) = detector();
            // bash drives the paste, launches the REPL; the REPL draws its
            // own prompt (its own transition, its own group) and then goes
            // away to compute.
            d.feed_at(b"\x1b[?2004h\x1b[?2004lpython3 -q\r\n", 0, Some(100), start);
            d.feed_at(
                b"\x1b[?2004h>>> \x1b[?2004lworking\r\n",
                0,
                Some(200),
                start,
            );
            assert_history(&d, true, false, false, false, Some(200));

            let s = d.snapshot_at(true, ld(true, true), Some(200), None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Executing);
            assert_eq!(
                s.detection_tier,
                DetectionTier::TerminalMode,
                "the REPL drove the signal itself and still holds the \
                 terminal, so the rung's premise holds exactly here"
            );
            assert_eq!(s.confidence, 0.0);
        }

        /// Row 5 — the alternate screen currently **on**. Unaffected on
        /// both axes and in both directions: the `Fullscreen` rung reads
        /// alt-screen's current value and sits above every availability
        /// question, which is why the fix narrows the executing rung rather
        /// than dropping alt-screen from the classifier. Note the session
        /// has never driven bracketed paste, so this holds with no T2
        /// availability at all, and the foreground group changes under it
        /// without moving the answer.
        ///
        /// **The rung expected to answer is `Fullscreen`**, above every
        /// availability question — which is why `ld(false, false)` here is a
        /// pager's shape rather than the `dash` shape rows 1–4c need.
        #[test]
        fn row_5_a_live_alt_screen_reports_fullscreen_with_no_availability_at_all() {
            let (mut d, start, now) = detector();
            d.feed_at(b"\x1b[?1049h:", 0, Some(100), start);
            assert_history(&d, false, true, true, false, None);

            let s = d.snapshot_at(true, ld(false, false), Some(200), None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Fullscreen);
            assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
            assert_eq!(s.confidence, 0.0);
        }

        /// Row 6 — bash drove bracketed paste, and a **readline child
        /// driving none** is now sitting at its own prompt. §8.7 row 7b, and
        /// what rev. 37 buys for what row 4b gives up.
        ///
        /// **The rung expected to answer is T3.** Under the rev.-36 rule
        /// this answered `Executing` / `terminal_mode` / 0.00 — §8.4 tells
        /// the agent that is deterministic and means wait, so the agent
        /// waited at a live prompt until its own timeout. Before rev. 36 it
        /// was worse: `AwaitingSecret` / 0.95, at an ordinary REPL prompt.
        ///
        /// `ld(false, false)` is a readline child's measured shape — echo
        /// off, canonical off — and the echo rung's `ICANON` conjunct is
        /// what lets it fall this far. It is the pair of row 4b on the
        /// scope-widen mutation: same signal, same owner, same holder,
        /// opposite answer, because the child is at a prompt rather than
        /// executing.
        #[test]
        fn row_6_a_readline_child_driving_no_paste_answers_at_prompt_via_t3() {
            let (mut d, start, now) = detector();
            d.feed_at(
                b"\x1b[?2004h\x1b[?2004lpython3 -q\r\n>>> ",
                0,
                Some(100),
                start,
            );
            assert_history(&d, true, false, false, false, Some(100));

            let s = d.snapshot_at(true, ld(false, false), Some(200), None, now);
            assert_eq!(
                s.interaction_mode,
                InteractionMode::AtPrompt,
                "a live REPL prompt, reported as a running command"
            );
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert!((s.confidence - 0.90).abs() < 1e-6, "{}", s.confidence);
        }

        /// The rule stated as a rule, rather than as five of its
        /// consequences: observing the alternate screen must not change any
        /// answer the classifier gives once the screen is handed back.
        ///
        /// Rows 1 and 2 are that claim for one prompt; this walks the
        /// prompt-bearing tails the T3 table actually distinguishes and
        /// requires the *whole* `Detection` to match with and without the
        /// alt-screen episode. It fails on the add-alt-screen mutation and
        /// would also catch a narrower reintroduction — one that gated some
        /// other rung on `saw_alt_screen` — which the five rows above,
        /// being fixed points, could miss.
        #[test]
        fn an_alt_screen_episode_changes_no_later_answer() {
            for tail in [
                &b"$ "[..],
                &b"Enter a value: "[..],
                &b">>> "[..],
                &b"linking target/debug/clasp"[..],
            ] {
                let (mut clean, start, now) = detector();
                feed(&mut clean, start, tail);
                let without = clean.snapshot_at(true, ld(true, true), None, None, now);

                let (mut toggled, start, now) = detector();
                feed(&mut toggled, start, b"\x1b[?1049h(END)\x1b[?1049l\r\n");
                feed(&mut toggled, start, tail);
                assert_history(&toggled, false, true, false, false, None);
                let with = toggled.snapshot_at(true, ld(true, true), None, None, now);

                assert_eq!(
                    with,
                    without,
                    "an alt-screen episode changed the answer for {:?}",
                    String::from_utf8_lossy(tail)
                );
            }
        }

        /// `session_tier` — the tier reported once the child is gone — is
        /// derived from the *same* availability notion the live ladder
        /// uses, so "T2 available" has exactly one meaning in this
        /// function.
        ///
        /// §8.3 does not speak to this directly: its first rung answers
        /// `Exited` before any tier question is asked, and §8.4's table
        /// describes the tier of the branch that *answered*. Resolved
        /// deliberately in favour of one definition, because a second and
        /// wider spelling of T2-availability sitting beside the narrowed
        /// one is precisely the shape the alt-screen disjunct survived in
        /// from rev. 23 to rev. 27.
        #[test]
        fn an_exited_alt_screen_only_session_reports_the_tier_that_could_have_answered() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"\x1b[?1049h(END)\x1b[?1049l\r\n$ ");
            assert_history(&d, false, true, false, false, None);
            assert_eq!(
                d.snapshot_at(false, LineDiscipline::UNKNOWN, None, None, now)
                    .detection_tier,
                DetectionTier::Heuristic,
                "a session that only ever drove the alternate screen was \
                 never classifiable by terminal mode"
            );
        }

        /// REQ-PD-016 row 4 — an integrated shell that has exited reports
        /// `semantic`.
        ///
        /// The row that closes the requirement's four-history matrix, and
        /// the one that makes the other three mean something. With it
        /// absent, a mutation collapsing the `!alive` arm to a literal
        /// `DetectionTier::Heuristic` was killed only by the
        /// bracketed-paste row, and a mutation collapsing it to
        /// "`session_tier` but never `Semantic`" was killed by **nothing in
        /// the workspace** — the T1 branch of `session_tier` had no exited
        /// witness at all.
        ///
        /// The history assertion is not decoration here. This row's answer
        /// (`Exited`, all scores 0.0) is byte-identical to every other
        /// exited row; the *only* thing that distinguishes it is that
        /// `saw_osc133` is true and the other two flags are false. A
        /// mistyped marker turns it into the never-observed row below,
        /// which asserts a different tier and would fail — but a mistyped
        /// marker plus a copied expectation would not, which is what the
        /// guard is for.
        #[test]
        fn an_exited_integrated_shell_reports_the_semantic_tier_it_reached() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"\x1b]133;A\x07bash-5.3$ ");
            assert_history(&d, false, false, false, true, None);

            let s = d.snapshot_at(false, LineDiscipline::UNKNOWN, None, None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Exited);
            assert_eq!(
                s.detection_tier,
                DetectionTier::Semantic,
                "a shell that emitted OSC 133 was classifiable semantically, \
                 and exiting does not retract that"
            );
            assert_eq!(s.confidence, 0.0);
        }

        /// Rows 2 and 3, in the T1 dimension: an OSC 133 subcommand the
        /// scanner does not model must not confer T1 availability.
        ///
        /// `saw_osc133` alone decides `session_tier` and gates *both* T1
        /// rungs, and like every availability *record* it is sticky —
        /// rev. 37 scoped the licence a record confers, not the record
        /// itself (see this module's docstring). So a forged record is
        /// never un-observed, and here it is forged by the *same* program
        /// throughout, which leaves scope with nothing to withhold. Set it
        /// from an unmodelled subcommand and `t1` is true while
        /// `at_marker` never can be — `last_marker` stays `None` — so the
        /// ladder falls past the T1 prompt rung to the T1 *executing* rung
        /// and answers `Executing` / `semantic` / 0.00 at a live prompt,
        /// with `pattern_score: 0.60` contradicting it in the same
        /// payload, §8.4 telling the agent `semantic` is deterministic and
        /// to wait, and nothing in the session able to clear it. That is
        /// the rev.-27 alt-screen defect exactly, one dimension over.
        ///
        /// The inputs are not hypothetical: Kitty and WezTerm emit
        /// `133;P;k=i`, and `133;L` is in circulation too, both from rc
        /// files that may never send an `A`/`B`/`C`/`D` at all. The
        /// scanner-level half is
        /// `scanner::tests::unknown_osc133_subcommands_do_not_move_the_t1_state`;
        /// this is the half that says what the agent would have been told.
        #[test]
        fn an_unmodelled_osc_133_subcommand_does_not_make_the_session_semantic() {
            for raw in [&b"\x1b]133;P;k=i\x07$ "[..], &b"\x1b]133;L\x07$ "[..]] {
                let shown = String::from_utf8_lossy(raw).into_owned();
                let (mut d, start, now) = detector();
                feed(&mut d, start, raw);
                assert_history(&d, false, false, false, false, None);

                let s = d.snapshot_at(true, ld(true, true), None, None, now);
                assert_eq!(
                    s.interaction_mode,
                    InteractionMode::AtPrompt,
                    "{shown:?}: a live prompt reported as a running command"
                );
                assert_eq!(s.detection_tier, DetectionTier::Heuristic, "{shown:?}");
                assert!(
                    (s.confidence - 0.60).abs() < 1e-6,
                    "{shown:?}: {}",
                    s.confidence
                );
                // The self-contradiction the forged flag would ship with,
                // pinned for the same reason row 2 pins it.
                assert!(
                    (s.pattern_score - 0.60).abs() < 1e-6,
                    "{shown:?}: {}",
                    s.pattern_score
                );

                // And `session_tier`, which is the half that outlives the
                // child: an unmodelled subcommand never made the session
                // classifiable semantically.
                assert_eq!(
                    d.snapshot_at(false, LineDiscipline::UNKNOWN, None, None, now)
                        .detection_tier,
                    DetectionTier::Heuristic,
                    "{shown:?}: an unmodelled marker forged the session tier"
                );
            }
        }

        /// REQ-PD-016 row 1 — nothing ever observed reports `heuristic`.
        ///
        /// The negative that separates the row above from the degenerate
        /// case: the same exited call, the same empty prompt line, the same
        /// zeroed scores, and the *only* difference in the input is the
        /// absence of the OSC 133 marker. Without this row, an
        /// implementation that answered `Semantic` unconditionally on the
        /// `!alive` path would satisfy every other assertion in this
        /// module.
        ///
        /// Also the unit-level statement of PTY row 9
        /// (`matrix_row_an_exited_session_reports_exited`), which asserts
        /// the same tier for `bash -c 'exit 3'` against a real PTY. That
        /// row reads its history off the raw byte stream, which for a
        /// silent child is empty; this one drives the stream directly, so
        /// it is where the three flags are pinned against a tail that is
        /// deliberately *not* empty.
        #[test]
        fn an_exited_session_that_observed_nothing_reports_the_heuristic_tier() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"bash-5.3$ ");
            assert_history(&d, false, false, false, false, None);

            let s = d.snapshot_at(false, LineDiscipline::UNKNOWN, None, None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Exited);
            assert_eq!(
                s.detection_tier,
                DetectionTier::Heuristic,
                "a session with no observed signal was never classifiable \
                 above the fallback tier"
            );
            assert_eq!(s.confidence, 0.0);
        }
    }

    /// §11.1 corpus 3 — the §8.6 head guards read through the combiner
    /// (REQ-PD-008, REQ-PD-017, REQ-PD-013).
    ///
    /// **Why a third corpus rather than more rows in `patterns.rs`.**
    /// Every number in §8.6's two tables belongs to *one* sub-signal, and
    /// `confidence = quiescent x max(pattern, cursor)` takes the larger.
    /// So a corpus asserting T3b alone stays perfectly green against a
    /// combiner in which T3c answers 0.9 on the same line — which is
    /// exactly what shipped, for every guarded row, until rev. 46. The
    /// only assertion that can see that is one made on both sub-signals
    /// *and* on the answer they combine to, which is what the rows below
    /// are.
    ///
    /// **The cursor is parked at each line's end, and that is the
    /// fixture, not a detail.** A parked cursor is the arrangement in
    /// which a guarded line is reachable at all; a corpus whose lines end
    /// in a newline is asserting `raw_cursor_score`'s `col == 0` branch
    /// and would pass against no head guard whatever
    /// (`the_same_corpus_newline_terminated_pins_column_zero_and_nothing_else`
    /// below is that claim, written out so it cannot be mistaken for
    /// coverage).
    mod head_guard_corpus {
        use super::*;
        use crate::screen::cursor::raw_cursor_score;
        use crate::screen::DEFAULT_PROMPT_CHARS;

        /// `(line, cursor_score, pattern_score, confidence)` with the
        /// cursor parked at the line's end and the session fully
        /// quiescent, so `confidence` is `max` of the two sub-scores.
        ///
        /// The three groups are the three things rev. 46 has to be true
        /// of at once: the guards reject on the cursor where they reject
        /// on the pattern; they still admit every real prompt on their
        /// near side; and they reach neither the row-anchored `>` nor the
        /// unguarded `:` and `)`.
        const CORPUS: &[(&str, f32, f32, f32)] = &[
            // --- far side: the guard rejects, and the answer is 0.00 ---
            ("Receiving objects:  47%", 0.0, 0.0, 0.0),
            ("[####------] 40%", 0.0, 0.0, 0.0),
            ("Coverage: 92%", 0.0, 0.0, 0.0),
            ("  100%", 0.0, 0.0, 0.0),
            ("############################", 0.0, 0.0, 0.0),
            ("Coverage change: -2.1%", 0.0, 0.0, 0.0),
            ("cpu -40%", 0.0, 0.0, 0.0),
            ("lines......: 87.5%", 0.0, 0.0, 0.0),
            ("width:100%", 0.0, 0.0, 0.0),
            // A real `csh`-family prompt answering 0.00 — the rev.-34
            // recall loss, now costed on both sub-signals rather than
            // one. It is in the corpus precisely because it is the row a
            // future widening would recover, and recovering it has to be
            // a deliberate edit to §8.6, to `patterns.rs` and to here.
            ("10.0.0.5% ", 0.0, 0.0, 0.0),
            // --- near side: the guard admits (REQ-PD-017) ---
            ("build01% ", 0.9, 0.6, 0.9),
            ("prod-01% ", 0.9, 0.6, 0.9),
            ("web1% ", 0.9, 0.6, 0.9),
            ("user@build01% ", 0.9, 0.6, 0.9),
            ("hostname% ", 0.9, 0.6, 0.9),
            ("% ", 0.9, 0.6, 0.9),
            ("zsh% ", 0.9, 0.6, 0.9),
            ("bash-5.3# ", 0.9, 0.6, 0.9),
            ("# ", 0.9, 0.6, 0.9),
            ("root@prod:/etc# ", 0.9, 0.85, 0.9),
            // The two the rev.-34 letter rule re-admits at 0.6 on T3b.
            // Both end in a `PROMPT_CHARS` member, so the cursor scores
            // them 0.9 and the combined answer is 0.90 — §8.6 rev. 46
            // says so in as many words, and this is where it is costed.
            ("mem2%", 0.9, 0.6, 0.9),
            ("x50%", 0.9, 0.6, 0.9),
            // --- carve-out 1: `^>\s*$` is a row anchor, not a character
            // guard, and is not transplanted. `foo> ` scoring 0 on the
            // pattern rung and 0.9 on the cursor is the case T3c exists
            // for; requiring the *line* to be recognised would collapse
            // the two sub-signals into one.
            ("sqlite>", 0.9, 0.95, 0.95),
            ("mysql>", 0.9, 0.95, 0.95),
            ("foo> ", 0.9, 0.0, 0.9),
            ("> ", 0.9, 0.5, 0.9),
            // --- carve-out 2: `:` and `)` have no T3b row and so no
            // guard to inherit. A parked cursor after either still scores
            // 0.9 — the residual §8.6 accepts by name, asserted here so
            // that narrowing it later is a deliberate edit rather than a
            // silent one.
            ("Password: ", 0.9, 0.95, 0.95),
            ("Enter the following commands:", 0.9, 0.8, 0.9),
            ("Continue) ", 0.9, 0.0, 0.9),
        ];

        /// The cursor parked at the end of `line`, which is what a shell
        /// that has finished writing its prompt leaves behind.
        fn parked(line: &str) -> vt100::Parser {
            let mut p = vt100::Parser::new(24, 80, 0);
            p.process(line.as_bytes());
            p
        }

        #[test]
        fn every_guarded_line_is_pinned_on_both_sub_signals_and_on_the_answer() {
            for (line, want_cursor, want_pattern, want_confidence) in CORPUS {
                let cursor = raw_cursor_score(parked(line).screen(), DEFAULT_PROMPT_CHARS);
                assert!(
                    (cursor - want_cursor).abs() < 1e-6,
                    "{line:?}: cursor_score {cursor}, want {want_cursor}"
                );

                let (mut d, start, settled) = detector();
                feed(&mut d, start, line.as_bytes());
                let s = d.snapshot_at(true, ld(true, true), None, Some(cursor), settled);

                assert_eq!(s.last_line, *line, "the scanner did not see the line");
                assert_eq!(s.detection_tier, DetectionTier::Heuristic, "{line:?}");
                assert!(
                    (s.quiescent_score - 1.0).abs() < 1e-6,
                    "{line:?}: not settled"
                );
                assert!(
                    (s.pattern_score - want_pattern).abs() < 1e-6,
                    "{line:?}: pattern_score {}, want {want_pattern}",
                    s.pattern_score
                );
                assert!(
                    (s.cursor_score - want_cursor).abs() < 1e-6,
                    "{line:?}: cursor_score {}, want {want_cursor}",
                    s.cursor_score
                );
                assert!(
                    (s.confidence - want_confidence).abs() < 1e-6,
                    "{line:?}: confidence {}, want {want_confidence}",
                    s.confidence
                );
                // The mode is what the agent acts on, and it is the half
                // of the answer that changed: a stalled progress bar used
                // to read `AtPrompt` off the cursor alone.
                let want_mode = if *want_confidence >= 0.5 {
                    InteractionMode::AtPrompt
                } else {
                    InteractionMode::Executing
                };
                assert_eq!(s.interaction_mode, want_mode, "{line:?}");
            }
        }

        /// The corpus that asserts nothing, written out so that it cannot
        /// be arrived at by accident.
        ///
        /// Terminate every line above and all thirty collapse to the same
        /// `cursor_score` — `raw_cursor_score` returns at `col == 0`
        /// before it examines a character, so the far side and the near
        /// side become indistinguishable and the whole corpus passes
        /// against an implementation with no head guard in it at all.
        /// That is the arrangement task 4's fixtures were in.
        #[test]
        fn the_same_corpus_newline_terminated_pins_column_zero_and_nothing_else() {
            let mut distinct = std::collections::BTreeSet::new();
            for (line, want_cursor, ..) in CORPUS {
                let terminated = format!("{line}\r\n");
                let p = parked(&terminated);
                assert_eq!(
                    p.screen().cursor_position().1,
                    0,
                    "{line:?}: the newline did not return the cursor to column 0"
                );
                assert_eq!(
                    raw_cursor_score(p.screen(), DEFAULT_PROMPT_CHARS),
                    0.0,
                    "{line:?}"
                );
                distinct.insert(want_cursor.to_bits());
            }
            assert_eq!(
                distinct.len(),
                2,
                "the parked corpus must carry both a 0.9 and a 0.0 side, or \
                 the collapse asserted above is not a collapse"
            );
        }

        /// The end-to-end shape of the defect: a `git clone` that stalls
        /// mid-transfer (§8.6 rev. 46, REQ-PD-008).
        ///
        /// Nothing here is contrived. `git` redraws its counter in place
        /// with a carriage return and never ends the line, so the last
        /// logical line really is `Receiving objects:  47%` with the
        /// cursor really parked after the `%`; a stall is silence, so
        /// `quiescent_score` really does climb to 1.0 with nothing left
        /// to disagree. Before rev. 46 that combination answered
        /// `AtPrompt` / `heuristic` / **0.90** — §8.4's act threshold —
        /// and told the agent to type at a download.
        #[test]
        fn a_stalled_git_clone_answers_executing_and_zero() {
            let (mut d, start, settled) = detector();
            let mut p = vt100::Parser::new(24, 80, 0);
            for pct in ["1", "7", "19", "47"] {
                let chunk = format!("\rReceiving objects:  {pct}%");
                feed(&mut d, start, chunk.as_bytes());
                p.process(chunk.as_bytes());
            }

            let cursor = raw_cursor_score(p.screen(), DEFAULT_PROMPT_CHARS);
            assert_eq!(cursor, 0.0, "the redrawn percentage scored as a prompt");
            let s = d.snapshot_at(true, ld(true, true), None, Some(cursor), settled);
            assert_eq!(s.last_line, "Receiving objects:  47%");
            assert!(
                (s.quiescent_score - 1.0).abs() < 1e-6,
                "{}",
                s.quiescent_score
            );
            assert_eq!(s.interaction_mode, InteractionMode::Executing);
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert_eq!(s.confidence, 0.0);

            // ...and the clone finishing, which is the same fixture with
            // the guard on the other side of its boundary. Without this
            // the row above passes against a combiner that has stopped
            // answering `AtPrompt` at all — and the shell whose prompt
            // this is, `csh` on a numbered host, is one of the sessions
            // T3 exists for.
            let done = "\r\nbuild01% ";
            feed(&mut d, start, done.as_bytes());
            p.process(done.as_bytes());
            let cursor = raw_cursor_score(p.screen(), DEFAULT_PROMPT_CHARS);
            assert_eq!(cursor, 0.9);
            let s = d.snapshot_at(true, ld(true, true), None, Some(cursor), settled);
            assert_eq!(s.last_line, "build01% ");
            assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
            assert!((s.confidence - 0.9).abs() < 1e-6, "{}", s.confidence);
        }
    }

    /// §11.4 — the escape-length ceiling's residual, asserted at what it
    /// actually *reaches* rather than at its cheapest form (§8.8 rev. 34,
    /// REQ-PD-018).
    ///
    /// `SEQUENCE_MAX` bounds how long an unterminated sequence may blind
    /// the scanner; on tripping it, `give_up` discards to the next newline
    /// rather than returning to `Ground`. The residual is that a sequence
    /// whose payload *contains* a newline hands everything after it to the
    /// full state machine. Rev. 27 recorded that as "the last line, which
    /// §8.6 scores 0.85". That is the floor. The ceiling is a genuine OSC
    /// 133 `PromptStart` event and `AtPrompt` / `semantic` / **1.00** — the
    /// highest-confidence answer the system can produce — plus two sticky
    /// (and, since rev. 37, program-scoped — a forged record is owned by
    /// the program that forged it, which is the program at the terminal)
    /// tier-gating flags and chosen text inside `get_command_history`.
    ///
    /// **Why this is written down rather than fixed.** It does not close:
    /// at the moment the ceiling trips, a huge well-formed sequence and a
    /// truncated one share a byte-identical prefix, so any online rule must
    /// act identically on both, and bounding blindness while never
    /// promoting a well-formed payload to text are not simultaneously
    /// achievable. The ceiling is the only free parameter. It is also
    /// neither new nor a regression — before `give_up` existed the trip
    /// returned straight to `Ground`, so all of this was reachable at the
    /// then-8 KiB ceiling with no newline needed — and a hostile child can
    /// print every one of these bytes directly with no ceiling involved
    /// (REQ-PD-010).
    ///
    /// **This is a §11.4 accepted-limitation assertion: update it when the
    /// ceiling changes, never delete it.** Every input below is sized
    /// relative to `SEQUENCE_MAX`, so changing the constant re-aims these
    /// tests rather than invalidating them — but changing the *behaviour*
    /// reddens them, which is the point. Two things the earlier record got
    /// wrong are pinned here as rows in their own right: "well-formed" is
    /// not load-bearing (an unterminated run of the same length leaks
    /// byte-identically, and the carrier does not matter either), and the
    /// accidental case does not need an `ESC` in the payload at all.
    mod sequence_ceiling_residual {
        use super::*;
        use crate::detect::scanner::{Osc133, SEQUENCE_MAX};

        /// A control string that runs past the ceiling, carrying `\r\n`
        /// inside its payload and then `smuggled`.
        ///
        /// `terminator` is `Some` for a carrier the emitting program closed
        /// properly and `None` for one it did not. Both are here because
        /// the difference makes none: the leak comes from the
        /// discard-to-newline rule, not from what the sequence was.
        fn over_ceiling(introducer: &[u8], terminator: Option<&[u8]>, smuggled: &[u8]) -> Vec<u8> {
            carrier(introducer, terminator, smuggled, SEQUENCE_MAX + 4096)
        }

        fn carrier(
            introducer: &[u8],
            terminator: Option<&[u8]>,
            smuggled: &[u8],
            filler: usize,
        ) -> Vec<u8> {
            let mut v = introducer.to_vec();
            v.extend(std::iter::repeat_n(b'A', filler));
            v.extend_from_slice(b"\r\n");
            v.extend_from_slice(smuggled);
            if let Some(t) = terminator {
                v.extend_from_slice(t);
            }
            v
        }

        /// One way of getting an over-long control string onto the wire.
        struct Carrier {
            name: &'static str,
            introducer: &'static [u8],
            /// `None` for a sequence the emitter never closed.
            terminator: Option<&'static [u8]>,
        }

        /// Every carrier §8.8 names, well-formed and not. The OSC/DCS split
        /// matters because the two parse their payloads by different rules
        /// everywhere *except* here; termination matters because rev. 27's
        /// record implied it did.
        const CARRIERS: &[Carrier] = &[
            Carrier {
                name: "OSC 52, BEL-terminated",
                introducer: b"\x1b]52;c;",
                terminator: Some(b"\x07"),
            },
            Carrier {
                name: "OSC 52, ST-terminated",
                introducer: b"\x1b]52;c;",
                terminator: Some(b"\x1b\\"),
            },
            Carrier {
                name: "DCS, ST-terminated",
                introducer: b"\x1bPq",
                terminator: Some(b"\x1b\\"),
            },
            Carrier {
                name: "OSC 52, unterminated",
                introducer: b"\x1b]52;c;",
                terminator: None,
            },
            Carrier {
                name: "DCS, unterminated",
                introducer: b"\x1bPq",
                terminator: None,
            },
        ];

        /// Feed one over-ceiling carrier to a fresh detector and return the
        /// markers it produced with the classification that follows.
        ///
        /// `ECHO` is **on** in every row here, and that is a choice rather
        /// than a default. Echo-off sits above every rung these rows reach
        /// and answers `AwaitingSecret` on its own, which would make each
        /// assertion below a statement about the echo rung instead of about
        /// the leak. With echo on, the only thing that can move the answer
        /// off T3 is the smuggled bytes — which is the property under test.
        /// It is also the realistic value: §8.7 measures `ECHO` on at a
        /// `dash` prompt and during a running command alike.
        fn drive(
            introducer: &[u8],
            terminator: Option<&[u8]>,
            smuggled: &[u8],
        ) -> (PromptDetector, Vec<Osc133Event>, Detection) {
            drive_as(introducer, terminator, smuggled, Some(100), Some(100))
        }

        /// `drive` with the availability *scope* made an argument: `owner`
        /// is who held the terminal when the forgery was scanned, `holder`
        /// who holds it at classification (§8.3, REQ-PD-025).
        ///
        /// **The default is a known group that does not change, and that is
        /// deliberate.** Through rev. 42 this module passed `None` on both
        /// sides, which is the degenerate fixture REQ-PD-018 names by hand:
        /// under `licensed = observed ∧ ¬(owner ∧ holder known ∧
        /// different)`, unknown-on-both-sides can never withhold, so every
        /// row passed identically against a scoped implementation and
        /// against rev. 36's unscoped one and the widen mutation could not
        /// redden any of them. `Some(100)`/`Some(100)` leaves every row's
        /// answer unchanged while making the rows below a *variation* of
        /// them rather than a different test.
        fn drive_as(
            introducer: &[u8],
            terminator: Option<&[u8]>,
            smuggled: &[u8],
            owner: Option<i32>,
            holder: Option<i32>,
        ) -> (PromptDetector, Vec<Osc133Event>, Detection) {
            let (mut d, start, now) = detector();
            let ev = d.feed_at(
                &over_ceiling(introducer, terminator, smuggled),
                0,
                owner,
                start,
            );
            let s = d.snapshot_at(true, ld(true, true), holder, None, now);
            (d, ev, s)
        }

        /// Row 1 of §8.8's residual table — the floor, and the only form
        /// rev. 27 recorded.
        #[test]
        fn a_prompt_shaped_tail_after_the_payloads_newline_answers_at_prompt_on_the_heuristic_tier()
        {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                let (_, ev, s) = drive(introducer, *terminator, b"root@prod:/etc# ");
                assert!(ev.is_empty(), "{name}: unexpected markers");
                assert_eq!(s.last_line, "root@prod:/etc# ", "{name}");
                assert_eq!(s.interaction_mode, InteractionMode::AtPrompt, "{name}");
                assert_eq!(s.detection_tier, DetectionTier::Heuristic, "{name}");
                assert!(
                    (s.confidence - 0.85).abs() < 1e-6,
                    "{name}: {}",
                    s.confidence
                );
            }
        }

        /// Row 2 — and the first step past what the record claimed. The
        /// answer is no longer a 0.85 guess labelled `heuristic`; it is
        /// 0.95 labelled `terminal_mode`, from the bracketed-paste rung,
        /// which reads the mode's **current value** and is gated on no
        /// availability at all (§8.3).
        ///
        /// The forgery also leaves `saw_bracketed_paste` set, and that
        /// record is sticky. What it *licenses* is not: since rev. 37 the
        /// licence is `observed && !(owner and holder both known and
        /// different)`, so the record the forging program armed licenses
        /// the T2 executing rung for **that program**, and lapses the
        /// moment something else holds the terminal. The flag is sticky and
        /// the licence is not — both halves are load-bearing, and scoping
        /// the flag as well would break REQ-PD-016's exited tier and
        /// REQ-PD-025's ConPTY degradation in one move (§11.4, rev. 42).
        #[test]
        fn a_bracketed_paste_set_after_the_payloads_newline_answers_at_prompt_via_terminal_mode() {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                let (d, _, s) = drive(introducer, *terminator, b"\x1b[?2004h");
                let m = d.scanner.modes();
                assert!(m.bracketed_paste, "{name}: mode not set");
                assert!(m.saw_bracketed_paste, "{name}: the record is not armed");
                // **The record's owner, asserted separately from the
                // answer** (REQ-PD-018, REQ-PD-025). The forged record
                // belongs to the program that forged it — the group the
                // scanner sampled when it observed the sequence, not the
                // group at classification. Asserting only the flag, under
                // the label *availability*, is the pre-rev.-37 spelling
                // rev. 42 withdrew: it leaves an implementer believing the
                // scoped rule is pinned here when it is pinned only at
                // REQ-PD-025.
                assert_eq!(
                    m.bracketed_paste_owner,
                    Some(100),
                    "{name}: the forged record is owned by the forging program"
                );
                assert_eq!(s.interaction_mode, InteractionMode::AtPrompt, "{name}");
                assert_eq!(s.detection_tier, DetectionTier::TerminalMode, "{name}");
                assert!(
                    (s.confidence - 0.95).abs() < 1e-6,
                    "{name}: {}",
                    s.confidence
                );
            }
        }

        /// Row 2's **scope** half (REQ-PD-018, §8.8 rev. 42): the forged
        /// record licenses the T2 executing rung for the **forging
        /// program** and for nothing else.
        ///
        /// **The bytes are not row 2's, and the difference is the whole
        /// test.** Row 2 smuggles `\x1b[?2004h` and is answered by the
        /// bracketed-paste rung, which reads the mode's *current value* and
        /// is gated on no availability at all — so scoping cannot move it
        /// and a row written on those bytes asserts nothing about the
        /// licence. §8.8 says exactly this: "the two forged current-value
        /// answers are unaffected by scoping entirely". Turning the mode
        /// back **off** leaves the record armed with the mode down, which
        /// is the only state in which the licensed rung is the one that
        /// answers.
        ///
        /// Three arms, and each is required:
        ///
        /// - owner == holder — the forging program is still at the
        ///   terminal, so its own record licenses its own rung. This is the
        ///   positive, and without it the row below would pass against an
        ///   implementation that never licenses anything.
        /// - owner ≠ holder — something else took the terminal, the licence
        ///   lapses, and the answer drops to the fallback tier. This is the
        ///   arm rev. 36's unscoped licence fails, and the reason the
        ///   widen mutation now reddens this module.
        /// - unknown on both sides — reproduces the owner == holder answer,
        ///   which is **not a bug**: §8.8 rev. 42 says unknown reproduces
        ///   rev. 36, and **on ConPTY that is every session**, so the
        ///   escape-sequence forgery residual is undiminished on Windows.
        ///   Keeping it is what stops the middle arm being read as
        ///   "scoping fixes this".
        #[test]
        fn the_forged_record_licenses_only_the_program_that_forged_it() {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                // The mode is armed and then turned off, so the record is
                // set and the ungated current-value rung is silent.
                let armed_then_off = b"\x1b[?2004h\x1b[?2004l";
                for (arm, owner, holder, tier) in [
                    (
                        "the forging program still holds the terminal",
                        Some(100),
                        Some(100),
                        DetectionTier::TerminalMode,
                    ),
                    (
                        "another program holds the terminal",
                        Some(100),
                        Some(200),
                        DetectionTier::Heuristic,
                    ),
                    (
                        "neither side is known — rev. 36, and every ConPTY session",
                        None,
                        None,
                        DetectionTier::TerminalMode,
                    ),
                ] {
                    let (d, _, s) =
                        drive_as(introducer, *terminator, armed_then_off, owner, holder);
                    let m = d.scanner.modes();
                    assert!(!m.bracketed_paste, "{name}/{arm}: the mode is still on");
                    // The record is sticky and stays armed in every arm —
                    // asserted, because scoping the *flag* as well would
                    // break REQ-PD-016's exited tier and REQ-PD-025's
                    // ConPTY degradation in one move (§11.4, rev. 42).
                    assert!(
                        m.saw_bracketed_paste,
                        "{name}/{arm}: the record must stay armed"
                    );
                    assert_eq!(m.bracketed_paste_owner, owner, "{name}/{arm}");
                    // What moves is the tier, not the mode: a program the
                    // shell launched is still `Executing` either way, and
                    // §8.4 still says wait. What changes is whether the
                    // answer is labelled deterministic or a guess.
                    assert_eq!(
                        s.interaction_mode,
                        InteractionMode::Executing,
                        "{name}/{arm}"
                    );
                    assert_eq!(s.detection_tier, tier, "{name}/{arm}");
                }
            }
        }

        /// Row 3 — the alternate screen, which changes what `read_output`
        /// is even allowed to claim about the buffer (§8.4).
        #[test]
        fn an_alt_screen_set_after_the_payloads_newline_answers_fullscreen() {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                let (d, _, s) = drive(introducer, *terminator, b"\x1b[?1049h");
                let m = d.scanner.modes();
                assert!(m.alt_screen, "{name}: mode not set");
                assert!(m.saw_alt_screen, "{name}: availability not set");
                assert_eq!(s.interaction_mode, InteractionMode::Fullscreen, "{name}");
                assert_eq!(s.detection_tier, DetectionTier::TerminalMode, "{name}");
            }
        }

        /// Row 4 — the top of the table, and the reason rev. 27's "0.85 at
        /// heuristic" was the wrong thing for 0.0.4's Tier-B work and the
        /// §8.7 acceptance matrix to read. A `PromptStart` **event** is
        /// produced, not merely a mode flag, and `semantic` / 1.00 is the
        /// answer §8.4 tells an agent it may act on without corroboration.
        #[test]
        fn an_osc133_marker_after_the_payloads_newline_answers_at_prompt_via_semantic() {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                let (d, ev, s) = drive(introducer, *terminator, b"\x1b]133;A\x07root@prod:/etc# ");
                assert_eq!(
                    ev.iter().map(|e| e.marker.clone()).collect::<Vec<_>>(),
                    vec![Osc133::PromptStart],
                    "{name}: no genuine marker event"
                );
                assert!(d.scanner.modes().saw_osc133, "{name}");
                assert_eq!(s.interaction_mode, InteractionMode::AtPrompt, "{name}");
                assert_eq!(s.detection_tier, DetectionTier::Semantic, "{name}");
                assert!(
                    (s.confidence - 1.0).abs() < 1e-6,
                    "{name}: {}",
                    s.confidence
                );
            }
        }

        /// Row 5 — the leak reaching `get_command_history` (§5.2). That
        /// tool is documented as best-effort; it is not documented as
        /// *chosen*, and the text below is chosen.
        #[test]
        fn an_osc133_command_span_after_the_payloads_newline_injects_the_reported_command() {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                let (_, ev, _) = drive(
                    introducer,
                    *terminator,
                    b"\x1b]133;B\x07ls\nrm -rf /\x1b]133;C\x07",
                );
                assert_eq!(
                    ev.iter().map(|e| e.marker.clone()).collect::<Vec<_>>(),
                    vec![
                        Osc133::CommandStart,
                        Osc133::OutputStart {
                            command: "ls\nrm -rf /".into()
                        }
                    ],
                    "{name}"
                );
            }
        }

        /// The negative that separates every row above from the degenerate
        /// case — without it they would pass against a scanner that never
        /// hid anything at all, and the ceiling would be doing no work.
        ///
        /// The `ESC`-free tail is the carrier-independent case, so it is
        /// the one swept across all five. The mode-forging tail is asserted
        /// on **DCS only**, deliberately: an OSC payload is *not* opaque to
        /// a non-ST escape at any length — `\x1b[?2004h` inside one is
        /// applied whether or not the ceiling is involved, because a title
        /// whose terminator was dropped must not swallow the marker behind
        /// it. That is the `OscEsc` rule, not this ceiling, and conflating
        /// the two here would assert the wrong thing about the wrong rule.
        #[test]
        fn the_residual_is_out_of_reach_below_the_ceiling() {
            for Carrier {
                name,
                introducer,
                terminator,
            } in CARRIERS
            {
                let (mut d, start, now) = detector();
                d.feed_at(
                    &carrier(
                        introducer,
                        *terminator,
                        b"root@prod:/etc# ",
                        SEQUENCE_MAX / 4,
                    ),
                    0,
                    None,
                    start,
                );
                let s = d.snapshot_at(true, ld(true, true), None, None, now);
                assert_eq!(s.last_line, "", "{name}: payload became terminal text");
                assert_eq!(s.interaction_mode, InteractionMode::Executing, "{name}");
                assert_eq!(s.detection_tier, DetectionTier::Heuristic, "{name}");
                assert_eq!(s.confidence, 0.0, "{name}");
            }

            let (mut d, start, now) = detector();
            d.feed_at(
                &carrier(
                    &b"\x1bPq"[..],
                    Some(&b"\x1b\\"[..]),
                    b"\x1b[?2004h",
                    SEQUENCE_MAX / 4,
                ),
                0,
                None,
                start,
            );
            let m = d.scanner.modes();
            assert!(!m.bracketed_paste && !m.saw_bracketed_paste);
            assert_eq!(
                d.snapshot_at(true, ld(true, true), None, None, now)
                    .detection_tier,
                DetectionTier::Heuristic,
                "a DCS under the ceiling kept its payload opaque"
            );
        }

        /// A format-faithful sixel image of `graphics` bytes whose final
        /// graphics row ends in `$`, with **no `ESC` in the payload**.
        ///
        /// `#` introduces a colour and `$` is the graphics carriage return,
        /// so the bytes that reach the T3 table when this trips the ceiling
        /// are ordinary image data. The bands are broken across lines,
        /// which is what makes the accident reachable at all — the discard
        /// ends at the payload's own newline — and is how sixel looks
        /// whenever it is stored or streamed line-wise rather than written
        /// as one unbroken run.
        fn sixel(graphics: usize) -> Vec<u8> {
            let band = format!("#1{}$-\n", "!255~".repeat(20));
            let last = format!("#1{}$", "!255~".repeat(20));
            let mut v = b"\x1bPq#0;2;0;0;0#1;2;100;100;100".to_vec();
            let bands = graphics.saturating_sub(last.len()) / band.len();
            for _ in 0..bands {
                v.extend_from_slice(band.as_bytes());
            }
            v.extend_from_slice(last.as_bytes());
            let payload_end = v.len();
            v.extend_from_slice(b"\x1b\\");
            assert!(
                !v[2..payload_end].contains(&0x1b),
                "the sixel payload must contain no ESC — that is the whole \
                 claim this fixture exists to support"
            );
            v
        }

        /// The ceiling's *value*, and the behaviour it was raised for.
        ///
        /// A literal, not `1024 * OSC_PAYLOAD_MAX` — comparing the constant
        /// against its own definition is a tautology, and the point of this
        /// test is that changing the number has to be a deliberate edit.
        /// The rows above are all ceiling-relative and so re-aim silently
        /// when it moves, which is right for them and leaves exactly this
        /// gap.
        ///
        /// The second half is why the number is what it is. Sixel frames
        /// run from ~100 KiB to several MiB; at `64 * OSC_PAYLOAD_MAX` the
        /// ceiling sat *below* the very class the implementation comment
        /// cited as the reason it had been raised, so a routine image
        /// reached the 0.60 rung by accident. 128 KiB is that routine
        /// class, and it must now be consumed whole.
        #[test]
        fn the_blindness_budget_is_a_megabyte_and_the_routine_sixel_fits_under_it() {
            assert_eq!(SEQUENCE_MAX, 1024 * 1024, "§8.8's blindness budget");

            let (mut d, start, now) = detector();
            d.feed_at(&sixel(128 * 1024), 0, None, start);
            let s = d.snapshot_at(true, ld(true, true), None, None, now);
            assert_eq!(
                s.last_line, "",
                "a routine 128 KiB sixel tripped the ceiling and handed its \
                 graphics data to the T3 table"
            );
            assert_eq!(s.confidence, 0.0);
        }

        /// The accidental case: no adversary, no `ESC`, a real image.
        ///
        /// §8.8 rev. 27 justified the ceiling as "above what real programs
        /// emit" and the implementation's own comment named sixel as the
        /// reason it had been raised — while sitting *below* the size sixel
        /// routinely reaches. The correction is not that the number was too
        /// small but that no constant satisfies that justification, which
        /// is why `SEQUENCE_MAX` is documented as a blindness budget
        /// instead. This test is what stops that from being a comment: it
        /// is written against the constant, so raising the ceiling again
        /// moves the boundary it asserts rather than deleting it.
        #[test]
        fn a_sixel_image_over_the_ceiling_forges_a_prompt_with_no_escape_in_its_payload() {
            let (mut d, start, now) = detector();
            d.feed_at(&sixel(SEQUENCE_MAX / 32), 0, None, start);
            let s = d.snapshot_at(true, ld(true, true), None, None, now);
            assert_eq!(s.last_line, "", "an image under the ceiling is opaque");
            assert_eq!(s.confidence, 0.0);

            let (mut d, start, now) = detector();
            d.feed_at(&sixel(SEQUENCE_MAX + 65536), 0, None, start);
            let s = d.snapshot_at(true, ld(true, true), None, None, now);
            assert!(
                s.last_line.ends_with('$'),
                "the graphics carriage return did not reach the tail: {:?}",
                s.last_line
            );
            assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert!((s.confidence - 0.6).abs() < 1e-6, "{}", s.confidence);
        }
    }
}
