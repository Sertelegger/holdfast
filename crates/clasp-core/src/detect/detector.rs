//! The tiered classifier (spec §8.3, §8.4) and the state it needs.

use super::patterns::PatternSet;
use super::scanner::{ModeScanner, Osc133Event};
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
    pub fn feed(&mut self, bytes: &[u8], base: u64) -> Vec<Osc133Event> {
        self.feed_at(bytes, base, Instant::now())
    }

    /// `feed` with an injected clock, so quiescence can be tested without
    /// sleeping.
    pub fn feed_at(&mut self, bytes: &[u8], base: u64, now: Instant) -> Vec<Osc133Event> {
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
        self.scanner.feed(bytes, base)
    }

    pub fn snapshot(&mut self, alive: bool, echo: Option<bool>) -> Detection {
        self.snapshot_at(alive, echo, Instant::now())
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
    pub fn snapshot_at(&mut self, alive: bool, echo: Option<bool>, now: Instant) -> Detection {
        let modes = self.scanner.modes();
        let last_line = self.scanner.last_line();
        let title = self.scanner.title().map(str::to_owned);

        let quiescent_score = self.quiescent_score(now);
        let pattern_score = self.config.patterns.score(&last_line);
        // Tier B is 0.0.4; until then the cursor sub-signal contributes
        // nothing and `max(pattern, cursor)` degenerates to `pattern`.
        let cursor_score = 0.0;

        // Availability, not current value: a program that has never driven
        // a terminal mode (`dash`) cannot be classified by one, and must
        // fall through to T3 rather than be read as "not at a prompt".
        //
        // Availability is stated **per signal**, not per tier (§8.3), and
        // it is *sticky* — observed once, never un-observed. So whatever a
        // signal's availability licenses has to hold for the rest of the
        // session, and only bracketed paste supports a claim that strong:
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
        //   notion — which is why this narrows the executing rung rather
        //   than dropping the signal from the classifier.
        // - **termios `ECHO`** likewise: readable is not observed. `dash`
        //   has a perfectly readable `ECHO` and it is *on* at a `dash`
        //   prompt, so a T2 answer there would be actively wrong.
        //
        // Through rev. 27 this read `saw_bracketed_paste || saw_alt_screen`.
        // Because availability is sticky, one alt-screen toggle marked a
        // session T2-available for life and the executing rung then
        // answered `Executing` at every later live prompt of a shell that
        // drives no terminal modes at all — with `pattern_score: 0.60`
        // contradicting it in the same payload, and §8.4 telling the agent
        // to wait. Nothing in the session could ever clear it. See the
        // `availability` test module for the five §8.7 rows that pin this
        // in both directions.
        let t1 = modes.saw_osc133;
        let t2_prompt_mode = modes.saw_bracketed_paste;
        let session_tier = if t1 {
            DetectionTier::Semantic
        } else if t2_prompt_mode {
            DetectionTier::TerminalMode
        } else {
            DetectionTier::Heuristic
        };
        let at_marker = matches!(self.scanner.last_marker(), Some(b'A') | Some(b'B'));

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
        } else if echo == Some(false) && !modes.bracketed_paste {
            (
                InteractionMode::AwaitingSecret,
                DetectionTier::TerminalMode,
                0.95,
                "echo disabled with no bracketed paste or alternate screen".to_string(),
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
        d.feed_at(bytes, 0, at);
    }

    // ---- the §8.7 measurement matrix, replayed as byte streams ----
    //
    // The mode/echo values in each row are the ones measured against real
    // PTYs in the spike and re-measured in the 0.0.2 integration suite.

    #[test]
    fn matrix_idle_bash_prompt() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004hbash-5.3$ ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.95);
    }

    #[test]
    fn matrix_during_a_running_command() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h\x1b[?2004lsleep 2\r\n");
        let s = d.snapshot_at(true, Some(true), now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn matrix_getpass_prompt() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"Password: ");
        let s = d.snapshot_at(true, Some(false), now);
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
        let s = d.snapshot_at(true, Some(false), now);
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
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.95);
    }

    #[test]
    fn matrix_python_repl_prompt() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h>>> ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn matrix_inside_a_tui() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?1049h:");
        let s = d.snapshot_at(true, Some(false), now);
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
        let s = d.snapshot_at(true, Some(true), now);
        assert_eq!(s.detection_tier, DetectionTier::Heuristic);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert!((s.confidence - 0.6).abs() < 1e-6, "{}", s.confidence);
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
            d.snapshot_at(true, Some(false), now).interaction_mode,
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
        let s = d.snapshot_at(true, Some(false), now);
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
        let s = d.snapshot_at(true, Some(false), now);
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
            d.snapshot_at(true, Some(false), now).interaction_mode,
            InteractionMode::Fullscreen
        );
    }

    #[test]
    fn osc133_prompt_markers_give_full_confidence() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b]133;A\x07bash-5.3$ \x1b]133;B\x07");
        let s = d.snapshot_at(true, Some(false), now);
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
        let s = d.snapshot_at(true, Some(false), now);
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
        let s = d.snapshot_at(true, Some(true), now);
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
            d.snapshot_at(true, Some(true), now).interaction_mode,
            InteractionMode::Executing
        );
    }

    // ---- T3 combiner ----

    #[test]
    fn quiescence_gates_the_heuristic() {
        let mut d = PromptDetector::default();
        let start = Instant::now();
        d.feed_at(b">>> ", 0, start);

        // Immediately after output: not settled, so no confidence at all
        // however prompt-shaped the tail is.
        let s = d.snapshot_at(true, Some(true), start);
        assert_eq!(s.quiescent_score, 0.0);
        assert!((s.pattern_score - 0.9).abs() < 1e-6);
        assert_eq!(s.confidence, 0.0);

        // Half the settle threshold: half the score.
        let s = d.snapshot_at(true, Some(true), start + Duration::from_millis(125));
        assert!(
            (s.quiescent_score - 0.5).abs() < 0.01,
            "{}",
            s.quiescent_score
        );
        assert!((s.confidence - 0.45).abs() < 0.01, "{}", s.confidence);

        // Past the threshold: saturated.
        let s = d.snapshot_at(true, Some(true), start + Duration::from_millis(400));
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
        d.feed_at(b"building\r\n>>> ", 0, start);
        let settled = start + Duration::from_millis(400);
        assert_eq!(
            d.snapshot_at(true, Some(true), settled).quiescent_score,
            1.0
        );

        // More output lands at the instant we were about to call it settled.
        d.feed_at(b"linking\r\n>>> ", 13, settled);
        let s = d.snapshot_at(true, Some(true), settled);
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
        let s = d.snapshot_at(true, Some(true), now);
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
        d.feed_at(b"$ ", 0, start);
        let settled = start + Duration::from_millis(400);
        assert_eq!(
            d.snapshot_at(true, Some(true), settled).quiescent_score,
            1.0
        );

        let events = d.feed_at(b"", 2, settled);
        assert!(events.is_empty());
        assert_eq!(
            d.snapshot_at(true, Some(true), settled).quiescent_score,
            1.0,
            "an empty read was counted as output"
        );
    }

    #[test]
    fn a_settled_but_unrecognised_tail_scores_zero_confidence() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"linking target/debug/clasp");
        let s = d.snapshot_at(true, Some(true), now);
        assert_eq!(s.quiescent_score, 1.0);
        assert_eq!(s.pattern_score, 0.0);
        assert_eq!(s.confidence, 0.0);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
    }

    #[test]
    fn the_cursor_sub_signal_is_reported_and_inert_until_tier_b() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"$ ");
        let s = d.snapshot_at(true, Some(true), now);
        assert_eq!(s.cursor_score, 0.0, "Tier B is 0.0.4");
        // max(pattern, cursor) must still pick the pattern up.
        assert!((s.confidence - s.pattern_score).abs() < 1e-6);
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
        d.feed_at(b"ready> ", 0, Instant::now());
        let s = d.snapshot_at(true, Some(true), now);
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
        d.feed_at(b">>> ", 0, start);
        let s = d.snapshot_at(true, Some(true), start + Duration::from_millis(250));
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
        let s = d.snapshot_at(false, None, now);
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
        // The `echo` column is not decoration: with echo off the T2 rung
        // answers AwaitingSecret before T3 is ever consulted, so the
        // heuristic row has to be a session whose echo is *on* — which is
        // exactly what a `dash` prompt looks like (§8.7).
        for (bytes, echo, tier) in [
            (
                &b"\x1b]133;A\x07alice@host:~$ \x1b]133;B\x07"[..],
                Some(false),
                DetectionTier::Semantic,
            ),
            (
                &b"\x1b[?2004halice@host:~$ "[..],
                Some(false),
                DetectionTier::TerminalMode,
            ),
            (&b"alice@host:~$ "[..], Some(true), DetectionTier::Heuristic),
        ] {
            let (mut d, start, now) = detector();
            feed(&mut d, start, bytes);
            let s = d.snapshot_at(true, echo, now);
            assert_eq!(s.detection_tier, tier, "{bytes:?}");
            assert_eq!(s.last_line, "alice@host:~$ ", "{bytes:?}");
            assert!(
                (s.pattern_score - 0.85).abs() < 1e-6,
                "{bytes:?}: corroborating scores must be reported whichever \
                 tier answers, got {}",
                s.pattern_score
            );
            assert_eq!(s.quiescent_score, 1.0, "{bytes:?}");
            assert_eq!(s.cursor_score, 0.0, "{bytes:?}");
        }
    }

    #[test]
    fn the_window_title_is_reported() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b]0;make -j8\x07\x1b[?2004h$ ");
        assert_eq!(
            d.snapshot_at(true, Some(false), now).title.as_deref(),
            Some("make -j8")
        );
    }

    #[test]
    fn a_backend_that_cannot_sample_echo_never_reports_awaiting_secret() {
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h\x1b[?2004lPassword: ");
        let s = d.snapshot_at(true, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
    }

    #[test]
    fn a_faked_bracketed_paste_fools_tier_2_as_documented() {
        // Spec §8.8: CLASP does not defend against a hostile child. This
        // asserts the limitation so it cannot change silently.
        let (mut d, start, now) = detector();
        feed(&mut d, start, b"\x1b[?2004h");
        assert_eq!(
            d.snapshot_at(true, Some(true), now).interaction_mode,
            InteractionMode::AtPrompt,
            "documented limitation: a program printing \\x1b[?2004h is believed"
        );
    }

    /// §11.1 `detector::availability` — the §8.3 availability rule, pinned
    /// in **both** directions (REQ-PD-011, REQ-PD-015).
    ///
    /// Availability is a *sticky per-signal* fact: observed once, never
    /// un-observed. So whatever a signal's availability licenses has to
    /// hold for the rest of the session, and exactly one of the three T2
    /// signals supports such a claim. Bracketed paste licenses the T2
    /// executing rung — *prompt mode is off, therefore not at a prompt* is
    /// valid only for a program known to signal its prompts that way.
    /// Observing the alternate screen says a child took the screen and
    /// gave it back; it licenses nothing about whether the shell now
    /// holding the tty signals its prompts at all.
    ///
    /// **Why this module exists as a module.** The rule was previously
    /// unpinned in *both* directions: the entire 0.0.2 suite passed with
    /// and without the `|| saw_alt_screen` disjunct, so two implementations
    /// that classify a live `dash` prompt differently both satisfied the
    /// text. A rule that only fails one way is half-pinned. The two
    /// mutations these rows exist to kill are:
    ///
    /// - **drop bracketed paste** from the rule — row 4 breaks, and note
    ///   that its `interaction_mode` (`Executing`) and its `confidence`
    ///   (`0.00`) are *unchanged* by that mutation. Only the tier moves.
    ///   A row asserted at its mode alone would not notice.
    /// - **add alt-screen back** to the rule — rows 2 and 3 break, on all
    ///   three fields.
    ///
    /// Rows 1 and 5 must not move under either mutation. Row 1 is the
    /// baseline `dash` prompt the availability gate was introduced (rev.
    /// 23) to protect; row 5 reads alt-screen's *current* value at the
    /// `Fullscreen` rung, which sits earlier in the ladder and is untouched
    /// by any change to availability.
    mod availability {
        use super::*;

        /// Assert the session *history* a row's byte stream is supposed to
        /// establish, before asking what the classifier makes of it.
        ///
        /// These five rows differ from one another only in that history —
        /// rows 1 and 2 end on byte-identical prompts — so a stream that
        /// silently stops establishing it degrades into another row that
        /// is already covered and keeps passing. A mistyped `\x1b[?1049h`
        /// turns row 2 back into row 1, which satisfies every assertion
        /// row 2 makes about the *answer*. This is the guard that makes
        /// the row name mean something.
        ///
        /// Argument order is `(bracketed paste seen, alt screen seen, alt
        /// screen now, osc 133 seen)`. All four are `bool`, so a
        /// transposition compiles; what stops it is that no two rows below
        /// carry the same four values, and the failure names the field.
        ///
        /// `saw_osc133` is the *third* tier-gating flag and the one
        /// REQ-PD-016's exited matrix keys on. Without it here, that
        /// matrix's OSC-133 row and its never-observed row are, as far as
        /// this guard can tell, the same stream.
        fn assert_history(
            d: &PromptDetector,
            saw_bp: bool,
            saw_alt: bool,
            alt_now: bool,
            saw_osc133: bool,
        ) {
            let m = d.scanner.modes();
            assert_eq!(
                m.saw_bracketed_paste, saw_bp,
                "observed-bracketed-paste history"
            );
            assert_eq!(m.saw_alt_screen, saw_alt, "observed-alt-screen history");
            assert_eq!(m.alt_screen, alt_now, "alternate screen right now");
            assert_eq!(m.saw_osc133, saw_osc133, "observed-osc-133 history");
        }

        /// Row 1 — `dash`, no terminal mode ever seen, sitting at `$ `.
        /// The case that always worked, asserted so the fix cannot buy
        /// rows 2 and 3 at its expense.
        #[test]
        fn row_1_dash_that_never_saw_a_mode_answers_at_prompt_via_t3() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"$ ");
            assert_history(&d, false, false, false, false);

            let s = d.snapshot_at(true, Some(true), now);
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
        #[test]
        fn row_2_dash_after_less_entered_and_left_the_alt_screen_still_answers_via_t3() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"\x1b[?1049h(END)\x1b[?1049l\r\n$ ");
            assert_history(&d, false, true, false, false);

            let s = d.snapshot_at(true, Some(true), now);
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
        #[test]
        fn row_3_a_bespoke_cli_that_alt_screened_once_and_now_prompts_answers_via_t3() {
            let (mut d, start, now) = detector();
            feed(
                &mut d,
                start,
                b"\x1b[?1049h drawing \x1b[?1049l\r\nEnter a value: ",
            );
            assert_history(&d, false, true, false, false);

            let s = d.snapshot_at(true, Some(true), now);
            assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
            assert_eq!(s.detection_tier, DetectionTier::Heuristic);
            assert!((s.confidence - 0.80).abs() < 1e-6, "{}", s.confidence);
        }

        /// Row 4 — bash, bracketed paste seen and now disabled, a command
        /// running. The one inference bracketed-paste availability
        /// legitimately licenses, and the row that breaks if the signal is
        /// *removed* from the rule.
        #[test]
        fn row_4_bash_with_bracketed_paste_seen_then_disabled_answers_executing_via_t2() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"\x1b[?2004h\x1b[?2004lsleep 2\r\n");
            assert_history(&d, true, false, false, false);

            let s = d.snapshot_at(true, Some(true), now);
            assert_eq!(s.interaction_mode, InteractionMode::Executing);
            assert_eq!(
                s.detection_tier,
                DetectionTier::TerminalMode,
                "removing bracketed paste from the availability rule drops \
                 this row to the heuristic tier while leaving its mode \
                 (`Executing`) and its confidence (0.00) untouched — the \
                 tier is the only field that catches that direction"
            );
            assert_eq!(s.confidence, 0.0);
        }

        /// Row 5 — the alternate screen currently **on**. Unaffected in
        /// both directions: the `Fullscreen` rung reads alt-screen's
        /// current value and sits above every availability question, which
        /// is why the fix narrows the executing rung rather than dropping
        /// alt-screen from the classifier. Note the session has never
        /// driven bracketed paste, so this holds with no T2 availability
        /// at all.
        #[test]
        fn row_5_a_live_alt_screen_reports_fullscreen_with_no_availability_at_all() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"\x1b[?1049h:");
            assert_history(&d, false, true, true, false);

            let s = d.snapshot_at(true, Some(true), now);
            assert_eq!(s.interaction_mode, InteractionMode::Fullscreen);
            assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
            assert_eq!(s.confidence, 0.0);
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
                let without = clean.snapshot_at(true, Some(true), now);

                let (mut toggled, start, now) = detector();
                feed(&mut toggled, start, b"\x1b[?1049h(END)\x1b[?1049l\r\n");
                feed(&mut toggled, start, tail);
                assert_history(&toggled, false, true, false, false);
                let with = toggled.snapshot_at(true, Some(true), now);

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
            assert_history(&d, false, true, false, false);
            assert_eq!(
                d.snapshot_at(false, None, now).detection_tier,
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
            assert_history(&d, false, false, false, true);

            let s = d.snapshot_at(false, None, now);
            assert_eq!(s.interaction_mode, InteractionMode::Exited);
            assert_eq!(
                s.detection_tier,
                DetectionTier::Semantic,
                "a shell that emitted OSC 133 was classifiable semantically, \
                 and exiting does not retract that"
            );
            assert_eq!(s.confidence, 0.0);
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
        /// the same tier for `bash -c 'exit 3'` but does not assert the
        /// history it depends on.
        #[test]
        fn an_exited_session_that_observed_nothing_reports_the_heuristic_tier() {
            let (mut d, start, now) = detector();
            feed(&mut d, start, b"bash-5.3$ ");
            assert_history(&d, false, false, false, false);

            let s = d.snapshot_at(false, None, now);
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
}
