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
        let t1 = modes.saw_osc133;
        let t2 = modes.saw_bracketed_paste || modes.saw_alt_screen;
        let session_tier = if t1 {
            DetectionTier::Semantic
        } else if t2 {
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
        } else if t2 {
            (
                InteractionMode::Executing,
                DetectionTier::TerminalMode,
                0.0,
                "bracketed paste is disabled".to_string(),
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

    /// A detector whose clock reads far enough ahead that the session is
    /// fully settled unless a test says otherwise.
    fn detector() -> (PromptDetector, Instant) {
        let d = PromptDetector::default();
        let now = Instant::now() + Duration::from_secs(10);
        (d, now)
    }

    fn feed(d: &mut PromptDetector, bytes: &[u8]) {
        d.feed_at(bytes, 0, Instant::now());
    }

    // ---- the §8.7 measurement matrix, replayed as byte streams ----
    //
    // The mode/echo values in each row are the ones measured against real
    // PTYs in the spike and re-measured in the 0.0.2 integration suite.

    #[test]
    fn matrix_idle_bash_prompt() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004hbash-5.3$ ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.95);
    }

    #[test]
    fn matrix_during_a_running_command() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004h\x1b[?2004lsleep 2\r\n");
        let s = d.snapshot_at(true, Some(true), now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn matrix_getpass_prompt() {
        let (mut d, now) = detector();
        feed(&mut d, b"Password: ");
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
        let (mut d, now) = detector();
        // A `read -s` runs inside a shell that has already used bracketed
        // paste; the mode is off while the command runs.
        feed(&mut d, b"\x1b[?2004h\x1b[?2004lPassword: ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
    }

    #[test]
    fn matrix_python_repl_prompt() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004h>>> ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn matrix_inside_a_tui() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?1049h:");
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
        let (mut d, now) = detector();
        feed(&mut d, b"$ ");
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
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004hbash-5.3$ ");
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
        let (mut d, now) = detector();
        feed(
            &mut d,
            b"\x1b]133;A\x07$ \x1b]133;B\x07sudo id\r\n\x1b]133;C\x07",
        );
        feed(&mut d, b"\x1b[?2004l[sudo] password for alice: ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AwaitingSecret);
        assert_eq!(s.detection_tier, DetectionTier::TerminalMode);
    }

    #[test]
    fn a_repl_inside_an_integrated_shell_reports_at_prompt() {
        let (mut d, now) = detector();
        feed(
            &mut d,
            b"\x1b]133;A\x07$ \x1b]133;B\x07python3\r\n\x1b]133;C\x07",
        );
        feed(&mut d, b"\x1b[?2004h>>> ");
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
        let (mut d, now) = detector();
        feed(
            &mut d,
            b"\x1b]133;A\x07$ \x1b]133;B\x07less f\r\n\x1b]133;C\x07",
        );
        feed(&mut d, b"\x1b[?1049h");
        assert_eq!(
            d.snapshot_at(true, Some(false), now).interaction_mode,
            InteractionMode::Fullscreen
        );
    }

    #[test]
    fn osc133_prompt_markers_give_full_confidence() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b]133;A\x07bash-5.3$ \x1b]133;B\x07");
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
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b]133;A\x07bash-5.3$ ");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.interaction_mode, InteractionMode::AtPrompt);
        assert_eq!(s.detection_tier, DetectionTier::Semantic);
        assert_eq!(s.confidence, 1.0);
    }

    #[test]
    fn osc133_output_markers_report_executing_at_zero_confidence() {
        let (mut d, now) = detector();
        feed(
            &mut d,
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
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b]133;C\x07out\r\n\x1b]133;D;0\x07");
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
        let (mut d, now) = detector();
        feed(&mut d, b"> ");
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
    fn a_settled_but_unrecognised_tail_scores_zero_confidence() {
        let (mut d, now) = detector();
        feed(&mut d, b"linking target/debug/clasp");
        let s = d.snapshot_at(true, Some(true), now);
        assert_eq!(s.quiescent_score, 1.0);
        assert_eq!(s.pattern_score, 0.0);
        assert_eq!(s.confidence, 0.0);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
    }

    #[test]
    fn the_cursor_sub_signal_is_reported_and_inert_until_tier_b() {
        let (mut d, now) = detector();
        feed(&mut d, b"$ ");
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
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004hbash-5.3$ ");
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
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b]133;A\x07alice@host:~$ \x1b]133;B\x07");
        let s = d.snapshot_at(true, Some(false), now);
        assert_eq!(s.detection_tier, DetectionTier::Semantic);
        assert_eq!(s.last_line, "alice@host:~$ ");
        assert!(
            (s.pattern_score - 0.85).abs() < 1e-6,
            "corroborating scores must be reported even when T1 answers"
        );
        assert_eq!(s.quiescent_score, 1.0);
    }

    #[test]
    fn the_window_title_is_reported() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b]0;make -j8\x07\x1b[?2004h$ ");
        assert_eq!(
            d.snapshot_at(true, Some(false), now).title.as_deref(),
            Some("make -j8")
        );
    }

    #[test]
    fn a_backend_that_cannot_sample_echo_never_reports_awaiting_secret() {
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004h\x1b[?2004lPassword: ");
        let s = d.snapshot_at(true, None, now);
        assert_eq!(s.interaction_mode, InteractionMode::Executing);
    }

    #[test]
    fn a_faked_bracketed_paste_fools_tier_2_as_documented() {
        // Spec §8.8: CLASP does not defend against a hostile child. This
        // asserts the limitation so it cannot change silently.
        let (mut d, now) = detector();
        feed(&mut d, b"\x1b[?2004h");
        assert_eq!(
            d.snapshot_at(true, Some(true), now).interaction_mode,
            InteractionMode::AtPrompt,
            "documented limitation: a program printing \\x1b[?2004h is believed"
        );
    }
}
