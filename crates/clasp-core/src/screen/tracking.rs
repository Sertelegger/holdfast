//! The adaptive enable/disable policy for Tier-B tracking (spec §4.5).
//!
//! Pure decision logic: no parser, no buffer, no wall clock. `now` is a
//! parameter on every method that needs it, which is what makes the
//! decision table testable without sleeping.

use std::time::{Duration, Instant};

/// Spec §4.2 `screen_tracking` / §18.2a. `off` and `on` are operator
/// overrides; `adaptive` is the default and the interesting one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScreenTracking {
    Off,
    #[default]
    Adaptive,
    On,
}

impl ScreenTracking {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Adaptive => "adaptive",
            Self::On => "on",
        }
    }

    /// Parse a config or tool-argument value. Returns `None` for anything
    /// outside the enum so callers can raise a schema error rather than
    /// silently falling back to a default the operator did not ask for.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "adaptive" => Some(Self::Adaptive),
            "on" => Some(Self::On),
            _ => None,
        }
    }
}

/// Why Tier B is currently on. Reported for diagnostics; the disable rule
/// does not read it (it re-derives the conditions from live state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnableReason {
    /// `screen_tracking = "on"` — operator forced it.
    Forced,
    /// The agent asked for screen state.
    ConsumerRequest,
    /// Tier A saw the alternate screen turn on.
    AltScreen,
    /// No bracketed paste and no OSC 133 within the grace window.
    NoDeterministicSignal,
}

/// The §4.5 state machine.
#[derive(Debug)]
pub struct TrackingPolicy {
    mode: ScreenTracking,
    idle_disable: Duration,
    no_signal_grace: Duration,
    started_at: Instant,
    last_consumer_touch: Instant,
    enabled: bool,
    enable_reason: Option<EnableReason>,
    alt_screen: bool,
    saw_deterministic_signal: bool,
}

impl TrackingPolicy {
    pub fn new(
        mode: ScreenTracking,
        idle_disable: Duration,
        no_signal_grace: Duration,
        now: Instant,
    ) -> Self {
        let forced = mode == ScreenTracking::On;
        Self {
            mode,
            idle_disable,
            no_signal_grace,
            started_at: now,
            last_consumer_touch: now,
            enabled: forced,
            enable_reason: forced.then_some(EnableReason::Forced),
            alt_screen: false,
            saw_deterministic_signal: false,
        }
    }

    pub fn mode(&self) -> ScreenTracking {
        self.mode
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn enable_reason(&self) -> Option<EnableReason> {
        self.enable_reason
    }

    pub fn alt_screen(&self) -> bool {
        self.alt_screen
    }

    pub fn saw_deterministic_signal(&self) -> bool {
        self.saw_deterministic_signal
    }

    /// Feed the Tier-A facts. `saw_deterministic_signal` is a latch on the
    /// caller's side, so it never goes back to false here.
    pub fn observe(&mut self, alt_screen: bool, saw_deterministic_signal: bool) {
        self.alt_screen = alt_screen;
        self.saw_deterministic_signal |= saw_deterministic_signal;
    }

    /// A consumer asked for screen state. Refreshes the idle timer and, in
    /// any mode but `off`, turns Tier B on.
    pub fn note_consumer(&mut self, now: Instant) {
        self.last_consumer_touch = now;
        if self.mode != ScreenTracking::Off {
            self.enable(EnableReason::ConsumerRequest);
        }
    }

    /// Apply the §4.5 enable and disable rules. Idempotent; call it as
    /// often as convenient.
    pub fn evaluate(&mut self, now: Instant) {
        if self.mode != ScreenTracking::Adaptive {
            return;
        }
        if self.enabled {
            if self.should_disable(now) {
                self.enabled = false;
                self.enable_reason = None;
            }
            return;
        }
        if self.alt_screen {
            self.enable(EnableReason::AltScreen);
        } else if !self.saw_deterministic_signal
            && now.duration_since(self.started_at) >= self.no_signal_grace
        {
            self.enable(EnableReason::NoDeterministicSignal);
        }
    }

    fn enable(&mut self, reason: EnableReason) {
        if !self.enabled {
            self.enabled = true;
            self.enable_reason = Some(reason);
        }
    }

    /// §4.5: "disable again after `screen_tracking_idle_disable_secs` with
    /// no screen-state consumer and alt-screen off."
    ///
    /// The extra `saw_deterministic_signal` condition is not decoration.
    /// For a session that has never produced bracketed paste or OSC 133,
    /// the T3 cursor signal (§8.6) is the *only* remaining prompt
    /// evidence, so the parser still has a consumer even when no agent has
    /// called `get_screen_state`. Disabling there would silently break
    /// prompt detection for exactly the programs §8.6 exists to serve —
    /// and the enable rule would immediately re-fire, thrashing.
    fn should_disable(&self, now: Instant) -> bool {
        !self.alt_screen
            && self.saw_deterministic_signal
            && now.duration_since(self.last_consumer_touch) >= self.idle_disable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_secs(300);
    const GRACE: Duration = Duration::from_secs(3);

    fn policy(mode: ScreenTracking, t0: Instant) -> TrackingPolicy {
        TrackingPolicy::new(mode, IDLE, GRACE, t0)
    }

    #[test]
    fn the_mode_enum_round_trips_its_spec_spellings() {
        for m in [
            ScreenTracking::Off,
            ScreenTracking::Adaptive,
            ScreenTracking::On,
        ] {
            assert_eq!(ScreenTracking::parse(m.as_str()), Some(m));
        }
        assert_eq!(ScreenTracking::default().as_str(), "adaptive");
    }

    #[test]
    fn an_unknown_mode_is_rejected_rather_than_defaulted() {
        // The negative half of `parse`, and the whole reason it returns an
        // `Option`: falling back to `adaptive` would turn a typo in the
        // config file into the default silently, instead of the schema
        // error the operator needs to see.
        for s in ["", "Off", "ADAPTIVE", "true", "auto", "adaptive "] {
            assert_eq!(ScreenTracking::parse(s), None, "{s:?} was accepted");
        }
    }

    /// A line-oriented shell: bracketed paste shows up immediately and the
    /// agent never asks for a screen. Tier B must stay off forever — this
    /// is the case §4.2a says would cost more than a core at scale.
    #[test]
    fn adaptive_stays_off_for_a_plain_line_oriented_session() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, true);
        for secs in [0, 1, 3, 10, 600, 86_400] {
            p.evaluate(t0 + Duration::from_secs(secs));
            assert!(!p.enabled(), "enabled itself at t+{secs}s with no trigger");
        }
    }

    #[test]
    fn adaptive_enables_on_alt_screen() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, true);
        p.evaluate(t0);
        assert!(!p.enabled());

        p.observe(true, true);
        p.evaluate(t0 + Duration::from_millis(1));
        assert!(p.enabled());
        assert_eq!(p.enable_reason(), Some(EnableReason::AltScreen));
    }

    #[test]
    fn adaptive_enables_on_a_consumer_request() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, true);
        p.evaluate(t0);
        assert!(!p.enabled());

        p.note_consumer(t0 + Duration::from_secs(1));
        assert!(p.enabled());
        assert_eq!(p.enable_reason(), Some(EnableReason::ConsumerRequest));
    }

    #[test]
    fn adaptive_enables_after_the_grace_window_with_no_deterministic_signal() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, false);

        p.evaluate(t0 + Duration::from_millis(2999));
        assert!(!p.enabled(), "fired before the 3 s grace window elapsed");

        p.evaluate(t0 + Duration::from_millis(3000));
        assert!(p.enabled());
        assert_eq!(p.enable_reason(), Some(EnableReason::NoDeterministicSignal));
    }

    #[test]
    fn a_deterministic_signal_inside_the_grace_window_cancels_that_trigger() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, false);
        p.evaluate(t0 + Duration::from_secs(2));
        assert!(!p.enabled());

        p.observe(false, true);
        p.evaluate(t0 + Duration::from_secs(60));
        assert!(!p.enabled(), "the signal arrived, so the trigger is dead");
    }

    #[test]
    fn adaptive_disables_after_the_idle_window_with_no_consumer() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, true);
        p.note_consumer(t0);
        assert!(p.enabled());

        p.evaluate(t0 + IDLE - Duration::from_millis(1));
        assert!(
            p.enabled(),
            "disabled early — hysteresis is the whole point"
        );

        p.evaluate(t0 + IDLE);
        assert!(!p.enabled());
        assert_eq!(p.enable_reason(), None);
    }

    #[test]
    fn a_consumer_touch_restarts_the_idle_window() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, true);
        p.note_consumer(t0);
        p.note_consumer(t0 + IDLE - Duration::from_secs(1));
        p.evaluate(t0 + IDLE + Duration::from_secs(1));
        assert!(
            p.enabled(),
            "the second touch should have moved the deadline"
        );
    }

    #[test]
    fn alt_screen_holds_tier_b_on_past_the_idle_window() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(true, true);
        p.evaluate(t0);
        assert!(p.enabled());

        p.evaluate(t0 + IDLE * 10);
        assert!(p.enabled(), "a TUI is still on screen; nothing to disable");

        p.observe(false, true);
        p.evaluate(t0 + IDLE * 10);
        assert!(!p.enabled(), "TUI exited and the idle window had elapsed");
    }

    #[test]
    fn a_session_with_no_deterministic_signal_is_never_idle_disabled() {
        // dash: the cursor heuristic is the only prompt evidence there is,
        // so Tier B has a consumer even with no get_screen_state calls.
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Adaptive, t0);
        p.observe(false, false);
        p.evaluate(t0 + GRACE);
        assert!(p.enabled());

        p.evaluate(t0 + GRACE + IDLE * 10);
        assert!(p.enabled());
    }

    #[test]
    fn off_never_enables_for_any_trigger() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::Off, t0);
        p.observe(true, false);
        p.evaluate(t0 + GRACE * 100);
        assert!(!p.enabled());
        p.note_consumer(t0 + GRACE * 100);
        assert!(!p.enabled(), "`off` must mean off, including for the agent");
    }

    #[test]
    fn on_is_enabled_from_the_first_instant_and_never_disables() {
        let t0 = Instant::now();
        let mut p = policy(ScreenTracking::On, t0);
        assert!(p.enabled());
        assert_eq!(p.enable_reason(), Some(EnableReason::Forced));
        p.observe(false, true);
        p.evaluate(t0 + IDLE * 100);
        assert!(p.enabled());
    }
}
