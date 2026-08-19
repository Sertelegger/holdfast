//! Minimal Tier-A byte scan: just enough of spec §4.5's mode table to
//! drive the adaptive Tier-B triggers.
//!
//! **This is a stand-in.** Milestone 0.0.2 ships the full Tier-A scanner
//! at [`crate::detect::scanner::ModeScanner`] (bracketed paste, alt
//! screen, OSC 133, window title), whose `modes()` already answers both
//! questions:
//! `alt_screen <- modes.alt_screen`,
//! `saw_deterministic_signal <- modes.saw_bracketed_paste || modes.saw_osc133`.
//! It is not used here because it sits behind the session's `detector`
//! mutex and reaching it from the tracker would add a lock to the
//! `screen -> buffer` order in the same change that establishes it. To
//! retire this module, delete it and feed
//! [`TrackingPolicy::observe`](super::tracking::TrackingPolicy::observe)
//! from `ModeScanner` in the reader thread instead — the policy's input
//! contract does not change, which is why the swap is mechanical.

/// Longest sequence we look for is 8 bytes (`\x1b[?1049h`), so carrying
/// 8 bytes between chunks is enough for any split to be reassembled.
const CARRY: usize = 8;

const ALT_ON: &[u8] = b"\x1b[?1049h";
const ALT_OFF: &[u8] = b"\x1b[?1049l";
const BRACKETED_PASTE_ON: &[u8] = b"\x1b[?2004h";
const BRACKETED_PASTE_OFF: &[u8] = b"\x1b[?2004l";
const OSC_133: &[u8] = b"\x1b]133;";

fn last_index_of(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Watches the byte stream for the two facts the adaptive policy needs:
/// whether the alternate screen is currently active, and whether any
/// deterministic prompt signal has ever been seen.
#[derive(Debug, Default)]
pub struct TierAProbe {
    carry: Vec<u8>,
    alt_screen: bool,
    saw_deterministic_signal: bool,
}

impl TierAProbe {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn alt_screen(&self) -> bool {
        self.alt_screen
    }

    pub fn saw_deterministic_signal(&self) -> bool {
        self.saw_deterministic_signal
    }

    /// Scan one PTY chunk. Safe across chunk boundaries: the trailing
    /// [`CARRY`] bytes of the previous chunk are prepended before the
    /// search, so `\x1b[?20` + `04h` is still recognised.
    pub fn scan(&mut self, chunk: &[u8]) {
        let mut hay = Vec::with_capacity(self.carry.len() + chunk.len());
        hay.extend_from_slice(&self.carry);
        hay.extend_from_slice(chunk);

        // The carry holds only the newest bytes, so positions in `hay`
        // are in stream order and the last occurrence is the newest.
        // Re-seeing a sequence that lay wholly inside the carry is
        // harmless: both effects are idempotent.
        match (last_index_of(&hay, ALT_ON), last_index_of(&hay, ALT_OFF)) {
            (Some(on), Some(off)) => self.alt_screen = on > off,
            (Some(_), None) => self.alt_screen = true,
            (None, Some(_)) => self.alt_screen = false,
            (None, None) => {}
        }

        if !self.saw_deterministic_signal {
            self.saw_deterministic_signal = [BRACKETED_PASTE_ON, BRACKETED_PASTE_OFF, OSC_133]
                .iter()
                .any(|n| last_index_of(&hay, n).is_some());
        }

        let keep = hay.len().min(CARRY);
        self.carry = hay[hay.len() - keep..].to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_screen_toggles() {
        let mut p = TierAProbe::new();
        assert!(!p.alt_screen());
        p.scan(b"\x1b[?1049h");
        assert!(p.alt_screen());
        p.scan(b"\x1b[?1049l");
        assert!(!p.alt_screen());
    }

    #[test]
    fn alt_screen_sequence_split_across_chunks_is_seen() {
        // A scanner without a carry would miss this entirely, which would
        // silently disable the alt-screen Tier-B trigger for any TUI whose
        // enter sequence happens to land on a read boundary.
        let mut p = TierAProbe::new();
        p.scan(b"before\x1b[?10");
        assert!(!p.alt_screen(), "half a sequence must not toggle anything");
        p.scan(b"49hafter");
        assert!(p.alt_screen());
    }

    #[test]
    fn last_occurrence_in_a_chunk_wins() {
        let mut p = TierAProbe::new();
        p.scan(b"\x1b[?1049h middle \x1b[?1049l tail");
        assert!(!p.alt_screen());
        p.scan(b"\x1b[?1049l x \x1b[?1049h");
        assert!(p.alt_screen());
    }

    #[test]
    fn the_last_of_several_occurrences_in_one_chunk_wins() {
        // Two `l`s straddling an `h`. `last_occurrence_in_a_chunk_wins`
        // above carries one of each per haystack, where the first and the
        // last index coincide and `position` would do; here they do not,
        // and taking the first reads this as on-after-off and leaves the
        // alternate screen stuck on.
        let mut p = TierAProbe::new();
        p.scan(b"\x1b[?1049l a \x1b[?1049h b \x1b[?1049l");
        assert!(!p.alt_screen());
    }

    #[test]
    fn the_screen_turns_off_when_the_entry_is_long_out_of_the_carry() {
        // The ordinary case, and the one the other alt-screen tests all
        // miss: a TUI enters, paints for a while, then exits. By then the
        // entry sequence is far outside the carry, so the haystack holds
        // an `l` and no `h` — an arm nothing else here reaches, because
        // every other test keeps the entry alive in the 8-byte carry.
        let mut p = TierAProbe::new();
        p.scan(b"\x1b[?1049h");
        p.scan(&[b'.'; 4096]);
        assert!(p.alt_screen());
        p.scan(b"\x1b[?1049l");
        assert!(!p.alt_screen());
    }

    #[test]
    fn bracketed_paste_latches_the_deterministic_signal() {
        let mut p = TierAProbe::new();
        assert!(!p.saw_deterministic_signal());
        p.scan(b"user@host$ \x1b[?2004h");
        assert!(p.saw_deterministic_signal());
        // The latch never clears: readline turning bracketed paste off
        // while a command runs does not mean the signal is unavailable.
        p.scan(b"\x1b[?2004l");
        assert!(p.saw_deterministic_signal());
        // …and it survives chunks with no signal in them at all. Without
        // this the "latch" claim is untested: `\x1b[?2004l` is itself in
        // the deterministic set, so an implementation that *assigns*
        // rather than latches still passes the assertion above. Two
        // filler chunks are needed and not one: the first only flushes
        // the signal out of the 8-byte carry, so the second is the first
        // scan whose haystack is signal-free.
        p.scan(&[b'x'; CARRY * 2]);
        p.scan(&[b'y'; CARRY * 2]);
        assert!(p.saw_deterministic_signal());
    }

    #[test]
    fn osc_133_latches_the_deterministic_signal() {
        let mut p = TierAProbe::new();
        p.scan(b"\x1b]133;A\x07$ ");
        assert!(p.saw_deterministic_signal());
    }

    #[test]
    fn plain_output_latches_nothing() {
        let mut p = TierAProbe::new();
        for chunk in [
            &b"Compiling holdfast-core v0.0.1\n"[..],
            &b"\x1b[32m    Finished\x1b[0m dev profile\n"[..],
            &b"\x1b[?25l spinner \x1b[?25h\n"[..],
        ] {
            p.scan(chunk);
        }
        assert!(!p.alt_screen());
        assert!(
            !p.saw_deterministic_signal(),
            "colour codes and cursor-visibility toggles are not prompt signals"
        );
    }

    #[test]
    fn truncated_variants_do_not_toggle() {
        let mut p = TierAProbe::new();
        // Missing the final byte, and a near-miss parameter.
        p.scan(b"\x1b[?1049");
        p.scan(b"\x1b[?104h");
        p.scan(b"\x1b[?2004");
        assert!(!p.alt_screen());
        assert!(!p.saw_deterministic_signal());
    }

    #[test]
    fn carry_is_bounded() {
        let mut p = TierAProbe::new();
        p.scan(&vec![b'x'; 100_000]);
        assert!(p.carry.len() <= CARRY);
    }
}
