//! §4.5.1 — Holdfast answers Primary Device Attributes and no other
//! terminal query.
//!
//! A PTY master is not a terminal, so a program that *waits* on a query
//! stalls until its own timeout. Measured (2026-08-13, `alpine:edge`):
//! fish 4.8.1 takes **10.04 s** to reach its first prompt with no reply,
//! **10.04 s** with XTGETTCAP, OSC 11, kitty-keyboard and XTVERSION all
//! answered and DA1 withheld, and **0.02 s** with DA1 alone. The probes
//! are batched behind Primary DA as a fence and resolve when it does, so
//! DA1 is not one stall among four — it is the query.
//!
//! **Nothing in this module knows what a `Session` is, and that is the
//! enforcement of REQ-TS-009's three governance clauses rather than a
//! stylistic preference.** `QueryResponder` returns the bytes owed and
//! writes nothing; the reader thread writes them through
//! `PtyBackend::write`. A `send_input` audit record (§9.4) is written in
//! `mcp::tools`, and a command-history entry is folded by the detector
//! from OSC 133 markers — neither is reachable from here, and neither is
//! reachable from the reader-loop block that calls `feed`. An assertion
//! that "some log does not contain a reply" passes trivially in a build
//! where no log was ever opened, which §9.2 names by hand as the trap, so
//! the audit half is checked structurally and stated here instead.

use std::time::{Duration, Instant};

/// One admitted query. §4.5.1's set has exactly one member and
/// `the_answered_set_has_exactly_one_member_and_it_is_da1` is what keeps
/// it that way: a query added here without being added to §4.5.1 fails
/// that test (REQ-TS-010).
struct Query {
    /// For assertion messages and for the REQ-TS-010 set assertion, which
    /// is the only reader outside `cfg(test)` — the field is the set's
    /// identity, not a debugging convenience.
    #[allow(dead_code)]
    name: &'static str,
    /// Every accepted spelling. DA1's parameter is optional and defaults
    /// to 0; **fish sends the explicit form**, and a matcher accepting
    /// only `\x1b[c` measured 10.04 s — indistinguishable from answering
    /// nothing (REQ-TS-007).
    spellings: &'static [&'static [u8]],
    /// The reply, byte-exact. `\x1b[?6c` claims VT102 and **nothing
    /// else**: every optional parameter is a capability claim a shell
    /// will then use, and Holdfast has no sixel, no ReGIS, no DEC locator.
    reply: &'static [u8],
}

const ANSWERED: [Query; 1] = [Query {
    name: "DA1",
    spellings: &[b"\x1b[c", b"\x1b[0c"],
    reply: b"\x1b[?6c",
}];

/// §4.2 `terminal_query_replies_per_min`. A child that prints query bytes
/// — `cat` of a binary file will do it — gets a reply typed into its own
/// input. Real terminals behave identically and §4.5.1 declines to invent
/// a guard; what it requires is that the damage be **bounded**, so past
/// the limit Holdfast is silent rather than amplifying a file into megabytes
/// of injected input.
pub const DEFAULT_TERMINAL_QUERY_REPLIES_PER_MIN: u32 = 60;

/// The window the limit is counted over. Fixed and non-sliding: the
/// counter resets when the window rolls, which is what lets the test
/// assert the limit **at its value** rather than as "bounded".
const REPLY_WINDOW: Duration = Duration::from_secs(60);

/// The longest prefix of any spelling that could still be completed by a
/// later chunk. `\x1b[0c` is 4 bytes, so 3 is the most that can be
/// pending; the constant is derived rather than written so a longer
/// spelling cannot outgrow it.
fn max_carry() -> usize {
    ANSWERED
        .iter()
        .flat_map(|q| q.spellings.iter())
        .map(|s| s.len() - 1)
        .max()
        .unwrap_or(0)
}

/// Scans the child's output for admitted queries and emits their replies.
///
/// **This type never writes anything itself.** It returns the bytes to
/// write and the caller does it, because the caller is the reader thread
/// and the only correct write path is `PtyBackend::write` — *not*
/// `Session::write_input`, which stamps `last_activity` and is the agent's
/// path (REQ-TS-009).
pub struct QueryResponder {
    enabled: bool,
    limit: u32,
    /// Replies emitted inside the current window.
    sent: u32,
    window_started: Instant,
    /// Trailing bytes of the previous chunk that are a proper prefix of
    /// some spelling. The reader reads 8192 bytes at a time and a query
    /// straddling that boundary is silence — the same failure as the
    /// wrong spelling, arriving by a different route.
    carry: Vec<u8>,
}

impl QueryResponder {
    pub fn new(enabled: bool, limit: u32) -> Self {
        Self {
            enabled,
            limit,
            sent: 0,
            window_started: Instant::now(),
            carry: Vec::new(),
        }
    }

    /// Replies owed for `chunk`, in order. Empty when `terminal_queries`
    /// is off, when the chunk carries no admitted query, or when the
    /// window's budget is spent.
    pub fn feed(&mut self, chunk: &[u8], now: Instant) -> Vec<&'static [u8]> {
        if !self.enabled {
            // Nothing is scanned and nothing is carried: `false` must be
            // indistinguishable from a build with no reply path at all.
            return Vec::new();
        }
        if now.duration_since(self.window_started) >= REPLY_WINDOW {
            self.window_started = now;
            self.sent = 0;
        }

        let mut hay = std::mem::take(&mut self.carry);
        hay.extend_from_slice(chunk);

        let mut out = Vec::new();
        let mut i = 0usize;
        'scan: while i < hay.len() {
            for q in &ANSWERED {
                for spelling in q.spellings {
                    if hay[i..].starts_with(spelling) {
                        if self.sent < self.limit {
                            self.sent += 1;
                            out.push(q.reply);
                        }
                        // Consume it either way. A suppressed reply must
                        // not leave the query to be re-matched.
                        i += spelling.len();
                        continue 'scan;
                    }
                }
            }
            i += 1;
        }

        // Re-carry only a trailing proper prefix of some spelling.
        let tail_start = hay.len().saturating_sub(max_carry());
        for start in tail_start..hay.len() {
            let tail = &hay[start..];
            if ANSWERED.iter().any(|q| {
                q.spellings
                    .iter()
                    .any(|s| s.len() > tail.len() && s.starts_with(tail))
            }) {
                self.carry = tail.to_vec();
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DA1_REPLY: &[u8] = b"\x1b[?6c";

    fn responder() -> QueryResponder {
        QueryResponder::new(true, DEFAULT_TERMINAL_QUERY_REPLIES_PER_MIN)
    }

    #[test]
    fn both_da1_spellings_are_answered_byte_exactly() {
        // `assert_eq!` on the whole vector, never `contains`: a reply
        // carrying optional parameters (`\x1b[?6;4c`) is a capability
        // claim Holdfast cannot honour, and `contains` would accept it.
        assert_eq!(responder().feed(b"\x1b[c", Instant::now()), vec![DA1_REPLY]);
        assert_eq!(
            responder().feed(b"\x1b[0c", Instant::now()),
            vec![DA1_REPLY]
        );
        // The parameterised form embedded in ordinary output, which is how
        // fish actually delivers it — wrapped in the alternate screen.
        assert_eq!(
            responder().feed(b"\x1b[?1049h\x1b[0c\x1b[?1049l", Instant::now()),
            vec![DA1_REPLY]
        );
    }

    #[test]
    fn every_declined_query_produces_no_write_at_all() {
        // **The load-bearing half.** `both_da1_spellings_are_answered…`
        // passes identically against an implementation that answers
        // everything, which is the outcome §4.5.1's admission rule exists
        // to prevent.
        let declined: [(&str, &[u8]); 8] = [
            ("XTGETTCAP", b"\x1bP+q696e646e\x1b\\"),
            ("OSC 10 foreground", b"\x1b]10;?\x07"),
            ("OSC 11 background", b"\x1b]11;?\x07"),
            ("OSC 12 cursor", b"\x1b]12;?\x07"),
            ("kitty keyboard", b"\x1b[?u"),
            ("XTVERSION", b"\x1b[>0q"),
            ("DSR-5", b"\x1b[5n"),
            // §4.5.1's worked example of the rule saying no: a fabricated
            // cursor position is worse than silence.
            ("CPR", b"\x1b[6n"),
        ];
        for (name, bytes) in declined {
            let out = responder().feed(bytes, Instant::now());
            assert!(
                out.is_empty(),
                "{name} was answered with {out:?}; §4.5.1 admits DA1 alone"
            );
        }
    }

    #[test]
    fn the_answered_set_has_exactly_one_member_and_it_is_da1() {
        // REQ-TS-010's enforcement point. Adding a query to the
        // implementation reddens this until §4.5.1 is amended too.
        assert_eq!(ANSWERED.len(), 1, "§4.5.1's set has exactly one member");
        assert_eq!(ANSWERED[0].name, "DA1");
        assert_eq!(ANSWERED[0].reply, DA1_REPLY);
        assert_eq!(
            ANSWERED[0].spellings,
            &[b"\x1b[c".as_slice(), b"\x1b[0c".as_slice()],
            "both spellings, and no third: `CSI 0 c` is the form fish sends"
        );
    }

    #[test]
    fn a_query_split_across_two_chunks_is_still_answered() {
        // The reader reads 8192 bytes at a time; a query on the boundary
        // is silence without the carry — the same failure as the wrong
        // spelling, arriving by a different route.
        let mut r = responder();
        assert!(r.feed(b"\x1b[", Instant::now()).is_empty());
        assert_eq!(r.feed(b"0c", Instant::now()), vec![DA1_REPLY]);

        // And the negative that separates a carry from a matcher that
        // simply answers any chunk starting with `0c`: a split that does
        // *not* reconstitute a query stays silent.
        let mut r = responder();
        assert!(r.feed(b"noise\x1b[", Instant::now()).is_empty());
        assert!(r.feed(b"1;1H", Instant::now()).is_empty());
    }

    #[test]
    fn the_reply_budget_is_sixty_per_minute_asserted_at_its_value() {
        let now = Instant::now();
        let mut r = responder();
        let flood: Vec<u8> = std::iter::repeat_n(b"\x1b[0c".as_slice(), 120)
            .flatten()
            .copied()
            .collect();
        assert_eq!(
            r.feed(&flood, now).len(),
            60,
            "the limit is asserted at its value, not as `bounded`"
        );

        // The negative that separates the limiter from a broken scanner:
        // exactly at the ceiling, every query is answered.
        let mut r = responder();
        let exact: Vec<u8> = std::iter::repeat_n(b"\x1b[0c".as_slice(), 60)
            .flatten()
            .copied()
            .collect();
        assert_eq!(
            r.feed(&exact, now).len(),
            60,
            "a limiter that drops replies below the ceiling"
        );
    }

    #[test]
    fn the_window_rolls_and_the_budget_returns() {
        // Pairs with the budget test, which alone is satisfied by a
        // responder that stops for ever.
        let now = Instant::now();
        let mut r = responder();
        let flood: Vec<u8> = std::iter::repeat_n(b"\x1b[0c".as_slice(), 120)
            .flatten()
            .copied()
            .collect();
        assert_eq!(r.feed(&flood, now).len(), 60);
        assert!(
            r.feed(b"\x1b[0c", now).is_empty(),
            "the budget was not spent"
        );
        assert_eq!(
            r.feed(b"\x1b[0c", now + Duration::from_secs(61)),
            vec![DA1_REPLY],
            "the window never rolled"
        );
    }

    #[test]
    fn terminal_queries_false_answers_nothing_and_true_answers() {
        // One test, both arms: the positive is what stops the negative
        // from passing against a build where the reply path was never
        // written at all.
        assert!(QueryResponder::new(false, 60)
            .feed(b"\x1b[0c", Instant::now())
            .is_empty());
        assert_eq!(
            QueryResponder::new(true, 60).feed(b"\x1b[0c", Instant::now()),
            vec![DA1_REPLY]
        );
    }

    #[test]
    fn a_disabled_responder_carries_nothing_across_chunks() {
        // `false` must be indistinguishable from a build with no reply
        // path: a disabled responder that still accumulated carry would
        // answer the first query after being enabled.
        let mut r = QueryResponder::new(false, 60);
        assert!(r.feed(b"\x1b[", Instant::now()).is_empty());
        assert!(r.feed(b"0c", Instant::now()).is_empty());
    }
}
