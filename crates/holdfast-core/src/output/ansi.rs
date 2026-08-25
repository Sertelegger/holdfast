//! ANSI/VT100 escape-sequence stripping, with the boundary rule from
//! spec §4.1.
//!
//! A sequence can straddle two PTY chunks: `\x1b[3` arrives, then `1m`.
//! The stripper is therefore a resumable state machine over absolute byte
//! offsets, and it reports where an unfinished sequence began so the read
//! path can stop short of it while the child is still alive.

/// Whether the caller wants escapes removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnsiMode {
    /// Escape sequences removed; clean text (default).
    #[default]
    Strip,
    /// Bytes pass through untouched. Redaction still runs (§5.2).
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not inside a sequence.
    Ground,
    /// Saw `\x1b`.
    Esc,
    /// Saw `\x1b[`: parameters, then a final byte in `0x40..=0x7e`.
    Csi,
    /// Saw `\x1b]`: runs until BEL or ST.
    Osc,
    /// Saw ESC inside an OSC; `\` completes the ST.
    OscEsc,
    /// DCS / SOS / PM / APC: runs until ST.
    Str,
    /// Saw ESC inside a string sequence.
    StrEsc,
    /// Charset designator `\x1b(`, `\x1b)`, `\x1b*`, `\x1b+`: one more byte.
    Charset,
}

/// A resumable ANSI stripper.
#[derive(Debug)]
pub struct AnsiStripper {
    state: State,
    /// Absolute offset of the `\x1b` that opened the sequence in flight.
    seq_start: u64,
}

impl Default for AnsiStripper {
    fn default() -> Self {
        Self::new()
    }
}

impl AnsiStripper {
    pub fn new() -> Self {
        Self {
            state: State::Ground,
            seq_start: 0,
        }
    }

    /// Absolute offset where the sequence currently in flight started, or
    /// `None` when the stripper is between sequences.
    pub fn pending_start(&self) -> Option<u64> {
        (self.state != State::Ground).then_some(self.seq_start)
    }

    /// Feed one byte at absolute offset `offset`. Returns the byte to
    /// emit, or `None` when it was consumed by an escape sequence.
    ///
    /// A byte that cannot continue the sequence in flight is treated as
    /// malformed: the accumulated sequence is dropped and the byte is
    /// reconsidered from `Ground` (spec §4.1, mid-buffer rule).
    pub fn feed(&mut self, offset: u64, byte: u8) -> Option<u8> {
        loop {
            match self.state {
                State::Ground => {
                    if byte == 0x1b {
                        self.state = State::Esc;
                        self.seq_start = offset;
                        return None;
                    }
                    // Layout survives; every other C0 control is dropped.
                    // A stray BEL or NUL is not text, and after a
                    // malformed introducer it is the tail of a sequence
                    // that was never going to complete (§4.1).
                    if byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r' | 0x08) {
                        return None;
                    }
                    return Some(byte);
                }
                State::Esc => {
                    return match byte {
                        b'[' => {
                            self.state = State::Csi;
                            None
                        }
                        b']' => {
                            self.state = State::Osc;
                            None
                        }
                        b'P' | b'X' | b'^' | b'_' => {
                            self.state = State::Str;
                            None
                        }
                        b'(' | b')' | b'*' | b'+' => {
                            self.state = State::Charset;
                            None
                        }
                        // Intermediate byte: still inside the sequence.
                        0x20..=0x2f => None,
                        // Final byte of a two-byte escape, e.g. `\x1bM`.
                        0x30..=0x7e => {
                            self.state = State::Ground;
                            None
                        }
                        _ => {
                            self.state = State::Ground;
                            continue;
                        }
                    };
                }
                State::Csi => {
                    return match byte {
                        // Parameter or intermediate bytes.
                        0x20..=0x3f => None,
                        // Final byte.
                        0x40..=0x7e => {
                            self.state = State::Ground;
                            None
                        }
                        _ => {
                            self.state = State::Ground;
                            continue;
                        }
                    };
                }
                State::Osc => {
                    return match byte {
                        0x07 => {
                            self.state = State::Ground;
                            None
                        }
                        0x1b => {
                            self.state = State::OscEsc;
                            None
                        }
                        // A control byte other than BEL/ESC cannot appear
                        // in an OSC string: the sequence is malformed.
                        0x00..=0x06 | 0x08..=0x1a | 0x1c..=0x1f => {
                            self.state = State::Ground;
                            continue;
                        }
                        _ => None,
                    };
                }
                State::OscEsc => {
                    if byte == b'\\' {
                        self.state = State::Ground;
                        return None;
                    }
                    // Not an ST after all; the ESC opened something new.
                    self.state = State::Ground;
                    continue;
                }
                State::Str => {
                    if byte == 0x1b {
                        self.state = State::StrEsc;
                    }
                    return None;
                }
                State::StrEsc => {
                    self.state = if byte == b'\\' {
                        State::Ground
                    } else {
                        State::Str
                    };
                    return None;
                }
                State::Charset => {
                    self.state = State::Ground;
                    return None;
                }
            }
        }
    }
}

/// Strip escapes from a standalone slice. Convenience for callers that
/// have no offsets to track (audit-log strings, `prompt.last_line`).
pub fn strip(bytes: &[u8]) -> Vec<u8> {
    let mut stripper = AnsiStripper::new();
    let mut out = Vec::with_capacity(bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        if let Some(e) = stripper.feed(i as u64, *b) {
            out.push(e);
        }
    }
    out
}

/// Reduce a string to something that renders as **one line of plain
/// text**, for a field whose whole purpose is to be read by a human
/// making a decision.
///
/// **This deliberately does *not* use [`strip`], and an earlier revision
/// that did was wrong in the one direction that matters.** `strip` is a
/// terminal-stream stripper: it parses sequences and **consumes their
/// payloads**, which is correct for a stream and catastrophic here.
/// Driven, before the change:
///
/// ```text
/// "ssh prod-01\x1b]0; -o ProxyCommand=nc 1.2.3.4 22\x07"  ->  "ssh prod-01"
/// ```
///
/// That is a forged **short** line — the operator is shown a command line
/// with an argument *missing*, which is layer D inverted: they approve a
/// line that is not the line. OSC, DCS and APC all do it, terminated or
/// not. `strip` is not at fault; it is answering a different question.
///
/// **The rule here is simpler and has no payload to lose: keep every
/// character that cannot *do* anything, drop every character that can.**
/// No state machine, no sequence grammar. An escape sequence loses its
/// `\x1b` and what is left — `[2K`, `]0; -o ProxyCommand=…` — stays on
/// screen as the visible nonsense it is. That is the intended outcome:
/// **a longer, stranger line, never a shorter innocent one.**
///
/// What is dropped:
///
/// * **Every control character** (`char::is_control`, so C0, DEL and C1).
///   `\x1b` is one of them, which is what defuses every escape sequence at
///   a stroke. `\r` rewrites the line from its start, `\x08` rubs out the
///   character before it, `\n` forges a second line of whatever the
///   surrounding diagnostic looks like, and `\t` moves the cursor to a
///   column of the agent's choosing. `strip` *keeps* those four, because
///   "layout survives" is the right rule for a stream and exactly the
///   wrong one for a line somebody is reading to make a decision.
/// * **The directional-formatting and zero-width characters.** Not
///   paranoia by association: U+202E reverses the rendering of everything
///   after it, which is the same attack in a different alphabet, and a
///   zero-width space breaks a word an operator is scanning for.
///
/// **Dropped rather than replaced with a marker.** A visible substitute
/// invites the question of whether the substitute itself can be forged,
/// and the text around a control character stays visible either way.
///
/// **What this does not do**, so nothing downstream reads it as more: it
/// is not a "safe to print anywhere" guarantee. A homoglyph is still a
/// homoglyph, `rn` still looks like `m` in some fonts, and a very long
/// line still scrolls. It removes a string's power to *rewrite* what is
/// already on screen; it does not make the remaining text trustworthy.
pub fn one_line_for_display(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_directional_or_zero_width(*c))
        .collect()
}

/// The Unicode formatting characters that change how the *rest* of a
/// string renders without contributing anything visible themselves.
///
/// Kept as an explicit list rather than "all of category `Cf`", because
/// `Cf` also contains characters that legitimately appear inside words in
/// several scripts, and this function's job is not to police text.
fn is_directional_or_zero_width(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        | '\u{FEFF}'              // BOM / zero-width no-break space
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_str(s: &str) -> String {
        String::from_utf8(strip(s.as_bytes())).unwrap()
    }

    /// **The characters [`strip`] deliberately keeps are the ones
    /// [`one_line_for_display`] must not**, and the pairing is the whole
    /// content of this row.
    ///
    /// `strip` serves a terminal stream, where `\r`, `\n`, `\t` and `\x08`
    /// are layout. `one_line_for_display` serves a single line a human is
    /// reading to make a decision, where each of them is a way for whoever
    /// wrote the string to change what that human sees (GH #45).
    ///
    /// The string-sequence half of the pairing is
    /// [`a_string_sequence_cannot_forge_a_short_line`], which is the case
    /// that made `one_line_for_display` stop calling `strip` at all.
    #[test]
    fn one_line_for_display_removes_what_strip_keeps() {
        // The pairing first: `strip` keeps all four, on purpose.
        assert_eq!(strip_str("a\rb\nc\td\x08e"), "a\rb\nc\td\x08e");

        // And the display form keeps none of them.
        assert_eq!(one_line_for_display("a\rb\nc\td\x08e"), "abcde");

        // The attack the field exists to defeat: a `\r` that rewrites the
        // line, and a CSI that erases it. Either one makes a hostile
        // command line render as a benign one.
        assert_eq!(
            one_line_for_display("ssh prod-01 -o ProxyCommand=nc 1 2\rssh prod-01"),
            "ssh prod-01 -o ProxyCommand=nc 1 2ssh prod-01",
            "the payload must stay visible; only its power to overwrite is removed"
        );
        assert_eq!(
            one_line_for_display("ssh prod-01 -o ProxyCommand=nc 1 2\x1b[2K\rssh prod-01"),
            "ssh prod-01 -o ProxyCommand=nc 1 2[2Kssh prod-01",
            "the CSI's parameters stay on screen as visible nonsense — only the \
             `\\x1b` that made them a command is gone"
        );
        // A forged second diagnostic line.
        assert!(!one_line_for_display("x\nholdfast attach: all clear").contains('\n'));

        // Directional overrides render the *rest* of the string
        // right-to-left, which is the same attack in another alphabet.
        assert_eq!(
            one_line_for_display("ssh \u{202E}10-dorp\u{202C}"),
            "ssh 10-dorp"
        );
        assert_eq!(one_line_for_display("pro\u{200B}d-01"), "prod-01");

        // Ordinary text is untouched, or the assertions above are
        // satisfied by a function that returns nothing.
        assert_eq!(
            one_line_for_display("ssh user@prod-01 -o ProxyCommand=nc 127.0.0.1 2222"),
            "ssh user@prod-01 -o ProxyCommand=nc 127.0.0.1 2222"
        );
        // Non-ASCII that is not a formatting character survives: an
        // operator's hostname may legitimately carry one.
        assert_eq!(one_line_for_display("ssh naïve-01"), "ssh naïve-01");
    }

    /// **A forged *short* line is the failure this function exists to
    /// prevent, and for one revision it produced them.**
    ///
    /// `one_line_for_display` used to call [`strip`], which parses
    /// OSC/DCS/APC sequences and **consumes their payloads** — correct for
    /// a terminal stream, and here it deleted an argument outright. The
    /// operator was shown `ssh prod-01` for a command line that carried
    /// `-o ProxyCommand=nc 1.2.3.4 22`, which is layer D inverted: they
    /// approve a line that is not the line.
    ///
    /// The four subjects are the ones the re-review drove. Each asserts
    /// the payload is **present**, not merely that the string changed —
    /// "shorter" is exactly the outcome under test, so a
    /// `!contains('\x1b')` row would have passed against the bug.
    #[test]
    fn a_string_sequence_cannot_forge_a_short_line() {
        const PAYLOAD: &str = "-o ProxyCommand=nc 1.2.3.4 22";
        for (label, subject) in [
            (
                "OSC, BEL-terminated",
                format!("ssh prod-01\x1b]0; {PAYLOAD}\x07"),
            ),
            (
                "APC, ST-terminated",
                format!("ssh prod-01\x1b_ {PAYLOAD}\x1b\\"),
            ),
            (
                "DCS, ST-terminated",
                format!("ssh prod-01\x1bP {PAYLOAD}\x1b\\"),
            ),
            ("OSC, unterminated", format!("ssh prod-01\x1b]0; {PAYLOAD}")),
        ] {
            let shown = one_line_for_display(&subject);
            assert!(
                shown.contains(PAYLOAD),
                "{label}: the payload was consumed, so the operator is shown a command \
                 line with an argument missing — a forged *short* line, which is the \
                 whole of what this field defends against. Got {shown:?}"
            );
            assert!(
                !shown.chars().any(char::is_control),
                "{label}: a control character survived: {shown:?}"
            );
            assert!(
                shown.starts_with("ssh prod-01"),
                "{label}: the operator's own text was disturbed: {shown:?}"
            );
        }

        // **The pairing, and it is `strip`'s own behaviour rather than a
        // hypothetical.** Without it a reader cannot tell whether the rows
        // above are asserting a fix or a tautology.
        assert_eq!(
            strip_str(&format!("ssh prod-01\x1b]0; {PAYLOAD}\x07")),
            "ssh prod-01",
            "`strip` consumes the payload — that is correct for a terminal stream and \
             is why `one_line_for_display` does not call it"
        );
    }

    #[test]
    fn sgr_colour_sequences_are_removed() {
        assert_eq!(
            strip_str("\x1b[32mok\x1b[0m done"),
            "ok done",
            "colour codes must not reach the agent as text"
        );
    }

    #[test]
    fn cursor_and_erase_sequences_are_removed() {
        assert_eq!(strip_str("a\x1b[2J\x1b[1;1Hb"), "ab");
        assert_eq!(strip_str("x\x1b[Ky"), "xy");
    }

    #[test]
    fn osc_title_sequences_are_removed_with_either_terminator() {
        assert_eq!(strip_str("\x1b]0;my title\x07rest"), "rest");
        assert_eq!(strip_str("\x1b]0;my title\x1b\\rest"), "rest");
    }

    #[test]
    fn two_byte_and_charset_escapes_are_removed() {
        assert_eq!(strip_str("a\x1bMb"), "ab");
        assert_eq!(strip_str("a\x1b(Bb"), "ab");
    }

    #[test]
    fn newlines_tabs_and_carriage_returns_survive() {
        assert_eq!(
            strip_str("one\r\n\ttwo"),
            "one\r\n\ttwo",
            "the stripper removes escapes, not layout"
        );
    }

    #[test]
    fn a_sequence_split_across_two_feeds_is_still_removed() {
        let mut s = AnsiStripper::new();
        let mut out = Vec::new();
        // First chunk ends mid-CSI.
        for (i, b) in b"ok\x1b[3".iter().enumerate() {
            if let Some(e) = s.feed(i as u64, *b) {
                out.push(e);
            }
        }
        assert_eq!(s.pending_start(), Some(2), "the ESC sits at offset 2");
        // Second chunk completes it.
        for (i, b) in b"1mdone".iter().enumerate() {
            if let Some(e) = s.feed(5 + i as u64, *b) {
                out.push(e);
            }
        }
        assert_eq!(s.pending_start(), None);
        assert_eq!(String::from_utf8(out).unwrap(), "okdone");
    }

    #[test]
    fn pending_start_reports_the_introducer_offset_not_the_read_end() {
        let mut s = AnsiStripper::new();
        for (i, b) in b"abcdef\x1b[".iter().enumerate() {
            s.feed(i as u64, *b);
        }
        assert_eq!(
            s.pending_start(),
            Some(6),
            "the read must be pulled back to the ESC, not to the last byte"
        );
    }

    #[test]
    fn a_malformed_sequence_drops_the_introducer_and_keeps_the_text() {
        // ESC followed by a control byte cannot start any sequence.
        assert_eq!(strip_str("a\x1b\x01b"), "ab");
        // A CSI interrupted by a newline is malformed; the newline and
        // everything after it survive.
        assert_eq!(strip_str("a\x1b[3\nb"), "a\nb");
    }

    #[test]
    fn a_bare_escape_at_the_end_leaves_the_machine_pending() {
        let mut s = AnsiStripper::new();
        assert_eq!(s.feed(0, b'x'), Some(b'x'));
        assert_eq!(s.feed(1, 0x1b), None);
        assert_eq!(s.pending_start(), Some(1));
    }

    #[test]
    fn stray_control_bytes_are_dropped_but_layout_is_not() {
        assert_eq!(strip_str("a\x00b\x07c"), "abc");
        assert_eq!(strip_str("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn ordinary_text_passes_through_byte_for_byte() {
        let text = "   Compiling holdfast-core v0.0.1\n    Finished in 13.72s\n";
        assert_eq!(strip_str(text), text);
    }
}
