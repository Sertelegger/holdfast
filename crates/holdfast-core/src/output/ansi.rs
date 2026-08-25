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
/// **[`strip`] is not enough on its own, and the gap is deliberate on
/// both sides.** `strip` serves a terminal *stream*, so it keeps `\t`,
/// `\n`, `\r` and `\x08` — "layout survives" is the right rule there and
/// exactly the wrong one here. A `\r` rewrites the line from its start, a
/// `\x08` rubs out the character before it, and a `\n` forges a second
/// line of whatever the surrounding diagnostic looks like. On a field
/// that exists so an operator can tell `ssh prod-01` from `ssh prod-01 -o
/// ProxyCommand=nc 127.0.0.1 2222`, any of the three hands the difference
/// back to whoever wrote the string (GH #45).
///
/// So: escape sequences go through [`strip`], then **every remaining
/// control character is dropped**, then the directional-formatting and
/// zero-width characters are dropped too. The second group is not
/// paranoia by association — U+202E reverses the rendering of everything
/// after it, which is the same attack in a different alphabet, and a
/// zero-width space breaks a word an operator is scanning for.
///
/// **Dropped rather than replaced with a marker.** A visible substitute
/// invites the question of whether the substitute itself can be forged,
/// and the bytes around a control character stay visible either way — an
/// agent that inserts `\r` gets a longer, stranger-looking line, which is
/// the honest outcome.
///
/// **What this does not do**, so nothing downstream reads it as more: it
/// is not a "safe to print anywhere" guarantee. A homoglyph is still a
/// homoglyph, `rn` still looks like `m` in some fonts, and a very long
/// line still scrolls. It removes the characters that let a string
/// *rewrite* what is already on screen; it does not make the remaining
/// text trustworthy.
pub fn one_line_for_display(s: &str) -> String {
    let stripped = strip(s.as_bytes());
    String::from_utf8_lossy(&stripped)
        .chars()
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
            "ssh prod-01 -o ProxyCommand=nc 1 2ssh prod-01"
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
