//! The T3c cursor-position prompt sub-signal (spec §8.6).
//!
//! Produces `cursor_score` only. The combiner
//! `confidence = quiescent_score * max(pattern_score, cursor_score)`
//! lives in the detector (milestone 0.0.2); this module is the source of
//! the third term and nothing else.

/// Spec §8.6 / §10.2 `prompts.cursor_prompt_chars`.
pub const DEFAULT_PROMPT_CHARS: &[char] = &['$', '%', '#', '>', ')', ':', '❯'];

/// Spec §4.2 `cursor_stable_samples`.
pub const DEFAULT_CURSOR_STABLE_SAMPLES: u32 = 3;

/// What the detector consumes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CursorSignal {
    /// `0.0` whenever the position is not yet stable — §8.6 is explicit
    /// that a cursor still moving mid-redraw says nothing.
    pub score: f32,
    pub row: u16,
    pub col: u16,
    pub stable: bool,
    pub stable_samples: u32,
}

/// Counts how many consecutive samples the cursor has held one position.
#[derive(Debug, Default)]
pub struct CursorStability {
    last: Option<(u16, u16)>,
    samples: u32,
}

impl CursorStability {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.last = None;
        self.samples = 0;
    }

    /// Record one sample.
    ///
    /// §8.6 says "consecutive parser updates"; we also sample on each
    /// observation poll. Without that, a program that paints its prompt in
    /// a single write and then goes quiet would never reach the required
    /// sample count and the signal would be permanently unavailable for
    /// precisely the quiescent-at-a-prompt case it exists to detect. Both
    /// kinds of sample answer the same question — has the cursor moved
    /// since we last looked — and quiescence is a separate gate in the
    /// §8.6 combiner, so counting polls cannot manufacture confidence for
    /// a session that is still producing output.
    pub fn observe(&mut self, pos: (u16, u16)) {
        if self.last == Some(pos) {
            self.samples = self.samples.saturating_add(1);
        } else {
            self.last = Some(pos);
            self.samples = 1;
        }
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    pub fn is_stable(&self, required: u32) -> bool {
        self.samples >= required
    }
}

/// The §8.6 T3c score for the current grid, ignoring stability. Callers
/// gate this on [`CursorStability::is_stable`].
pub fn raw_cursor_score(screen: &vt100::Screen, prompt_chars: &[char]) -> f32 {
    let (row, col) = screen.cursor_position();
    if col == 0 {
        // Start of line: nothing has been typed or prompted yet.
        return 0.0;
    }
    // Text strictly left of the cursor on the cursor's own row.
    let line = screen
        .rows(0, col)
        .nth(usize::from(row))
        .unwrap_or_default();

    // "ends with one of PROMPT_CHARS followed by 0..=1 spaces"
    let candidate = line.strip_suffix(' ').unwrap_or(&line);
    if candidate
        .chars()
        .next_back()
        .is_some_and(|c| prompt_chars.contains(&c))
    {
        return 0.9;
    }
    if line.chars().all(char::is_whitespace) {
        return 0.0;
    }
    // Cursor sits mid-text: ambiguous.
    0.3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen_after(bytes: &[u8]) -> vt100::Parser {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(bytes);
        p
    }

    fn score_of(bytes: &[u8]) -> f32 {
        raw_cursor_score(screen_after(bytes).screen(), DEFAULT_PROMPT_CHARS)
    }

    /// §8.6's first branch.
    ///
    /// **The third case is the one that asserts anything.** Measured by
    /// mutation: deleting the `col == 0` guard fails *no* test, because
    /// `rows(0, 0)` yields an empty line and the whitespace branch below
    /// returns 0.0 anyway — the first two cases here pass for a reason
    /// that has nothing to do with column zero. So the third puts *text*
    /// on the cursor's row and leaves the cursor at column 0, which is
    /// the arrangement where "start of line" and "empty line" stop
    /// coinciding: an implementation reading the whole row scores it 0.9.
    #[test]
    fn column_zero_scores_nothing() {
        assert_eq!(score_of(b""), 0.0);
        assert_eq!(score_of(b"finished\r\n"), 0.0);
        assert_eq!(score_of(b"\x1b[1;1H$ \x1b[1;1H"), 0.0);
    }

    /// §8.6 reads *"`line` = `screen.line(row)` up to `col`"*, and that
    /// clause needs its own fixture: in every other test here the cursor
    /// sits at the end of its row, so the text left of it and the whole
    /// row are the same string and an implementation that ignored `col`
    /// would pass all of them.
    #[test]
    fn only_the_text_left_of_the_cursor_counts() {
        // Row reads `abc$ `; the cursor is parked at column 2, so what is
        // left of it is `ab` — mid-text, 0.3. Scoring the whole row gives
        // 0.9 off the trailing `$ ` the cursor never reached.
        assert_eq!(score_of(b"\x1b[1;1Habc$ \x1b[1;3H"), 0.3);
    }

    #[test]
    fn a_shell_prompt_with_one_trailing_space_scores_high() {
        assert_eq!(score_of(b"user@host:~$ "), 0.9);
        assert_eq!(score_of(b"root# "), 0.9);
        assert_eq!(score_of(b"zsh% "), 0.9);
        assert_eq!(score_of(b"> "), 0.9);
        assert_eq!(score_of(b"Continue) "), 0.9);
        assert_eq!(score_of(b"Password: "), 0.9);
        assert_eq!("\u{276f} ".len(), 4, "the fancy prompt char is multi-byte");
        assert_eq!(score_of("\u{276f} ".as_bytes()), 0.9);
    }

    #[test]
    fn a_prompt_char_with_no_trailing_space_still_scores_high() {
        assert_eq!(score_of(b"sqlite>"), 0.9);
    }

    #[test]
    fn two_trailing_spaces_are_not_a_prompt() {
        // §8.6 allows 0..=1 spaces. Two means we are looking at text that
        // merely happens to contain a prompt character.
        assert_eq!(score_of(b"cost: $  "), 0.3);
    }

    #[test]
    fn mid_text_is_ambiguous() {
        assert_eq!(score_of(b"Compiling clasp-core"), 0.3);
    }

    #[test]
    fn a_whitespace_only_line_scores_nothing() {
        assert_eq!(score_of(b"   "), 0.0);
    }

    #[test]
    fn the_score_reads_the_cursor_row_not_the_last_painted_row() {
        // Paint a prompt on row 5, then move the cursor to row 2 col 4
        // which holds ordinary text. A naive "last line" implementation
        // scores 0.9 here; reading the cursor's own row scores 0.3.
        let bytes = b"\x1b[3;1Hplain text\x1b[6;1H$ \x1b[3;5H";
        assert_eq!(score_of(bytes), 0.3);
    }

    #[test]
    fn stability_requires_consecutive_identical_samples() {
        let mut s = CursorStability::new();
        assert!(!s.is_stable(DEFAULT_CURSOR_STABLE_SAMPLES));
        s.observe((5, 2));
        s.observe((5, 2));
        assert!(
            !s.is_stable(DEFAULT_CURSOR_STABLE_SAMPLES),
            "two is not three"
        );
        s.observe((5, 2));
        assert!(s.is_stable(DEFAULT_CURSOR_STABLE_SAMPLES));
        assert_eq!(s.samples(), 3);
    }

    #[test]
    fn any_movement_restarts_the_count() {
        let mut s = CursorStability::new();
        for _ in 0..10 {
            s.observe((5, 2));
        }
        assert!(s.is_stable(DEFAULT_CURSOR_STABLE_SAMPLES));
        s.observe((5, 3));
        assert_eq!(s.samples(), 1);
        assert!(!s.is_stable(DEFAULT_CURSOR_STABLE_SAMPLES));
    }

    #[test]
    fn reset_clears_the_history() {
        let mut s = CursorStability::new();
        for _ in 0..5 {
            s.observe((1, 1));
        }
        s.reset();
        assert_eq!(s.samples(), 0);
        s.observe((1, 1));
        assert_eq!(s.samples(), 1, "a re-seeded parser starts a fresh count");
    }
}
