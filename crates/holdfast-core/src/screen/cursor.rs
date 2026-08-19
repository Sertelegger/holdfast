//! The T3c cursor-position prompt sub-signal (spec §8.6).
//!
//! Produces `cursor_score` only. The combiner
//! `confidence = quiescent_score * max(pattern_score, cursor_score)`
//! lives in the detector (milestone 0.0.2); this module is the source of
//! the third term and nothing else.

use regex::Regex;
use std::sync::LazyLock;

/// Spec §8.6 / §10.2 `prompts.cursor_prompt_chars`.
pub const DEFAULT_PROMPT_CHARS: &[char] = &['$', '%', '#', '>', ')', ':', '❯'];

/// Spec §4.2 `cursor_stable_samples`.
pub const DEFAULT_CURSOR_STABLE_SAMPLES: u32 = 3;

/// The §8.6 T3b rows whose head guard is a property of the character
/// rather than of the sub-signal reading it (§8.6 rev. 46, REQ-PD-008).
///
/// Each entry is one row of the T3b table, **byte-identical** to its
/// spelling in `detect::patterns::DEFAULT_PATTERNS`; the test that holds
/// the two tables to that identity lives in `patterns.rs`, next to the
/// table it is protecting. Transplanting the row string rather than
/// re-deriving the rule is the whole of REQ-PD-008: the defect it closes
/// *is* a second edit, so a second *spelling* of the same guard would be
/// the same defect one revision later, differing from its original only
/// where nobody looked. The two shipped guards are, verbatim:
///
/// - `(?:^|[^#])#\s*$` — the character before the `#` is not itself a
///   `#`, which is what separates `bash-5.3# ` from a `####…` banner.
/// - `(?:^|[^0-9]|[A-Za-z][A-Za-z0-9_.\-]*\d)%\s*$` — start of line, or a
///   non-digit precedes the `%`, or the run of `[A-Za-z0-9_.\-]` reaching
///   the `%` carries a letter, which is what separates `build01% ` from
///   `Receiving objects:  47%`.
///
/// Both are matched against `candidate` — the text left of the cursor
/// with T3c's own single trailing space already stripped — so the row's
/// `\s*$` matches empty and what is left of the row is exactly its head
/// guard. T3c therefore does not acquire T3b's *tail* rule along with it:
/// §8.6 allows 0..=1 trailing spaces on this sub-signal and `\s*$` allows
/// any number, and `hostname%  ` must stay ambiguous here.
pub const HEAD_GUARDS: &[(char, &str)] = &[
    ('#', r"(?:^|[^#])#\s*$"),
    ('%', r"(?:^|[^0-9]|[A-Za-z][A-Za-z0-9_.\-]*\d)%\s*$"),
];

static COMPILED_HEAD_GUARDS: LazyLock<Vec<(char, Regex)>> = LazyLock::new(|| {
    HEAD_GUARDS
        .iter()
        .map(|(c, re)| {
            (
                *c,
                Regex::new(re).expect("bundled T3c head guard must compile"),
            )
        })
        .collect()
});

/// Whether the character closing `candidate` may score as a prompt at all
/// (§8.6 rev. 46, REQ-PD-008).
///
/// **What this deliberately does not do**, because the repair is narrower
/// than "T3c gets T3b's table":
///
/// - It does not give T3c T3b's *rows*. `foo> ` still scores 0.9 here and
///   0 on the pattern rung, which is what T3c is for and what §8.6 cited
///   when it anchored `^>\s*$`: that anchor is a claim about the *line*,
///   not about the character, and importing it would collapse the two
///   sub-signals into one.
/// - It does not reach `:` or `)`. Neither has a T3b row, so there is no
///   guard to inherit; a cursor parked after `Steps:` still scores 0.9,
///   which is the residual §8.6 already accepts by name.
/// - It changes nothing about newline-terminated output, which was never
///   exposed: `col == 0` returns before any character is examined. The
///   one class T3c re-opened, measured over §8.6's 65-line corpus, is
///   output redrawn in place with a carriage return — dominated by
///   progress bars, whose quiescence is exactly what peaks.
///
/// A rejection is `0.0` at the call site and not §8.6's `0.3`
/// "ambiguous". The two say different things and the stronger one is
/// true: a guard rejects because the trailing token has been *identified*
/// as something other than a prompt — the `%` closes a number, the run of
/// `#` is a rule or a banner — which is evidence, not an absence of it.
/// It is also the value §8.6 and §23.3 state the answer returns to, 0.90
/// down to 0.00, once the guards reach the second sub-signal; 0.3 would
/// leave a stalled `git clone` reporting a third of a prompt forever.
fn head_guard_admits(candidate: &str, prompt_char: char) -> bool {
    COMPILED_HEAD_GUARDS
        .iter()
        .find(|(c, _)| *c == prompt_char)
        .is_none_or(|(_, re)| re.is_match(candidate))
}

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
    if let Some(c) = candidate
        .chars()
        .next_back()
        .filter(|c| prompt_chars.contains(c))
    {
        // REQ-PD-008: a head guard is a property of the character, so
        // the guard the T3b table puts on `c` applies to the text left of
        // the cursor too. `head_guard_admits` carries the argument for
        // why a rejection is 0.0 and not the 0.3 below.
        return if head_guard_admits(candidate, c) {
            0.9
        } else {
            0.0
        };
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
        assert_eq!(score_of(b"Compiling holdfast-core"), 0.3);
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

    // ---- §8.6 rev. 46 / REQ-PD-008: the head guards ----

    /// The far side of the two guards: lines whose T3b row scores 0 and
    /// whose *cursor* scored 0.9 until rev. 46.
    ///
    /// That gap is the defect, not an omission in the corpus: every
    /// number in §8.6's two tables belongs to one sub-signal, so a corpus
    /// asserting T3b stays green against a combiner in which T3c answers
    /// 0.9 on the same line — and `confidence = quiescent *
    /// max(pattern, cursor)` takes the larger of the two.
    const GUARD_REJECTS: &[&str] = &[
        "Receiving objects:  47%",
        "[####------] 40%",
        "Coverage: 92%",
        "  100%",
        "Coverage change: -2.1%",
        "cpu -40%",
        "lines......: 87.5%",
        "width:100%",
        "############################",
        // A real prompt scoring 0 on *both* sub-signals — the documented
        // rev.-34 recall loss, listed here rather than quietly omitted so
        // that T3c cannot become the back door that recovers what §8.6
        // decided to give up.
        "10.0.0.5% ",
    ];

    /// The near side of the same two guards (REQ-PD-017). Every line is a
    /// real prompt the guard admits, so a guard one character wider
    /// zeroes a live shell on the only tier such a session has.
    const GUARD_ADMITS: &[&str] = &[
        "build01% ",
        "prod-01% ",
        "web1% ",
        "user@build01% ",
        "hostname% ",
        "% ",
        "zsh% ",
        "bash-5.3# ",
        "# ",
        "root@prod:/etc# ",
        // The two lines the rev.-34 letter rule re-admits on T3b at 0.6.
        // Both end in a `PROMPT_CHARS` member, so §8.6 rev. 46 says a
        // cursor parked after either scores 0.9 — asserted as the
        // accepted cost it is rather than left to look like an oversight.
        "mem2%",
        "x50%",
    ];

    #[test]
    fn a_guarded_character_scores_nothing_where_its_t3b_row_scores_nothing() {
        for line in GUARD_REJECTS {
            assert_eq!(score_of(line.as_bytes()), 0.0, "{line:?}");
        }
        // The pairing, and it is what makes the loop above mean anything:
        // "scores 0" is satisfied by a scorer that has stopped scoring,
        // which is the exact failure mode a change whose whole content is
        // *more zeroes* invites.
        for line in GUARD_ADMITS {
            assert_eq!(score_of(line.as_bytes()), 0.9, "{line:?}");
        }
    }

    #[test]
    fn a_guard_rejection_is_zero_and_not_the_ambiguous_third() {
        // §8.6's pseudocode falls through to 0.3 for anything not
        // prompt-shaped, so "skip the 0.9 branch" is the naive repair and
        // it answers 0.30 on a settled session. The two are different
        // claims: 0.3 says *we cannot tell*, 0.0 says *we can, and this
        // is not a prompt*. The guard established the second — a `%` that
        // closes a number, a `#` inside a run of them — and 0.00 is the
        // value §8.6 records the combined answer returning to.
        assert_eq!(score_of(b"Coverage: 92%"), 0.0);
        assert_eq!(score_of(b"############################"), 0.0);
        // The separator: a line that genuinely is ambiguous still scores
        // 0.3, so this is not "everything unrecognised is now 0".
        assert_eq!(score_of(b"Compiling holdfast-core"), 0.3);
    }

    #[test]
    fn the_guards_do_not_reach_the_prompt_chars_with_no_t3b_guard_to_inherit() {
        // Carve-out 1 — `^>\s*$` is a *row anchor*: a claim about the
        // line, not about the character. Transplanting it would collapse
        // the two sub-signals into one, and `foo> ` — 0 on the pattern
        // rung, 0.9 here — is precisely the case T3c exists for.
        for line in ["sqlite>", "mysql>", "foo> ", "> "] {
            assert_eq!(score_of(line.as_bytes()), 0.9, "{line:?}");
        }
        // Carve-out 2 — `:` and `)` have no T3b row, so there is no guard
        // to inherit and §8.6 declined a generic `:\s*$` row on
        // measurement rather than by oversight. These stay at 0.9: the
        // residual §8.6 already accepts by name, asserted so that
        // narrowing it later is a deliberate edit to both.
        for line in ["Password: ", "Enter the following commands:", "Continue) "] {
            assert_eq!(score_of(line.as_bytes()), 0.9, "{line:?}");
        }
    }

    /// The only class §8.6 measured T3c re-opening: output redrawn in
    /// place with a carriage return.
    ///
    /// It is also the worst case for the combiner rather than an exotic
    /// one. A progress bar is the one kind of ordinary output that does
    /// not end its line, so it is the one kind that can leave a
    /// percentage left of a parked cursor — and a stalled download is
    /// silent, so `quiescent_score` climbs to 1.0 with nothing to
    /// disagree.
    #[test]
    fn a_carriage_return_redrawn_progress_bar_is_where_the_guard_bites() {
        assert_eq!(
            score_of(b"Receiving objects:  1%\rReceiving objects:  47%"),
            0.0
        );

        // The newline-terminated twin, and the reason it is written out
        // instead of relied on: it is 0 for an entirely different reason.
        // `col == 0` returns before any character is examined, so a
        // corpus whose lines all end in a newline asserts the column-zero
        // branch and passes against no head guard whatever — which is how
        // this defect survived the task that shipped `raw_cursor_score`.
        let terminated = screen_after(b"Receiving objects:  47%\r\n");
        assert_eq!(
            terminated.screen().cursor_position(),
            (1, 0),
            "the twin has to actually be at column zero for this to say anything"
        );
        assert_eq!(
            raw_cursor_score(terminated.screen(), DEFAULT_PROMPT_CHARS),
            0.0
        );

        // ...and the same row with the cursor parked back at its end,
        // which is the arrangement in which a guarded line is reachable
        // at all. Same text, column 23, still 0 — now because of the
        // guard.
        let parked = screen_after(b"Receiving objects:  47%");
        assert_eq!(parked.screen().cursor_position(), (0, 23));
        assert_eq!(raw_cursor_score(parked.screen(), DEFAULT_PROMPT_CHARS), 0.0);

        // The near side of the redraw itself: a shell that repaints its
        // prompt over a progress line is admitted, so none of the above
        // reads as "output redrawn in place scores 0".
        assert_eq!(score_of(b"cloning\rbuild01% "), 0.9);
    }
}
