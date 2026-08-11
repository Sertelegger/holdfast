//! The tier-3 fallback pattern table (spec §8.6).
//!
//! Used only when no deterministic signal is available. Patterns are
//! matched against the detector's last logical line, which is at most 512
//! bytes, so a linear pass over the table costs microseconds.
//!
//! **Two haystack preconditions, both normative (§8.6, REQ-PD-012), and
//! both load-bearing for the anchors below.** First, the haystack is one
//! logical line with its terminator removed — not a tail. The `regex`
//! crate's `^` and `$` anchor the *haystack*, and the multi-line flag is
//! not set, so feeding a multi-line tail silently stops every `^`-anchored
//! row from matching rather than matching the last line of it. Nine of the
//! twenty-two rows depend on that `^` to separate a prompt that owns its
//! line from ordinary output that merely ends the same way. Second, ANSI
//! stripping happens first: `"\x1b[1;32m$\x1b[0m "` scores 0 while the
//! stripped `"$ "` scores 0.6. The stripper lands at 0.0.3, so 0.0.2 runs
//! T3 with its full false-positive surface and no recall on coloured
//! prompts; both facts are asserted below as the documented behaviour they
//! are, to be updated rather than deleted when the stripper arrives.

use crate::{ClaspError, Result};
use regex::{Regex, RegexBuilder};

/// Hard cap on caller-supplied patterns.
///
/// Every pattern in the set is matched on every `score()`, and `score()`
/// runs inside `Session::detection()` — the path that answers *every* tool
/// call. Unbounded it accepted 5000 patterns and put each `score()` at
/// milliseconds. The bundled table is 22 rows, so 64 is far beyond what a
/// real caller needs and keeps the whole set comfortably under a tenth of
/// a millisecond. Exceeding it is the caller's mistake, so it takes the
/// same channel as an uncompilable regex (§5.1).
const MAX_EXTRA_PATTERNS: usize = 64;

/// Cap on the compiled size of one caller-supplied pattern.
///
/// There is no catastrophic backtracking to defend against — the regex
/// crate is automaton-based, and `(a+)+$` was measured linear — but
/// *compilation* is not free. `(?:(?:a{50}){50}){50}` expands to 125 000
/// repetitions and was accepted. The crate's 10 MiB default is a sensible
/// budget for a program compiling regexes it wrote itself and much too
/// generous for ones an agent hands over; a real prompt pattern compiles
/// to a few hundred bytes.
const PATTERN_SIZE_LIMIT: usize = 64 * 1024;

/// How much of a rejected pattern is echoed back in the error.
///
/// `start_session(prompt_patterns:)` takes these straight off the wire, so
/// the string is whatever the agent sent. Echoed whole, a 200 KB regex
/// produced a 200,044-byte `invalid_params` message — measured — which
/// lands in the MCP transcript and stays there for the rest of the
/// conversation. The *reason* is the actionable half of the message, so
/// the pattern is clipped rather than the message.
const ECHOED_PATTERN_MAX: usize = 120;

/// A caller-supplied pattern: `start_session(prompt_patterns: [...])` and
/// the global config both deserialise into this.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptPattern {
    pub regex: String,
    pub score: f32,
}

/// The shipped table, verbatim from spec §8.6 (rev. 26), in table order.
///
/// Nine rows carry a head guard — a leading `^`, a `(?:^|[^…])` class, or
/// the `\?` that qualifies a confirmation prompt. Those guards are what
/// rev. 26 added after measuring the table against 65 lines of ordinary
/// build, test, `git`, package-manager and `--help` output: 30 of the 65
/// scored above 0, several at or above §8.4's 0.85 act threshold. Every
/// correction narrows *where* a row may match; none deletes a row or
/// lowers a real prompt's score, because T3 is the only tier a
/// `dash`-shaped session has and lost recall there is unrecoverable.
///
/// Changing any score or anchor here changes what CLASP reports about a
/// live session on the tier with no corroborating signal, so each row is
/// pinned by a positive that only it can satisfy, a near-miss that pins
/// its anchors, and — for the guarded rows — the ordinary-output line the
/// guard was added to reject.
pub const DEFAULT_PATTERNS: &[(&str, f32)] = &[
    (
        r"^(?:\S.*[^A-Za-z0-9_.\-])?[Pp]assword(?:\s+for\s+[^:]+)?:\s*$",
        0.95,
    ),
    (
        r"^(?:\S.*[^A-Za-z0-9_.\-])?[Pp]assphrase\s*(?:for\s+key\s+[^:]+)?:\s*$",
        0.95,
    ),
    (
        r"\?\s*[\[(](?:[YyNn]/[YyNn]|yes/no)[^\])]*[\])]\s*:?\s*$",
        0.9,
    ),
    (r"\(yes/no(?:/[^)]*)?\)\s*\?\s*$", 0.9),
    (r"[\[(](?:[YyNn]/[YyNn]|yes/no)[^\])]*[\])]\s*:?\s*$", 0.6),
    (r"^\s*[Ee]nter\s[^:]{0,60}:\s*$", 0.8),
    (r"\?\s*$", 0.55),
    (r"^>>>\s*$", 0.9),
    (r"^\.\.\.\s*$", 0.85),
    (r"irb\([^)]+\):\d+:\d+>\s*$", 0.9),
    (r"node>\s*$", 0.9),
    (r"\$\s*$", 0.6),
    (r"(?:^|[^#])#\s*$", 0.6),
    (r"(?:^|[^0-9])%\s*$", 0.6),
    (r"^>\s*$", 0.5),
    (r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:.*[\$#]\s*$", 0.85),
    (r"\(gdb\)\s*$", 0.95),
    (r"\(lldb\)\s*$", 0.95),
    (r"\(Pdb\)\s*$", 0.95),
    (r"mysql>\s*$", 0.95),
    (r"postgres=#\s*$", 0.95),
    (r"sqlite>\s*$", 0.95),
];

#[derive(Debug, Clone)]
pub struct PatternSet {
    compiled: Vec<(Regex, f32)>,
}

impl Default for PatternSet {
    fn default() -> Self {
        Self::defaults()
    }
}

impl PatternSet {
    /// The shipped table. Infallible: every constant is compiled by a test.
    pub fn defaults() -> Self {
        let compiled = DEFAULT_PATTERNS
            .iter()
            .map(|(re, score)| {
                let re = Regex::new(re).expect("bundled prompt pattern must compile");
                (re, *score)
            })
            .collect();
        Self { compiled }
    }

    /// Build a set from caller-supplied patterns. `replace` swaps the
    /// bundled table out entirely; otherwise the extras are appended and
    /// scoring takes the maximum, so an extra pattern can only raise a
    /// score, never lower one (§8.6).
    pub fn build(extra: &[PromptPattern], replace: bool) -> Result<Self> {
        if extra.len() > MAX_EXTRA_PATTERNS {
            return Err(ClaspError::InvalidPattern(format!(
                "{} prompt patterns supplied; at most {MAX_EXTRA_PATTERNS} are accepted",
                extra.len()
            )));
        }
        let mut compiled: Vec<(Regex, f32)> = if replace {
            Vec::new()
        } else {
            Self::defaults().compiled
        };
        for p in extra {
            let re = RegexBuilder::new(&p.regex)
                .size_limit(PATTERN_SIZE_LIMIT)
                .build()
                .map_err(|e| {
                    ClaspError::InvalidPattern(format!(
                        "{}: {}",
                        echoed(&p.regex),
                        first_line(&e.to_string())
                    ))
                })?;
            compiled.push((re, p.score.clamp(0.0, 1.0)));
        }
        Ok(Self { compiled })
    }

    /// Highest-scoring pattern that matches, else 0.0 (§8.6 T3b).
    pub fn score(&self, line: &str) -> f32 {
        self.compiled
            .iter()
            .filter(|(re, _)| re.is_match(line))
            .map(|(_, s)| *s)
            .fold(0.0f32, f32::max)
    }

    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }
}

/// `regex::Error`'s Display is a multi-line diagram; only the first line
/// belongs in an MCP error message.
fn first_line(s: &str) -> String {
    s.lines()
        .next()
        .unwrap_or("invalid regex")
        .trim()
        .to_string()
}

/// The offending pattern, clipped to `ECHOED_PATTERN_MAX`.
///
/// Naming the pattern matters — a caller that sent several cannot act on
/// "one of them is invalid" — so the identifying head is kept rather than
/// the whole thing dropped.
fn echoed(pattern: &str) -> String {
    if pattern.chars().count() <= ECHOED_PATTERN_MAX {
        return pattern.to_string();
    }
    let head: String = pattern.chars().take(ECHOED_PATTERN_MAX).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real prompts, with the score §8.6 says each must produce.
    ///
    /// At least one line per row of the table, in table order, and each
    /// chosen so its expected score is reachable *only* while that row is
    /// present: where two rows can match the same line the expectation is
    /// the higher one, so deleting it drops the score rather than leaving
    /// it. Rows with no positive are rows that are not really shipped —
    /// eleven of the pre-rev.-26 rows were in that state and could be
    /// deleted, or typo'd, with the whole workspace still green.
    ///
    /// The five shapes rev. 26 exists for are here by name: apt's
    /// `[Y/n]`, the lowercase `[y/n]`, `[yes/no]:`, ssh's host-key
    /// question, and terraform's indented `Enter a value:`. All five
    /// scored 0 against the previous table.
    const PROMPT_CORPUS: &[(&str, f32)] = &[
        // Row 1 — password. The trailing-blank variant is not decoration:
        // "Password:" alone cannot tell `\s*$` from `$`, and every real
        // terminal puts a space after the colon.
        ("Password:", 0.95),
        ("Password:   ", 0.95),
        ("Password for alice:", 0.95),
        ("[sudo] password for jane: ", 0.95),
        ("jane@prod-01's password: ", 0.95),
        // Row 2 — passphrase. Also matched by the `Enter …:` row at 0.8,
        // so 0.95 is reachable only from this row.
        ("Enter passphrase for key '/home/a/.ssh/id_ed25519':", 0.95),
        (
            "Enter passphrase for key '/home/a/.ssh/id_ed25519':  ",
            0.95,
        ),
        // Row 3 — `?`-qualified confirmation. The unqualified row also
        // matches every one of these at 0.6; 0.9 says the `\?` half is
        // present. The first is apt/dpkg's, which scored 0 before rev. 26.
        ("Do you want to continue? [Y/n] ", 0.9),
        ("Continue? [y/N] ", 0.9),
        ("Continue? [y/n] ", 0.9),
        ("Overwrite? (y/n) ", 0.9),
        // `[yes/no]: ` is the one shape whose trailing `\s*$` sits after
        // the optional colon, so it is what pins that anchor for row 3.
        ("Proceed? [yes/no]: ", 0.9),
        // Row 4 — ssh host-key acceptance, where the choice group precedes
        // the `?` and row 3 therefore cannot fire. Without this row the
        // line falls to the generic trailing-`?` row at 0.55.
        (
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            0.9,
        ),
        ("Continue connecting (yes/no)? ", 0.9),
        // Row 5 — the same choice group with no preceding `?`.
        ("Overwrite [y/N] ", 0.6),
        ("Overwrite [yes/no]: ", 0.6),
        // Row 6 — the generic imperative-input idiom. Leading whitespace
        // is deliberately allowed: terraform's measured prompt is indented.
        ("  Enter a value: ", 0.8),
        ("Enter your name: ", 0.8),
        // Row 7 — generic question.
        ("Are you sure? ", 0.55),
        // Rows 8 and 9 — Python PS1 and PS2, each owning its whole line,
        // which is what makes `^` free of recall cost on both.
        (">>> ", 0.9),
        ("... ", 0.85),
        // Rows 10 and 11 — named REPLs.
        ("irb(main):001:0> ", 0.9),
        ("node> ", 0.9),
        // Rows 12, 13, 14 — the single-character shell prompts. These are
        // the rows §8.8 costs at one leaked byte, and they stay because a
        // `dash` session has nothing else.
        ("bash-5.3$ ", 0.6),
        ("$ ", 0.6),
        ("bash-5.3# ", 0.6),
        ("# ", 0.6),
        ("hostname% ", 0.6),
        ("% ", 0.6),
        // Row 15 — `sh`/`dash` PS2, the whole reason the `>` row exists.
        ("> ", 0.5),
        // Row 16 — full `user@host:path$`. Both also match a
        // single-character row at 0.6.
        ("alice@build01:~/src$ ", 0.85),
        ("root@prod:/etc# ", 0.85),
        // Rows 17–19 — debuggers.
        ("(gdb) ", 0.95),
        ("(lldb) ", 0.95),
        ("(Pdb) ", 0.95),
        // Rows 20–22 — database REPLs.
        ("mysql> ", 0.95),
        ("postgres=# ", 0.95),
        ("sqlite> ", 0.95),
    ];

    /// §8.6's measured false-positive surface, asserted **at the score it
    /// documents** rather than as a blanket zero (REQ-PD-013).
    ///
    /// A zero assertion cannot tell "this row is correctly narrow" from
    /// "this row stopped matching anything", and two of these lines do not
    /// score 0 by design: a `mysql>` in a README is byte-identical to the
    /// real prompt, and the trailing-`?` row is calibrated above `AtPrompt`
    /// and below §8.4's act threshold on purpose. Recording both as numbers
    /// makes a tightening that kills recall and a loosening that re-opens a
    /// class fail the same test, and makes changing either a deliberate
    /// edit to §8.6 and to this corpus together.
    ///
    /// The four classes rev. 26 closed are here at 0 by name, because they
    /// are what the head guards were added for.
    const ORDINARY_CORPUS: &[(&str, f32)] = &[
        // Known-lossy; stays. No regex separates these from the prompt.
        ("mysql>", 0.95),
        ("sqlite>", 0.95),
        // Accepted: below the act threshold, and rarely the last line.
        ("Enter the following commands:", 0.8),
        // Accepted, reduced from 0.9 by the `?` split: `--help` prose that
        // describes a confirmation rather than asking one.
        ("  -f, --force   overwrite without asking [y/N]", 0.6),
        // Known-lossy; stays. Deliberately above `AtPrompt`, below act.
        ("What now?", 0.55),
        ("how do I reset my password?", 0.55),
        // Was 0.95 — an indented config key with an empty value is
        // shape-identical to a real prompt. Closed by the head guard.
        ("  password:", 0.0),
        ("    password:", 0.0),
        ("  db_password:", 0.0),
        // Was 0.85, *exactly* §8.4's act threshold. A stalled installer
        // goes quiet, quiescence climbs to 1.0, and the agent is told to
        // act while the install runs. Closed by anchoring the Python PS2.
        ("Installing collected packages...", 0.0),
        ("Resolving dependencies...", 0.0),
        ("Waiting for the daemon to start...", 0.0),
        ("Cloning into 'repo'...", 0.0),
        // Was 0.6. Progress output matters disproportionately: a progress
        // bar is exactly the output that pauses, which is when quiescence
        // peaks. A percentage is a digit followed by `%`; a prompt is not.
        ("Receiving objects:  47%", 0.0),
        ("[####------] 40%", 0.0),
        ("Coverage: 92%", 0.0),
        ("  100%", 0.0),
        ("############################", 0.0),
        // Was 0.5, the exact `AtPrompt` boundary, on the broadest row in
        // the table by reach.
        ("Author: Jane Doe <jane@example.com>", 0.0),
        ("  File \"/srv/app/main.py\", line 3, in <module>", 0.0),
        ("</html>", 0.0),
        ("Usage: mytool [OPTIONS] <FILE>", 0.0),
        // Ordinary build output that never matched anything.
        ("", 0.0),
        ("Compiling clasp-core v0.0.1", 0.0),
        ("warning: unused variable", 0.0),
        ("total 48", 0.0),
    ];

    /// One near-miss per row: a line that carries the row's trigger token
    /// but runs past its anchor, or sits on the wrong side of its guard.
    ///
    /// A corpus of obviously-different lines pins no anchor, because an
    /// anchor only bites at the boundary. Each of these is the shortest
    /// realistic line that crosses one — a rule that fired here would be a
    /// confident wrong answer in exactly the case T3 exists to cover, and
    /// it is the tier with nothing to disagree with it.
    const NEAR_MISS_CORPUS: &[(&str, f32)] = &[
        // Row 1 — past the colon, with and without trailing blanks:
        // `\s*$` skips blanks, not content.
        ("Password: hunter2", 0.0),
        ("Password: hunter2   ", 0.0),
        ("the Password: field is required", 0.0),
        // ...and the guard's other half: an identifier that merely *ends*
        // in `password` is not a prompt, indented or not.
        ("db_password:", 0.0),
        // Row 2 — `ssh-add` writing this to a log must not read as a live
        // secret prompt.
        (
            "Enter passphrase for key '/home/a/.ssh/id_ed25519': supplied",
            0.0,
        ),
        ("  passphrase:", 0.0),
        // Row 3 — the choice group is not the end of the line.
        ("Continue? [y/N] extra", 0.0),
        // Row 4 — the answer echoed after the question.
        (
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? yes",
            0.0,
        ),
        // Row 5 — prose that opens with the choice group.
        ("[y/N] is the default", 0.0),
        // Row 6 — one for the tail anchor, one for the head: `Enter` must
        // open the line, or the row swallows every sentence containing it.
        ("Enter a value: 42", 0.0),
        ("Please Enter a value: ", 0.0),
        // Row 7.
        ("Why? Because.", 0.0),
        // Row 8 — the `^` half. Unanchored, documentation quoting the
        // Python prompt reads as the Python prompt.
        ("Type the code after the >>> ", 0.0),
        (">>> import os", 0.0),
        // Row 9.
        ("... and 3 more warnings", 0.0),
        // Rows 10 and 11.
        ("irb(main):001:0> puts 1", 0.0),
        ("see node> in the docs", 0.0),
        // Rows 12, 13, 14 — the echoed command after each prompt, which is
        // what the tail anchor separates from the prompt itself.
        ("echo $PATH", 0.0),
        ("bash-5.3# rm -rf /tmp/x", 0.0),
        ("hostname% ls -la", 0.0),
        // Row 15 — a quoted reply line, which `>` opens and does not end.
        ("> quoted reply text", 0.0),
        // Row 16.
        ("alice@build01:~/src$ ls", 0.0),
        // Rows 17–19.
        ("(gdb) break main", 0.0),
        ("(lldb) run", 0.0),
        ("(Pdb) n", 0.0),
        // Rows 20–22.
        ("see mysql> in the docs", 0.0),
        ("postgres=# SELECT 1;", 0.0),
        ("sqlite> .tables", 0.0),
    ];

    /// Every asserted line in the module, in one iterator, for the
    /// mutation guards below.
    fn full_corpus() -> impl Iterator<Item = &'static (&'static str, f32)> {
        PROMPT_CORPUS
            .iter()
            .chain(ORDINARY_CORPUS)
            .chain(NEAR_MISS_CORPUS)
    }

    /// The shipped table, owned, so a mutant can be derived from it.
    fn rows() -> Vec<(String, f32)> {
        DEFAULT_PATTERNS
            .iter()
            .map(|(re, s)| ((*re).to_string(), *s))
            .collect()
    }

    /// The corpus lines on which a mutant table disagrees with the shipped
    /// one. Empty means the mutation is invisible — a row or an anchor
    /// nothing asserts.
    fn divergences(mutant: &[(String, f32)]) -> Vec<&'static str> {
        let shipped = PatternSet::defaults();
        let mutant = PatternSet {
            compiled: mutant
                .iter()
                .map(|(re, s)| (Regex::new(re).expect("mutant must compile"), *s))
                .collect(),
        };
        full_corpus()
            .filter(|(line, _)| (shipped.score(line) - mutant.score(line)).abs() >= 1e-6)
            .map(|(line, _)| *line)
            .collect()
    }

    #[test]
    fn every_bundled_pattern_compiles() {
        for (re, score) in DEFAULT_PATTERNS {
            Regex::new(re).unwrap_or_else(|e| panic!("{re} failed to compile: {e}"));
            assert!((0.0..=1.0).contains(score), "{re} has score {score}");
        }
        // A *literal* count, not `DEFAULT_PATTERNS.len()`. Comparing the
        // compiled set against its own source is a tautology that stays
        // green when a row leaves the table, which is how eleven of the
        // pre-rev.-26 rows came to be deletable with nothing failing. The
        // per-row positives in `PROMPT_CORPUS` catch a row being removed;
        // this literal is the only thing that catches one being *added*,
        // so both directions stay covered.
        assert_eq!(DEFAULT_PATTERNS.len(), 22, "§8.6 rev. 26 has 22 rows");
        assert_eq!(PatternSet::defaults().len(), DEFAULT_PATTERNS.len());
    }

    #[test]
    fn known_prompts_score_as_specified() {
        let p = PatternSet::defaults();
        for (line, want) in PROMPT_CORPUS {
            let got = p.score(line);
            assert!(
                (got - want).abs() < 1e-6,
                "{line:?}: got {got}, want {want}"
            );
        }
    }

    #[test]
    fn ordinary_output_scores_as_specified() {
        // Expected scores, never a blanket `== 0.0` (REQ-PD-013). See
        // `ORDINARY_CORPUS` for why two of these lines are non-zero.
        let p = PatternSet::defaults();
        for (line, want) in ORDINARY_CORPUS {
            let got = p.score(line);
            assert!(
                (got - want).abs() < 1e-6,
                "{line:?}: got {got}, want {want} (§8.6 false-positive table)"
            );
        }
    }

    #[test]
    fn near_misses_score_zero() {
        let p = PatternSet::defaults();
        for (line, want) in NEAR_MISS_CORPUS {
            let got = p.score(line);
            assert!(
                (got - want).abs() < 1e-6,
                "{line:?}: got {got}, want {want}"
            );
        }
    }

    // ---- mutation guards ----
    //
    // Three tests that run a mutation sweep over the *whole* table rather
    // than trusting each row's own assertion. A pattern table is the shape
    // where per-row confidence fails: rows overlap, so a row can be
    // deleted or widened and another row can quietly supply the same score
    // to the line that was supposed to pin it. These ask the only question
    // that matters — does *some* asserted line move — and name the row if
    // none does.

    #[test]
    fn every_row_is_pinned_by_the_corpus() {
        for (i, (re, score)) in DEFAULT_PATTERNS.iter().enumerate() {
            let mut mutant = rows();
            mutant.remove(i);
            assert!(
                !divergences(&mutant).is_empty(),
                "row {i} ({re} @ {score}) can be deleted with the whole \
                 corpus still green — another row is masking its positive"
            );
        }
    }

    #[test]
    fn every_trailing_anchor_is_pinned_by_the_corpus() {
        // `\s*$` → `$`. Every row ends in `\s*$` because every real prompt
        // is followed by the space the user types after, so narrowing it
        // costs recall on all 22 rows at once and does so silently: the
        // prompt string still "looks right" in any test that omits the
        // trailing blank.
        for (i, (re, score)) in DEFAULT_PATTERNS.iter().enumerate() {
            let narrowed = re
                .strip_suffix(r"\s*$")
                .map(|head| format!("{head}$"))
                .unwrap_or_else(|| panic!("row {i} ({re}) does not end in `\\s*$`"));
            let mut mutant = rows();
            mutant[i] = (narrowed, *score);
            assert!(
                !divergences(&mutant).is_empty(),
                "row {i} ({re} @ {score}) has no corpus line with trailing \
                 whitespace, so narrowing `\\s*$` to `$` is invisible"
            );
        }
    }

    #[test]
    fn every_rev26_head_guard_is_pinned_by_the_corpus() {
        // The other half of the sweep, and the half rev. 26 is about.
        // Widening a head guard is the mutation that re-opens a
        // false-positive class, and unlike the two above it cannot be
        // derived mechanically — each guard means something different — so
        // the widened form and the line it must recover are written out.
        let guards: &[(&str, &str, &str)] = &[
            (
                r"^(?:\S.*[^A-Za-z0-9_.\-])?[Pp]assword(?:\s+for\s+[^:]+)?:\s*$",
                r"(?:\S.*[^A-Za-z0-9_.\-])?[Pp]assword(?:\s+for\s+[^:]+)?:\s*$",
                "an indented YAML/helm key with an empty value",
            ),
            (
                r"^(?:\S.*[^A-Za-z0-9_.\-])?[Pp]assphrase\s*(?:for\s+key\s+[^:]+)?:\s*$",
                r"(?:\S.*[^A-Za-z0-9_.\-])?[Pp]assphrase\s*(?:for\s+key\s+[^:]+)?:\s*$",
                "the same, for passphrase",
            ),
            (
                r"\?\s*[\[(](?:[YyNn]/[YyNn]|yes/no)[^\])]*[\])]\s*:?\s*$",
                r"[\[(](?:[YyNn]/[YyNn]|yes/no)[^\])]*[\])]\s*:?\s*$",
                "`--help` prose describing a confirmation, at 0.9 not 0.6",
            ),
            (
                r"^\s*[Ee]nter\s[^:]{0,60}:\s*$",
                r"\s*[Ee]nter\s[^:]{0,60}:\s*$",
                "any sentence containing `Enter <thing>:`",
            ),
            (r"^>>>\s*$", r">>>\s*$", "prose quoting the Python prompt"),
            (
                r"^\.\.\.\s*$",
                r"\.\.\.\s*$",
                "every trailing-ellipsis status line, at §8.4's act threshold",
            ),
            (r"(?:^|[^#])#\s*$", r"#\s*$", "a `####…` separator banner"),
            (r"(?:^|[^0-9])%\s*$", r"%\s*$", "every progress percentage"),
            (
                r"^>\s*$",
                r">\s*$",
                "`git log` authors, traceback frames, closing tags, `<FILE>`",
            ),
        ];

        for (guarded, widened, recovers) in guards {
            let i = DEFAULT_PATTERNS
                .iter()
                .position(|(re, _)| re == guarded)
                .unwrap_or_else(|| panic!("{guarded} is no longer in the table"));
            let mut mutant = rows();
            mutant[i] = ((*widened).to_string(), DEFAULT_PATTERNS[i].1);
            assert!(
                !divergences(&mutant).is_empty(),
                "widening row {i} to {widened} changes nothing in the \
                 corpus, so the guard against {recovers} is untested"
            );
        }

        // ...and the guards table must cover every guarded row, or a row
        // added later with a head guard gets one for free and untested.
        // A guard is a leading `^`, a `(?:^|[^…])` class, or the `\?` that
        // qualifies a confirmation prompt — the last distinguished from
        // the bare `\?\s*$` row by the bracket that follows it.
        let guarded_rows = DEFAULT_PATTERNS
            .iter()
            .filter(|(re, _)| {
                re.starts_with('^') || re.starts_with(r"(?:^|") || re.starts_with(r"\?\s*[")
            })
            .count();
        assert_eq!(
            guarded_rows,
            guards.len(),
            "{guarded_rows} rows carry a head guard but only {} are \
             mutation-tested",
            guards.len()
        );
    }

    #[test]
    fn the_haystack_must_be_a_single_line() {
        // REQ-PD-012. The `regex` crate's `^` anchors the *haystack* and
        // the multi-line flag is off, so a caller that hands T3b a tail
        // instead of a line does not get "the last line of the tail
        // matched" — it gets silence from all nine `^`-anchored rows,
        // including every one rev. 26 added. That is the fail-safe
        // direction and it is still a caller bug, so it is asserted here
        // rather than left to be discovered as missing recall.
        let p = PatternSet::defaults();
        assert_eq!(
            p.score("Collecting packages\n>>> "),
            0.0,
            "a multi-line haystack must not match an `^`-anchored row"
        );
        assert_eq!(p.score("building\n... "), 0.0);
        assert_eq!(p.score("done\n> "), 0.0);
        // The line terminator itself is the case that must still work:
        // `\s*$` absorbs it, so a caller that trims the newline and one
        // that does not agree.
        assert!((p.score(">>> \n") - 0.9).abs() < 1e-6);
        assert!((p.score("$ \r\n") - 0.6).abs() < 1e-6);
    }

    #[test]
    fn an_ansi_decorated_prompt_scores_zero_until_the_stripper_lands() {
        // The 0.0.2-only gap (§8.6, REQ-PD-012), asserted as the
        // documented behaviour it is. Most real prompts are SGR-coloured,
        // so until the 0.0.3 stripper runs ahead of this table T3 carries
        // its full false-positive surface *and* no recall on them — the
        // wrong way round, which is why 0.0.3 is not optional. Update this
        // test when the stripper lands; do not delete it.
        let p = PatternSet::defaults();
        assert_eq!(p.score("\x1b[1;32m$\x1b[0m "), 0.0);
        assert!((p.score("$ ") - 0.6).abs() < 1e-6);
    }

    #[test]
    fn the_highest_scoring_match_wins() {
        // "alice@host:~$ " matches both the full user@host rule (0.85) and
        // the bare "$" rule (0.6).
        let p = PatternSet::defaults();
        assert!((p.score("alice@host:~$ ") - 0.85).abs() < 1e-6);

        // That assertion alone would also pass under "first match wins":
        // the two rows this line matches happen to sit in descending order.
        // (The table as a whole is *not* ordered by score — the 0.55
        // generic-question row sits between 0.8 and 0.9 — but that is not
        // what makes the assertion above weak; the local order of the
        // matching rows is.)
        // An appended pattern breaks the coincidence: this one is last in
        // the list and outscores the bundled `$` rule that matches first.
        let p = PatternSet::build(
            &[PromptPattern {
                regex: r"bash-\d+\.\d+\$\s*$".into(),
                score: 0.95,
            }],
            false,
        )
        .unwrap();
        assert!(
            (p.score("bash-5.3$ ") - 0.95).abs() < 1e-6,
            "got {}",
            p.score("bash-5.3$ ")
        );
    }

    #[test]
    fn extra_patterns_extend_the_defaults() {
        let p = PatternSet::build(
            &[PromptPattern {
                regex: r"myapp>\s*$".into(),
                score: 0.9,
            }],
            false,
        )
        .unwrap();
        assert!((p.score("myapp> ") - 0.9).abs() < 1e-6);
        assert!(
            (p.score(">>> ") - 0.9).abs() < 1e-6,
            "defaults must survive"
        );
    }

    #[test]
    fn replace_drops_the_defaults() {
        let p = PatternSet::build(
            &[PromptPattern {
                regex: r"myapp>\s*$".into(),
                score: 0.9,
            }],
            true,
        )
        .unwrap();
        assert!((p.score("myapp> ") - 0.9).abs() < 1e-6);
        assert_eq!(p.score(">>> "), 0.0, "defaults should have been replaced");
    }

    #[test]
    fn an_invalid_pattern_is_reported_not_panicked() {
        let e = PatternSet::build(
            &[PromptPattern {
                regex: "((unclosed".into(),
                score: 0.9,
            }],
            false,
        )
        .unwrap_err();
        assert!(matches!(e, ClaspError::InvalidPattern(_)), "got {e:?}");
        // The message must stay short enough for a tool response.
        assert!(!e.to_string().contains('\n'), "{e}");
        // A caller that sent several patterns cannot act on "one of them
        // is invalid", so the message has to name which. Dropping the
        // pattern from the format string is otherwise undetectable.
        assert!(
            e.to_string().contains("((unclosed"),
            "the error does not say which pattern failed: {e}"
        );
    }

    #[test]
    fn a_rejected_pattern_is_not_echoed_back_whole() {
        // These arrive over the wire from `start_session(prompt_patterns:)`
        // and every byte of the rejection lands in the MCP transcript.
        // Unclipped, a 200 KB regex produced a 200,044-byte
        // `invalid_params` message — measured — which then sits in the
        // agent's conversation history for good.
        let huge = "(".repeat(200_000);
        let e = PatternSet::build(
            &[PromptPattern {
                regex: huge,
                score: 0.9,
            }],
            false,
        )
        .unwrap_err();
        let msg = e.to_string();
        assert!(msg.chars().count() < 400, "{} chars", msg.chars().count());
        // Clipped, not dropped: the head still identifies the pattern...
        assert!(
            msg.contains("((((("),
            "the pattern is unidentifiable: {msg}"
        );
        // ...and the reason survives the clip, which is the whole point of
        // clipping the pattern rather than truncating the message.
        assert!(
            msg.contains("unclosed") || msg.contains("regex parse error"),
            "the reason was lost to the truncation: {msg}"
        );
    }

    #[test]
    fn a_pattern_that_compiles_to_an_enormous_automaton_is_rejected() {
        // Not backtracking — this crate has none — but compile cost.
        // `{50}` nested three deep is 125 000 repetitions, accepted under
        // the crate's 10 MiB default limit.
        let e = PatternSet::build(
            &[PromptPattern {
                regex: r"(?:(?:a{50}){50}){50}".into(),
                score: 0.9,
            }],
            true,
        )
        .unwrap_err();
        assert!(matches!(e, ClaspError::InvalidPattern(_)), "got {e:?}");

        // The separator: an ordinary prompt pattern is nowhere near the
        // limit, so this must not be a set that rejects everything.
        PatternSet::build(
            &[PromptPattern {
                regex: r"(?:myapp|myotherapp)\[\d+\]>\s*$".into(),
                score: 0.9,
            }],
            true,
        )
        .expect("a realistic pattern must still compile");
    }

    #[test]
    fn the_number_of_caller_patterns_is_capped() {
        // `score()` walks the whole set, and it runs inside
        // `Session::detection()` — on the path that answers every tool
        // call. 5000 patterns were accepted and cost milliseconds per call.
        let many = |n: usize| -> Vec<PromptPattern> {
            (0..n)
                .map(|i| PromptPattern {
                    regex: format!(r"p{i}>\s*$"),
                    score: 0.5,
                })
                .collect()
        };
        let e = PatternSet::build(&many(MAX_EXTRA_PATTERNS + 1), false).unwrap_err();
        assert!(matches!(e, ClaspError::InvalidPattern(_)), "got {e:?}");

        // The boundary itself, so the cap cannot quietly become off-by-one
        // or collapse to "reject any extras at all".
        let set = PatternSet::build(&many(MAX_EXTRA_PATTERNS), false)
            .expect("exactly the cap must be accepted");
        assert_eq!(set.len(), MAX_EXTRA_PATTERNS + DEFAULT_PATTERNS.len());
    }

    #[test]
    fn scores_are_clamped_into_range() {
        let p = PatternSet::build(
            &[PromptPattern {
                regex: "^x$".into(),
                score: 42.0,
            }],
            true,
        )
        .unwrap();
        assert_eq!(p.score("x"), 1.0);

        // The lower half. `pattern_score` is reported verbatim in every
        // detection response (§8.4), so a negative one is agent-visible
        // nonsense, and `confidence = quiescent * max(pattern, cursor)`
        // consumes it directly.
        //
        // Stated honestly: the floor is held twice — by this clamp and by
        // `score`'s `fold(0.0, f32::max)` identity — so removing *either*
        // alone is invisible here and only removing both fails. That is
        // worth an assertion anyway: the redundancy is what makes the
        // guarantee robust, and nothing else in the tree says the floor
        // is 0.0 at all.
        let p = PatternSet::build(
            &[PromptPattern {
                regex: "^x$".into(),
                score: -5.0,
            }],
            true,
        )
        .unwrap();
        assert_eq!(p.score("x"), 0.0);
    }
}
