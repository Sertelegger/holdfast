//! The tier-3 fallback pattern table (spec §8.6).
//!
//! Used only when no deterministic signal is available. Patterns are
//! matched against the detector's last logical line, which is at most 512
//! bytes, so a linear pass over the table costs microseconds.

use crate::{ClaspError, Result};
use regex::{Regex, RegexBuilder};

/// Hard cap on caller-supplied patterns.
///
/// Every pattern in the set is matched on every `score()`, and `score()`
/// runs inside `Session::detection()` — the path that answers *every* tool
/// call. Unbounded it accepted 5000 patterns and put each `score()` at
/// milliseconds. The bundled table is 21 rows, so 64 is far beyond what a
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

/// The shipped table, verbatim from spec §8.6.
pub const DEFAULT_PATTERNS: &[(&str, f32)] = &[
    (r"[Pp]assword(?:\s+for\s+[^:]+)?:\s*$", 0.95),
    (r"[Pp]assphrase\s*(?:for\s+key\s+[^:]+)?:\s*$", 0.95),
    (r"\[y/N\]\s*$", 0.9),
    (r"\(y/n\)\s*$", 0.9),
    (r"\?\s*\[Yy/Nn\]\s*$", 0.9),
    (r">>>\s*$", 0.9),
    (r"\.\.\.\s*$", 0.85),
    (r"irb\([^)]+\):\d+:\d+>\s*$", 0.9),
    (r"node>\s*$", 0.9),
    (r"\(gdb\)\s*$", 0.95),
    (r"\(lldb\)\s*$", 0.95),
    (r"\(Pdb\)\s*$", 0.95),
    (r"mysql>\s*$", 0.95),
    (r"postgres=#\s*$", 0.95),
    (r"sqlite>\s*$", 0.95),
    (r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:.*[\$#]\s*$", 0.85),
    (r"\$\s*$", 0.6),
    (r"#\s*$", 0.6),
    (r"%\s*$", 0.6),
    (r">\s*$", 0.5),
    (r"\?\s*$", 0.55),
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

    #[test]
    fn every_bundled_pattern_compiles() {
        for (re, score) in DEFAULT_PATTERNS {
            Regex::new(re).unwrap_or_else(|e| panic!("{re} failed to compile: {e}"));
            assert!((0.0..=1.0).contains(score), "{re} has score {score}");
        }
        assert_eq!(PatternSet::defaults().len(), DEFAULT_PATTERNS.len());
    }

    #[test]
    fn known_prompts_score_as_specified() {
        let p = PatternSet::defaults();
        for (line, want) in [
            ("Password:", 0.95),
            // A real prompt is usually followed by blanks; this pins the
            // `\s*` in `\s*$`, which "Password:" alone cannot distinguish
            // from a bare `$`.
            ("Password:   ", 0.95),
            ("Password for alice:", 0.95),
            ("Enter passphrase for key '/home/a/.ssh/id_ed25519':", 0.95),
            ("Continue? [y/N] ", 0.9),
            (">>> ", 0.9),
            ("... ", 0.85),
            ("(Pdb) ", 0.95),
            ("mysql> ", 0.95),
            ("alice@build01:~/src$ ", 0.85),
            ("bash-5.3$ ", 0.6),
            ("# ", 0.6),
        ] {
            let got = p.score(line);
            assert!(
                (got - want).abs() < 1e-6,
                "{line:?}: got {got}, want {want}"
            );
        }
    }

    #[test]
    fn ordinary_output_scores_zero() {
        let p = PatternSet::defaults();
        for line in [
            "",
            "Compiling clasp-core v0.0.1",
            "warning: unused variable",
            "total 48",
            // Near-misses for the anchored rules. An anchor only bites at
            // the boundary, so a corpus of obviously-different lines pins
            // nothing: these carry the trigger token but run past it, and
            // a rule that fired here would be a confident wrong answer in
            // exactly the case tier 3 exists to cover.
            "Password: hunter2",
            "the Password: field is required",
            // Trailing whitespace must not rescue a line that has already
            // continued past the colon: `\s*$` skips blanks, not content.
            "Password: hunter2   ",
            "see mysql> in the docs",
        ] {
            assert_eq!(p.score(line), 0.0, "{line:?} should not look like a prompt");
        }
    }

    #[test]
    fn the_highest_scoring_match_wins() {
        // "alice@host:~$ " matches both the full user@host rule (0.85) and
        // the bare "$" rule (0.6).
        let p = PatternSet::defaults();
        assert!((p.score("alice@host:~$ ") - 0.85).abs() < 1e-6);

        // The bundled table happens to be ordered by descending score, so
        // the assertion above would also pass for a "first match wins"
        // implementation. An appended pattern is not: this one is last in
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
    }
}
