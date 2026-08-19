//! The literal-prefix index and the in-flight secret scanner that the
//! **targeted holdback** (spec §4.1) is built on.
//!
//! The holdback boundary is not a byte count. It is the start of a secret
//! that is *still arriving*: bytes that match a known secret prefix, run
//! all the way to `buffer.head`, and do not yet satisfy the rule that
//! produced the prefix. When no such candidate exists — the overwhelming
//! majority of reads — the boundary is `buffer.head` and the holdback has
//! no observable effect at all.

use super::rules::RuleSet;
use std::collections::HashMap;

/// Cap on prefixes generated per rule by character-class expansion
/// (`prefilter_prefix_expansion_limit`, spec §4.2).
pub const DEFAULT_PREFIX_EXPANSION_LIMIT: usize = 64;

/// Prefixes shorter than this are too generic to be worth indexing: they
/// would hold back ordinary output without protecting anything.
pub const MIN_PREFIX_LEN: usize = 3;

/// Bytes a still-arriving value may contain by default: printable ASCII,
/// no space and no control characters. A rule marked `binary` (a PEM
/// block) opts out.
fn is_value_byte(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}

/// Whether `pattern` opens with `\b` (after an optional inline-flag
/// group). Together with a non-empty `derive_prefixes` result this means
/// the derived literal *is* the start of the match, so a candidate that
/// sits mid-word can never satisfy the rule.
pub fn starts_with_word_boundary(pattern: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let mut i = 0usize;
    if p.first() == Some(&'(') && p.get(1) == Some(&'?') {
        if let Some(close) = p.iter().position(|c| *c == ')') {
            let flags: String = p[2..close].iter().collect();
            if !flags.is_empty() && flags.chars().all(|c| "imsxuU-".contains(c)) {
                i = close + 1;
            }
        }
    }
    p.get(i) == Some(&'\\') && p.get(i + 1) == Some(&'b')
}

fn is_regex_meta(c: char) -> bool {
    matches!(
        c,
        '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | ']' | '{' | '}' | '|'
    )
}

/// Derive literal prefixes from a regex source by walking its leading
/// atoms (REQ-O-006). Stops at the first construct whose expansion is not
/// a fixed literal — a quantifier, a group, a range class — so the result
/// is always a set of strings every match must literally begin with.
///
/// `gh[pousr]_[0-9A-Za-z]{36,}` yields the five `gh?_` forms;
/// `github_pat_[0-9A-Za-z_]{40,}` yields `github_pat_`;
/// `(?:AKIA|ASIA)…` yields nothing (the rule declares its prefixes).
pub fn derive_prefixes(pattern: &str, limit: usize) -> Vec<Vec<u8>> {
    let p: Vec<char> = pattern.chars().collect();
    let mut i = 0usize;

    // A leading inline-flag group, e.g. `(?i)`, consumes no input.
    if p.first() == Some(&'(') && p.get(1) == Some(&'?') {
        if let Some(close) = p.iter().position(|c| *c == ')') {
            let flags: String = p[2..close].iter().collect();
            if !flags.is_empty() && flags.chars().all(|c| "imsxuU-".contains(c)) {
                i = close + 1;
            }
        }
    }
    // Zero-width anchors likewise.
    loop {
        match (p.get(i), p.get(i + 1)) {
            (Some('^'), _) => i += 1,
            (Some('\\'), Some('b')) | (Some('\\'), Some('A')) => i += 2,
            _ => break,
        }
    }

    let mut branches: Vec<Vec<u8>> = vec![Vec::new()];
    while let Some(&c) = p.get(i) {
        // Parse exactly one atom, and the index just past it.
        let (atom, next): (Vec<char>, usize) = match c {
            '[' => {
                // Only a plain enumeration of literals expands. Anything
                // with a range, negation, or escape ends the derivation.
                let Some(end_rel) = p[i..].iter().position(|c| *c == ']') else {
                    break;
                };
                let end = i + end_rel;
                let inner: Vec<char> = p[i + 1..end].to_vec();
                if inner.is_empty()
                    || inner
                        .iter()
                        .any(|c| matches!(c, '^' | '-' | '\\' | '[' | ']'))
                {
                    break;
                }
                (inner, end + 1)
            }
            '\\' => {
                let Some(&e) = p.get(i + 1) else { break };
                // `\d`, `\s`, `\w` … are classes, not literals.
                if e.is_ascii_alphanumeric() {
                    break;
                }
                (vec![e], i + 2)
            }
            _ if is_regex_meta(c) => break,
            _ => (vec![c], i + 1),
        };

        // A quantifier binds to the atom we just parsed, which makes that
        // atom optional or repeated — so it cannot be part of a prefix.
        if matches!(p.get(next), Some('?') | Some('*') | Some('+') | Some('{')) {
            break;
        }
        if atom.iter().any(|c| !c.is_ascii()) {
            break;
        }
        if branches.len() * atom.len() > limit {
            break;
        }

        let mut expanded = Vec::with_capacity(branches.len() * atom.len());
        for branch in &branches {
            for a in &atom {
                let mut next_branch = branch.clone();
                next_branch.push(*a as u8);
                expanded.push(next_branch);
            }
        }
        branches = expanded;
        i = next;
    }

    branches.retain(|b| b.len() >= MIN_PREFIX_LEN);
    branches.sort();
    branches.dedup();
    branches
}

#[derive(Debug)]
struct Candidate {
    prefix: Vec<u8>,
    rule: usize,
    /// The rule's own pattern opens with `\b` at this literal, so a match
    /// can only begin where a word boundary does. Without this, `\bsk-…`
    /// treats `disk-usage` as an in-flight OpenAI key and `\bcio…` treats
    /// `spacious` as an in-flight crates.io token — measured at ~11% of
    /// chunk boundaries in ordinary output, which would make `held_back`
    /// routine (§4.1 names that as the rev. 10–14 failure).
    requires_word_boundary: bool,
}

/// Literal secret prefixes, bucketed by first byte for a cheap scan.
///
/// Matching is ASCII-case-insensitive throughout. Rules carrying `(?i)`
/// (every context rule does) would otherwise need per-prefix case
/// metadata, and over-matching here is safe in one direction only: it can
/// make the holdback engage on text that was never going to become a
/// secret, which self-heals the moment a space or newline arrives. It can
/// never cause a secret to be released early.
#[derive(Debug)]
pub struct PrefixIndex {
    by_first_byte: HashMap<u8, Vec<Candidate>>,
    total: usize,
}

impl PrefixIndex {
    pub fn build(rules: &RuleSet, expansion_limit: usize) -> Self {
        let mut by_first_byte: HashMap<u8, Vec<Candidate>> = HashMap::new();
        let mut total = 0usize;
        for (idx, rule) in rules.rules.iter().enumerate() {
            let derived = derive_prefixes(&rule.pattern, expansion_limit);
            // A derivable leading literal means the prefix is where the
            // match starts, so the pattern's own `\b` applies to it. When
            // derivation yields nothing (a leading group, or the context
            // rules whose declared prefixes sit *inside* the match) the
            // boundary belongs somewhere else and must not be demanded.
            let requires_word_boundary =
                !derived.is_empty() && starts_with_word_boundary(&rule.pattern);
            let prefixes = match &rule.declared_prefixes {
                Some(declared) => declared.clone(),
                None => derived,
            };
            for prefix in prefixes {
                if prefix.len() < MIN_PREFIX_LEN {
                    continue;
                }
                total += 1;
                by_first_byte
                    .entry(prefix[0].to_ascii_lowercase())
                    .or_default()
                    .push(Candidate {
                        prefix,
                        rule: idx,
                        requires_word_boundary,
                    });
            }
        }
        // Longest prefix first, so the most specific rule claims a
        // position when several share a first byte.
        for bucket in by_first_byte.values_mut() {
            bucket.sort_by_key(|c| std::cmp::Reverse(c.prefix.len()));
        }
        Self {
            by_first_byte,
            total,
        }
    }

    pub fn len(&self) -> usize {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Prefixes indexed for a given rule name — for tests and `doctor`.
    pub fn prefixes_for(&self, rules: &RuleSet, rule_name: &str) -> Vec<Vec<u8>> {
        let Some(idx) = rules.rules.iter().position(|r| r.name == rule_name) else {
            return Vec::new();
        };
        let mut out: Vec<Vec<u8>> = self
            .by_first_byte
            .values()
            .flatten()
            .filter(|c| c.rule == idx)
            .map(|c| c.prefix.clone())
            .collect();
        out.sort();
        out
    }

    /// Absolute offset of the earliest in-flight secret prefix in
    /// `region`, whose first byte sits at absolute offset `region_start`
    /// and whose last byte is the last byte in the buffer (spec §4.1).
    ///
    /// A position qualifies when all three hold:
    ///
    /// 1. an indexed prefix matches there and **at least one** value byte
    ///    has arrived after it — a bare `ghp_` carries no secret material
    ///    and is not withheld;
    /// 2. every byte from the prefix to the end of the region could still
    ///    belong to the value, so `ghp_abc def` (a space arrived) is not a
    ///    token in flight and releases immediately;
    /// 3. the rule's own anchored regex does **not** match yet. Once the
    ///    whole token has landed the redactor covers it, so there is
    ///    nothing left to withhold. Using the rule's own regex is what
    ///    keeps this test from drifting away from the rule.
    pub fn earliest_partial(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        for (i, byte) in region.iter().enumerate() {
            let Some(bucket) = self.by_first_byte.get(&byte.to_ascii_lowercase()) else {
                continue;
            };
            for candidate in bucket {
                // `\b` in the rule means the match cannot start mid-word.
                // Position 0 is treated as a boundary: the region is a
                // window, so the byte before it is not available and
                // over-holding by one position is the safe direction.
                if candidate.requires_word_boundary
                    && i > 0
                    && (region[i - 1].is_ascii_alphanumeric() || region[i - 1] == b'_')
                {
                    continue;
                }
                let value_start = i + candidate.prefix.len();
                // Needs the whole prefix plus at least one value byte.
                if value_start >= region.len() {
                    continue;
                }
                if !region[i..value_start].eq_ignore_ascii_case(&candidate.prefix) {
                    continue;
                }
                let rule = &rules.rules[candidate.rule];
                if !rule.binary && !region[value_start..].iter().all(|b| is_value_byte(*b)) {
                    continue;
                }
                if rule.anchored.is_match(&region[i..]) {
                    continue;
                }
                return Some(region_start + i as u64);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::rules::RuleSet;

    fn s(v: &[Vec<u8>]) -> Vec<String> {
        v.iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }

    #[test]
    fn character_class_expands_into_one_prefix_per_alternative() {
        let got = derive_prefixes(r"\bgh[pousr]_[0-9A-Za-z]{36,}", 64);
        let mut want = vec!["gho_", "ghp_", "ghr_", "ghs_", "ghu_"];
        want.sort();
        assert_eq!(s(&got), want);
    }

    #[test]
    fn a_literal_run_yields_one_prefix() {
        assert_eq!(
            s(&derive_prefixes(r"\bgithub_pat_[0-9A-Za-z_]{40,}", 64)),
            vec!["github_pat_"]
        );
        assert_eq!(
            s(&derive_prefixes(r"\bsk-ant-[A-Za-z0-9_-]{24,}", 64)),
            vec!["sk-ant-"]
        );
    }

    #[test]
    fn inline_flags_and_escaped_punctuation_are_handled() {
        assert_eq!(
            s(&derive_prefixes(
                r#"(?i)dd_api_key["'\s]*[:=]\s*(?P<value>[a-f0-9]{32})"#,
                64
            )),
            vec!["dd_api_key"]
        );
        assert_eq!(
            s(&derive_prefixes(r"\bya29\.[0-9A-Za-z_-]{20,}", 64)),
            vec!["ya29."]
        );
    }

    #[test]
    fn derivation_stops_before_a_quantified_atom() {
        // The trailing `A` is quantified, so it is not part of the prefix.
        assert_eq!(s(&derive_prefixes(r"\bxyzA{2,4}", 64)), vec!["xyz"]);
        // A leading group is not a literal at all.
        assert!(derive_prefixes(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}", 64).is_empty());
    }

    #[test]
    fn short_prefixes_are_dropped() {
        // `ab` is below MIN_PREFIX_LEN: too generic to index.
        assert!(derive_prefixes(r"\bab[0-9]{10}", 64).is_empty());
    }

    #[test]
    fn the_expansion_cap_is_enforced() {
        // Five 2-way classes want 32 prefixes; a cap of 8 stops the walk
        // at the last expansion that still fits.
        let got = derive_prefixes(r"x[ab][ab][ab][ab][ab]", 8);
        assert_eq!(got.len(), 8);
        assert!(got.iter().all(|p| p.len() == 4), "{:?}", s(&got));
        // The same pattern under the shipped cap expands all the way.
        assert_eq!(derive_prefixes(r"x[ab][ab][ab][ab][ab]", 64).len(), 32);
    }

    #[test]
    fn the_index_covers_declared_and_derived_prefixes() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert_eq!(
            s(&index.prefixes_for(&rules, "github-token")),
            vec!["gho_", "ghp_", "ghr_", "ghs_", "ghu_"],
            "derived from the pattern"
        );
        assert_eq!(
            s(&index.prefixes_for(&rules, "aws-access-key-id")),
            vec!["ABIA", "ACCA", "AKIA", "ASIA"],
            "declared in TOML because the pattern starts with a group"
        );
        assert!(index.len() > 40, "index has {} prefixes", index.len());
    }

    /// The §11.4 "partial-secret prefix index" table, executable.
    #[test]
    fn the_in_flight_table_from_the_spec() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let cases: &[(&str, bool, &str)] = &[
            ("ghp_abcdef", true, "partial, below the GitHub minimum"),
            (
                "ghp_0123456789abcdefghijABCDEFGHIJ012345",
                false,
                "complete: the redactor covers it",
            ),
            ("ghp_", false, "bare prefix carries no secret material"),
            ("hello world", false, "ordinary text"),
            ("ghp_abc def", false, "a space ended the candidate"),
        ];
        for (input, expect_hold, why) in cases {
            let got = index.earliest_partial(&rules, input.as_bytes(), 0);
            assert_eq!(got.is_some(), *expect_hold, "{input:?} ({why}) -> {got:?}");
        }
    }

    #[test]
    fn the_earliest_candidate_wins() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        // Two partials in flight; the boundary must be the first one.
        let region = b"ghp_abc sk-ant-xy";
        // The first candidate is followed by a space, so only the second
        // is genuinely in flight.
        assert_eq!(index.earliest_partial(&rules, region, 100), Some(108));
        // With no space, the earlier one qualifies and wins.
        let region = b"ghp_abcsk-ant-xy";
        assert_eq!(index.earliest_partial(&rules, region, 100), Some(100));

        // …and now the ordering itself, which neither case above pins.
        // Measured: reversing the candidate loop (`.enumerate().rev()`)
        // leaves the **whole workspace** green against the two fixtures
        // above, because each of them has exactly one candidate that
        // qualifies — in the first the space kills `ghp_`, and in the
        // second `sk-ant-` sits mid-word behind a `c` and its rule's `\b`
        // forbids it. A scan that walks backwards answers both
        // identically, so "earliest" was a claim in the name only.
        //
        // This fixture separates the two directions: `/` is a word
        // boundary *and* a legal value byte, so `ghp_` and `sk-ant-` both
        // qualify at the same time and only a left-to-right scan reports
        // the first one.
        let region = b"ghp_abc/sk-ant-xy";
        assert_eq!(
            index.earliest_partial(&rules, &region[7..], 107),
            Some(108),
            "the later candidate must qualify on its own, or the assertion \
             below separates earliest-from-nothing rather than earliest-from-latest"
        );
        assert_eq!(
            index.earliest_partial(&rules, region, 100),
            Some(100),
            "both candidates qualify, so the earlier one is the boundary"
        );
    }

    #[test]
    fn offsets_are_absolute() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let region = b"building...\nghp_abcdef";
        assert_eq!(
            index.earliest_partial(&rules, region, 1_000_000),
            Some(1_000_012),
            "the offset must be region_start + index, not the index"
        );
    }

    /// REQ-O-006: user rules feed the index, so a site-specific token
    /// gets the same in-flight protection as a built-in one.
    #[test]
    fn user_rules_contribute_to_the_index() {
        let rules = RuleSet::builtin_with_extra(
            r#"
            [[rule]]
            name = "internal-token"
            kind = "acme-internal"
            pattern = '''\bINT_[A-Z0-9]{10,}'''
            positive = ["INT_ABCDEFGHIJ"]
            negative = ["INT_ABC"]
            "#,
        )
        .unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert_eq!(
            s(&index.prefixes_for(&rules, "internal-token")),
            vec!["INT_"]
        );
        assert_eq!(index.earliest_partial(&rules, b"INT_ABC", 0), Some(0));
        assert_eq!(
            index.earliest_partial(&rules, b"INT_ABCDEFGHIJ", 0),
            None,
            "complete token: nothing left to withhold"
        );
    }

    /// `\b` in a rule means its match cannot begin mid-word, and the
    /// index must honour that. Without it `disk-usage` reads as an
    /// in-flight OpenAI key (`\bsk-`) and `spacious` as an in-flight
    /// crates.io token (`\bcio`) — measured at ~11% of chunk boundaries
    /// in near-miss output, which is exactly the "held_back becomes
    /// routine" failure §4.1 attributes to revisions 10–14.
    #[test]
    fn a_prefix_sitting_mid_word_is_not_a_candidate() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        for text in ["df: 42% disk-usa", "a spacio", "the task-runn", "risk-fre"] {
            assert_eq!(
                index.earliest_partial(&rules, text.as_bytes(), 0),
                None,
                "{text:?} can never satisfy the rule: its `\\b` forbids a mid-word match"
            );
        }
        // The same literal at a real word boundary still qualifies, so
        // the fix removes impossible candidates rather than the feature.
        assert_eq!(
            index.earliest_partial(&rules, b"printf sk-AAA", 0),
            Some(7),
            "a genuine in-flight token must still set the boundary"
        );
    }

    #[test]
    fn the_leading_word_boundary_is_detected_through_inline_flags() {
        assert!(starts_with_word_boundary(r"\bghp_[0-9A-Za-z]{36,}"));
        assert!(starts_with_word_boundary(r"(?i)\bcloudflare[a-z]{0,4}"));
        assert!(!starts_with_word_boundary(r"(?i)bearer\s+(?P<value>.+)"));
        assert!(!starts_with_word_boundary(r"-----BEGIN"));
    }

    /// The regression guard for the rev. 10–14 blanket holdback: a stream
    /// of realistic output must never produce a boundary.
    ///
    /// The corpus is deliberately *near-miss* heavy. A corpus of output
    /// containing no indexed prefix at all cannot tell a correct scanner
    /// from one that holds back on any prefix match — verified by deleting
    /// all three qualifying conditions and watching this test stay green
    /// against the sanitised version.
    #[test]
    fn ordinary_build_output_never_yields_a_boundary() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let lines = [
            "   Compiling holdfast-core v0.0.1 (/home/user/src/holdfast)",
            "    Finished `dev` profile [unoptimized + debuginfo] target(s) in 13.72s",
            "test output::rules::tests::the_prefilter_reports_matching_rule_indices ... ok",
            "warning: unused variable: `n` --> src/lib.rs:42:9",
            "$ git status --porcelain",
            " M crates/holdfast-core/src/output/mod.rs",
            "1234567890 bytes written to /tmp/build.log",
            // Near-misses: every one of these contains an indexed prefix.
            "   Compiling api-gateway v0.3.1 (/home/user/src/api-gateway)",
            "df -h reports 42% disk-usage on /dev/nvme0n1p2",
            "$ task-runner --config ./task-runner.toml run build",
            "a spacious, delicious and precious take on risk-taking",
            "[INFO] fetching next_token from the paginator",
            "$ curl -sS -H \"Authorization: Bearer $GH_TOKEN\" https://example.internal/v1",
        ];
        for line in lines {
            // Every prefix of every line: whatever the reader has seen so
            // far is a legal buffer state.
            for take in 1..=line.len() {
                let region = &line.as_bytes()[..take];
                assert_eq!(
                    index.earliest_partial(&rules, region, 0),
                    None,
                    "ordinary output must never be held back: {:?}",
                    &line[..take]
                );
            }
        }
    }

    /// The measured residual, pinned so it is visible rather than assumed
    /// absent. Each of these is a *legitimate* in-flight candidate — the
    /// rule really could still complete — and each releases the moment a
    /// byte arrives that the value cannot contain. Narrowing them needs
    /// the scanner to test continuation against the rule's own value class
    /// (`\bkey-[a-f0-9]` rejects `key-v`) rather than the generic
    /// printable-byte test; that is a follow-up, not a 0.0.3 change.
    ///
    /// This test exists so that follow-up has to update it deliberately.
    #[test]
    fn the_known_transient_holdbacks_are_pinned() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        for text in [
            "use crate::re_exports", // resend `\bre_`
            "parsing key-value",     // mailgun `\bkey-`
            "$ echo $POWERSYNC_",    // powersync context rule
        ] {
            assert!(
                index.earliest_partial(&rules, text.as_bytes(), 0).is_some(),
                "expected the documented residual for {text:?}"
            );
            // Self-healing: one byte the value cannot contain releases it.
            let released = format!("{text} ");
            assert_eq!(
                index.earliest_partial(&rules, released.as_bytes(), 0),
                None,
                "the candidate must die as soon as a space arrives: {released:?}"
            );
        }
    }
}
