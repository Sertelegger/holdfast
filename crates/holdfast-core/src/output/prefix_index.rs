//! The literal-prefix index and the in-flight secret scanner that the
//! **targeted holdback** (spec §4.1) is built on.
//!
//! The holdback boundary is not a byte count. It is the start of a secret
//! that is *still arriving*: bytes that match a known secret prefix, run
//! all the way to `buffer.head`, and do not yet satisfy the rule that
//! produced the prefix. When no such candidate exists — the overwhelming
//! majority of reads — the boundary is `buffer.head` and the holdback has
//! no observable effect at all.
//!
//! `buffer.head` is not the only place the redactor's evidence runs out.
//! A read judges a *window*, and `redaction_lookahead_bytes` ends that
//! window early; a match that begins inside it and ends outside it is
//! invisible to `find_spans` and comes back raw (GH #14).
//! [`PrefixIndex::unresolved_from`] asks the same in-flight question at
//! that edge, and answers it for rules with no indexed prefix as well,
//! which is the half no window size reaches.

use super::rules::RuleSet;
use regex_automata::{
    dfa::{dense, Automaton, StartKind},
    util::syntax,
    Anchored, Input,
};
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
///
/// **Superseded for most rules by [`PrefixIndex::still_alive`] (GH #142)**
/// and kept for the three places that outlive it: the nine
/// `has_value_group` context rules on the raw stream (GH #152),
/// [`trailing_value_run_start`], and the fallback when a rule's liveness
/// automaton could not be built.
fn is_value_byte(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}

/// The pattern a rule's **liveness** automaton is built from: the rule's
/// own source with every `\b` rewritten to its ASCII-only spelling, or
/// `None` for a pattern this rewrite cannot be trusted on.
///
/// The rewrite is the difference between a usable predicate and one that
/// is *worse* than the byte-class test it replaces. A Unicode word
/// boundary cannot be compiled into a DFA at all without the quit set —
/// every byte ≥ 0x80 becomes a quit byte, a quit must be read as ALIVE
/// for soundness, and the result holds back any output carrying a glyph.
/// With the ASCII spelling there is no quit set, and the predicate is
/// exact on everything the rules can actually match.
///
/// **Why the substitution cannot release a secret early.** `\b` is
/// *"exactly one side is a word character"*, and the two spellings differ
/// only where one of those sides is a non-ASCII byte, which
/// `(?-u:\b)` reads as a non-word byte and `\b` may read as a word
/// character. Two cases, and both are safe:
///
/// * **At the candidate's own leading boundary** the other side is the
///   indexed prefix's first byte, which is an ASCII word byte
///   (`every_rule_compiles_a_liveness_automaton` asserts it, for user
///   rules too). `\b` then reduces to *"the byte behind is not a word
///   character"*, and "not an **ASCII** word byte" is a superset of "not
///   a **Unicode** word character" — so `(?-u:\b)` holds wherever `\b`
///   does and liveness over-approximates.
/// * **At any later boundary** the divergence needs a non-ASCII byte at
///   or after the first value byte — and [`is_value_byte`], the predicate
///   this replaces, already releases the candidate on *any* such byte.
///   Wherever the rewrite could under-approximate, the shipped test had
///   already let go.
///
/// **`\B` gets no such argument, so a pattern carrying one gets no
/// automaton.** `\B` is the negation, so the ASCII spelling
/// *under*-approximates by the same reasoning, and at a *leading* `\B`
/// the divergent byte sits behind the candidate where `is_value_byte`
/// never looked. No shipped rule uses one; a user rule that does keeps
/// the byte-class test, which is what it has today.
///
/// The walk tracks escapes rather than calling `str::replace`, so a
/// pattern containing `\\b` — an escaped backslash followed by a literal
/// `b` — keeps its meaning instead of acquiring a word boundary it never
/// had.
fn liveness_pattern(pattern: &str) -> Option<String> {
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('b') => out.push_str("(?-u:\\b)"),
            Some('B') => return None,
            Some(escaped) => {
                out.push('\\');
                out.push(escaped);
            }
            None => out.push('\\'),
        }
    }
    Some(out)
}

/// A rule's liveness automaton, or `None` when it could not be built.
///
/// **Dense rather than lazy, and that choice is what keeps this type
/// behind its `Arc`.** A `dfa::dense::DFA` owns no mutable search state,
/// so it is `Send + Sync` and [`PrefixIndex::still_alive`] stays `&self`;
/// the lazy `hybrid` DFA needs `&mut Cache` on every transition, which
/// would put a cache pool between `OutputProcessor` — one per daemon,
/// shared by every read path — and its callers.
///
/// A failure is not an error: the caller falls back to [`is_value_byte`],
/// which is the shipped predicate and holds *more* than liveness does.
fn build_liveness(pattern: &str) -> Option<dense::DFA<Vec<u32>>> {
    dense::Builder::new()
        .configure(
            dense::DFA::config()
                // The search always starts at a known candidate offset,
                // so the unanchored start state is dead weight — and
                // building it is what made an earlier probe report this
                // engine as unusable at 9.9 GB of resident memory.
                .start_kind(StartKind::Anchored)
                // Explicit, though it is also the default: a Unicode word
                // boundary must fail to build here rather than silently
                // install a quit set. `liveness_pattern` has removed the
                // last one, and this is what keeps a future rule from
                // reintroducing it unnoticed.
                .unicode_word_boundary(false),
        )
        .syntax(syntax::Config::new().utf8(false))
        .build(&liveness_pattern(pattern)?)
        .ok()
}

/// Whether a rule's holdback, opened at `prefix`, can only last for a
/// bounded number of further bytes — the gate that decides which rules a
/// **view** may drive a withhold for (GH #142).
///
/// **Why boundedness is the criterion.** On the raw stream a holdback is
/// self-healing: the byte that kills the candidate is the same byte the
/// caller was waiting to receive, so a candidate that will never complete
/// dies as soon as the next delimiter lands. A view deletes control
/// bytes, which is to say *it deletes the predicate's own escape hatch* —
/// so on a view the question is not "will this candidate die?" but "can
/// it be kept alive for ever?". `\beyJ[A-Za-z0-9_-]{10,}\.eyJ…` can: an
/// unbounded run of base64 stands between its prefix and the `.` it still
/// needs, so `\x1b]0;eyJxxxx\x07` strands the caller permanently in the
/// stream that drops the BEL.
///
/// Mechanically that is a **cycle** in the subgraph of states that are
/// neither dead nor matching. Dead states have already released the
/// candidate; a match state is not withheld either, because
/// [`PrefixIndex::earliest_partial`]'s condition 3 skips a rule whose
/// token has landed. Anything reachable and outside both, that reaches
/// itself, is an unbounded holdback.
///
/// **Computed, never declared.** Twelve of the fifty-one shipped rules
/// fail this, and a hand-written list of those twelve would silently
/// mis-gate every rule an operator adds through `extra_redaction_patterns`
/// — in the unsafe direction, since a rule absent from the list would be
/// gated by default.
///
/// The alphabet is every byte. A view can only ever carry a subset of
/// those, and a larger alphabet finds more cycles, so this is the
/// conservative reading; it also avoids the trap that classifying over
/// `0x21..=0x7e` alone — no space — loses `bearer-authorization`, whose
/// only cycle is the `\s+` after its keyword.
fn holdback_is_bounded(dfa: &dense::DFA<Vec<u32>>, prefix: &[u8]) -> bool {
    let input = Input::new(prefix).anchored(Anchored::Yes);
    let Ok(mut sid) = dfa.start_state_forward(&input) else {
        return false;
    };
    for byte in prefix {
        sid = dfa.next_state(sid, *byte);
        if dfa.is_dead_state(sid) || dfa.is_match_state(sid) {
            return true;
        }
        if dfa.is_quit_state(sid) {
            return false;
        }
    }
    // Iterative depth-first search, colouring grey on the way down and
    // black on the way back up: a grey successor is a back edge, which is
    // a cycle.
    let mut colour: HashMap<usize, bool> = HashMap::new();
    let mut stack: Vec<(_, u16)> = vec![(sid, 0u16)];
    colour.insert(sid.as_usize(), true);
    while let Some(top) = stack.last_mut() {
        if top.1 > u8::MAX as u16 {
            let done = top.0;
            stack.pop();
            colour.insert(done.as_usize(), false);
            continue;
        }
        let (from, byte) = (top.0, top.1 as u8);
        top.1 += 1;
        let to = dfa.next_state(from, byte);
        if dfa.is_dead_state(to) || dfa.is_match_state(to) {
            continue;
        }
        if dfa.is_quit_state(to) {
            return false;
        }
        match colour.get(&to.as_usize()) {
            Some(true) => return false,
            Some(false) => continue,
            None => {
                colour.insert(to.as_usize(), true);
                stack.push((to, 0));
            }
        }
    }
    true
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
    /// One liveness automaton per rule, parallel to `rules.rules`. See
    /// [`build_liveness`]; `None` means the rule keeps [`is_value_byte`].
    liveness: Vec<Option<dense::DFA<Vec<u32>>>>,
    /// Whether each rule may drive a **view**-based withhold, computed by
    /// [`holdback_is_bounded`] at build time. Parallel to `rules.rules`.
    gated: Vec<bool>,
}

impl PrefixIndex {
    pub fn build(rules: &RuleSet, expansion_limit: usize) -> Self {
        let mut by_first_byte: HashMap<u8, Vec<Candidate>> = HashMap::new();
        let mut total = 0usize;
        let liveness: Vec<Option<dense::DFA<Vec<u32>>>> = rules
            .rules
            .iter()
            .map(|rule| build_liveness(&rule.pattern))
            .collect();
        let mut gated: Vec<bool> = Vec::with_capacity(rules.rules.len());
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
            // Whether this rule's holdback is bounded is a question about
            // its automaton driven from each of *its own* prefixes, so the
            // answer is accumulated here rather than re-derived from
            // `by_first_byte` afterwards.
            //
            // **An empty `all` is `true`, and that is the honest answer
            // rather than a convenience.** A rule with no indexed prefix
            // — `telegram-bot-token` is the whole of that set — can never
            // become a candidate, so it has no holdback for a view to
            // strand and the flag is unobservable either way.
            let mut bounded = true;
            for prefix in prefixes {
                if prefix.len() < MIN_PREFIX_LEN {
                    continue;
                }
                bounded &= match &liveness[idx] {
                    Some(dfa) => holdback_is_bounded(dfa, &prefix),
                    // No automaton, no proof. `is_value_byte` on the raw
                    // stream is what this rule keeps, and a view may not
                    // drive it.
                    None => false,
                };
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
            gated.push(bounded);
        }
        // Longest prefix first, so the most specific rule claims a
        // position when several share a first byte.
        for bucket in by_first_byte.values_mut() {
            bucket.sort_by_key(|c| std::cmp::Reverse(c.prefix.len()));
        }
        Self {
            by_first_byte,
            total,
            liveness,
            gated,
        }
    }

    /// Whether rule `rule` could still match if `region` grew — asked at
    /// absolute position `at` within it (GH #142).
    ///
    /// This is the sharp form of *"every byte from the indexed prefix to
    /// the end of the region could still belong to the value"*. The
    /// byte-class test it replaces answers with a single range, which is
    /// wrong in both directions at once: it holds runs no rule could ever
    /// complete, and it releases the moment a control byte lands inside a
    /// value that is genuinely still arriving.
    ///
    /// **Four things this gets right, each of which is a way to get it
    /// wrong.**
    ///
    /// 1. **`next_eoi_state` is never called.** *"The haystack may
    ///    grow"* is exactly *"do not walk end-of-input"*. Walking it asks
    ///    whether the rule matches the bytes that have arrived, which for
    ///    `ghp_` plus 39 of 40 characters answers DEAD — and releases the
    ///    secret this function exists to hold.
    /// 2. **The look-behind arrives by range, not by re-slicing.**
    ///    `Input::range(at..)` lets the automaton read `region[at - 1]`
    ///    when it decides the leading `\b`; handing it `&region[at..]`
    ///    instead makes every candidate look like the start of the
    ///    haystack, so `xghp_0123` reads as live when its `\b` forbids it.
    /// 3. **A match is not the same question.** Liveness is stale the
    ///    instant the rule matches, which is why the caller keeps its
    ///    separate anchored-match test rather than folding it in here.
    /// 4. **A quit state is ALIVE.** With the ASCII word boundary
    ///    [`liveness_pattern`] installs there is no quit set and the arm
    ///    is unreachable, but reading a quit as DEAD would release an
    ///    in-flight secret the moment a glyph appeared near it, so the arm
    ///    is written rather than assumed away.
    fn still_alive(&self, rule: usize, region: &[u8], at: usize) -> bool {
        let Some(dfa) = self.liveness.get(rule).and_then(Option::as_ref) else {
            return region[at..].iter().all(|b| is_value_byte(*b));
        };
        let input = Input::new(region).range(at..).anchored(Anchored::Yes);
        // The only failure `start_state_forward` reports is a quit byte in
        // the look-behind — rule 4 above.
        let Ok(mut sid) = dfa.start_state_forward(&input) else {
            return true;
        };
        for byte in &region[at..] {
            sid = dfa.next_state(sid, *byte);
            if dfa.is_dead_state(sid) {
                return false;
            }
            if dfa.is_quit_state(sid) {
                return true;
            }
        }
        true
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
    /// 2. the rule could still match if more bytes arrived
    ///    ([`Self::still_alive`]), so `ghp_abc def` is not a token in
    ///    flight and neither is `parsing key-value` — `v` is not a hex
    ///    digit and `\bkey-[a-f0-9]{32}` can never reach it (GH #142);
    /// 3. the rule's own anchored regex does **not** match yet. Once the
    ///    whole token has landed the redactor covers it, so there is
    ///    nothing left to withhold. Using the rule's own regex is what
    ///    keeps this test from drifting away from the rule.
    ///
    /// **Two rule classes keep the old byte-class test on this — the
    /// raw — stream, and the second of them is why GH #152 stays open.**
    /// A `binary` rule opts out of condition 2 entirely, as before: a PEM
    /// body's newlines defeat any value-run test at every line. And the
    /// nine `has_value_group` context rules keep [`is_value_byte`],
    /// because their patterns legitimately admit whitespace between the
    /// label and the value — so liveness reports `Password: ` alive, and
    /// a candidate that can still grow never dies at the end of a region
    /// that has stopped growing. Measured: applying liveness there takes
    /// `earliest_partial` on `"$ ssh dev@box\r\nPassword: "` from `None`
    /// to `Some(15)`, `read_output` returns only the first line with
    /// `held_back: true`, `prompt.last_line` becomes `""`, and three
    /// shipped pty fixtures hang. A shell sitting at a password prompt is
    /// the most common state this tool exists to handle. GH #152 asks for
    /// the narrower widening that would fix it; the coupling is recorded
    /// there rather than guessed at here.
    pub fn earliest_partial(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        self.scan(rules, region, region_start, false)
    }

    /// [`Self::earliest_partial`] over a **normalised view** of a region
    /// rather than over the raw bytes, restricted to the rules whose
    /// holdback [`holdback_is_bounded`] can prove terminates (GH #142).
    ///
    /// The offset returned is relative to `region_start` as usual, so a
    /// caller passing a view's bytes with `region_start = 0` gets a
    /// view-relative index and maps it back with `NormalView::raw_offset`.
    ///
    /// **The restriction is the whole of the difference, and it is not an
    /// optimisation.** On the raw stream a candidate that will never
    /// complete is killed by the next delimiter, which is a byte the
    /// caller wanted anyway. A view has had its control bytes deleted, so
    /// for a rule with an unbounded holdback there may be no byte left
    /// that can ever end it — `\x1b]0;SECRET_DONE\x07` becomes
    /// `]0;SECRET_DONE`, nothing more arrives, and a withhold taken on
    /// that evidence is permanent. The twelve rules that fail the gate
    /// therefore keep GH #142's residual, loudly rather than quietly once
    /// GH #160 lands.
    ///
    /// Condition 2 is liveness for every rule here, with no `binary` or
    /// `has_value_group` arm: those classes exist because the byte-class
    /// test is the *safer* answer on the raw stream, and a rule that
    /// reaches this scan has already been proved unable to strand.
    pub fn earliest_partial_in_view(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        self.scan(rules, region, region_start, true)
    }

    fn scan(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
        in_view: bool,
    ) -> Option<u64> {
        for (i, byte) in region.iter().enumerate() {
            let Some(bucket) = self.by_first_byte.get(&byte.to_ascii_lowercase()) else {
                continue;
            };
            for candidate in bucket {
                if in_view && !self.gated[candidate.rule] {
                    continue;
                }
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
                let in_flight = if in_view {
                    self.still_alive(candidate.rule, region, i)
                } else if rule.binary {
                    true
                } else if rule.has_value_group {
                    region[value_start..].iter().all(|b| is_value_byte(*b))
                } else {
                    self.still_alive(candidate.rule, region, i)
                };
                if !in_flight {
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

    /// Absolute offset of the earliest byte in `region` the redactor
    /// **cannot vouch for**, given that whatever follows `region` was *not*
    /// available to the matcher (GH #14).
    ///
    /// [`Self::earliest_partial`] asks this question at `buffer.head`,
    /// where the bytes after the region do not exist yet. A **window** ends
    /// for a different reason — `redaction_lookahead_bytes` cut it — but
    /// the consequence is identical and worse: a match that begins inside
    /// the window and ends outside it is invisible to `find_spans`, so its
    /// bytes come back raw, with `redactions: {}` and no audit entry. A
    /// larger constant moves that edge and closes nothing.
    ///
    /// **Two detectors, and each reaches a case the other cannot.**
    ///
    /// * *Prefix-anchored* — [`Self::earliest_partial`], reused verbatim so
    ///   the two surfaces cannot drift. It is the only one that reaches a
    ///   rule marked `binary`, whose value may contain whitespace:
    ///   `private-key-block` is the whole of that set, and a PEM body's
    ///   newlines defeat the value-run test below at every line. It is also
    ///   the only one that can see an *opening anchor with no closing
    ///   anchor*, which is the shape GH #14 reports.
    /// * *Trailing value run* — [`trailing_value_run_start`]. A match that
    ///   runs off the end of the region covers every byte between its start
    ///   and that end, so for a non-`binary` rule it cannot begin before
    ///   the maximal trailing run of value bytes. That bound needs no
    ///   prefix, which makes it the only thing that reaches a rule with
    ///   **no index entry at all** — `\b[0-9]{4}-…` derives no literal and
    ///   declares none, so `earliest_partial` is structurally blind to it
    ///   and no lookahead constant changes that.
    ///
    /// **Deliberately sound in one direction only.** It over-reports: a
    /// long run of printable bytes that was never going to be a secret is
    /// named unresolved. Deciding what that costs is the caller's job, not
    /// this function's — `OutputProcessor::process` consults it only when
    /// the window really was cut short of `buffer.head`, and only lets it
    /// bite when the run reaches back past the entire lookahead margin,
    /// which ordinary output does not produce.
    pub fn unresolved_from(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        let anchored = self.earliest_partial(rules, region, region_start);
        let run = trailing_value_run_start(region).map(|i| region_start + i as u64);
        match (anchored, run) {
            (Some(a), Some(r)) => Some(a.min(r)),
            (a, r) => a.or(r),
        }
    }
}

/// Index of the first byte of the maximal trailing run of bytes that could
/// be *interior* to a non-`binary` rule's value, or `None` when `region`
/// ends on a byte no such value may contain.
///
/// The delimiter test is [`is_value_byte`] — the same one
/// [`PrefixIndex::earliest_partial`] uses to decide that a candidate is
/// still in flight — so one notion of "what a value may contain" serves
/// both, and narrowing it later narrows both together.
pub fn trailing_value_run_start(region: &[u8]) -> Option<usize> {
    let mut i = region.len();
    while i > 0 && is_value_byte(region[i - 1]) {
        i -= 1;
    }
    (i < region.len()).then_some(i)
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
        // **Re-pinned deliberately for GH #142**, from `Some(100)`.
        // `earliest_partial`'s continuation test used to be *printable
        // and not a space*, which `sk-ant-xy` satisfies, so `ghp_` read
        // as a GitHub token still arriving. It never was one:
        // `\bghp_[0-9A-Za-z]{36,}` cannot reach a `-`, and the rule's own
        // automaton says so. `sk-ant-` sits mid-word behind a `c` and its
        // `\b` forbids it. **The new expectation is that nothing here is
        // in flight at all** — not that a different candidate wins.
        let region = b"ghp_abcsk-ant-xy";
        assert_eq!(index.earliest_partial(&rules, region, 100), None);

        // …and now the ordering itself, which neither case above pins.
        // Measured: reversing the candidate loop (`.enumerate().rev()`)
        // leaves the **whole workspace** green against the two fixtures
        // above, because each of them has at most one candidate that
        // qualifies — in the first the space kills `ghp_`, and in the
        // second nothing qualifies at all. A scan that walks backwards
        // answers both identically, so "earliest" was a claim in the name
        // only.
        //
        // This fixture separates the two directions, and its shape is
        // GH #142's doing as well: the `/` the original used is a legal
        // value byte but not a legal *continuation* of a GitHub token, so
        // under liveness only one candidate survived it and the row
        // stopped separating anything. `password` is alphanumeric, so
        // `\bghp_[0-9A-Za-z]{36,}` is genuinely still able to match
        // across it, while `password` is `generic-secret-assignment`'s
        // own declared prefix and qualifies on its own account. Both are
        // in flight at the same instant and only a left-to-right scan
        // reports the first.
        let region = b"ghp_passwordX";
        assert_eq!(
            index.earliest_partial(&rules, &region[4..], 104),
            Some(104),
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

    /// GH #14: `unresolved_from` answers a question `earliest_partial`
    /// structurally cannot — *given that I could not see past the end of
    /// this region, from where can I not vouch for the bytes?* — and the
    /// reason it is a second function rather than a wider region passed to
    /// the first is that the answer must not depend on the rule having an
    /// indexed prefix.
    ///
    /// The fixture's first atom is a character *range*, so `derive_prefixes`
    /// yields nothing and the rule declares nothing: it has no entry in the
    /// index at all. `earliest_partial` is asserted blind to it here, which
    /// is what makes the second assertion a different fact rather than a
    /// restatement.
    #[test]
    fn a_value_run_reaching_the_regions_end_is_unresolved_with_no_prefix_at_all() {
        let rules = RuleSet::builtin_with_extra(
            r#"
            [[rule]]
            name = "gh14-envelope"
            kind = "acme-envelope"
            pattern = '''\b[0-9]{4}-ACMEBOX-[A-Za-z0-9+/=]{16,}-ENDACMEBOX'''
            positive = ["1234-ACMEBOX-abcdefghijklmnop-ENDACMEBOX"]
            negative = ["1234-ACMEBOX-short-ENDACMEBOX"]
            "#,
        )
        .unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert!(
            index.prefixes_for(&rules, "gh14-envelope").is_empty(),
            "the fixture must have no index entry, or this asserts the wrong half"
        );
        let region = b"$ dump\n1234-ACMEBOX-QUJDREVGR0hJSktM";
        assert_eq!(
            index.earliest_partial(&rules, region, 500),
            None,
            "with no indexed prefix the prefix-anchored scan cannot see this rule"
        );
        assert_eq!(
            index.unresolved_from(&rules, region, 500),
            Some(507),
            "the run of value bytes reaching the region's end begins after the newline"
        );
    }

    /// The paired direction, and what keeps the run bound from naming a
    /// boundary in every read: a region ending on a byte no value may
    /// contain has nothing in flight at its edge at all.
    #[test]
    fn a_region_ending_on_a_delimiter_leaves_nothing_unresolved() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let line = b"   Compiling holdfast-core\n";
        assert_eq!(trailing_value_run_start(line), None);
        assert_eq!(index.unresolved_from(&rules, line, 0), None);
        // Mid-word it is the word, which is the honest answer to the
        // question asked. Deciding that a partial word at the far end of an
        // 8 KiB lookahead margin is not worth declining belongs to
        // `OutputProcessor::process`; this function does not pretend to
        // know how far from the caller's range its own answer sits.
        assert_eq!(
            trailing_value_run_start(b"   Compiling holdfast-co"),
            Some(13)
        );
    }

    /// The measured residual, pinned so it is visible rather than assumed
    /// absent. Each of these is a *legitimate* in-flight candidate — the
    /// rule really could still complete — and each releases the moment a
    /// byte arrives that the value cannot contain.
    ///
    /// **The follow-up this test was written to force has landed, and one
    /// row has moved (GH #142).** The 0.0.3 note said narrowing these
    /// needed "the scanner to test continuation against the rule's own
    /// value class (`\bkey-[a-f0-9]` rejects `key-v`) rather than the
    /// generic printable-byte test"; that is now exactly what
    /// [`PrefixIndex::still_alive`] does, and `parsing key-value` has
    /// moved from the residual to
    /// `the_holdbacks_that_liveness_retired`. The two rows left are the
    /// two the change does **not** reach: `re_exports` really is a live
    /// `\bre_[A-Za-z0-9_]{24,}` prefix, and `$POWERSYNC_` belongs to a
    /// `has_value_group` context rule, which keeps the byte-class test on
    /// the raw stream (GH #152).
    #[test]
    fn the_known_transient_holdbacks_are_pinned() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        for text in [
            "use crate::re_exports", // resend `\bre_`
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

    /// The other half of the row above: what GH #142's predicate
    /// **stopped** withholding, pinned so it cannot silently come back.
    ///
    /// Both of these were held by the byte-class test and released by
    /// nothing until a delimiter arrived. Neither was ever a credential:
    /// `\bkey-[a-f0-9]{32}` cannot reach the `v` of `value`, and it
    /// cannot reach the `m` of `manager` either. The second is the shape
    /// that matters in practice — an npm progress line ending in an
    /// escape with no newline after it, which
    /// `ordinary_output_ending_in_an_escape_sequence_is_not_held_back`
    /// covers end to end.
    #[test]
    fn the_holdbacks_that_liveness_retired() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        for text in [
            "parsing key-value",           // mailgun `\bkey-`, `v` is not hex
            "npm WARN @acme/key-manager",  // the same rule, the real shape
            "a build of api-gateway v0.3", // `\b(?:sdk|mob|api)-` wants hex
        ] {
            assert_eq!(
                index.earliest_partial(&rules, text.as_bytes(), 0),
                None,
                "no rule can still match {text:?}, so nothing is in flight"
            );
        }
    }

    /// **A shell sitting at a password prompt must hand over the prompt
    /// (GH #142, GH #152).**
    ///
    /// This is the row the `has_value_group` carve-out exists for, and
    /// the suite has never had it. Removing that carve-out puts liveness
    /// on `generic-secret-assignment`, whose `["'\s]*[:=]\s*` legitimately
    /// admits the trailing space — so the candidate is alive, the region
    /// has stopped growing, and `earliest_partial` here goes `None` ->
    /// `Some(15)`. `read_output` then returns `"$ ssh dev@box\r\n"` with
    /// `held_back: true`, `safe_last_line` returns `""` through its
    /// case-2 gate, and `echo_off_prompts_with_and_without_canonical_mode`,
    /// `matrix_row_getpass_is_awaiting_secret_with_no_bracketed_paste_history`
    /// and `matrix_row_bash_read_s_is_awaiting_secret_and_flags_a_write`
    /// all fail on their 20-second deadlines.
    ///
    /// The second row is the same defect **still open on `main`**, kept
    /// visible rather than assumed absent: with no trailing space the `:`
    /// is inside `0x21..=0x7e`, so the byte-class test holds nine bytes
    /// permanently. The three pty fixtures miss it only because all three
    /// of their prompts happen to end in a space. GH #152 owns it.
    #[test]
    fn a_password_prompt_at_head_is_not_withheld() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let at_prompt = b"$ ssh dev@box\r\nPassword: ";
        assert!(
            index
                .prefixes_for(&rules, "generic-secret-assignment")
                .contains(&b"password".to_vec()),
            "the premise: `password` is an indexed prefix, so the line really \
             does offer the scanner a candidate"
        );
        assert_eq!(
            index.earliest_partial(&rules, at_prompt, 0),
            None,
            "a password prompt is not a credential in flight"
        );
        // The pre-existing defect, pinned rather than fixed here.
        assert_eq!(
            index.earliest_partial(&rules, b"$ ssh dev@box\r\nEnter password:", 0),
            Some(21),
            "GH #152: with no trailing space the `:` keeps the byte-class \
             run alive, so the last nine bytes are withheld permanently"
        );
    }

    /// User rules shaped to break the GH #142 liveness engine rather than
    /// to exercise it: an **interior** word boundary (the shipped set has
    /// one only on the context rules), a `\B` (the shipped set has none
    /// at all), an escaped backslash immediately before a `b` (which a
    /// `str::replace` rewrite corrupts), and a case-folded pattern.
    ///
    /// REQ-O-006 puts `extra_redaction_patterns` through every mechanism
    /// this work adds — the automaton, the soundness lemma and the gate —
    /// and the shipped fifty-one cannot supply that coverage, so these do.
    const ADVERSARIAL_USER_RULES: &str = r#"
        [[rule]]
        name = "acme-interior-boundary"
        kind = "acme-internal"
        pattern = '''\bACMEIB-[A-Z]{4}\b-[0-9]{8}'''
        positive = ["ACMEIB-ABCD-01234567"]
        negative = ["ACMEIB-ABCD"]

        [[rule]]
        name = "acme-negated-boundary"
        kind = "acme-internal"
        pattern = '''\bACMENB-[A-Z0-9]{6}\B[0-9]{6}'''
        positive = ["ACMENB-ABCDEF123456"]
        negative = ["ACMENB-ABCDEF"]

        [[rule]]
        name = "acme-escaped-backslash"
        kind = "acme-internal"
        pattern = '''\bACMEESC-\\bkey[0-9]{8}'''
        positive = ['''ACMEESC-\bkey12345678''']
        negative = ["ACMEESC-bkey12345678"]

        [[rule]]
        name = "acme-folded"
        kind = "acme-internal"
        pattern = '''(?i)\bacmefold_[a-z0-9]{20,}'''
        positive = ["ACMEFOLD_abcdefghij0123456789"]
        negative = ["acmefold_short"]
    "#;

    /// The span of `positive` that `rule` actually matches — the haystack
    /// a liveness drive is entitled to be asked about. A rule's example
    /// carries its context (`export DB_PASSWORD=hunter2hunter2`), and
    /// driving from the `e` of `export` would ask a different question.
    fn matched_span<'a>(rule: &super::super::rules::CompiledRule, positive: &'a str) -> &'a str {
        let m = rule
            .regex
            .find(positive.as_bytes())
            .unwrap_or_else(|| panic!("{}: its own positive example must match", rule.name));
        &positive[m.start()..m.end()]
    }

    /// GH #142's engine: every rule gets a liveness automaton, and the
    /// two structural facts that make the ASCII word boundary sound.
    ///
    /// **Why `(?-u:\b)` and not `\b`.** With the Unicode spelling the DFA
    /// carries a quit set over every byte ≥ 0x80, a quit must be read as
    /// ALIVE, and the predicate then holds back any output with a glyph
    /// in it — measurably worse than the byte-class test it replaces, and
    /// it fails `redaction_sweep`'s reached-rows floor. The rewrite
    /// deletes the quit set outright.
    ///
    /// The soundness of that rewrite rests on *one side of every leading
    /// boundary being an ASCII word byte*, which is a property of the
    /// rules rather than of the engine — so it is asserted here, over
    /// user rules as well, rather than assumed.
    #[test]
    fn every_rule_compiles_a_liveness_automaton() {
        let rules = RuleSet::builtin_with_extra(ADVERSARIAL_USER_RULES).unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert_eq!(index.liveness.len(), rules.rules.len());
        assert!(rules.rules.len() >= 51, "{} rules", rules.rules.len());

        // 1. Every rule builds — except the one carrying a `\B`, which is
        //    refused on purpose and keeps `is_value_byte`.
        let unbuilt: Vec<&str> = rules
            .rules
            .iter()
            .zip(&index.liveness)
            .filter(|(_, dfa)| dfa.is_none())
            .map(|(r, _)| r.name.as_str())
            .collect();
        assert_eq!(
            unbuilt,
            vec!["acme-negated-boundary"],
            "a rule with no automaton silently falls back to the byte-class \
             test, so the set of them is pinned rather than counted"
        );

        // 2. **The soundness lemma.** Wherever a rule has a word boundary
        //    at all, the indexed prefix liveness is driven from starts
        //    with an ASCII word byte, so `(?-u:\b)` over-approximates
        //    `\b` at the only boundary whose other side the input
        //    supplies. `private-key-block` is the sole prefix that starts
        //    on punctuation and its pattern has no `\b`, which is why the
        //    lemma is stated this way round rather than as "all prefixes".
        let mut pairs = 0usize;
        for bucket in index.by_first_byte.values() {
            for candidate in bucket {
                pairs += 1;
                let rule = &rules.rules[candidate.rule];
                if !rule.pattern.contains(r"\b") {
                    continue;
                }
                let first = candidate.prefix[0];
                assert!(
                    first.is_ascii_alphanumeric() || first == b'_',
                    "{}: prefix {:?} starts on a non-word byte, so the ASCII \
                     word boundary is no longer an over-approximation of the \
                     rule's own `\\b`",
                    rule.name,
                    String::from_utf8_lossy(&candidate.prefix)
                );
                // 3. …and the pair is not structurally dead: some byte
                //    keeps it alive, or its holdback could never engage.
                let alive = (0u8..=0xff).any(|b| {
                    let mut region = candidate.prefix.clone();
                    region.push(b);
                    index.still_alive(candidate.rule, &region, 0)
                });
                assert!(
                    alive,
                    "{}: no continuation byte keeps prefix {:?} alive",
                    rule.name,
                    String::from_utf8_lossy(&candidate.prefix)
                );
            }
        }
        assert!(pairs >= 100, "only {pairs} (rule, prefix) pairs judged");
    }

    /// Rules built to separate the **sound** reading of the view gate
    /// from the cheap syntactic ones that look equivalent on the shipped
    /// fifty-one.
    ///
    /// Each `infinite-*` has an unbounded quantifier standing between its
    /// indexed prefix and something the match still requires, so the set
    /// of continuations that keep it alive-and-unmatched has a cycle and a
    /// view can strand it for ever. A syntactic walk that looks only at
    /// the *immediately following* sibling, or that does not recurse
    /// through `Repetition` / `Capture` / `Alternation`, calls all three
    /// bounded — and the shipped rules cannot tell the two readings apart,
    /// so pinning the shipped twelve alone is not a pin at all.
    ///
    /// The two `bounded-*` rules are the paired direction: without them
    /// the row is satisfied by a gate that excludes everything.
    const GATE_PROBE_RULES: &str = r#"
        [[rule]]
        name = "infinite-optional-separator"
        kind = "acme-internal"
        pattern = '''\bacmeinf_[A-Za-z0-9]*[_-]?KEY[0-9]{8,}'''
        positive = ["acmeinf_ab-KEY01234567"]
        negative = ["acmeinf_ab-KEY1"]

        [[rule]]
        name = "infinite-repeated-group"
        kind = "acme-internal"
        pattern = '''\bacmerep_(?:[a-z]+END)+'''
        positive = ["acmerep_abcEND"]
        negative = ["acmerep_END"]

        [[rule]]
        name = "infinite-nullable-sibling"
        kind = "acme-internal"
        pattern = '''\bacmenul_[a-z]*(?:b?)END[0-9]{4}'''
        positive = ["acmenul_abbEND1234"]
        negative = ["acmenul_END"]

        [[rule]]
        name = "infinite-layout-byte"
        kind = "acme-internal"
        pattern = '''\bacmetab_[\t]+KEY[0-9]{4}'''
        positive = ["acmetab_\tKEY1234"]
        negative = ["acmetab_KEY1234"]

        [[rule]]
        name = "bounded-large-repetition"
        kind = "acme-internal"
        pattern = '''\bacmebig_[A-Za-z0-9]{0,40}KEY[0-9]{4}'''
        positive = ["acmebig_abcKEY1234"]
        negative = ["acmebig_KEY"]

        [[rule]]
        name = "bounded-plain"
        kind = "acme-internal"
        pattern = '''\bacmeok_[a-f0-9]{16,}'''
        positive = ["acmeok_0123456789abcdef"]
        negative = ["acmeok_short"]
    "#;

    /// Every rule whose gate flag is `false`, by name.
    fn ungated(rules: &RuleSet, index: &PrefixIndex) -> Vec<String> {
        let mut names: Vec<String> = rules
            .rules
            .iter()
            .zip(&index.gated)
            .filter(|(_, g)| !**g)
            .map(|(r, _)| r.name.clone())
            .collect();
        names.sort();
        names
    }

    /// **The gate that decides which rules a view may drive is computed
    /// from the automaton, not declared (GH #142, GH #160).**
    ///
    /// Twelve of the shipped fifty-one fail it. That number is pinned
    /// here, and so is the *criterion*, because the two are not the same
    /// assertion: the shipped rules cannot discriminate the sound reading
    /// of "an unbounded repetition stands between the prefix and a still
    /// required element" from either of the two under-specified ones, so a
    /// row that only pinned the twelve would pass against an
    /// implementation that mis-gates every user rule of the three shapes
    /// in [`GATE_PROBE_RULES`].
    #[test]
    fn the_view_driven_withhold_gate_is_computed_not_declared() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert_eq!(
            ungated(&rules, &index),
            vec![
                // The nine `has_value_group` context rules: each has an
                // unbounded `\s*` or `[^…]+` between label and value.
                "aws-secret-access-key",
                "bearer-authorization",
                "cloudflare-api-token",
                "database-connection-password",
                "datadog-api-key",
                "generic-secret-assignment",
                // `[A-Za-z0-9_-]{10,}` before the `.eyJ` it still needs.
                "jwt",
                "powersync-token",
                // `[\s\S]*?` before `-----END`.
                "private-key-block",
                "railway-token",
                "secret-key-assignment",
                // `[A-Za-z0-9_]+` before the `/B` it still needs.
                "slack-webhook-url",
            ],
            "the twelve rules that keep GH #142's residual (GH #160)"
        );

        // The criterion, against rules built to break it. All three
        // `infinite-*` shapes are wrongly called bounded by a syntactic
        // walk that does not recurse, and all three can be stranded.
        let probe = format!("{GATE_PROBE_RULES}{ADVERSARIAL_USER_RULES}");
        let rules = RuleSet::builtin_with_extra(&probe).unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let ungated = ungated(&rules, &index);
        for name in [
            "infinite-optional-separator",
            "infinite-repeated-group",
            "infinite-nullable-sibling",
            // Only a `\t` keeps this one alive, so it is the row that
            // makes the alphabet a decision rather than an accident: a
            // classification over printable bytes alone calls it bounded,
            // and a view that carries tabs — every one of them does —
            // strands it.
            "infinite-layout-byte",
            // **No automaton, no proof.** `\B` is refused by
            // `liveness_pattern`, so this rule keeps `is_value_byte` on
            // the raw stream and must not reach a view scan at all.
            // Defaulting an unanalysable rule *into* the gate is the one
            // mistake here that loses bytes for ever.
            "acme-negated-boundary",
        ] {
            assert!(
                ungated.iter().any(|n| n == name),
                "{name} can be held open for ever and was gated in: {ungated:?}"
            );
        }
        for name in ["bounded-large-repetition", "bounded-plain"] {
            assert!(
                !ungated.iter().any(|n| n == name),
                "{name}'s holdback is bounded, so gating it out costs \
                 protection for nothing: {ungated:?}"
            );
        }
        // …and the paired behavioural fact, so the flag is not merely a
        // number. `acmeinf_` is ungated, so no view may withhold on it;
        // `acmeok_` is gated, so every view may.
        assert_eq!(
            index.earliest_partial_in_view(&rules, b"title acmeinf_abc", 0),
            None,
            "an ungated rule must not drive a view-side withhold"
        );
        assert_eq!(
            index.earliest_partial_in_view(&rules, b"title acmeok_0123", 0),
            Some(6),
            "a gated rule still does"
        );
        // The raw scan is unmoved by the gate: it has its own escape
        // hatch and does not need one.
        assert_eq!(
            index.earliest_partial(&rules, b"title acmeinf_abc", 0),
            Some(6),
            "the gate must not reach the raw stream"
        );
    }

    /// The rewrite reads the pattern rather than scanning it for a
    /// substring, and refuses what it cannot argue about.
    ///
    /// Row two is the one that matters: `str::replace("\\b", …)` — which
    /// is the obvious spelling — turns an escaped backslash followed by a
    /// literal `b` into a word boundary, and the liveness automaton then
    /// answers about a pattern the matcher never had.
    #[test]
    fn the_liveness_rewrite_is_escape_aware() {
        assert_eq!(
            liveness_pattern(r"\bghp_[0-9A-Za-z]{36,}").as_deref(),
            Some(r"(?-u:\b)ghp_[0-9A-Za-z]{36,}")
        );
        assert_eq!(
            liveness_pattern(r"\bACMEESC-\\bkey[0-9]{8}").as_deref(),
            Some(r"(?-u:\b)ACMEESC-\\bkey[0-9]{8}"),
            "the escaped backslash's `b` is a literal, not a boundary"
        );
        assert_eq!(
            liveness_pattern(r"(?i)\bcloudflare[a-z]{0,4}(?:token|key)\b[:=]").as_deref(),
            Some(r"(?i)(?-u:\b)cloudflare[a-z]{0,4}(?:token|key)(?-u:\b)[:=]"),
            "an interior boundary is rewritten too"
        );
        assert_eq!(
            liveness_pattern(r"\bacme[0-9]{4}\B[a-z]{4}"),
            None,
            "`\\B` inverts the comparison, so no automaton is built for it"
        );
    }

    /// **The mutation this file exists to catch.** A rule that is
    /// genuinely still able to match must never be reported dead, and the
    /// way to get that wrong is to walk end-of-input: `next_eoi_state`
    /// asks *"does this match the bytes that arrived"*, which for a token
    /// one character short of its minimum answers no — and releases it.
    ///
    /// Driven constructively rather than by fixture. Every truncation of
    /// every rule's **own** positive example is alive by construction:
    /// the rest of that example is a continuation that completes it. The
    /// look-behind is `…` (U+2026, three non-ASCII bytes and not a word
    /// character either way), so the row also pins the quit-set question
    /// from the other side — a Unicode `\b` returns `MatchError(Quit)`
    /// from `start_state_forward` here, and reading that as dead releases
    /// an in-flight credential the moment a glyph precedes it.
    #[test]
    fn a_truncated_match_is_alive_behind_a_non_ascii_look_behind() {
        let rules = RuleSet::builtin_with_extra(ADVERSARIAL_USER_RULES).unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let lead = "…".as_bytes();
        let mut checked = 0usize;
        for (idx, rule) in rules.rules.iter().enumerate() {
            if index.liveness[idx].is_none() {
                continue;
            }
            for positive in &rule.positive {
                let span = matched_span(rule, positive);
                for take in 1..=span.len() {
                    if !span.is_char_boundary(take) {
                        continue;
                    }
                    let mut region = lead.to_vec();
                    region.extend_from_slice(&span.as_bytes()[..take]);
                    assert!(
                        index.still_alive(idx, &region, lead.len()),
                        "{}: {:?} can still become {span:?} and was called dead",
                        rule.name,
                        &span[..take]
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 2_000, "only {checked} truncations judged");
    }

    /// The other direction, and the mutation it catches: the look-behind
    /// byte must reach the automaton by **range**, not by re-slicing the
    /// region. `Input::new(&region[at..])` makes every candidate look like
    /// the start of the haystack, where a `\b` always holds — so a rule
    /// whose pattern forbids a mid-word match would be held open on text
    /// it can never match.
    #[test]
    fn a_candidate_sitting_mid_word_is_dead_for_a_word_boundary_rule() {
        let rules = RuleSet::builtin_with_extra(ADVERSARIAL_USER_RULES).unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let mut checked = 0usize;
        for (idx, rule) in rules.rules.iter().enumerate() {
            if index.liveness[idx].is_none() || !starts_with_word_boundary(&rule.pattern) {
                continue;
            }
            for positive in &rule.positive {
                let span = matched_span(rule, positive);
                let mut region = b"x".to_vec();
                region.extend_from_slice(span.as_bytes());
                assert!(
                    !index.still_alive(idx, &region, 1),
                    "{}: {span:?} behind a word byte can never satisfy its own \
                     `\\b`, so the look-behind did not reach the automaton",
                    rule.name
                );
                // The same bytes at a real boundary stay alive, so the row
                // separates "the look-behind was read" from "everything is
                // dead".
                let mut ok = b" ".to_vec();
                ok.extend_from_slice(span.as_bytes());
                assert!(
                    index.still_alive(idx, &ok, 1),
                    "{}: {span:?} at a boundary must be alive",
                    rule.name
                );
                checked += 1;
            }
        }
        assert!(checked > 40, "only {checked} rules judged");
    }
}
