//! The literal-prefix index and the in-flight secret scanner that the
//! **targeted holdback** (spec §4.1) is built on.
//!
//! The holdback boundary is not a byte count. It is the start of a secret
//! that is *still arriving*: bytes that match a known secret prefix, keep
//! the rule that produced that prefix able to match all the way to
//! `buffer.head`, and do not yet satisfy it. When no such candidate
//! exists — the overwhelming
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

use super::pem::{self, PemExtent, RegionEnd};
use super::rules::RuleSet;
use regex_automata::{
    dfa::{dense, Automaton, StartKind},
    util::{primitives::StateID, syntax},
    Anchored, Input,
};

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

/// Bytes an emitted view reproduces verbatim: printable ASCII, space
/// included, plus the line feed.
///
/// **The set is "what no view rewrites", not "what looks like text".**
/// `\x1b` and the C1 range are removed by the stripped view; `\t` is
/// expanded to a tab stop by the rendered one, and spaces are in
/// `[ A-Z]`, so an expanded tab can complete a label a raw `\t` kills;
/// `\r` moves the cursor to column 0, so the rendered row can carry
/// text the raw byte order does not; and a byte that is not part of a
/// well-formed UTF-8 sequence is dropped by the C1 views and is outside
/// every Unicode class the rules are built from. Each one is a route by
/// which a match the raw bytes cannot complete is completed in a view
/// that `all_spans` judges.
///
/// Used only by [`PrefixIndex::binary_rule_alive`], because it is only
/// there that a raw byte decides a *release* (GH #166). `\n` is in the
/// set: the grid joins real line breaks with `\n` and only a wrapped
/// continuation is joined with nothing, so a line feed present in the
/// raw bytes is present in every view of them.
fn is_plain_text_byte(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\n'
}

/// `[A-Za-z0-9_]` — what both spellings of `\b` agree is a word character.
fn is_ascii_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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
/// **Why the substitution cannot release a secret early — and exactly
/// what "cannot" is quantified over, because the two boundaries are not
/// proved to the same standard.** `\b` is *"exactly one side is a word
/// character"*, and the two spellings differ only where one of those
/// sides is a non-ASCII byte, which `(?-u:\b)` reads as a non-word byte
/// and `\b` may read as a word character.
///
/// * **At the candidate's own leading boundary the argument is
///   absolute.** The other side of that boundary is the indexed prefix's
///   first byte, which [`PrefixIndex::build`] guarantees is an ASCII word
///   byte by refusing an automaton to any rule where it is not. `\b` then
///   reduces to *"the byte behind is not a word character"*, and "not an
///   **ASCII** word byte" is a superset of "not a **Unicode** word
///   character" — so `(?-u:\b)` holds wherever `\b` does, and liveness
///   over-approximates the rule. That half rests on `build`'s refusal
///   and on nothing else.
/// * **At every later boundary the argument is *relative*, and its
///   baseline is [`is_value_byte`].** Divergence there needs a non-ASCII
///   byte at or after the first value byte, and where it happens the
///   rewrite can *under*-approximate: the automaton may call DEAD a
///   candidate the rule could still complete, which is the direction that
///   releases. What makes that safe is not the rewrite, it is the floor —
///   `is_value_byte`, the predicate shipped at `11df4d0`, releases the
///   candidate on *any* byte ≥ 0x80 outright. So the claim proved here is
///   **"liveness releases nothing the byte-class test held"**, and not the
///   stronger "liveness never releases an in-flight secret". The two read
///   the same only because the byte-class test is the baseline.
///
/// **The relative half does not travel, and whoever moves this predicate
/// must re-derive it.** Anything that drives this automaton where
/// `is_value_byte` is not the thing it replaces — a view-driven withhold
/// (GH #142's reverted step, where a view carries no `is_value_byte`
/// baseline at all and the deleted byte cannot revise the decision), or
/// GH #152 moving the `has_value_group` rules across — loses the floor
/// and with it the argument. Such a caller needs the absolute property at
/// the trailing boundary too, which nothing here supplies: it would have
/// to enforce a refusal at that boundary the way [`PrefixIndex::build`]
/// enforces one at the leading boundary.
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

/// Whether the rule's match can begin **one byte before** an occurrence
/// of `prefix` — the shape that makes [`PrefixIndex::still_alive`] answer
/// the wrong question about it.
///
/// `still_alive` anchors the whole pattern at the candidate, so what it
/// actually answers is *"can this rule match **starting here**"*. For a
/// prefix the rule's own match reaches only after consuming earlier
/// bytes that is the wrong question, and it is wrong in the direction
/// that **releases**. Measured, against the shipped
/// `generic-secret-assignment`
/// (`(?i)\b[a-z0-9_.-]{0,32}(?:password|…)\b["'\s]*[:=]…`):
///
/// ```text
/// rule.regex.is_match("MY_APP_PASSWORD=hunter2hunter2")            == true
/// still_alive(rule, "MY_APP_PASSWORD=hunter2hunter2", at = 7)      == false
/// ```
///
/// The leading `\b` cannot hold between the `_` at 6 and the `P` at 7,
/// so anchoring there is DEAD on arrival — while the rule matches the
/// whole region from offset 0. A rule this answers `false` for gets no
/// automaton, exactly as the punctuation-prefix case above does, and
/// keeps [`is_value_byte`], which holds strictly more.
///
/// **Latent today, and that is why it is computed rather than noted.**
/// The nine `has_value_group` context rules are exactly the ones whose
/// declared prefixes sit inside their own match, and
/// [`PrefixIndex::earliest_partial`] keeps them on [`is_value_byte`] for
/// an unrelated reason (GH #152). Closing #152 by moving them across
/// would land that false DEAD on a shipped rule against an ordinary
/// env-var line, and a refusal computed here cannot be forgotten there.
///
/// **What this proves, and what it does not — stated because the
/// difference is the whole of it.** It proves the match cannot begin
/// exactly one byte before the prefix. That reaches every lead-in whose
/// minimum length is one or less, which is the family the hazard lives
/// in: `{0,n}`, `*`, `?` and `+` all admit a gap of exactly one byte. It
/// does **not** reach a lead-in whose minimum is two or more. Three
/// shapes have one, and all three need the rule to **declare** its
/// prefixes, because a derived prefix is by construction a literal every
/// match begins with: a fixed literal lead-in, a `{2,n}` run, and an
/// alternation branch with a declared prefix starting two bytes into it.
/// `(?:\bacme|\bfoo)[a-z]{2,6}tok_[A-Za-z0-9]{20,}` with
/// `prefixes = ["tok_"]` is the second, and it keeps an automaton that
/// calls `acmexytok_ABCDEFGHIJ` dead at offset 6.
///
/// **That residual is measured empty on the rule set, and searching one
/// byte deeper would not find it anyway.** Sweeping the same walk at
/// depths one through six over the shipped fifty-one plus the adversarial
/// user rules: depths one and two refuse the *same* two rules, and depth
/// **three** — which is [`MIN_PREFIX_LEN`], the first depth at which a
/// rule's own value run can be entered and spell its own prefix — jumps
/// to seven and starts refusing `openai-api-key`, `jwt` and
/// `aws-access-key-id`. There is no depth between "reaches more real
/// lead-ins" and "starts refusing rules that are fine".
///
/// **Chasing the deep occurrences was tried and is not worth having.**
/// The unbounded reachability walk refuses an automaton to **23 of the 51
/// shipped rules** — `\bsk-ant-[A-Za-z0-9_-]{24,}` reaches its own
/// `sk-ant-` from inside its own value run, because that run's character
/// class can spell it. Every one of those interior occurrences is
/// preceded, in the same region, by that rule's *own* earlier candidate,
/// and [`PrefixIndex::earliest_partial`] scans left to right and answers
/// with the earliest — so the deep walk buys nothing and costs the
/// change.
fn rule_may_start_one_byte_before(dfa: &dense::DFA<Vec<u32>>, prefix: &[u8]) -> bool {
    fn consumes(dfa: &dense::DFA<Vec<u32>>, mut sid: StateID, prefix: &[u8]) -> bool {
        for byte in prefix {
            sid = dfa.next_state(sid, *byte);
            if dfa.is_dead_state(sid) {
                return false;
            }
            if dfa.is_quit_state(sid) {
                return true;
            }
        }
        // **A dense DFA reports a match one byte late**, so landing in a
        // match state here means the match ended *before* this prefix was
        // covered and the byte that put us here is outside it. A match
        // state that can still be extended is a different thing, which is
        // why this asks rather than assuming.
        !dfa.is_match_state(sid) || (0u8..=0xff).any(|b| !dfa.is_dead_state(dfa.next_state(sid, b)))
    }

    // **One seed per start configuration `regex-automata` distinguishes**,
    // read off `util::start::Start` rather than reasoned about: `Text`
    // (the empty seed), `WordByte`, `NonWordByte`, `LineLF` and `LineCR`.
    // `\r` is its own class and `\n` does not stand in for it — the
    // determinizer gives `LineCR` a half-CRLF look-behind where `LineLF`
    // gets `StartCRLF` — and on a pty `\r` is the *common* byte before a
    // line. Missing a start state means missing a lead-in, which is the
    // direction that releases. `CustomLineTerminator` needs a
    // `LookMatcher` this crate never sets, so it is unreachable here.
    for lead in [None, Some(b'a'), Some(b'-'), Some(b'\n'), Some(b'\r')] {
        let hay: Vec<u8> = lead.into_iter().collect();
        let input = Input::new(&hay).range(hay.len()..).anchored(Anchored::Yes);
        let Ok(sid) = dfa.start_state_forward(&input) else {
            // A quit byte in the look-behind: nothing was analysed, so
            // nothing is proved, so the rule gets no automaton.
            return true;
        };
        // The alphabet is every byte, for the reason the rest of this
        // file takes the conservative reading: a narrower one finds fewer
        // lead-ins, and missing one is what releases a secret.
        for byte in 0u8..=0xff {
            let to = dfa.next_state(sid, byte);
            if dfa.is_dead_state(to) {
                continue;
            }
            if dfa.is_quit_state(to) || consumes(dfa, to, prefix) {
                return true;
            }
        }
    }
    false
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
    /// One bucket per byte value, indexed rather than hashed (GH #163).
    ///
    /// **The bucket lookup runs once per input byte of every read, and
    /// a `HashMap<u8, _>` charged a SipHash of one byte for each.**
    /// Measured on this tree, that hash was 0.378 ms of a 0.751 ms
    /// `earliest_partial` over the default 41,472-byte read window —
    /// about half the cost of a scan that finds nothing, which is what
    /// ordinary output does on every read. The key is one byte, so the
    /// table that removes the hash entirely is 256 slots; most are
    /// empty and an empty `Vec` is three words, so the whole array is
    /// 6 KiB behind one `Box`, built once per rule set.
    ///
    /// **Keyed by the ASCII-lowercased first byte, and read the same
    /// way** — the case-insensitivity above is the array's index
    /// function, not a property of the map it replaced.
    /// [`Self::bucket`] is the single lookup, so the two spellings
    /// cannot drift apart.
    by_first_byte: Box<[Vec<Candidate>; 256]>,
    total: usize,
    /// One liveness automaton per rule, parallel to `rules.rules`. See
    /// [`build_liveness`]; `None` means the rule keeps [`is_value_byte`].
    liveness: Vec<Option<dense::DFA<Vec<u32>>>>,
    /// The bucket keys a `binary` rule's prefix can open with — `-` alone
    /// in the shipped set — so [`Self::unterminated_candidates`], which
    /// asks about those rules and no others, skips every other byte of a
    /// region without a bucket lookup. It runs on every read.
    binary_first_byte: Box<[bool; 256]>,
}

/// A `binary` candidate the redactor will not see closed — see
/// [`PrefixIndex::unterminated_candidates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unterminated {
    /// Absolute offset of the anchor.
    pub start: u64,
    /// Absolute offset one past the last byte it is believed over: the
    /// region's end when `in_flight`, otherwise where it died or closed.
    pub end: u64,
    /// Still believed at the region's end. The ones that are not were
    /// returned because they carry key material.
    pub in_flight: bool,
    /// Its body carried a run of `pem::PEM_MATERIAL_RUN` base64
    /// characters — always true of one that is not `in_flight`, and what
    /// the stream's end-of-stream flush asks of one that is.
    pub material: bool,
    /// Not a candidate but key-body lines *after* one that stopped short
    /// of its closing boundary (`pem::body_lines`): a pager's next
    /// screenful, the middle of a key printed in chunks, a decorated key
    /// whose candidate died on its first decoration. Masked like a dead
    /// candidate when not `in_flight`. When `in_flight` it is a last line
    /// still arriving that may turn out to be one — a live stream holds
    /// from `start`, and nothing masks it on that account.
    pub resumed: bool,
}

/// What [`PrefixIndex::candidate_scan`] found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CandidateScan {
    /// See [`PrefixIndex::unterminated_candidates`].
    pub found: Vec<Unterminated>,
    /// The absolute anchor of every private-key candidate that stopped
    /// short of its closing boundary, in order: each one's body lines are
    /// followed for `UNVOUCHED_CARRY_BYTES` past it, so a surface that
    /// forgets bytes — a live stream's lookbehind — must keep the anchor
    /// until then or stop finding them.
    pub stopped_short: Vec<u64>,
}

impl PrefixIndex {
    pub fn build(rules: &RuleSet, expansion_limit: usize) -> Self {
        let mut by_first_byte: Box<[Vec<Candidate>; 256]> =
            Box::new(std::array::from_fn(|_| Vec::new()));
        let mut total = 0usize;
        let mut liveness: Vec<Option<dense::DFA<Vec<u32>>>> = Vec::with_capacity(rules.rules.len());
        let mut binary_first_byte = Box::new([false; 256]);
        for (idx, rule) in rules.rules.iter().enumerate() {
            let derived = derive_prefixes(&rule.pattern, expansion_limit);
            // A derivable leading literal means the prefix is where the
            // match starts, so the pattern's own `\b` applies to it. When
            // derivation yields nothing (a leading group, or the context
            // rules whose declared prefixes sit *inside* the match) the
            // boundary belongs somewhere else and must not be demanded.
            let requires_word_boundary =
                !derived.is_empty() && starts_with_word_boundary(&rule.pattern);
            let prefixes: Vec<Vec<u8>> = match &rule.declared_prefixes {
                Some(declared) => declared.clone(),
                None => derived,
            }
            .into_iter()
            .filter(|p| p.len() >= MIN_PREFIX_LEN)
            .collect();

            // **The ASCII word-boundary lemma, enforced here rather than
            // asserted about a test fixture.** [`liveness_pattern`]'s
            // rewrite over-approximates `\b` only because the byte on the
            // *pattern* side of the candidate's leading boundary is an
            // ASCII word byte — which, for an indexed candidate, is the
            // prefix's first byte. No shipped rule breaks that, but
            // `extra_redaction_patterns` accepts arbitrary rules, and one
            // whose pattern carries a `\b` and whose prefix opens on
            // punctuation breaks it in the direction that **releases** an
            // in-flight secret: measured, `\b(?:-zq-|-zr-)[A-Za-z0-9]{10,}`
            // against `"\u{e9}-zq-ABCD"` is alive to the rule's own regex,
            // dead to the ASCII rewrite, and was held by the byte-class
            // test this replaces.
            //
            // Such a rule gets no automaton at all: it keeps
            // [`is_value_byte`] on the raw stream, which is what it has
            // today, and that is the safe direction — the byte-class test
            // holds strictly more than liveness does.
            let lemma_holds =
                !rule.pattern.contains("\\b") || prefixes.iter().all(|p| is_ascii_word_byte(p[0]));
            // **And the automaton is only asked about prefixes the rule's
            // match begins at.** `still_alive` anchors at the candidate,
            // so a prefix the match can only reach after earlier bytes is
            // DEAD on arrival — see `rule_may_start_one_byte_before`,
            // which
            // measures it on `generic-secret-assignment`. Same refusal,
            // same fallback, and for the same reason: an automaton that
            // answers the wrong question is worse than no automaton.
            let dfa = lemma_holds
                .then(|| build_liveness(&rule.pattern))
                .flatten()
                .filter(|d| {
                    !prefixes
                        .iter()
                        .any(|p| rule_may_start_one_byte_before(d, p))
                });

            for prefix in &prefixes {
                total += 1;
                if rule.binary {
                    binary_first_byte[prefix[0].to_ascii_lowercase() as usize] = true;
                }
                by_first_byte[prefix[0].to_ascii_lowercase() as usize].push(Candidate {
                    prefix: prefix.clone(),
                    rule: idx,
                    requires_word_boundary,
                });
            }
            liveness.push(dfa);
        }
        // Longest prefix first, so the most specific rule claims a
        // position when several share a first byte.
        for bucket in by_first_byte.iter_mut() {
            bucket.sort_by_key(|c| std::cmp::Reverse(c.prefix.len()));
        }
        Self {
            by_first_byte,
            total,
            liveness,
            binary_first_byte,
        }
    }

    /// The candidates a region byte routes to — **the** lookup the scan
    /// performs, factored out so nothing else can spell it differently.
    ///
    /// `to_ascii_lowercase` here is not an optimisation and dropping it
    /// is not a fold-insensitive scan with a slightly different cost: it
    /// is the index function [`Self::build`] keyed the table with, so a
    /// raw `byte as usize` reads the wrong slot for every uppercase byte
    /// and silently stops indexing the `(?i)` rules — every context rule
    /// carries one. `every_first_byte_routes_to_the_bucket_the_map_held`
    /// asserts the routing for all 256 values against a map built the
    /// way the replaced `HashMap` was.
    #[inline]
    fn bucket(&self, byte: u8) -> &[Candidate] {
        &self.by_first_byte[byte.to_ascii_lowercase() as usize]
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
    ///
    /// **`value_tail` is [`value_tail_start`] for the whole `region`,
    /// computed once by the caller (GH #163).** The no-automaton arm
    /// below used to walk `region[at..]` itself, once per candidate at
    /// every anchor, which is the second of the two full-suffix walks
    /// the issue reports. `region[at..].iter().all(is_value_byte)` holds
    /// exactly when `at >= value_tail`: the predicate is upward-closed
    /// in `at`, and `value_tail` is by construction its least witness.
    /// The rewrite is **exact**, not conservative in either direction,
    /// and the differential oracle below is what says so.
    fn still_alive(&self, rule: usize, region: &[u8], at: usize, value_tail: usize) -> bool {
        let Some(dfa) = self.liveness.get(rule).and_then(Option::as_ref) else {
            return at >= value_tail;
        };
        let input = Input::new(region).range(at..).anchored(Anchored::Yes);
        // `start_state_forward` fails on a quit byte in the look-behind
        // (rule 4 above) or on an anchored-mode mismatch, which cannot
        // happen here — [`build_liveness`] sets `StartKind::Anchored` and
        // the input above asks for `Anchored::Yes`. Both go the same way.
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

    /// The in-flight test for a rule marked `binary` (GH #166): the
    /// rule's own automaton where its answer can be trusted, and the
    /// unconditional hold everywhere else.
    ///
    /// **Two reasons it is not simply [`Self::still_alive`], and each
    /// one on its own releases key material.**
    ///
    /// 1. **No automaton means no fallback here.** `still_alive` falls
    ///    back to [`is_value_byte`], which is the shipped predicate and
    ///    holds strictly more *for a rule whose value is one unbroken
    ///    run of printable bytes*. A `binary` rule is exactly the rule
    ///    that is not: a PEM body's newlines put it outside
    ///    `0x21..=0x7e` on its second line, so the fallback would
    ///    release a key rather than hold it. The unconditional `true`
    ///    this replaced is the correct answer when there is no
    ///    automaton, and it is kept.
    /// 2. **A DEAD state is only trustworthy on bytes every emitted view
    ///    reproduces verbatim.** `holdback_boundary` reads the **raw**
    ///    region and nothing else, deliberately (`OutputProcessor`,
    ///    spec §4.1) — but redaction does not: `all_spans` judges the
    ///    normalised views as well (GH #135, #139), so the rule can
    ///    cover bytes its raw regex cannot. That asymmetry was harmless
    ///    while this arm was an unconditional `true`, which no raw byte
    ///    could change. It stops being harmless the moment a raw byte
    ///    can *release*. Measured on this tree, with the automaton and
    ///    without this guard: `-----BEGIN RSA PRIVATE KEY-----`, 40
    ///    lines of body and **one `0x9b`** in the middle of it, no
    ///    `-----END` yet — `still_alive` is `false` and
    ///    `earliest_partial` is `None`, because `[\s\S]` is a
    ///    *codepoint* class and a lone C1 byte is not one. The key body
    ///    already arrived goes out in the clear, and the raw regex
    ///    cannot redact it either, so no marker and no audit entry
    ///    records it. `\x1b[0m` inside the header and a `\r` or `\t`
    ///    before the dead state are the same failure by three other
    ///    routes: each is a byte a view removes or rewrites, and the
    ///    stripped or rendered text can complete a match the raw bytes
    ///    cannot.
    ///
    /// So the walk stops at the first byte outside
    /// [`is_plain_text_byte`] and answers ALIVE. What is left is a
    /// verdict reached entirely on bytes that no view alters, which is
    /// the case `-----BEGIN CERTIFICATE-----` is in — it dies on the
    /// `-` that follows a label of plain ASCII, 27 bytes in, before any
    /// newline and whatever colour a build prints afterwards.
    ///
    /// **The direction is still release-only.** Every arm above either
    /// returns `true`, which is what this replaced, or returns `false`
    /// having proved the rule cannot match from here.
    ///
    /// **Since GH #242 that is half of the answer.** The two guards above
    /// now live in [`Self::binary_rule_alive`], and an anchor that opens a
    /// PEM boundary is also bounded by what can follow it — see
    /// [`Self::binary_extent`]. A candidate that answers `false` here
    /// because its PEM text ended is not thereby released: when it ended
    /// with key material behind it, [`Self::unterminated_candidates`]
    /// reports it and every surface masks it.
    fn binary_in_flight(&self, rule: usize, region: &[u8], at: usize) -> bool {
        self.binary_extent(rule, region, at).alive
    }

    /// How far the `binary` candidate at `region[at..]` is believed, and
    /// whether it is still believed at the region's end (GH #242).
    ///
    /// **Two judges, and the candidate needs both.** The rule's own
    /// automaton, walked exactly as [`Self::binary_in_flight`]'s two
    /// guards describe, decides whether this anchor is the rule's at all
    /// — it is what kills `-----BEGIN CERTIFICATE-----` on its label. It
    /// cannot bound the candidate after that, because
    /// `private-key-block`'s `[\s\S]*?` has no dead state: until GH #242
    /// an unterminated header was therefore believed until the carry ran
    /// out, and one line of prose masked the next 16 KiB of every surface.
    /// When the anchor opens an RFC 7468 boundary, [`pem::extent`] bounds
    /// it instead — see that module for the alphabet, the streams it is
    /// judged over, and why "died with material" is masked rather than
    /// released.
    ///
    /// **The rule's automaton is walked only as far as the PEM walk got**,
    /// which is what keeps a region of many dead candidates linear: with
    /// `[\s\S]*?` and no control byte to stop at, the automaton alone
    /// walks every candidate to the region's end.
    ///
    /// An anchor that opens no RFC 7468 boundary — a user `binary` rule of
    /// some other shape — keeps exactly the behaviour it had: the rule's
    /// automaton over the whole region, and no material, so nothing is
    /// masked for it once it dies.
    pub(crate) fn binary_extent(&self, rule: usize, region: &[u8], at: usize) -> PemExtent {
        let pem = pem::opens_boundary(region, at).then(|| pem::extent(region, at));
        let limit = pem.map_or(region.len(), |p| p.end.max(at));
        let rule_alive = self.binary_rule_alive(rule, &region[..limit], at);
        match pem {
            Some(p) if rule_alive => p,
            Some(_) => PemExtent {
                end: at,
                alive: false,
                material: false,
                header: false,
                closed: false,
            },
            None => PemExtent {
                end: if rule_alive { region.len() } else { at },
                alive: rule_alive,
                material: false,
                header: false,
                closed: false,
            },
        }
    }

    /// The rule's own automaton from `at` to the end of `region`, with the
    /// two guards [`Self::binary_in_flight`] documents: no automaton means
    /// alive, and a byte some emitted view alters ends the walk alive.
    fn binary_rule_alive(&self, rule: usize, region: &[u8], at: usize) -> bool {
        let Some(dfa) = self.liveness.get(rule).and_then(Option::as_ref) else {
            return true;
        };
        let input = Input::new(region).range(at..).anchored(Anchored::Yes);
        let Ok(mut sid) = dfa.start_state_forward(&input) else {
            return true;
        };
        for byte in &region[at..] {
            if !is_plain_text_byte(*byte) {
                return true;
            }
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

    /// Every `binary` candidate in `region` that the redactor will not see
    /// closed: the ones still believed at the region's end, and the ones
    /// that died with key material behind them (GH #242, GH #243).
    ///
    /// **A candidate that dies is not released by dying.** Before GH #242
    /// no `private-key-block` candidate could die after its label, so
    /// "not in flight" only ever meant "closed", and the redactor had the
    /// span. Once a candidate can stop at the first byte that is not PEM
    /// text, `head -n 15 id_rsa` and then a prompt is a candidate that is
    /// neither in flight nor matched — and releasing it would put fourteen
    /// lines of key body on the wire because a prompt followed them. So
    /// the dead ones carrying material are returned too, with the extent
    /// [`pem::extent`] found, and every surface masks them.
    ///
    /// **Candidates a complete match covers are not filtered here**, and
    /// that is deliberate: the answer would need the rule's anchored
    /// regex, which for `[\s\S]*?` scans to the next `-----END` from every
    /// anchor — the quadratic walk GH #163 took out of this module. Every
    /// caller already holds the complete spans for the same bytes and
    /// drops a candidate one of them covers; see
    /// [`OutputProcessor::process`](super::OutputProcessor::process).
    ///
    /// **And the key-body lines after a candidate that stopped short**
    /// (`resumed`; the independent review of GH #242). A candidate stops at
    /// the first byte that is not PEM text, and a key's body can go on
    /// after one: the next screenful of `less`, the middle of a key
    /// printed by `sed` in chunks, every line of a key printed with a
    /// timestamp or a `bat` gutter in front of it. Before GH #242 all of
    /// those were masked with the rest of the carry; `pem::body_lines`
    /// masks the lines among them that carry key body, for the same
    /// `UNVOUCHED_CARRY_BYTES` past the anchor, and keeps the rest.
    /// `end` says whether the region's last line may still be arriving.
    ///
    /// Same anchor rules as [`Self::earliest_partial`] — the word
    /// boundary, the prefix, one byte after it — and one entry per anchor.
    pub fn unterminated_candidates(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
        end: RegionEnd,
    ) -> Vec<Unterminated> {
        self.candidate_scan(rules, region, region_start, end).found
    }

    /// [`Self::unterminated_candidates`], and the anchors whose body lines
    /// it followed — which a surface that forgets bytes needs, and nothing
    /// else does.
    pub fn candidate_scan(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
        end: RegionEnd,
    ) -> CandidateScan {
        let mut out = Vec::new();
        let mut stopped_short = Vec::new();
        let mut follow: Vec<(usize, usize)> = Vec::new();
        for (i, byte) in region.iter().enumerate() {
            if !self.binary_first_byte[byte.to_ascii_lowercase() as usize] {
                continue;
            }
            for candidate in self.bucket(*byte) {
                if !rules.rules[candidate.rule].binary {
                    continue;
                }
                if candidate.requires_word_boundary
                    && i > 0
                    && (region[i - 1].is_ascii_alphanumeric() || region[i - 1] == b'_')
                {
                    continue;
                }
                let value_start = i + candidate.prefix.len();
                if value_start >= region.len()
                    || !region[i..value_start].eq_ignore_ascii_case(&candidate.prefix)
                {
                    continue;
                }
                let e = self.binary_extent(candidate.rule, region, i);
                if e.alive || e.material {
                    out.push(Unterminated {
                        start: region_start + i as u64,
                        end: region_start + e.end as u64,
                        in_flight: e.alive,
                        material: e.material,
                        resumed: false,
                    });
                }
                if e.stopped_short() {
                    stopped_short.push(region_start + i as u64);
                    let reach = (i + super::UNVOUCHED_CARRY_BYTES).min(region.len());
                    if e.end < reach {
                        follow.push((e.end, reach));
                    }
                }
                break;
            }
        }
        // One walk per stretch of the region some stopped candidate
        // reaches, not one per candidate: a file of prose mentioning the
        // header on every other line would otherwise walk the same
        // sixteen kilobytes once for each.
        follow.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(follow.len());
        for (from, to) in follow {
            match merged.last_mut() {
                Some(last) if from <= last.1 => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        for (from, to) in merged {
            let lines = pem::body_lines(region, from, to, end);
            out.extend(lines.ranges.into_iter().map(|(s, e)| Unterminated {
                start: region_start + s as u64,
                end: region_start + e as u64,
                in_flight: false,
                material: true,
                resumed: true,
            }));
            out.extend(lines.hold_from.map(|h| Unterminated {
                start: region_start + h as u64,
                end: region_start + to as u64,
                in_flight: true,
                material: false,
                resumed: true,
            }));
        }
        CandidateScan {
            found: out,
            stopped_short,
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
            .iter()
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
    /// **A `binary` rule is asked condition 2 as well, and the automaton
    /// is the only thing that may answer it (GH #166).** The byte-class
    /// test never could: a PEM body's newlines defeat any value-run test
    /// at every line, which is why this arm was an unconditional `true`.
    /// An unconditional `true` is not the conservative reading of
    /// condition 2, it is the *absence* of it — condition 3 then asks
    /// only *has this rule matched*, never *can it still match*, so
    /// `-----BEGIN CERTIFICATE-----` — which matches
    /// `private-key-block`'s indexed prefix and is its own shipped
    /// `negative` example — pins `holdback_boundary` at that anchor for
    /// the rest of the session, past `-----END CERTIFICATE-----` and past
    /// every ordinary line after it. Spec §9.2's stream rule names that
    /// exact shape as the thing its terminating clause exists to prevent.
    /// The automaton answers the question the rule can actually be held
    /// to, and it is the *narrowing* direction: it releases only where
    /// `true` held, and only where the rule is in a dead state, from
    /// which no arriving byte can produce a match. [`Self::binary_in_flight`]
    /// and not [`Self::still_alive`], because a `binary` rule needs both
    /// of that method's guards spelled differently — an absent automaton
    /// keeps the unconditional hold rather than falling back to
    /// [`is_value_byte`], and a dead state is only believed when it was
    /// reached on bytes every emitted view reproduces verbatim. Each is
    /// measured there against a key it otherwise releases.
    ///
    /// **The `has_value_group` carve-out is untouched, and it is why GH
    /// #152 stays open.** The nine context rules keep [`is_value_byte`],
    /// because their patterns legitimately admit whitespace between the
    /// label and the value — so liveness reports `Password: ` alive, and
    /// a candidate that can still grow never dies at the end of a region
    /// that has stopped growing. Measured against the automaton
    /// [`PrefixIndex::build`] would install: driven from the `P` of
    /// `"$ ssh dev@box\r\nPassword: "` it is ALIVE, `earliest_partial`
    /// goes `None` -> `Some(15)`, `read_output` returns only the first
    /// line with `held_back: true`, `prompt.last_line` becomes `""`, and
    /// three shipped pty fixtures hang. A shell sitting at a password
    /// prompt is the most common state this tool exists to handle.
    ///
    /// **Removing the carve-out is no longer sufficient to reintroduce
    /// that, and #152 should not read it as sufficient to *fix* the
    /// issue either.** `build` refuses `generic-secret-assignment` and
    /// `secret-key-assignment` an automaton on separate grounds — their
    /// declared prefixes sit inside their own match, see
    /// [`rule_may_start_one_byte_before`] — so those two fall back to
    /// [`is_value_byte`] however this branch is spelled. Measured on this
    /// tree, `still_alive(generic-secret-assignment, …, 15)` is `false`.
    /// #152 asks for a narrower widening of the *byte class*; the
    /// coupling is recorded there rather than guessed at here.
    pub fn earliest_partial(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        let value_tail = value_tail_start(region);
        self.earliest_partial_bounded(rules, region, region_start, value_tail, region.len())
    }

    /// [`Self::earliest_partial`] with the suffix fact hoisted out of the
    /// loop and an optional ceiling on the anchors it visits (GH #163).
    ///
    /// **`value_tail` is a fact about `region`, and `scan_ceiling` is a
    /// promise from the caller.** The first is [`value_tail_start`] and
    /// changes no answer — see [`Self::still_alive`]. The second
    /// **does**: with a ceiling below `region.len()` this function
    /// returns `None` where [`Self::earliest_partial`] returns
    /// `Some(region_start + i)` for some `i >= scan_ceiling`. It is
    /// therefore **not** a cheaper spelling of the public predicate and
    /// must never be reached from one.
    ///
    /// Exactly one caller may pass a real ceiling:
    /// [`Self::unresolved_from`], whose answer is the `min` of this scan
    /// and [`trailing_value_run_start`]. When the trailing run starts at
    /// `t`, every anchor at or after `t` loses that `min` outright, so
    /// declining to look for one cannot move the composed answer. The
    /// `min` is the whole of the argument; a surface without it would
    /// release bytes it used to withhold, and there are **five** of them
    /// rather than the four a reader lists from memory —
    /// `OutputProcessor::holdback_boundary`, the view-driven boundary
    /// beside it, `mcp/detection.rs`'s `prompt.last_line`, and *both* of
    /// `attach/redact_stream.rs`'s calls (`feed` and
    /// `feed_while_withholding`).
    /// `the_scan_ceiling_is_confined_to_unresolved_from` and the source
    /// guard of the same name are what hold that line.
    fn earliest_partial_bounded(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
        value_tail: usize,
        scan_ceiling: usize,
    ) -> Option<u64> {
        let ceiling = scan_ceiling.min(region.len());
        for (i, byte) in region[..ceiling].iter().enumerate() {
            let bucket = self.bucket(*byte);
            if bucket.is_empty() {
                continue;
            }
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
                let in_flight = if rule.binary {
                    // Not `still_alive`: a `binary` rule needs both of
                    // that method's guards spelled differently, and
                    // each of them releases key material (GH #166).
                    self.binary_in_flight(candidate.rule, region, i)
                } else if rule.has_value_group {
                    // The suffix fact, exactly (GH #163): `region[k..]`
                    // is all value bytes iff `k >= value_tail`. Note the
                    // slice — this arm asks about `value_start`, where
                    // the fallback in `still_alive` asks about the
                    // *anchor*, and spelling both the same way holds
                    // where the shipped scan released.
                    value_start >= value_tail
                } else {
                    self.still_alive(candidate.rule, region, i, value_tail)
                };
                if !in_flight {
                    continue;
                }
                // **`anchored_whole_match`, not `anchored.is_match`**
                // (GH #202). This arm releases a candidate on the ground
                // that `find_spans` has already redacted it, and a rule
                // carrying `value_must_not_match` can match here and
                // decline there — which would release a value that is
                // still growing toward one the rule *will* accept. See
                // `CompiledRule::anchored_whole_match`.
                if rule.anchored_whole_match(&region[i..]) {
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
    /// * *Prefix-anchored* — [`Self::earliest_partial`]'s scan. **Not
    ///   `earliest_partial` itself, since GH #163**: this is the one
    ///   caller entitled to a ceiling on it, and the paragraph below the
    ///   list is why. The scan's *body* is still shared, which is what
    ///   "cannot drift" was ever about. It is the only one that reaches a
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
        // **The trailing run is computed first and then spent twice**
        // (GH #163): once as this function's own second detector, and
        // once as a ceiling on the prefix-anchored scan. The composed
        // answer is a `min`, so an anchor at or after `t` could only
        // ever lose it — and the fixture that makes that worth doing is
        // 270,336 bytes of `-sk-` with no trailing delimiter, where the
        // anchored scan spends 22.3 s arriving at `Some(t + 1)` and the
        // run answers `Some(t)` in 0.157 ms (measured on this tree).
        //
        // `unwrap_or(region.len())` is [`value_tail_start`], which is
        // what the scan wants: where the region ends on a non-value byte
        // there is no run, `t` is `region.len()`, and the ceiling is the
        // no-op it has to be. Spelled through
        // [`trailing_value_run_start`] rather than through the unwrapped
        // form so that the detector this paragraph names is the function
        // this line calls — the two agree only because both bottom out
        // in [`is_value_byte`], and GH #152 is a live proposal to widen
        // one of them.
        let run = trailing_value_run_start(region);
        let tail = run.unwrap_or(region.len());
        let anchored = self.earliest_partial_bounded(rules, region, region_start, tail, tail);
        let run = run.map(|i| region_start + i as u64);
        match (anchored, run) {
            (Some(a), Some(r)) => Some(a.min(r)),
            (a, r) => a.or(r),
        }
    }
}

/// **The pre-GH #163 scan, kept as a differential oracle.**
///
/// [`PrefixIndex::earliest_partial`] is a security predicate: a faster
/// version that releases one byte it used to hold is a leak, and one
/// that holds where it used to release is a strand. Each of the three
/// changes GH #163 landed is argued exact at its own site; this is what
/// checks the argument against the code it replaced, over the shipped
/// rule set, the adversarial user rules, and **randomly generated rule
/// sets** — the last being the only arm that reaches the no-automaton
/// fallback at all, since every rule the shipped file refuses an
/// automaton is a `has_value_group` context rule that never gets there.
///
/// It is deliberately **not** an independent reimplementation. It
/// differs from the shipped scan in exactly the three places the issue
/// touched — the bucket lookup, the `has_value_group` arm and the
/// no-automaton fallback — and shares everything else, the liveness
/// walk included, so a mismatch localises to a change rather than to a
/// copy that drifted.
#[cfg(test)]
impl PrefixIndex {
    /// The `HashMap<u8, Vec<Candidate>>` the 256-slot array replaced,
    /// rebuilt with the key function [`Self::build`] filled it with.
    fn reference_map(&self) -> std::collections::HashMap<u8, &Vec<Candidate>> {
        self.by_first_byte
            .iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.is_empty())
            .map(|(byte, bucket)| (byte as u8, bucket))
            .collect()
    }

    pub(crate) fn earliest_partial_reference(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        let by_first_byte = self.reference_map();
        for (i, byte) in region.iter().enumerate() {
            let Some(bucket) = by_first_byte.get(&byte.to_ascii_lowercase()) else {
                continue;
            };
            for candidate in bucket.iter() {
                if candidate.requires_word_boundary
                    && i > 0
                    && (region[i - 1].is_ascii_alphanumeric() || region[i - 1] == b'_')
                {
                    continue;
                }
                let value_start = i + candidate.prefix.len();
                if value_start >= region.len() {
                    continue;
                }
                if !region[i..value_start].eq_ignore_ascii_case(&candidate.prefix) {
                    continue;
                }
                let rule = &rules.rules[candidate.rule];
                let in_flight = if rule.binary {
                    self.binary_in_flight(candidate.rule, region, i)
                } else if rule.has_value_group {
                    region[value_start..].iter().all(|b| is_value_byte(*b))
                } else if self.liveness[candidate.rule].is_none() {
                    // `still_alive`'s no-automaton arm, as it was walked.
                    region[i..].iter().all(|b| is_value_byte(*b))
                } else {
                    // The automaton arm is untouched by GH #163, so the
                    // oracle shares it; `value_tail` is unreachable here.
                    self.still_alive(candidate.rule, region, i, usize::MAX)
                };
                if !in_flight {
                    continue;
                }
                // Shared with the scan above on purpose (GH #202): an
                // oracle that kept `anchored.is_match` here would differ
                // from the implementation exactly where a rule refuses
                // its value, and the differential test that compares the
                // two would then *require* the leak.
                if rule.anchored_whole_match(&region[i..]) {
                    continue;
                }
                return Some(region_start + i as u64);
            }
        }
        None
    }

    pub(crate) fn unresolved_from_reference(
        &self,
        rules: &RuleSet,
        region: &[u8],
        region_start: u64,
    ) -> Option<u64> {
        let anchored = self.earliest_partial_reference(rules, region, region_start);
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
/// The delimiter test is [`is_value_byte`], which
/// [`PrefixIndex::earliest_partial`] shared until GH #142 and now keeps
/// for the `has_value_group` context rules and for any rule `build`
/// refused an automaton. **The two notions have
/// parted, deliberately**: this function takes a region and no rule, so
/// there is no automaton to drive and nothing sharper to ask. Narrowing
/// the in-flight predicate therefore did *not* narrow this one, and the
/// GH #14 half of [`PrefixIndex::unresolved_from`] is untouched by it —
/// widening `is_value_byte` here is also what GH #152 must not do, since
/// it takes `trailing_value_run_start(b"   Compiling holdfast-core\n")`
/// from `None` to `Some(0)`.
pub fn trailing_value_run_start(region: &[u8]) -> Option<usize> {
    let start = value_tail_start(region);
    (start < region.len()).then_some(start)
}

/// The least index `t` for which `region[t..]` is entirely
/// [`is_value_byte`] — the suffix fact GH #163 asks of the region once
/// instead of letting every candidate at every anchor ask its own copy.
///
/// [`trailing_value_run_start`] is this with the empty run spelled
/// `None`, which is what its callers want and what the scan does not:
/// a region ending on a non-value byte has `t == region.len()`, and
/// `k >= region.len()` is the correct — and correctly vacuous — answer
/// to *"is `region[k..]` all value bytes"* for the only `k` that can
/// reach it.
fn value_tail_start(region: &[u8]) -> usize {
    let mut i = region.len();
    while i > 0 && is_value_byte(region[i - 1]) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::rules::RuleSet;
    use std::collections::HashMap;

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

    /// **Every shipped rule must yield at least one indexed prefix** (GH
    /// #170).
    ///
    /// [`PrefixIndex::unresolved_from`] above and
    /// `attach/redact_stream.rs` both *describe* this class — a rule
    /// whose pattern derives no literal and which declares none gets no
    /// entry in the index, so [`PrefixIndex::earliest_partial`] is
    /// structurally blind to it and the targeted holdback can never cover
    /// a partial value of it — and neither one **enumerates** it.
    /// `telegram-bot-token` sat in that class from the day it was added:
    /// `\b[0-9]{8,10}:AA…` breaks derivation at the leading class and the
    /// rule declares nothing, so a partial token comes back with
    /// `held_back: false` and the observer stream drops the bytes with no
    /// marker. Whole-value reads redact it correctly, which is why the
    /// rule's own positive/negative fixture passes and nothing noticed.
    ///
    /// **The ledger is not a waiver.** The assertion is set *equality*, so
    /// it fails in both directions: when a **new** rule joins the blind
    /// class — the next defect, which is the whole point of the check —
    /// and when a listed rule is fixed but left here. That second half is
    /// what separates a ledger from the hand-kept count GH #53 watched go
    /// stale; this one cannot rot quietly, because rotting is a failure.
    ///
    /// The sweep runs a range rather than the default alone, and the
    /// range is cover for a seam that is not wired yet rather than for a
    /// site that lowered anything. `prefilter_prefix_expansion_limit`
    /// does not reach [`PrefixIndex::build`]: `output/mod.rs` passes the
    /// hardcoded `DEFAULT_PREFIX_EXPANSION_LIMIT`, and
    /// `tests/config_surface.rs` both classifies the key
    /// `Inert::NamedElsewhere` and asserts it stays off
    /// `processing_limits()`. No operator can lower it today. When one
    /// can, "indexed" will already mean indexed across the range.
    ///
    /// **What still slips past — this guard proves existence, not reach:**
    ///
    /// * *An entry that can never resolve.* A declared prefix sitting
    ///   behind a non-optional atom indexes fine and counts here, but
    ///   [`PrefixIndex::earliest_partial`]'s third condition anchors the
    ///   rule's own regex **at the prefix**, so it never matches and the
    ///   candidate never clears. Measured on the one-line fix GH #170
    ///   proposes (`prefixes = [":AA"]`): a *complete* telegram token then
    ///   holds back forever instead of leaking — this test goes green on
    ///   it. That is why the ledger still has an entry.
    /// * *An incomplete declared set.* Declared prefixes **replace** the
    ///   derived ones rather than joining them, so a rule that declares
    ///   some of its alternation's branches counts as covered here.
    ///   `launchdarkly-key` alternates `(?:sdk|mob|api)-` and declares
    ///   only the first two: measured, an in-flight `api-…` key is not
    ///   held back while `sdk-…` and `mob-…` are. This guard is blind to
    ///   that by construction — it asks for one entry, not the right set.
    /// * *Prefix quality.* An entry at exactly [`MIN_PREFIX_LEN`] that
    ///   collides with ordinary output counts the same as a good one;
    ///   `the_known_transient_holdbacks_are_pinned` covers that direction.
    /// * *Below the sweep floor.* 8 is headroom, not a boundary:
    ///   measured, the blind set is byte-identical from 5 upward, and 5
    ///   is where `gh[pousr]`'s five branches stop fitting. At 4 and 3
    ///   and 2 `github-token` loses its entry as well; at 1
    ///   `posthog-key` goes too. `Config::validate` demands only
    ///   non-zero, so 1..8 is reachable in principle and unswept — which
    ///   costs nothing while the knob reaches nothing, and is the second
    ///   thing to fix on the day it does.
    /// * *User rules.* Only [`RuleSet::builtin`] is swept;
    ///   `extra_redaction_patterns` from an operator's config is not.
    /// * *The other three exposure axes* — escape-splicing (GH #142), the
    ///   context rules (GH #160), the scan window (GH #166) — are
    ///   disjoint from this one and untouched by it.
    ///
    /// **A behavioural version of this guard was measured and rejected.**
    /// Driving each rule's own `positive` fixture truncated by one byte
    /// through [`PrefixIndex::earliest_partial`] and demanding a candidate
    /// reads like the stronger check, and is not one: 25 of 51 rules fail
    /// it correctly, because an open-ended quantifier (`{24,}`) means the
    /// truncated example still satisfies the rule, so the redactor already
    /// covers it and there is rightly nothing to withhold. A guard with 25
    /// standing exceptions is a guard nobody reads.
    #[test]
    fn every_shipped_rule_yields_at_least_one_indexed_prefix() {
        /// Rules known to have no index entry, each with the issue that
        /// tracks it. Removing a fix from the tree without removing it
        /// here fails this test, and so does the reverse.
        const KNOWN_BLIND: &[(&str, &str)] = &[("telegram-bot-token", "GH #170")];

        let rules = RuleSet::builtin().unwrap();
        // Vacuity control, the house rule in this suite: a rule set that
        // failed to load has nothing to check and would pass silently.
        assert!(
            rules.rules.len() >= 40,
            "only {} rules loaded — the sweep below would be vacuous",
            rules.rules.len()
        );
        let mut expected: Vec<&str> = KNOWN_BLIND.iter().map(|(n, _)| *n).collect();
        expected.sort_unstable();

        for (name, _) in KNOWN_BLIND {
            assert!(
                rules.rules.iter().any(|r| r.name == *name),
                "the ledger names `{name}`, which is not a shipped rule any more: \
                 drop the row rather than leaving it to match nothing"
            );
        }

        // The span GH #170 measured. 8 is headroom rather than a
        // boundary: the cap only starts dropping multi-branch classes
        // below 5, where `gh[pousr]`'s five branches stop fitting —
        // a tuning question and not this blind spot.
        for limit in [8usize, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
            let index = PrefixIndex::build(&rules, limit);
            let mut blind: Vec<&str> = rules
                .rules
                .iter()
                .filter(|r| index.prefixes_for(&rules, &r.name).is_empty())
                .map(|r| r.name.as_str())
                .collect();
            blind.sort_unstable();
            assert_eq!(
                blind, expected,
                "at prefilter_prefix_expansion_limit={limit}, the set of rules with no \
                 indexed prefix is not the known-blind ledger. A name here and not in \
                 KNOWN_BLIND is a new rule the partial-secret holdback cannot cover at \
                 all: give it a `prefixes` entry whose literal starts the match, or \
                 file the issue and add it to the ledger. A name in KNOWN_BLIND and \
                 not here is fixed — delete its row."
            );
        }

        // The shipped default is in the sweep, but pin it by name too:
        // the sweep would still pass if the constant moved outside it.
        assert!(
            (8..=4096).contains(&DEFAULT_PREFIX_EXPANSION_LIMIT),
            "DEFAULT_PREFIX_EXPANSION_LIMIT ({DEFAULT_PREFIX_EXPANSION_LIMIT}) left the \
             swept range, so this test no longer covers the shipped configuration"
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
    /// Each of these was held by the byte-class test and released by
    /// nothing until a delimiter arrived, and none was ever a credential:
    /// `\bkey-[a-f0-9]{32}` cannot reach the `v` of `value` or the `m` of
    /// `manager`, and `launchdarkly-key`'s `sdk-` wants a hex UUID and
    /// cannot reach the `g` of `gateway`. The npm shapes are the ones
    /// that matter in practice — a progress line ending in an escape with
    /// no newline after it — and
    /// `ordinary_output_ending_in_an_escape_sequence_is_not_held_back`
    /// covers that end to end.
    ///
    /// **Each row is checked for being a candidate at all before it is
    /// checked for being released.** A row whose text forms no candidate
    /// answers `None` whatever the predicate does — it was green before
    /// this work and it would be green against a revert — and this test's
    /// first draft shipped one (`api-gateway`, whose `api-` alternative
    /// `launchdarkly-key` does not index).
    #[test]
    fn the_holdbacks_that_liveness_retired() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        for (text, live) in [
            // mailgun `\bkey-`, and `v` is not a hex digit
            ("parsing key-value", "parsing key-0123"),
            // the same rule, the real shape
            ("npm WARN @acme/key-manager", "npm WARN @acme/key-0123abcd"),
            // launchdarkly `\bsdk-`, which wants a hex UUID
            ("npm WARN @acme/sdk-gateway", "npm WARN @acme/sdk-0123abcd"),
        ] {
            assert!(
                index.earliest_partial(&rules, live.as_bytes(), 0).is_some(),
                "{live:?} must form a candidate, or {text:?} tests nothing"
            );
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
    /// the suite has never had it. `generic-secret-assignment`'s
    /// `["'\s]*[:=]\s*` legitimately admits the trailing space, so an
    /// automaton for it is alive here while the region has stopped
    /// growing: `earliest_partial` would go `None` -> `Some(15)`,
    /// `read_output` would return `"$ ssh dev@box\r\n"` with
    /// `held_back: true`, `safe_last_line` would return `""` through its
    /// case-2 gate, and `echo_off_prompts_with_and_without_canonical_mode`,
    /// `matrix_row_getpass_is_awaiting_secret_with_no_bracketed_paste_history`
    /// and `matrix_row_bash_read_s_is_awaiting_secret_and_flags_a_write`
    /// would all fail on their 20-second deadlines.
    ///
    /// **Two things now stand between this row and that, not one.** The
    /// carve-out is the first; the second is that `PrefixIndex::build`
    /// refuses this rule an automaton at all, because its declared
    /// prefixes sit inside its own match
    /// ([`rule_may_start_one_byte_before`]). Removing the carve-out alone
    /// leaves the row green, which is the safe direction and also a trap
    /// for GH #152: the fix it needs is a sharper byte class, not a
    /// re-routing.
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
    /// this work adds — the automaton and the two refusals that guard it
    /// — and the shipped fifty-one cannot supply that coverage, so these
    /// do.
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
        name = "acme-non-word-prefix"
        kind = "acme-internal"
        pattern = '''\b(?:-zq-|-zr-)[A-Za-z0-9]{10,}'''
        prefixes = ["-zq-", "-zr-"]
        positive = ["-zq-ABCDEFGHIJ"]
        negative = ["-zq-ABC"]

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

    /// GH #142's engine: which rules get a liveness automaton and which
    /// are refused one, and the two structural facts that make the ASCII
    /// word boundary sound.
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
    fn the_liveness_automata_and_the_refusals_are_both_pinned() {
        let rules = RuleSet::builtin_with_extra(ADVERSARIAL_USER_RULES).unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert_eq!(index.liveness.len(), rules.rules.len());
        assert!(rules.rules.len() >= 51, "{} rules", rules.rules.len());

        // 1. Every rule builds except those `build` refuses on purpose,
        //    each of which keeps `is_value_byte`: the `\B` (no
        //    over-approximation argument), the punctuation-opening prefix
        //    (the leading-boundary lemma), and the two context rules
        //    whose match can begin before their own prefix.
        let unbuilt: Vec<&str> = rules
            .rules
            .iter()
            .zip(&index.liveness)
            .filter(|(_, dfa)| dfa.is_none())
            .map(|(r, _)| r.name.as_str())
            .collect();
        assert_eq!(
            unbuilt,
            vec![
                "secret-key-assignment",
                "generic-secret-assignment",
                "acme-negated-boundary",
                "acme-non-word-prefix"
            ],
            "a rule with no automaton silently falls back to the byte-class \
             test, so the set of them is pinned rather than counted"
        );

        // **The refusal above is a leak that would otherwise be shipped,
        // so it is asserted on behaviour and not only on the list.**
        // `\b` holds between `é` (a Unicode word character) and `-`; the
        // ASCII rewrite sees `0xa9` and `-` as both non-word and says it
        // does not, so an automaton for this rule would report a value
        // half-arrived as DEAD and release it — where the byte-class test
        // this work replaces held it. The offset is the `-` of `-zq-`,
        // which is 2 — immediately past a two-byte `é`.
        let idx = rules
            .rules
            .iter()
            .position(|r| r.name == "acme-non-word-prefix")
            .expect("the fixture rule is in the set");
        assert!(
            rules.rules[idx]
                .regex
                .is_match("é-zq-ABCDEFGHIJ".as_bytes()),
            "the premise: this rule really can still match from that prefix"
        );
        assert_eq!(
            index.earliest_partial(&rules, "é-zq-ABCD".as_bytes(), 0),
            Some(2),
            "a value still arriving behind a non-ASCII byte must not be \
             released just because the ASCII word boundary cannot see it"
        );

        // 2. **The soundness lemma, as a property of the index rather
        //    than of the shipped rule file.** Every indexed prefix a
        //    liveness automaton will be driven from starts with an ASCII
        //    word byte, so `(?-u:\b)` over-approximates `\b` at the only
        //    boundary whose other side the input supplies.
        //    `PrefixIndex::build` makes that true by refusing an automaton
        //    to a rule that breaks it, so this is a check on the refusal
        //    rather than a hope about the rules. `private-key-block` is
        //    the sole *shipped* prefix that opens on punctuation, and its
        //    pattern has no `\b` at all.
        let mut pairs = 0usize;
        for bucket in index.by_first_byte.iter() {
            for candidate in bucket {
                pairs += 1;
                let rule = &rules.rules[candidate.rule];
                if index.liveness[candidate.rule].is_none() || !rule.pattern.contains(r"\b") {
                    continue;
                }
                let first = candidate.prefix[0];
                assert!(
                    is_ascii_word_byte(first),
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
                    index.still_alive(candidate.rule, &region, 0, value_tail_start(&region))
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

    /// **A prefix the rule's match can only reach after earlier bytes
    /// gets no automaton (GH #142).**
    ///
    /// [`PrefixIndex::still_alive`] anchors the pattern at the candidate,
    /// so it answers *"can this rule match starting here"*. For a
    /// declared prefix that sits *inside* its own match that is the wrong
    /// question and it answers in the releasing direction. The first two
    /// assertions are the reproduction, driven against the automaton
    /// `PrefixIndex::build` would have installed; the third is the
    /// refusal that makes it unreachable.
    ///
    /// **Latent today and pinned anyway.** `generic-secret-assignment`
    /// has a `value` capture group, so `earliest_partial` keeps it on
    /// [`is_value_byte`] for an unrelated reason (GH #152) and never asks
    /// the automaton. #152's fix is exactly the change that would start
    /// asking, which is why the refusal lives in `build` and not in a
    /// comment on `earliest_partial`.
    #[test]
    fn a_prefix_the_rule_reaches_only_after_earlier_bytes_gets_no_automaton() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let idx = rules
            .rules
            .iter()
            .position(|r| r.name == "generic-secret-assignment")
            .expect("the rule is shipped");
        let region = b"MY_APP_PASSWORD=hunter2hunter2";
        // `password` is one of its declared prefixes and sits at 7.
        assert!(
            index
                .prefixes_for(&rules, "generic-secret-assignment")
                .iter()
                .any(|p| p == b"password"),
            "the premise: `password` is indexed, at offset 7 of the fixture"
        );

        // 1. The premise: the rule really does match the whole region —
        //    from offset 0, because `[a-z0-9_.-]{0,32}` takes `MY_APP_`.
        assert!(
            rules.rules[idx].regex.is_match(region),
            "the premise: an ordinary env-var line this rule matches"
        );

        // 2. The reproduction, against the automaton that would have been
        //    installed. Anchored at 7 the leading `\b` sits between the
        //    `_` at 6 and the `P` at 7 — two word bytes, so it cannot
        //    hold, and the rule is DEAD on arrival at its own prefix.
        let dfa = build_liveness(&rules.rules[idx].pattern)
            .expect("the pattern itself compiles; it is the anchoring that is wrong");
        let input = Input::new(region).range(7..).anchored(Anchored::Yes);
        let mut sid = dfa
            .start_state_forward(&input)
            .expect("no quit set, so the look-behind is readable");
        let mut died = false;
        for byte in &region[7..] {
            sid = dfa.next_state(sid, *byte);
            if dfa.is_dead_state(sid) {
                died = true;
                break;
            }
        }
        assert!(
            died,
            "the reproduction is stale: this automaton no longer calls a \
             matching region dead when anchored at its interior prefix"
        );

        // 3. The fix: `build` refuses it the automaton, so `still_alive`
        //    falls back to `is_value_byte` — which holds the region, the
        //    safe direction and what `11df4d0` does.
        assert!(
            index.liveness[idx].is_none(),
            "a rule whose match can begin before its own indexed prefix \
             must get no automaton"
        );
        assert!(
            index.still_alive(idx, region, 7, value_tail_start(region)),
            "with no automaton the byte-class fallback must hold, not release"
        );

        // 4. …and the refusal separates the two families rather than
        //    catching everything. `launchdarkly-key` also declares its
        //    prefixes and also derives none, and its match *does* begin
        //    at them.
        let ld = rules
            .rules
            .iter()
            .position(|r| r.name == "launchdarkly-key")
            .expect("the rule is shipped");
        assert!(
            index.liveness[ld].is_some(),
            "a declared prefix the match begins at must keep its automaton, \
             or the check is a ban on declared prefixes"
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
    /// character either way), which is the shape a Unicode `\b` would
    /// answer `MatchError(Quit)` for.
    ///
    /// **It does not pin the quit arms, and saying so is the point.**
    /// `build_liveness` sets `unicode_word_boundary(false)` and
    /// `liveness_pattern` removes the last Unicode `\b`, so no automaton
    /// here has a quit set and inverting both arms of `still_alive`
    /// leaves every row in this file green — measured. The arms are
    /// written for a future rule that reintroduces one, and they are
    /// unguarded until it does.
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
                        index.still_alive(idx, &region, lead.len(), value_tail_start(&region)),
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
                    !index.still_alive(idx, &region, 1, value_tail_start(&region)),
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
                    index.still_alive(idx, &ok, 1, value_tail_start(&ok)),
                    "{}: {span:?} at a boundary must be alive",
                    rule.name
                );
                checked += 1;
            }
        }
        assert!(checked > 40, "only {checked} rules judged");
    }

    /// A PEM body long enough that the fixture cannot pass by fitting
    /// inside one scan window — spec §9.2: *"If the fixture fits inside
    /// one unit, it is not testing this rule."* At 64 base64 characters
    /// per line these are the shape `openssl` emits.
    fn pem_body(lines: usize) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..lines)
            .map(|i| {
                let mut line: String = (0..64)
                    .map(|k| ALPHABET[(i * 7 + k * 13 + k * k) % 64] as char)
                    .collect();
                line.push('\n');
                line
            })
            .collect()
    }

    /// The premises every row below rests on, asserted once: which rule
    /// owns the `-----BEGIN` anchor, that it is the `binary` arm of
    /// [`PrefixIndex::earliest_partial`] that decides it, and that the
    /// arm has an automaton to decide it *with*.
    ///
    /// Without this the three tests prove nothing: a rule set in which
    /// `private-key-block` stopped being `binary`, or an automaton
    /// `build` had started refusing, would send every region through a
    /// different branch and the release/hold rows would still pass for
    /// the wrong reason.
    fn private_key_block(rules: &RuleSet, index: &PrefixIndex) -> usize {
        let idx = rules
            .rules
            .iter()
            .position(|r| r.name == "private-key-block")
            .expect("the rule is shipped");
        assert_eq!(
            s(&index.prefixes_for(rules, "private-key-block")),
            vec!["-----BEGIN"],
            "the anchor these rows are about"
        );
        assert!(
            rules.rules[idx].binary && !rules.rules[idx].has_value_group,
            "the `binary` arm is the one that decides these regions"
        );
        assert!(
            index.liveness[idx].is_some(),
            "the `binary` arm falls back to the unconditional hold without \
             an automaton, and then it decides nothing"
        );
        idx
    }

    /// **A streaming private key is held at its own `-----BEGIN`, and the
    /// liveness test is what holds it** (GH #166, spec REQ-O-003).
    ///
    /// This is the half of the `binary` arm's narrowing that must not
    /// move. `cat ~/.ssh/id_rsa` puts a key on the stream whose
    /// `-----END` has not arrived; `private-key-block` can still reach it
    /// from the anchor, so the read stops there and keeps stopping there
    /// for as long as the key keeps arriving. REQ-O-005 settles what
    /// happens if it never does: *"Quiescence does **not** release the
    /// holdback. A partial secret in a session that stopped producing
    /// output stays withheld; `read_output(redact: false)` is the audited
    /// escape hatch."*
    ///
    /// **The byte-class fallback is asserted to disagree**, which is why
    /// the `binary` arm may not simply call [`PrefixIndex::still_alive`]
    /// and take whatever comes back: `is_value_byte` is `false` on the
    /// newline ending the header line, so a `binary` rule that fell into
    /// that fallback would release a key on its second line.
    #[test]
    fn a_streaming_private_key_is_held_at_its_begin_anchor() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let pk = private_key_block(&rules, &index);

        for header in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            // `[ A-Z]{0,10}` after `PRIVATE KEY` is the arm this one
            // needs, and no other header form exercises it.
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ] {
            let text = format!("{header}\n{}", pem_body(50));
            let region = text.as_bytes();

            // Premises. The candidate is found at 0 (condition 1), the
            // rule has not matched (condition 3 is not what decides
            // this), and the region is far past `partial_secret_scan_bytes`
            // so the row is not passing on a fixture that fits.
            assert!(region.starts_with(b"-----BEGIN"), "{header}");
            assert!(region.len() > 512, "{header}: {} bytes", region.len());
            assert!(
                !rules.rules[pk].anchored.is_match(region),
                "{header}: the key is still arriving, so condition 3 must \
                 not be the thing deciding this row"
            );
            assert!(
                !region.iter().all(|b| is_value_byte(*b)),
                "{header}: the byte-class fallback releases this region, so \
                 the `binary` arm must not be reachable by falling into it"
            );

            // Conclusion.
            assert!(
                index.binary_in_flight(pk, region, 0),
                "{header}: the rule can still reach `-----END` from here"
            );
            assert_eq!(
                index.earliest_partial(&rules, region, 0),
                Some(0),
                "{header}: the read must stop at the anchor"
            );
        }

        // And the hold is attributable to this rule rather than to some
        // other candidate that happens to sit at offset 0.
        let text = format!("-----BEGIN RSA PRIVATE KEY-----\n{}", pem_body(50));
        let without = RuleSet::builtin_without(&["private-key-block".to_string()]).unwrap();
        let without_index = PrefixIndex::build(&without, DEFAULT_PREFIX_EXPANSION_LIMIT);
        assert_eq!(
            without_index.earliest_partial(&without, text.as_bytes(), 0),
            None,
            "with `private-key-block` disabled nothing holds this region, so \
             the `Some(0)` above is that rule's and no other's"
        );
    }

    /// **A streaming private key carrying a byte an emitted view removes
    /// is still held** (GH #166; the routes are GH #135's rendered page
    /// and GH #139's 8-bit grammar).
    ///
    /// This row exists because the first version of this change did not
    /// pass it, and nothing else in the tree did either. Handing the
    /// `binary` arm to the automaton alone releases every region below:
    /// `[\s\S]` is a *codepoint* class, so a lone C1 byte or any other
    /// byte that is not part of a well-formed UTF-8 sequence puts the
    /// automaton in a dead state **inside the key body**, and the
    /// boundary goes `Some(0)` to `None` with the body already arrived.
    ///
    /// **And the redactor does not catch it either**, which is the half
    /// that makes it a leak rather than an inefficiency: the same class
    /// keeps `rule.regex` from matching the raw bytes, so `find_spans`
    /// returns no span, there is no marker and no audit entry. What does
    /// cover these bytes is `all_spans` over the *normalised* views —
    /// and only once `-----END` has landed, which by construction it has
    /// not. `holdback_boundary` reads the raw region and nothing else
    /// (spec §4.1), so the hold is the only thing standing here.
    ///
    /// The four rows are one route each: an invalid UTF-8 byte, an ANSI
    /// escape inside the label, a tab the rendered grid expands into the
    /// spaces `[ A-Z]` accepts, and a `\r` that moves the cursor to
    /// column 0 so the rendered row carries text the raw byte order does
    /// not.
    #[test]
    fn a_streaming_private_key_carrying_a_view_sensitive_byte_is_still_held() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let pk = private_key_block(&rules, &index);
        let body = pem_body(40);

        let mut c1 = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        c1.extend_from_slice(&body.as_bytes()[..512]);
        c1.push(0x9b);
        c1.extend_from_slice(&body.as_bytes()[512..]);

        let mut lone_continuation = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        lone_continuation.extend_from_slice(body.as_bytes());
        lone_continuation.push(0xbf);

        let mut escape = b"-----BEGIN \x1b[0mRSA PRIVATE KEY-----\n".to_vec();
        escape.extend_from_slice(body.as_bytes());

        let mut tab = b"-----BEGIN\tRSA PRIVATE KEY-----\n".to_vec();
        tab.extend_from_slice(body.as_bytes());

        let mut carriage = b"-----BEGIN CERTIFICATE\r-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        carriage.extend_from_slice(body.as_bytes());

        // **Two of the five routes changed shape at GH #242, and neither
        // changed what reaches the wire.** A `-----BEGIN` candidate is now
        // believed only while what follows can be PEM text (`pem.rs`), so:
        //
        // * the lone continuation byte is not PEM text and *ends* the
        //   candidate — which no longer releases it, because a candidate
        //   that dies with key material behind it is masked from its
        //   anchor to the byte that killed it. The hold becomes a mask; the
        //   key body stays off every surface. Asserted below the loop.
        // * the redraw's first anchor dies on the `\r` inside its label, and
        //   the second — the header the rendered row actually shows — is
        //   the one held. What is released is `-----BEGIN CERTIFICATE\r`,
        //   which is not a secret, and the grid judges the row it renders
        //   on its own account. Asserted below the loop.
        for (name, region) in [
            ("c1-in-body", &c1),
            ("escape-in-label", &escape),
            ("tab-in-label", &tab),
        ] {
            // Premises. The candidate is found, the region is far past
            // 512 bytes, and — the one that makes this a leak — the
            // rule's own regex cannot match these bytes, so nothing
            // downstream of a release would have redacted them.
            assert!(region.starts_with(b"-----BEGIN"), "{name}");
            assert!(region.len() > 512, "{name}: {} bytes", region.len());
            assert!(
                !rules.rules[pk].regex.is_match(region),
                "{name}: if the raw regex matched, `find_spans` would cover \
                 these bytes and the hold would not be the only protection"
            );
            assert!(
                !region.iter().all(|b| is_plain_text_byte(*b)),
                "{name}: the row is about a byte a view alters, so it has to \
                 contain one"
            );

            // Conclusion.
            assert!(
                index.binary_in_flight(pk, region, 0),
                "{name}: a key is still arriving and the raw bytes cannot \
                 decide otherwise"
            );
            assert_eq!(
                index.earliest_partial(&rules, region, 0),
                Some(0),
                "{name}: the read must stop at the anchor"
            );
        }

        // The lone continuation byte: not in flight, and masked instead.
        let kill = lone_continuation.len() - 1;
        assert!(!rules.rules[pk].regex.is_match(&lone_continuation));
        assert!(!index.binary_in_flight(pk, &lone_continuation, 0));
        assert_eq!(
            index.unterminated_candidates(&rules, &lone_continuation, 0, RegionEnd::Arriving),
            vec![Unterminated {
                start: 0,
                end: kill as u64,
                in_flight: false,
                material: true,
                resumed: false,
            }],
            "the whole body in front of the byte that ended it is reported, \
             and every surface masks what is reported"
        );

        // The redraw: the anchor that is held is the one a terminal shows.
        let second = carriage
            .windows(10)
            .rposition(|w| w == b"-----BEGIN")
            .expect("the fixture carries two anchors");
        assert!(second > 0 && !rules.rules[pk].regex.is_match(&carriage));
        assert_eq!(
            index.earliest_partial(&rules, &carriage, 0),
            Some(second as u64),
            "the body is held from the header the rendered row shows"
        );
    }

    /// **A streaming certificate is released, because the rule anchored
    /// at its `-----BEGIN` can never match** (GH #166).
    ///
    /// A certificate is not a secret — it is the half of a key pair a
    /// server hands every client that connects to it — and
    /// `private-key-block` says so itself: `-----BEGIN CERTIFICATE-----`
    /// is the rule's own shipped `negative` example. What it *is* is a
    /// literal match for the rule's indexed prefix, so before GH #166 the
    /// `binary` arm answered "in flight" about it unconditionally and
    /// condition 3 never revisited that, because the rule had not matched
    /// and never would. `holdback_boundary` then pinned at the anchor for
    /// the rest of the session.
    ///
    /// Spec §9.2 states the shape on the stream path in the same terms:
    /// *"Without this clause, `-----BEGIN CERTIFICATE-----` — a prefix
    /// that matches `private-key-block`'s opening and can never complete
    /// its pattern — blackens an observer's stream for the rest of the
    /// session."*
    ///
    /// **The release is not a hole in REQ-O-003.** Its subject is *"the
    /// earliest **in-flight secret prefix**"*; a prefix from which no
    /// arriving byte can produce a match is not one, and a DEAD state is
    /// that statement about this rule and this anchor exactly.
    #[test]
    fn a_streaming_certificate_is_released_because_its_rule_cannot_complete() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let pk = private_key_block(&rules, &index);
        assert!(
            rules.rules[pk]
                .negative
                .iter()
                .any(|n| n == "-----BEGIN CERTIFICATE-----"),
            "the rule declares a certificate a non-match; this row is that \
             declaration reaching the holdback"
        );

        let text = format!("-----BEGIN CERTIFICATE-----\n{}", pem_body(50));
        let region = text.as_bytes();

        // Premises: every condition except liveness is satisfied, so
        // liveness is the only thing that can release this region.
        assert!(region.starts_with(b"-----BEGIN"));
        assert!(region.len() > 512, "{} bytes", region.len());
        assert!(
            !rules.rules[pk].anchored.is_match(region),
            "condition 3 cannot be what releases this — the rule has not \
             matched and cannot"
        );

        // Conclusion.
        assert!(
            !index.binary_in_flight(pk, region, 0),
            "` CERTIFICATE` fits `[ A-Z]{{0,20}}` but the `-` that follows \
             is neither another gap byte nor the `P` of `PRIVATE KEY`, so \
             the automaton is in a dead state"
        );
        assert!(
            region[..28].iter().all(|b| is_plain_text_byte(*b)),
            "and it dies inside that plain-ASCII label, which is what makes \
             the dead state believable at all"
        );
        assert_eq!(
            index.earliest_partial(&rules, region, 0),
            None,
            "nothing is in flight, so the read must not stop"
        );

        // **The narrowing is per-anchor, not per-region.** A combined PEM
        // — a certificate followed by its key, which is what an haproxy
        // or a stunnel bundle is — carries two candidates, and the dead
        // one must not release the live one. `earliest_partial` walks
        // left to right and returns the first *qualifying* position, so
        // the certificate's bytes go out and the key's do not.
        let bundle = format!(
            "-----BEGIN CERTIFICATE-----\n{}-----END CERTIFICATE-----\n\
             -----BEGIN RSA PRIVATE KEY-----\n{}",
            pem_body(20),
            pem_body(20)
        );
        let key_at = bundle
            .find("-----BEGIN RSA")
            .expect("the bundle carries a second anchor") as u64;
        assert!(key_at > 512, "the key's anchor is at {key_at}");
        assert_eq!(
            index.earliest_partial(&rules, bundle.as_bytes(), 0),
            Some(key_at),
            "the boundary moves to the key's own anchor, not to the \
             certificate's and not to nowhere"
        );
    }

    /// **A finished certificate followed by ordinary output does not
    /// strand the session** (GH #166).
    ///
    /// This is the row that separates "the holdback waited for more
    /// bytes" from "the holdback will never release". `-----END
    /// CERTIFICATE-----` has landed, a build has printed two lines after
    /// it, and nothing about the session is in flight — yet the anchor is
    /// still in the region and the rule still has not matched, so an
    /// unconditional `binary` arm answers `held_back: true` here and at
    /// every later read for as long as those bytes are in the scan
    /// window.
    ///
    /// It is asserted at a region far wider than
    /// `partial_secret_scan_bytes`' 512 (spec REQ-O-007: *"The
    /// partial-secret scan is bounded by `partial_secret_scan_bytes`
    /// (default 512)"*) because 512 is what hides it today: the anchor
    /// falls out of the window before the certificate ends, so the strand
    /// is prevented by accident rather than by the predicate. This row is
    /// the one that keeps widening that window from re-introducing it.
    #[test]
    fn a_finished_certificate_followed_by_build_output_does_not_strand() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let pk = private_key_block(&rules, &index);

        let text = format!(
            "-----BEGIN CERTIFICATE-----\n{}-----END CERTIFICATE-----\n\
             $ cargo build\n   Compiling holdfast-core v0.0.7\n\
                 Finished `dev` profile in 0.41s\n",
            pem_body(50)
        );
        let region = text.as_bytes();

        // Premises.
        assert!(region.starts_with(b"-----BEGIN"));
        assert!(region.len() > 512, "{} bytes", region.len());
        assert!(
            !rules.rules[pk].anchored.is_match(region),
            "`-----END CERTIFICATE-----` does not satisfy a rule that wants \
             `-----END…PRIVATE KEY-----`, so condition 3 never fires here — \
             which is precisely why the old arm stranded"
        );

        // Conclusion.
        assert!(!index.binary_in_flight(pk, region, 0));
        assert_eq!(
            index.earliest_partial(&rules, region, 0),
            None,
            "the session is not withholding anything; there is nothing left \
             that could arrive to make this rule match"
        );
    }

    // ---------------------------------------------------------------
    // GH #163 — the three cheap steps, and the proof they change no
    // answer.
    // ---------------------------------------------------------------

    /// Step 0: the 256-slot array routes every byte value to the bucket
    /// the `HashMap<u8, _>` it replaced held under the same key.
    ///
    /// **All 256 values, not the ones a fixture happens to contain.** The
    /// mutation this exists for is indexing by `byte` where the map was
    /// keyed by `byte.to_ascii_lowercase()`: it is invisible on any
    /// lowercase input and silently un-indexes every `(?i)` rule — which
    /// is all nine context rules — against uppercase output.
    #[test]
    fn every_first_byte_routes_to_the_bucket_the_map_held() {
        for (label, rules) in [
            ("built-in", RuleSet::builtin().unwrap()),
            (
                "built-in + adversarial user rules",
                RuleSet::builtin_with_extra(ADVERSARIAL_USER_RULES).unwrap(),
            ),
        ] {
            let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);

            // The map `build` used to fill, keyed the way it keyed it.
            let mut map: HashMap<u8, Vec<(Vec<u8>, usize)>> = HashMap::new();
            for bucket in index.by_first_byte.iter() {
                for c in bucket {
                    map.entry(c.prefix[0].to_ascii_lowercase())
                        .or_default()
                        .push((c.prefix.clone(), c.rule));
                }
            }

            for byte in 0u8..=0xff {
                let got: Vec<(Vec<u8>, usize)> = index
                    .bucket(byte)
                    .iter()
                    .map(|c| (c.prefix.clone(), c.rule))
                    .collect();
                let want = map
                    .get(&byte.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_default();
                assert_eq!(
                    got, want,
                    "{label}: byte {byte:#04x} ({:?}) does not route to the \
                     bucket the map held for it",
                    byte as char
                );
            }

            // The array is the whole index and nothing fell out of it.
            let slotted: usize = index.by_first_byte.iter().map(|b| b.len()).sum();
            assert_eq!(slotted, index.len(), "{label}: prefixes lost in the array");

            // And the fold is load-bearing rather than incidental: an
            // uppercase byte must reach a non-empty lowercase bucket, or
            // the assertion above is satisfied by two empty lists.
            assert!(
                !index.bucket(b'S').is_empty()
                    && index.bucket(b'S').len() == index.bucket(b's').len(),
                "{label}: `S` must reach the `s` bucket, which must not be empty"
            );
        }
    }

    /// The suffix fact is the predicate it replaces, at every index —
    /// asserted directly, because both rewrites below rest on it.
    #[test]
    fn the_suffix_fact_is_exactly_the_walk_it_replaces() {
        let regions: &[&[u8]] = &[
            b"",
            b" ",
            b"a",
            b"abc",
            b"abc ",
            b" abc",
            b"ab cd",
            b"ghp_abcdef\n",
            b"\n\n\n",
            b"\x00\x7f\x80\xffabc",
        ];
        for region in regions {
            let t = value_tail_start(region);
            for k in 0..=region.len() {
                assert_eq!(
                    k >= t,
                    region[k..].iter().all(|b| is_value_byte(*b)),
                    "region {region:?}, k = {k}, value_tail = {t}"
                );
            }
            // The `Option` spelling, pinned against the **pre-GH #163
            // walk** rather than against its own new body — otherwise
            // this row restates the implementation and proves nothing
            // about the rewrite.
            let mut i = region.len();
            while i > 0 && is_value_byte(region[i - 1]) {
                i -= 1;
            }
            assert_eq!(
                trailing_value_run_start(region),
                (i < region.len()).then_some(i),
                "region {region:?}: the `Option` spelling moved"
            );
        }
    }

    /// User rules whose declared prefixes contain a byte no value may
    /// contain — the only shape that separates GH #163's suffix fact
    /// from the two ways of spelling it wrong.
    ///
    /// **Neither mutation is reachable from the shipped fifty-one**, and
    /// that is a fact about the rule file rather than about the rewrite:
    /// every shipped prefix is printable and space-free, so `value_tail`
    /// can never land strictly inside one, and the anchor and the value
    /// start are never on opposite sides of it. An operator's rule may
    /// put a space in a label, and `extra_redaction_patterns` takes one.
    const SUFFIX_FACT_USER_RULES: &str = r#"
        [[rule]]
        name = "acme-spaced-label"
        kind = "acme-internal"
        pattern = '''(?i)acmepw [:=]?\s*(?P<value>[A-Za-z0-9]{8,})'''
        prefixes = ["acmepw "]
        positive = ["acmepw ABCDEFGH"]
        negative = ["acmepw ABC"]

        [[rule]]
        name = "acme-spaced-punct-prefix"
        kind = "acme-internal"
        pattern = '''\b-zb- [A-Za-z0-9]{10,}'''
        prefixes = ["-zb- "]
        positive = ["x-zb- ABCDEFGHIJ"]
        negative = ["x-zb- ABC"]
    "#;

    /// Step 1, and the two mutations that prove which slice each arm
    /// asks about.
    ///
    /// * `has_value_group` asks about **`value_start`**: at
    ///   `value_start == value_tail` the arm holds, and a `>` releases.
    /// * the no-automaton fallback asks about **the anchor**: with the
    ///   non-value byte inside the prefix, `at < value_tail <= value_start`,
    ///   and spelling the fallback `value_start >= value_tail` withholds
    ///   bytes the shipped scan released.
    #[test]
    fn each_arm_asks_the_suffix_fact_about_its_own_slice() {
        let rules = RuleSet::builtin_with_extra(SUFFIX_FACT_USER_RULES).unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);

        let spaced = rules
            .rules
            .iter()
            .position(|r| r.name == "acme-spaced-label")
            .unwrap();
        let punct = rules
            .rules
            .iter()
            .position(|r| r.name == "acme-spaced-punct-prefix")
            .unwrap();
        assert!(
            rules.rules[spaced].has_value_group,
            "the premise of the first half: this rule reaches the \
             `has_value_group` arm"
        );
        assert!(
            index.liveness[punct].is_none(),
            "the premise of the second half: a `\\b` pattern whose prefix \
             opens on punctuation is refused an automaton, so it reaches \
             the fallback — the arm the shipped fifty-one cannot"
        );

        // -- the `has_value_group` arm, at `value_start == value_tail` --
        let region: &[u8] = b"acmepw ABCDEFG";
        assert_eq!(
            value_tail_start(region),
            7,
            "the space is the last non-value byte"
        );
        assert_eq!(
            index.earliest_partial(&rules, region, 0),
            Some(0),
            "seven of the eight value characters have arrived, so the label \
             is a credential in flight. `value_start > value_tail` releases \
             it, and the trailing run starts exactly at the value"
        );

        // -- the fallback, with the anchor and the value start straddling
        //    `value_tail` --
        let region: &[u8] = b"-zb- ABCDEF";
        assert_eq!(value_tail_start(region), 5);
        assert_eq!(
            index.earliest_partial(&rules, region, 0),
            None,
            "the space inside the prefix is a byte no value may contain, so \
             the rule cannot match from the anchor — asking the suffix fact \
             about `value_start` instead of the anchor withholds this"
        );
    }

    /// One non-value byte at the very end of the region kills the
    /// `has_value_group` arm at **every** earlier anchor, however many
    /// labels the region carries.
    #[test]
    fn one_non_value_byte_at_the_end_kills_the_arm_at_every_anchor() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);

        let open = b"password=aaaa secret=bbbb password=cccc api_key=dddd";
        assert!(
            index.earliest_partial(&rules, open, 0).is_some(),
            "the premise: these labels are candidates while the run is open"
        );

        let mut closed = open.to_vec();
        closed.push(b'\n');
        assert_eq!(
            value_tail_start(&closed),
            closed.len(),
            "the trailing run is empty, so no index can be at or above it"
        );
        assert_eq!(
            index.earliest_partial(&rules, &closed, 0),
            None,
            "a single `\\n` at the end ends every candidate in the region at \
             once — the arm is a fact about the region's suffix, not about \
             the distance from any one anchor"
        );
    }

    /// Step 2': the scan ceiling is `unresolved_from`'s and reaches no
    /// other surface.
    ///
    /// The ceiling is sound **only** under the `min` that
    /// `unresolved_from` composes. Applied to the public predicate it
    /// answers `None` where the scan answers `Some`, which is
    /// `holdback_boundary` releasing a token still arriving.
    #[test]
    fn the_scan_ceiling_is_confined_to_unresolved_from() {
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);

        // A region whose only candidate sits *inside* the trailing run,
        // so the ceiling would suppress it.
        let region: &[u8] = b"$ echo ghp_abcdef";
        let tail = value_tail_start(region);
        assert_eq!(tail, 7, "the space before the token starts the run");

        assert_eq!(
            index.earliest_partial(&rules, region, 1000),
            Some(1007),
            "the public predicate must not take the ceiling: this is the \
             GitHub token `holdback_boundary` is withholding"
        );
        assert_eq!(
            index.earliest_partial_bounded(&rules, region, 1000, tail, tail),
            None,
            "the premise — the ceiling really does change this scan's own \
             answer, which is why it may not be applied to the one above"
        );
        assert_eq!(
            index.unresolved_from(&rules, region, 1000),
            Some(1007),
            "and the composed answer is unchanged, because the trailing run \
             starts at the same place"
        );
    }

    /// A deterministic xorshift64*, so the differential corpus below is
    /// reproducible and needs no dependency.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// A random rule set, spelled as `extra_redaction_patterns` TOML.
    ///
    /// **The generator's job is the fallback arm.** A word-leading prefix
    /// gets an automaton and never reaches it; the shapes that do are a
    /// `\B` anywhere in the pattern and a punctuation-opening prefix
    /// under a `\b`. A prefix carrying a space is what puts `value_tail`
    /// somewhere other than the two places a shipped rule can put it.
    fn random_rule_toml(rng: &mut Rng, n: usize) -> String {
        const HEAD: &[&str] = &["acme", "zq", "tok", "kx", "b7"];
        const BODY: &[&str] = &["-", "_", " ", "", "."];
        const CLASS: &[&str] = &["[A-Za-z0-9]", "[A-Za-z0-9_-]", "[a-f0-9]"];
        let mut out = String::new();
        for i in 0..n {
            let head = HEAD[rng.below(HEAD.len())];
            let body = BODY[rng.below(BODY.len())];
            let lead = if rng.below(3) == 0 { "-" } else { "" };
            let prefix = format!("{lead}{head}{body}k{i}{body}");
            let class = CLASS[rng.below(CLASS.len())];
            let fold = if rng.below(2) == 0 { "(?i)" } else { "" };
            let (pattern, declared) = match rng.below(4) {
                0 => (format!("{fold}\\b{prefix}(?P<value>{class}{{6,}})"), true),
                1 => (format!("{fold}\\b{prefix}{class}{{8,}}\\B[0-9]{{2}}"), true),
                2 => (format!("{fold}\\b{prefix}{class}{{10,}}"), true),
                _ => (format!("{fold}{prefix}{class}{{4,}}"), rng.below(2) == 0),
            };
            out.push_str(&format!(
                "[[rule]]\nname = \"g163-{i}\"\nkind = \"g163\"\npattern = '''{pattern}'''\n"
            ));
            if declared {
                out.push_str(&format!("prefixes = [\"{prefix}\"]\n"));
            }
            if rng.below(8) == 0 {
                out.push_str("binary = true\n");
            }
            out.push_str(&format!(
                "positive = [\"x{prefix}ABCDEFabcdef0123456789\"]\nnegative = [\"x{prefix}\"]\n\n"
            ));
        }
        out
    }

    fn random_region(rng: &mut Rng, prefixes: &[Vec<u8>]) -> Vec<u8> {
        const DELIMS: &[u8] = b" \t\r\n:=\"',;()[]{}\x00\x1b\x7f\x80\xc3\xff";
        const VALUES: &[u8] = b"abcdefABCDEF0123456789-_.";
        let mut out = Vec::new();
        for _ in 0..1 + rng.below(8) {
            match rng.below(6) {
                0 | 1 if !prefixes.is_empty() => {
                    let p = prefixes[rng.below(prefixes.len())].clone();
                    for b in &p {
                        out.push(if rng.below(4) == 0 {
                            b.to_ascii_uppercase()
                        } else {
                            *b
                        });
                    }
                }
                2 => {
                    for _ in 0..rng.below(24) {
                        out.push(VALUES[rng.below(VALUES.len())]);
                    }
                }
                3 => out.push(DELIMS[rng.below(DELIMS.len())]),
                4 => {
                    for _ in 0..rng.below(8) {
                        out.push(rng.next_u64() as u8);
                    }
                }
                _ => out.extend_from_slice(b"-sk-"),
            }
        }
        out
    }

    fn index_prefixes(index: &PrefixIndex) -> Vec<Vec<u8>> {
        index
            .by_first_byte
            .iter()
            .flatten()
            .map(|c| c.prefix.clone())
            .collect()
    }

    /// **The answer-preservation proof for all three steps**, against the
    /// implementation they replaced, over the shipped rule set, the
    /// adversarial user rules, the suffix-fact rules and randomly
    /// generated rule sets.
    ///
    /// Random rule sets are not decoration. Every rule the shipped file
    /// refuses an automaton is a `has_value_group` context rule, which
    /// never reaches [`PrefixIndex::still_alive`] at all — so the arm the
    /// `at` / `value_start` mutation lives in is dead code against the
    /// built-in fifty-one, and a hand corpus over them cannot kill it.
    #[test]
    fn the_cheap_steps_answer_what_the_pre_163_scan_did() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut checks = 0usize;

        fn check(index: &PrefixIndex, rules: &RuleSet, region: &[u8], label: &str) {
            for start in [0u64, 1_000_000] {
                assert_eq!(
                    index.earliest_partial(rules, region, start),
                    index.earliest_partial_reference(rules, region, start),
                    "{label}: earliest_partial diverged on {region:?} at {start}"
                );
                assert_eq!(
                    index.unresolved_from(rules, region, start),
                    index.unresolved_from_reference(rules, region, start),
                    "{label}: unresolved_from diverged on {region:?} at {start}"
                );
            }
        }

        for (label, rules) in [
            ("built-in", RuleSet::builtin().unwrap()),
            (
                "adversarial",
                RuleSet::builtin_with_extra(ADVERSARIAL_USER_RULES).unwrap(),
            ),
            (
                "suffix-fact",
                RuleSet::builtin_with_extra(SUFFIX_FACT_USER_RULES).unwrap(),
            ),
        ] {
            let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
            let prefixes = index_prefixes(&index);
            for _ in 0..3_000 {
                let region = random_region(&mut rng, &prefixes);
                check(&index, &rules, &region, label);
                checks += 1;
            }
        }

        let mut random_sets = 0usize;
        for round in 0..400 {
            let n = 1 + rng.below(5);
            let toml = random_rule_toml(&mut rng, n);
            let Ok(rules) = RuleSet::from_toml(&toml) else {
                continue;
            };
            random_sets += 1;
            let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
            let prefixes = index_prefixes(&index);
            for _ in 0..40 {
                let region = random_region(&mut rng, &prefixes);
                check(&index, &rules, &region, &format!("random rule set {round}"));
                checks += 1;
            }
        }

        assert!(
            random_sets > 300,
            "only {random_sets} random rule sets compiled"
        );
        assert!(checks > 20_000, "only {checks} regions checked");

        // **The refused-value regions, by hand, because the generator
        // cannot reach them (GH #202).** `random_region` splices indexed
        // prefixes with random bytes, and the odds of it producing a
        // value that is digit-free *and* carries one of
        // `( < > [ ] { } | \` or a backtick are negligible — so with
        // `value_must_not_match` shipped, reverting either scan to
        // `anchored.is_match` left this whole target green. That is the
        // hole these rows close: the implementation and its oracle have
        // to agree on the arm where a rule matches and then declines.
        let rules = RuleSet::builtin().unwrap();
        let index = PrefixIndex::build(&rules, DEFAULT_PREFIX_EXPANSION_LIMIT);
        let mut in_flight = 0usize;
        for region in [
            // refused: no digit, and a bracket, pipe or backtick
            &b"API_KEY=abcd(efgh"[..],
            b"$ echo password=my{pass}phrase",
            b"reassembled the token: `get_screen_state`",
            b"export TOKEN={GITHUB}",
            b"pub session_key: Option<SessionKey>,",
            b"auth_token=alpha|bravo|charlie",
            // admitted: the same shape with a digit, and two passphrases
            b"API_KEY=abcd(efg1",
            b"password=correcthorsebatterystaple",
            b"MASTER_KEY=correct.horse.battery.staple",
        ] {
            check(&index, &rules, region, "refused-value");
            if index.earliest_partial(&rules, region, 0).is_some() {
                in_flight += 1;
            }
        }
        // **Not vacuous, and asserted as a discriminating pair rather
        // than only a count.** Two regions differing in one byte: the
        // refused one is held in flight, the admissible one is released
        // because `find_spans` will redact it. `check` above proves the
        // oracle agrees; this proves there is something to agree about.
        assert!(
            index
                .earliest_partial(&rules, b"API_KEY=abcd(efgh", 0)
                .is_some(),
            "a refused value must be in flight, or the rows above agree about nothing"
        );
        assert!(
            index
                .earliest_partial(&rules, b"API_KEY=abcd(efg1", 0)
                .is_none(),
            "one digit makes the same value admissible, and an admissible whole \
             match is released rather than held"
        );
        assert!(
            in_flight >= 3,
            "only {in_flight} of the hand rows are in flight; a region whose value \
             does not run to its end is not a candidate at all, so this floor sits \
             below the row count on purpose"
        );
    }
}
