//! The redaction rule set: TOML schema, loader, compiled form.
//!
//! The rule file (spec §9.2) is the single source of truth for what a
//! secret looks like. Everything downstream — the redactor, the prefix
//! index, the partial-secret scanner — derives from it, so there is no
//! second list to keep in sync.

pub use super::redact::UNRESOLVED_KIND;

use regex::bytes::{Regex, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use std::sync::{Arc, OnceLock};

/// The vendored default rule set, compiled into the binary.
pub const DEFAULT_RULES_TOML: &str = include_str!("../../data/redaction_default.toml");

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("redaction rules are not valid TOML: {0}")]
    Toml(String),
    #[error("rule `{name}` has an invalid pattern: {source}")]
    Pattern { name: String, source: regex::Error },
    #[error("rule `{0}` must declare at least one positive and one negative example")]
    MissingExamples(String),
    /// REQ-O-011a: `unresolved` is the marker a bounded window emits for a
    /// match it *could not judge*, so it is the one kind that names no
    /// rule. A rule claiming it would make `[REDACTED:unresolved]`
    /// ambiguous between "this rule matched" and "nothing matched and we
    /// withheld anyway", which is exactly the distinction the string
    /// exists to carry. Rejected at compile time so an operator's
    /// `extra_redaction_patterns` cannot take it either (§10.2).
    #[error("rule `{0}` claims the reserved kind `unresolved`, which names no rule (REQ-O-011a)")]
    ReservedKind(String),
    /// GH #128: `[security] disabled_redaction_rules` names a rule the
    /// built-in set does not have.
    ///
    /// A name that matches nothing switches off nothing, while reading
    /// — in the operator's own file — as a decision about redaction that
    /// has been taken. That is the shape GH #128 is about, so it is an
    /// error rather than a no-op.
    /// [`Config::validate`](crate::config::Config::validate) refuses it
    /// at load, which is where an operator sees it; this variant is the
    /// same refusal at the rule compiler, for a `Config` built in code
    /// rather than parsed.
    #[error("no built-in redaction rule is named `{name}`; the built-in set has {count}")]
    UnknownRule { name: String, count: usize },
    // GH #202 had a `ValueConstraintWithoutValue` variant here: declaring
    // `value_must_not_match` on a rule with no `value` group was a load
    // error, because such a rule had nowhere to apply it. GH #245 gave it
    // somewhere — a rule with no `value` group redacts its whole match,
    // so its whole match is what the refusal judges — and a refusal with
    // a subject is no longer a silent no-op, which was the only ground
    // for the error. See `RuleSpec::value_must_not_match`.
}

/// Top level of the rule file.
#[derive(Debug, Default, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub source_version: String,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleSpec>,
}

/// One rule as written in TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSpec {
    pub name: String,
    pub kind: String,
    pub pattern: String,
    /// Literal prefixes for the partial-secret index (§4.1). Auto-derived
    /// from `pattern` when absent.
    #[serde(default)]
    pub prefixes: Option<Vec<String>>,
    /// True when the value may contain whitespace or control bytes (PEM
    /// blocks). Governs the partial-secret scanner's continuation test.
    #[serde(default)]
    pub binary: bool,
    /// A regex which, when it matches the **whole** of the `value`
    /// capture, disqualifies the candidate: the rule found its label and
    /// its separator, and then judged what followed not to be a
    /// credential (GH #202).
    ///
    /// **This is upstream gitleaks' own mechanism and its own polarity.**
    /// `generic-api-key` carries an allowlist whose `regexes` are tested
    /// against the captured secret and suppress the finding on a full
    /// match; at the pinned `gitleaks-8.28.0` that regex is
    /// `^[a-zA-Z_.-]+$`, upstream's documented workaround for the
    /// positive lookahead Go's engine does not have. This field is that
    /// same test, and upstream's regex can be written into it verbatim.
    /// What the shipped rules put in it is **not** upstream's regex, and
    /// the rule file says why: measured over a corpus of real-shaped
    /// credentials, upstream's own value constraints drop ten of
    /// thirty-two, three of them shipped `positive` fixtures of these
    /// very rules.
    ///
    /// **Refusal, not selection, and that is the safe direction.** A
    /// mistake in a *required* pattern refuses a real credential and
    /// leaks it; a mistake in this one admits a candidate that is then
    /// redacted. The field cannot express the first error.
    ///
    /// **What it judges is exactly what the rule would redact** (GH
    /// #245): the `value` capture on a rule that has one, and the whole
    /// match on a rule that does not. GH #202 made the second case a load
    /// error on the ground that such a rule had "no value to judge"; but
    /// a rule without a `value` group redacts its whole match, so the
    /// whole match *is* its value, and the error was keeping a
    /// shape-keyed rule from saying "this is the one shape of my match
    /// that is not a credential" — which is what `openai-api-key` needs
    /// for OpenSSH's `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com`.
    #[serde(default)]
    pub value_must_not_match: Option<String>,
    #[serde(default)]
    pub positive: Vec<String>,
    #[serde(default)]
    pub negative: Vec<String>,
}

/// A rule with its regexes compiled.
#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub kind: String,
    /// Source text, kept so the prefix index can derive literal prefixes.
    pub pattern: String,
    /// Finds occurrences anywhere in a window.
    pub regex: Regex,
    /// The same pattern anchored to the start of the haystack. The
    /// partial-secret scanner asks "has the whole token arrived yet?" by
    /// running this against `buffer[candidate .. head]`, so the answer
    /// can never drift from the rule that produced the candidate.
    pub anchored: Regex,
    /// Prefixes exactly as declared in TOML, if any.
    pub declared_prefixes: Option<Vec<Vec<u8>>>,
    pub binary: bool,
    /// Whether `pattern` has a capture group named `value`; when it does
    /// only that group is redacted, leaving the context prefix visible.
    pub has_value_group: bool,
    /// [`RuleSpec::value_must_not_match`], compiled and anchored to both
    /// ends of the value — the `value` capture, or the whole match on a
    /// rule without one — with `\A…\z` and forced into **byte** mode.
    ///
    /// Both of those are load-bearing. Anchoring is what makes the field
    /// a judgement about the whole value rather than about some substring
    /// of it — and it is upstream's semantics, whose `^…$` does the same.
    /// Byte mode is what keeps a value that is not valid UTF-8 from
    /// silently failing every `.` in the refusal and so being *admitted*
    /// by accident; a credential arrives as bytes and this rule set
    /// matches bytes everywhere else.
    pub value_refusal: Option<Regex>,
    pub positive: Vec<String>,
    pub negative: Vec<String>,
}

impl CompiledRule {
    /// Whether the bytes this rule would redact — its `value` capture, or
    /// its whole match when it has no `value` group — are still a
    /// credential once the rule's own refusal has looked at them (GH #202,
    /// GH #245).
    ///
    /// `true` for every rule that declares no refusal, which is most of
    /// the shipped set and every user rule that does not ask for one.
    /// `only_the_rules_named_for_it_carry_a_value_refusal` pins which
    /// shipped rules do.
    pub fn value_admissible(&self, value: &[u8]) -> bool {
        match &self.value_refusal {
            None => true,
            Some(re) => !re.is_match(value),
        }
    }

    /// The partial-secret scanner's completeness test: *has a whole
    /// match arrived at `hay`'s start, and will `find_spans` emit a span
    /// for it?*
    ///
    /// **The second clause is the one that is easy to drop, and dropping
    /// it is a leak.** `PrefixIndex::earliest_partial` stops holding a
    /// candidate back the moment a whole match exists, on the ground
    /// that `find_spans` will redact it. A refused value breaks that
    /// ground: the regex matches, `find_spans` declines, and the bytes
    /// go out raw — while the value is *still growing*. `API_KEY=abcdefgh`
    /// at the buffer head is refused, released, and one `9` later it is
    /// `abcdefgh9`, a credential whose first eight bytes the agent
    /// already has. Asking the refusal here keeps the candidate in
    /// flight until it is terminated, which is the direction §4.1 is
    /// allowed to err in.
    ///
    /// **A rule without a `value` group is asked the same question of
    /// its whole match** (GH #245), because that is what `find_spans`
    /// judges for it. `openai-api-key` refuses OpenSSH's
    /// `sk-ecdsa-sha2-nistp256-cert-v01`; at the buffer head that name is
    /// a whole match the redactor will decline, so it stays in flight
    /// until the `@` that follows it kills the rule — rather than being
    /// released on the ground that a marker covers it.
    pub fn anchored_whole_match(&self, hay: &[u8]) -> bool {
        match (&self.value_refusal, self.has_value_group) {
            (Some(_), true) => match self.anchored.captures(hay) {
                Some(caps) => match caps.name("value") {
                    Some(m) => self.value_admissible(m.as_bytes()),
                    // A `value` group that did not participate cannot be
                    // judged, so the match is not one this rule will act
                    // on. Unreachable for the shipped set (every shipped
                    // rule's group is unconditional) and deliberately
                    // the hold-back answer rather than the release one.
                    None => false,
                },
                None => false,
            },
            (Some(_), false) => match self.anchored.find(hay) {
                Some(m) => self.value_admissible(m.as_bytes()),
                None => false,
            },
            (None, _) => self.anchored.is_match(hay),
        }
    }
}

/// The active rule set: compiled rules plus a `RegexSet` prefilter.
#[derive(Debug)]
pub struct RuleSet {
    pub source_version: String,
    pub rules: Vec<CompiledRule>,
    /// Prefilter — names the rules that can possibly match a window
    /// before we pay for per-rule scanning.
    pub prefilter: RegexSet,
}

impl RuleSet {
    /// The vendored default set.
    pub fn builtin() -> Result<Self, RuleError> {
        Self::from_toml(DEFAULT_RULES_TOML)
    }

    /// The vendored default set plus user rules. A user rule whose `name`
    /// matches a built-in replaces it in place (preserving rule order); a
    /// new name is appended after the built-ins (spec §9.2).
    pub fn builtin_with_extra(extra_toml: &str) -> Result<Self, RuleError> {
        let mut file: RuleFile =
            toml::from_str(DEFAULT_RULES_TOML).map_err(|e| RuleError::Toml(e.to_string()))?;
        let extra: RuleFile =
            toml::from_str(extra_toml).map_err(|e| RuleError::Toml(e.to_string()))?;
        for rule in extra.rules {
            match file.rules.iter_mut().find(|r| r.name == rule.name) {
                Some(slot) => *slot = rule,
                None => file.rules.push(rule),
            }
        }
        Self::compile(file)
    }

    /// The vendored default set **minus** the rules an operator switched
    /// off with `[security] disabled_redaction_rules` (GH #128).
    ///
    /// Deliberately shaped like [`builtin_with_extra`](Self::builtin_with_extra)
    /// — parse the vendored file, edit the `RuleSpec` list, compile once
    /// — rather than filtering a compiled [`RuleSet`]. The prefilter
    /// `RegexSet` reports *indices into `rules`*, so removing a compiled
    /// rule means rebuilding the prefilter anyway, and a filter that
    /// forgot to would leave every later rule's index off by the number
    /// removed: every redaction after the first disabled rule would name
    /// the wrong kind. Editing the specs and compiling once cannot have
    /// that bug.
    ///
    /// It is also what REQ-O-006 asks for. The §4.1 prefix index is
    /// *"auto-derived from the **active** redaction rule set"*, and
    /// `OutputProcessor::new` derives it from whatever `RuleSet` it is
    /// handed — so the index follows the reduced set here without a
    /// second edit, and there is no window in which rules and index
    /// disagree (REQ-RTD-002).
    ///
    /// An unknown name is [`RuleError::UnknownRule`], never a silent
    /// no-op. Disabling every rule is legal and yields an empty set: the
    /// operator enumerated every rule by name, the §9.4 row records
    /// exactly that, and the startup line says it — which is the whole
    /// difference between this and the `redaction_enabled = false` that
    /// GH #128 found recording the opposite of what it did.
    pub fn builtin_without(disabled: &[String]) -> Result<Self, RuleError> {
        let mut file: RuleFile =
            toml::from_str(DEFAULT_RULES_TOML).map_err(|e| RuleError::Toml(e.to_string()))?;
        for name in disabled {
            if !file.rules.iter().any(|r| &r.name == name) {
                return Err(RuleError::UnknownRule {
                    name: name.clone(),
                    count: file.rules.len(),
                });
            }
        }
        file.rules
            .retain(|r| !disabled.iter().any(|d| d == &r.name));
        Self::compile(file)
    }

    pub fn from_toml(toml_src: &str) -> Result<Self, RuleError> {
        let file: RuleFile =
            toml::from_str(toml_src).map_err(|e| RuleError::Toml(e.to_string()))?;
        Self::compile(file)
    }

    fn compile(file: RuleFile) -> Result<Self, RuleError> {
        let mut rules = Vec::with_capacity(file.rules.len());
        let mut patterns = Vec::with_capacity(file.rules.len());
        for spec in file.rules {
            // **First**, ahead of the examples guard, so a rule
            // declaring the reserved kind is reported on *that* ground
            // rather than on whatever else happens to be wrong with it.
            // Nothing shipped reaches either branch: `unresolved`
            // appears zero times under `crates/`.
            if spec.kind == UNRESOLVED_KIND {
                return Err(RuleError::ReservedKind(spec.name));
            }
            if spec.positive.is_empty() || spec.negative.is_empty() {
                return Err(RuleError::MissingExamples(spec.name));
            }
            let regex = Regex::new(&spec.pattern).map_err(|source| RuleError::Pattern {
                name: spec.name.clone(),
                source,
            })?;
            // `(?:...)` keeps any inline flags in `spec.pattern` scoped to
            // the original expression rather than leaking past the anchor.
            let anchored = Regex::new(&format!("^(?:{})", spec.pattern)).map_err(|source| {
                RuleError::Pattern {
                    name: spec.name.clone(),
                    source,
                }
            })?;
            let has_value_group = regex.capture_names().any(|n| n == Some("value"));
            // GH #202. `\A…\z` rather than `^…$`: `$` also matches
            // *before* a trailing newline, so a refusal written to
            // reject `foo` would let `foo\n` through, and `binary` rules
            // carry newlines inside their values by construction.
            // `(?s-u:…)` puts the author's own expression in byte mode,
            // where `.` is any byte and a value that is not valid UTF-8
            // cannot slip past a refusal by failing to decode.
            //
            // A rule without a `value` group is no longer refused one
            // (GH #245): its whole match is its value, and
            // `value_admissible` is what `find_spans` asks of it too.
            let value_refusal = match &spec.value_must_not_match {
                None => None,
                Some(src) => Some(Regex::new(&format!(r"\A(?s-u:{src})\z")).map_err(|source| {
                    RuleError::Pattern {
                        name: spec.name.clone(),
                        source,
                    }
                })?),
            };
            patterns.push(prefilter_pattern(&spec.pattern));
            rules.push(CompiledRule {
                name: spec.name,
                kind: spec.kind,
                pattern: spec.pattern,
                regex,
                anchored,
                declared_prefixes: spec
                    .prefixes
                    .map(|ps| ps.into_iter().map(|p| p.into_bytes()).collect()),
                binary: spec.binary,
                has_value_group,
                value_refusal,
                positive: spec.positive,
                negative: spec.negative,
            });
        }
        let verbatim: Vec<String> = rules.iter().map(|r| r.pattern.clone()).collect();
        let prefilter =
            prefilter_or_verbatim(&patterns, &verbatim).map_err(|source| RuleError::Pattern {
                name: "<prefilter>".into(),
                source,
            })?;
        Ok(Self {
            source_version: file.source_version,
            rules,
            prefilter,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The built-in rules this set does **not** carry, by name, sorted
    /// (GH #128).
    ///
    /// **Read off the live set, not off the config.** This is what the
    /// §9.4 `session_start` row and the startup line both report, and
    /// deriving it here means neither can say a rule is off while the
    /// read path still runs it: the only way to make them lie is to
    /// hand the read path a different `RuleSet` than the one asked,
    /// which is a much louder bug than a copied field. That is the
    /// lesson of the row this replaces — `redaction_enabled` copied a
    /// config bool that gated nothing.
    pub fn disabled_builtin_rules(&self) -> Vec<&'static str> {
        let present: std::collections::BTreeSet<&str> =
            self.rules.iter().map(|r| r.name.as_str()).collect();
        builtin_rule_names()
            .iter()
            .filter(|name| !present.contains(name.as_str()))
            .map(String::as_str)
            .collect()
    }
}

/// `[A-Za-z0-9_]` **minus `k`, `K`, `s` and `S`** — the ASCII word
/// characters a `\b` rewrite may lean on.
///
/// The four exclusions are not a superstition and they are not a guess:
/// they are the only ASCII characters whose `(?i)` expansion reaches
/// outside ASCII, `k`/`K` through U+212A KELVIN SIGN and `s`/`S` through
/// U+017F LATIN SMALL LETTER LONG S.
/// `the_case_unstable_ascii_letters_are_derived_and_not_asserted`
/// recomputes the set over the whole of Unicode rather than trusting
/// this sentence. A `(?i)` rule opening `\bsk-` can therefore match a
/// first character that is **not** an ASCII word byte, which is exactly
/// the premise [`prefilter_pattern`]'s first lemma needs.
fn is_case_stable_ascii_word(c: char) -> bool {
    (c.is_ascii_alphanumeric() || c == '_') && !matches!(c, 'k' | 'K' | 's' | 'S')
}

/// The pattern the **prefilter** is built from: the rule's own source
/// with every Unicode word boundary either respelled `(?-u:\b)` or
/// deleted, whichever is provably match-preserving at that boundary
/// (GH #194).
///
/// A Unicode `\b` installs a quit set over every byte ≥ 0x80, so one
/// `é` anywhere in a read window drops the whole `RegexSet` onto the
/// slow engine. Measured on REQ-O-007's 41,472 B default read window,
/// release, prefilter scan only: **0.082 ms pure ASCII against 37.4 ms
/// with one em dash at the midpoint, 456x** — and the shipped file then
/// put a `\b` in forty-five of its fifty-one rules, so the prefilter had
/// been paying that on any output carrying a glyph.
///
/// **Why *every* boundary has to go and not just the unprovable ones.**
/// A `RegexSet` is one automaton over all the patterns. Leaving a single
/// Unicode `\b` in the set re-arms the quit set for the set, so the
/// per-rule refusal `PrefixIndex::build` can afford — where a refused
/// rule simply keeps `is_value_byte` — has no analogue here. Deleting
/// the boundary is what makes a refusal expressible at all.
///
/// # The contract, and which direction it runs in
///
/// The prefilter is a *filter*: [`redact::find_spans`] runs only the
/// rules it names. Naming a rule that cannot match costs one wasted
/// `Regex` pass; failing to name one that can is a credential going out
/// unredacted. So the property to preserve is **superset**, and it is
/// preserved by two lemmas, one per branch:
///
/// * **Deleting an assertion can only enlarge the language.** Every
///   accepting path through the original automaton is still an accepting
///   path when a zero-width assertion is taken out of it, so
///   `L(P without \b) ⊇ L(P)` unconditionally, for any position and any
///   nesting. This branch needs no premise about the rule and is the
///   fallback for every boundary the other lemma cannot reach. (The
///   deletion is spelled `(?:)` rather than nothing, because `x\b?`
///   parses and `x?` is not what it meant.)
///
/// * **`\b` → `(?-u:\b)` is superset-preserving at a boundary whose
///   *pattern* side can only be a case-stable ASCII word byte.** `\b` is
///   *"exactly one side is a word character"*. Pin the pattern side to
///   such a byte and both spellings agree that side is a word character,
///   so both reduce to *"the other side is not one"* — and "not an
///   **ASCII** word byte" is a superset of "not a **Unicode** word
///   character", because every ASCII word byte is a Unicode word
///   character and every byte of a non-ASCII character is ≥ 0x80 and so
///   not an ASCII word byte. This is [`prefix_index`]'s leading-boundary
///   lemma (GH #142, PR #164); what differs is where the premise comes
///   from — there `PrefixIndex::build` enforces it on the indexed
///   prefix, here it is read off the pattern text, because a prefilter
///   has no prefixes.
///
/// **So the deletion branch is superset-preserving for every pattern,
/// and the respelling branch only for a pattern whose premise this walk
/// can actually read.** That distinction is the whole safety argument
/// and it is not a formality: a review of this code found four
/// constructs where an earlier version read the premise wrongly and the
/// prefilter therefore **declined to name a rule that matches**, which
/// is a credential going out of `redact_str` in the clear. Each is now
/// refused, each has a shipped rule in `ADVERSARIAL_BOUNDARY_RULES`
/// carrying the divergent haystack as its own positive example, and
/// each has its own mutation row:
///
/// * a multi-character escape — [`escape_token_len`];
/// * extended mode — [`mentions_extended_flag`];
/// * a stacked quantifier, `\bz+*`, where `(z+)*` admits zero while a
///   one-character read sees only the `+`;
/// * `\b{start}`, which is a *named boundary assertion* and not a
///   quantified `\b`; leaving its brace run behind produced
///   `(?:){start}`, which does not compile, so
///   [`prefilter_or_verbatim`] reinstalled the sources for **every**
///   rule and one user rule silently returned the whole set to the
///   cliff — measured at 360x on one em dash.
///
/// **Beyond those, the premise is read conservatively and every failure
/// is a deletion.** A boundary keeps its meaning only when the pattern
/// character touching it is a bare case-stable ASCII word literal —
/// immediately to the right and not followed by `?`, `*`, `+` or `{`, or
/// immediately to the left. `\b(?:AKIA|ASIA)` and `\b[0-9]{8,10}` are
/// both provably fine by hand and both get the deletion anyway, because
/// a group or a class is past what this walk reads. **When the shipped
/// set was fifty-one rules, fifteen took a deletion at their leading
/// boundary** — eight
/// on a case-unstable head letter, four on a group open, three on a
/// class open. That costs prefilter selectivity, which costs time.
///
/// **What the conservatism is protecting, with the counterexample.**
/// `(?i)\b[a-z0-9_.-]{0,32}(?:password|…)\b` — the two generic
/// assignment rules — can begin its match on `.` or `-`, and `\b` holds
/// between `é` and `-` where `(?-u:\b)` reads `0xa9` and `-` as both
/// non-word and says it does not. Respelling **unconditionally** is
/// therefore unsound, and not theoretically:
/// `the_rewritten_prefilter_names_everything_the_rules_do` fails on it,
/// first counterexample `(?i)\bz{0,3}--zq_k13_[A-Za-z0-9]{4,}` against a
/// haystack opening `é-`.
///
/// **`\B` is deleted, never respelled.** It is the negation, so the
/// ASCII spelling *under*-approximates by the same reasoning, and there
/// is no premise that rescues it. No shipped rule has one; a user rule
/// with one keeps a strictly more permissive prefilter entry, which is
/// the safe direction.
///
/// The walk tracks escapes rather than calling `str::replace`, so a
/// pattern containing `\\b` — an escaped backslash then a literal `b` —
/// keeps its meaning. A `\b` inside a character class needs no handling:
/// `regex` rejects `[\b]` outright, so such a rule fails `Regex::new`
/// above and never reaches here.
///
/// [`redact::find_spans`]: super::redact::find_spans
/// [`prefix_index`]: super::prefix_index
fn prefilter_pattern(pattern: &str) -> String {
    let src: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut i = 0usize;
    // Extended mode moves every adjacency the respelling branch reads,
    // so a pattern that mentions the flag gets the deletion branch at
    // every boundary and no premise is needed.
    let precise = !mentions_extended_flag(&src);
    // Whether the character just emitted was a bare case-stable ASCII
    // word literal. A quantifier, a class close, a group close or any
    // escape at all clears it, which is what keeps `a*\b`, `[abc]\b`,
    // `(?:x|y)\b` and `\pL\b` out of the respelling branch.
    let mut left_is_word = false;
    while i < src.len() {
        let c = src[i];
        if c != '\\' {
            out.push(c);
            left_is_word = is_case_stable_ascii_word(c);
            i += 1;
            continue;
        }
        match src.get(i + 1) {
            Some(&kind @ ('b' | 'B')) => {
                // `\b{start}` is an assertion and `\b{2}` is a quantified
                // one; either way the whole token is a zero-width
                // assertion, so the whole token goes. Leaving the brace
                // run behind made `\b{start}` come out as `(?:){start}`,
                // which does not compile — and the all-or-nothing
                // fallback then reinstalled the verbatim patterns for
                // **every** rule. Measured: the shipped fifty-one plus
                // one `\b{start}` user rule went back to 360x on one em
                // dash.
                //
                // **A braced boundary also always takes the deletion
                // branch** (`eaten == 0` below). `\b{end}` and friends
                // are *different assertions* from `\b`; respelling one
                // as `(?-u:\b)` turns out to be sound under the same
                // premise, but only by a case analysis over four named
                // boundaries no shipped rule uses. Deletion needs no
                // premise and costs nothing here.
                let eaten = brace_len(&src, i + 2).unwrap_or(0);
                // `\B` is the negation, so the ASCII spelling
                // *under*-approximates and no premise rescues it. A
                // brace run makes `src[i + 2]` a `{`, so this is already
                // false for one — `left_ok` is where the guard bites.
                let right_is_word = precise
                    && kind == 'b'
                    && matches!(src.get(i + 2), Some(&n) if is_case_stable_ascii_word(n))
                    // Any quantifier chain starts with one of these, and
                    // a chain is what `\bz+*` is: `(z+)*` admits zero
                    // while a one-character read sees only the `+`. `+`
                    // alone would be safe and is refused with the rest,
                    // because telling them apart is the parse this walk
                    // does not do.
                    && !matches!(src.get(i + 3), Some('?' | '*' | '+' | '{'));
                let left_ok = precise && eaten == 0 && kind == 'b' && left_is_word;
                out.push_str(if right_is_word || left_ok {
                    "(?-u:\\b)"
                } else {
                    "(?:)"
                });
                left_is_word = false;
                i += 2 + eaten;
            }
            Some(_) => {
                let len = escape_token_len(&src, i);
                out.extend(&src[i..i + len]);
                left_is_word = false;
                i += len;
            }
            None => {
                out.push('\\');
                i += 1;
            }
        }
    }
    out
}

/// The number of `char`s the escape token starting at `src[i]` occupies,
/// where `src[i]` is a backslash.
///
/// **This exists because reading two characters is not reading an
/// escape, and the difference was a leak.** `\pL` and `\x73` are three
/// and four characters; consuming two left `L` and `3` to be walked as
/// plain literals, which set the left-neighbour flag from a character
/// the pattern does not have there. The braced spellings `\p{L}` and
/// `\x{2d}` were safe only because `}` happens to clear the same flag.
/// Measured through `redact_str` before the fix: a rule
/// `(?i)\x73\b-acmehx-[A-Za-z0-9]{8,}` matches `ſ-acmehx-ABCDEFGH` while
/// the prefilter declines to name it, and the credential goes out in the
/// clear. That spelling also walks straight past the `k`/`K`/`s`/`S`
/// exclusion, because `\x73` *is* `s` and the walk never sees one.
///
/// Unbraced hex forms are consumed by digit count rather than greedily,
/// so `\x7Fed` keeps its `ed`.
fn escape_token_len(src: &[char], i: usize) -> usize {
    let Some(&kind) = src.get(i + 1) else {
        return 1; // a trailing lone backslash
    };
    let digits = match kind {
        'x' => 2,
        'u' => 4,
        'U' => 8,
        // A one-letter Unicode class name when unbraced: `\pL`.
        'p' | 'P' => 1,
        _ => return 2,
    };
    if src.get(i + 2) == Some(&'{') {
        return brace_len(src, i + 2).map_or(src.len() - i, |n| 2 + n);
    }
    let mut taken = 0usize;
    while taken < digits {
        match src.get(i + 2 + taken) {
            Some(c) if matches!(kind, 'p' | 'P') || c.is_ascii_hexdigit() => taken += 1,
            _ => break,
        }
    }
    2 + taken
}

/// The length of the `{…}` run starting at `src[at]`, or `None` when it
/// is unclosed. Regex braces do not nest.
fn brace_len(src: &[char], at: usize) -> Option<usize> {
    if src.get(at) != Some(&'{') {
        return None;
    }
    src[at + 1..].iter().position(|c| *c == '}').map(|o| o + 2)
}

/// Whether `pattern` mentions the `x` flag in any inline flag group.
///
/// **Extended mode is the one construct that cannot be handled at the
/// boundary, so it is handled at the pattern.** Under `(?x)` whitespace
/// is insignificant, which means the character beside a `\b` in the
/// *source* is not the character beside it in the *pattern* — in either
/// direction — and both of [`prefilter_pattern`]'s adjacency reads are
/// about source characters. Measured through `redact_str` before this
/// guard: `(?x)\ba {0,3}-acmetok-[A-Za-z0-9]{8,}` matches
/// `é-acmetok-ABCDEFGH`, the zero-admitting-quantifier guard reads a
/// space where the quantifier is and concludes `a` is mandatory, the
/// prefilter declines to name the rule, and the credential goes out in
/// the clear. The scoped `(?x:…)` spelling fails identically.
///
/// Turning the flag *off* counts too. `(?-x)` only has a job in a
/// pattern where something turned it on, and a walk that tracked which
/// spans were extended would be the parser this deliberately is not.
/// No shipped rule mentions the flag, so the whole guard costs nothing
/// today.
fn mentions_extended_flag(src: &[char]) -> bool {
    let mut i = 0usize;
    while i < src.len() {
        if src[i] == '\\' {
            i += escape_token_len(src, i);
            continue;
        }
        if src[i] == '(' && src.get(i + 1) == Some(&'?') {
            let mut j = i + 2;
            while let Some(&c) = src.get(j) {
                match c {
                    'x' => return true,
                    'i' | 'm' | 's' | 'u' | 'U' | 'R' | '-' => j += 1,
                    _ => break,
                }
            }
        }
        i += 1;
    }
    false
}

/// The lazy-DFA cache ceiling the prefilter is built with, against the
/// `regex` crate's 2 MiB default (GH #194's second cliff).
///
/// **It is a ceiling, not an allocation, and the distinction is the
/// whole reason the number can be this large.** `regex` grows the cache
/// as a search discovers states and gives up on the DFA — falling back
/// to the one-state-at-a-time engine — when the cache would pass the
/// limit. The fifty-one-rule set this was measured on saturates well
/// below any of the candidates. Sweeping over six corpora (1 MiB each of this
/// repository's own source, its `grep -rn` output and its
/// `CHANGELOG`+`README`+`ROADMAP`, REQ-O-007's 41,472 B default read
/// window, 380 KB of `git log`, and 5.4 MB of concatenated `.rs`), one
/// process per limit so a freed cache cannot be counted as the next
/// one's, prefilter scan only, **rule sources rather than rewrites** so
/// this isolates the ceiling:
///
/// ```text
/// dfa_size_limit   total over the six corpora   resident cache
/// 2 MiB (default)              577.9 ms                1.8 MiB
/// 8 MiB                        187.1 ms                7.6 MiB
/// 16 MiB                        31.1 ms               10.4 MiB
/// 32 MiB                        26.0 ms               10.4 MiB
/// 64 MiB                        25.3 ms               10.4 MiB
/// ```
///
/// It stops growing at 16 MiB and 32 and 64 MiB measure the same, so
/// the headroom is not memory spent. What it buys is the cliff staying
/// gone when §9.2's quarterly gitleaks refresh makes the set bigger.
///
/// **The shipped combination is cheaper than that table, because
/// [`prefilter_pattern`] deletes the quit set and a smaller automaton
/// needs a smaller cache**: rewrites at 64 MiB measure **5.2 MiB**
/// against the 10.4 MiB above.
///
/// The cost is paid **per thread that concurrently runs a redaction
/// scan**, because `regex` keeps a cache pool rather than one cache.
/// Measured on the worst corpus, `main` against what ships here: 2.6
/// MiB/thread against **3.3 MiB/thread**, so twelve concurrent readers
/// move 29 MiB to 38 MiB.
///
/// **There is one `RuleSet` per daemon in the default configuration and
/// two when `security.disabled_redaction_rules` is non-empty**, never
/// one per session. `builtin_shared` is a process-wide `OnceLock` and
/// `Config::redaction_rules_shared` hands that same `Arc` to the single
/// `OutputProcessor` in `HoldfastServer` — but `mcp/mod.rs:529` takes
/// `builtin_shared()` for the audit log *unconditionally*, so an
/// operator who switches a rule off has the reduced set and the full one
/// resident at once, and a cache pool belongs to a `RegexSet` rather
/// than to a process.
/// The prefilter, from the rewritten patterns where they compile and
/// from the rule sources where they do not.
///
/// **The fallback keeps an unforeseen user rule costing speed rather
/// than the daemon.** The deletion branch of [`prefilter_pattern`] is
/// superset-preserving unconditionally and the respelling branch is
/// taken only where the walk can read its premise, so a set built from
/// the rewrites names everything the rules can match. What it is *not*
/// is proved to **compile** for a pattern nobody has seen. If it does
/// not, the sources go in — GH #194's cliff and all — because a
/// `RuleSet` that refuses to load is a daemon that refuses to start,
/// and the rewrite is a performance fix.
///
/// **It is all-or-nothing, and that is the point.** A `RegexSet` reports
/// indices into `rules`, so a per-rule fallback would have to keep the
/// two lists aligned; swapping the whole list cannot get that wrong.
///
/// **It is also silent, which is a known gap and a deliberate one.**
/// The natural report is [`crate::diag!`], as `Config::redaction_rules_shared`
/// uses for the same class of degradation — but `diag::emit` redacts
/// through `builtin_shared()`, and `builtin_shared` is a `OnceLock`
/// whose initialiser is `RuleSet::builtin()`, so a `diag!` from inside
/// `compile` re-enters the lock it is being called under. Reporting it
/// belongs at the three callers, and is left to a follow-up rather than
/// done badly here. It is separated into this function so the fallback
/// itself is testable without one:
/// `the_prefilter_falls_back_to_the_rule_sources_when_a_rewrite_will_not_compile`
/// drives it directly, because after the `\b{…}` repair no pattern is
/// known to reach it — 44,181 compiling four-atom patterns produced
/// zero rewrite failures.
fn prefilter_or_verbatim(
    rewritten: &[String],
    verbatim: &[String],
) -> Result<RegexSet, regex::Error> {
    match build_prefilter(rewritten) {
        Ok(set) => Ok(set),
        Err(_) => build_prefilter(verbatim),
    }
}

fn build_prefilter(patterns: &[String]) -> Result<RegexSet, regex::Error> {
    RegexSetBuilder::new(patterns)
        .dfa_size_limit(PREFILTER_DFA_SIZE_LIMIT)
        .build()
}

/// 64 MiB — see [`build_prefilter`] for the sweep this came off.
const PREFILTER_DFA_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// The line a host prints at startup when the operator has switched
/// rules off, or `None` when the set is the shipped one (GH #128).
///
/// **Reject-or-report is GH #128's own guidance, and this is the report
/// half.** The list is rejected when it is wrong (an unknown name) and
/// reported when it is right, because a redaction rule being off is
/// security-relevant and must not be discoverable only by reading the
/// config back — which is the state that let `redaction_enabled = false`
/// sit in a file for a release doing nothing.
///
/// Derived from the set, like [`RuleSet::disabled_builtin_rules`]: the
/// line says what the read path will really do.
pub fn disabled_rules_notice(set: &RuleSet) -> Option<String> {
    let off = set.disabled_builtin_rules();
    if off.is_empty() {
        return None;
    }
    Some(format!(
        "holdfast: {} of {} built-in redaction rules are switched off by \
         security.disabled_redaction_rules and will redact nothing: {} \
         ({} rules in force)",
        off.len(),
        builtin_rule_names().len(),
        off.join(", "),
        set.len(),
    ))
}

/// Every built-in rule's `name`, sorted — the set an operator's
/// `[security] disabled_redaction_rules` is checked against (GH #128).
///
/// **Parsed from [`DEFAULT_RULES_TOML`], never a list written out here.**
/// A hand-kept copy would accept a name the shipped rule file no longer
/// has, or refuse one it gained, and the failure in the first direction
/// is a config that reads as a redaction decision and takes none. It
/// does not compile the regexes, so validating a config costs a TOML
/// parse rather than fifty-odd `Regex::new` calls.
pub fn builtin_rule_names() -> &'static std::collections::BTreeSet<String> {
    static NAMES: OnceLock<std::collections::BTreeSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        // Same reasoning as `builtin_shared`: a vendored rule file that
        // does not parse is a broken binary, and
        // `the_builtin_set_compiles_and_is_substantial` proves it parses.
        let file: RuleFile = toml::from_str(DEFAULT_RULES_TOML)
            .expect("the vendored redaction rule file must be valid TOML");
        file.rules.into_iter().map(|r| r.name).collect()
    })
}

/// The process-wide built-in rule set.
///
/// Fifty-odd regexes take real time to compile, and every session shares
/// the same table, so compiling one per session would be absurd. Callers that
/// only need the default set take it from here; callers that need a
/// user-extended set (0.0.5's config loader) build their own `RuleSet` and
/// hand it round as an `Arc`.
///
/// **This is the entry point `Session` uses in 0.0.4** to give its
/// `ScreenTracker` a rule table (§9.2 redaction of screen state). It is
/// declared here rather than there because the rule set belongs to
/// `output`, and because an optional rule table is a rule table someone
/// will forget to supply.
pub fn builtin_shared() -> Arc<RuleSet> {
    static SHARED: OnceLock<Arc<RuleSet>> = OnceLock::new();
    Arc::clone(SHARED.get_or_init(|| {
        // Same reasoning as `HoldfastServer::with_audit_path` (Task 9): a
        // failure here means the compiled-in rule file is malformed, which
        // `the_builtin_set_compiles_and_is_substantial` proves it is not.
        // Starting up without redaction is the one outcome we must not
        // have, so this panics rather than degrading.
        Arc::new(RuleSet::builtin().expect("built-in redaction rules must compile"))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// User rules shaped to break the GH #194 prefilter rewrite rather
    /// than to exercise it: a `\B` (the shipped set has none at all), an
    /// escaped backslash immediately before a `b` (which a
    /// `str::replace` rewrite corrupts), a `(?i)` head on the two
    /// letters that case-fold outside ASCII, a punctuation-opening
    /// prefix under a `\b`, and a boundary whose only neighbour may
    /// match zero times.
    ///
    /// No shipped rule reaches any of these, which is the whole
    /// reason they are written out.
    const ADVERSARIAL_BOUNDARY_RULES: &str = r#"
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
        name = "acme-folded-head"
        kind = "acme-internal"
        pattern = '''(?i)\bskey_[a-z0-9]{20,}'''
        positive = ["SKEY_abcdefghij0123456789"]
        negative = ["skey_short"]

        [[rule]]
        name = "acme-non-word-prefix"
        kind = "acme-internal"
        pattern = '''\b(?:-zq-|-zr-)[A-Za-z0-9]{10,}'''
        prefixes = ["-zq-", "-zr-"]
        positive = ["-zq-ABCDEFGHIJ"]
        negative = ["-zq-ABC"]

        [[rule]]
        name = "acme-zero-quantifier"
        kind = "acme-internal"
        pattern = '''\bz{0,3}-acmezq-[A-Za-z0-9]{8,}'''
        positive = ["-acmezq-ABCDEFGH"]
        negative = ["-acmezq-ABC"]

        [[rule]]
        name = "acme-trailing-boundary"
        kind = "acme-internal"
        pattern = '''ACMETB-[A-Z0-9]{6}key\b'''
        positive = ["ACMETB-ABC123key"]
        negative = ["ACMETB-ABC123keyx"]

        [[rule]]
        name = "acme-multibyte-class-escape"
        kind = "acme-internal"
        pattern = '''(?i)\pL\b-acmepl-[A-Za-z0-9]{8,}'''
        positive = ["é-acmepl-ABCDEFGH"]
        negative = ["X-acmepl-ABC"]

        [[rule]]
        name = "acme-hex-escape-head"
        kind = "acme-internal"
        pattern = '''(?i)\x73\b-acmehx-[A-Za-z0-9]{8,}'''
        positive = ["ſ-acmehx-ABCDEFGH"]
        negative = ["s-acmehx-ABC"]

        [[rule]]
        name = "acme-braced-class-escape"
        kind = "acme-internal"
        pattern = '''\p{L}\b-acmepb-[A-Za-z0-9]{8,}'''
        positive = ["é-acmepb-ABCDEFGH"]
        negative = ["X-acmepb-ABC"]

        [[rule]]
        name = "acme-extended-mode"
        kind = "acme-internal"
        pattern = '''(?x)\ba {0,3}-acmetok-[A-Za-z0-9]{8,}'''
        positive = ["é-acmetok-ABCDEFGH"]
        negative = ["a-acmetok-ABC"]

        [[rule]]
        name = "acme-extended-mode-scoped"
        kind = "acme-internal"
        pattern = '''(?x:\ba {0,3}-acmexs-[A-Za-z0-9]{8,})'''
        positive = ["é-acmexs-ABCDEFGH"]
        negative = ["a-acmexs-ABC"]

        [[rule]]
        name = "acme-stacked-quantifier"
        kind = "acme-internal"
        pattern = '''\bz+*-acmest-[A-Za-z0-9]{8,}'''
        positive = ["é-acmest-ABCDEFGH"]
        negative = ["z-acmest-ABC"]

        [[rule]]
        name = "acme-named-boundary"
        kind = "acme-internal"
        pattern = '''\b{start}acmebs-[A-Za-z0-9]{8,}'''
        positive = ["acmebs-ABCDEFGH"]
        negative = ["xacmebs-ABCDEFGH"]
    "#;

    /// The fallback at [`prefilter_or_verbatim`], driven directly.
    ///
    /// **Deleting the fallback outright used to leave every test
    /// green.** It cannot be reached through `compile` any more: after
    /// the `\b{…}` repair, 44,181 compiling four-atom patterns over an
    /// alphabet of boundaries, groups, quantifiers and classes produced
    /// **zero** rewrites that fail to compile. That is a good property
    /// and a bad test, so the fallback is exercised at its own seam
    /// with a rewritten list that cannot build.
    #[test]
    fn the_prefilter_falls_back_to_the_rule_sources_when_a_rewrite_will_not_compile() {
        let verbatim = vec![r"\bghp_[0-9A-Za-z]{36,}".to_string(), "second".to_string()];
        let good: Vec<String> = verbatim.iter().map(|p| prefilter_pattern(p)).collect();

        let set = prefilter_or_verbatim(&good, &verbatim).expect("the rewrites compile");
        let hits: Vec<usize> = set
            .matches(b"ghp_0123456789abcdefghijABCDEFGHIJ012345")
            .into_iter()
            .collect();
        assert_eq!(hits, vec![0]);

        // A rewritten list that cannot build: the set is the sources, so
        // the indices still line up with `rules` and every rule is still
        // named. The cliff comes back with them, which is the trade.
        let broken = vec!["(".to_string(), "second".to_string()];
        let set = prefilter_or_verbatim(&broken, &verbatim)
            .expect("an unbuildable rewrite falls back rather than failing the load");
        let hits: Vec<usize> = set
            .matches(b"ghp_0123456789abcdefghijABCDEFGHIJ012345")
            .into_iter()
            .collect();
        assert_eq!(
            hits,
            vec![0],
            "the fallback must keep index 0 meaning rule 0; a shortened or reordered \
             list would make every redaction after it name the wrong kind"
        );
        assert_eq!(
            set.matches(b"second").into_iter().collect::<Vec<_>>(),
            vec![1]
        );

        // Both unbuildable is the caller's error, unchanged.
        assert!(prefilter_or_verbatim(&broken, &broken).is_err());
    }

    /// The four characters [`is_case_stable_ascii_word`] refuses,
    /// recomputed over the whole of Unicode rather than believed.
    ///
    /// **This is the premise of the respelling lemma and nothing else
    /// checks it.** `(?i)\bsk-` looks like a pattern whose first
    /// character must be an ASCII word byte and is not: `s` folds to
    /// U+017F, so `-ſk-…` matches the rule while `(?-u:\b)` sees `-`
    /// and `0xc5` as both non-word and reports no match. One byte of
    /// Unicode data out of date here is a silent under-report, so the
    /// set is derived.
    ///
    /// It sweeps every non-ASCII scalar once against one class regex —
    /// 1.1 M cheap tests — and only then asks the sixty-three
    /// single-character regexes about the handful that survive.
    #[test]
    fn the_case_unstable_ascii_letters_are_derived_and_not_asserted() {
        use regex::Regex;
        let word: Vec<char> = (0u8..=127)
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .map(|b| b as char)
            .collect();
        let class: String = word.iter().map(|c| regex::escape(&c.to_string())).collect();
        let any = Regex::new(&format!("(?i)^[{class}]$")).unwrap();
        let mut buf = [0u8; 4];
        let reaching: Vec<char> = (0x80u32..0x11_0000)
            .filter_map(char::from_u32)
            .filter(|u| any.is_match(u.encode_utf8(&mut buf)))
            .collect();

        let mut unstable: Vec<char> = Vec::new();
        for c in &word {
            let one = Regex::new(&format!("(?i)^{}$", regex::escape(&c.to_string()))).unwrap();
            if reaching
                .iter()
                .any(|u| one.is_match(u.encode_utf8(&mut buf)))
            {
                unstable.push(*c);
            }
        }
        unstable.sort_unstable();
        assert_eq!(
            unstable,
            vec!['K', 'S', 'k', 's'],
            "the ASCII letters whose `(?i)` expansion leaves ASCII have changed; \
             `is_case_stable_ascii_word` is the premise of the `(?-u:\\b)` lemma \
             and must exclude exactly these"
        );
        for c in &unstable {
            assert!(
                !is_case_stable_ascii_word(*c),
                "`{c}` case-folds outside ASCII and must not carry a boundary"
            );
        }
        assert!(is_case_stable_ascii_word('a') && is_case_stable_ascii_word('0'));
        assert!(is_case_stable_ascii_word('_') && !is_case_stable_ascii_word('-'));
    }

    /// Each branch of [`prefilter_pattern`], named by the reason it is
    /// that branch rather than by its output.
    #[test]
    fn the_prefilter_rewrite_respells_what_it_can_prove_and_deletes_the_rest() {
        // Right neighbour is a bare case-stable ASCII word literal.
        assert_eq!(
            prefilter_pattern(r"\bghp_[0-9A-Za-z]{36,}"),
            r"(?-u:\b)ghp_[0-9A-Za-z]{36,}"
        );
        // Left neighbour is, when the right one is not.
        assert_eq!(
            prefilter_pattern(r"(?i)[_-]key\b[:=]"),
            r"(?i)[_-]key(?-u:\b)[:=]"
        );
        // Neither: a group close on the left, a class open on the right.
        assert_eq!(
            prefilter_pattern(r"(?:token|key)\b[:=]"),
            r"(?:token|key)(?:)[:=]"
        );
        // The shape the two generic assignment rules have, and the one
        // an unconditional respelling gets wrong.
        assert_eq!(
            prefilter_pattern(r"(?i)\b[a-z0-9_.-]{0,32}(?:password)\b"),
            r"(?i)(?:)[a-z0-9_.-]{0,32}(?:password)(?:)"
        );
        // `s` folds to U+017F, so it cannot carry the boundary.
        assert_eq!(prefilter_pattern(r"\bsk-ant-"), r"(?:)sk-ant-");
        // A word literal that may match zero times cannot either.
        assert_eq!(prefilter_pattern(r"\bz{0,3}-x"), r"(?:)z{0,3}-x");
        assert_eq!(prefilter_pattern(r"\bz?-x"), r"(?:)z?-x");
        assert_eq!(prefilter_pattern(r"\bz*-x"), r"(?:)z*-x");
        // `+` is min-1, so the literal really *is* the adjacent byte —
        // and it is refused anyway, because `\bz+*` is legal and `(z+)*`
        // admits zero. Telling those apart is a parse this walk does not
        // do, so the whole quantifier alphabet is refused.
        assert_eq!(prefilter_pattern(r"\bz+-x"), r"(?:)z+-x");
        assert_eq!(prefilter_pattern(r"\bz+*-x"), r"(?:)z+*-x");
        // A multi-character escape is one token, so its trailing source
        // character is not a left neighbour. `\pL` and `\x73` both end
        // on an ASCII word character and both used to respell the
        // boundary after them; `\x73` *is* `s`, so it also walked past
        // the case-fold exclusion.
        assert_eq!(prefilter_pattern(r"\pL\b-x"), r"\pL(?:)-x");
        assert_eq!(prefilter_pattern(r"\x73\b-x"), r"\x73(?:)-x");
        assert_eq!(prefilter_pattern(r"\p{L}\b-x"), r"\p{L}(?:)-x");
        assert_eq!(prefilter_pattern(r"\u00e9\b-x"), r"\u00e9(?:)-x");
        assert_eq!(prefilter_pattern(r"\U000000e9\b-x"), r"\U000000e9(?:)-x");
        // …and the hex forms are consumed by digit count rather than
        // greedily, so `\x7Fed` keeps its `ed` — and `d` really is the
        // boundary's left neighbour, so that one respells.
        assert_eq!(prefilter_pattern(r"\x7Fed\b-x"), r"\x7Fed(?-u:\b)-x");
        assert_eq!(prefilter_pattern(r"\x7F\b-x"), r"\x7F(?:)-x");
        // Extended mode moves every adjacency, so the whole pattern
        // drops to deletion even where the premise looks satisfied.
        assert_eq!(prefilter_pattern(r"(?x)\bfoo"), r"(?x)(?:)foo");
        assert_eq!(prefilter_pattern(r"(?x:\bfoo)"), r"(?x:(?:)foo)");
        assert_eq!(prefilter_pattern(r"(?-x)\bfoo"), r"(?-x)(?:)foo");
        assert_eq!(prefilter_pattern(r"(?i)\bfoo"), r"(?i)(?-u:\b)foo");
        // `\b{start}` is a named assertion, not a quantified `\b`. The
        // whole token goes: leaving `{start}` behind produced
        // `(?:){start}`, which does not compile, and the all-or-nothing
        // fallback then reinstated the cliff for every rule in the set.
        assert_eq!(prefilter_pattern(r"\b{start}foo"), r"(?:)foo");
        assert_eq!(prefilter_pattern(r"foo\b{end}"), r"foo(?:)");
        assert_eq!(prefilter_pattern(r"x\b{2}y"), r"x(?:)y");
        // `\B` has no lemma at all.
        assert_eq!(prefilter_pattern(r"a\B[0-9]"), r"a(?:)[0-9]");
        // An escaped backslash before a `b` is not a word boundary.
        assert_eq!(
            prefilter_pattern(r"\bACMEESC-\\bkey[0-9]{8}"),
            r"(?-u:\b)ACMEESC-\\bkey[0-9]{8}"
        );
        // `(?:)` and not "" — `x\b?` parses, and `x?` is a different rule.
        assert_eq!(prefilter_pattern(r"x\b?"), r"x(?-u:\b)?");
        assert_eq!(prefilter_pattern(r"-\b?"), r"-(?:)?");
        // A pattern with no boundary is returned unchanged.
        let plain = r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+";
        assert_eq!(prefilter_pattern(plain), plain);
        // A trailing lone backslash cannot panic the walk.
        assert_eq!(prefilter_pattern("abc\\"), "abc\\");
    }

    /// **The superset property, over the shipped rules and over rule
    /// sets nobody wrote.**
    ///
    /// `find_spans` runs only the rules the prefilter names, so the one
    /// thing the rewrite must never do is fail to name a rule that can
    /// match: that is a credential on the wire. Over-naming costs a
    /// wasted `Regex` pass and is deliberately not checked — the
    /// asymmetry is the design.
    ///
    /// **Random rule sets are not decoration, and the reason first
    /// written here was wrong.** It said only the generic assignment
    /// pair reaches the deletion branch at a *leading* boundary. A
    /// mechanical census of all 51 says **fifteen** do — eight on a
    /// case-unstable head letter (`\bsk-ant-`, `\bSG\.`, `\bkey-`, …),
    /// four on a group open, three on a class open — so the built-in
    /// corpus carries far more of this test than that sentence credited.
    /// What the generator is still for is the *premise-reading* failures:
    /// no shipped pattern contains `\x`, `\p`, `\b{` or an `x` flag, and
    /// no shipped boundary is deleted by the zero-admitting-quantifier
    /// guard at all, so those arms are reachable only from
    /// `ADVERSARIAL_BOUNDARY_RULES` and from generated rules.
    ///
    /// The generator is PR #196's with the shapes GH #194 needs added: a
    /// leading class admitting punctuation, a zero-admitting quantifier
    /// between the boundary and the first literal, and `(?i)` over a
    /// `k`/`s` head. The haystack generator substitutes U+212A and
    /// U+017F into seeds for the same reason.
    ///
    /// **No divergence count is quoted here on purpose.** The one that
    /// used to be — "2,623 over 4,051 patterns" — came from a wider
    /// exploratory sweep than this test runs, so nobody could reproduce
    /// it by running the thing it was written on. What is reproducible
    /// is that every mutation in the table below turns this row red, and
    /// the counterexample it names first.
    #[test]
    fn the_rewritten_prefilter_names_everything_the_rules_do() {
        use regex::bytes::Regex;

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

        fn random_pattern(rng: &mut Rng, i: usize) -> String {
            const HEAD: &[&str] = &["acme", "zq", "tok", "kx", "b7", "sk", "key"];
            const BODY: &[&str] = &["-", "_", " ", "", "."];
            const CLASS: &[&str] = &["[A-Za-z0-9]", "[A-Za-z0-9_-]", "[a-f0-9]", "[a-z0-9_.-]"];
            let head = HEAD[rng.below(HEAD.len())];
            let body = BODY[rng.below(BODY.len())];
            let lead = if rng.below(3) == 0 { "-" } else { "" };
            let prefix = format!("{lead}{head}{body}k{i}{body}");
            let class = CLASS[rng.below(CLASS.len())];
            let fold = if rng.below(2) == 0 { "(?i)" } else { "" };
            match rng.below(8) {
                0 => format!("{fold}\\b{prefix}(?P<value>{class}{{6,}})"),
                1 => format!("{fold}\\b{prefix}{class}{{8,}}\\B[0-9]{{2}}"),
                2 => format!("{fold}\\b{prefix}{class}{{10,}}"),
                3 => format!("{fold}\\b{class}{{0,8}}{prefix}{class}{{4,}}\\b"),
                4 => format!("{fold}{prefix}{class}{{4,}}\\b-"),
                5 => format!("{fold}\\b(?:{head}|zz){body}{class}{{4,}}"),
                6 => format!("{fold}\\bz{{0,3}}-{prefix}{class}{{4,}}"),
                _ => format!("{fold}{prefix}{class}{{4,}}"),
            }
        }

        /// The literal runs of a pattern, so a haystack can be built
        /// that actually reaches it.
        fn seeds_of(p: &str) -> Vec<String> {
            let mut v = Vec::new();
            let mut cur = String::new();
            let mut it = p.chars();
            while let Some(c) = it.next() {
                let boundary = match c {
                    '\\' => {
                        it.next();
                        true
                    }
                    '[' | '(' | ')' | ']' | '{' | '}' | '|' | '?' | '*' | '+' | '^' | '$' | '.' => {
                        true
                    }
                    _ => {
                        cur.push(c);
                        false
                    }
                };
                if boundary {
                    if cur.len() > 1 {
                        v.push(std::mem::take(&mut cur));
                    }
                    cur.clear();
                }
            }
            if cur.len() > 1 {
                v.push(cur);
            }
            v
        }

        fn random_haystack(rng: &mut Rng, seeds: &[String]) -> Vec<u8> {
            const DELIMS: &[u8] = b" \t\r\n:=\"',;()[]{}-_.\x00\x1b\x7f\x80\xc3\xa9\xff";
            const VALUES: &[u8] = b"abcdefABCDEF0123456789-_.";
            const GLYPHS: &[&str] = &[
                "\u{e9}",
                "\u{2014}",
                "\u{1F600}",
                "\u{17F}",
                "\u{212A}",
                "\u{200B}",
            ];
            let mut out = Vec::new();
            for _ in 0..1 + rng.below(10) {
                match rng.below(8) {
                    0 | 1 if !seeds.is_empty() => {
                        let s = &seeds[rng.below(seeds.len())];
                        for b in s.bytes() {
                            match b {
                                b's' | b'S' if rng.below(3) == 0 => {
                                    out.extend_from_slice("\u{17F}".as_bytes())
                                }
                                b'k' | b'K' if rng.below(3) == 0 => {
                                    out.extend_from_slice("\u{212A}".as_bytes())
                                }
                                _ => out.push(if rng.below(4) == 0 {
                                    b.to_ascii_uppercase()
                                } else {
                                    b
                                }),
                            }
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
                    5 => out.extend_from_slice(GLYPHS[rng.below(GLYPHS.len())].as_bytes()),
                    6 => out.extend_from_slice(b"-sk-"),
                    _ => out.extend_from_slice(b"password=hunter2hunter2"),
                }
            }
            out
        }

        // **`builtin_with_extra`, not `builtin`.** The adversarial
        // constant's whole purpose is shapes the shipped rules do
        // not have, and until this line it only ever reached a test
        // asking whether the rewrite *builds*. Each of those rules now
        // carries a positive example that **is** its divergent haystack
        // — `é-acmepl-ABCDEFGH` rather than `X-acmepl-…` — because a
        // positive in ASCII proves nothing here: the counterexamples all
        // need a non-ASCII character in the position the pattern reads.
        let set = RuleSet::builtin_with_extra(ADVERSARIAL_BOUNDARY_RULES).unwrap();

        // Arm 1: every rule against its own positive examples,
        // and against each of them with seven non-ASCII probes planted
        // at the first byte, the midpoint and the last byte — GH #194's
        // own axis, one position at a time.
        let probes: [&[u8]; 7] = [
            "\u{e9}".as_bytes(),
            "\u{2014}".as_bytes(),
            "\u{1F600}".as_bytes(),
            &[0x80],
            &[0xff],
            "\u{17F}".as_bytes(),
            "\u{212A}".as_bytes(),
        ];
        let mut planted: Vec<Vec<u8>> = Vec::new();
        for rule in &set.rules {
            for example in &rule.positive {
                let b = example.as_bytes();
                planted.push(b.to_vec());
                for probe in probes {
                    for at in [0usize, b.len() / 2, b.len()] {
                        let mut v = b[..at].to_vec();
                        v.extend_from_slice(probe);
                        v.extend_from_slice(&b[at..]);
                        planted.push(v);
                    }
                }
            }
        }

        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut patterns: Vec<String> = set.rules.iter().map(|r| r.pattern.clone()).collect();
        let shipped = patterns.len();
        for i in 0..1_200 {
            patterns.push(random_pattern(&mut rng, i));
        }

        let mut checks = 0usize;
        let mut compiled = 0usize;
        for (idx, pattern) in patterns.iter().enumerate() {
            let Ok(original) = Regex::new(pattern) else {
                continue;
            };
            let rewritten = Regex::new(&prefilter_pattern(pattern))
                .unwrap_or_else(|e| panic!("the rewrite of {pattern:?} does not compile: {e}"));
            compiled += 1;
            let seeds = seeds_of(pattern);
            let extra: &[Vec<u8>] = if idx < shipped { &planted } else { &[] };
            for k in 0..extra.len() + 200 {
                let haystack = if k < extra.len() {
                    extra[k].clone()
                } else {
                    random_haystack(&mut rng, &seeds)
                };
                checks += 1;
                if original.is_match(&haystack) {
                    assert!(
                        rewritten.is_match(&haystack),
                        "the prefilter would not name a rule that matches: pattern \
                         {pattern:?} rewritten {:?} haystack {:?}",
                        prefilter_pattern(pattern),
                        String::from_utf8_lossy(&haystack),
                    );
                }
            }
        }
        // **The same property asked of the `RegexSet` the loader
        // actually installs, not of the rewrite in isolation.** The loop
        // above proves `prefilter_pattern` is superset-preserving;
        // nothing in it would notice `compile` pushing something else.
        // This arm drives `set.prefilter` — indices and all — over the
        // planted corpus, so a lossy call site is caught here rather
        // than only in `redaction_sweep`.
        let mut wired = 0usize;
        for haystack in &planted {
            let named: Vec<usize> = set.prefilter.matches(haystack).into_iter().collect();
            for (i, rule) in set.rules.iter().enumerate() {
                if rule.regex.is_match(haystack) {
                    wired += 1;
                    assert!(
                        named.contains(&i),
                        "the installed prefilter does not name `{}`, which matches {:?}",
                        rule.name,
                        String::from_utf8_lossy(haystack),
                    );
                }
            }
        }
        assert!(
            wired > 100,
            "only {wired} rule/haystack pairs matched; the planted corpus no longer \
             reaches the shipped rules"
        );

        assert!(
            compiled > 1_000,
            "only {compiled} patterns compiled; the generator has stopped generating"
        );
        assert!(
            checks > 250_000,
            "only {checks} haystacks checked; the corpus has shrunk"
        );
    }

    /// The set the rewrite actually installs carries no Unicode word
    /// boundary — asked of `regex-automata` rather than of the rewritten
    /// text, so it is not the walk checking itself.
    ///
    /// `unicode_word_boundary(false)` is the configuration
    /// `build_liveness` uses for the same reason: a Unicode `\b` **fails
    /// to build** under it instead of silently installing the quit set
    /// GH #194 is about. A `RegexSet` has no such switch, so this builds
    /// the same patterns one at a time to get the refusal.
    #[test]
    fn no_pattern_the_prefilter_is_built_from_carries_a_unicode_word_boundary() {
        use regex_automata::{
            dfa::{dense, StartKind},
            util::syntax,
        };
        let set = RuleSet::builtin_with_extra(ADVERSARIAL_BOUNDARY_RULES).unwrap();
        let builds = |p: &str| -> bool {
            dense::Builder::new()
                .configure(
                    dense::DFA::config()
                        .start_kind(StartKind::Anchored)
                        .unicode_word_boundary(false),
                )
                .syntax(syntax::Config::new().utf8(false))
                .build(p)
                .is_ok()
        };
        let mut refused_before = 0usize;
        for rule in &set.rules {
            if !builds(&rule.pattern) {
                refused_before += 1;
            }
            assert!(
                builds(&prefilter_pattern(&rule.pattern)),
                "`{}` still carries a boundary the byte DFA needs a quit set for: {}",
                rule.name,
                prefilter_pattern(&rule.pattern)
            );
        }
        assert!(
            refused_before >= 45,
            "only {refused_before} of {} rules were refused before the rewrite, so this \
             test is no longer watching anything",
            set.rules.len()
        );
    }

    /// GH #194's headline: one byte >= 0x80 anywhere in a read window
    /// costs the prefilter its automaton.
    ///
    /// Measured on this tree, release, on REQ-O-007's 41,472 B default
    /// read window (512 lookbehind + 32,768 + 8,192 lookahead):
    /// **0.082 ms pure ASCII, 37.4 ms with one em dash at the midpoint,
    /// 39.1 ms with one `é` — 456x**. After the rewrite both are 0.09 ms,
    /// and the same holds for a 4-byte emoji and a lone `0x80`, at the
    /// first byte, the midpoint and the last: 316-546x, all of it gone.
    ///
    /// The assertion is the same shape as the cache one and for the same
    /// reason: a ratio inside one process is a statement about the
    /// engine, an absolute budget is a statement about the machine. The
    /// floor is 20x against a measured 316-546x, and it is paired with an
    /// absolute floor on the ASCII arm — see the assertion for why a bare
    /// ratio is not enough.
    #[test]
    fn one_non_ascii_byte_anywhere_in_the_window_no_longer_costs_the_automaton() {
        use std::time::Instant;
        let set = RuleSet::builtin().unwrap();
        let ascii: Vec<u8> = DEFAULT_RULES_TOML
            .bytes()
            .filter(|b| b.is_ascii())
            .collect();
        // 512 + 32_768 + 8_192, REQ-O-007's default read window.
        let base: Vec<u8> = ascii.iter().cycle().take(41_472).copied().collect();

        // Minimum of seven, for the reason given on the cache test
        // above: a mean carries a neighbour's scheduling stall into the
        // ratio and this assertion flaked on one.
        let bench = |w: &[u8]| {
            for _ in 0..2 {
                std::hint::black_box(set.prefilter.matches(w).into_iter().count());
            }
            (0..7)
                .map(|_| {
                    let t = Instant::now();
                    std::hint::black_box(set.prefilter.matches(w).into_iter().count());
                    t.elapsed().as_secs_f64()
                })
                .fold(f64::INFINITY, f64::min)
        };
        let flat = bench(&base);

        // **The ratio alone is blind to a regression that moves both
        // arms, and that is not hypothetical.** Reverting *both* halves
        // of GH #194 — an identity `prefilter_pattern` and the crate's
        // 2 MiB `dfa_size_limit`, which is exactly `main` — leaves this
        // test green with 5x of slack, because the ceiling revert
        // inflates `flat` from 0.066 ms to 11.4 ms and the bound with
        // it. So the ratio's non-degeneracy was borrowed from the other
        // commit's constant, and nothing said so.
        //
        // The floor is the ASCII arm on its own. Measured on this tree:
        // healthy is 0.05–0.15 ms and holds under twelve busy-loop
        // processes on twelve cores; the both-halves-reverted tree is
        // 11.4 ms. 2 ms is an order of magnitude above the first and
        // more than five times below the second.
        assert!(
            flat < 2e-3,
            "the ASCII arm alone costs {:.3} ms for {} B, which is not a healthy \
             prefilter at all; the ratio below would pass against it",
            flat * 1e3,
            base.len(),
        );

        // A two-byte glyph, a three-byte one, a four-byte one, and a
        // lone continuation byte that is no glyph at all — each at the
        // first byte, the midpoint and the last.
        let probes: [(&str, &[u8]); 4] = [
            ("é", "\u{e9}".as_bytes()),
            ("em dash", "\u{2014}".as_bytes()),
            ("emoji", "\u{1F600}".as_bytes()),
            ("lone 0x80", &[0x80]),
        ];
        for (name, probe) in probes {
            for (where_, at) in [
                ("first", 0usize),
                ("midpoint", base.len() / 2),
                ("last", base.len() - 1),
            ] {
                let mut w = base[..at].to_vec();
                w.extend_from_slice(probe);
                w.extend_from_slice(&base[at..]);
                let with = bench(&w);
                assert!(
                    with < flat * 20.0 + 1e-4,
                    "{name} at the {where_} byte costs {:.3} ms against {:.3} ms for the \
                     same window in ASCII; GH #194's quit set is back",
                    with * 1e3,
                    flat * 1e3,
                );
            }
        }
    }

    /// GH #194's second cliff: the prefilter's lazy DFA outgrows the
    /// `regex` crate's 2 MiB default cache and falls off it, on **pure
    /// ASCII** — a different failure from the Unicode word boundary,
    /// with its own fix.
    ///
    /// **They are not independent, and the direction matters.** The
    /// ceiling does nothing for the Unicode cliff (measured 1.01x and
    /// 0.94x), but the boundary rewrite makes *this* one worse without
    /// the ceiling — 19.09 ms against a 5.59 ms base at 256 KiB of this
    /// corpus, because deleting the quit set means the automaton
    /// actually explores states and then thrashes a 2 MiB cache. So the
    /// ceiling is a **prerequisite** for the rewrite rather than a
    /// separate improvement: reverting the rewrite alone is safe,
    /// reverting the ceiling alone is not, and a tree with the rewrite
    /// and without the ceiling fails this very test.
    ///
    /// **The corpus is the rule file with its non-ASCII bytes removed,
    /// and that is not a convenience.** Every near-miss a real DFA cache
    /// meets is in there by construction — every shipped rule's worth of
    /// positive *and* negative examples, so the automaton is dragged
    /// deep into many rules at once and then told no — and it is
    /// `include_str!`-compiled, so the test needs no fixture and cannot
    /// drift from the rules it is about. Stripping bytes ≥ 0x80 is what
    /// makes this a measurement of the cache and not of the quit set:
    /// with them in, both arms are slow for the *other* reason.
    ///
    /// **The assertion is a ratio inside one process, deliberately.** An
    /// absolute millisecond budget is a statement about the machine;
    /// this is a statement about the engine, and the mechanism — a cache
    /// that either holds the automaton or is cleared on every block — is
    /// not machine-dependent. Measured on this tree, release, 262,144 B:
    /// **5.15 ms at the crate default against 0.057 ms here**. The ratio
    /// is load- and method-sensitive — 56x, 71x and 91x on three
    /// measurements of the same two arms — so the floor is **8x**, below
    /// the lowest of them and still an order of magnitude clear of "the
    /// two are the same". An earlier revision of this comment claimed
    /// 258x from a mean rather than a minimum and from a *different*
    /// pair of arms, and nobody could reproduce it.
    #[test]
    fn the_prefilter_cache_ceiling_keeps_a_quarter_mib_ascii_window_off_the_slow_path() {
        use std::time::Instant;
        let set = RuleSet::builtin().unwrap();
        let patterns: Vec<String> = set.rules.iter().map(|r| r.pattern.clone()).collect();
        let stock = RegexSet::new(&patterns).expect("the shipped patterns compile");

        let ascii: Vec<u8> = DEFAULT_RULES_TOML
            .bytes()
            .filter(|b| b.is_ascii())
            .collect();
        let window: Vec<u8> = ascii.iter().cycle().take(256 * 1024).copied().collect();

        // Same answer from both, or the comparison is between two
        // different pieces of work rather than two cache ceilings.
        let stock_hits: Vec<usize> = stock.matches(&window).into_iter().collect();
        let ours_hits: Vec<usize> = set.prefilter.matches(&window).into_iter().collect();
        assert_eq!(
            stock_hits, ours_hits,
            "the cache ceiling must not change which rules the prefilter names"
        );

        // **And that equality cannot fail on this corpus, which is why
        // it is not the guard.** The window is the rule file, so it
        // carries every rule's own positive example and *both* sides
        // always name every rule. A `prefilter_pattern` returning
        // `"(?s).*"` — a filter with no selectivity whatever — passes
        // the row above and then reports a triumphant ratio while
        // measuring nothing. The guard is selectivity on a haystack
        // that holds no credential at all.
        let prose: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
            .iter()
            .cycle()
            .take(64 * 1024)
            .copied()
            .collect();
        let named: Vec<&str> = set
            .prefilter
            .matches(&prose)
            .into_iter()
            .map(|i| set.rules[i].name.as_str())
            .collect();
        assert!(
            named.is_empty(),
            "the prefilter names {named:?} on 64 KiB of plain prose holding no \
             credential, so it is not filtering and the ratio below measures nothing"
        );

        // **The minimum of seven runs, not the mean.** A shared CI box
        // stalls a run at random and a mean carries the stall into the
        // ratio; a minimum can only be inflated if every run is stalled.
        // This test flaked once on a mean while a neighbouring agent was
        // running three `cargo build`s, which is exactly the shape.
        let bench = |rs: &RegexSet| {
            for _ in 0..2 {
                std::hint::black_box(rs.matches(&window).into_iter().count());
            }
            (0..7)
                .map(|_| {
                    let t = Instant::now();
                    std::hint::black_box(rs.matches(&window).into_iter().count());
                    t.elapsed().as_secs_f64()
                })
                .fold(f64::INFINITY, f64::min)
        };
        let stock_s = bench(&stock);
        let ours_s = bench(&set.prefilter);
        assert!(
            ours_s * 8.0 < stock_s,
            "a {} B prefilter scan takes {:.3} ms at dfa_size_limit={} and {:.3} ms at \
             the crate default; GH #194's cache cliff is back or the corpus no longer \
             reaches it",
            window.len(),
            ours_s * 1e3,
            PREFILTER_DFA_SIZE_LIMIT,
            stock_s * 1e3,
        );
    }

    #[test]
    fn the_builtin_set_compiles_and_is_substantial() {
        let set = RuleSet::builtin().expect("built-in rules must compile");
        assert!(
            set.len() >= 40,
            "expected a substantial rule set, got {}",
            set.len()
        );
        assert!(
            !set.source_version.is_empty(),
            "provenance must be recorded"
        );
    }

    /// REQ-SEC-007: every shipped pattern has positive and negative tests.
    /// The examples live beside the rule in TOML, so a rule with no
    /// examples fails to load at all (`MissingExamples`) and a rule with
    /// wrong examples fails here.
    ///
    /// **This is the *pattern* check and it is not the whole of the
    /// coverage.** It hands each fixture to `rule.regex` directly, so it
    /// proves the regex is the one its author meant and nothing about
    /// what the pipeline does with it. The *pipeline* check over the same
    /// fixtures is `tests/redaction_sweep.rs`, which runs them through
    /// `process` and `StreamRedactor` and asks what a consumer can
    /// reconstruct from the bytes that went out (GH #135, #138, #139).
    #[test]
    fn every_rule_matches_its_positives_and_rejects_its_negatives() {
        let set = RuleSet::builtin().unwrap();
        for rule in &set.rules {
            for p in &rule.positive {
                assert!(
                    rule_redacts(rule, p.as_bytes()),
                    "rule `{}` failed to match its positive example {p:?}",
                    rule.name
                );
            }
            for n in &rule.negative {
                assert!(
                    !rule_redacts(rule, n.as_bytes()),
                    "rule `{}` matched its negative example {n:?}",
                    rule.name
                );
            }
        }
    }

    /// What one rule decides about one input, **spelled the way
    /// [`find_spans`] spells it** — pattern first, then the rule's own
    /// `value_must_not_match` (GH #202), on the `value` capture or, for a
    /// rule without one, on the whole match (GH #245).
    ///
    /// [`find_spans`]: super::super::redact::find_spans
    fn rule_redacts(rule: &CompiledRule, hay: &[u8]) -> bool {
        if !rule.has_value_group {
            return rule
                .regex
                .find_iter(hay)
                .any(|m| rule.value_admissible(m.as_bytes()));
        }
        rule.regex
            .captures_iter(hay)
            .filter_map(|c| c.name("value"))
            .any(|m| rule.value_admissible(m.as_bytes()))
    }

    /// **Which negatives the *pattern* refuses and which ones only the
    /// *refusal* refuses, pinned by name.**
    ///
    /// The arm above had to widen when `value_must_not_match` arrived:
    /// before GH #202 a `negative` meant "the pattern does not match
    /// this", and now it means "this rule redacts nothing here", which
    /// is the weaker of the two claims. That widening is correct — a
    /// fixture asserting a *rule's* behaviour should ask the rule and
    /// not one half of it — but on its own it lets a pattern quietly
    /// grow broad enough to match an old negative while the refusal
    /// catches the fallout and the suite stays green.
    ///
    /// So the split is a fixture too. The negatives listed here are held
    /// by a refusal; every other one is held by its pattern, as it was
    /// before this field existed. A pattern that starts matching a
    /// negative it used to reject moves a row into the first list and
    /// reds here even though nothing leaks.
    #[test]
    fn the_refusal_holds_exactly_the_negatives_it_is_named_for() {
        const REFUSAL_HELD: &[(&str, &str)] = &[
            // GH #245: the OpenSSH algorithm name, judged as a whole
            // match because `openai-api-key` has no `value` group.
            (
                "openai-api-key",
                "pubkeyacceptedalgorithms sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com",
            ),
            // GH #244: English after `Basic`, refused for its length.
            (
                "basic-authorization",
                "Authorization: Basic authentication is required",
            ),
            (
                "secret-key-assignment",
                "pub session_key: Option<SessionKey>,",
            ),
            (
                "secret-key-assignment",
                "master_key = config.master_key.clone()",
            ),
            // GH #245: a `::` path, led by a `&`.
            ("secret-key-assignment", "secret_key: &crate::SecretKey,"),
            (
                "generic-secret-assignment",
                "reassembled the token: `get_screen_state`",
            ),
            ("generic-secret-assignment", "export TOKEN={GITHUB}"),
            (
                "generic-secret-assignment",
                "let cancellation_token = cancellation_token.clone();",
            ),
            // GH #245: the two code shapes the refusal gained.
            ("generic-secret-assignment", "pub paren_token: token::Paren,"),
            ("generic-secret-assignment", "semi_token: node.semi_token,"),
        ];
        let set = RuleSet::builtin().unwrap();
        let mut held: Vec<(&str, &str)> = Vec::new();
        for rule in &set.rules {
            for n in &rule.negative {
                // The pattern alone still matches, so the refusal is the
                // only thing standing between this row and a marker.
                if rule.regex.is_match(n.as_bytes()) {
                    held.push((rule.name.as_str(), n.as_str()));
                }
            }
        }
        assert_eq!(
            held, REFUSAL_HELD,
            "the set of negatives held by a refusal rather than by a pattern moved; \
             update this list deliberately rather than to make it pass"
        );
        // And the refusal really is what holds them: each row's pattern
        // matches and the rule still redacts nothing.
        for (name, row) in REFUSAL_HELD {
            let rule = set.rules.iter().find(|r| &r.name == name).unwrap();
            assert!(
                rule.value_refusal.is_some(),
                "`{name}` is listed as refusal-held and declares no refusal"
            );
            assert!(
                !rule_redacts(rule, row.as_bytes()),
                "`{name}` still redacts {row:?}"
            );
        }
    }

    /// A rule with **no** `value` group judges its **whole match** with
    /// `value_must_not_match` (GH #245).
    ///
    /// GH #202 made this a load error, on the ground that such a rule had
    /// "no value to judge". It has one: a rule without a `value` group
    /// redacts its whole match, so its whole match is what a refusal
    /// must look at — and `openai-api-key` needs exactly that to decline
    /// OpenSSH's `sk-ecdsa-sha2-nistp256-cert-v01`.
    ///
    /// **Three arms, because each is a way to get it wrong.** The refusal
    /// must reach `find_spans` (the pipeline), not only the rule helper;
    /// it must judge the whole match and not a prefix of it; and a match
    /// it does not refuse must still be redacted, or the arm above is
    /// satisfied by a rule set that redacts nothing.
    #[test]
    fn a_value_refusal_on_a_rule_without_a_value_group_judges_the_whole_match() {
        let src = r#"
[[rule]]
name = "no-value-group"
kind = "test"
pattern = '''\bxyzzy-[0-9a-z]{8,}'''
value_must_not_match = '''xyzzy-[a-z]+'''
positive = ["xyzzy-01234567"]
negative = ["xyzzy-abcdefgh"]
"#;
        let set = RuleSet::from_toml(src).expect("a whole-match refusal compiles");
        let rule = &set.rules[0];
        assert!(!rule.has_value_group && rule.value_refusal.is_some());

        // 1. Refused through the pipeline, not only through the helper.
        assert!(
            super::super::redact::find_spans(&set, b"see xyzzy-abcdefgh here", 0).is_empty(),
            "find_spans must consult the refusal on a rule with no `value` group"
        );
        // 2. Judged whole: a match the expression covers only a prefix of
        //    is admitted, because `\A…\z` anchors both ends.
        let spans = super::super::redact::find_spans(&set, b"see xyzzy-abcdefgh1 here", 0);
        assert_eq!(
            spans.iter().map(|s| (s.start, s.end)).collect::<Vec<_>>(),
            vec![(4, 19)],
            "a whole match the refusal does not cover must be redacted, all of it"
        );
        // 3. The control: an ordinary match still redacts.
        assert!(rule_redacts(rule, b"xyzzy-01234567"));
        assert!(!rule_redacts(rule, b"xyzzy-abcdefgh"));
    }

    /// The refusal is anchored to **both** ends of the value and reads
    /// bytes, not characters (GH #202).
    ///
    /// Three separate ways to get this wrong, each of which leaks or
    /// over-redacts silently, and each pinned here: an unanchored
    /// refusal would decline any value *containing* the expression; `$`
    /// in place of `\z` would let a trailing newline past it; and a
    /// refusal left in Unicode mode fails every `.` on a value that is
    /// not valid UTF-8 — so a credential carrying one stray byte would
    /// be *admitted* by a refusal written to decline it, which is the
    /// direction that leaks.
    ///
    /// **`\z` rather than `$` is explicitness and not a fix, and an
    /// earlier draft of this comment claimed otherwise.** In Perl,
    /// Python and PCRE `$` also matches *before* a final newline, and
    /// the draft said swapping it in would let `value\n` past the
    /// refusal. It would not: in the `regex` crate `$` without `(?m)`
    /// is end-of-haystack exactly, so the two spellings are the same
    /// automaton. A mutation swapping them is **equivalent**, which is
    /// why no row here reds for it — driven directly rather than
    /// assumed, `\A(?s-u:[a-z]+)$` and `\A(?s-u:[a-z]+)\z` both refuse
    /// `abcd` and both admit `abcd\n`, and only `(?m)$` differs.
    #[test]
    fn a_value_refusal_is_anchored_at_both_ends_and_reads_bytes() {
        let src = r#"
[[rule]]
name = "probe"
kind = "test"
pattern = '''\bprobe=(?P<value>[^\s]{4,})'''
value_must_not_match = '''[a-z]+'''
positive = ["probe=AB12"]
negative = ["probe=abcd"]
"#;
        let set = RuleSet::from_toml(src).unwrap();
        let rule = &set.rules[0];
        assert!(!rule.value_admissible(b"abcd"), "a whole match is refused");
        assert!(
            rule.value_admissible(b"abZcd"),
            "anchoring: a value merely *containing* the expression is not refused"
        );
        assert!(
            rule.value_admissible(b"abcd\n"),
            "end-anchoring: a trailing byte outside the expression must leave \
             the value un-refused"
        );

        // Byte mode. `.` in a Unicode-mode refusal cannot cross an
        // invalid UTF-8 byte, so `(?s:.+)` would admit this value; in
        // byte mode it refuses it.
        let bytes_src = src.replace(r"[a-z]+", r"(?s:.+)");
        let bytes_set = RuleSet::from_toml(&bytes_src).unwrap();
        assert!(
            !bytes_set.rules[0].value_admissible(b"ab\xffcd"),
            "the refusal must read bytes: a value that is not valid UTF-8 \
             must not slip past a refusal that covers every byte"
        );
    }

    /// **`anchored_whole_match`, driven on all three of its arms —
    /// including the one the shipped rule set cannot reach.**
    ///
    /// Both label-keyed rules have an unconditional `value` group, so
    /// the "group did not participate" arm is dead code against the
    /// built-in rules and a corpus over them cannot kill a mutation
    /// in it. A rule whose `value` sits inside an alternation reaches
    /// it, and that arm must answer **false** — *hold this candidate
    /// back* — because a match this rule will not act on is not a
    /// reason to release bytes that are still arriving. Answering
    /// `true` there releases them, which is the leak
    /// `anchored_whole_match` exists to close.
    #[test]
    fn anchored_whole_match_holds_back_when_the_value_group_did_not_participate() {
        let src = r#"
[[rule]]
name = "optional-value"
kind = "test"
pattern = '''\bprobe=(?:unset|(?P<value>[^\s]{4,}))'''
value_must_not_match = '''[a-z]+'''
positive = ["probe=AB12"]
negative = ["probe=abcd"]
"#;
        let set = RuleSet::from_toml(src).unwrap();
        let rule = &set.rules[0];

        // 1. Whole match, admissible value -> release.
        assert!(
            rule.anchored_whole_match(b"probe=AB12"),
            "an admissible value is a whole match"
        );
        // 2. Whole match, refused value -> hold back.
        assert!(
            !rule.anchored_whole_match(b"probe=abcd"),
            "a refused value must not count as a whole match"
        );
        // 3. Whole match, `value` group absent -> hold back. The regex
        //    matches and there is nothing to judge.
        assert!(
            rule.anchored.is_match(b"probe=unset"),
            "the control: the pattern really does match with no `value` group, \
             so arm 3 is reached rather than short-circuited by arm 2"
        );
        assert!(
            !rule.anchored_whole_match(b"probe=unset"),
            "a match whose `value` group did not participate must hold back, \
             not release"
        );
        // 4. No match at all -> hold back.
        assert!(!rule.anchored_whole_match(b"nothing here"));

        // 5. A rule with **no** `value` group judges its whole anchored
        //    match (GH #245): refused -> hold back, admitted -> release.
        let whole = RuleSet::from_toml(
            &src.replace(r"(?:unset|(?P<value>[^\s]{4,}))", r"[^\s]{4,}")
                .replace("[a-z]+", "probe=[a-z]+"),
        )
        .unwrap();
        let whole = &whole.rules[0];
        assert!(!whole.has_value_group && whole.value_refusal.is_some());
        assert!(
            whole.anchored_whole_match(b"probe=AB12"),
            "an admissible whole match releases"
        );
        assert!(
            !whole.anchored_whole_match(b"probe=abcd"),
            "a refused whole match must not count as one: the redactor will \
             decline it, so releasing it would hand out bytes still growing"
        );
        assert!(!whole.anchored_whole_match(b"nothing here"));

        // And a rule with no refusal is unaffected on every arm: it
        // answers exactly what `anchored.is_match` answers.
        let plain =
            RuleSet::from_toml(&src.replace("value_must_not_match = '''[a-z]+'''\n", "")).unwrap();
        let plain = &plain.rules[0];
        for hay in [
            &b"probe=AB12"[..],
            b"probe=abcd",
            b"probe=unset",
            b"nothing here",
        ] {
            assert_eq!(
                plain.anchored_whole_match(hay),
                plain.anchored.is_match(hay),
                "a rule with no refusal must answer what the anchored form does: {:?}",
                String::from_utf8_lossy(hay)
            );
        }
    }

    /// Every shipped rule not named here declares no refusal, and for
    /// those `value_admissible` is unconditionally `true` — so the
    /// feature cannot have changed what they redact.
    #[test]
    fn only_the_rules_named_for_it_carry_a_value_refusal() {
        let set = RuleSet::builtin().unwrap();
        let with: Vec<&str> = set
            .rules
            .iter()
            .filter(|r| r.value_refusal.is_some())
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            with,
            vec![
                "openai-api-key",
                "basic-authorization",
                "secret-key-assignment",
                "generic-secret-assignment"
            ],
            "the set of rules carrying a value refusal moved"
        );
        for rule in set.rules.iter().filter(|r| r.value_refusal.is_none()) {
            assert!(
                rule.value_admissible(b"anything at all \xff"),
                "`{}` declares no refusal and must admit every value",
                rule.name
            );
        }
    }

    #[test]
    fn rule_names_are_unique_and_kinds_are_populated() {
        let set = RuleSet::builtin().unwrap();
        let mut names: Vec<&str> = set.rules.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate rule name");
        for rule in &set.rules {
            assert!(!rule.kind.is_empty(), "rule `{}` has no kind", rule.name);
        }
    }

    #[test]
    fn anchored_form_only_matches_at_offset_zero() {
        let set = RuleSet::builtin().unwrap();
        let rule = set
            .rules
            .iter()
            .find(|r| r.name == "github-token")
            .expect("github-token rule");
        let token = b"ghp_0123456789abcdefghijABCDEFGHIJ012345";
        assert!(rule.anchored.is_match(token));
        let shifted = b"xx ghp_0123456789abcdefghijABCDEFGHIJ012345";
        assert!(
            !rule.anchored.is_match(shifted),
            "anchored form must not float; it is the scanner's completeness test"
        );
        assert!(
            rule.regex.is_match(shifted),
            "the unanchored form still finds it"
        );
    }

    #[test]
    fn value_group_rules_are_flagged() {
        let set = RuleSet::builtin().unwrap();
        let dd = set
            .rules
            .iter()
            .find(|r| r.name == "datadog-api-key")
            .unwrap();
        assert!(dd.has_value_group, "context rules capture only the value");
        let gh = set.rules.iter().find(|r| r.name == "github-token").unwrap();
        assert!(!gh.has_value_group, "prefix rules redact the whole match");
    }

    #[test]
    fn a_rule_without_examples_is_rejected() {
        let err = RuleSet::from_toml(
            r#"
            [[rule]]
            name = "no-examples"
            kind = "x"
            pattern = "abc"
            "#,
        )
        .expect_err("must refuse a rule with no examples");
        assert!(matches!(err, RuleError::MissingExamples(n) if n == "no-examples"));
    }

    #[test]
    fn a_user_rule_declaring_the_reserved_kind_is_rejected() {
        // §9.2(b): `unresolved` is the marker for a match the redactor's
        // window could not *judge*. Every other `[REDACTED:<kind>]`
        // names a rule that matched; this one means the opposite, so a
        // rule able to claim it makes a genuinely matched secret
        // indistinguishable from a withheld partial — the one
        // distinction the marker exists to carry.
        //
        // The rule below is **valid in every other respect** — a
        // compiling pattern, non-empty examples, a name no built-in
        // uses — or `MissingExamples` or `Pattern` fires first and this
        // row passes with no guard present at all.
        let err = RuleSet::builtin_with_extra(
            r#"
            [[rule]]
            name = "impostor"
            kind = "unresolved"
            pattern = 'IMP_[A-Z0-9]{8}'
            positive = ["IMP_ABCD1234"]
            negative = ["IMP_ABC"]
            "#,
        )
        .expect_err("`compile` must refuse the reserved kind");
        assert!(
            matches!(err, RuleError::ReservedKind(ref n) if n == "impostor"),
            "the error must name the offending rule; got {err:?}"
        );
        assert!(err.to_string().contains("impostor"), "{err}");
    }

    #[test]
    fn an_ordinary_user_rule_still_loads() {
        // **The pairing, and it is what makes the row above mean
        // anything.** A loader that rejected every user rule, and a
        // guard written as `contains("unresolved")`, both pass the
        // rejection row on their own — the blocklist-shaped failure
        // reached through the *absence* of a negative.
        let builtin = RuleSet::builtin().unwrap();
        let set = RuleSet::builtin_with_extra(
            r#"
            [[rule]]
            name = "ordinary"
            kind = "internal-token"
            pattern = 'ORD_[A-Z0-9]{8}'
            positive = ["ORD_ABCD1234"]
            negative = ["ORD_ABC"]
            "#,
        )
        .expect("an ordinary user rule must load");
        // Computed, never a literal count: the shipped set drifts.
        assert_eq!(set.len(), builtin.len() + 1);
        assert!(set.rules.iter().any(|r| r.kind == "internal-token"));

        // Second arm, in the same test: the reservation is **exact
        // equality**, not a prefix and not a substring. `marker`
        // interpolates `kind` verbatim, so `unresolved-token` produces a
        // different string that collides with nothing — and under
        // REQ-CFG-003 an over-rejected config is a daemon that refuses
        // to start, which is a real cost for no safety.
        let set = RuleSet::builtin_with_extra(
            r#"
            [[rule]]
            name = "near-miss"
            kind = "unresolved-token"
            pattern = 'NMS_[A-Z0-9]{8}'
            positive = ["NMS_ABCD1234"]
            negative = ["NMS_ABC"]
            "#,
        )
        .expect("`unresolved-token` is a legal kind and must still load");
        assert!(set.rules.iter().any(|r| r.kind == "unresolved-token"));
    }

    #[test]
    fn the_reserved_kind_constant_has_one_definition() {
        // 0.0.6 imports it from *this* module while `redact` defines it,
        // so the re-export is the thing under test: two `const`s with
        // the same text would satisfy every other assertion here and
        // diverge in silence.
        assert_eq!(UNRESOLVED_KIND, "unresolved");
        assert_eq!(UNRESOLVED_KIND, crate::output::redact::UNRESOLVED_KIND);
    }

    #[test]
    fn an_invalid_pattern_names_the_rule() {
        let err = RuleSet::from_toml(
            r#"
            [[rule]]
            name = "broken"
            kind = "x"
            pattern = "([unclosed"
            positive = ["a"]
            negative = ["b"]
            "#,
        )
        .expect_err("must refuse an uncompilable pattern");
        assert!(matches!(err, RuleError::Pattern { ref name, .. } if name == "broken"));
    }

    #[test]
    fn user_rules_extend_and_override_by_name() {
        let base = RuleSet::builtin().unwrap();
        let set = RuleSet::builtin_with_extra(
            r#"
            [[rule]]
            name = "internal-token"
            kind = "acme-internal"
            pattern = '''\bINT_[A-Z0-9]{10,}'''
            positive = ["INT_ABCDEFGHIJ"]
            negative = ["INT_ABC"]

            [[rule]]
            name = "github-token"
            kind = "github-overridden"
            pattern = '''\bghp_[0-9A-Za-z]{36,}'''
            positive = ["ghp_0123456789abcdefghijABCDEFGHIJ012345"]
            negative = ["ghp_abc"]
            "#,
        )
        .unwrap();
        assert_eq!(
            set.len(),
            base.len() + 1,
            "the override replaces in place; only the new rule grows the set"
        );
        let overridden = set.rules.iter().find(|r| r.name == "github-token").unwrap();
        assert_eq!(overridden.kind, "github-overridden");
        assert!(set.rules.iter().any(|r| r.name == "internal-token"));
    }

    /// GH #128: a disabled rule leaves the set, and the set is still a
    /// working set — every remaining rule, every remaining prefilter
    /// index.
    ///
    /// **The index assertion is the one that matters.** The prefilter
    /// reports positions into `rules`, so an implementation that removed
    /// the rule from `rules` and kept the original `RegexSet` would pass
    /// a length check and then name the *wrong kind* on every redaction
    /// after the hole. `github-token` sits after `aws-access-key-id` in
    /// the shipped file, so this pairing is exactly that case.
    #[test]
    fn a_disabled_rule_leaves_the_set_and_the_prefilter_still_indexes_it() {
        let full = RuleSet::builtin().unwrap();
        let set = RuleSet::builtin_without(&["aws-access-key-id".to_string()]).unwrap();

        assert_eq!(set.len(), full.len() - 1);
        assert!(!set.rules.iter().any(|r| r.name == "aws-access-key-id"));
        assert!(
            set.rules.iter().any(|r| r.name == "github-token"),
            "disabling one rule must not take its neighbours with it"
        );

        let hay = b"token=ghp_0123456789abcdefghijABCDEFGHIJ012345 done";
        let hits: Vec<usize> = set.prefilter.matches(hay).into_iter().collect();
        assert!(
            !hits.is_empty(),
            "the prefilter was not rebuilt from the reduced set"
        );
        for i in &hits {
            assert!(
                set.rules[*i].regex.is_match(hay),
                "prefilter index {i} names `{}`, which does not match — the RegexSet and \
                 the rule list have drifted apart",
                set.rules[*i].name
            );
        }
        assert!(hits.iter().any(|i| set.rules[*i].name == "github-token"));
    }

    /// A name the built-in set does not carry is an error and not a
    /// silent no-op (GH #128), and the message names it.
    #[test]
    fn an_unknown_disabled_rule_name_is_refused_and_named() {
        let err = RuleSet::builtin_without(&["aws_access_key_id".to_string()])
            .expect_err("a misspelled rule name must not compile to the full set");
        let msg = err.to_string();
        assert!(
            msg.contains("aws_access_key_id"),
            "the operator can only fix what the message names: {msg}"
        );
        // The reserved pseudo-kind is not a rule name either, and the
        // same refusal covers it (REQ-O-011a, §9.2).
        assert!(RuleSet::builtin_without(&[UNRESOLVED_KIND.to_string()]).is_err());
    }

    /// Disabling every rule is legal, enumerated, and yields a set that
    /// still compiles — an empty `RegexSet` matches nothing rather than
    /// everything, which is the failure a "no rules means no prefilter"
    /// shortcut would have.
    #[test]
    fn disabling_every_rule_yields_an_empty_set_that_still_answers() {
        let all: Vec<String> = builtin_rule_names().iter().cloned().collect();
        let set = RuleSet::builtin_without(&all).expect("an empty rule set is a rule set");
        assert!(set.is_empty());
        assert!(set
            .prefilter
            .matches(b"ghp_0123456789abcdefghijABCDEFGHIJ012345")
            .into_iter()
            .next()
            .is_none());
        assert_eq!(set.disabled_builtin_rules().len(), all.len());
    }

    /// `disabled_builtin_rules` reads the **set**, so it reports what the
    /// read path will really do rather than what a config said.
    #[test]
    fn the_disabled_list_is_derived_from_the_set_and_not_from_a_config() {
        assert!(
            RuleSet::builtin()
                .unwrap()
                .disabled_builtin_rules()
                .is_empty(),
            "the built-in set has nothing disabled, whatever any config says"
        );
        let set =
            RuleSet::builtin_without(&["jwt".to_string(), "github-token".to_string()]).unwrap();
        assert_eq!(
            set.disabled_builtin_rules(),
            vec!["github-token", "jwt"],
            "sorted, so the audit row and the startup line do not depend on config order"
        );
    }

    /// The names are the shipped file's, not a copy kept beside it.
    #[test]
    fn the_built_in_names_are_the_shipped_rule_files_own() {
        let names = builtin_rule_names();
        let set = RuleSet::builtin().unwrap();
        assert_eq!(names.len(), set.len());
        for rule in &set.rules {
            assert!(names.contains(&rule.name), "{} is missing", rule.name);
        }
    }

    #[test]
    fn the_prefilter_reports_matching_rule_indices() {
        let set = RuleSet::builtin().unwrap();
        let hay = b"token=ghp_0123456789abcdefghijABCDEFGHIJ012345 done";
        let hits: Vec<usize> = set.prefilter.matches(hay).into_iter().collect();
        assert!(
            hits.iter().any(|i| set.rules[*i].name == "github-token"),
            "github-token must be among the prefilter hits"
        );
        let clean = b"   Compiling holdfast-core v0.0.1 (/home/user/src/holdfast)";
        assert!(
            set.prefilter.matches(clean).into_iter().next().is_none(),
            "ordinary build output must not trip any rule"
        );
    }

    /// Kills "`builtin_shared` calls `RuleSet::builtin()` every time" — a
    /// version that recompiles the whole table per call still returns a
    /// correct, equal rule set, so equality proves nothing. Pointer
    /// identity is the only thing that distinguishes the two.
    #[test]
    fn the_shared_set_is_compiled_once_and_handed_out_by_reference() {
        let a = builtin_shared();
        let b = builtin_shared();
        assert!(
            Arc::ptr_eq(&a, &b),
            "builtin_shared must hand out the same allocation, not a fresh compile"
        );
        // …and it must be the real set, not an empty placeholder that
        // would also satisfy `ptr_eq`.
        assert_eq!(a.len(), RuleSet::builtin().unwrap().len());
        assert!(a.len() >= 40);
    }
}
