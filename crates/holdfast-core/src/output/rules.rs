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
    pub positive: Vec<String>,
    pub negative: Vec<String>,
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
    /// operator enumerated all fifty-one by name, the §9.4 row records
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
                positive: spec.positive,
                negative: spec.negative,
            });
        }
        // **The fallback is the one thing that keeps a user rule from
        // costing more than speed.** Every branch of `prefilter_pattern`
        // is superset-preserving, so a set built from the rewrites names
        // everything the rules can match; what it is not is *proved to
        // compile* for a pattern nobody has seen. If it does not, the
        // originals go in — GH #194's cliff and all — because a
        // `RuleSet` that refuses to load is a daemon that refuses to
        // start, and the rewrite is a performance fix.
        let prefilter = match build_prefilter(&patterns) {
            Ok(set) => set,
            Err(_) => {
                let verbatim: Vec<String> = rules.iter().map(|r| r.pattern.clone()).collect();
                build_prefilter(&verbatim).map_err(|source| RuleError::Pattern {
                    name: "<prefilter>".into(),
                    source,
                })?
            }
        };
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
/// with one em dash at the midpoint, 456x** — and the shipped file puts
/// a `\b` in forty-five of its fifty-one rules, so the prefilter has
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
/// **The premise is read conservatively and the failures are all in the
/// safe direction.** A boundary keeps its meaning only when the pattern
/// character touching it is a bare case-stable ASCII word literal —
/// immediately to the right and not made optional by a following `?`,
/// `*` or `{`, or immediately to the left. `\b(?:AKIA|ASIA)` and
/// `\b[0-9]{8,10}` are both provably fine by hand and both get the
/// deletion anyway, because a group or a class is past what this walk
/// reads. That costs prefilter selectivity, which costs time.
///
/// **What the conservatism is actually protecting, with the
/// counterexample.** `(?i)\b[a-z0-9_.-]{0,32}(?:password|…)\b` — the two
/// generic assignment rules — can begin its match on `.` or `-`, and
/// `\b` holds between `é` and `-` where `(?-u:\b)` reads `0xa9` and `-`
/// as both non-word and says it does not. Respelling **unconditionally**
/// is therefore unsound, and not theoretically: the differential in
/// `the_rewritten_prefilter_names_everything_the_rules_do` finds 2,623
/// haystacks over 4,051 patterns where it under-reports, against zero
/// for this function. The first it finds is
/// `(?i)\bz{0,3}--zq_k13_[A-Za-z0-9]{4,}` on a haystack opening `é-`.
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
    // Whether the character just emitted was a bare case-stable ASCII
    // word literal. A quantifier, a class close or a group close all
    // clear it, which is what keeps `a*\b`, `[abc]\b` and `(?:x|y)\b`
    // out of the respelling branch.
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
            Some('b') => {
                let right_is_word = matches!(src.get(i + 2), Some(&n) if is_case_stable_ascii_word(n))
                    && !matches!(src.get(i + 3), Some('?') | Some('*') | Some('{'));
                out.push_str(if right_is_word || left_is_word {
                    "(?-u:\\b)"
                } else {
                    "(?:)"
                });
                left_is_word = false;
                i += 2;
            }
            Some('B') => {
                out.push_str("(?:)");
                left_is_word = false;
                i += 2;
            }
            Some(&escaped) => {
                out.push('\\');
                out.push(escaped);
                left_is_word = false;
                i += 2;
            }
            None => {
                out.push('\\');
                i += 1;
            }
        }
    }
    out
}

/// The lazy-DFA cache ceiling the prefilter is built with, against the
/// `regex` crate's 2 MiB default (GH #194's second cliff).
///
/// **It is a ceiling, not an allocation, and the distinction is the
/// whole reason the number can be this large.** `regex` grows the cache
/// as a search discovers states and gives up on the DFA — falling back
/// to the one-state-at-a-time engine — when the cache would pass the
/// limit. The shipped fifty-one-rule set saturates well below any of
/// the candidates: sweeping 2/4/8/16/32/64 MiB over six corpora
/// (1 MiB of this repository's own source, its `grep -rn` output, its
/// `CHANGELOG`+`README`+`ROADMAP`, REQ-O-007's 41,472 B default read
/// window, 380 KB of `git log`, and 5.4 MB of concatenated `.rs`) the
/// resident cache tops out at **10.4 MiB at 16 MiB and stops growing**
/// — 32 MiB and 64 MiB measure the same 10.6 MiB. What the headroom
/// buys is not memory spent, it is the cliff staying gone when §9.2's
/// quarterly gitleaks refresh makes the set bigger.
///
/// **Measured, release build, prefilter scan only, worst corpus** (1 MiB
/// of this repository's own `.rs`, zero bytes ≥ 0x80 — this is not the
/// Unicode cliff, it is the cache one):
///
/// ```text
/// dfa_size_limit   total over the six corpora   resident cache
/// 2 MiB (default)              355.1 ms                1.8 MiB
/// 8 MiB                        105.0 ms                7.6 MiB
/// 16 MiB                        19.4 ms               10.4 MiB
/// 64 MiB                        23.9 ms               10.5 MiB
/// ```
///
/// The cost is paid **per thread that concurrently runs a redaction
/// scan**, because `regex` keeps a cache pool rather than one cache:
/// measured on the same corpus, 2.5 MiB/thread today against 5.9
/// MiB/thread here, so twelve concurrent readers move 29 MiB to 69 MiB.
/// There is one `RuleSet` per daemon — `builtin_shared` is a process-wide
/// `OnceLock` and `Config::redaction_rules_shared` hands the same `Arc`
/// to the single `OutputProcessor` in `HoldfastServer` — so that is the
/// whole of it, not a per-session figure.
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
    /// The shipped fifty-one reach none of these, which is the whole
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
    "#;

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
        // `+` is min-1, so the literal really is the adjacent byte.
        assert_eq!(prefilter_pattern(r"\bz+-x"), r"(?-u:\b)z+-x");
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
    /// **Random rule sets are not decoration.** Only two of the shipped
    /// fifty-one — the generic assignment pair — reach the deletion
    /// branch at a *leading* boundary, and neither can be made to
    /// diverge by hand, so a corpus over the built-ins alone is green
    /// against a rewrite that is wrong. The generator is PR #196's with
    /// the shapes GH #194 needs added: a leading class admitting
    /// punctuation, a zero-admitting quantifier between the boundary and
    /// the first literal, and `(?i)` over a `k`/`s` head. The haystack
    /// generator substitutes U+212A and U+017F into seeds for the same
    /// reason.
    ///
    /// Measured on this tree at a wider setting (4,000 random rules,
    /// 500 haystacks each): this finds **2,623** divergences for an
    /// unconditional `\b` → `(?-u:\b)`, **642** for one that forgets the
    /// case-fold exclusion and **632** for one that forgets the
    /// zero-quantifier guard — and **0** for what ships.
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

        let set = RuleSet::builtin().unwrap();

        // Arm 1: every shipped rule against its own positive examples,
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
    /// 39.1 ms with one `é` — 456x**. After the rewrite both are 0.09 ms.
    ///
    /// The assertion is the same shape as the cache one and for the same
    /// reason: a ratio inside one process is a statement about the
    /// engine, an absolute budget is a statement about the machine. The
    /// floor is 4x against a measured 450x.
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
    /// ASCII** — a separate failure from the Unicode word boundary and
    /// with a separate fix.
    ///
    /// **The corpus is the rule file with its non-ASCII bytes removed,
    /// and that is not a convenience.** Every near-miss a real DFA cache
    /// meets is in there by construction — fifty-one rules' worth of
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
    /// **10.33 ms at the crate default against 0.040 ms here, 258x**.
    /// The floor is 8x, which is thirty times inside the measurement and
    /// still an order of magnitude clear of "the two are the same".
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
                    rule.regex.is_match(p.as_bytes()),
                    "rule `{}` failed to match its positive example {p:?}",
                    rule.name
                );
            }
            for n in &rule.negative {
                assert!(
                    !rule.regex.is_match(n.as_bytes()),
                    "rule `{}` matched its negative example {n:?}",
                    rule.name
                );
            }
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
