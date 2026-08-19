//! The redaction rule set: TOML schema, loader, compiled form.
//!
//! The rule file (spec §9.2) is the single source of truth for what a
//! secret looks like. Everything downstream — the redactor, the prefix
//! index, the partial-secret scanner — derives from it, so there is no
//! second list to keep in sync.

pub use super::redact::UNRESOLVED_KIND;

use regex::bytes::{Regex, RegexSet};
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
            patterns.push(spec.pattern.clone());
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
        let prefilter = RegexSet::new(&patterns).map_err(|source| RuleError::Pattern {
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

    #[test]
    fn the_prefilter_reports_matching_rule_indices() {
        let set = RuleSet::builtin().unwrap();
        let hay = b"token=ghp_0123456789abcdefghijABCDEFGHIJ012345 done";
        let hits: Vec<usize> = set.prefilter.matches(hay).into_iter().collect();
        assert!(
            hits.iter().any(|i| set.rules[*i].name == "github-token"),
            "github-token must be among the prefilter hits"
        );
        let clean = b"   Compiling holdfast-core v0.0.1 (/home/user/src/clasp)";
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
