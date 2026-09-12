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
