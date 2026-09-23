//! The two **label-keyed** redaction rules against ordinary prose and
//! ordinary source (GH #202).
//!
//! `generic-secret-assignment` and `secret-key-assignment` match on the
//! *label* and do not inspect the value. That is deliberate and it is not
//! what this target is about: `password = not-set-yet` still comes back
//! `password = [REDACTED:generic]`, exactly as the 0.0.7 CHANGELOG
//! records it under GH #125, and changing that is an operator's decision
//! (`disabled_redaction_rules`, GH #128) rather than a test's.
//!
//! What GH #202 measured is narrower and is a defect on any reading: the
//! pair fires on text where **no assignment occurs at all**. `` the
//! token: `get_screen_state` `` and `the secret::binding flake cluster`
//! are prose and code respectively, and both came back with bytes
//! replaced by a marker the caller cannot undo except by re-reading the
//! whole window with `redact: false`.
//!
//! **Both are fixed now, in two steps taken separately, and the target
//! keeps them separable.**
//!
//! 1. **The separator half.** Both rules refuse a value whose first byte
//!    is another `:`: the separator is already consumed by `[:=]` at
//!    that point, so a value opening on a second colon means the source
//!    read `label::…` — a scope-resolution operator, not an assignment.
//!    [`NAMESPACE_PROSE`] is its corpus and [`PRE_FIX_RULES`] its
//!    control.
//! 2. **The value half.** Both rules carry `value_must_not_match`, which
//!    refuses a value with **no digit in it that also carries one of
//!    `( < > [ ] { } | \` or a backtick** — the bracket and quote bytes no
//!    credential alphabet uses (`_`, `.` and `:` were in the first draft
//!    and came back out; see [`REAL_SHAPED_CREDENTIALS`]).
//!    `` the token: `get_screen_state` `` has no second colon and so
//!    survived step 1; it is refused here. [`VALUE_SIDE_PROSE`] is its
//!    corpus and [`COLON_ONLY_RULES`] — the rules exactly as `main`
//!    carried them between the two — its control.
//! 3. **GH #245, Part 6 below.** Two more digit-free code shapes are
//!    refused — a `::` path, and a lower-case field access carrying an
//!    `_` — and a label no longer owns the next line's first word.
//!    [`CODE_SHAPES`] and [`CROSS_LINE`] are its corpora and
//!    [`BEFORE_245`] — the four rules it touched, as `a81b02d` shipped
//!    them — its control.
//!
//! The disjunction is what makes step 2 cost nothing. A bare "must
//! contain a digit" drops every digit-free passphrase; a bare value
//! character class drops a bcrypt hash and a password carrying `!` or
//! `@`; refusing only their *conjunction* drops neither, and
//! [`REAL_SHAPED_CREDENTIALS`] asserts that over every row it has.
//!
//! **Why the assertions here are not vacuous.** Every arm that asserts an
//! *absence* is paired with the same input run through the rule set that
//! came **before the step it measures**, installed by name over the
//! built-in set through [`RuleSet::builtin_with_extra`]. A rule set that
//! stopped matching anything at all would pass the absence arms and fail
//! the controls. Each corpus additionally carries a `not_vacuous` floor,
//! because an emptied table passes an absence arm *and* its control.
//!
//! [`RuleSet::builtin_with_extra`]: holdfast_core::output::rules::RuleSet::builtin_with_extra

use std::sync::Arc;

use holdfast_core::output::redact::{find_spans, redact_str};
use holdfast_core::output::rules::RuleSet;
use holdfast_core::output::{OutputProcessor, ProcessedRead, ReadOptions, WindowSnapshot};

/// **The intermediate control: both rules exactly as `main` carried them
/// between GH #202's two halves.** The colon refusal is in the pattern;
/// `value_must_not_match` is absent.
///
/// The arms for the value-side half measure against *this*, not against
/// [`PRE_FIX_RULES`]. Measuring the second half against the state before
/// the first would credit it with the first half's work, and the two
/// halves refuse different things for different reasons.
const COLON_ONLY_RULES: &str = r#"
[[rule]]
name = "secret-key-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:secret|private|encryption|signing|master|session)[_-]key\b["'\s]*[:=]\s*["']?(?P<value>[^:\s"';,)][^\s"';,)]{7,})'''
prefixes = ["secret_key", "secret-key", "private_key", "private-key", "encryption_key", "encryption-key", "signing_key", "signing-key", "master_key", "master-key", "session_key", "session-key"]
positive = ["CLERK_SECRET_KEY=sk_test_0123456789abcdef01234567"]
negative = ["SECRET_KEY_FILE=/run/secrets/app"]

[[rule]]
name = "generic-secret-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b["'\s]*[:=]\s*["']?(?P<value>[^:\s"';,)][^\s"';,)]{7,})'''
prefixes = ["password", "passwd", "secret", "apikey", "api_key", "api-key", "accesstoken", "access_token", "access-token", "authtoken", "auth_token", "auth-token"]
positive = ["export DB_PASSWORD=hunter2hunter2"]
negative = ["password: short"]
"#;

/// The value expression both rules carried before GH #202, reinstated by
/// name so the absence arms below have something to be measured against.
///
/// Spelled out rather than derived from the shipped pattern: a control
/// computed from the thing it controls cannot see a change to it.
const PRE_FIX_RULES: &str = r#"
[[rule]]
name = "secret-key-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:secret|private|encryption|signing|master|session)[_-]key\b["'\s]*[:=]\s*["']?(?P<value>[^\s"';,)]{8,})'''
prefixes = ["secret_key", "secret-key", "private_key", "private-key", "encryption_key", "encryption-key", "signing_key", "signing-key", "master_key", "master-key", "session_key", "session-key"]
positive = ["CLERK_SECRET_KEY=sk_test_0123456789abcdef01234567"]
negative = ["SECRET_KEY_FILE=/run/secrets/app"]

[[rule]]
name = "generic-secret-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b["'\s]*[:=]\s*["']?(?P<value>[^\s"';,)]{8,})'''
prefixes = ["password", "passwd", "secret", "apikey", "api_key", "api-key", "accesstoken", "access_token", "access-token", "authtoken", "auth_token", "auth-token"]
positive = ["export DB_PASSWORD=hunter2hunter2"]
negative = ["password: short"]
"#;

/// Rows taken from the corpora measured for GH #202 — third-party Rust
/// (`syn`, `tokio`, `hyper`, `serde`, `rmcp`), crates.io READMEs, the
/// Python 3.12 standard library, and this repository's own `git log` and
/// design docs. Every one of them is prose or source with no credential
/// anywhere in it, and every one of them was redacted before the fix.
const NAMESPACE_PROSE: &[&str] = &[
    "the secret::binding flake cluster was closed one row at a time",
    "`attach::secret::SecretBytes` is not serializable, by construction",
    "grep -rn 'secret::binding::' crates/holdfast-core/src",
    "`secret::provider`'s own fixture moved out of the shared directory",
    "- `mask_password::PasswordMasked` type was added in this release",
    "`libc::passwd::pw_gecos` and the corresponding field are supported",
    "use jsonwebtoken::{encode, decode, Header, EncodingKey};",
    "hash_password::<sha2::Sha256>(\"my_password\", \"abcd\", &mut buf1);",
    "the private_key::pkcs8_parser module re-exports it unchanged",
    "app.encryption_key::ROTATION_INTERVAL is a compile-time constant",
];

/// **GH #202's value-side half: prose and source where the label and the
/// separator are both there and the value is still not a credential.**
///
/// Nothing here has a second colon against the separator, so the first
/// half of #202 cannot see any of it and every row came back mangled on
/// `main` until this change. What each row's value has instead is one of
/// `( < > [ ] { } | \` or a backtick — a bracket, a pipe, a backslash or
/// a quote, none of which appears in any credential alphabet — and no
/// digit anywhere to vouch for it.
///
/// **`_`, `.` and `:` are deliberately absent from that set** and two
/// rows here were rewritten when they came out: `as_token: node.as_token`
/// and `app.encryption_key: ROTATION_INTERVAL` carried nothing else and
/// are mangled again. They are the residual, not the fix — see
/// [`a_bare_alphabetic_value_is_the_residual_false_positive`].
///
/// The first three are the issue's own measured rows, in the issue's own
/// words; the rest are taken from the same corpora as [`NAMESPACE_PROSE`].
/// Every row is a **verbatim line from one of those corpora**, not a
/// constructed one, because a constructed row is easy to get wrong in
/// the direction that makes the arm vacuous: an earlier draft of this
/// table wrote `input.parse::<Token![struct]>()` without the
/// `struct_token:` label that precedes it in `syn`, and that row matches
/// neither rule in *any* version, so it would have proved nothing while
/// reading as evidence. `the_colon_only_pattern_mangled_every_one_of_
/// those_rows` is what catches that, and it caught exactly that.
///
/// The last two rows are `secret-key-assignment`'s. Without them this
/// table measures one rule of the pair and the other could be reverted
/// silently.
const VALUE_SIDE_PROSE: &[&str] = &[
    // #202's own measured rows: the headline, the second example in the
    // issue body, and the shape that dominated its count on this
    // repository's own source.
    "reassembled the token: `get_screen_state`",
    "export TOKEN={GITHUB}",
    "let cancellation_token = cancellation_token.clone();",
    // third-party Rust (`syn`) — the single largest contributor to the
    // 1,140 matches over 10.6 MiB, all of it `*_token:` struct fields.
    "pub for_token: Token![for],",
    "try_token: input.parse()?,",
    "trait_token: self.trait_token.clone(),",
    "colon2_token: &Option<Token![::]>,",
    // the Python 3.12 standard library
    "token = Token(typeid, self.address, rident)",
    "secret = bytes(password, self.encoding)",
    "proxy_passwd = unquote(proxy_passwd)",
    // this project's own source and docs
    "pub cancel_token: Option<String>,",
    "confirmation_token: token.map(str::to_string),",
    // **The backtick, as the only structural byte in the value.** Every
    // other row here would still be refused with the backtick removed
    // from the set — #202's own headline row carries `_` as well — so a
    // mutation deleting it survived until this row existed. Markdown and
    // colourised `grep` quote bare identifiers after a label constantly,
    // and this is that shape with nothing else in it.
    "the token: `getscreenstate` is reassembled",
    // `secret-key-assignment`'s half of the pair
    "pub session_key: Option<SessionKey>,",
    "master_key = config.master_key.clone()",
];

/// Credential shapes the **label-only** rules are the only thing that
/// catches — no provider prefix, no citable token format, nothing a
/// shape-keyed rule could key on. Both rules' own shipped positives are
/// in here, and the rest are constructed to span the value alphabets real
/// credentials actually use: hex, base64 with `+/=`, bcrypt's `$`, a
/// UUID, Azure's `~`, punctuation-bearing human passwords, and — the ones
/// an entropy or digit floor would drop — passphrases with no digit in
/// them at all.
const REAL_SHAPED_CREDENTIALS: &[&str] = &[
    // the two rules' own shipped positives
    "export DB_PASSWORD=hunter2hunter2",
    "api_key: 's3cr3t-value'",
    "LINODE_TOKEN=0123456789abcdef0123456789abcdef",
    "CLERK_SECRET_KEY=sk_test_0123456789abcdef01234567",
    "SECRET_KEY = 'django-insecure-0123456789abcdef'",
    "app.encryption_key: 0123456789abcdef",
    // provider tokens with no citable shape (the `group-3 walk` set)
    "VERCEL_TOKEN=Abc123XyZ456Def789Ghi012Jkl345",
    "NETLIFY_AUTH_TOKEN=nfp_aBcDeF1234567890gHiJkLmNoP",
    "DOPPLER_TOKEN=dp.st.dev.AbCdEf123456789",
    "POSTMARK_API_KEY=12345678-1234-1234-1234-123456789012",
    "TOGETHER_API_KEY=1234567890abcdef1234567890abcdef1234567890abcdef",
    "COHERE_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    "WANDB_API_KEY=0123456789abcdef0123456789abcdef01234567",
    "AZURE_CLIENT_SECRET=8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ",
    "access_token=ya29.A0ARrdaM-abcdefghijklmnop",
    "auth_token: SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ01",
    "api-key: \"sk-proj-AbCdEf1234567890\"",
    "SIGNING_KEY=k7Jd93LxQpZ2mNvB",
    "MASTER_KEY=aBcDeF1234567890GhIjKl",
    "private_key: MIIEpAIBAAKCAQEA0123456789",
    // value alphabets: base64, bcrypt, punctuation, an embedded colon
    "secret: aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=",
    "secret=abc+def/ghi=jkl123mno",
    "password=$2b$12$KIXQJ0Vx8FJ1234567890abcdefghijklmnopq",
    "password = \"Tr0ub4dor&3xyz\"",
    "password=P@ssw0rd!2024xyz",
    "MYSQL_PASSWORD=r00t:passw0rd",
    "password: <MySecretPass123>",
    "auth_token = {abcdef1234567890}",
    // no digit anywhere: a digit floor or an entropy floor drops these
    "password=correcthorsebatterystaple",
    "password=Kaefergartenstrasse",
    "api_key=abcdefghijklmnopqrstuvwx",
    "session_key: qwertyuiopasdfgh",
    // no digit *and* not one unbroken run of letters -- the two rows a
    // bare "must contain a digit" and a bare "must be alphabetic" would
    // each drop, added for GH #202's value-side half. Hyphens are not in
    // the refused set and neither is `@` or `!`.
    "MASTER_KEY=correct-horse-battery-staple",
    "password=P@ssword!Secure",
    // **The seven rows a review lane added, and the reason the refused
    // set is narrower than its first draft.** Every one is digit-free
    // *and* carries `_`, `.` or `:` — which the first draft refused, so
    // every one of them leaked in full. They are here because the first
    // thirty-four could not see the defect: none of those rows was in
    // the class the refusal can act on at all, so "drops none of the
    // thirty-four" was true by construction and measured nothing.
    //
    // Period and underscore are one-click separator options in
    // 1Password, Bitwarden, KeePassXC and xkcdpass, and EFF-wordlist
    // words carry no digit by construction, so the first two are a
    // *recommended* password shape rather than a contrived one.
    "MASTER_KEY=correct.horse.battery.staple",
    "MASTER_KEY=correct_horse_battery_staple",
    "password=my:very:secret:phrase",
    "SECRET_KEY=django.insecure.keyphrase",
    // Two vendor tokens whose prefix *guarantees* the `.`, and which
    // this rule set has no shape-keyed backstop for: a digit-free body
    // is about 1 in 68 for Vault's 24 base62 characters and 1 in 1,140
    // for Doppler's 40.
    "access_token=hvs.CAESIJxKzWqTvNbMqLdFgHjKlPoIuYtReWqAsDfGhJkL",
    "DOPPLER_TOKEN=dp.st.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh",
    // base64url: `_` is in its alphabet, `-` is too, and neither is
    // refused. `secrets.token_urlsafe()` is the standard Flask
    // `SECRET_KEY` recipe.
    "api_key=abcd_efgh_ijkl_mnopqrst",
    // **GH #245's rows: one on each side of every branch it added**, so a
    // branch that grew one byte too wide reds here rather than leaking.
    // The `::` branch is letters only: a digit, or a `!` that is not
    // opening a macro, takes a value out of it.
    "password=P::ssw0rd!",
    "password=Hunter::Two::2",
    // The field-access branch is lower-case only: a dotted vendor token
    // whose config name carries an `_` -- Doppler's default
    // `dev_personal` -- has an upper-case base62 body and stays redacted,
    // and so does a mixed-case or digit-bearing value of the same shape.
    "DOPPLER_TOKEN=dp.st.dev_personal.AbCdEfGhIjKlMnOpQrStUvWxYzAbCd",
    "SECRET_KEY=Correct.Horse_Battery",
    "api_key=abcd_efgh.ijkl2345",
    // The separator: an assignment a formatter wrapped onto the next,
    // indented line is still reached.
    "let password =\n    \"hunter2hunter2\";",
    "api_key =\r\n    's3cr3t-value'",
];

/// **The guard that keeps the two corpus-driven arms from passing on an
/// empty loop.** A review lane emptied `REAL_SHAPED_CREDENTIALS` and the
/// whole target stayed green: both arms reduce to `for row in &[] {}`
/// followed by an `is_empty()` that is vacuously true, and those two arms
/// are the entire "nothing was traded" half of GH #202 — the security
/// half. Paired with a real value-class narrowing that drops bcrypt
/// hashes and punctuation-bearing passwords, the emptied table made a
/// genuine leak ship green.
///
/// Stated as a floor rather than an equality so that **adding** a
/// credential shape is free and **removing** one is a decision somebody
/// has to write down.
fn not_vacuous(corpus: &[&str], floor: usize, name: &str) {
    assert!(
        corpus.len() >= floor,
        "`{name}` has {} rows and this target needs at least {floor}: below that \
         the arms it feeds are vacuously true and a value-class narrowing that \
         drops a real credential passes them. Raise the floor deliberately if \
         a row genuinely has to go.",
        corpus.len()
    );
}

fn builtin() -> RuleSet {
    RuleSet::builtin().expect("the vendored rule set must compile")
}

fn pre_fix() -> RuleSet {
    RuleSet::builtin_with_extra(PRE_FIX_RULES).expect("the pre-fix rule set must compile")
}

/// `main` between GH #202's two halves — see [`COLON_ONLY_RULES`].
fn colon_only() -> RuleSet {
    RuleSet::builtin_with_extra(COLON_ONLY_RULES).expect("the colon-only rule set must compile")
}

/// The names of the rules that produced a span, in span order.
fn hits(rules: &RuleSet, text: &str) -> Vec<String> {
    find_spans(rules, text.as_bytes(), 0)
        .into_iter()
        .map(|s| rules.rules[s.rule].name.clone())
        .collect()
}

// ------------------------------------------------------------ Part 1: prose

/// The fix itself: a namespace path is not an assignment.
#[test]
fn a_namespace_path_is_not_an_assignment() {
    not_vacuous(NAMESPACE_PROSE, 10, "NAMESPACE_PROSE");
    let rules = builtin();
    let mut mangled = Vec::new();
    for row in NAMESPACE_PROSE {
        let out = redact_str(&rules, row);
        if out != *row {
            mangled.push(format!("{row:?}\n  -> {out:?} by {:?}", hits(&rules, row)));
        }
    }
    assert!(
        mangled.is_empty(),
        "{} of {} prose rows came back altered:\n{}",
        mangled.len(),
        NAMESPACE_PROSE.len(),
        mangled.join("\n")
    );
}

/// **Control for the arm above.** Every one of those rows *was* redacted
/// by the pattern that shipped through 0.0.7 — so the arm above is
/// measuring a change and not an empty rule set.
#[test]
fn the_pre_fix_pattern_mangled_every_one_of_those_prose_rows() {
    not_vacuous(NAMESPACE_PROSE, 10, "NAMESPACE_PROSE");
    let rules = pre_fix();
    let mut survived = Vec::new();
    for row in NAMESPACE_PROSE {
        if redact_str(&rules, row) == *row {
            survived.push(*row);
        }
    }
    assert!(
        survived.is_empty(),
        "{} prose rows were already clean before the fix, so they prove nothing about it:\n{:#?}",
        survived.len(),
        survived
    );
}

// -------------------------------------- Part 1b: the value-side half

/// **GH #202's other half: the label and the separator are both there,
/// and the value is still not a credential.**
///
/// `value_must_not_match` refuses a value that carries no digit *and*
/// carries one of the bytes that make source-code or markup structure.
#[test]
fn a_structural_value_with_no_digit_in_it_is_not_a_credential() {
    not_vacuous(VALUE_SIDE_PROSE, 15, "VALUE_SIDE_PROSE");
    let rules = builtin();
    let mut mangled = Vec::new();
    for row in VALUE_SIDE_PROSE {
        let out = redact_str(&rules, row);
        if out != *row {
            mangled.push(format!("{row:?}\n  -> {out:?} by {:?}", hits(&rules, row)));
        }
    }
    assert!(
        mangled.is_empty(),
        "{} of {} value-side rows came back altered:\n{}",
        mangled.len(),
        VALUE_SIDE_PROSE.len(),
        mangled.join("\n")
    );
}

/// **Control for the arm above, against `main` rather than against
/// 0.0.7.** Every one of those rows was mangled by the pattern that
/// shipped *after* the colon refusal — so the arm above measures the
/// value-side half specifically, not the two halves together.
#[test]
fn the_colon_only_pattern_mangled_every_one_of_those_rows() {
    not_vacuous(VALUE_SIDE_PROSE, 15, "VALUE_SIDE_PROSE");
    let rules = colon_only();
    let mut survived = Vec::new();
    for row in VALUE_SIDE_PROSE {
        if redact_str(&rules, row) == *row {
            survived.push(*row);
        }
    }
    assert!(
        survived.is_empty(),
        "{} value-side rows were already clean before this change, so they prove \
         nothing about it — a row with no label, or with a second colon the first \
         half already caught, lands here:\n{:#?}",
        survived.len(),
        survived
    );
}

/// **Both rules of the pair are exercised by that table**, and neither
/// could be reverted without a row going red.
///
/// Without this arm `VALUE_SIDE_PROSE` could drift into fourteen rows
/// that all reach `generic-secret-assignment`, and
/// `secret-key-assignment`'s refusal could be deleted outright with the
/// whole file green.
#[test]
fn the_value_side_table_reaches_both_rules_of_the_pair() {
    let before = colon_only();
    let mut by_rule: std::collections::BTreeMap<String, usize> = Default::default();
    for row in VALUE_SIDE_PROSE {
        for name in hits(&before, row) {
            *by_rule.entry(name).or_default() += 1;
        }
    }
    for name in ["generic-secret-assignment", "secret-key-assignment"] {
        assert!(
            by_rule.get(name).copied().unwrap_or_default() > 0,
            "no row of VALUE_SIDE_PROSE reaches `{name}`, so this target cannot see \
             its refusal disappear: {by_rule:?}"
        );
    }
    eprintln!("GH #202 value-side rows by rule: {by_rule:?}");
}

// ---------------------------------------------- Part 2: nothing was traded

/// The anti-regression that matters: **a variant that drops one of these
/// is a leak.** Every row is a credential the label-only rules are the
/// only thing that catches, and every row must still come back redacted.
#[test]
fn every_credential_shape_the_label_only_rules_catch_is_still_caught() {
    not_vacuous(REAL_SHAPED_CREDENTIALS, 48, "REAL_SHAPED_CREDENTIALS");
    let rules = builtin();
    let mut lost = Vec::new();
    for row in REAL_SHAPED_CREDENTIALS {
        if redact_str(&rules, row) == *row {
            lost.push(*row);
        }
    }
    assert!(
        lost.is_empty(),
        "{} of {} real-shaped credentials are no longer redacted:\n{:#?}",
        lost.len(),
        REAL_SHAPED_CREDENTIALS.len(),
        lost
    );
}

/// The same corpus against the pre-fix rule set, asserted **equal**. This
/// is the bidirectional half GH #206 asks for and GH #194 did not need:
/// the fix must not have moved the credential set in *either* direction,
/// so a variant that redacted strictly more would fail here even though
/// it loses nothing.
#[test]
fn the_fix_moved_the_credential_set_in_neither_direction() {
    not_vacuous(REAL_SHAPED_CREDENTIALS, 48, "REAL_SHAPED_CREDENTIALS");
    let (after, before) = (builtin(), pre_fix());
    let mut differing = Vec::new();
    for row in REAL_SHAPED_CREDENTIALS {
        let (a, b) = (redact_str(&after, row), redact_str(&before, row));
        if a != b {
            differing.push(format!("{row:?}\n  before {b:?}\n  after  {a:?}"));
        }
    }
    assert!(
        differing.is_empty(),
        "{} credential rows are redacted differently than before the fix:\n{}",
        differing.len(),
        differing.join("\n")
    );
}

/// Both rules' own shipped positives are still matched **by their own
/// regex**, not merely covered by some earlier rule that happens to
/// overlap. Two rows of `REAL_SHAPED_CREDENTIALS` are masked that way and
/// both were found by attributing every row with `builtin_without`:
/// `CLERK_SECRET_KEY=sk_test_…` is also a `stripe-secret-key` match and
/// `access_token=ya29.…` is also a `gcp-oauth-token` match. A
/// pipeline-level check alone would therefore pass with
/// `secret-key-assignment` deleted outright; the other thirty rows are
/// produced by the pair and nothing else.
#[test]
fn each_label_keyed_rule_still_matches_its_own_positives_itself() {
    let rules = builtin();
    let mut lost = Vec::new();
    for rule in rules
        .rules
        .iter()
        .filter(|r| r.name.ends_with("-assignment"))
    {
        assert!(
            !rule.positive.is_empty(),
            "`{}` ships no positive example",
            rule.name
        );
        for positive in &rule.positive {
            if !rule.regex.is_match(positive.as_bytes()) {
                lost.push(format!("`{}` no longer matches {positive:?}", rule.name));
            }
        }
    }
    assert!(lost.is_empty(), "{}", lost.join("\n"));
}

/// **F2: the eight-byte value floor, pinned from both sides.**
///
/// This change rewrote `{8,}` as `[first-byte]{7,}`, which is exactly the
/// shape an off-by-one hides in — and a review lane showed the floor was
/// held by a *single* string in the whole workspace, `export
/// TOKEN={GITHUB}` (value `{GITHUB}`, eight bytes) inside
/// [`the_issues_headline_row_is_still_redacted`]. That row exists to
/// record an open bug and is meant to be rewritten the day somebody
/// closes it, so the floor was resting on a row nobody is asked to keep.
/// With that one string removed, a minimum of **nine** passed the whole
/// target, `redaction_sweep` and the lib fixtures: every exactly-eight-
/// character credential would have stopped being redacted silently.
///
/// Both directions, because a floor asserted from one side is satisfied
/// by "redact everything" or by "redact nothing" depending which side.
#[test]
fn the_eight_byte_value_floor_is_pinned_from_both_sides() {
    let rules = builtin();
    for (text, value_len) in [
        ("export APP_PASSWORD=hunter22", 8),
        ("api_key: 12345678", 8),
        ("SIGNING_KEY=abcdefgh", 8),
    ] {
        assert_ne!(
            redact_str(&rules, text),
            text,
            "a {value_len}-byte value is at the floor and must be redacted: {text:?}"
        );
    }
    for (text, value_len) in [
        ("export APP_PASSWORD=hunter2", 7),
        ("api_key: 1234567", 7),
        ("SIGNING_KEY=abcdefg", 7),
    ] {
        assert_eq!(
            redact_str(&rules, text),
            text,
            "a {value_len}-byte value is below the floor and must not be redacted: {text:?}"
        );
    }
}

// -------------------------------------------- Part 3: the limitation, named

/// **REQ-TST-006, as an explicit "this is the limitation" assertion.**
///
/// The fix buys its false-positive reduction with exactly one class of
/// false negative: **a credential whose own first byte is `:`, however it
/// is quoted or spaced.** An earlier draft of this comment said "written
/// directly against the separator" and gave `password=:hunter2hunter2` as
/// the case, which a review lane showed reads narrower than the class is:
/// `["']?` consumes an opening quote, `\s*` consumes a whitespace run
/// including a newline, so the JSON and YAML spellings are the same
/// residual and a reader would have concluded they were still covered.
/// All four spellings are asserted below so the class is the fixture.
///
/// No provider mints such a credential, no shipped fixture contains one,
/// and no row of `REAL_SHAPED_CREDENTIALS` is one — but the class is real
/// and is recorded here rather than left to be rediscovered. If somebody
/// closes it, these rows go red and say so.
#[test]
fn a_credential_whose_first_byte_is_a_colon_is_the_documented_limitation() {
    let (rules, before) = (builtin(), pre_fix());
    for spelling in [
        "password=:hunter2hunter2",          // directly against the separator
        "password = :hunter2hunter2",        // a whitespace run
        r#"{"password":":hunter2hunter2"}"#, // JSON: the quote is consumed first
        "password:\n  :hunter2hunter2",      // YAML: `\s*` eats the newline
    ] {
        assert_eq!(
            redact_str(&rules, spelling),
            spelling,
            "GH #202's residual closed for {spelling:?} — update this row rather \
             than deleting it"
        );
        // And it is a residual, not the status quo: the pre-fix pattern
        // redacted every one of these spellings.
        assert_ne!(
            redact_str(&before, spelling),
            spelling,
            "the pre-fix pattern must redact {spelling:?}, or this is not a residual"
        );
    }

    // The paired arm, without which the assertions above pass against a
    // rule set that matches nothing: one byte later in the value and the
    // same text is redacted.
    let caught = "password=x:hunter2hunter2";
    assert_ne!(
        redact_str(&rules, caught),
        caught,
        "a colon *inside* the value must still be redacted — the fix was \
         supposed to constrain the first byte only"
    );
}

/// **The half of GH #202 this change does not close, measured rather
/// than implied.**
///
/// The issue's own headline row is a plain `label: value`: there is no
/// second colon for the fix to key on, and the value `` `get_screen_state` ``
/// is still replaced by a marker. Closing it means constraining what the
/// value *contains* — a character class, a digit, an entropy floor — and
/// each of those was measured against the corpus above and drops a real
/// credential: a value class costs `password=$2b$12$…` and
/// `password=P@ssw0rd!…`, a required digit costs every one of the four
/// digit-free passphrases in `REAL_SHAPED_CREDENTIALS`.
///
/// **That reasoning was right about the two constraints it names and
/// wrong to stop there, and this row is the rewrite rather than the
/// deletion.** A required digit does cost every digit-free passphrase; a
/// value *character class* — an allowlist of bytes the value may be
/// drawn from — does cost the bcrypt hash and the punctuation-bearing
/// password. What costs neither is the **disjunction**: refuse a value
/// only when it has no digit *and* carries a structural byte. Measured
/// over the same corpora, that takes third-party Rust from 1,140
/// matches to 79 and drops **none** of `REAL_SHAPED_CREDENTIALS`,
/// including all four digit-free passphrases and both rows added with
/// it.
///
/// So the three rows below are asserted **clean**, in both directions,
/// and the residual moved rather than closing: see
/// [`a_digit_free_structural_credential_is_the_documented_limitation`].
#[test]
fn the_issues_headline_row_is_no_longer_redacted() {
    let (rules, before) = (builtin(), colon_only());
    for row in [
        "reassembled the token: `get_screen_state`",
        "export TOKEN={GITHUB}",
        "let cancellation_token = cancellation_token.clone();",
    ] {
        assert_eq!(
            redact_str(&rules, row),
            row,
            "GH #202's headline row is redacted again — this is the row the issue \
             was written about"
        );
        // And it is a change, not the status quo: `main` carried the
        // colon refusal and still mangled every one of these.
        assert_ne!(
            redact_str(&before, row),
            row,
            "the colon-only rule set must mangle {row:?}, or this arm measures nothing"
        );
    }
}

/// **REQ-TST-006 for the value-side half: what it buys the reduction
/// with.**
///
/// A credential that carries **no digit and one of the refused bytes**
/// — `api_key=alpha(bravo)charlie`, `SECRET_KEY=[bracketed-secret]` — is
/// no longer redacted. No provider mints one: the refused set is
/// precisely the bytes absent from every credential alphabet walked
/// (base64, base64url, base62, base58, hex, crypt radix-64, UUID, PEM,
/// Azure's `~`), so only a password generator running with symbols on
/// and digits off can produce one.
///
/// **An earlier draft of this test asserted `password=my.pass.phrase`
/// and `SECRET_KEY=a_b_c_d_e_f_g_h` here, and that was the defect rather
/// than the limitation.** `.` and `_` were in the refused set, so a
/// dot- or underscore-separated diceware passphrase — a *recommended*
/// password shape, offered as a one-click separator by 1Password,
/// Bitwarden, KeePassXC and xkcdpass — leaked in full, along with
/// HashiCorp Vault and Doppler tokens whose prefixes guarantee the `.`.
/// Both rows are now in [`REAL_SHAPED_CREDENTIALS`] and redacted. The
/// residual below is what is left after taking `_`, `.` and `:` back
/// out.
///
/// **Each row is paired with the same value carrying one digit**, which
/// must still be redacted. Without that pairing every assertion here is
/// satisfied by a rule set that matches nothing at all — which is
/// exactly the failure the `not_vacuous` floor exists for elsewhere in
/// this file.
#[test]
fn a_digit_free_structural_credential_is_the_documented_limitation() {
    let (rules, before) = (builtin(), colon_only());
    for (missed, caught) in [
        ("api_key=alpha(bravo)charlie", "api_key=alpha(bravo1charlie"),
        (
            "auth_token=<placeholder-value>",
            "auth_token=<placeholder-1>",
        ),
        ("password=my{pass}phrase", "password=my{pass}phrase1"),
        ("SECRET_KEY=[bracketed-secret]", "SECRET_KEY=[bracketed-1]"),
        ("auth_token=alpha|bravo|charlie", "auth_token=alpha|bravo|1"),
    ] {
        assert_eq!(
            redact_str(&rules, missed),
            missed,
            "GH #202's value-side residual closed for {missed:?} — update this row \
             rather than deleting it"
        );
        assert_ne!(
            redact_str(&before, missed),
            missed,
            "the colon-only rule set must redact {missed:?}, or this is not a residual"
        );
        assert_ne!(
            redact_str(&rules, caught),
            caught,
            "one digit must be enough to bring the value back: {caught:?}"
        );
    }

    // The other half of the class, stated as its own pairing: a value
    // with no digit and **no** structural byte is untouched, however
    // long or short. This is what keeps the refusal from collapsing into
    // the bare digit requirement the comment above rejected.
    for passphrase in [
        "password=correcthorsebatterystaple",
        "MASTER_KEY=correct-horse-battery-staple",
        "MASTER_KEY=correct.horse.battery.staple",
        "MASTER_KEY=correct_horse_battery_staple",
        "password=my:very:secret:phrase",
        "password=P@ssword!Secure",
        "api_key=abcdefgh",
    ] {
        assert_ne!(
            redact_str(&rules, passphrase),
            passphrase,
            "a digit-free value with no structural byte must still be redacted: \
             {passphrase:?}"
        );
    }
}

/// **What the refusal still gets wrong, from the other side: a bare
/// alphabetic value.**
///
/// The residual on this project's own docs after the change is almost
/// entirely `secret: SecretBytes`-shaped — a struct field whose value is
/// one unbroken run of letters. It carries no digit and no structural
/// byte, so the refusal admits it and the marker still lands on prose.
///
/// **That is not an oversight; it is the price of
/// `password=correcthorsebatterystaple`.** A digit-free run of letters
/// after a credential label is exactly a passphrase, and nothing in the
/// value distinguishes the two — the rule set has no dictionary and a
/// diceware passphrase *is* dictionary words, so it could not use one.
/// Recording the residual at its measured value is what stops a later
/// reader concluding the label-keyed rules stopped firing on prose
/// altogether.
#[test]
fn a_bare_alphabetic_value_is_the_residual_false_positive() {
    let rules = builtin();
    for row in [
        "Secret { secret: SecretBytes, done: oneshot::Sender },",
        "let api_key = ApiKeyMaterial;",
    ] {
        assert_ne!(
            redact_str(&rules, row),
            row,
            "the bare-alphabetic residual closed for {row:?} — if a later change \
             separates a passphrase from an identifier, rewrite this row and say \
             how rather than deleting it"
        );
    }
    // Paired, so the row is not satisfied by "redact everything": one
    // structural byte in the same value and it is refused.
    for row in [
        "Secret { secret: Secret<Bytes>, done: oneshot::Sender },",
        "let api_key = ApiKeyMaterial(x);",
    ] {
        assert_eq!(
            redact_str(&rules, row),
            row,
            "the same value with a refused byte must be refused: {row:?}"
        );
    }
}

/// **The refusal is honoured by §4.1's holdback, and that is not
/// cosmetic — the version that was not would leak.**
///
/// `PrefixIndex::earliest_partial` stops holding a candidate back once
/// the rule's anchored form sees a whole match, on the ground that
/// `find_spans` has already redacted it. A refused value breaks that
/// ground: the pattern matches, `find_spans` declines, and the bytes go
/// out raw — **while the value is still growing**. `API_KEY=abcdefgh`
/// at the buffer head is refused today and is `abcdefgh9` one byte
/// later, a credential whose first eight bytes the agent already has.
///
/// So the scan asks `CompiledRule::anchored_whole_match`, which re-runs
/// the refusal. The arm below drives the real pipeline at the buffer
/// tail: the refused value is **held back**, not released, and the
/// control shows the same read releasing it when the value is
/// credential-shaped.
#[test]
fn a_refused_value_at_the_buffer_tail_is_held_back_rather_than_released() {
    let p = OutputProcessor::builtin().unwrap();

    // Refused: no digit, and `(` in it. One more byte could make it a
    // credential, so the read must not hand it over.
    let growing = "$ echo API_KEY=abcd(efgh";
    let r = read(&p, growing.as_bytes());
    assert!(
        r.held_back,
        "a refused value at the head must stay in flight, not be released: \
         output={:?}",
        r.output
    );
    assert!(
        !r.output.contains("abcd(efgh"),
        "the in-flight value reached the caller anyway: {:?}",
        r.output
    );

    // The growth this protects against: one digit later the same bytes
    // are a credential, and the marker covers the whole value rather
    // than the one byte that arrived last.
    let grown = format!("{growing}9\n");
    let r = read(&p, grown.as_bytes());
    assert!(
        !r.held_back && r.output.contains("[REDACTED:generic]") && !r.output.contains("abcd(efgh"),
        "the grown value must come back as one marker: held_back={} output={:?}",
        r.held_back,
        r.output
    );

    // Control: terminate the refused value instead of growing it and the
    // whole line is released, unredacted. The holdback is a rate, not a
    // strand.
    let terminated = format!("{growing}\n");
    let r = read(&p, terminated.as_bytes());
    assert!(
        !r.held_back && r.output == terminated && r.redactions.is_empty(),
        "a terminated refused value must be released whole and unmarked: \
         held_back={} output={:?} redactions={:?}",
        r.held_back,
        r.output,
        r.redactions
    );
}

/// **The second cost, which the arm above is structurally blind to: at
/// the buffer tail the fix trades a marker for a *shortened read*.**
///
/// Found by a review lane, not by this file, and that is the point of
/// writing it down. Both rules carry `has_value_group`, so
/// `PrefixIndex::earliest_partial` disqualifies a candidate only when
/// `rule.anchored` can already see a whole match. A stricter value class
/// matches less often, so it disqualifies *less*, so the holdback
/// boundary moves **earlier** — never later, which is the direction that
/// would be a leak.
///
/// The effect is that an un-terminated `… secret::binding` at the head of
/// the buffer used to come back mangled and now comes back **truncated**
/// with `held_back: true`. §20.6's REQ-O-011a is what makes that a
/// shortening rather than a marker swap on a cursor read. It is a rate
/// and not a strand — the next byte outside the value class releases the
/// whole line, asserted below — but for a line the child has echoed and
/// not yet terminated it persists, and it takes `status`'s
/// `prompt.last_line` to `""` for as long as it does.
///
/// Every arm of `read_output_returns_ordinary_prose_unaltered_and_reports_nothing`
/// appends [`TAIL`], which guarantees no holdback, so nothing else here
/// can see this.
#[test]
fn at_the_buffer_tail_the_fix_withholds_where_it_used_to_mangle() {
    let after = OutputProcessor::builtin().unwrap();
    let before = OutputProcessor::new(Arc::new(pre_fix()), after.audit.clone(), after.limits);
    let line = "$ cargo test secret::binding";

    let r_before = read(&before, line.as_bytes());
    let r_after = read(&after, line.as_bytes());

    assert!(
        !r_before.held_back && r_before.output.contains("[REDACTED:generic]"),
        "the control must show the pre-fix set returning the line mangled and \
         not held back: held_back={} output={:?}",
        r_before.held_back,
        r_before.output
    );
    assert!(
        r_after.held_back && !r_after.output.contains("[REDACTED:"),
        "the fix must hold the tail back rather than mark it: held_back={} output={:?}",
        r_after.held_back,
        r_after.output
    );
    assert!(
        line.starts_with(r_after.output.as_str()),
        "the withheld read must be a prefix of the line, not a rewrite of it: {:?}",
        r_after.output
    );

    // **It is a rate, not a strand.** One byte outside the value class and
    // the whole line is released, unmangled — which is the fix working.
    let terminated = format!("{line}\n");
    let r = read(&after, terminated.as_bytes());
    assert!(
        !r.held_back && r.output == terminated && r.redactions.is_empty(),
        "a terminated line must be released whole and unredacted: held_back={} output={:?} redactions={:?}",
        r.held_back,
        r.output,
        r.redactions
    );

    eprintln!(
        "GH #202 second-order cost — untyped tail {line:?}: before held_back={} bytes={}, after held_back={} bytes={}",
        r_before.held_back,
        r_before.output.len(),
        r_after.held_back,
        r_after.output.len()
    );
}

// ------------------------------------- Part 4: what the prefilter can skip

/// The consequence GH #194 wants and GH #202 says it cannot have: on a
/// window of ordinary text the prefilter's hit set should be **empty**,
/// so `find_spans` can skip every rule regex rather than paying for one.
///
/// Measured over nine corpora for #202, `generic-secret-assignment` was
/// the rule standing between the prefilter and an empty hit set on the
/// overwhelming majority of windows that had one. This row asserts it on
/// the corpus the issue itself names — this repository's own commit
/// prose — and reports the numbers rather than only the verdict.
#[test]
fn ordinary_prose_leaves_the_prefilter_with_nothing_to_run() {
    let (after, before) = (builtin(), pre_fix());
    let window = NAMESPACE_PROSE.join("\n");

    let named_before: Vec<&str> = before
        .prefilter
        .matches(window.as_bytes())
        .into_iter()
        .map(|i| before.rules[i].name.as_str())
        .collect();
    let named_after: Vec<&str> = after
        .prefilter
        .matches(window.as_bytes())
        .into_iter()
        .map(|i| after.rules[i].name.as_str())
        .collect();

    assert_eq!(
        named_before,
        vec!["secret-key-assignment", "generic-secret-assignment"],
        "the control must show the pre-fix prefilter naming exactly the pair #202 blames"
    );
    assert!(
        named_after.is_empty(),
        "the prefilter still names {named_after:?} on a window with no assignment in it"
    );
    eprintln!(
        "GH #194/#202 — prefilter hit set over {} B of namespace prose: before {named_before:?}, after {named_after:?}",
        window.len()
    );
}

/// **And the value-side half buys GH #194's skip nothing at all, which
/// is worth asserting rather than leaving to be assumed.**
///
/// The separator half is spelled in the *pattern*, so the prefilter —
/// which is built from the patterns — stops naming the pair on a window
/// of namespace prose, and the arm above measures exactly that.
/// `value_must_not_match` is a **post-match** refusal: `find_spans` runs
/// the rule and then declines what it captured, so the prefilter still
/// names the pair on every window of `VALUE_SIDE_PROSE` and the skip
/// never fires. Measured over the same nine corpora at REQ-O-007's
/// 41,472 B window, the share of windows with an empty hit set is
/// **unchanged to the window**: third-party Rust 75.4 %, the CPython
/// stdlib 92.2 %, this project's own source 58.3 %, its docs 71.4 %,
/// this repo's `git log` 67.7 %.
///
/// The alternative that *would* move it is to put the constraint in the
/// pattern, and with no lookaround in the `regex` crate "at least eight
/// bytes and one of them a digit" needs a nine-branch union over the
/// index of the first digit — built for #202, confirmed correct, and
/// rejected for costing an order of magnitude on scan time and being
/// unreadable in a hand-edited file. This row records that the trade was
/// taken knowingly: **fewer mangled bytes, no cheaper scan.**
#[test]
fn the_value_side_half_does_not_buy_the_prefilter_a_skip() {
    let (after, before) = (builtin(), colon_only());
    let window = VALUE_SIDE_PROSE.join("\n");

    let names = |set: &RuleSet| -> Vec<String> {
        set.prefilter
            .matches(window.as_bytes())
            .into_iter()
            .map(|i| set.rules[i].name.clone())
            .collect()
    };
    let (a, b) = (names(&after), names(&before));
    assert_eq!(
        a, b,
        "the prefilter hit set moved, so `value_must_not_match` reached the \
         prefilter — it is a post-match refusal and must not"
    );
    assert!(
        a.iter().any(|n| n.ends_with("-assignment")),
        "the control is empty: this window must still name the pair, or the arm \
         above proves nothing: {a:?}"
    );
    // ...and yet nothing is redacted, which is the whole point.
    assert!(
        find_spans(&after, window.as_bytes(), 0).is_empty(),
        "the prefilter names the pair, the rules run, and nothing is redacted"
    );
    eprintln!("GH #194/#202 — value-side window still names {a:?}, redacts nothing");
}

// ---------------------------------------- Part 5: through the real surface

const TAIL: &str = "\nbuild finished in 13.72s\n";

fn read(processor: &OutputProcessor, buffer: &[u8]) -> ProcessedRead {
    let head = buffer.len() as u64;
    let scan_start = head.saturating_sub(processor.limits.partial_secret_scan_bytes as u64);
    let w = WindowSnapshot {
        window: buffer,
        window_start: 0,
        // The whole buffer is the window here, so the unvouched scan's
        // extra lookbehind (GH #195) has nowhere further back to reach.
        carry_region: buffer,
        carry_region_start: 0,
        tail_region: &buffer[scan_start as usize..],
        tail_region_start: scan_start,
        req_start: 0,
        head,
        cap_end: head,
        child_alive: true,
        bypass_holdback: false,
        front_clipped: false,
        truncated_at_tail: false,
    };
    processor.process(&w, &ReadOptions::default())
}

/// #202's own surface, not the rule's: a `read_output` of ordinary prose
/// returns it **byte-identical** and reports `redactions: {}`. The
/// rule-level arms above cannot see a pipeline that redacts on its own
/// account, and the issue was written against `read_output` rather than
/// against `find_spans`.
#[test]
fn read_output_returns_ordinary_prose_unaltered_and_reports_nothing() {
    let processor = OutputProcessor::builtin().unwrap();
    let source = format!("{}{TAIL}", NAMESPACE_PROSE.join("\n"));
    let r = read(&processor, source.as_bytes());
    assert_eq!(
        r.output, source,
        "read_output altered prose that contains no credential"
    );
    assert!(
        r.redactions.is_empty(),
        "read_output reported {:?} over prose with no credential in it",
        r.redactions
    );

    // Control: the same read against the pre-fix rule set both alters the
    // bytes and reports the count, so the arm above is not passing because
    // the read never reached the prose.
    let rules = Arc::new(pre_fix());
    let audit = processor.audit.clone();
    let before = OutputProcessor::new(rules, audit, processor.limits);
    let r = read(&before, source.as_bytes());
    assert_ne!(r.output, source, "the pre-fix read must alter the prose");
    assert_eq!(
        r.redactions.get("generic").copied().unwrap_or_default(),
        NAMESPACE_PROSE.len(),
        "the pre-fix read must report one `generic` redaction per prose row: {:?}",
        r.redactions
    );
}

/// The same, on the **value-side** corpus and against the colon-only
/// control (GH #202).
///
/// `read_output` is the surface the issue was written against, and the
/// rule-level arms above cannot see a pipeline that redacts on its own
/// account — §4.1's holdback and the normalised views both run their own
/// `find_spans`.
#[test]
fn read_output_returns_value_side_source_unaltered_and_reports_nothing() {
    let processor = OutputProcessor::builtin().unwrap();
    let source = format!("{}{TAIL}", VALUE_SIDE_PROSE.join("\n"));

    let r = read(&processor, source.as_bytes());
    assert_eq!(
        r.output, source,
        "read_output altered source that contains no credential"
    );
    assert!(
        r.redactions.is_empty(),
        "read_output reported {:?} over source with no credential in it",
        r.redactions
    );
    assert!(
        !r.held_back,
        "the value-side corpus must not be held back once terminated"
    );

    // Control: `main`'s own rules mangle every row of it.
    let before = OutputProcessor::new(
        Arc::new(colon_only()),
        processor.audit.clone(),
        processor.limits,
    );
    let r = read(&before, source.as_bytes());
    assert_ne!(
        r.output, source,
        "the colon-only read must alter the source"
    );
    assert_eq!(
        r.redactions.get("generic").copied().unwrap_or_default(),
        VALUE_SIDE_PROSE.len(),
        "the colon-only read must report one `generic` redaction per row: {:?}",
        r.redactions
    );
}

// ------------------------------------------------ Part 6: GH #245

/// **The label-keyed rules and `bearer-authorization` exactly as
/// `a81b02d` shipped them** — `\s*` after the separator, `\s+` after
/// `bearer`, and #202's one-branch refusal — and `openai-api-key` with no
/// refusal at all. Spelled out, never derived, so the control cannot move
/// with the thing it controls.
const BEFORE_245: &str = r#"
[[rule]]
name = "openai-api-key"
kind = "openai"
pattern = '''\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{24,}'''
prefixes = ["sk-", "sk-proj-", "sk-svcacct-", "sk-admin-"]
positive = ["sk-AAAABBBBCCCCDDDDEEEEFFFFGGGG"]
negative = ["sk-tiny"]

[[rule]]
name = "bearer-authorization"
kind = "bearer"
pattern = '''(?i)bearer\s+(?P<value>[A-Za-z0-9._~+/-]{20,}=*)'''
positive = ["Authorization: Bearer abcdefghijklmnopqrstuvwxyz"]
negative = ["Bearer short"]

[[rule]]
name = "secret-key-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:secret|private|encryption|signing|master|session)[_-]key\b["'\s]*[:=]\s*["']?(?P<value>[^:\s"';,)][^\s"';,)]{7,})'''
prefixes = ["secret_key", "secret-key", "private_key", "private-key", "encryption_key", "encryption-key", "signing_key", "signing-key", "master_key", "master-key", "session_key", "session-key"]
value_must_not_match = '''[^0-9]*[(<>\[\]{}|\\`][^0-9]*'''
positive = ["CLERK_SECRET_KEY=sk_test_0123456789abcdef01234567"]
negative = ["SECRET_KEY_FILE=/run/secrets/app"]

[[rule]]
name = "generic-secret-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b["'\s]*[:=]\s*["']?(?P<value>[^:\s"';,)][^\s"';,)]{7,})'''
prefixes = ["password", "passwd", "secret", "apikey", "api_key", "api-key", "accesstoken", "access_token", "access-token", "authtoken", "auth_token", "auth-token"]
value_must_not_match = '''[^0-9]*[(<>\[\]{}|\\`][^0-9]*'''
positive = ["export DB_PASSWORD=hunter2hunter2"]
negative = ["password: short"]
"#;

/// `a81b02d` for the four rules GH #245 touched — see [`BEFORE_245`].
fn before_245() -> RuleSet {
    RuleSet::builtin_with_extra(BEFORE_245).expect("the a81b02d control compiles")
}

/// **A label at the end of a line, and whatever the next line happens to
/// start with.** The dogfood pass's own shapes: the first three are
/// `rg -n` hits under a line of prose, the next three are interactive
/// transcripts — ssh's retry prompt among them, which is every failed
/// password attempt — and the last is `bearer-authorization`'s, whose
/// `\s+` crossed a line the same way. On `a81b02d` every one came back
/// with the next line's first word replaced by a marker.
const CROSS_LINE: &[&str] = &[
    "L1 the window reassembled a mid-token:\ncrates/holdfast-core/src/output/redact.rs:207:    let spans = find_spans(rules, window, 0);",
    "Set your API token:\nREADME.md:11:export FOO=bar",
    "Set your API token:\n\nREADME.md:11:export FOO=bar",
    "dev@build-01's password: \r\nPermission denied, please try again.\r\n",
    "Vault token:\r\nSuccessfully authenticated! You are now logged in.",
    "Enter your GitHub personal access token:\r\nAuthentication succeeded",
    "the header is Authorization: Bearer\ncrates/holdfast-core/src/output/redact.rs:207:",
    // A Python block under a label, verbatim from the CPython stdlib: the
    // indented line is a statement, not the label's value.
    "            if not have_password:\n                password = None",
    // `env | sort` with an empty variable: an `=` may cross only into an
    // *indented* line, and the next variable is not one.
    "API_TOKEN=\nHOME=/home/dev\nLANG=C.UTF-8",
];

/// The fix: none of those rows is altered.
#[test]
fn a_label_at_the_end_of_a_line_does_not_own_the_next_line() {
    not_vacuous(CROSS_LINE, 9, "CROSS_LINE");
    let rules = builtin();
    let mut mangled = Vec::new();
    for row in CROSS_LINE {
        let out = redact_str(&rules, row);
        if out != *row {
            mangled.push(format!("{row:?}\n  -> {out:?} by {:?}", hits(&rules, row)));
        }
    }
    assert!(
        mangled.is_empty(),
        "{} of {} cross-line rows came back altered:\n{}",
        mangled.len(),
        CROSS_LINE.len(),
        mangled.join("\n")
    );
}

/// **Control: `a81b02d` mangled every one of those rows**, and did it by
/// replacing a word that sits on the *second* line.
#[test]
fn before_gh_245_every_cross_line_row_lost_a_word_on_its_second_line() {
    not_vacuous(CROSS_LINE, 9, "CROSS_LINE");
    let rules = before_245();
    for row in CROSS_LINE {
        let spans = find_spans(&rules, row.as_bytes(), 0);
        let first_break = row.find('\n').expect("every row spans a line break");
        assert!(
            spans.iter().any(|s| s.start as usize > first_break),
            "the control must redact something past the line break in {row:?}, or \
             the row proves nothing about the separator: {spans:?}"
        );
    }
}

/// The same rows through `read_output`, the surface the issue reported —
/// and the pipeline's normalised views (GH #135) judge them too.
#[test]
fn read_output_hands_the_cross_line_rows_back_whole() {
    let processor = OutputProcessor::builtin().unwrap();
    let source = format!("{}{TAIL}", CROSS_LINE.join("\n"));
    let r = read(&processor, source.as_bytes());
    assert_eq!(r.output, source, "read_output altered a cross-line row");
    assert!(r.redactions.is_empty(), "{:?}", r.redactions);
}

/// **What the separator keeps: an assignment wrapped onto the next line.**
/// rustfmt and prettier both break `let token = "<long literal>";` after
/// the `=` and indent the literal, and a secret written into source is
/// that long. Every label-keyed rule still reaches it — one row per rule,
/// because the separator is spelled out in each of them and each could be
/// reverted alone.
#[test]
fn an_assignment_wrapped_onto_an_indented_line_is_still_redacted() {
    let rules = builtin();
    for (row, rule) in [
        (
            "let password =\n    \"hunter2hunter2\";",
            "generic-secret-assignment",
        ),
        (
            "api_key =\r\n    's3cr3t-value'",
            "generic-secret-assignment",
        ),
        (
            "SECRET_KEY =\n    'django-insecure-0123456789'",
            "secret-key-assignment",
        ),
        (
            "const aws_secret_access_key =\n  \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01\";",
            "aws-secret-access-key",
        ),
        (
            "cloudflare_api_token =\n  \"0123456789abcdefghij0123456789abcdefghij\"",
            "cloudflare-api-token",
        ),
        (
            "railway_token =\n  \"0123abcd-4567-89ef-0123-456789abcdef\"",
            "railway-token",
        ),
        (
            "powersync_token =\n  \"abcdef0123456789\"",
            "powersync-token",
        ),
        (
            "dd_api_key =\n  \"0123456789abcdef0123456789abcdef\"",
            "datadog-api-key",
        ),
    ] {
        let got = hits(&rules, row);
        assert!(
            got.iter().any(|n| n == rule),
            "`{rule}` must still reach a wrapped assignment in {row:?}: {got:?}"
        );
    }
}

/// **REQ-TST-006: what the separator gives up, stated.** A `:` never
/// crosses a line any more, so two spellings that put a real value on the
/// line after its label are no longer reached by a label-keyed rule:
///
/// * YAML's plain scalar on the line after its key, indented under it —
///   legal, and rare next to `key: value`;
/// * a credential a prompt echoes on the line after it — the same bytes
///   as ssh's retry prompt with a credential where `Permission` was, so
///   nothing in the value tells the two apart, and ssh's shape happens on
///   every failed attempt.
///
/// Each is paired with the control, under which it was redacted, and the
/// pair is closed by the `=` spelling of the same value, which still is —
/// so no arm here is satisfied by a rule set that matches nothing.
#[test]
fn a_value_on_the_line_after_a_colon_is_the_documented_limitation() {
    let (rules, before) = (builtin(), before_245());
    for missed in [
        "password:\n  hunter2hunter2hunter2",
        "Paste your token:\nhunter2hunter2hunter2",
    ] {
        assert_eq!(
            redact_str(&rules, missed),
            missed,
            "the next-line residual closed for {missed:?} — rewrite this row \
             rather than deleting it"
        );
        assert_ne!(
            redact_str(&before, missed),
            missed,
            "a81b02d must have redacted {missed:?}, or this is not a residual"
        );
    }
    let caught = "password =\n  hunter2hunter2hunter2";
    assert_ne!(redact_str(&rules, caught), caught);
}

/// **The two code shapes, verbatim from the corpora GH #245 measured**
/// (`syn`, `mio`, CPython, `rustls`). On `a81b02d` every row was redacted;
/// none carries a digit, so none is a shape #202's digit rule vouches for.
const CODE_SHAPES: &[&str] = &[
    // A `::` path.
    "pub paren_token: token::Paren,",
    "pub brace_token: token::Brace,",
    "pub bracket_token: token::Bracket,",
    "_token: mio::Token,",
    "private_key: &crate::SecretKey,",
    // A lower-case field access carrying an `_`.
    "semi_token: node.semi_token,",
    "colon_token: node.colon_token,",
    "self.add_password = self.passwd.add_password",
    "handshake_client_traffic_secret: self.client_handshake_traffic_secret,",
];

#[test]
fn the_two_code_shapes_are_not_credentials() {
    not_vacuous(CODE_SHAPES, 9, "CODE_SHAPES");
    let rules = builtin();
    let mut mangled = Vec::new();
    for row in CODE_SHAPES {
        let out = redact_str(&rules, row);
        if out != *row {
            mangled.push(format!("{row:?}\n  -> {out:?} by {:?}", hits(&rules, row)));
        }
    }
    assert!(mangled.is_empty(), "{}", mangled.join("\n"));
}

/// Control, and reach: `a81b02d` redacted every row, and the table reaches
/// both label-keyed rules, so neither's copy of the refusal can be
/// reverted without a row going red.
#[test]
fn before_gh_245_every_code_shape_was_redacted_by_both_rules_of_the_pair() {
    let before = before_245();
    let mut by_rule: std::collections::BTreeMap<String, usize> = Default::default();
    for row in CODE_SHAPES {
        let names = hits(&before, row);
        assert!(
            !names.is_empty(),
            "a81b02d left {row:?} alone, so it proves nothing"
        );
        for name in names {
            *by_rule.entry(name).or_default() += 1;
        }
    }
    for name in ["generic-secret-assignment", "secret-key-assignment"] {
        assert!(
            by_rule.get(name).copied().unwrap_or_default() > 0,
            "no row of CODE_SHAPES reaches `{name}`: {by_rule:?}"
        );
    }
}

/// **Each new branch on each rule of the pair, one row apiece.** The
/// corpora exercised the `::` branch on both rules but the field-access
/// branch only on `generic-secret-assignment`, so these four rows are
/// constructed — each is the shape of a verbatim row above, on the other
/// label — and each must be refused by exactly the rule it names. Without
/// them `secret-key-assignment`'s copy of the field-access branch could be
/// deleted and only a documented-limitation row would notice.
#[test]
fn each_new_branch_is_carried_by_both_rules_of_the_pair() {
    let (rules, before) = (builtin(), before_245());
    for (row, rule) in [
        (
            "pub brace_token: token::Brace,",
            "generic-secret-assignment",
        ),
        ("semi_token: node.semi_token,", "generic-secret-assignment"),
        ("signing_key: &crypto::SigningKey,", "secret-key-assignment"),
        (
            "signing_key: self.signing_key_pair,",
            "secret-key-assignment",
        ),
    ] {
        assert_eq!(redact_str(&rules, row), row, "{row:?} was altered");
        assert_eq!(
            hits(&before, row),
            vec![rule.to_string()],
            "the control must redact {row:?} by `{rule}` alone, or the row does not \
             pin that rule's branch"
        );
    }
}

/// **REQ-TST-006: what the two new branches give up.** A digit-free value
/// that is nothing but letters joined by `::`, and a digit-free lower-case
/// value that mixes `.` and `_`, are refused wherever they are — a human
/// could choose either. Each is paired with the same value carrying one
/// digit, which is redacted, and with the control, which redacted both.
#[test]
fn the_two_code_shapes_cost_a_digit_free_credential_of_the_same_shape() {
    let (rules, before) = (builtin(), before_245());
    for (missed, caught) in [
        ("password=Hello::World", "password=Hello::World1"),
        (
            "SECRET_KEY=correct.horse_battery",
            "SECRET_KEY=correct.horse_battery9",
        ),
    ] {
        assert_eq!(
            redact_str(&rules, missed),
            missed,
            "GH #245's residual closed for {missed:?} — rewrite this row"
        );
        assert_ne!(
            redact_str(&before, missed),
            missed,
            "not a residual: {missed:?}"
        );
        assert_ne!(
            redact_str(&rules, caught),
            caught,
            "one digit must bring {caught:?} back"
        );
    }
}

/// **The OpenSSH algorithm name is not an OpenAI key** — `ssh -G`'s own
/// lines, which list it under three keywords. The control reported each
/// as `[REDACTED:openai]`; the paired arm plants a real-shaped key on the
/// same line, which is still redacted.
#[test]
fn an_openssh_algorithm_name_is_not_an_openai_key() {
    let (rules, before) = (builtin(), before_245());
    let lines = [
        "hostkeyalgorithms sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
        "pubkeyacceptedalgorithms sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com",
        "casignaturealgorithms sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519@openssh.com",
        "HostKeyAlgorithms +sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ];
    let mut before_marked = 0usize;
    for line in lines {
        assert_eq!(redact_str(&rules, line), line, "{line:?} was altered");
        if redact_str(&before, line) != line {
            before_marked += 1;
        }
    }
    assert!(
        before_marked >= 3,
        "the control must mark the `-cert-v01` lines, or this proves nothing"
    );
    let planted = format!("{} sk-proj-AbCdEf0123456789GhIjKlMnOpQr", lines[0]);
    let out = redact_str(&rules, &planted);
    assert!(
        out.contains("[REDACTED:openai]") && !out.contains("AbCdEf0123456789"),
        "a real key beside the algorithm name must still be redacted: {out:?}"
    );
}

/// **The refusal holds at the buffer head too** (§4.1): the algorithm name
/// still arriving is withheld until the `@` that kills the rule, and is
/// then released whole and unmarked — rather than being released on the
/// ground that a marker covers it, which the refusal makes untrue.
#[test]
fn an_openssh_algorithm_name_at_the_buffer_head_is_released_whole() {
    let processor = OutputProcessor::builtin().unwrap();
    let line = "hostkeyalgorithms sk-ecdsa-sha2-nistp256-cert-v01@openssh.com\n";
    let r = read(&processor, line.as_bytes());
    assert!(
        !r.held_back && r.output == line && r.redactions.is_empty(),
        "held_back={} output={:?} redactions={:?}",
        r.held_back,
        r.output,
        r.redactions
    );
    let head = "hostkeyalgorithms sk-ecdsa-sha2-nistp256-cert-v01";
    let r = read(&processor, head.as_bytes());
    assert!(
        r.redactions.is_empty() && !r.output.contains("[REDACTED"),
        "a refused whole match must never be marked: {:?}",
        r.output
    );

    // **The arm that separates holding from releasing.** A refused whole
    // match is not the end of the question while bytes are still
    // arriving: one upper-case byte more and the same run is outside the
    // refused family and is a key. So a refused match at the head is
    // *held*, and the byte that makes it a key finds it still withheld —
    // where releasing it on the ground that it "matched" would already
    // have handed out every byte but the last.
    let growing = "export KEY=sk-ssh-abcdefghijklmnopqrstuvw";
    let r = read(&processor, growing.as_bytes());
    assert!(
        r.held_back && !r.output.contains("abcdefghijklmnop"),
        "a refused match still arriving must be held: held_back={} output={:?}",
        r.held_back,
        r.output
    );
    let grown = format!("{growing}X\n");
    let r = read(&processor, grown.as_bytes());
    assert!(
        r.output.contains("[REDACTED:openai]") && !r.output.contains("abcdefghijklmnop"),
        "one byte later it is a key and must come back as one marker: {:?}",
        r.output
    );
}
