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
//! **One of those two is fixed here and the other is not, and the
//! difference is the whole shape of this target.** Both rules now refuse
//! a value whose first byte is another `:`: the separator is already
//! consumed by `[:=]` at that point, so a value opening on a second colon
//! means the source read `label::…` — a scope-resolution operator, not an
//! assignment. That costs no true positive, so it ships.
//! `` the token: `get_screen_state` `` has no second colon in it and is
//! **still redacted**; closing that means judging what the value
//! *contains*, and every constraint measured for #202 drops a real
//! credential with it. [`the_issues_headline_row_is_still_redacted`]
//! asserts the open half at its measured value rather than leaving the
//! reader to assume the issue was closed.
//!
//! **Why the assertions here are not vacuous.** Every arm that asserts an
//! *absence* is paired with the same input run through the **pre-fix**
//! pattern, installed by name over the built-in set through
//! [`RuleSet::builtin_with_extra`]. A rule set that stopped matching
//! anything at all would pass the absence arms and fail the controls.
//!
//! [`RuleSet::builtin_with_extra`]: holdfast_core::output::rules::RuleSet::builtin_with_extra

use std::sync::Arc;

use holdfast_core::output::redact::{find_spans, redact_str};
use holdfast_core::output::rules::RuleSet;
use holdfast_core::output::{OutputProcessor, ProcessedRead, ReadOptions, WindowSnapshot};

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

// ---------------------------------------------- Part 2: nothing was traded

/// The anti-regression that matters: **a variant that drops one of these
/// is a leak.** Every row is a credential the label-only rules are the
/// only thing that catches, and every row must still come back redacted.
#[test]
fn every_credential_shape_the_label_only_rules_catch_is_still_caught() {
    not_vacuous(REAL_SHAPED_CREDENTIALS, 32, "REAL_SHAPED_CREDENTIALS");
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
    not_vacuous(REAL_SHAPED_CREDENTIALS, 32, "REAL_SHAPED_CREDENTIALS");
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
/// digit-free passphrases in `REAL_SHAPED_CREDENTIALS`. That is a
/// security trade for a human to take, not a test to encode.
///
/// So this row asserts the residual **is still there**. When somebody
/// takes that decision it goes red, which is the point: an issue half
/// closed should not read as an issue closed.
#[test]
fn the_issues_headline_row_is_still_redacted() {
    let rules = builtin();
    for row in [
        "reassembled the token: `get_screen_state`",
        "export TOKEN={GITHUB}",
        "let cancellation_token = cancellation_token.clone();",
    ] {
        assert_ne!(
            redact_str(&rules, row),
            row,
            "GH #202's value-side half has been closed for {row:?} — update this row \
             and the rule file's comment rather than deleting it"
        );
    }
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

// ---------------------------------------- Part 5: through the real surface

const TAIL: &str = "\nbuild finished in 13.72s\n";

fn read(processor: &OutputProcessor, buffer: &[u8]) -> ProcessedRead {
    let head = buffer.len() as u64;
    let scan_start = head.saturating_sub(processor.limits.partial_secret_scan_bytes as u64);
    let w = WindowSnapshot {
        window: buffer,
        window_start: 0,
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
