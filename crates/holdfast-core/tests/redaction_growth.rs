//! How much a redacted read can **grow** over the raw bytes it replaced.
//!
//! A `[REDACTED:<kind>]` marker is sized by its kind, not by what it
//! covers, so a short secret comes back longer than it went in.
//! `Config::validate` caps `limits.output_buffer_bytes` and
//! `limits.resource_read_max_bytes` at a quarter of `MAX_FRAME_BYTES` on
//! the strength of that growth staying under **4x** for a buffer made
//! entirely of worst cases, and until this target the 4x rested on a
//! comment in `config.rs` that works the worst case out by hand from the
//! rule file. GH #244 changed the rule file under that comment — an empty
//! user in a connection string, three new kinds, each longer than
//! most — so the bound is measured here instead.
//!
//! **What this is and is not.** It tiles each rule's shortest match —
//! written out below, one per rule whose context is short and whose kind
//! is long, which is where growth lives — with each separator a buffer can
//! put between two of them, runs the result through `redact_str`, and
//! asserts the ratio. It is a measurement over constructed worst cases,
//! not a proof over every string: a rule added later with a shorter match
//! needs a row here, and the comment in `config.rs` should then point at
//! this file rather than re-derive it.

use holdfast_core::output::redact::redact_str;
use holdfast_core::output::rules::RuleSet;

/// The bound `Config::validate` relies on: `MAX_FRAME_BYTES / 4`.
const FRAME_HEADROOM_FACTOR: f64 = 4.0;

/// Each rule's shortest match, as far as its pattern allows: the fewest
/// context bytes and a one-byte (or minimum-length) value.
const SHORTEST: &[(&str, &str)] = &[
    // An empty user is legal since GH #244, so this is one byte shorter
    // than the `amqp://a:x@` config.rs worked from.
    ("database-connection-password", "amqp://:x@"),
    ("database-connection-password", "amqp://a:x@"),
    // The value's second branch, which takes a quote the first stops at
    // and does not run past an `@` — so it tiles with no separator. Its
    // two-byte floor is what keeps this row under `amqp://:x@`'s; the
    // next test measures the one-byte spelling it declined.
    ("database-connection-password", "amqp://:'x@"),
    ("url-userinfo-password", "ws://:x@"),
    ("mysql-cli-password", "mysql -px"),
    ("mysql-cli-password", "mysql -p'x'"),
    ("registry-login-password", "oras login -p x"),
    ("registry-login-password", "oras login -px"),
    ("basic-authorization", "authorization basic abcd"),
    ("generic-secret-assignment", "x_pwd=12345678"),
    ("secret-key-assignment", "app_key=12345678"),
    ("bearer-authorization", "bearer abcdefghijklmnopqrst"),
    ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
];

/// What can sit between two tiles: nothing, or one byte of each class the
/// value classes stop at.
const SEPARATORS: &[&str] = &["", " ", "\n", "\"", "'", ";", ","];

const TILES: usize = 64;

fn growth(rules: &RuleSet, unit: &str, sep: &str) -> f64 {
    let raw: String = std::iter::repeat_n(format!("{unit}{sep}"), TILES).collect();
    let out = redact_str(rules, &raw);
    out.len() as f64 / raw.len() as f64
}

#[test]
fn no_shortest_match_tiles_past_the_frame_headroom() {
    let rules = RuleSet::builtin().unwrap();
    let mut worst = (0.0f64, "", "");
    for (rule, unit) in SHORTEST {
        assert!(
            rules.rules.iter().any(|r| r.name == *rule),
            "`{rule}` is not shipped; drop or rename the row"
        );
        // The row is only a worst case if the rule really matches it.
        let out = redact_str(&rules, unit);
        assert!(
            out.contains("[REDACTED:"),
            "{unit:?} is not a match for `{rule}` any more, so it bounds nothing: {out:?}"
        );
        for sep in SEPARATORS {
            let g = growth(&rules, unit, sep);
            assert!(
                g <= FRAME_HEADROOM_FACTOR,
                "{unit:?} tiled with {sep:?} grows {g:.3}x, past the {FRAME_HEADROOM_FACTOR}x \
                 `Config::validate` sizes MAX_FRAME_BYTES' headroom on"
            );
            if g > worst.0 {
                worst = (g, unit, sep);
            }
        }
    }
    eprintln!(
        "worst measured growth: {:.3}x, {:?} tiled with {:?}",
        worst.0, worst.1, worst.2
    );
}

/// **Why `url-userinfo-password` redacts its whole match and not a `value`
/// group.** The same rule with a `value` group leaves `ws://:` and `@` of
/// every eight-byte tile in place and adds a marker to each; tiled with no
/// separator — which it can be, because the next `ws` starts on a word
/// boundary — that is the widest growth in the rule set. Measured, not
/// asserted in prose: the value-group spelling must grow more than the
/// shipped one *and* more than any shipped row above, or the choice the
/// rule file explains is not buying anything.
#[test]
fn the_url_rule_redacts_its_whole_match_because_a_value_group_would_grow_most() {
    let shipped = RuleSet::builtin().unwrap();
    let value_group = RuleSet::builtin_with_extra(
        r#"
[[rule]]
name = "url-userinfo-password"
kind = "url-password"
pattern = '''\b(?:https?|ftps?|ssh|git(?:\+(?:ssh|https?))?|svn(?:\+ssh)?|wss?|smtps?|imaps?|pop3s?|ldaps?|mqtts?|nats|socks(?:4a?|5h?)|rtsps?|rtmps?)://[^:@/?#\s"'`]*:(?P<value>[^/?#\s"'`]+)@'''
prefixes = ["https://x-access-token:"]
positive = ["ws://:x@"]
negative = ["ws://x"]
"#,
    )
    .unwrap();

    let as_shipped = growth(&shipped, "ws://:x@", "");
    let as_value_group = growth(&value_group, "ws://:x@", "");
    assert!(
        as_value_group > as_shipped,
        "a value group must grow more than the whole match: {as_value_group:.3}x vs {as_shipped:.3}x"
    );
    let shipped_ref = &shipped;
    let shipped_worst = SHORTEST
        .iter()
        .flat_map(|(_, unit)| {
            SEPARATORS
                .iter()
                .map(move |sep| growth(shipped_ref, unit, sep))
        })
        .fold(0.0f64, f64::max);
    assert!(
        as_value_group > shipped_worst,
        "the value-group spelling ({as_value_group:.3}x) must be past every shipped \
         worst case ({shipped_worst:.3}x), or whole-match redaction is not what keeps \
         the bound"
    );
    eprintln!(
        "url-userinfo-password tiled: whole match {as_shipped:.3}x, value group \
         {as_value_group:.3}x, shipped worst {shipped_worst:.3}x"
    );
}

/// **Why the connection string's quote-bearing branch needs two bytes.**
/// That branch (`a81b02d`'s value class, restored by review of GH #244 so
/// a password with a `'` in it is redacted again) cannot run past an
/// `@`, so `amqp://:'@` tiles back to back with no separator. With a
/// one-byte floor each ten-byte tile would keep nine bytes and gain a
/// marker — past every shipped worst case above. Measured both ways: the
/// shipped rule does not match that tile at all, and the one-byte
/// spelling grows more than anything the shipped set can.
#[test]
fn the_connection_string_quote_branch_needs_two_bytes_to_stay_inside_the_bound() {
    let shipped = RuleSet::builtin().unwrap();
    let one_byte = RuleSet::builtin_with_extra(
        r#"
[[rule]]
name = "database-connection-password"
kind = "connection-string"
pattern = '''\b(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|oracle|cockroachdb|clickhouse|snowflake|mongodb|rediss?|valkeys?|amqps?|neo4j|bolt)(?:\+[A-Za-z0-9_]+)*://[^:@/\s]*:(?P<value>[^\s"'`]+|[^@/\s]+)@'''
prefixes = ["amqp://"]
positive = ["amqp://:'@"]
negative = ["amqp://x"]
"#,
    )
    .unwrap();

    let tile = "amqp://:'@";
    assert_eq!(
        redact_str(&shipped, tile),
        tile,
        "the shipped rule must not match a one-byte quote password"
    );
    let as_one_byte = growth(&one_byte, tile, "");
    let shipped_ref = &shipped;
    let shipped_worst = SHORTEST
        .iter()
        .flat_map(|(_, unit)| {
            SEPARATORS
                .iter()
                .map(move |sep| growth(shipped_ref, unit, sep))
        })
        .fold(0.0f64, f64::max);
    assert!(
        as_one_byte > shipped_worst,
        "the one-byte spelling ({as_one_byte:.3}x) must be past every shipped worst \
         case ({shipped_worst:.3}x), or the two-byte floor is not what keeps the bound"
    );
    eprintln!(
        "connection string tiled {tile:?}: one-byte branch {as_one_byte:.3}x, shipped \
         worst {shipped_worst:.3}x"
    );
}
