//! Locating secrets in a byte window and replacing them with markers
//! (spec §9.2, §4.1 boundary-safe redaction).
//!
//! Spans are computed over the *expanded* window — the requested range
//! plus lookbehind and lookahead — so a secret or its context prefix that
//! straddles a cursor boundary is still found. Trimming to the requested
//! range happens afterwards, during rendering.

use super::rules::RuleSet;

/// A run of bytes to replace, in absolute buffer offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64,
    /// Index into `RuleSet::rules` — names the kind in the marker.
    pub rule: usize,
}

/// What the agent sees in place of a secret.
pub fn marker(kind: &str) -> String {
    format!("[REDACTED:{kind}]")
}

/// Find every secret span in `window`, whose first byte is at absolute
/// offset `window_start`. Spans come back sorted and non-overlapping.
pub fn find_spans(rules: &RuleSet, window: &[u8], window_start: u64) -> Vec<Span> {
    let mut spans = Vec::new();
    // The prefilter names the candidate rules in one pass; without it we
    // would run every rule regex over every window.
    for rule_idx in rules.prefilter.matches(window).into_iter() {
        let rule = &rules.rules[rule_idx];
        if rule.has_value_group {
            // Context rule: redact the value, leave `DD_API_KEY=` visible
            // so the agent can tell *what* was withheld.
            for caps in rule.regex.captures_iter(window) {
                if let Some(m) = caps.name("value") {
                    spans.push(Span {
                        start: window_start + m.start() as u64,
                        end: window_start + m.end() as u64,
                        rule: rule_idx,
                    });
                }
            }
        } else {
            for m in rule.regex.find_iter(window) {
                spans.push(Span {
                    start: window_start + m.start() as u64,
                    end: window_start + m.end() as u64,
                    rule: rule_idx,
                });
            }
        }
    }
    merge_spans(spans)
}

/// Collapse overlapping and adjacent spans into one (REQ-O-009). Two
/// spans that touch produce a single marker rather than `[REDACTED:x][REDACTED:y]`,
/// which is what makes a secret split by a cursor boundary read as one
/// redaction from both sides.
///
/// The earliest span names the kind; ties go to the earlier rule, which
/// is why rule order in the TOML is specific-first.
pub fn merge_spans(mut spans: Vec<Span>) -> Vec<Span> {
    if spans.is_empty() {
        return spans;
    }
    spans.sort_by_key(|s| (s.start, s.rule));
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        match out.last_mut() {
            Some(last) if span.start <= last.end => {
                last.end = last.end.max(span.end);
            }
            _ => out.push(span),
        }
    }
    out
}

/// Redact a standalone string: no windows, no offsets, no holdback.
///
/// This is the entry point for every non-buffer surface that §9.2 lists —
/// audit-log fields, `status.command`/`args`, `prompt.last_line`, and
/// error contexts carrying byte excerpts.
pub fn redact_str(rules: &RuleSet, text: &str) -> String {
    let bytes = text.as_bytes();
    let spans = find_spans(rules, bytes, 0);
    if spans.is_empty() {
        return text.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    for span in spans {
        let (start, end) = (span.start as usize, span.end as usize);
        out.extend_from_slice(&bytes[cursor..start]);
        out.extend_from_slice(marker(&rules.rules[span.rule].kind).as_bytes());
        cursor = end;
    }
    out.extend_from_slice(&bytes[cursor..]);
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RuleSet {
        RuleSet::builtin().unwrap()
    }

    /// The rule index of a rule named in the TOML, so a test can talk
    /// about "the datadog rule" without depending on its position.
    fn rule_index(r: &RuleSet, name: &str) -> usize {
        r.rules
            .iter()
            .position(|rule| rule.name == name)
            .unwrap_or_else(|| panic!("no rule named {name}"))
    }

    #[test]
    fn a_prefix_secret_is_found_with_absolute_offsets() {
        let r = rules();
        let window = b"echo ghp_0123456789abcdefghijABCDEFGHIJ012345 done";
        let spans = find_spans(&r, window, 1_000);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start, 1_005);
        assert_eq!(spans[0].end, 1_045);
        assert_eq!(r.rules[spans[0].rule].kind, "github");
    }

    /// The same offset arithmetic on the *other* branch of `find_spans`.
    ///
    /// `find_spans` has two arms — a context rule takes its span from the
    /// `value` capture group, a prefix rule from the whole match — and
    /// every other test in this module reaches the value arm through
    /// `redact_str`, which passes `window_start: 0`. Dropping
    /// `window_start +` from the value arm alone is therefore invisible:
    /// zero plus anything is anything. This is the arm asserted at a
    /// non-zero window start, and the label offsets are asserted too, so
    /// it also pins *which* bytes the value group covers.
    #[test]
    fn a_context_rule_reports_absolute_offsets_too() {
        let r = rules();
        //           0         1         2
        //           0123456789012345678901234567890
        let window = b"x DD_API_KEY=0123456789abcdef0123456789abcdef";
        let spans = find_spans(&r, window, 2_000);
        assert_eq!(spans.len(), 1, "the two matching rules collapse into one");
        assert_eq!(
            spans[0].start, 2_013,
            "the span starts after `DD_API_KEY=`, not at it"
        );
        assert_eq!(spans[0].end, 2_045);
        assert_eq!(r.rules[spans[0].rule].kind, "datadog");
    }

    #[test]
    fn a_context_rule_redacts_the_value_and_keeps_the_label() {
        let r = rules();
        let out = redact_str(&r, "DD_API_KEY=0123456789abcdef0123456789abcdef end");
        assert_eq!(out, "DD_API_KEY=[REDACTED:datadog] end");
    }

    #[test]
    fn redaction_removes_the_secret_and_keeps_everything_else() {
        let r = rules();
        let secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let out = redact_str(&r, &format!("before {secret} after"));
        // Both halves matter: an implementation that returned "" would
        // pass the absence check alone.
        assert!(!out.contains(secret), "the secret leaked: {out}");
        assert_eq!(out, "before [REDACTED:github] after");
    }

    #[test]
    fn text_with_no_secrets_is_returned_unchanged() {
        let r = rules();
        let text = "   Compiling clasp-core v0.0.1\n    Finished in 13.72s\n";
        assert_eq!(redact_str(&r, text), text);
    }

    #[test]
    fn multiple_secrets_on_one_line_each_get_a_marker() {
        let r = rules();
        let out = redact_str(
            &r,
            "a ghp_0123456789abcdefghijABCDEFGHIJ012345 b AKIAIOSFODNN7EXAMPLE c",
        );
        assert_eq!(out, "a [REDACTED:github] b [REDACTED:aws] c");
    }

    #[test]
    fn adjacent_spans_collapse_into_a_single_marker() {
        let merged = merge_spans(vec![
            Span {
                start: 10,
                end: 20,
                rule: 3,
            },
            Span {
                start: 20,
                end: 30,
                rule: 7,
            },
            Span {
                start: 25,
                end: 28,
                rule: 9,
            },
        ]);
        assert_eq!(
            merged,
            vec![Span {
                start: 10,
                end: 30,
                rule: 3
            }],
            "touching and contained spans become one; the earliest names the kind"
        );
    }

    #[test]
    fn disjoint_spans_are_left_alone() {
        let merged = merge_spans(vec![
            Span {
                start: 40,
                end: 50,
                rule: 1,
            },
            Span {
                start: 10,
                end: 20,
                rule: 2,
            },
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].start, 10, "output is sorted by start");
        assert_eq!(merged[1].start, 40);
    }

    /// The doc comment says "ties go to the earlier rule", and nothing
    /// coming through `find_spans` can check it: the prefilter yields rule
    /// indices in ascending order, so equal-start spans are already pushed
    /// earliest-rule-first and a stable sort keeps them that way whether
    /// or not `rule` is in the sort key. Handing `merge_spans` the reverse
    /// order is the only input that distinguishes the two.
    #[test]
    fn equal_starts_are_named_by_the_earlier_rule_whatever_order_they_arrive_in() {
        let a = Span {
            start: 100,
            end: 140,
            rule: 9,
        };
        let b = Span {
            start: 100,
            end: 140,
            rule: 2,
        };
        assert_eq!(
            merge_spans(vec![a, b]),
            vec![b],
            "the later rule was handed in first and must not name the span"
        );
        // The paired direction: already-sorted input answers the same, so
        // this is a tie-break rather than a reversal.
        assert_eq!(merge_spans(vec![b, a]), vec![b]);
    }

    #[test]
    fn overlapping_rules_produce_one_marker_named_by_the_earlier_rule() {
        // `sk-ant-…` matches both the Anthropic rule and the broader
        // OpenAI `sk-` rule. Anthropic is listed first, so it wins.
        let r = rules();
        assert!(
            rule_index(&r, "anthropic-api-key") < rule_index(&r, "openai-api-key"),
            "the TOML orders specific rules before general ones; this test \
             asserts the consequence, so it must hold at the source"
        );
        let out = redact_str(&r, "key=sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGG.");
        assert_eq!(out, "key=[REDACTED:anthropic].");
    }

    #[test]
    fn a_connection_string_keeps_its_host_and_loses_its_password() {
        let r = rules();
        let out = redact_str(
            &r,
            "psql postgresql://svc:hunter2GOESHERE@db.internal:5432/app",
        );
        assert!(!out.contains("hunter2GOESHERE"));
        assert_eq!(
            out,
            "psql postgresql://svc:[REDACTED:connection-string]@db.internal:5432/app"
        );
    }

    #[test]
    fn a_private_key_block_is_redacted_whole() {
        let r = rules();
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ==\n-----END RSA PRIVATE KEY-----";
        let out = redact_str(&r, &format!("cat id_rsa\n{pem}\ndone"));
        assert!(!out.contains("MIIEpAIBAAKCAQ=="));
        assert_eq!(out, "cat id_rsa\n[REDACTED:private-key]\ndone");
    }

    /// REQ-O-009's actual subject, and the one shape §9.2 says a fixture
    /// has to have: **the input never contains the secret in one piece.**
    ///
    /// A secret split across two reads is contiguous only in the expanded
    /// window `find_spans` is handed, which is why the window is expanded
    /// at all. Both halves alone are inert — asserted here, because that
    /// is what makes the third case a *reconstruction* rather than a
    /// third copy of `a_prefix_secret_is_found_with_absolute_offsets`.
    /// An implementation that redacted each read's own bytes and merged
    /// afterwards passes every other test in this module and fails this.
    #[test]
    fn a_secret_split_across_two_reads_is_found_in_the_joined_window() {
        let r = rules();
        let head = b"echo ghp_0123456789abcdefghij";
        let tail = b"ABCDEFGHIJ012345 done";
        assert!(
            find_spans(&r, head, 0).is_empty(),
            "the leading half is not a secret on its own"
        );
        assert!(
            find_spans(&r, tail, 0).is_empty(),
            "the trailing half is not a secret on its own"
        );

        let mut window = head.to_vec();
        window.extend_from_slice(tail);
        let spans = find_spans(&r, &window, 0);
        assert_eq!(spans.len(), 1, "the joined window carries one secret");
        assert_eq!((spans[0].start, spans[0].end), (5, 45));
        assert_eq!(r.rules[spans[0].rule].kind, "github");
    }
}
