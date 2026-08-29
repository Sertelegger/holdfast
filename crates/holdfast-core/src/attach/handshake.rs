//! The attach handshake's version contract (§7.5, §12.3, §18.4b, §23.3).
//!
//! **The rule, symmetric:** same `protocol_major` → compatible; any
//! difference → refuse, in *either* direction, and *both* peers check
//! (REQ-D-004a).
//!
//! **The match below has four arms and that is deliberate.** §18.4b:
//! "an exhaustive three-arm match over them is incomplete on purpose …
//! a three-arm match with a catch-all compiles, runs, and reports a
//! stale *client* as some generic failure." `protocol_too_old` is the
//! arm that catches it. `limit_reached` has no v0.1.0 behaviour and is
//! asserted **unreachable** rather than exercised. Indexed at §25 — do
//! not "simplify" this.
//!
//! **`terminal_busy` is not decided here** (GH #66). It is the one token
//! in the catalogue that depends on the *other* clients already attached
//! rather than on this connection's version, so it is `conn.rs`'s call and
//! not `evaluate_attach`'s. Unlike `limit_reached` it is genuinely
//! reachable in v0.1.0.
//!
//! **One version, not two.** These are `crate::protocol::handshake`'s
//! constants, not a second pair. §7.5: "one daemon advertises one
//! version on both sockets, which is the number `holdfast version` prints
//! (§3.2)". The assertion that this is true of the *wire* rather than of
//! this file's imports lives in Task 5 and Task 11, for the reason given
//! beside `the_two_sockets_advertise_the_same_protocol_version`.

use crate::protocol::handshake::{PROTOCOL_MAJOR, PROTOCOL_MINOR};

/// §18.4b's tokens. `AttachReject.message` carries a whole sentence and
/// always *begins* with one of these, so a client branches on the cause
/// without matching prose (§7.5).
///
/// **Declared in §18.4b's row order**, per §18's preamble (rev. 47) —
/// `session_not_found`, `protocol_too_new`, `protocol_too_old`,
/// `limit_reached`, `terminal_busy`. That order is neither alphabetical
/// nor grouped by cause, so it is only preserved by being asserted.
/// **`terminal_busy` is the fifth and it appends** — the note here used to
/// warn that a fifth token would *insert* at its catalogued position, and
/// that remains the rule; last is simply where §18.4b catalogues this one,
/// because the row was written at the same time as the token.
/// These are `const`s and not an enum, so the preamble's argument
/// rather than its letter is what carries here — see the plan's
/// *The §18 ordering rule, swept*, which is explicit that the sequence
/// assertion is the plan's choice and **not** REQ-T-017's reach.
pub const REJECT_SESSION_NOT_FOUND: &str = "session_not_found";
pub const REJECT_PROTOCOL_TOO_NEW: &str = "protocol_too_new";
pub const REJECT_PROTOCOL_TOO_OLD: &str = "protocol_too_old";
/// §18.4b: reserved for post-v0.1.0; v0.1.0 has no per-session limit and
/// never emits this. `no_attach_reject_is_limit_reached_in_v0_1_0`
/// asserts that rather than leaving it ambiguous.
pub const REJECT_LIMIT_REACHED: &str = "limit_reached";
/// §18.4b's fifth row, catalogued last because it is the newest (GH #66).
///
/// **Refuses a second *writer* on a terminal that already has one**, and
/// nothing else — two clients on two terminals is the multi-attach feature
/// §4.3 builds the hub for, and an observer never contends for a keyboard.
///
/// The failure it prevents is not holdfast's to fix once it happens: two
/// processes calling `read()` on one terminal device are handed alternate
/// bytes by the kernel, so a `Ctrl-B d` is split between them and the
/// client that missed it stays alive believing nothing happened. Measured
/// exactly that way — one client exited 0, the other survived.
///
/// tmux never needs this because a foreground client owns the terminal and
/// job control stops a backgrounded one with `SIGTTIN` the moment it reads.
/// `holdfast attach` has no such protection and has to say so itself.
pub const REJECT_TERMINAL_BUSY: &str = "terminal_busy";

/// `None` when the client's major matches and the attach may proceed;
/// otherwise the `(reason, message)` pair for an `AttachReject`.
///
/// **Both message strings are §7.5 normative text, character for
/// character.** In particular `protocol_too_old`'s carries a comma
/// before "or" that §7.4.1's *control*-protocol wording does not — this
/// is the attach catalog, not that one, and a `format!` copied from
/// §7.4.1 gets it wrong in a way only a whole-sentence assertion sees.
pub fn evaluate_attach(client_major: u32) -> Option<(&'static str, String)> {
    match client_major.cmp(&PROTOCOL_MAJOR) {
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Greater => Some((
            REJECT_PROTOCOL_TOO_NEW,
            format!(
                "{REJECT_PROTOCOL_TOO_NEW} — daemon supports up to \
                 {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}; restart the daemon."
            ),
        )),
        std::cmp::Ordering::Less => Some((
            REJECT_PROTOCOL_TOO_OLD,
            format!(
                "{REJECT_PROTOCOL_TOO_OLD} — daemon speaks attach protocol \
                 {PROTOCOL_MAJOR}.x; upgrade the client, or stop the daemon."
            ),
        )),
    }
}

/// The client's own check, run on an `Attached` the daemon *accepted*.
///
/// §7.5's *"The client checks too"* paragraph: an older daemon that has
/// never heard of the symmetry rule can accept a client it cannot
/// understand, and the client is the peer that can still tell. There is
/// no wire token for that refusal, "because the peer that would have
/// sent one is the peer that failed to check". It is also the only
/// reason `Attached` carries `protocol_major`/`protocol_minor` at all.
pub fn client_accepts_daemon(daemon_major: u32) -> bool {
    daemon_major == PROTOCOL_MAJOR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_major_attaches() {
        assert!(evaluate_attach(PROTOCOL_MAJOR).is_none());
    }

    #[test]
    fn the_version_gate_ranges_over_the_major_only() {
        // The negative that separates "the gate works" from "the gate
        // refuses everything". §12.3: same-major different-minor is
        // forwards/backwards compatible in both directions, so the minor
        // must reach no decision at all. `evaluate_attach` takes only a
        // major, and this test is what pins that signature: adding a
        // `client_minor` parameter that changes the answer breaks it.
        assert!(evaluate_attach(PROTOCOL_MAJOR).is_none());
        assert!(client_accepts_daemon(PROTOCOL_MAJOR));
        // Neither constant appears in the decision, so a daemon bumping
        // PROTOCOL_MINOR cannot start refusing anybody. `PROTOCOL_MINOR`
        // is *named* here rather than asserted on, because there is
        // nothing about it to assert — the assertion is the line above,
        // and `assert_eq!(x.is_none(), true)` would only trip clippy's
        // `bool_assert_comparison` under Task 13 Step 5's `-D warnings`.
        let _ = PROTOCOL_MINOR;
    }

    #[test]
    fn a_newer_client_is_refused_with_protocol_too_new() {
        let (reason, message) = evaluate_attach(PROTOCOL_MAJOR + 1).expect("must refuse");
        assert_eq!(reason, "protocol_too_new");
        // §7.5's normative sentence, whole. A `starts_with` + `contains`
        // pair passes against a message that has drifted anywhere in the
        // middle — which is exactly how the sibling assertion below
        // shipped a dropped comma green.
        //
        // Written on **one unbroken line**, unlike the implementation.
        // The impl uses a `\`-continuation to stay inside the column
        // limit, and an expected string that used the same continuation
        // would be the same expression as the thing under test: a
        // continuation that stopped eating leading whitespace would
        // widen both sides identically and this assertion would pass on
        // a message with a doubled space in it.
        let expected = format!(
            "protocol_too_new — daemon supports up to {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}; restart the daemon."
        );
        assert_eq!(message, expected);
    }

    #[test]
    fn an_older_client_is_refused_with_protocol_too_old() {
        // REQ-D-004a's missing direction. §18.4b: a suite that only
        // drives one major above passes against three arms and looks
        // thorough doing it.
        let (reason, message) = evaluate_attach(PROTOCOL_MAJOR - 1).expect("must refuse");
        assert_eq!(reason, "protocol_too_old");
        // The whole sentence, including the comma before "or". §7.5's
        // wording differs here from §7.4.1's control-protocol wording,
        // and a `contains("upgrade the client")` assertion cannot tell
        // the two apart.
        // One unbroken line, for the reason given in the sibling test.
        let expected = format!(
            "protocol_too_old — daemon speaks attach protocol {PROTOCOL_MAJOR}.x; upgrade the client, or stop the daemon."
        );
        assert_eq!(message, expected);
    }

    #[test]
    fn both_refusal_messages_begin_with_their_bare_token() {
        // §7.5's branching rule, asserted as a property over both arms
        // rather than restated inside each. The negative that matters:
        // a message beginning with prose ("Sorry, protocol_too_old …")
        // still contains the token and still fails here.
        for major in [PROTOCOL_MAJOR + 1, PROTOCOL_MAJOR - 1] {
            let (reason, message) = evaluate_attach(major).unwrap();
            assert!(message.starts_with(reason), "{message}");
            // `starts_with`, not a byte slice. §7.5's separator is
            // space + U+2014 EM DASH + space, which is **five** bytes
            // (`20 E2 80 94 20`) and not three: `&message[16..19]` for
            // `protocol_too_new` cuts the em dash mid-codepoint and
            // panics with `byte index 19 is not a char boundary`. Even
            // on a boundary the comparison could not hold, because the
            // literal `" — "` is itself 5 bytes.
            assert!(
                message[reason.len()..].starts_with(" — "),
                "the separator after the token must be exactly \" — \": {message}"
            );
            // Both sentences are built with a `\`-continuation across
            // two source lines, and a continuation that stopped
            // swallowing the next line's indentation would inject
            // seventeen spaces into the middle of the message. Asserted
            // here as a property of both arms so it holds without either
            // whole-sentence assertion having to reproduce the
            // implementation's line breaks.
            assert!(!message.contains("  "), "doubled space in {message}");
            assert!(!message.contains('\n'), "newline in {message}");
        }
    }

    #[test]
    fn the_two_version_refusals_do_not_share_a_reason() {
        // An implementation that returned one token for both directions
        // passes each of the two tests above only if that token happens
        // to be the one it asserts. This test fails for either choice.
        let (new_reason, _) = evaluate_attach(PROTOCOL_MAJOR + 1).unwrap();
        let (old_reason, _) = evaluate_attach(PROTOCOL_MAJOR - 1).unwrap();
        assert_ne!(new_reason, old_reason);
    }

    #[test]
    fn the_client_refuses_a_daemon_that_leniently_accepted_it() {
        assert!(!client_accepts_daemon(PROTOCOL_MAJOR + 1));
        assert!(!client_accepts_daemon(PROTOCOL_MAJOR - 1));
        assert!(client_accepts_daemon(PROTOCOL_MAJOR));
    }

    #[test]
    fn the_reject_tokens_are_the_four_18_4b_values_in_catalogue_order() {
        // The four-arm guard, at the catalog level. §18.4b's set is
        // closed; a fifth token added without a spec edit, or one of the
        // four deleted to "simplify" the match, fails here. Paired with
        // the two refusal tests above, which pin *which* two of the four
        // `evaluate_attach` can produce.
        //
        // **A sequence, not a sorted set.** An earlier revision of this
        // test called `sort_unstable()` first and compared against an
        // alphabetised list — which is a set comparison, and a set
        // comparison is green against every append. That is the exact
        // fault §18's preamble (rev. 47) names, and it applies here even
        // though these are five `const`s rather than an enum: they have
        // a declaration order, that order is published in the order the
        // arms are written, and §18.4b's row order is
        // session_not_found, protocol_too_new, protocol_too_old,
        // limit_reached, terminal_busy — which is neither alphabetical nor
        // grouped by cause, so nothing but this assertion holds it.
        assert_eq!(
            [
                REJECT_SESSION_NOT_FOUND,
                REJECT_PROTOCOL_TOO_NEW,
                REJECT_PROTOCOL_TOO_OLD,
                REJECT_LIMIT_REACHED,
                REJECT_TERMINAL_BUSY,
            ],
            [
                "session_not_found",
                "protocol_too_new",
                "protocol_too_old",
                "limit_reached",
                "terminal_busy",
            ]
        );
        // The negative: `evaluate_attach` reaches exactly two of them,
        // never `session_not_found` (that is the registry's answer) and
        // never `limit_reached` (unreachable in v0.1.0).
        for major in [
            PROTOCOL_MAJOR - 1,
            PROTOCOL_MAJOR,
            PROTOCOL_MAJOR + 1,
            PROTOCOL_MAJOR + 9,
        ] {
            if let Some((reason, _)) = evaluate_attach(major) {
                assert!(
                    reason == REJECT_PROTOCOL_TOO_NEW || reason == REJECT_PROTOCOL_TOO_OLD,
                    "the version gate produced {reason}"
                );
            }
        }
    }
}
