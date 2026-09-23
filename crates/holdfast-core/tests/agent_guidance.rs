//! What the agent is *told*, pinned where the agent reads it: the tool
//! descriptions `tools/list` carries.
//!
//! The server `instructions` are asserted beside the code that builds them
//! — `mcp::tests::assert_instructions_survive_the_client`, through
//! `get_info` on both transports — because the shim's half is private and
//! `#[cfg(unix)]`. This file is the per-tool half: when the instructions
//! have to stay short (GH #230), the detail goes into the one tool it is
//! about, and a reword that drops it would otherwise go unnoticed.
//!
//! Descriptions keep their source line breaks on the wire, so every
//! needle is matched against whitespace-collapsed text.

use holdfast_core::mcp::passthrough;
use holdfast_core::mcp::{HoldfastServer, CLIENT_INSTRUCTIONS_BUDGET};

fn description(tool: rmcp::model::Tool) -> String {
    tool.description
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// **GH #242, the explanation half.** `[REDACTED:unresolved]` names no
/// rule, and agents were told nothing about it, so they read it as *a
/// secret was here*. On this repository's own CHANGELOG it covered whole
/// sections of ordinary prose.
///
/// Each needle is a separate thing the agent has to be able to act on:
/// what the marker is; that it can nonetheless hide a real secret,
/// including one a rule matched; that a re-read is **not** a guaranteed
/// way past it; what `redact: false` returns, that it is audited, and
/// when it may be used; and that `redactions` is how a real marker is
/// told from one that was already in the text.
///
/// **The caveat is pinned because the first draft said the opposite.** It
/// read *"no rule matched those bytes. … It is often ordinary text. … The
/// reliable way to the text is `redact: false`"*, and the review drove it
/// against the code: an unterminated private-key header, then a GitHub
/// token a few lines on, came back as one `[REDACTED:unresolved]` with
/// `redactions: {unresolved: 1}` and no `github` count, because
/// `output::redact::merge_spans` folds a real match that meets an
/// unjudgeable region into the one marker (pinned on the read path by
/// `output::tests::an_unresolved_mask_that_meets_a_real_match_is_one_marker_and_the_weaker_kind`).
/// An agent following that text re-reads with `redact: false` and pulls
/// a live credential into its context believing nothing matched.
///
/// The re-read needle is a promise *not* made, and it is pinned for that
/// reason. `output/mod.rs` records that a larger `max_bytes` "is **not** a
/// general recourse" and that protection is non-monotonic in it — a read
/// that reaches `buffer.head` takes a branch `max_bytes` cannot move — so
/// a description telling the agent a bigger read resolves the marker
/// would send it round a loop that ends at `redact: false` anyway.
#[test]
fn read_output_explains_the_unresolved_marker_and_the_audited_way_past_it() {
    let d = description(HoldfastServer::read_output_tool_attr());
    for needle in [
        "`[REDACTED:unresolved]` is different: it covers bytes this read could not vouch for",
        "it can hide a real secret",
        "or one a rule did match inside the region, which is then counted as `unresolved`",
        "neither is guaranteed",
        "`redact: false` returns the raw text, any secret in it included",
        "audit log",
        "use it only when you already know the region is not a credential",
        "`redactions` counts only the markers this response substituted",
    ] {
        assert!(
            d.contains(needle),
            "read_output's advertised description dropped {needle:?}:\n{d}"
        );
    }
}

/// What no tool description may say about `[REDACTED:unresolved]`,
/// compared case-insensitively: that nothing matched the bytes under it.
/// See the row above for why that is false, and what it costs.
///
/// Every tool rather than `read_output` alone, because the claim is the
/// one a writer reaches for — §9.2 of the spec and `redact.rs`'s own
/// `UNRESOLVED_KIND` doc both put it that way — and `wait_for_pattern`,
/// `send_input` and `get_screen_state` all return redacted text. The
/// server instructions are held to the same list by
/// `mcp::tests::assert_instructions_survive_the_client`, which this
/// copies because an integration test cannot see a `#[cfg(test)]` item.
#[test]
fn no_tool_description_calls_the_unresolved_marker_unmatched() {
    const FALSE_UNRESOLVED_CLAIMS: [&str; 2] = ["no rule matched", "nothing matched"];
    let tools = passthrough::tool_manifest();
    assert!(tools.len() >= 12, "the router lost tools");
    for tool in tools {
        let name = tool.name.to_string();
        let d = description(tool).to_lowercase();
        for claim in FALSE_UNRESOLVED_CLAIMS {
            assert!(
                !d.contains(claim),
                "`{name}`'s description says {claim:?}, which is false of \
                 `[REDACTED:unresolved]` when a real match was folded into it:\n{d}"
            );
        }
    }
}

/// **What the old instructions said about `wait_for_pattern`, now on the
/// tool itself.** GH #230's rewrite cut the instructions to what an agent
/// must not miss and moved per-tool detail to the tool it is about. These
/// three were only ever in the instructions: that a pattern-less wait
/// ends promptly for the three non-`Executing` modes, that
/// `prompt.reason` separates a measured prompt from a guessed one, and
/// that an unmatched wait at a measured prompt says so in `warning`.
///
/// *Promptly* rather than *at once*: GH #248 holds a `Fullscreen` or
/// `AwaitingSecret` already showing at the first sample for the settle
/// window, in case it predates the write the wait follows.
#[test]
fn wait_for_pattern_carries_what_the_instructions_used_to_say_about_it() {
    let d = description(HoldfastServer::wait_for_pattern_tool_attr());
    for needle in [
        "`Fullscreen`, `AwaitingSecret` and `Exited` come back promptly rather than at the deadline",
        "`prompt.reason`",
        "`warning`",
    ] {
        assert!(
            d.contains(needle),
            "wait_for_pattern's advertised description dropped {needle:?}:\n{d}"
        );
    }
}

/// **GH #230's second half.** The password-prompt rule lived only at the
/// end of the server instructions, past Claude Code's cut, and
/// `send_input`'s own description was *"Send keystrokes to a session's
/// stdin."* — so nothing an agent actually received told it not to type a
/// password here. The instructions now lead with the rule; this is the
/// copy on the tool an agent is about to misuse.
///
/// **The needle is the prohibition, not its vocabulary.** It used to be
/// `AwaitingSecret` and `request_secret_input` separately, and the review
/// rewrote the paragraph as *"Also for a password: when interaction_mode
/// is AwaitingSecret, type it here directly; request_secret_input is only
/// needed when no agent knows the value"* — both words present, the rule
/// inverted, every row green.
#[test]
fn send_input_points_a_password_prompt_at_request_secret_input() {
    let d = description(HoldfastServer::send_input_tool_attr());
    for needle in [
        "Not for a password: when `interaction_mode` is `AwaitingSecret`, use `request_secret_input`",
        "never passes through you",
    ] {
        assert!(
            d.contains(needle),
            "send_input's advertised description dropped {needle:?}, which is what \
             sends a password prompt somewhere other than here:\n{d}"
        );
    }
}

/// **A guard, and a hedged one.** The knob that sets Claude Code's cut on
/// server instructions is named `CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH`,
/// and 2.1.280 counts the tool descriptions that exceed it in its
/// `tengu_mcp_tools_listed` telemetry. Whether it also *cuts* them was
/// not established from the bundle; holding every description under the
/// same number costs nothing today and means the question never has to be
/// answered the hard way. Counted in UTF-16 units, as the client counts.
#[test]
fn every_tool_description_fits_the_same_budget() {
    const BUDGET: usize = CLIENT_INSTRUCTIONS_BUDGET;
    let tools = passthrough::tool_manifest();
    assert!(tools.len() >= 12, "the router lost tools");
    for tool in tools {
        let name = tool.name.to_string();
        let units = tool
            .description
            .as_deref()
            .unwrap_or_default()
            .encode_utf16()
            .count();
        assert!(
            units <= BUDGET,
            "`{name}`'s description is {units} UTF-16 units, over the {BUDGET} Claude Code \
             applies to MCP descriptions"
        );
    }
}
