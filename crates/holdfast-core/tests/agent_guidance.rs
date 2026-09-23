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
use holdfast_core::mcp::HoldfastServer;

fn description(tool: rmcp::model::Tool) -> String {
    tool.description
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// **GH #242, the explanation half.** `[REDACTED:unresolved]` names no
/// rule and means the opposite of every other marker — nothing matched,
/// and the read could not vouch for the bytes — and agents were told
/// nothing about it, so they read it as *a secret was here*. On this
/// repository's own CHANGELOG it covered whole sections of ordinary prose.
///
/// Each needle is a separate thing the agent has to be able to act on:
/// what the marker is (and that it is not a rule's), that a larger read
/// may clear it, the audited way to the raw text, and that `redactions` is
/// how a real marker is told from one that was already in the text.
#[test]
fn read_output_explains_the_unresolved_marker_and_the_audited_way_past_it() {
    let d = description(HoldfastServer::read_output_tool_attr());
    for needle in [
        "[REDACTED:unresolved]",
        "no rule matched",
        "larger `max_bytes`",
        "`redact: false`",
        "audit log",
        "`redactions` counts only the markers this response substituted",
    ] {
        assert!(
            d.contains(needle),
            "read_output's advertised description dropped {needle:?}:\n{d}"
        );
    }
}

/// **GH #230's second half.** The password-prompt rule lived only at the
/// end of the server instructions, past Claude Code's cut, and
/// `send_input`'s own description was *"Send keystrokes to a session's
/// stdin."* — so nothing an agent actually received told it not to type a
/// password here. The instructions now lead with the rule; this is the
/// copy on the tool an agent is about to misuse.
#[test]
fn send_input_points_a_password_prompt_at_request_secret_input() {
    let d = description(HoldfastServer::send_input_tool_attr());
    for needle in ["AwaitingSecret", "request_secret_input"] {
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
    const BUDGET: usize = 2048;
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
