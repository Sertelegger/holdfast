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
/// what the marker is — since GH #242's narrowing, mostly private-key
/// material cut short or paged through, and never a header merely
/// mentioned in prose; that it can nonetheless hide a real secret,
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
/// `output::tests::an_unresolved_mask_that_meets_a_real_match_is_one_marker_and_the_weaker_kind`,
/// which since GH #242's narrowing folds a key id inside text the
/// candidate still believes: the `github` shape now ends the candidate
/// at the token's `_`, and the token comes back `[REDACTED:github]`).
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
        // GH #242's other half (lane-read-path) made the marker mostly a
        // private key the read could not tie to a whole one — cut short,
        // or paged through — and a prose header no marker at all. The
        // description says so, or it reads as a reason to try
        // `redact: false` on a key.
        "private-key material the read could not tie to a whole key",
        "a pager's next screenful of a key",
        "A key header that is only mentioned in prose is not masked",
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

/// Every `description` an agent is shown for `tool`: the tool's own, and
/// every one inside its `inputSchema` and `outputSchema`, each with a path
/// that says where it was found.
///
/// The schemas are most of `tools/list` by size, and their descriptions
/// are this crate's doc comments, published by `schemars` — so a comment
/// written for a maintainer lands in front of the agent unless it is kept
/// out of `///`.
fn published_descriptions(tool: &rmcp::model::Tool) -> Vec<(String, String)> {
    fn walk(value: &serde_json::Value, path: String, out: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if key == "description" {
                        if let Some(text) = child.as_str() {
                            out.push((path.clone(), text.to_string()));
                        }
                    }
                    walk(child, format!("{path}.{key}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let name = tool.name.to_string();
    let mut out = Vec::new();
    if let Some(d) = tool.description.as_deref() {
        out.push((name.clone(), d.to_string()));
    }
    let input = serde_json::Value::Object(tool.input_schema.as_ref().clone());
    walk(&input, format!("{name}.inputSchema"), &mut out);
    if let Some(output) = tool.output_schema.as_ref() {
        let output = serde_json::Value::Object(output.as_ref().clone());
        walk(&output, format!("{name}.outputSchema"), &mut out);
    }
    out
}

/// **A running command's `heuristic` tier is stated where the tier is
/// described.** The detector withholds the OSC 133 and bracketed-paste
/// rungs once the shell hands the terminal to a program it started, so
/// every external command reads `Executing` / `heuristic` with the reason
/// `no deterministic signal`, in a session whose integration is working.
/// An agent told only that `semantic` means *markers* and `heuristic`
/// means *a guess* reads that as a broken integration.
///
/// Checked on every tool that publishes the `DetectionTier` definition,
/// because each carries its own copy, and at least one must.
#[test]
fn detection_tier_says_a_running_command_reads_heuristic() {
    let mut seen = 0;
    for tool in passthrough::tool_manifest() {
        let name = tool.name.to_string();
        let Some(output) = tool.output_schema.as_ref() else {
            continue;
        };
        let Some(tier) = output
            .get("$defs")
            .and_then(|d| d.get("DetectionTier"))
            .and_then(|t| t.get("description"))
            .and_then(|d| d.as_str())
        else {
            continue;
        };
        seen += 1;
        let tier = tier.split_whitespace().collect::<Vec<_>>().join(" ");
        for needle in [
            "A running command normally reads `heuristic`, even in an integrated shell",
            "once the shell hands the terminal to a program",
            "`no deterministic signal`",
            "`semantic` again at the shell's next prompt",
        ] {
            assert!(
                tier.contains(needle),
                "`{name}`'s DetectionTier description dropped {needle:?}:\n{tier}"
            );
        }
    }
    assert!(
        seen >= 7,
        "only {seen} tools publish DetectionTier; the prompt-bearing tools lost it"
    );
}

/// **What the agent is shown is prose, not source.** `wait_for_pattern`'s
/// `pattern` argument reached `tools/list` with runs of spaces, literal
/// `\"` and the name of a private function (`run_wait_for_idle`): a
/// string-continuation edit made inside a `///` comment, which rustdoc and
/// `schemars` publish byte for byte. Nothing looked at the rendered text.
///
/// Indentation at the start of a line is allowed — a Markdown list item's
/// continuation is indented on purpose — so the space check is on what
/// follows it.
#[test]
fn no_published_description_carries_source_artefacts() {
    let mut checked = 0;
    for tool in passthrough::tool_manifest() {
        for (path, text) in published_descriptions(&tool) {
            checked += 1;
            for line in text.lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "{path} has a run of spaces inside a line: {line:?}"
                );
            }
            assert!(
                !text.contains("\\\""),
                "{path} carries a literal backslash-quote: {text:?}"
            );
        }
    }
    assert!(checked > 100, "only {checked} descriptions were walked");

    let wait = HoldfastServer::wait_for_pattern_tool_attr();
    let pattern = wait
        .input_schema
        .get("properties")
        .and_then(|p| p.get("pattern"))
        .and_then(|p| p.get("description"))
        .and_then(|d| d.as_str())
        .expect("pattern has a description");
    assert!(
        !pattern.contains("run_wait_for_idle"),
        "the pattern argument names a private function again: {pattern}"
    );
}

/// `no_tool_description_calls_the_unresolved_marker_unmatched`, extended to
/// the schemas: `read_output`'s own `redactions` field told the agent that
/// `unresolved` means *nothing matched these bytes*, in the one place an
/// agent totalling the map would look, while the tool's description said
/// the opposite.
#[test]
fn no_published_schema_calls_the_unresolved_marker_unmatched() {
    const FALSE_UNRESOLVED_CLAIMS: [&str; 2] = ["no rule matched", "nothing matched"];
    for tool in passthrough::tool_manifest() {
        for (path, text) in published_descriptions(&tool) {
            let text = text
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            for claim in FALSE_UNRESOLVED_CLAIMS {
                assert!(
                    !text.contains(claim),
                    "{path} says {claim:?}, which is false of \
                     `[REDACTED:unresolved]` when a real match was folded into it:\n{text}"
                );
            }
        }
    }
}
