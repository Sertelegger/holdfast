//! The connect handshake and its version contract (spec §7.4.1, §12.3,
//! §18.3a, §23.3).
//!
//! The control protocol is a declared breaking-change boundary. The
//! rule, stated once here and enforced on both peers:
//!
//! * **Same major** → compatible. Minor differences are additive-only.
//! * **Different major** → refuse to connect, in *either* direction.
//!
//! §7.4.1 states the rule symmetrically and §18.3a catalogues the two
//! `reject_reason` tokens, so a client older than the daemon is refused
//! just as a newer one is.

use serde::{Deserialize, Serialize};

/// Bumped only for a breaking wire change (§23.3).
pub const PROTOCOL_MAJOR: u32 = 1;
/// Bumped for additive changes: new methods, new optional fields.
pub const PROTOCOL_MINOR: u32 = 0;

/// How long either peer waits for the **first** frame of the handshake
/// before giving up on the connection.
///
/// The one deadline on the control protocol, and it is deliberately the
/// only one. Without it a peer that connects and sends nothing pins a
/// daemon task and a file descriptor until the daemon dies, and a daemon
/// that accepts and never replies wedges `clasp mcp` *before it can
/// answer MCP `initialize`* — an agent-visible server that never starts,
/// with no diagnostic anywhere.
///
/// **It does not extend past the handshake, and must not.** A blanket
/// client deadline would truncate a legitimate `wait_for_pattern`, which
/// is 30 s by default and 3600 s at its cap; the handshake, by contrast,
/// is one frame each way between two local processes, so five seconds is
/// four orders of magnitude of headroom rather than a tuning parameter.
///
/// The uid gate (§9.1) already establishes that any peer reaching this
/// is the same user, so this is not a defence against an attacker. It is
/// a defence against a wedged process, which is a state the `--force`
/// path in `clasp daemon stop` already exists to resolve.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Build identifier reported in the handshake. Wired to a real git SHA
/// by the release pipeline in 0.0.12; `unknown` until then.
pub fn build_id() -> &'static str {
    option_env!("HOLDFAST_BUILD_SHA").unwrap_or("unknown")
}

/// Which kind of peer is connecting (§7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKind {
    #[serde(rename = "shim")]
    Shim,
    #[serde(rename = "cli")]
    Cli,
    #[serde(rename = "ui-bridge")]
    UiBridge,
}

impl ClientKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shim => "shim",
            Self::Cli => "cli",
            Self::UiBridge => "ui-bridge",
        }
    }
}

/// `holdfast/handshake` params — client → daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakeParams {
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub client_kind: ClientKind,
    pub client_version: String,
}

impl HandshakeParams {
    /// The params this build sends.
    pub fn current(kind: ClientKind) -> Self {
        Self {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: kind,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// `holdfast/handshake` data — daemon → client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakeData {
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub daemon_version: String,
    pub build: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

/// §18.3a's two tokens. The wire carries a whole sentence, but it always
/// begins with one of these so a client can branch on the cause without
/// string-matching prose.
pub const REJECT_CLIENT_TOO_NEW: &str = "client_protocol_too_new";
pub const REJECT_CLIENT_TOO_OLD: &str = "client_protocol_too_old";

/// Decide whether to accept a peer, and build the response.
pub fn evaluate(params: &HandshakeParams) -> HandshakeData {
    let reject_reason = match params.protocol_major.cmp(&PROTOCOL_MAJOR) {
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Greater => Some(format!(
            "{REJECT_CLIENT_TOO_NEW} — daemon supports up to \
             {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}; restart the daemon."
        )),
        std::cmp::Ordering::Less => Some(format!(
            "{REJECT_CLIENT_TOO_OLD} — daemon speaks protocol \
             {PROTOCOL_MAJOR}.x; upgrade the client or stop the daemon."
        )),
    };
    HandshakeData {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        build: build_id().to_string(),
        accepted: reject_reason.is_none(),
        reject_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(major: u32, minor: u32) -> HandshakeParams {
        HandshakeParams {
            protocol_major: major,
            protocol_minor: minor,
            client_kind: ClientKind::Shim,
            client_version: "0.0.1".into(),
        }
    }

    #[test]
    fn same_major_is_accepted_and_advertises_this_builds_version() {
        let d = evaluate(&params(PROTOCOL_MAJOR, PROTOCOL_MINOR));
        assert!(d.accepted);
        assert!(d.reject_reason.is_none());
        assert_eq!(d.protocol_major, PROTOCOL_MAJOR);
        assert_eq!(d.protocol_minor, PROTOCOL_MINOR);
        assert_eq!(d.daemon_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn a_newer_minor_on_the_same_major_is_still_accepted() {
        // §7.4.1: same-major different-minor is forwards/backwards
        // compatible, because minor changes are additive only.
        let d = evaluate(&params(PROTOCOL_MAJOR, PROTOCOL_MINOR + 7));
        assert!(d.accepted, "minor skew must not refuse the connection");
        let d = evaluate(&params(PROTOCOL_MAJOR, 0));
        assert!(d.accepted);
    }

    #[test]
    fn a_newer_major_is_refused_with_the_documented_reason() {
        let d = evaluate(&params(PROTOCOL_MAJOR + 1, 0));
        assert!(!d.accepted, "§23.3: mismatched majors refuse to connect");
        let reason = d.reject_reason.expect("a refusal must say why");
        assert!(reason.starts_with(REJECT_CLIENT_TOO_NEW), "{reason}");
        assert!(
            reason.contains("restart the daemon"),
            "the reason must tell the user what to do: {reason}"
        );
    }

    #[test]
    fn an_older_major_is_refused_too() {
        // §7.4.1/§18.3a state the rule symmetrically. A daemon that only
        // checked `client > daemon` would accept this and then mis-parse
        // every subsequent frame.
        let d = evaluate(&params(PROTOCOL_MAJOR - 1, 99));
        assert!(!d.accepted);
        let reason = d.reject_reason.expect("a refusal must say why");
        assert!(reason.starts_with(REJECT_CLIENT_TOO_OLD), "{reason}");
    }

    #[test]
    fn the_reject_reason_tokens_are_the_18_3a_spellings() {
        // Every other assertion in the tree — here, in `client.rs`, and
        // in `control_protocol.rs` — compares a `reject_reason` against
        // these *constants*, and the daemon builds the reason from the
        // same constants. A typo in either `const` therefore round-trips
        // green through the whole suite and fails only against a peer
        // built from §18.3a. The **literals** are the pinning: replacing
        // them with the constants deletes the test while leaving it
        // green. Same argument, verbatim, as
        // `method_names_are_the_7_4_1_catalogue_strings` and
        // `client_kind_wire_strings_match_the_spec` below — this is the
        // one §18.3a surface the pattern had missed.
        assert_eq!(REJECT_CLIENT_TOO_NEW, "client_protocol_too_new");
        assert_eq!(REJECT_CLIENT_TOO_OLD, "client_protocol_too_old");
    }

    #[test]
    fn client_kind_wire_strings_match_the_spec() {
        for (kind, wire) in [
            (ClientKind::Shim, "\"shim\""),
            (ClientKind::Cli, "\"cli\""),
            (ClientKind::UiBridge, "\"ui-bridge\""),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), wire);
            assert_eq!(kind.as_str(), wire.trim_matches('"'));
        }
    }

    #[test]
    fn current_params_carry_this_builds_protocol_version() {
        let p = HandshakeParams::current(ClientKind::Cli);
        assert_eq!(p.protocol_major, PROTOCOL_MAJOR);
        assert_eq!(p.protocol_minor, PROTOCOL_MINOR);
        assert_eq!(p.client_kind, ClientKind::Cli);
        assert!(evaluate(&p).accepted, "we must accept ourselves");
    }
}
