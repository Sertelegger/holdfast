//! Who asked for a tool call, for the §9.4 audit record.
//!
//! §9.4 records *who* read unredacted output. That fact is worth exactly
//! as much as it is hard to forge, so it is derived from the
//! control-protocol connection — which the daemon authenticated with
//! `SO_PEERCRED` before parsing a single frame — and **never** from the
//! request body.
//!
//! The alternative, an agent-supplied `surface` argument, is worse than
//! no field at all: an agent that can label its own
//! `read_output(redact: false)` as a human running `clasp logs --raw`
//! can disguise the one event the log exists to capture, and the
//! disguise reads as authoritative. There is deliberately no code path
//! from a `Request`'s params to a [`Caller`].
//!
//! Two facts, not one. The **tool** answers "what mechanism performed
//! the read"; the **caller** answers "who asked for it". A human running
//! `clasp logs --raw` and an agent calling `read_output(redact: false)`
//! both run `read_output`, and collapsing them into one string would
//! make the log unable to tell them apart.
//!
//! ## Attribution, never authorisation
//!
//! `client_kind` is **audit attribution only and must never become a
//! redaction switch.** No read path may branch on it to decide whether
//! to redact — not for the CLI, not for the bridge, not for the shim.
//! §7.5's `Attach.role` is the only field that selects raw versus
//! redacted output, and REQ-SEC-008a forbids deriving *that* from
//! `client_kind`. This value points the other way: it records what was
//! already decided. Reading it to decide anything turns an audit record
//! into an authorisation input, which is the failure REQ-SEC-018 names.
//!
//! ## How it travels
//!
//! A tokio task-local, scoped by the daemon around each tool dispatch.
//! The alternative — an extra parameter on every tool handler — cannot
//! be threaded through `#[tool]`'s generated signatures, and the audit
//! write happens deep inside the read path rather than at the boundary.
//!
//! **One rule for consumers:** read [`current`] on the task that is
//! inside the scope. `tokio::task::spawn_blocking` and `tokio::spawn` do
//! **not** inherit task-locals, so a read path that hands work to the
//! blocking pool must capture [`current`] *before* it does so and carry
//! the value in. Getting this wrong degrades to `in_process`, which is
//! visible in the log rather than silently wrong.

use crate::protocol::handshake::ClientKind;

/// The accountable party behind a tool call (§9.4).
///
/// The variant names read from this crate's point of view; the strings
/// [`Caller::as_str`] renders are §9.4's, and the two are deliberately
/// not the same. Do not "fix" the mismatch by renaming either side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// No control-protocol connection: `clasp mcp --no-daemon`, and
    /// Windows in 0.0.11. Only `clasp mcp` runs in this mode, so it is an
    /// agent — but it is recorded distinctly rather than as `shim`, so
    /// that a *missing* scope in daemon mode shows up as an anomaly
    /// instead of quietly impersonating one of the real callers.
    InProcess,
    /// The MCP shim — the agent. Recorded as `"shim"`: the handshake's
    /// own token, not this variant's name.
    Agent,
    /// A `clasp` CLI subcommand, run by a human at a terminal.
    Cli,
    /// The web-UI bridge (0.0.10). Recorded as `"ui-bridge"`, hyphen
    /// included — the handshake's spelling, not snake_case.
    UiBridge,
}

impl Caller {
    /// The only way to construct a non-default `Caller`: from the kind
    /// the peer declared in its authenticated handshake.
    pub fn from_client_kind(kind: ClientKind) -> Self {
        match kind {
            ClientKind::Shim => Self::Agent,
            ClientKind::Cli => Self::Cli,
            ClientKind::UiBridge => Self::UiBridge,
        }
    }

    /// The value recorded in §9.4's `client_kind` field:
    /// `"shim" | "cli" | "ui-bridge" | "in_process"`.
    ///
    /// The first three are the handshake tokens carried **verbatim**,
    /// hyphen included, so that one actor has one name across
    /// `redaction_disabled`, `attach_connect` and `attach_disconnect`
    /// and a log consumer can join on the column with no mapping table.
    /// `"shim"` reads worse than `"agent"` in isolation and is still
    /// what ships: the rename was proposed and rejected, because it puts
    /// two names for one actor in one log. `in_process` is the one value
    /// in the log's own snake_case, because it is the one value that is
    /// *not* a handshake token — it means no control-protocol connection
    /// existed, and it is spelled apart on purpose so that a missing
    /// caller context in daemon mode reads as an anomaly.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::Agent => "shim",
            Self::Cli => "cli",
            Self::UiBridge => "ui-bridge",
        }
    }
}

tokio::task_local! {
    static CALLER: Caller;
}

/// Run `fut` with `caller` recorded as the accountable party.
pub async fn with_caller<F>(caller: Caller, fut: F) -> F::Output
where
    F: std::future::Future,
{
    CALLER.scope(caller, fut).await
}

/// The caller for the current task, or [`Caller::InProcess`] outside any
/// scope.
pub fn current() -> Caller {
    CALLER.try_with(|c| *c).unwrap_or(Caller::InProcess)
}

/// The pair §9.4 records for a read that disabled redaction.
///
/// `tool` is `&'static str` on purpose: it names a handler in this
/// binary, so it can only ever come from a string literal at the call
/// site, never from a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSurface {
    /// The tool that performed the read — the mechanism.
    pub tool: &'static str,
    /// Who asked for it — the accountability.
    pub client_kind: &'static str,
}

/// Build the §9.4 surface for `tool`, taking the caller from the
/// connection context rather than from anything the caller sent.
pub fn audit_surface(tool: &'static str) -> AuditSurface {
    AuditSurface {
        tool,
        client_kind: current().as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_kinds_map_onto_distinct_accountable_parties() {
        assert_eq!(Caller::from_client_kind(ClientKind::Shim), Caller::Agent);
        assert_eq!(Caller::from_client_kind(ClientKind::Cli), Caller::Cli);
        assert_eq!(
            Caller::from_client_kind(ClientKind::UiBridge),
            Caller::UiBridge
        );
        // Pinned literally, because the mutation this kills is a
        // *rename*: `shim` → `agent` and `ui-bridge` → `ui_bridge` both
        // read better in isolation and both break §9.4's join across
        // `redaction_disabled`, `attach_connect` and `attach_disconnect`
        // by giving one actor two names. `in_process` is snake_case
        // because it alone is not a handshake token.
        assert_eq!(Caller::Agent.as_str(), "shim");
        assert_eq!(Caller::Cli.as_str(), "cli");
        assert_eq!(Caller::UiBridge.as_str(), "ui-bridge");
        assert_eq!(Caller::InProcess.as_str(), "in_process");
        // The negative the literals above do not give on their own: a
        // table that rendered every variant as the same string would
        // satisfy "the spelling is a handshake token" and still lose the
        // one distinction the field exists to make.
        assert_ne!(Caller::Agent.as_str(), Caller::Cli.as_str());
    }

    #[tokio::test]
    async fn the_caller_is_visible_inside_the_scope_and_not_outside_it() {
        assert_eq!(current(), Caller::InProcess, "no scope means in-process");
        let seen = with_caller(Caller::Cli, async { current() }).await;
        assert_eq!(seen, Caller::Cli);
        assert_eq!(
            current(),
            Caller::InProcess,
            "the scope must not outlive the call"
        );
    }

    #[tokio::test]
    async fn the_scope_reaches_synchronous_code_called_from_within_it() {
        // The audit write happens deep inside the read path, in ordinary
        // synchronous code, not at the async boundary.
        fn deep() -> AuditSurface {
            audit_surface("read_output")
        }
        let s = with_caller(Caller::Agent, async { deep() }).await;
        assert_eq!(s.tool, "read_output");
        assert_eq!(s.client_kind, "shim");
    }

    #[tokio::test]
    async fn concurrent_callers_do_not_leak_into_each_other() {
        // Two connections are served by two tasks. A task-local that
        // leaked would let a CLI read be recorded as an agent's.
        let (a, b) = tokio::join!(
            with_caller(Caller::Cli, async {
                tokio::task::yield_now().await;
                current()
            }),
            with_caller(Caller::Agent, async {
                tokio::task::yield_now().await;
                current()
            })
        );
        assert_eq!(a, Caller::Cli);
        assert_eq!(b, Caller::Agent);
    }

    #[test]
    fn the_audit_surface_records_both_the_tool_and_the_caller() {
        let s = audit_surface("read_output");
        assert_eq!(s.tool, "read_output");
        assert_eq!(s.client_kind, "in_process");
    }
}
