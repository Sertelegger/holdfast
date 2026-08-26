//! §9's secret machinery: the request the agent can ask for and can
//! never observe.
//!
//! **The binding invariant for everything under this module.** The value
//! travels client → daemon → PTY and enters no MCP response, no log and
//! no broadcast, so — §9.2, verbatim — there is *"no boundary at which a
//! redactor could run on it"*. The protections here are structural
//! rather than filtering: a type that cannot serialise
//! ([`crate::attach::secret::SecretBytes`]), a response schema with no
//! field able to hold the value, a write path that consumes, and a
//! `Drop` that zeroes. If a change here would let the agent learn a
//! secret's value, its length, or its identity beyond what it asked for,
//! the change is wrong however convenient it reads.
//!
//! `redact_str` is **not** the tool for the value. It is the tool for
//! `prompt_text`, which is an agent-supplied string and a different
//! thing entirely.

pub mod approval;
pub mod binding;
pub mod profile;
pub mod provider;
pub mod request;

/// §17.5's binding-approval lifecycle. **Nothing here can hold a value or
/// a reference** — an approval is a decision about *which* credential
/// (REQ-SEC-016), and the surface is the binding's name and provider.
pub use approval::{
    approval_window, audit_binding_approval, Approval, BindingApprovals, Decide, Decided, Outcome,
};

/// §9.6's operator bindings. **No item here takes an agent-supplied
/// string**, which is REQ-SEC-012's structural half stated as a set of
/// signatures: `command_line` takes a session's own `command`/`args`,
/// `select` takes those plus the child's own prompt line, and `autofill`
/// takes the operator's config and a `&Session`. There is nowhere to put
/// a `prompt_text` even by accident.
pub use binding::{
    autofill, autofill_approved, command_line, keychain_step_runs, select, Autofill, FellThrough,
};

/// §9.6's operator-declared session profiles (GH #46). **The operator
/// writes the command line and the agent fills named slots in it** — so
/// there is no signature here by which an agent could author a
/// credential-bearing command line, the same move that already stops it
/// *naming* a secret. [`profile::render`]'s two arguments are the
/// operator's template and the agent's values, and it returns exactly one
/// argv element per template element.
pub use profile::{render, ProfileFault, VarFault};

/// **`resolve_with` and `ScriptProvider` are deliberately absent from
/// this list.** Between them they spell *"spawn this program with this
/// argument as a secret provider"*, and re-exporting them would put that
/// in the published API of the one module whose premise is that no such
/// signature exists (REQ-SEC-012's structural half). `resolve_with` is
/// `pub(crate)` in [`provider`] and `ScriptProvider` is `#[cfg(test)]`
/// there, so a release build does not contain the second one at all.
pub use provider::{resolve, ArgvProvider, ProviderError, SecretProvider};
/// **`pub(crate)`, unlike its neighbours above, and deliberately.** Its one
/// consumer is `crate::mcp::tools`, which threads it from `snapshot` to
/// `take_if_unadopted_matching` and reads nothing out of it; there is no
/// external caller and no reason to put it in `holdfast-core`'s published
/// API. Widening it later is additive, narrowing it is not.
pub(crate) use request::SlotSnapshot;
pub use request::{
    buffer_notice, Adopted, CancelReason, Collision, RaisedBy, RaisedRequest, Resolution,
    SecretSlots, SlotTake,
};
