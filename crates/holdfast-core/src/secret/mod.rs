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

pub mod binding;
pub mod provider;
pub mod request;

/// §9.6's operator bindings. **No item here takes an agent-supplied
/// string**, which is REQ-SEC-012's structural half stated as a set of
/// signatures: `command_line` takes a session's own `command`/`args`,
/// `select` takes those plus the child's own prompt line, and `autofill`
/// takes the operator's config and a `&Session`. There is nowhere to put
/// a `prompt_text` even by accident.
pub use binding::{autofill, command_line, keychain_step_runs, select, Autofill, FellThrough};

/// **`resolve_with` and `ScriptProvider` are deliberately absent from
/// this list.** Between them they spell *"spawn this program with this
/// argument as a secret provider"*, and re-exporting them would put that
/// in the published API of the one module whose premise is that no such
/// signature exists (REQ-SEC-012's structural half). `resolve_with` is
/// `pub(crate)` in [`provider`] and `ScriptProvider` is `#[cfg(test)]`
/// there, so a release build does not contain the second one at all.
pub use provider::{resolve, ArgvProvider, ProviderError, SecretProvider};
pub use request::{
    buffer_notice, Adopted, CancelReason, Collision, RaisedBy, RaisedRequest, Resolution,
    SecretSlots, SlotTake,
};
