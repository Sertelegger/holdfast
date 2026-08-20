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

pub mod provider;
pub mod request;

pub use provider::{
    resolve, resolve_with, ArgvProvider, ProviderError, ScriptProvider, SecretProvider,
};
pub use request::{
    buffer_notice, Adopted, CancelReason, Collision, RaisedBy, RaisedRequest, Resolution,
    SecretSlots,
};
