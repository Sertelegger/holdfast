//! The daemon ↔ client control protocol (spec §7.4).
//!
//! This is a declared breaking-change boundary (§23.3): once shipped, a
//! shape change to any type here breaks every shim and CLI built against
//! a different major. Additive change — a new method, a new optional
//! field — is fine and does not move the major.

// **The wire types are cross-platform; the transport is not.** `frame`,
// `handshake` and `method` are the shapes this boundary declares, and they
// stay on every target — the golden record in `tests/wire-shape/` is a
// claim about the protocol, not about Unix, and 0.0.11 will encode the
// same frames over whatever Windows transport it lands. `client` is a
// pool of `tokio::net::UnixStream`, so it goes with the daemon (#19).
#[cfg(unix)]
pub mod client;
pub mod frame;
pub mod handshake;
pub mod method;

#[cfg(unix)]
pub use client::{ClientError, ControlClient};
pub use frame::{FrameError, MAX_FRAME_BYTES};
pub use handshake::{ClientKind, HandshakeData, HandshakeParams, PROTOCOL_MAJOR, PROTOCOL_MINOR};
pub use method::{CborValue, ControlError, ErrorCode, Request, Response};
