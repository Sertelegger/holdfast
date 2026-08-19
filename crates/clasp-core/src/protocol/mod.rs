//! The daemon ↔ client control protocol (spec §7.4).
//!
//! This is a declared breaking-change boundary (§23.3): once shipped, a
//! shape change to any type here breaks every shim and CLI built against
//! a different major. Additive change — a new method, a new optional
//! field — is fine and does not move the major.

pub mod client;
pub mod frame;
pub mod handshake;
pub mod method;

pub use client::{ClientError, ControlClient};
pub use frame::{FrameError, MAX_FRAME_BYTES};
pub use handshake::{ClientKind, HandshakeData, HandshakeParams, PROTOCOL_MAJOR, PROTOCOL_MINOR};
pub use method::{CborValue, ControlError, ErrorCode, Request, Response};
