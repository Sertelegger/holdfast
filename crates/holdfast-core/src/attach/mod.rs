//! The attach protocol (spec §7.5) — the live duplex PTY stream on
//! `attach.sock`.
//!
//! **This module is a declared breaking-change boundary (§23.3).** It is
//! consumed by `holdfast attach`, `holdfast watch`, and — from 0.0.10 — the web
//! UI's WebSocket path, which mirrors these frames verbatim (§7.6.3). A
//! rename, a removal, or a semantics shift here costs two transports and
//! is a gate item. Adding a variant or an optional field is not.
//!
//! Wire encoding is `crate::protocol::frame`'s, unchanged: a 4-byte
//! big-endian length prefix and a 16 MiB body cap. There is exactly one
//! codec in this crate and this module is not it.
//!
//! The submodule list below grows one entry per task of this milestone;
//! each `pub mod` line lands in the commit that creates the file it
//! names, so every commit on the branch compiles on its own.

pub mod frames;
pub mod handshake;

pub use frames::{
    decode_server_frame, AttachMode, AttachRole, ClientFrame, ClientFrameKind, ServerFrame,
    SignalName, KNOWN_SERVER_TYPES,
};
pub use handshake::{
    client_accepts_daemon, evaluate_attach, REJECT_LIMIT_REACHED, REJECT_PROTOCOL_TOO_NEW,
    REJECT_PROTOCOL_TOO_OLD, REJECT_SESSION_NOT_FOUND,
};
