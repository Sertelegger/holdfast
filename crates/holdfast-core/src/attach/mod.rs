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

/// **The only gated submodule in `attach/`**, because it is the only one
/// that names a `UnixStream`. Blanket-gating the module would take the
/// frame catalog and the version contract off the `windows-cross` job,
/// which is where a §23.3 wire surface gets type-checked for the
/// platform that mirrors it in 0.0.10.
#[cfg(unix)]
pub mod conn;
pub mod frames;
pub mod handshake;
/// **Not gated.** `AttachConn` and the hub name no platform type, and
/// keeping them off `#[cfg(unix)]` is what leaves the per-connection
/// shape type-checked for the transport that mirrors it in 0.0.10.
pub mod hub;

pub use frames::{
    decode_client_frame, decode_server_frame, AttachMode, AttachRole, ClientDecode, ClientFrame,
    ClientFrameKind, ServerFrame, SignalName, KNOWN_SERVER_TYPES,
};
pub use handshake::{
    client_accepts_daemon, evaluate_attach, REJECT_LIMIT_REACHED, REJECT_PROTOCOL_TOO_NEW,
    REJECT_PROTOCOL_TOO_OLD, REJECT_SESSION_NOT_FOUND,
};
