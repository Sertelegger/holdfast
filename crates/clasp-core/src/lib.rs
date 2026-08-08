//! CLASP core: PTY-backed session management and the MCP tool surface.

pub mod buffer;
pub mod error;
pub mod mcp;
pub mod pty;
pub mod session;

pub use error::{ClaspError, Result};
