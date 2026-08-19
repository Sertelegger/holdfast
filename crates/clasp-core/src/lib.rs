//! CLASP core: PTY-backed session management and the MCP tool surface.

pub mod audit;
pub mod buffer;
pub mod clock;
pub mod config;
pub mod daemon;
pub mod detect;
pub mod error;
pub mod mcp;
pub mod output;
pub mod protocol;
pub mod pty;
pub mod screen;
pub mod session;

pub use error::{ClaspError, Result};
