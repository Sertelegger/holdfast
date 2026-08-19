//! The daemon (spec §7): a long-lived process that owns sessions and
//! serves the control protocol over a Unix socket.
//!
//! Unix only. Windows runs stdio-only with no daemon at all (§3.3,
//! §3.6); that path lands in 0.0.11.

pub mod paths;
pub mod peer;
pub mod server;
pub mod spawn;

pub use paths::RuntimePaths;
pub use server::{Daemon, DaemonStatus, StopOutcome, StopParams};
