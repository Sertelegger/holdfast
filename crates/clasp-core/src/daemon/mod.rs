//! The daemon (spec §7): a long-lived process that owns sessions and
//! serves the control protocol over a Unix socket.
//!
//! Unix only. Windows runs stdio-only with no daemon at all (§3.3,
//! §3.6); that path lands in 0.0.11.

// **The daemon has no unmediated way to print.** Its stderr *is*
// `daemon.log`, which §9.2 lists as a redacted boundary, and its stdout
// — on the `start_detached` path — is the same file, while on the shim's
// path a stray `println!` lands on the MCP JSON-RPC wire (see
// `spawn::ensure_daemon`, which measured 20 smoke assertions failing at
// once from one unparseable line). `crate::diag!` is the only producer,
// and this pair of denials is what keeps a re-introduced `eprintln!`
// from being a review finding instead of a build failure. Scoped to this
// module subtree rather than the crate because `mcp::` legitimately has
// its own stderr producer today (review I-4).
#![deny(clippy::print_stderr, clippy::print_stdout)]

pub mod paths;
pub mod peer;
pub mod server;
pub mod spawn;

pub use paths::RuntimePaths;
pub use server::{Daemon, DaemonStatus, StopOutcome, StopParams};
