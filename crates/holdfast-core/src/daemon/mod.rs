//! The daemon (spec §7): a long-lived process that owns sessions and
//! serves the control protocol over a Unix socket.
//!
//! Unix only. Windows runs stdio-only with no daemon at all (§3.3,
//! §3.6); that path lands in 0.0.11.

// **The daemon has no unmediated way to print**, and neither does
// anything else here: `clippy::print_stderr` and `clippy::print_stdout`
// are denied at the crate root (see `lib.rs`), not on this subtree.
//
// They were denied here, and the review that asked for it wrote that
// `mcp::` "legitimately has its own stderr producer today" — which was
// true of the call site and false of the boundary. That producer is the
// constructor *this* module calls, so its line went into `daemon.log`
// unredacted while the denial sat one directory away (re-review I-2).

pub mod attach_server;
pub mod paths;
pub mod peer;
pub mod server;
pub mod spawn;

pub use paths::RuntimePaths;
pub use server::{Daemon, DaemonStatus, StopOutcome, StopParams};
