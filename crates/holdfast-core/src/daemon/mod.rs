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

// **`paths` is NOT gated, and the asymmetry is the whole shape of this
// module on Windows (#19).** The other four are the daemon proper — Unix
// sockets, `flock`, `setsid`, `SO_PEERCRED` — and have no meaning without
// one. `paths` holds `RuntimePaths`, which answers "where does this
// instance keep its logs". TWO modules import it outside their own tests,
// and they are the ones that matter: `audit` takes `open_log_append` for
// the §9.4 trail, and `mcp::serve_stdio` calls `RuntimePaths::discover()`
// on EVERY transport, stdio-only included. Gating the module would take
// the audit trail off Windows to make a cross-compile check go green,
// which is a green gate that checks nothing, strictly worse than the red
// one it replaced. Its own mode-bit internals carry the `#[cfg(unix)]`,
// not the module.
//
// (An earlier revision listed four consumers. `diag` uses it only in its
// tests, and `config`'s dependency is the Windows warning helper added in
// this same change — citing either would be citing this commit back at
// itself as evidence for itself.)
#[cfg(unix)]
pub mod attach_server;
pub mod paths;
#[cfg(unix)]
pub mod peer;
#[cfg(unix)]
pub mod server;
#[cfg(unix)]
pub mod spawn;

pub use paths::RuntimePaths;
#[cfg(unix)]
pub use server::{Daemon, DaemonStatus, StopOutcome, StopParams};
