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
// instance keep its logs". THREE modules import it outside their own
// tests, and each is a separate reason:
//
// * `audit` takes `open_log_append` for the §9.4 trail (`audit.rs:8`).
// * `mcp::serve_stdio` calls `RuntimePaths::discover()` on EVERY
//   transport, stdio-only included (`mcp/mod.rs:565`).
// * `config::config_path()` calls `paths::home_dir()` to resolve
//   `$HOME/.config/holdfast/config.toml` (`config.rs:152`). **Ungated,
//   and not about Windows at all**, which is what makes it the strongest
//   of the three: the other two argue about what Windows would lose,
//   while this one is a plain path-resolution dependency that holds on
//   every target. Gating `paths` would force `config` to re-grow its own
//   `var_os("HOME")`, which is the second-spelling hazard c14ba36 removed
//   — an install reading its config from one home and writing its logs
//   under another.
//
// Gating the module would take the audit trail off Windows to make a
// cross-compile check go green, which is a green gate that checks
// nothing, strictly worse than the red one it replaced. Its own mode-bit
// internals carry the `#[cfg(unix)]`, not the module.
//
// **The count has now been wrong in both directions, which is why it is
// spelled out per consumer, with line numbers, above.** The first
// revision said four. 816d3ee cut it to two: it struck `diag`, which is
// right — `diag.rs`'s only use is inside `#[cfg(test)] mod tests` — and
// it struck `config` on the grounds that `config`'s dependency is "the
// Windows warning helper added in this same change", so citing it would
// be citing this commit back at itself as evidence for itself. That
// helper call is real (`warn_inherited_acl_once()` at `config.rs:276`,
// inside `#[cfg(windows)] fn untrusted_reason`) and the circularity
// argument for it holds. It is simply not `config`'s only non-test
// dependency: c14ba36 had already added `config_path()`'s one commit
// earlier, and the correction counted one of the two. Three.
//
// Listed so they are not re-counted as consumers in either direction:
// `diag.rs:290`, `audit.rs:{765,836}` and `config.rs:2179` are all inside
// `#[cfg(test)]` modules.
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
