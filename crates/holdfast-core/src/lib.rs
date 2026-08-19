//! CLASP core: PTY-backed session management and the MCP tool surface.

// **Nothing in this crate has an unmediated way to print**, and the
// denial is at the crate root because that is the only scope that
// matches the hazard. Whatever links this library can be the daemon,
// whose stderr *is* `daemon.log` — §9.2 lists it as a redacted boundary
// — and whose stdout, on the `start_detached` path, is the same file;
// under `clasp mcp` a stray `println!` lands on the MCP JSON-RPC wire
// instead (see `spawn::ensure_daemon`, which measured 20 smoke
// assertions failing at once from one unparseable line). `crate::diag!`
// is the only sanctioned producer.
//
// **This was scoped to `daemon/` and that was the defect** (re-review
// I-2): `mcp::HoldfastServer::with_audit_path_config_and_clock` — the
// constructor the daemon itself calls — wrote a bare `eprintln!` into
// `daemon.log`, and the guard `diag.rs` advertises as making that a
// build failure did not reach the module it happened in. A guard that
// does not cover the code it guards is not a guard. The scope is
// asserted by `no_module_in_this_crate_can_print_around_the_redactor`,
// so narrowing it back is a red test and not a review finding.
#![deny(clippy::print_stderr, clippy::print_stdout)]

pub mod audit;
pub mod buffer;
pub mod clock;
pub mod config;
pub mod daemon;
pub mod detect;
pub mod diag;
pub mod error;
pub mod mcp;
pub mod output;
pub mod protocol;
pub mod pty;
pub mod screen;
pub mod session;

pub use error::{HoldfastError, Result};
