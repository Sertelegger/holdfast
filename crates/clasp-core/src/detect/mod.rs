//! Prompt detection (spec §8): deterministic first, heuristic only as a
//! fallback.

pub mod scanner;

pub use scanner::{ModeScanner, Modes, Osc133, Osc133Event};
