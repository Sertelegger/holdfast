//! Prompt detection (spec §8): deterministic first, heuristic only as a
//! fallback.

pub mod detector;
pub mod patterns;
pub mod scanner;

pub use detector::{
    Detection, DetectionConfig, DetectionTier, InteractionMode, PromptDetector,
    DEFAULT_SETTLE_THRESHOLD_MS,
};
pub use patterns::{PatternSet, PromptPattern, DEFAULT_PATTERNS};
pub use scanner::{ModeScanner, Modes, Osc133, Osc133Event};
