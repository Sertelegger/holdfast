use thiserror::Error;

pub type Result<T> = std::result::Result<T, HoldfastError>;

#[derive(Debug, Error)]
pub enum HoldfastError {
    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session name already in use: {0}")]
    NameTaken(String),

    #[error("concurrent session limit reached ({0})")]
    LimitReached(usize),

    #[error("session has exited")]
    SessionDied,

    /// A write could not be handed to the PTY within its deadline —
    /// almost always because an earlier write is still parked on a
    /// blocking master fd that the child is not draining.
    #[error("timed out waiting to write to the session")]
    WriteTimeout,

    #[error("invalid prompt pattern: {0}")]
    InvalidPattern(String),

    #[error("pty error: {0}")]
    Pty(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
