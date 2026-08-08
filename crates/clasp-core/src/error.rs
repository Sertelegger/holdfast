use thiserror::Error;

pub type Result<T> = std::result::Result<T, ClaspError>;

#[derive(Debug, Error)]
pub enum ClaspError {
    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session name already in use: {0}")]
    NameTaken(String),

    #[error("concurrent session limit reached ({0})")]
    LimitReached(usize),

    #[error("session has exited")]
    SessionDied,

    #[error("pty error: {0}")]
    Pty(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
