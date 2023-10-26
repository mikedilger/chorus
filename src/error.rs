use thiserror::Error;

/// Errors that can occur in the chorus crate
#[derive(Error, Debug)]
pub enum Error {
    // Config
    #[error("Config: {0}")]
    Config(#[from] ron::error::SpannedError),

    // I/O Error
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}
