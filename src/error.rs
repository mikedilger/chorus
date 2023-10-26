use thiserror::Error;

/// Errors that can occur in the chorus crate
#[derive(Error, Debug)]
pub enum Error {
    // I/O Error
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}
