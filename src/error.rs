use thiserror::Error;

/// Errors that can occur in the chorus crate
#[derive(Error, Debug)]
pub enum Error {
    // Bad hex input
    #[error("Bad hex input")]
    BadHexInput,

    // Output buffer too small
    #[error("Output buffer too small")]
    BufferTooSmall,

    // Config
    #[error("Config: {0}")]
    Config(#[from] ron::error::SpannedError),

    // End of Input
    #[error("End of input")]
    EndOfInput,

    // I/O Error
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    // JSON Bad String Character
    #[error("JSON string bad character: codepoint {0}")]
    JsonBadStringChar(u32),

    // JSON Escape
    #[error("JSON string escape error")]
    JsonEscape,

    // JSON Escape Surrogate
    #[error("JSON string escape surrogate (ancient style) is not supported")]
    JsonEscapeSurrogate,

    // UTF-8
    #[error("UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    // UTF-8
    #[error("UTF-8 error")]
    Utf8Error,
}
