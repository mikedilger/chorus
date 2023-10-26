use thiserror::Error;

/// Errors that can occur in the chorus crate
#[derive(Error, Debug)]
pub enum Error {
    // Config
    #[error("Config: {0}")]
    Config(#[from] ron::error::SpannedError),

    // Http
    #[error("HTTP: {0}")]
    Http(#[from] hyper::http::Error),

    // Hyper
    #[error("Hyper: {0}")]
    Hyper(#[from] hyper::Error),

    // I/O Error
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Private Key Not Found")]
    NoPrivateKey,

    // Rustls
    #[error("TLS: {0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),
}
