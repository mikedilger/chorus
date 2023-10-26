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

    // JSON Error
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Private Key Not Found")]
    NoPrivateKey,

    // Rustls
    #[error("TLS: {0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),

    // Speedy
    #[error("Speedy: {0}")]
    Speedy(#[from] speedy::Error),

    // Tunstenite
    #[error("Websocket: {0}")]
    Tungstenite(#[from] hyper_tungstenite::tungstenite::error::Error),

    // Tunstenite Protocol
    #[error("Websocket Protocol: {0}")]
    WebsocketProtocol(#[from] hyper_tungstenite::tungstenite::error::ProtocolError),
}
