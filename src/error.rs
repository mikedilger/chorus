use std::error::Error as StdError;
use std::panic::Location;

#[derive(Debug)]
pub struct Error {
    pub inner: ChorusError,
    location: &'static Location<'static>,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}", self.inner, self.location)
    }
}

/// Errors that can occur in the chorus crate
#[derive(Debug)]
pub enum ChorusError {
    // Auth failure
    AuthFailure(String),

    // Auth required
    AuthRequired,

    // Bad event id
    BadEventId,

    // Bad hex input
    BadHexInput,

    // Output buffer too small
    BufferTooSmall,

    // Channel Recv
    ChannelRecv(tokio::sync::broadcast::error::RecvError),

    // Channel Send
    ChannelSend(tokio::sync::broadcast::error::SendError<usize>),

    // Config
    Config(ron::error::SpannedError),

    // Crypto
    Crypto(secp256k1::Error),

    // Deleted event
    Deleted,

    // Duplicate event
    Duplicate,

    // End of Input
    EndOfInput,

    // Event is Invalid
    EventIsInvalid(String),

    // Http
    Http(hyper::http::Error),

    // Hyper
    Hyper(hyper::Error),

    // I/O
    Io(std::io::Error),

    // JSON Bad (general)
    JsonBad(&'static str, usize),

    // JSON Bad Character
    JsonBadCharacter(char, usize, char),

    // JSON Bad Event
    JsonBadEvent(&'static str, usize),

    // JSON Bad Filter
    JsonBadFilter(&'static str, usize),

    // JSON Bad String Character
    JsonBadStringChar(u32),

    // JSON Escape
    JsonEscape,

    // JSON Escape Surrogate
    JsonEscapeSurrogate,

    // LMDB
    Lmdb(heed::Error),

    // No private key
    NoPrivateKey,

    // No such subscription
    NoSuchSubscription,

    // Restricted
    Restricted,

    // Rustls
    Rustls(tokio_rustls::rustls::Error),

    // Timed Out
    TimedOut,

    // Tungstenite
    Tungstenite(hyper_tungstenite::tungstenite::error::Error),

    // Filter is underspecified
    Scraper,

    // Too many errors
    TooManyErrors,

    // Too many subscriptions
    TooManySubscriptions,

    // URL Parse
    UrlParse(url::ParseError),

    // UTF-8
    Utf8(std::str::Utf8Error),

    // UTF-8
    Utf8Error,

    // Tungstenite Protocol
    WebsocketProtocol(hyper_tungstenite::tungstenite::error::ProtocolError),
}

impl std::fmt::Display for ChorusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChorusError::AuthFailure(s) => write!(f, "AUTH failure: {s}"),
            ChorusError::AuthRequired => write!(f, "AUTH required"),
            ChorusError::BadEventId => write!(f, "Bad event id, does not match hash"),
            ChorusError::BadHexInput => write!(f, "Bad hex input"),
            ChorusError::BufferTooSmall => write!(f, "Output buffer too small"),
            ChorusError::ChannelRecv(e) => write!(f, "{e}"),
            ChorusError::ChannelSend(e) => write!(f, "{e}"),
            ChorusError::Config(e) => write!(f, "{e}"),
            ChorusError::Crypto(e) => write!(f, "{e}"),
            ChorusError::Deleted => write!(f, "Event was previously deleted"),
            ChorusError::Duplicate => write!(f, "Duplicate event"),
            ChorusError::EndOfInput => write!(f, "End of input"),
            ChorusError::EventIsInvalid(s) => write!(f, "Event is invalid: {s}"),
            ChorusError::Http(e) => write!(f, "{e}"),
            ChorusError::Hyper(e) => write!(f, "{e}"),
            ChorusError::Io(e) => write!(f, "{e}"),
            ChorusError::JsonBad(err, pos) => write!(f, "JSON bad: {err} at position {pos}"),
            ChorusError::JsonBadCharacter(c, pos, ec) => write!(
                f,
                "JSON bad character: {c} at position {pos}, {ec} was expected"
            ),
            ChorusError::JsonBadEvent(err, pos) => {
                write!(f, "JSON bad event: {err} at position {pos}")
            }
            ChorusError::JsonBadFilter(err, pos) => {
                write!(f, "JSON bad filter: {err} at position {pos}")
            }
            ChorusError::JsonBadStringChar(ch) => {
                write!(f, "JSON string bad character: codepoint {ch}")
            }
            ChorusError::JsonEscape => write!(f, "JSON string escape error"),
            ChorusError::JsonEscapeSurrogate => write!(
                f,
                "JSON string escape surrogate (ancient style) is not supported"
            ),
            ChorusError::Lmdb(e) => write!(f, "{e}"),
            ChorusError::NoPrivateKey => write!(f, "Private Key Not Found"),
            ChorusError::NoSuchSubscription => write!(f, "No such subscription"),
            ChorusError::Restricted => write!(f, "Restricted"),
            ChorusError::Rustls(e) => write!(f, "{e}"),
            ChorusError::TimedOut => write!(f, "Timed out"),
            ChorusError::Tungstenite(e) => write!(f, "{e}"),
            ChorusError::Scraper => write!(f, "Filter is underspecified. Scrapers are not allowed"),
            ChorusError::TooManyErrors => write!(f, "Too many errors"),
            ChorusError::TooManySubscriptions => write!(f, "Too many subscriptions"),
            ChorusError::UrlParse(e) => write!(f, "{e}"),
            ChorusError::Utf8(e) => write!(f, "{e}"),
            ChorusError::Utf8Error => write!(f, "UTF-8 error"),
            ChorusError::WebsocketProtocol(e) => write!(f, "{e}"),
        }
    }
}

impl StdError for ChorusError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ChorusError::ChannelRecv(e) => Some(e),
            ChorusError::ChannelSend(e) => Some(e),
            ChorusError::Config(e) => Some(e),
            ChorusError::Crypto(e) => Some(e),
            ChorusError::Http(e) => Some(e),
            ChorusError::Hyper(e) => Some(e),
            ChorusError::Io(e) => Some(e),
            ChorusError::Lmdb(e) => Some(e),
            ChorusError::Rustls(e) => Some(e),
            ChorusError::Tungstenite(e) => Some(e),
            ChorusError::UrlParse(e) => Some(e),
            ChorusError::Utf8(e) => Some(e),
            ChorusError::WebsocketProtocol(e) => Some(e),
            _ => None,
        }
    }
}

// Note: we impl Into because our typical pattern is ChorusError::Variant.into()
//       when we tried implementing From, the location was deep in rust code's
//       blanket into implementation, which wasn't the line number we wanted.
//
//       As for converting other error types (below) the try! macro uses From so it
//       is correct.
#[allow(clippy::from_over_into)]
impl Into<Error> for ChorusError {
    #[track_caller]
    fn into(self) -> Error {
        Error {
            inner: self,
            location: std::panic::Location::caller(),
        }
    }
}

impl From<tokio::sync::broadcast::error::RecvError> for Error {
    #[track_caller]
    fn from(err: tokio::sync::broadcast::error::RecvError) -> Self {
        Error {
            inner: ChorusError::ChannelRecv(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<tokio::sync::broadcast::error::SendError<usize>> for Error {
    #[track_caller]
    fn from(err: tokio::sync::broadcast::error::SendError<usize>) -> Self {
        Error {
            inner: ChorusError::ChannelSend(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<ron::error::SpannedError> for Error {
    #[track_caller]
    fn from(err: ron::error::SpannedError) -> Self {
        Error {
            inner: ChorusError::Config(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<secp256k1::Error> for Error {
    #[track_caller]
    fn from(err: secp256k1::Error) -> Self {
        Error {
            inner: ChorusError::Crypto(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<hyper::http::Error> for Error {
    #[track_caller]
    fn from(err: hyper::http::Error) -> Self {
        Error {
            inner: ChorusError::Http(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<hyper::Error> for Error {
    #[track_caller]
    fn from(err: hyper::Error) -> Self {
        Error {
            inner: ChorusError::Hyper(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::io::Error> for Error {
    #[track_caller]
    fn from(err: std::io::Error) -> Self {
        Error {
            inner: ChorusError::Io(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<heed::Error> for Error {
    #[track_caller]
    fn from(err: heed::Error) -> Self {
        Error {
            inner: ChorusError::Lmdb(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<tokio_rustls::rustls::Error> for Error {
    #[track_caller]
    fn from(err: tokio_rustls::rustls::Error) -> Self {
        Error {
            inner: ChorusError::Rustls(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<hyper_tungstenite::tungstenite::error::Error> for Error {
    #[track_caller]
    fn from(err: hyper_tungstenite::tungstenite::error::Error) -> Self {
        Error {
            inner: ChorusError::Tungstenite(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    #[track_caller]
    fn from(err: std::str::Utf8Error) -> Self {
        Error {
            inner: ChorusError::Utf8(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<hyper_tungstenite::tungstenite::error::ProtocolError> for Error {
    #[track_caller]
    fn from(err: hyper_tungstenite::tungstenite::error::ProtocolError) -> Self {
        Error {
            inner: ChorusError::WebsocketProtocol(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<url::ParseError> for Error {
    #[track_caller]
    fn from(err: url::ParseError) -> Self {
        Error {
            inner: ChorusError::UrlParse(err),
            location: std::panic::Location::caller(),
        }
    }
}
