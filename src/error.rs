use std::convert::Infallible;
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
    // Nostr AUTH failure
    AuthFailure(String),

    // Auth required
    AuthRequired,

    // Bad request
    BadRequest(&'static str),

    // Bad X-Real-Ip header
    BadRealIpHeader(String),

    // Bad X-Real-Ip header characters
    BadRealIpHeaderCharacters,

    // Event is banned
    BannedEvent,

    // User is banned
    BannedUser,

    // Base64 Decode Error
    Base64Decode(base64::DecodeError),

    // Blocked IP
    BlockedIp,

    // Blossom Authorization failure
    BlossomAuthFailure(String),

    // Channel Recv
    ChannelRecv(tokio::sync::broadcast::error::RecvError),

    // Channel Send
    ChannelSend(tokio::sync::broadcast::error::SendError<u64>),

    // Config
    Config(toml::de::Error),

    // Crypto
    Crypto(secp256k1::Error),

    // Closing on error(s)
    ErrorClose,

    // Event is Invalid
    EventIsInvalid(String),

    // From hex
    FromHex(hex::FromHexError),

    // From UTF8
    FromUtf8(std::string::FromUtf8Error),

    // General
    General(String),

    // Http
    Http(hyper::http::Error),

    // Hyper
    Hyper(hyper::Error),

    // Infallible
    Infallible,

    // Invalid URI
    InvalidUri(hyper::http::uri::InvalidUri),

    // Invalid URI Parts
    InvalidUriParts(hyper::http::uri::InvalidUriParts),

    // I/O
    Io(std::io::Error),

    // Management Authorization failure
    ManagementAuthFailure(String),

    // Missing Table
    MissingTable(&'static str),

    // Negentropy error
    Negentropy(negentropy::Error),

    // Non-ASCII HTTP header value
    NonAsciiHttpHeaderValue(http::header::ToStrError),

    // No private key
    NoPrivateKey,

    // Not Implemented
    NotImplemented,

    // No such subscription
    NoSuchSubscription,

    // Protected Event
    ProtectedEvent,

    // Pocket Db Error
    PocketDb(pocket_db::Error),

    // Pocket Db Heed Error
    PocketDbHeed(pocket_db::heed::Error),

    // Pocket Types Error
    PocketType(pocket_types::Error),

    // Rate limit exceeded
    RateLimitExceeded,

    // X-Real-Ip header is missing
    RealIpHeaderMissing,

    // Restricted
    Restricted,

    // Rustls
    Rustls(tokio_rustls::rustls::Error),

    // Filter is underspecified
    Scraper,

    // Serde JSON
    SerdeJson(serde_json::Error),

    // Shutting Down
    ShuttingDown,

    // Signal - Not Blossom Request
    SignalNotBlossom,

    // Speedy
    Speedy(speedy::Error),

    // Timed Out
    TimedOut,

    // Too many subscriptions
    TooManySubscriptions,

    // Tungstenite
    Tungstenite(hyper_tungstenite::tungstenite::error::Error),

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
            ChorusError::BadRequest(s) => write!(f, "Bad Request: {s}"),
            ChorusError::BadRealIpHeader(s) => write!(f, "Bad X-Real-Ip header: {s}"),
            ChorusError::BadRealIpHeaderCharacters => {
                write!(f, "Bad X-Real-Ip header (non utf-8 characters)")
            }
            ChorusError::BannedEvent => write!(f, "Event is banned"),
            ChorusError::BannedUser => write!(f, "User is banned"),
            ChorusError::Base64Decode(e) => write!(f, "{e}"),
            ChorusError::BlockedIp => write!(f, "IP is temporarily blocked"),
            ChorusError::BlossomAuthFailure(s) => write!(f, "Authorization failure: {s}"),
            ChorusError::ChannelRecv(e) => write!(f, "{e}"),
            ChorusError::ChannelSend(e) => write!(f, "{e}"),
            ChorusError::Config(e) => write!(f, "{e}"),
            ChorusError::Crypto(e) => write!(f, "{e}"),
            ChorusError::ErrorClose => write!(f, "Closing due to error(s)"),
            ChorusError::EventIsInvalid(s) => write!(f, "Event is invalid: {s}"),
            ChorusError::FromHex(e) => write!(f, "{e}"),
            ChorusError::FromUtf8(e) => write!(f, "{e}"),
            ChorusError::General(s) => write!(f, "{s}"),
            ChorusError::Http(e) => write!(f, "{e}"),
            ChorusError::Hyper(e) => write!(f, "{e}"),
            ChorusError::Infallible => panic!("INFALLIBLE"),
            ChorusError::InvalidUri(e) => write!(f, "{e}"),
            ChorusError::InvalidUriParts(e) => write!(f, "{e}"),
            ChorusError::Io(e) => write!(f, "{e}"),
            ChorusError::ManagementAuthFailure(s) => write!(f, "Authorization failure: {s}"),
            ChorusError::MissingTable(t) => write!(f, "Missing table: {t}"),
            ChorusError::Negentropy(e) => write!(f, "Negentropy: {e}"),
            ChorusError::NonAsciiHttpHeaderValue(e) => {
                write!(f, "Non ASCII HTTP header value: {e}")
            }
            ChorusError::NoPrivateKey => write!(f, "Private Key Not Found"),
            ChorusError::NotImplemented => write!(f, "Not implemented"),
            ChorusError::NoSuchSubscription => write!(f, "No such subscription"),
            ChorusError::PocketDb(e) => write!(f, "{e}"),
            ChorusError::PocketDbHeed(e) => write!(f, "{e}"),
            ChorusError::PocketType(e) => write!(f, "{e}"),
            ChorusError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            ChorusError::ProtectedEvent => write!(f, "Protected event"),
            ChorusError::RealIpHeaderMissing => write!(f, "X-Real-Ip header is missing"),
            ChorusError::Restricted => write!(f, "Restricted"),
            ChorusError::Rustls(e) => write!(f, "{e}"),
            ChorusError::Scraper => write!(f, "Filter is underspecified. Scrapers are not allowed"),
            ChorusError::SerdeJson(e) => write!(f, "{e}"),
            ChorusError::ShuttingDown => write!(f, "Shutting down"),
            ChorusError::SignalNotBlossom => write!(f, "internal-signal-not-blossom"),
            ChorusError::Speedy(e) => write!(f, "{e}"),
            ChorusError::TimedOut => write!(f, "Timed out"),
            ChorusError::TooManySubscriptions => write!(f, "Too many subscriptions"),
            ChorusError::Tungstenite(e) => write!(f, "{e}"),
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
            ChorusError::Base64Decode(e) => Some(e),
            ChorusError::ChannelRecv(e) => Some(e),
            ChorusError::ChannelSend(e) => Some(e),
            ChorusError::Config(e) => Some(e),
            ChorusError::Crypto(e) => Some(e),
            ChorusError::FromHex(e) => Some(e),
            ChorusError::FromUtf8(e) => Some(e),
            ChorusError::Http(e) => Some(e),
            ChorusError::Hyper(e) => Some(e),
            ChorusError::InvalidUri(e) => Some(e),
            ChorusError::InvalidUriParts(e) => Some(e),
            ChorusError::Io(e) => Some(e),
            ChorusError::NonAsciiHttpHeaderValue(e) => Some(e),
            ChorusError::PocketDb(e) => Some(e),
            ChorusError::PocketDbHeed(e) => Some(e),
            ChorusError::PocketType(e) => Some(e),
            ChorusError::Rustls(e) => Some(e),
            ChorusError::SerdeJson(e) => Some(e),
            ChorusError::Speedy(e) => Some(e),
            ChorusError::Tungstenite(e) => Some(e),
            ChorusError::UrlParse(e) => Some(e),
            ChorusError::Utf8(e) => Some(e),
            ChorusError::WebsocketProtocol(e) => Some(e),
            _ => None,
        }
    }
}

impl ChorusError {
    #[track_caller]
    pub fn into_err(self) -> Error {
        Error {
            inner: self,
            location: std::panic::Location::caller(),
        }
    }

    pub fn punishment(&self) -> f32 {
        match self {
            ChorusError::AuthFailure(_) => 0.25,
            ChorusError::AuthRequired => 0.0,
            ChorusError::BadRequest(_) => 0.1,
            ChorusError::BadRealIpHeader(_) => 0.0,
            ChorusError::BadRealIpHeaderCharacters => 0.0,
            ChorusError::BannedEvent => 0.1,
            ChorusError::BannedUser => 0.2,
            ChorusError::Base64Decode(_) => 0.0,
            ChorusError::BlockedIp => 0.0,
            ChorusError::BlossomAuthFailure(_) => 0.0,
            ChorusError::ChannelRecv(_) => 0.0,
            ChorusError::ChannelSend(_) => 0.0,
            ChorusError::Config(_) => 0.0,
            ChorusError::Crypto(_) => 0.1,
            ChorusError::ErrorClose => 1.0,
            ChorusError::EventIsInvalid(_) => 0.2,
            ChorusError::FromHex(_) => 0.2,
            ChorusError::FromUtf8(_) => 0.2,
            ChorusError::General(_) => 0.0,
            ChorusError::Http(_) => 0.0,
            ChorusError::Hyper(_) => 0.0,
            ChorusError::Infallible => panic!("INFALLIBLE"),
            ChorusError::InvalidUri(_) => 0.0,
            ChorusError::InvalidUriParts(_) => 0.0,
            ChorusError::Io(_) => 0.0,
            ChorusError::ManagementAuthFailure(_) => 0.0,
            ChorusError::MissingTable(_) => 0.0,
            ChorusError::Negentropy(_) => 0.1,
            ChorusError::NonAsciiHttpHeaderValue(_) => 0.2,
            ChorusError::NoPrivateKey => 0.0,
            ChorusError::NotImplemented => 0.0,
            ChorusError::NoSuchSubscription => 0.05,
            ChorusError::PocketDb(_) => 0.0,
            ChorusError::PocketDbHeed(_) => 0.0,
            ChorusError::PocketType(_) => 0.25,
            ChorusError::RateLimitExceeded => 1.0,
            ChorusError::ProtectedEvent => 0.35,
            ChorusError::RealIpHeaderMissing => 0.0,
            ChorusError::Restricted => 0.1,
            ChorusError::Rustls(_) => 0.0,
            ChorusError::Scraper => 0.4,
            ChorusError::SerdeJson(_) => 0.0,
            ChorusError::ShuttingDown => 0.0,
            ChorusError::SignalNotBlossom => 0.0,
            ChorusError::Speedy(_) => 0.0,
            ChorusError::TimedOut => 0.1,
            ChorusError::TooManySubscriptions => 0.1,
            ChorusError::Tungstenite(_) => 0.0,
            ChorusError::UrlParse(_) => 0.1,
            ChorusError::Utf8(_) => 0.1,
            ChorusError::Utf8Error => 0.1,
            ChorusError::WebsocketProtocol(_) => 0.1,
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

impl From<tokio::sync::broadcast::error::SendError<u64>> for Error {
    #[track_caller]
    fn from(err: tokio::sync::broadcast::error::SendError<u64>) -> Self {
        Error {
            inner: ChorusError::ChannelSend(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<toml::de::Error> for Error {
    #[track_caller]
    fn from(err: toml::de::Error) -> Self {
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

impl From<hyper::http::uri::InvalidUri> for Error {
    #[track_caller]
    fn from(err: hyper::http::uri::InvalidUri) -> Self {
        Error {
            inner: ChorusError::InvalidUri(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<hyper::http::uri::InvalidUriParts> for Error {
    #[track_caller]
    fn from(err: hyper::http::uri::InvalidUriParts) -> Self {
        Error {
            inner: ChorusError::InvalidUriParts(err),
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

impl From<http::header::ToStrError> for Error {
    #[track_caller]
    fn from(err: http::header::ToStrError) -> Self {
        Error {
            inner: ChorusError::NonAsciiHttpHeaderValue(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<pocket_db::Error> for Error {
    #[track_caller]
    fn from(err: pocket_db::Error) -> Self {
        Error {
            inner: ChorusError::PocketDb(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<pocket_db::heed::Error> for Error {
    #[track_caller]
    fn from(err: pocket_db::heed::Error) -> Self {
        Error {
            inner: ChorusError::PocketDbHeed(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<pocket_types::Error> for Error {
    #[track_caller]
    fn from(err: pocket_types::Error) -> Self {
        Error {
            inner: ChorusError::PocketType(err),
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

impl From<speedy::Error> for Error {
    #[track_caller]
    fn from(err: speedy::Error) -> Self {
        Error {
            inner: ChorusError::Speedy(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<serde_json::Error> for Error {
    #[track_caller]
    fn from(err: serde_json::Error) -> Self {
        Error {
            inner: ChorusError::SerdeJson(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<hex::FromHexError> for Error {
    #[track_caller]
    fn from(err: hex::FromHexError) -> Self {
        Error {
            inner: ChorusError::FromHex(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::string::FromUtf8Error> for Error {
    #[track_caller]
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error {
            inner: ChorusError::FromUtf8(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<base64::DecodeError> for Error {
    #[track_caller]
    fn from(err: base64::DecodeError) -> Self {
        Error {
            inner: ChorusError::Base64Decode(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<negentropy::Error> for Error {
    #[track_caller]
    fn from(e: negentropy::Error) -> Error {
        Error {
            inner: ChorusError::Negentropy(e),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        panic!("INFALLIBLE")
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}
