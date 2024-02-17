use crate::types::{Event, Id};
use std::fmt;

pub enum NostrReplyPrefix {
    None,
    AuthRequired,
    Pow,
    Duplicate,
    Blocked,
    RateLimited,
    Restricted,
    Invalid,
    Error,
}

impl fmt::Display for NostrReplyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NostrReplyPrefix::None => Ok(()),
            NostrReplyPrefix::AuthRequired => write!(f, "auth-required: "),
            NostrReplyPrefix::Pow => write!(f, "pow: "),
            NostrReplyPrefix::Duplicate => write!(f, "duplicate: "),
            NostrReplyPrefix::Blocked => write!(f, "blocked: "),
            NostrReplyPrefix::RateLimited => write!(f, "rate-limited: "),
            NostrReplyPrefix::Restricted => write!(f, "restricted: "),
            NostrReplyPrefix::Invalid => write!(f, "invalid: "),
            NostrReplyPrefix::Error => write!(f, "error: "),
        }
    }
}

pub enum NostrReply<'a> {
    Event(&'a str, Event<'a>),
    Ok(Id, bool, NostrReplyPrefix, String),
    Eose(&'a str),
    Closed(&'a str, NostrReplyPrefix, String),
    Notice(String),
}

impl NostrReply<'_> {
    pub fn as_json(&self) -> String {
        match self {
            NostrReply::Event(subid, event) => format!(r#"["EVENT", "{subid}", {}]"#, event),
            NostrReply::Ok(id, ok, prefix, msg) => format!(r#"["OK","{id}",{ok},"{prefix}{msg}"]"#),
            NostrReply::Eose(subid) => format!(r#"["EOSE","{subid}"]"#),
            NostrReply::Closed(subid, prefix, msg) => {
                format!(r#"["CLOSED","{subid}","{prefix}{msg}"]"#)
            }
            NostrReply::Notice(msg) => format!(r#"["NOTICE","{msg}"]"#),
        }
    }
}

impl fmt::Display for NostrReply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_json())
    }
}
