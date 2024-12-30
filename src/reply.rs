use pocket_types::{Event, Hll8, Id};
use std::fmt;

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NostrReply<'a> {
    Auth(String),
    Event(&'a str, &'a Event),
    Ok(Id, bool, NostrReplyPrefix, String),
    Eose(&'a str),
    Closed(&'a str, NostrReplyPrefix, String),
    Notice(String),
    Count(&'a str, usize, Option<Hll8>),
}

impl NostrReply<'_> {
    pub fn as_json(&self) -> String {
        match self {
            NostrReply::Auth(challenge) => format!(r#"["AUTH","{challenge}"]"#),
            NostrReply::Event(subid, event) => format!(r#"["EVENT","{subid}",{}]"#, event),
            NostrReply::Ok(id, ok, prefix, msg) => format!(r#"["OK","{id}",{ok},"{prefix}{msg}"]"#),
            NostrReply::Eose(subid) => format!(r#"["EOSE","{subid}"]"#),
            NostrReply::Closed(subid, prefix, msg) => {
                format!(r#"["CLOSED","{subid}","{prefix}{msg}"]"#)
            }
            NostrReply::Notice(msg) => format!(r#"["NOTICE","{msg}"]"#),
            NostrReply::Count(subid, c, opthll) => {
                if let Some(hll) = opthll {
                    let hll = hll.to_hex_string();
                    format!(r#"["COUNT","{subid}",{{"count":{c}, "hll":"{hll}"}}]"#)
                } else {
                    format!(r#"["COUNT","{subid}",{{"count":{c}}}]"#)
                }
            }
        }
    }
}

impl fmt::Display for NostrReply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_json())
    }
}
