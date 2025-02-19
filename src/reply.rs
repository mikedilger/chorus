use pocket_types::{write_hex, Event, Hll8, Id};
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum NostrReplyPrefix {
    None,
    AuthRequired,
    Pow,
    Duplicate,
    Blocked,
    RateLimited,
    Redacted,
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
            NostrReplyPrefix::Redacted => write!(f, "redacted: "),
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
    NegErr(&'a str, String),
    NegMsg(&'a str, Vec<u8>),
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
            NostrReply::NegErr(subid, reason) => {
                format!(r#"["NEG-ERR","{subid}","{reason}"]"#)
            }
            NostrReply::NegMsg(subid, msg) => {
                // write msg as hex
                let mut buf: Vec<u8> = vec![0; msg.len() * 2];
                write_hex!(msg, &mut buf, msg.len()).unwrap();
                let msg_hex = unsafe { std::str::from_utf8_unchecked(&buf) };
                format!(r#"["NEG-MSG","{subid}","{}"]"#, msg_hex)
            }
        }
    }
}

impl fmt::Display for NostrReply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_json())
    }
}
