use crate::Error;
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
    NegErr(&'a str, String),
    NegMsg(&'a str, Vec<u8>),
}

impl NostrReply<'_> {
    pub fn as_json(&self) -> Result<String, Error> {
        Ok(match self {
            NostrReply::Auth(challenge) => {
                let esc_challenge = escape(challenge)?;
                format!(r#"["AUTH","{esc_challenge}"]"#)
            }
            NostrReply::Event(subid, event) => {
                let esc_subid = escape(subid)?;
                format!(r#"["EVENT","{esc_subid}",{event}]"#)
            }
            NostrReply::Ok(id, ok, prefix, msg) => {
                let esc_msg = escape(msg)?;
                format!(r#"["OK","{id}",{ok},"{prefix}{esc_msg}"]"#)
            }
            NostrReply::Eose(subid) => {
                let esc_subid = escape(subid)?;
                format!(r#"["EOSE","{esc_subid}"]"#)
            }
            NostrReply::Closed(subid, prefix, msg) => {
                format!(r#"["CLOSED","{subid}","{prefix}{msg}"]"#)
            }
            NostrReply::Notice(msg) => {
                let esc_msg = escape(msg)?;
                format!(r#"["NOTICE","{esc_msg}"]"#)
            }
            NostrReply::Count(subid, c, opthll) => {
                let esc_subid = escape(subid)?;
                if let Some(hll) = opthll {
                    let hll = hll.to_hex_string();
                    format!(r#"["COUNT","{esc_subid}",{{"count":{c}, "hll":"{hll}"}}]"#)
                } else {
                    format!(r#"["COUNT","{esc_subid}",{{"count":{c}}}]"#)
                }
            }
            NostrReply::NegErr(subid, reason) => {
                let esc_subid = escape(subid)?;
                let esc_reason = escape(reason)?;
                format!(r#"["NEG-ERR","{esc_subid}","{esc_reason}"]"#)
            }
            NostrReply::NegMsg(subid, msg) => {
                let esc_subid = escape(subid)?;
                // write msg as hex
                let mut buf: Vec<u8> = vec![0; msg.len() * 2];
                write_hex!(msg, &mut buf, msg.len()).unwrap();
                let msg_hex = unsafe { std::str::from_utf8_unchecked(&buf) };
                format!(r#"["NEG-MSG","{esc_subid}","{}"]"#, msg_hex)
            }
        })
    }
}

fn escape(s: &str) -> Result<String, Error> {
    let v: Vec<u8> = Vec::with_capacity(256);
    let e = pocket_types::json::json_escape(s.as_bytes(), v)?;
    Ok(unsafe { String::from_utf8_unchecked(e) })
}
