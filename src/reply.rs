use crate::types::{Event, Id};
use std::fmt;

pub enum NostrReply<'a> {
    Event(&'a str, Event<'a>),
    Ok(Id, bool, String),
    Eose(&'a str),
    Closed(&'a str, String),
    Notice(String),
}

impl NostrReply<'_> {
    pub fn as_json(&self) -> String {
        match self {
            NostrReply::Event(subid, event) => format!(r#"["EVENT", "{subid}", {}]"#, event),
            NostrReply::Ok(id, ok, msg) => format!(r#"["OK","{id}",{ok},"{msg}"]"#),
            NostrReply::Eose(subid) => format!(r#"["EOSE","{subid}"]"#),
            NostrReply::Closed(subid, msg) => format!(r#"["CLOSED","{subid}","{msg}"]"#),
            NostrReply::Notice(msg) => format!(r#"["NOTICE","{msg}"]"#),
        }
    }
}

impl fmt::Display for NostrReply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_json())
    }
}
