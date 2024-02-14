use crate::error::Error;
use crate::reply::NostrReply;
use crate::types::parse::json_escape::json_unescape;
use crate::types::parse::json_parse::*;
use crate::WebSocketService;
use futures::SinkExt;
use hyper_tungstenite::tungstenite::Message;

impl WebSocketService {
    pub async fn handle_nostr_message(&mut self, msg: String) -> Result<(), Error> {
        // If the msg is large, grow the session buffer
        // (it will be freed when they disconnect)
        if msg.len() > 4096 {
            let newlen = 4096 * ((msg.len() / 4096) + 1);
            self.buffer.resize(newlen, 0);
        }

        let input = msg.as_bytes();
        let mut inpos = 0;
        eat_whitespace(input, &mut inpos);
        verify_char(input, b'[', &mut inpos)?;
        eat_whitespace(input, &mut inpos);
        verify_char(input, b'"', &mut inpos)?;
        if &input[inpos..inpos + 4] == b"REQ\"" {
            self.req(msg, inpos + 4).await?;
        } else if &input[inpos..inpos + 6] == b"EVENT\"" {
            self.event(msg, inpos + 6).await?;
        } else if &input[inpos..inpos + 6] == b"CLOSE\"" {
            self.close(msg, inpos + 6).await?;
        } else if &input[inpos..inpos + 5] == b"AUTH\"" {
            self.auth(msg, inpos + 5).await?;
        } else {
            log::warn!("{}: Received unhandled text message: {}", self.peer, msg);
            let reply = NostrReply::Notice("Command unrecognized".to_owned());
            self.websocket.send(Message::text(reply.as_json())).await?;
        }

        Ok(())
    }

    pub async fn req(&mut self, _msg: String, mut _inpos: usize) -> Result<(), Error> {
        unimplemented!()
    }

    pub async fn event(&mut self, _msg: String, mut _inpos: usize) -> Result<(), Error> {
        unimplemented!()
    }

    pub async fn close(&mut self, msg: String, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        // ["CLOSE", <subid>]

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);
        verify_char(input, b'"', &mut inpos)?;

        // read "subid" string into buffer
        let (_inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer[..])?;

        // consider as a &str
        let subid = unsafe { std::str::from_utf8_unchecked(&self.buffer[..outlen]) };

        // If we have that subscription
        let reply = if self.subscriptions.contains_key(subid) {
            // Remove it, and let them know
            self.subscriptions.remove(subid);
            NostrReply::Closed(subid, "".to_owned())
        } else {
            NostrReply::Notice(format!("no such subscription id: {}", subid))
        };
        self.websocket.send(Message::text(reply.as_json())).await?;
        Ok(())
    }

    pub async fn auth(&mut self, _msg: String, __inpos: usize) -> Result<(), Error> {
        unimplemented!()
    }
}
