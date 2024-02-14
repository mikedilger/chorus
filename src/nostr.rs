use crate::error::Error;
use crate::globals::GLOBALS;
use crate::reply::NostrReply;
use crate::types::parse::json_escape::json_unescape;
use crate::types::parse::json_parse::*;
use crate::types::{Event, Filter, Kind, OwnedFilter};
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

    pub async fn req(&mut self, msg: String, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        // ["REQ", <subid>, json-filter, json-filter, ... ]

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        let mut outpos = 0;

        // Read the subid into the session buffer
        verify_char(input, b'"', &mut inpos)?;
        let (inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer[outpos..])?;
        inpos += inlen;
        let subid = unsafe { String::from_utf8_unchecked(self.buffer[outpos..outlen].to_owned()) };
        outpos += outlen;
        verify_char(input, b'"', &mut inpos)?; // FIXME: json_unescape should eat the closing quote

        log::info!("SUBID={}", subid);

        // Read the filter into the session buffer
        let mut filters: Vec<OwnedFilter> = Vec::new();
        loop {
            eat_whitespace(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            verify_char(input, b',', &mut inpos)?;
            // whitespace after the comma is handled within Filter::from_json
            let (incount, outcount, filter) =
                Filter::from_json(&input[inpos..], &mut self.buffer[outpos..])?;
            inpos += incount;
            outpos += outcount;

            let filterbytes = filter.as_bytes().to_owned();
            filters.push(OwnedFilter(filterbytes));
        }

        // Serve events matching subscription
        {
            let mut events: Vec<Event> = Vec::new();
            for filter in filters.iter() {
                let filter_events = GLOBALS
                    .store
                    .get()
                    .unwrap()
                    .find_events(filter.as_filter()?)?;
                events.extend(filter_events)
            }

            // sort
            events.sort_by_key(|e| std::cmp::Reverse(e.created_at()));

            // dedup
            events.dedup();

            for event in events.drain(..) {
                let reply = NostrReply::Event(&subid, event);
                self.websocket.send(Message::text(reply.as_json())).await?;
            }

            // eose
            let reply = NostrReply::Eose(&subid);
            self.websocket.send(Message::text(reply.as_json())).await?;
        }

        // Store subscription
        self.subscriptions.insert(subid, filters);

        Ok(())
    }

    pub async fn event(&mut self, msg: String, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        // Read the event into the session buffer
        let (_incount, event) = Event::from_json(&input[inpos..], &mut self.buffer)?;

        // Check if the event passes muster
        if !validate_event(&event).await? {
            let reply = NostrReply::Ok(
                event.id(),
                false,
                "blocked: this personal relay only accepts events related to its users".to_owned(),
            );
            self.websocket.send(Message::text(reply.as_json())).await?;
            return Ok(());
        }

        // Store and index the event
        let reply = match GLOBALS.store.get().unwrap().store_event(&event) {
            Ok(offset) => {
                GLOBALS.new_events.send(offset)?; // advertise the new event
                NostrReply::Ok(event.id(), true, "".to_owned())
            }
            Err(Error::Duplicate) => NostrReply::Ok(event.id(), true, "duplicate:".to_owned()),
            Err(e) => NostrReply::Ok(event.id(), false, format!("{e}")),
        };

        self.websocket.send(Message::text(reply.as_json())).await?;
        Ok(())
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

async fn validate_event(event: &Event<'_>) -> Result<bool, Error> {
    // FIXME: check signature

    // Accept relay lists from anybody
    if event.kind() == Kind(10002) {
        return Ok(true);
    }

    // If the author is one of our users, always accept it
    if GLOBALS
        .config
        .read()
        .await
        .user_keys
        .contains(&event.pubkey())
    {
        return Ok(true);
    }

    // If the event tags one of our users, always accept it
    for mut tag in event.tags()?.iter() {
        if tag.next() == Some(b"p") {
            if let Some(value) = tag.next() {
                for ukhex in &GLOBALS.config.read().await.user_hex_keys {
                    if value == ukhex.as_bytes() {
                        return Ok(true);
                    }
                }
            }
        }
    }

    // Reject everything else
    Ok(false)
}
