use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::reply::{NostrReply, NostrReplyPrefix};
use crate::types::parse::json_escape::json_unescape;
use crate::types::parse::json_parse::*;
use crate::types::{Event, Filter, Kind, OwnedFilter, Pubkey, Time};
use crate::WebSocketService;
use futures::SinkExt;
use hyper_tungstenite::tungstenite::Message;
use url::Url;

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
        const PERSONAL_MSG: &str = "this personal relay only accepts events related to its users";

        let input = msg.as_bytes();

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        // Read the event into the session buffer
        let (_incount, event) = Event::from_json(&input[inpos..], &mut self.buffer)?;
        let id = event.id();

        let reply = match self.event_inner().await {
            Ok(()) => NostrReply::Ok(id, true, NostrReplyPrefix::None, "".to_string()),
            Err(e) => match e.inner {
                ChorusError::AuthRequired => NostrReply::Ok(
                    id,
                    false,
                    NostrReplyPrefix::AuthRequired,
                    PERSONAL_MSG.to_owned(),
                ),
                ChorusError::Duplicate => {
                    NostrReply::Ok(id, false, NostrReplyPrefix::Duplicate, "".to_string())
                }
                ChorusError::EventIsInvalid(why) => {
                    NostrReply::Ok(id, false, NostrReplyPrefix::Invalid, why)
                }
                ChorusError::Restricted => NostrReply::Ok(
                    id,
                    false,
                    NostrReplyPrefix::Restricted,
                    PERSONAL_MSG.to_owned(),
                ),
                _ => NostrReply::Ok(id, false, NostrReplyPrefix::Error, format!("{}", e)),
            },
        };
        self.websocket.send(Message::text(reply.as_json())).await?;

        Ok(())
    }

    async fn event_inner(&mut self) -> Result<(), Error> {
        // Delineate the event back out of the session buffer
        let event = Event::delineate(&self.buffer)?;

        if GLOBALS.config.read().await.verify_events {
            // Verify the event is valid (id is hash, signature is valid)
            if let Err(e) = event.verify() {
                return Err(ChorusError::EventIsInvalid(format!("{}", e)).into());
            }
        }

        // Screen the event to see if we are willing to accept it
        if !screen_event(&event, self.user).await? {
            if self.user.is_some() {
                return Err(ChorusError::Restricted.into());
            } else {
                return Err(ChorusError::AuthRequired.into());
            }
        }

        // Store and index the event
        let offset = GLOBALS.store.get().unwrap().store_event(&event)?;
        GLOBALS.new_events.send(offset)?; // advertise the new event

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
            NostrReply::Closed(subid, NostrReplyPrefix::None, "".to_owned())
        } else {
            NostrReply::Notice(format!("no such subscription id: {}", subid))
        };
        self.websocket.send(Message::text(reply.as_json())).await?;
        Ok(())
    }

    pub async fn auth(&mut self, msg: String, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        // Read the event into the session buffer
        let (_incount, event) = Event::from_json(&input[inpos..], &mut self.buffer)?;
        let id = event.id();

        // Always return an OK message, based on the results of our auth_inner
        let reply = match self.auth_inner().await {
            Ok(()) => NostrReply::Ok(id, true, NostrReplyPrefix::None, "".to_string()),
            Err(e) => match e.inner {
                ChorusError::AuthFailure => {
                    NostrReply::Ok(id, false, NostrReplyPrefix::Invalid, "".to_string())
                }
                _ => NostrReply::Ok(id, false, NostrReplyPrefix::Error, format!("{}", e)),
            },
        };
        self.websocket.send(Message::text(reply.as_json())).await?;

        Ok(())
    }

    async fn auth_inner(&mut self) -> Result<(), Error> {
        // Delineate the event back out of the session buffer
        let event = Event::delineate(&self.buffer)?;

        // Verify the event (even if config.verify_events is off, because this is
        // strictly necessary for AUTH)
        event.verify()?;

        // Verify the event is the right kind
        if event.kind() != Kind(22242) {
            return Err(ChorusError::AuthFailure.into());
        }

        // Verify the challenge and relay tags
        let mut challenge_ok = false;
        let mut relay_ok = false;
        for mut tag in event.tags()?.iter() {
            match tag.next() {
                Some(b"relay") => {
                    if let Some(value) = tag.next() {
                        // We check if the URL host matches
                        // (when normalized, puny-encoded IDNA, etc)
                        let utf8value = std::str::from_utf8(value)?;
                        let url = match Url::parse(utf8value) {
                            Ok(u) => u,
                            Err(_) => return Err(ChorusError::AuthFailure.into()),
                        };
                        if let Some(h) = url.host() {
                            let theirhost = h.to_owned();
                            if theirhost == GLOBALS.config.read().await.hostname {
                                relay_ok = true;
                            }
                        }
                    }
                }
                Some(b"challenge") => {
                    if let Some(value) = tag.next() {
                        if value == self.challenge.as_bytes() {
                            challenge_ok = true;
                        }
                    }
                }
                None => break,
                _ => continue,
            }
        }

        if !(challenge_ok && relay_ok) {
            return Err(ChorusError::AuthFailure.into());
        }

        // Verify the created_at timestamp is within reason
        let timediff = (Time::now().0 as i64).abs_diff(event.created_at().0 as i64);
        if timediff < 600 {
            return Err(ChorusError::AuthFailure.into());
        }

        // They are now authenticated
        self.user = Some(event.pubkey());

        Ok(())
    }
}

async fn screen_event(event: &Event<'_>, user: Option<Pubkey>) -> Result<bool, Error> {
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

    // If the user is authenticated as one of our users, accept anything
    // that they give us
    if let Some(pk) = user {
        if GLOBALS.config.read().await.user_keys.contains(&pk) {
            return Ok(true);
        }
    }

    // Reject everything else
    Ok(false)
}
