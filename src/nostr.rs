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

        let max_subscriptions = GLOBALS.config.read().await.max_subscriptions;
        if self.subscriptions.len() >= max_subscriptions {
            let reply = NostrReply::Closed(
                &subid,
                NostrReplyPrefix::RateLimited,
                format!(
                    "No more than {max_subscriptions} subscriptions are allowed at any one time"
                ),
            );
            self.websocket.send(Message::text(reply.as_json())).await?;
            return Ok(());
        }

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

        let user = self.user;
        let authorized_user = authorized_user(&user).await;

        // NOTE on private events (DMs, GiftWraps)
        // Most relays check if you are seeking them, and of which pubkey, and if you are
        // not AUTHed as that pubkey you get a 'auth-required', or if you are AUTHed as
        // a different pubkey you get a 'restricted'.
        // We take a different tack. You can ask for these events, and we even load them,
        // but then we filter them out in screen_outgoing_event() and don't send events they
        // aren't supposed to see. This prevents sending errors and having them ask again. It
        // is also faster as we don't have to do any filter analysis at this point in the code.

        // Serve events matching subscription
        {
            let mut events: Vec<Event> = Vec::new();
            for filter in filters.iter() {
                let mut filter_events = GLOBALS
                    .store
                    .get()
                    .unwrap()
                    .find_events(filter.as_filter()?)?;
                for event in filter_events.drain(..) {
                    let event_flags = event_flags(&event, &user).await;
                    if screen_outgoing_event(&event, event_flags, authorized_user) {
                        events.push(event);
                    }
                }
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
        self.subscriptions.insert(subid.to_owned(), filters);

        log::debug!(
            "{}, new subscription \"{subid}\", {} total",
            self.peer,
            self.subscriptions.len()
        );

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
                    NostrReply::Ok(id, true, NostrReplyPrefix::Duplicate, "".to_string())
                }
                ChorusError::Deleted => NostrReply::Ok(
                    id,
                    true,
                    NostrReplyPrefix::None,
                    "That event is deleted".to_string(),
                ),
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
        let user = self.user;
        let authorized_user = authorized_user(&user).await;

        // Delineate the event back out of the session buffer
        let event = Event::delineate(&self.buffer)?;

        let event_flags = event_flags(&event, &user).await;

        if !event_flags.author_is_an_authorized_user || GLOBALS.config.read().await.verify_events {
            // Verify the event is valid (id is hash, signature is valid)
            if let Err(e) = event.verify() {
                return Err(ChorusError::EventIsInvalid(format!("{}", e)).into());
            }
        }

        // Screen the event to see if we are willing to accept it
        if !screen_incoming_event(&event, event_flags, authorized_user).await? {
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
                ChorusError::AuthFailure(s) => {
                    NostrReply::Ok(id, false, NostrReplyPrefix::Invalid, s)
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
            return Err(ChorusError::AuthFailure("Wrong event kind".to_string()).into());
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
                            Err(e) => return Err(ChorusError::AuthFailure(format!("{e}")).into()),
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

        if !challenge_ok {
            return Err(ChorusError::AuthFailure("challenge is wrong".to_string()).into());
        }
        if !relay_ok {
            return Err(ChorusError::AuthFailure("relay is wrong".to_string()).into());
        }

        // Verify the created_at timestamp is within reason
        let timediff = (Time::now().0 as i64).abs_diff(event.created_at().0 as i64);
        if timediff > 600 {
            return Err(
                ChorusError::AuthFailure("Time is more than 10 minutes off".to_string()).into(),
            );
        }

        // They are now authenticated
        self.user = Some(event.pubkey());

        Ok(())
    }
}

async fn screen_incoming_event(
    event: &Event<'_>,
    _event_flags: EventFlags,
    authorized_user: bool,
) -> Result<bool, Error> {
    // Accept anything from authenticated authorized users
    if authorized_user {
        return Ok(true);
    }

    // Accept relay lists from anybody
    if event.kind() == Kind(10002) {
        return Ok(true);
    }

    // Allow if event kind ephemeral
    if event.kind().is_ephemeral() {
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

    Ok(false)
}

fn screen_outgoing_event(
    event: &Event<'_>,
    event_flags: EventFlags,
    authorized_user: bool,
) -> bool {
    // Allow Relay Lists
    if event.kind() == Kind(10002) {
        return true;
    }

    // Allow if event kind ephemeral
    if event.kind().is_ephemeral() {
        return true;
    }

    // Forbid if it is a private event (DM or GiftWrap) and theey are neither the recipient
    // nor the author
    if event.kind() == Kind(4) || event.kind() == Kind(1059) {
        return event_flags.tags_current_user || event_flags.author_is_current_user;
    }

    // Allow if an authorized_user is asking
    if authorized_user {
        return true;
    }

    // Everybody can see events from our authorized users
    if event_flags.author_is_an_authorized_user {
        return true;
    }

    // Do not allow the rest
    false
}

async fn authorized_user(user: &Option<Pubkey>) -> bool {
    match user {
        None => false,
        Some(pk) => GLOBALS.config.read().await.user_keys.contains(pk),
    }
}

pub struct EventFlags {
    pub author_is_an_authorized_user: bool,
    pub author_is_current_user: bool,
    pub tags_an_authorized_user: bool,
    pub tags_current_user: bool,
}

async fn event_flags(event: &Event<'_>, user: &Option<Pubkey>) -> EventFlags {
    let author_is_an_authorized_user = GLOBALS
        .config
        .read()
        .await
        .user_keys
        .contains(&event.pubkey());

    let author_is_current_user = match user {
        None => false,
        Some(pk) => event.pubkey() == *pk,
    };

    let mut tags_an_authorized_user = false;
    let mut tags_current_user = false;

    if let Ok(tags) = event.tags() {
        for mut tag in tags.iter() {
            if let Some(b"p") = tag.next() {
                if let Some(value) = tag.next() {
                    if let Ok(tagged_pk) = Pubkey::read_hex(value) {
                        if let Some(current_user) = user {
                            if *current_user == tagged_pk {
                                tags_current_user = true;
                            }
                        }

                        if GLOBALS.config.read().await.user_keys.contains(&tagged_pk) {
                            tags_an_authorized_user = true;
                        }
                    }
                }
            }
        }
    }

    EventFlags {
        author_is_an_authorized_user,
        author_is_current_user,
        tags_an_authorized_user,
        tags_current_user,
    }
}
