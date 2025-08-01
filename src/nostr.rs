use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::neg_storage::NegentropyStorageVector;
use crate::reply::{NostrReply, NostrReplyPrefix};
use crate::WebSocketService;
use hyper_tungstenite::tungstenite::Message;
use negentropy::Negentropy;
use pocket_db::ScreenResult;
use pocket_types::json::{eat_whitespace, json_unescape, verify_char};
use pocket_types::{read_hex, Event, Filter, Hll8, Kind, OwnedFilter, Pubkey, Time};
use url::Url;

impl WebSocketService {
    pub async fn handle_nostr_message(&mut self, msg: &str) -> Result<(), Error> {
        // If the msg is large, grow the session buffer
        // (it will be freed when they disconnect)
        if msg.len() > 4096 {
            let newlen = 4096 * ((msg.len() / 4096) + 1);
            self.buffer.resize(newlen, 0);
        }

        log::trace!(target: "Client", "{}: {}", self.peer, msg);

        let input = msg.as_bytes();
        let mut inpos = 0;
        eat_whitespace(input, &mut inpos);
        verify_char(input, b'[', &mut inpos)?;
        eat_whitespace(input, &mut inpos);
        verify_char(input, b'"', &mut inpos)?;
        if &input[inpos..inpos + 4] == b"REQ\"" {
            self.req(msg, inpos + 4, false).await?;
        } else if &input[inpos..inpos + 6] == b"COUNT\"" {
            self.req(msg, inpos + 6, true).await?;
        } else if &input[inpos..inpos + 6] == b"EVENT\"" {
            self.event(msg, inpos + 6).await?;
        } else if &input[inpos..inpos + 6] == b"CLOSE\"" {
            self.close(msg, inpos + 6).await?;
        } else if &input[inpos..inpos + 5] == b"AUTH\"" {
            self.auth(msg, inpos + 5).await?;
        } else if &input[inpos..inpos + 9] == b"NEG-OPEN\"" {
            self.neg_open(msg, inpos + 9).await?;
        } else if &input[inpos..inpos + 8] == b"NEG-MSG\"" {
            self.neg_msg(msg, inpos + 8).await?;
        } else if &input[inpos..inpos + 10] == b"NEG-CLOSE\"" {
            self.neg_close(msg, inpos + 10).await?;
        } else {
            log::warn!(target: "Client", "{}: Received unhandled text message: {}", self.peer, msg);
            let reply = NostrReply::Notice("Command unrecognized".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
        }

        Ok(())
    }

    pub async fn req(&mut self, msg: &str, mut inpos: usize, count: bool) -> Result<(), Error> {
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
        let subid =
            unsafe { String::from_utf8_unchecked(self.buffer[outpos..outpos + outlen].to_owned()) };
        outpos += outlen;
        verify_char(input, b'"', &mut inpos)?; // FIXME: json_unescape should eat the closing quote

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

            filters.push(filter.to_owned());
        }

        if let Err(e) = self.req_inner(&subid, filters, count).await {
            let reply = match e.inner {
                ChorusError::TooManySubscriptions => {
                    let max_subscriptions = GLOBALS.config.read().max_subscriptions;
                    NostrReply::Closed(
                        &subid,
                        NostrReplyPrefix::Blocked,
                        format!(
                            "No more than {max_subscriptions} subscriptions are allowed at any one time"
                        ),
                    )
                }
                ChorusError::Scraper => {
                    NostrReply::Closed(&subid, NostrReplyPrefix::Invalid, format!("{}", e.inner))
                }
                _ => NostrReply::Closed(&subid, NostrReplyPrefix::Error, format!("{}", e.inner)),
            };
            self.send(Message::text(reply.as_json()?)).await?;
            Err(e)
        } else {
            Ok(())
        }
    }

    async fn req_inner(
        &mut self,
        subid: &String,
        filters: Vec<OwnedFilter>,
        count: bool,
    ) -> Result<(), Error> {
        let max_subscriptions = GLOBALS.config.read().max_subscriptions;
        if self.subscriptions.len() >= max_subscriptions {
            return Err(ChorusError::TooManySubscriptions.into());
        }

        let authorized_user = self.authed_as.iter().any(|u| crate::is_authorized_user(*u));

        if self.authed_as.is_empty() {
            for filter in filters.iter() {
                // If any DM kinds were requested, complain.
                // But if NO kinds were requested, we will just silently not return DMs (elsewhere)
                if filter
                    .kinds()
                    .any(|k| k.as_u16() == 4 || k.as_u16() == 1059)
                {
                    // They need to AUTH first to request DMs
                    let reply = NostrReply::Closed(
                        subid,
                        NostrReplyPrefix::AuthRequired,
                        "DM kinds were included in the filters".to_owned(),
                    );
                    self.send(Message::text(reply.as_json()?)).await?;
                    return Ok(());
                }
            }
        }

        let completes = filters.iter().all(|f| f.completes());

        let mut redacted: bool = false;

        // NOTE on private events (DMs, GiftWraps)
        // As seen above, we will send CLOSED auth-required if they ask for DMs and are not
        // AUTHed yet.
        // But we never send 'restricted'. We don't analyze the filter far enough to know.
        // Instead we rely on screen_outgoing_event() to remove events they shouldn't see.

        // Serve events matching subscription
        {
            let mut events: Vec<&Event> = Vec::new();

            for filter in filters.iter() {
                let screen = |event: &Event| -> ScreenResult {
                    let event_flags = event_flags(event, self.authed_as.as_slice());
                    screen_outgoing_event(event, &event_flags, authorized_user)
                };
                let (filter_events, was_redacted) = {
                    let config = &*GLOBALS.config.read();
                    GLOBALS.store.get().unwrap().find_events(
                        filter,
                        config.allow_scraping,
                        config.allow_scrape_if_limited_to,
                        config.allow_scrape_if_max_seconds,
                        screen,
                    )?
                };
                events.extend(filter_events);
                redacted = redacted || was_redacted;
            }

            // sort
            events.sort_by_key(|e| std::cmp::Reverse(e.created_at()));

            // dedup
            events.dedup();

            if count {
                // HyperLogLog count
                let mut opthll: Option<Hll8> = None;
                if filters.len() == 1 {
                    if let Ok(Some(offset)) = filters[0].hyperloglog_offset() {
                        let mut hll8 = Hll8::new();
                        for event in events.iter() {
                            hll8.add_element(event.pubkey().as_bytes(), offset)?;
                        }
                        opthll = Some(hll8);
                    }
                }
                let reply = NostrReply::Count(subid, events.len(), opthll);
                self.send(Message::text(reply.as_json()?)).await?;
            } else {
                for event in events.drain(..) {
                    let reply = NostrReply::Event(subid, event);
                    self.send(Message::text(reply.as_json()?)).await?;
                }

                // New policy Feb 2025: Redactions trigger a "CLOSED: auth-required" because
                // some clients will not AUTH otherwise.
                // (But we also already sent partial results, which I think is good)
                if redacted {
                    // They need to AUTH first
                    let reply = NostrReply::Closed(
                        subid,
                        NostrReplyPrefix::AuthRequired,
                        "At least one matching event requires AUTH".to_owned(),
                    );
                    self.send(Message::text(reply.as_json()?)).await?;
                    return Ok(());
                }

                if completes {
                    // Closed
                    let reply = NostrReply::Closed(subid, NostrReplyPrefix::None, "".to_owned());
                    self.send(Message::text(reply.as_json()?)).await?;
                } else {
                    // EOSE
                    let reply = NostrReply::Eose(subid);
                    self.send(Message::text(reply.as_json()?)).await?;
                }
            }
        }

        if !count && !completes {
            // Store subscription
            self.subscriptions.insert(subid.to_owned(), filters);

            log::debug!(
                target: "Client",
                "{}: new subscription \"{subid}\", {} total",
                self.peer,
                self.subscriptions.len()
            );
        }

        Ok(())
    }

    pub async fn event(&mut self, msg: &str, mut inpos: usize) -> Result<(), Error> {
        const PERSONAL_MSG: &str = "this personal relay only accepts events related to its users";

        let input = msg.as_bytes();

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        // Read the event into the session buffer
        let (_incount, event) = Event::from_json(&input[inpos..], &mut self.buffer)?;
        let id = event.id();

        if let Err(e) = self.event_inner().await {
            let reply = match e.inner {
                ChorusError::AuthRequired => NostrReply::Ok(
                    id,
                    false,
                    NostrReplyPrefix::AuthRequired,
                    PERSONAL_MSG.to_owned(),
                ),
                ChorusError::EventIsInvalid(ref why) => {
                    log::error!(target: "Client", "{}: {}", self.peer, e);
                    NostrReply::Ok(id, false, NostrReplyPrefix::Invalid, why.to_string())
                }
                ChorusError::Restricted => {
                    log::error!(target: "Client", "{}: {}", self.peer, e);
                    NostrReply::Ok(
                        id,
                        false,
                        NostrReplyPrefix::Restricted,
                        PERSONAL_MSG.to_owned(),
                    )
                }
                ChorusError::BannedEvent => NostrReply::Ok(
                    id,
                    false,
                    NostrReplyPrefix::Blocked,
                    "Event has been banned".to_string(),
                ),
                ChorusError::BannedUser => NostrReply::Ok(
                    id,
                    false,
                    NostrReplyPrefix::Blocked,
                    "Author has been banned".to_string(),
                ),
                ChorusError::PocketDb(ref pe) => match pe.inner {
                    pocket_db::InnerError::Deleted => NostrReply::Ok(
                        id,
                        false,
                        NostrReplyPrefix::Blocked,
                        "That event is deleted".to_string(),
                    ),
                    pocket_db::InnerError::Duplicate => {
                        NostrReply::Ok(id, true, NostrReplyPrefix::Duplicate, "".to_string())
                    }
                    _ => NostrReply::Ok(id, false, NostrReplyPrefix::Error, format!("{}", e.inner)),
                },
                _ => NostrReply::Ok(id, false, NostrReplyPrefix::Error, format!("{}", e.inner)),
            };
            self.send(Message::text(reply.as_json()?)).await?;
            Err(e)
        } else {
            let reply = NostrReply::Ok(id, true, NostrReplyPrefix::None, "".to_string());
            self.send(Message::text(reply.as_json()?)).await?;
            Ok(())
        }
    }

    async fn event_inner(&mut self) -> Result<(), Error> {
        let authorized_user = self.authed_as.iter().any(|u| crate::is_authorized_user(*u));

        // Delineate the event back out of the session buffer
        let event = unsafe { Event::delineate(&self.buffer)? };

        let event_flags = event_flags(event, self.authed_as.as_slice());

        if GLOBALS.config.read().verify_events {
            // Verify the event is valid (id is hash, signature is valid)
            if let Err(e) = event.verify() {
                return Err(ChorusError::EventIsInvalid(format!("{}", e.inner)).into());
            }
        }

        // Handle Request to Vanish events
        if event.kind() == Kind::from(62) {
            if let Ok(true) = verify_relay_tag(event, true) {
                // Erase their events (and giftwraps to them)
                GLOBALS.store.get().unwrap().vanish(event)?;

                // Add their pubkey to the blocklist so their events cannot come back
                crate::mark_pubkey_approval(event.pubkey(), false)?;
            }

            return Ok(());
        }

        // Screen the event to see if we are willing to accept it
        if !screen_incoming_event(event, event_flags, authorized_user).await? {
            if self.authed_as.is_empty() {
                return Err(ChorusError::AuthRequired.into());
            } else {
                return Err(ChorusError::Restricted.into());
            }
        }

        // Store and index the event
        let offset = GLOBALS.store.get().unwrap().store_event(event)?;
        GLOBALS.new_events.send(offset)?; // advertise the new event

        Ok(())
    }

    pub async fn close(&mut self, msg: &str, mut inpos: usize) -> Result<(), Error> {
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
        if self.subscriptions.contains_key(subid) {
            // Remove it
            self.subscriptions.remove(subid);

            // Don't send a CLOSED because there is no valid prefix for this kind of
            // message, and clients just presume it was closed.
            /*
            let reply = NostrReply::Closed(subid, NostrReplyPrefix::None, "".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
             */

            Ok(())
        } else {
            Err(ChorusError::NoSuchSubscription.into())
        }
    }

    pub async fn auth(&mut self, msg: &str, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        // Read the event into the session buffer
        let (_incount, event) = Event::from_json(&input[inpos..], &mut self.buffer)?;
        let id = event.id();

        // Always return an OK message, based on the results of our auth_inner
        if let Err(e) = self.auth_inner().await {
            let reply = match e.inner {
                ChorusError::AuthFailure(_) => {
                    NostrReply::Ok(id, false, NostrReplyPrefix::Invalid, format!("{}", e.inner))
                }
                _ => NostrReply::Ok(id, false, NostrReplyPrefix::Error, format!("{}", e.inner)),
            };
            self.send(Message::text(reply.as_json()?)).await?;
            Err(e)
        } else {
            let reply = NostrReply::Ok(id, true, NostrReplyPrefix::None, "".to_string());
            self.send(Message::text(reply.as_json()?)).await?;
            Ok(())
        }
    }

    async fn auth_inner(&mut self) -> Result<(), Error> {
        // Delineate the event back out of the session buffer
        let event = unsafe { Event::delineate(&self.buffer)? };

        // Verify the event (even if config.verify_events is off, because this is
        // strictly necessary for AUTH)
        event.verify()?;

        // Verify the event is the right kind
        if event.kind() != Kind::from(22242) {
            return Err(ChorusError::AuthFailure("Wrong event kind".to_string()).into());
        }

        // Verify the relay tag
        let relay_ok = match verify_relay_tag(event, false) {
            Ok(b) => b,
            Err(e) => return Err(ChorusError::AuthFailure(format!("{e}")).into()),
        };
        if !relay_ok {
            return Err(ChorusError::AuthFailure("relay is wrong".to_string()).into());
        }

        // Verify the challenge tag
        let challenge_ok = match verify_challenge_tag(event, self.challenge.as_bytes()) {
            Ok(b) => b,
            Err(e) => return Err(ChorusError::AuthFailure(format!("{e}")).into()),
        };
        if !challenge_ok {
            return Err(ChorusError::AuthFailure("challenge is wrong".to_string()).into());
        }

        // Verify the created_at timestamp is within reason
        let timediff = (Time::now().as_u64() as i64).abs_diff(event.created_at().as_u64() as i64);
        if timediff > 600 {
            return Err(
                ChorusError::AuthFailure("Time is more than 10 minutes off".to_string()).into(),
            );
        }

        // They are now authenticated
        self.authed_as.push(event.pubkey());

        Ok(())
    }

    pub async fn neg_open(&mut self, msg: &str, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        // ["NEG-OPEN", "<subid>", "<filter>", "<hex-message>"]

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        let mut outpos = 0;

        // Read the subid into the session buffer
        let subid = {
            verify_char(input, b'"', &mut inpos)?;
            let (inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer[outpos..])?;
            inpos += inlen;
            let subid = unsafe {
                String::from_utf8_unchecked(self.buffer[outpos..outpos + outlen].to_owned())
            };
            outpos += outlen;
            verify_char(input, b'"', &mut inpos)?; // FIXME: json_unescape should eat the closing quote
            subid
        };

        self.negentropy_sub = Some(subid.clone());

        if !GLOBALS.config.read().enable_negentropy {
            let reply =
                NostrReply::NegErr(&subid, "blocked: Negentropy sync is disabled".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        }

        // Read the filter into the session buffer
        let filter = {
            eat_whitespace(input, &mut inpos);
            verify_char(input, b',', &mut inpos)?;
            // whitespace after the comma is handled within Filter::from_json
            let (incount, outcount, filter) =
                Filter::from_json(&input[inpos..], &mut self.buffer[outpos..])?;
            inpos += incount;
            outpos += outcount;
            filter.to_owned()
        };

        // Read the negentropy message
        let incoming_msg = {
            eat_whitespace(input, &mut inpos);
            verify_char(input, b',', &mut inpos)?;
            eat_whitespace(input, &mut inpos);
            verify_char(input, b'"', &mut inpos)?;
            let (inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer[outpos..])?;
            inpos += inlen;
            verify_char(input, b'"', &mut inpos)?;
            let mut msg = vec![0; outlen / 2];
            read_hex!(&self.buffer[outpos..outpos + outlen], &mut msg, outlen / 2)?;
            //outpos += outlen;
            msg
        };

        // NEG-ERR if the message was empty
        if incoming_msg.is_empty() {
            let reply = NostrReply::NegErr(&subid, "error: Empty negentropy message".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        }

        // If the version is too high, respond with our version number
        if incoming_msg[0] != 0x61 {
            let reply = NostrReply::NegMsg(&subid, vec![0x61]);
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        }

        let authorized_user = self.authed_as.iter().any(|u| crate::is_authorized_user(*u));

        // Find all matching events
        let mut events: Vec<&Event> = Vec::new();
        let screen = |event: &Event| -> ScreenResult {
            let event_flags = event_flags(event, self.authed_as.as_slice());
            screen_outgoing_event(event, &event_flags, authorized_user)
        };
        let (filter_events, _redacted) = {
            let config = &*GLOBALS.config.read();
            GLOBALS.store.get().unwrap().find_events(
                &filter,
                config.allow_scraping || config.allow_scrape_if_negentropy,
                config.allow_scrape_if_limited_to,
                config.allow_scrape_if_max_seconds,
                screen,
            )?
        };
        events.extend(filter_events);
        events.sort_by(|a, b| {
            a.created_at()
                .cmp(&b.created_at())
                .then(a.id().cmp(&b.id()))
        });
        events.dedup();

        let mut nsv = NegentropyStorageVector::with_capacity(events.len());
        for event in &events {
            let id = negentropy::Id::from_slice(event.id().as_slice())?;
            let time = event.created_at().as_u64();
            nsv.insert(time, id)?;
        }
        nsv.seal()?;

        // Save the matching events under the subscription Id
        self.neg_subscriptions.insert(subid.clone(), nsv);

        // Look it up again immediately
        let Some(nsv) = self.neg_subscriptions.get(&subid) else {
            return Err(ChorusError::General(
                "NEG-OPEN inserted data is immediately missing!".to_owned(),
            )
            .into());
        };

        let mut neg = Negentropy::owned(nsv, 1024 * 1024)?; // websocket frame size limit
        match neg.reconcile(&incoming_msg) {
            Ok(response) => {
                let reply = NostrReply::NegMsg(&subid, response);
                self.send(Message::text(reply.as_json()?)).await?;
            }
            Err(e) => {
                let reply = NostrReply::NegErr(&subid, format!("{e}"));
                self.send(Message::text(reply.as_json()?)).await?;
            }
        }

        Ok(())
    }

    pub async fn neg_msg(&mut self, msg: &str, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        // ["NEG-MSG", "<subid>", "<hex-message>"]

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        let mut outpos = 0;

        // Read the subid into the session buffer
        let subid = {
            verify_char(input, b'"', &mut inpos)?;
            let (inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer[outpos..])?;
            inpos += inlen;
            let subid = unsafe {
                String::from_utf8_unchecked(self.buffer[outpos..outpos + outlen].to_owned())
            };
            outpos += outlen;
            verify_char(input, b'"', &mut inpos)?; // FIXME: json_unescape should eat the closing quote
            subid
        };

        self.negentropy_sub = Some(subid.clone());

        if !GLOBALS.config.read().enable_negentropy {
            let reply =
                NostrReply::NegErr(&subid, "blocked: Negentropy sync is disabled".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        }

        // Read the negentropy message
        let incoming_msg = {
            eat_whitespace(input, &mut inpos);
            verify_char(input, b',', &mut inpos)?;
            eat_whitespace(input, &mut inpos);
            verify_char(input, b'"', &mut inpos)?;
            let (inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer[outpos..])?;
            inpos += inlen;
            verify_char(input, b'"', &mut inpos)?;
            let mut msg = vec![0; outlen / 2];
            read_hex!(&self.buffer[outpos..outpos + outlen], &mut msg, outlen / 2)?;
            // outpos += outlen;
            msg
        };

        // NEG-ERR if the message was empty
        if incoming_msg.is_empty() {
            let reply = NostrReply::NegErr(&subid, "error: Empty negentropy message".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        }

        // If the version is too high, return an error (version negotiation should
        // have already happened in NEG-OPEN)
        if incoming_msg[0] != 0x61 {
            let reply = NostrReply::NegErr(&subid, "Version mismatch".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        }

        // Look up the events we have
        let Some(nsv) = self.neg_subscriptions.get(&subid) else {
            let reply = NostrReply::NegErr(&subid, "Subscription not found".to_owned());
            self.send(Message::text(reply.as_json()?)).await?;
            return Ok(());
        };

        let mut neg = Negentropy::owned(nsv, 1024 * 1024)?; // websocket frame size limit
        match neg.reconcile(&incoming_msg) {
            Ok(response) => {
                let reply = NostrReply::NegMsg(&subid, response);
                self.send(Message::text(reply.as_json()?)).await?;
            }
            Err(e) => {
                let reply = NostrReply::NegErr(&subid, format!("{e}"));
                self.send(Message::text(reply.as_json()?)).await?;
            }
        }

        Ok(())
    }

    pub async fn neg_close(&mut self, msg: &str, mut inpos: usize) -> Result<(), Error> {
        let input = msg.as_bytes();

        // ["NEG-CLOSE", "<subid>"]

        eat_whitespace(input, &mut inpos);
        verify_char(input, b',', &mut inpos)?;
        eat_whitespace(input, &mut inpos);

        // Read the subid into the session buffer
        let subid = {
            verify_char(input, b'"', &mut inpos)?;
            let (inlen, outlen) = json_unescape(&input[inpos..], &mut self.buffer)?;
            inpos += inlen;
            let subid = unsafe { String::from_utf8_unchecked(self.buffer[..outlen].to_owned()) };
            verify_char(input, b'"', &mut inpos)?; // FIXME: json_unescape should eat the closing quote
            subid
        };

        self.negentropy_sub = Some(subid.clone());

        // Close the subscription
        self.neg_subscriptions.remove(&subid);

        // No need to reply to the client
        Ok(())
    }
}

async fn screen_incoming_event(
    event: &Event,
    event_flags: EventFlags,
    authorized_user: bool,
) -> Result<bool, Error> {
    // Accept anything from authenticated authorized users
    // We do this before checking moderation since authorized overrides moderation
    if authorized_user {
        return Ok(true);
    }

    // Reject if event approval is false
    if let Some(false) = crate::get_event_approval(event.id())? {
        return Err(ChorusError::BannedEvent.into());
    }

    // Reject if pubkey approval is false
    if let Some(false) = crate::get_pubkey_approval(event.pubkey())? {
        return Err(ChorusError::BannedUser.into());
    }

    // If the event has a '-' tag, require the user to be AUTHed and match
    // the event author
    for mut tag in event.tags()?.iter() {
        if tag.next() == Some(b"-") {
            // The event is protected. Only accept if user is AUTHed as the event author
            if !event_flags.author_is_current_user {
                return Err(ChorusError::ProtectedEvent.into());
            }
        }
    }

    // Accept if an open relay
    if GLOBALS.config.read().open_relay {
        return Ok(true);
    }

    // Accept relay lists from anybody
    if GLOBALS.config.read().serve_relay_lists
        && (event.kind() == Kind::from(10002) || event.kind() == Kind::from(10050))
    {
        return Ok(true);
    }

    // Allow if event kind ephemeral
    if event.kind().is_ephemeral() && GLOBALS.config.read().serve_ephemeral {
        return Ok(true);
    }

    // If the author is one of our users, always accept it
    if crate::is_authorized_user(event.pubkey()) {
        return Ok(true);
    }

    // If the event tags one of our users, always accept it
    for mut tag in event.tags()?.iter() {
        if tag.next() == Some(b"p") {
            if let Some(value) = tag.next() {
                if let Ok(pk) = Pubkey::read_hex(value) {
                    if crate::is_authorized_user(pk) {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

pub fn screen_outgoing_event(
    event: &Event,
    event_flags: &EventFlags,
    authorized_user: bool,
) -> ScreenResult {
    // Deny if it is a private event (DM or GiftWrap) and they are neither the recipient
    // nor the author
    // (even for authorized users)
    if event.kind() == Kind::from(4) || event.kind() == Kind::from(1059) {
        if event_flags.tags_current_user || event_flags.author_is_current_user {
            // they are tagged, it is ok
            return ScreenResult::Match;
        } else {
            // they are not tagged
            return ScreenResult::Redacted;
        }
    }

    // Deny (and delete) if it has an expired expiration tag
    // (even for authorized users)
    if matches!(event.is_expired(), Ok(true)) {
        let _ = GLOBALS.store.get().unwrap().remove_event(event.id());
        return ScreenResult::Mismatch;
    }

    let event_approval = crate::get_event_approval(event.id());
    let pubkey_approval = crate::get_pubkey_approval(event.pubkey());

    // Deny if it is marked approval:false (event or pubkey)
    // (even for authorized users)
    // event overrides pubkey
    if let Ok(Some(false)) = event_approval {
        return ScreenResult::Mismatch;
    }
    if let Ok(Some(false)) = pubkey_approval {
        return ScreenResult::Mismatch;
    }

    // Allow if is is marked approval:true (event or pubkey)
    if let Ok(Some(true)) = event_approval {
        return ScreenResult::Match;
    }
    if let Ok(Some(true)) = pubkey_approval {
        return ScreenResult::Match;
    }

    // Allow if we are an open relay
    if GLOBALS.config.read().open_relay {
        return ScreenResult::Match;
    }

    // Allow Relay Lists
    if GLOBALS.config.read().serve_relay_lists
        && (event.kind() == Kind::from(10002) || event.kind() == Kind::from(10050))
    {
        return ScreenResult::Match;
    }

    // Allow if event kind ephemeral
    if event.kind().is_ephemeral() && GLOBALS.config.read().serve_ephemeral {
        return ScreenResult::Match;
    }

    // Allow if an authorized_user is asking
    if authorized_user {
        return ScreenResult::Match;
    }

    // Allow if author is one of our authorized users
    if event_flags.author_is_an_authorized_user {
        return ScreenResult::Match;
    }

    // Do not allow the rest
    ScreenResult::Redacted
}

pub struct EventFlags {
    pub author_is_an_authorized_user: bool,
    pub author_is_current_user: bool,
    pub tags_an_authorized_user: bool,
    pub tags_current_user: bool,
}

pub fn event_flags(event: &Event, authed_as: &[Pubkey]) -> EventFlags {
    let author_is_an_authorized_user = crate::is_authorized_user(event.pubkey());

    let author_is_current_user = authed_as.iter().any(|u| *u == event.pubkey());

    let mut tags_an_authorized_user = false;
    let mut tags_current_user = false;

    if let Ok(tags) = event.tags() {
        for mut tag in tags.iter() {
            if let Some(b"p") = tag.next() {
                if let Some(value) = tag.next() {
                    if let Ok(tagged_pk) = Pubkey::read_hex(value) {
                        if authed_as.contains(&tagged_pk) {
                            tags_current_user = true;
                        }

                        if crate::is_authorized_user(tagged_pk) {
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

fn verify_relay_tag(event: &Event, allow_all_relays: bool) -> Result<bool, Error> {
    for mut tag in event.tags()?.iter() {
        match tag.next() {
            Some(b"relay") => {
                if let Some(value) = tag.next() {
                    if allow_all_relays && value == b"ALL_RELAYS" {
                        return Ok(true);
                    } else {
                        // We check if the URL host matches
                        // (when normalized, puny-encoded IDNA, etc)
                        let utf8value = std::str::from_utf8(value)?;
                        let url = Url::parse(utf8value)?;
                        if let Some(h) = url.host() {
                            if h == GLOBALS.config.read().hostname {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    Ok(false)
}

fn verify_challenge_tag(event: &Event, challenge: &[u8]) -> Result<bool, Error> {
    for mut tag in event.tags()?.iter() {
        match tag.next() {
            Some(b"challenge") => {
                if let Some(value) = tag.next() {
                    if value == challenge {
                        return Ok(true);
                    }
                }
            }
            _ => continue,
        }
    }

    Ok(false)
}
