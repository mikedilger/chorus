pub mod config;
pub mod counting_stream;
pub mod error;
pub mod filestore;
pub mod globals;
pub mod ip;
mod neg_storage;
pub mod nostr;
pub mod reply;
pub mod tls;
pub mod web;

use crate::config::{Config, FriendlyConfig};
use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::{HashedIp, HashedPeer, IpData, SessionExit};
use crate::reply::NostrReply;
use futures::{sink::SinkExt, stream::StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_tungstenite::tungstenite;
use hyper_tungstenite::{HyperWebsocket, WebSocketStream};
use hyper_util::rt::TokioIo;
use neg_storage::NegentropyStorageVector;
use pocket_db::{ScreenResult, Store};
use pocket_types::{Id, OwnedFilter, Pubkey};
use speedy::{Readable, Writable};
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::Duration;
use textnonce::TextNonce;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::Message;

/// Serve a single network connection
pub async fn serve<T>(stream: TokioIo<T>, peer: HashedPeer)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Serve the network stream with our http server and our ChorusService
    let service = ChorusService { peer };

    let http1builder = GLOBALS.http1builder.clone();
    let connection = http1builder
        .serve_connection(stream, service)
        .with_upgrades();

    // If our service exits with an error, log the error
    if let Err(he) = connection.await {
        if let Some(src) = he.source() {
            if &*format!("{}", src) == "Transport endpoint is not connected (os error 107)" {
                // do nothing
            } else {
                // Print in detail
                log::error!(target: "Client", "{}: {:?}", peer, src);
            }
        } else {
            // Print in less detail
            let e: Error = he.into();
            log::error!(target: "Client", "{}: {}", peer, e);
        }
    }
}

// This is our per-connection HTTP service
struct ChorusService {
    peer: HashedPeer,
}

impl Service<Request<Incoming>> for ChorusService {
    type Response = Response<BoxBody<Bytes, Self::Error>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    // This is called for each HTTP request made by the client
    // NOTE: it is not called for each websocket message once upgraded.
    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let mut hashed_peer = self.peer;

        let failvalue =
            |c: ChorusError| -> Self::Future { Box::pin(futures::future::ready(Err(c.into()))) };

        if GLOBALS.config.read().chorus_is_behind_a_proxy {
            // If chorus is behind a proxy that sets an "X-Real-Ip" header, we use
            // that ip address instead (otherwise their log file will just give the proxy IP
            // for every peer)
            //
            // This header must be found and be valid for us to proceed
            if let Some(rip) = req.headers().get("x-real-ip") {
                if let Ok(ripstr) = rip.to_str() {
                    if let Ok(ipaddr) = ripstr.parse::<IpAddr>() {
                        let hashed_ip = HashedIp::new(ipaddr);
                        hashed_peer = HashedPeer::from_parts(hashed_ip, hashed_peer.port());
                    } else {
                        return failvalue(ChorusError::BadRealIpHeader(ripstr.to_owned()));
                    }
                } else {
                    return failvalue(ChorusError::BadRealIpHeaderCharacters);
                }
            } else {
                return failvalue(ChorusError::RealIpHeaderMissing);
            }

            // Possibly IP block late (if behind a proxy)
            if GLOBALS.config.read().enable_ip_blocking {
                if let Ok(ip_data) =
                    crate::get_ip_data(GLOBALS.store.get().unwrap(), hashed_peer.ip())
                {
                    if ip_data.is_banned() {
                        log::debug!(target: "Client",
                                    "{}: Blocking reconnection until {}",
                                    hashed_peer.ip(),
                                    ip_data.ban_until);
                        return failvalue(ChorusError::BlockedIp);
                    }
                }
            }
        }

        Box::pin(async move { handle_http_request(hashed_peer, req).await })
    }
}

async fn handle_http_request(
    peer: HashedPeer,
    mut request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    let ua = match request.headers().get("user-agent") {
        Some(ua) => ua.to_str().unwrap_or("NON-UTF8-HEADER").to_owned(),
        None => "(no user-agent)".to_owned(),
    };

    let origin = match request.headers().get("origin") {
        Some(o) => o.to_str().unwrap_or("NON-UTF8-HEADER").to_owned(),
        None => "(no origin)".to_owned(),
    };

    let max_conn = GLOBALS.config.read().max_connections_per_ip;
    if let Some(cur) = GLOBALS.num_connections_per_ip.get(&peer.ip()) {
        if *cur.value() >= max_conn {
            return Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Empty::new().map_err(|e| e.into()).boxed())?);
        }
    }

    if hyper_tungstenite::is_upgrade_request(&request) {
        // If the client asks for a Sec-Websocket-Protocol that we don't understand,
        // Respond with 501 Not Implemented
        let maybe_protocol: Option<String> = match request.headers().get("sec-websocket-protocol") {
            None => None,
            Some(hv) => hv.to_str().ok().map(|s| s.to_owned()),
        };
        if let Some(ref protocol) = maybe_protocol {
            let mut we_can_do_nostr: bool = false;
            for option in protocol.split(',') {
                if option.trim() == "nostr" {
                    we_can_do_nostr = true;
                    break;
                }
            }
            if !we_can_do_nostr {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_IMPLEMENTED)
                    .body(Empty::new().map_err(|e| e.into()).boxed())?);
            }
        }

        let web_socket_config = WebSocketConfig {
            max_write_buffer_size: 1024 * 1024,  // 1 MB
            max_message_size: Some(1024 * 1024), // 1 MB
            max_frame_size: Some(1024 * 1024),   // 1 MB
            ..Default::default()
        };

        let (mut response, websocket) =
            hyper_tungstenite::upgrade(&mut request, Some(web_socket_config))?;

        // If the client asked for Sec-Websocket-Protocol, then we already checked it must
        // have asked for 'nostr', so send that as a response header
        if maybe_protocol.is_some() {
            response.headers_mut().insert(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::header::HeaderValue::from_static("nostr"),
            );
        }

        // Start the websocket thread
        tokio::spawn(async move { websocket_thread(peer, websocket, origin, ua).await });

        Ok(response.map(|body| body.map_err(|e| e.into()).boxed()))
    } else {
        web::serve_http(peer, request).await
    }
}

async fn websocket_thread(peer: HashedPeer, websocket: HyperWebsocket, origin: String, ua: String) {
    // Await the websocket upgrade process
    match websocket.await {
        Ok(websocket) => {
            // Build a websocket service
            let mut ws_service = WebSocketService {
                peer,
                subscriptions: HashMap::new(),
                neg_subscriptions: HashMap::new(),
                // We start with a 1-page buffer, and grow it if needed.
                buffer: vec![0; 4096],
                websocket,
                last_message: Instant::now(),
                burst_tokens: GLOBALS.config.read().throttling_burst,
                challenge: TextNonce::new().into_string(),
                user: None,
                error_punishment: 0.0,
                replied: false,
                negentropy_sub: None,
            };

            // Increment connection count
            let old_num_websockets = GLOBALS.num_connections.fetch_add(1, Ordering::SeqCst);

            // Increment per-ip connection count
            GLOBALS
                .num_connections_per_ip
                .entry(peer.ip())
                .and_modify(|count| *count += 1)
                .or_insert(1);

            // we cheat somewhat and log these websocket open and close messages
            // as server messages
            log::info!(
                target: "Server",
                "{}: TOTAL={}, New Connection: {}, {}",
                peer,
                old_num_websockets + 1,
                origin,
                ua,
            );

            // Everybody gets a ban on disconnect to prevent rapid reconnection
            let mut session_exit: SessionExit = SessionExit::Ok;
            let mut msg = "Closed";

            // Handle the websocket
            if let Err(e) = ws_service.handle_websocket_stream().await {
                match e.inner {
                    ChorusError::Tungstenite(tungstenite::error::Error::Protocol(
                        tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                    )) => {
                        // So they disconnected ungracefully.
                        // No big deal, still SessionExit::Ok
                        msg = "Reset";
                    }
                    ChorusError::Tungstenite(tungstenite::error::Error::Io(ref ioerror)) => {
                        match ioerror.kind() {
                            std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof => {
                                // no biggie.
                                msg = "Reset";
                            }
                            _ => {
                                log::error!(target: "Client", "{}: {}", peer, e);
                                session_exit = SessionExit::ErrorExit;
                                msg = "Error Exited";
                            }
                        }
                    }
                    ChorusError::ErrorClose => {
                        session_exit = SessionExit::TooManyErrors;
                        msg = "Errored Out";
                    }
                    ChorusError::RateLimitExceeded => {
                        session_exit = SessionExit::TooManyErrors; // close enough for now.
                        msg = "Rate Limit Exceeded";
                    }
                    ChorusError::TimedOut => {
                        session_exit = SessionExit::Timeout;
                        msg = "Timed Out (with no subscriptions)";
                    }
                    ChorusError::Io(_) => {
                        // Usually "Connection reset by peer" but any I/O error
                        // isn't a big deal.
                        msg = "Reset";
                    }
                    _ => {
                        log::error!(target: "Client", "{}: {}", peer, e);
                        session_exit = SessionExit::ErrorExit;
                        msg = "Error Exited";
                    }
                }
            }

            // Decrement connection count
            let old_num_websockets = GLOBALS.num_connections.fetch_sub(1, Ordering::SeqCst);

            // Decrement per-ip connection count
            match GLOBALS.num_connections_per_ip.get_mut(&peer.ip()) {
                Some(mut refmut) => {
                    if *refmut.value_mut() > 0 {
                        *refmut.value_mut() -= 1;
                    } else {
                        unreachable!("The connection should be in the map")
                    }
                }
                None => unreachable!("The connection count should be greater than zero"),
            };

            // Update ip data (including ban time)
            let minimum_ban_seconds = GLOBALS.config.read().minimum_ban_seconds;
            let ban_seconds = if GLOBALS.config.read().enable_ip_blocking {
                let mut ban_seconds = 0;
                if let Ok(mut ip_data) = get_ip_data(GLOBALS.store.get().unwrap(), peer.ip()) {
                    ban_seconds =
                        ip_data.update_on_session_close(session_exit, minimum_ban_seconds);
                    let _ = update_ip_data(GLOBALS.store.get().unwrap(), peer.ip(), &ip_data);
                }
                ban_seconds
            } else {
                minimum_ban_seconds
            };

            // we cheat somewhat and log these websocket open and close messages
            // as server messages
            log::info!(
                target: "Server",
                "{}: TOTAL={}, {}, ban={}s",
                peer,
                old_num_websockets - 1,
                msg,
                ban_seconds
            );
        }
        Err(e) => {
            log::error!(target: "Client", "{}: {}", peer, e);
        }
    }
}

struct WebSocketService {
    pub peer: HashedPeer,
    pub subscriptions: HashMap<String, Vec<OwnedFilter>>,
    pub neg_subscriptions: HashMap<String, NegentropyStorageVector>,
    pub buffer: Vec<u8>,
    pub websocket: WebSocketStream<TokioIo<Upgraded>>,
    pub last_message: Instant,
    pub burst_tokens: usize,
    pub challenge: String,
    pub user: Option<Pubkey>,
    pub error_punishment: f32,
    pub replied: bool,
    pub negentropy_sub: Option<String>,
}

impl WebSocketService {
    async fn send(&mut self, m: Message) -> Result<(), Error> {
        log::trace!(target: "Client", "{}: {}", self.peer, m);

        // Throttling: we consume burst tokens, but we do not throttle on output
        if m.len() > self.burst_tokens {
            log::info!(target: "Client", "{}: Rate limited exceeded", self.peer);
            let reply = NostrReply::Notice("Rate limit exceeded.".into());
            self.websocket.send(Message::text(reply.as_json())).await?;
            let error = ChorusError::RateLimitExceeded;
            self.error_punishment += error.punishment();
            return Err(error.into());
        } else {
            self.burst_tokens -= m.len();
        }

        self.replied = true;
        Ok(self.websocket.send(m).await?)
    }

    async fn wsclose(&mut self, error: Error) -> Result<(), Error> {
        use tungstenite::protocol::frame::coding::CloseCode;
        use tungstenite::protocol::frame::CloseFrame;

        let (code, reason) = match &error.inner {
            ChorusError::TimedOut => (CloseCode::Policy, Cow::Borrowed("timed out")),
            ChorusError::ShuttingDown => (CloseCode::Restart, Cow::Borrowed("restarting")),
            ChorusError::BannedUser | ChorusError::BlockedIp => {
                (CloseCode::Policy, Cow::Borrowed("banned"))
            }
            e => (CloseCode::Error, Cow::Owned(format!("{}", e))),
        };

        let close_frame = CloseFrame { code, reason };

        // NOTE: This is the same as sending Message::Close(..)
        self.websocket.close(Some(close_frame)).await?;

        // Drive to completion
        while (self.websocket.next().await).is_some() {}

        Err(error)
    }

    async fn handle_websocket_stream(&mut self) -> Result<(), Error> {
        // Subscribe to the shutting down channel
        let mut shutting_down = GLOBALS.shutting_down.subscribe();

        // Subscribe to the new_events broadcast channel
        let mut new_events = GLOBALS.new_events.subscribe();

        // Offer AUTH to clients right off the bat
        let reply = NostrReply::Auth(self.challenge.clone());
        self.send(Message::text(reply.as_json())).await?;

        let mut last_message_at = Instant::now();

        let timeout_seconds = GLOBALS.config.read().timeout_seconds;

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let _ = interval.tick().await; // consume the first tick
        tokio::pin!(interval);

        loop {
            tokio::select! {
                instant = interval.tick() => {
                    // Drop them if they have no subscriptions
                    if self.subscriptions.is_empty() && self.neg_subscriptions.is_empty() {
                        // And they are idle for timeout_seconds with no subscriptions
                        if last_message_at + Duration::from_secs(timeout_seconds) < instant {
                            self.wsclose(ChorusError::TimedOut.into()).await?;
                        }
                    }
                }
                message_option = self.websocket.next() => {
                    last_message_at = Instant::now();
                    match message_option {
                        Some(message) => {
                            let message = message?;
                            if let Err(e) = self.handle_websocket_message(message).await {
                                self.wsclose(e).await?;
                            }
                        },
                        None => break, // the websocket is closed
                    }
                },
                offset_result = new_events.recv() => {
                    let offset = offset_result?;
                    self.handle_new_event(offset).await?;
                },
                _r = shutting_down.changed() => {
                    self.wsclose(ChorusError::ShuttingDown.into()).await?;
                },
            }
        }

        Ok(())
    }

    // If the event matches a subscription they have open, send them the event
    async fn handle_new_event(&mut self, new_event_offset: u64) -> Result<(), Error> {
        if self.subscriptions.is_empty() {
            return Ok(());
        }

        let event = GLOBALS
            .store
            .get()
            .unwrap()
            .get_event_by_offset(new_event_offset)?;

        let event_flags = nostr::event_flags(event, &self.user);
        let authorized_user = self.user.map(is_authorized_user).unwrap_or(false);

        'subs: for (subid, filters) in self.subscriptions.iter() {
            for filter in filters.iter() {
                if filter.event_matches(event)? {
                    let screen_result =
                        nostr::screen_outgoing_event(event, &event_flags, authorized_user);
                    if screen_result == ScreenResult::Redacted {
                        // TBD:  Update subscription so the final close can
                        //       let them know there were redactions from
                        //       the post-EOSE data
                    } else if screen_result == ScreenResult::Match {
                        let message = NostrReply::Event(subid, event);
                        // note, this is not currently counted in throttling
                        self.websocket
                            .send(Message::text(message.as_json()))
                            .await?;
                        continue 'subs;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_websocket_message(&mut self, message: Message) -> Result<(), Error> {
        // Throttling
        {
            let (throttling_burst, throttling_bytes_per_second) = {
                let config = GLOBALS.config.read();
                (config.throttling_burst, config.throttling_bytes_per_second)
            };

            // Get (and update) timing
            let elapsed = self.last_message.elapsed();
            self.last_message = Instant::now();

            // Grant new tokens
            let new_tokens = throttling_bytes_per_second * elapsed.as_millis() as usize / 1_000;
            self.burst_tokens += new_tokens;

            // Cap tokens to a maximum
            if self.burst_tokens > throttling_burst {
                self.burst_tokens = throttling_burst;
            }

            // Consume tokens, possibly closing the connection if there are not enough
            if message.len() > self.burst_tokens {
                log::info!(target: "Client", "{}: Rate limited exceeded", self.peer);
                let reply = NostrReply::Notice("Rate limit exceeded.".into());
                self.websocket.send(Message::text(reply.as_json())).await?;
                let error = ChorusError::RateLimitExceeded;
                self.error_punishment += error.punishment();
                return Err(error.into());
            } else {
                self.burst_tokens -= message.len();
            }
        }

        match message {
            Message::Text(msg) => {
                log::trace!(target: "Client", "{}: <= {}", self.peer, msg);
                self.replied = false;
                // This is defined in nostr.rs
                if let Err(e) = self.handle_nostr_message(&msg).await {
                    self.error_punishment += e.inner.punishment();
                    log::error!(target: "Client", "{}: {e}", self.peer);
                    if !matches!(e.inner, ChorusError::AuthRequired) {
                        if msg.len() < 2048 {
                            log::warn!(target: "Client", "{}:   msg was {}", self.peer, msg);
                        } else {
                            log::warn!(target: "Client", "{}:   msg > 2048 (not shown)", self.peer);
                        }
                    }
                    if !self.replied {
                        if let Some(subid) = &self.negentropy_sub {
                            let reply = NostrReply::NegErr(subid, format!("error: {e}"));
                            self.send(Message::text(reply.as_json())).await?;
                        } else {
                            let reply = NostrReply::Notice(format!("error: {}", e.inner));
                            self.send(Message::text(reply.as_json())).await?;
                        }
                    }
                    if self.error_punishment >= 1.0 {
                        let reply = NostrReply::Notice("Closing due to error(s)".into());
                        self.send(Message::text(reply.as_json())).await?;
                        return Err(ChorusError::ErrorClose.into());
                    }
                }
            }
            Message::Binary(msg) => {
                let reply = NostrReply::Notice(
                    "binary messages are not processed by this relay".to_owned(),
                );
                self.send(Message::text(reply.as_json())).await?;
                log::info!(target: "Client",
                    "{}: Received unhandled binary message: {:02X?}",
                    self.peer,
                    msg
                );
            }
            Message::Ping(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                log::debug!(target: "Client", "{}: Received ping message: {:02X?}", self.peer, msg);
            }
            Message::Pong(msg) => {
                log::debug!(target: "Client", "{}: Received pong message: {:02X?}", self.peer, msg);
            }
            Message::Close(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                if let Some(msg) = &msg {
                    log::debug!(target: "Client",
                        "{}: Received websocket close message with code {} and message: {}",
                        self.peer,
                        msg.code,
                        msg.reason
                    );
                } else {
                    log::debug!(
                        target: "Client",
                        "{}: Received websocket close message",
                        self.peer,
                    );
                }
            }
            Message::Frame(_msg) => {
                unreachable!();
            }
        }

        Ok(())
    }
}

/// Print statistics
pub fn print_stats() {
    let mut runtime: u64 = GLOBALS.start_time.elapsed().as_secs();
    if runtime < 1 {
        runtime = 1;
    }
    log::info!(
        target: "Server",
        "Runtime: {} seconds", runtime
    );
    log::info!(
        target: "Server",
        "Inbound: {} bytes ({} B/s)",
        GLOBALS.bytes_inbound.load(Ordering::Relaxed),
        (GLOBALS.bytes_inbound.load(Ordering::Relaxed) as f32) / (runtime as f32)
    );
    log::info!(
        target: "Server",
        "Outbound: {} bytes ({} B/s)",
        GLOBALS.bytes_outbound.load(Ordering::Relaxed),
        (GLOBALS.bytes_outbound.load(Ordering::Relaxed) as f32) / (runtime as f32)
    );
    if let Ok(status) = GLOBALS.store.get().unwrap().stats() {
        log::info!(
            target: "Server",
            "Store: {} event bytes in {} events, {} bytes for the indexes",
            status.event_bytes,
            status.index_stats.i_index_entries,
            status.index_stats.disk_usage
        );
    }
}

/// Load config file
pub fn load_config<P: AsRef<Path>>(config_path: P) -> Result<Config, Error> {
    // Read config file
    let mut file = OpenOptions::new().read(true).open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let friendly_config: FriendlyConfig = toml::from_str(&contents)?;
    let config: Config = friendly_config.into_config()?;
    Ok(config)
}

/// Setup logging
pub fn setup_logging(config: &Config) {
    env_logger::Builder::new()
        .filter_level(config.library_log_level)
        .filter(Some("Server"), config.server_log_level)
        .filter(Some("Client"), config.client_log_level)
        .format_target(true)
        .format_module_path(false)
        .format_timestamp_millis()
        .init();

    log::debug!(target: "Server", "Loaded config file.");
}

/// Setup storage
pub fn setup_store(config: &Config) -> Result<Store, Error> {
    let store = Store::new(
        &config.data_directory,
        vec![
            "approved-events",  // id.as_slice() -> u8(bool)
            "approved-pubkeys", // pubkey.as_slice() -> u8(bool)
            "ip_data",          // HashedIp.0 -> IpData
            "users",            // pubkey.as_slice() -> u8(bool) true if moderator
        ],
    )?;
    Ok(store)
}

/// Get IpData from storage about this remote HashedIp
pub fn get_ip_data(store: &Store, ip: HashedIp) -> Result<IpData, Error> {
    let ip_data = store
        .extra_table("ip_data")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("ip_data")))?;
    let txn = store.read_txn()?;
    let key = &ip.0;
    let bytes = match ip_data.get(&txn, key)? {
        Some(b) => b,
        None => return Ok(Default::default()),
    };
    Ok(IpData::read_from_buffer(bytes)?)
}

/// Get IpData in storage about this remote HashedIp
pub fn update_ip_data(store: &Store, ip: HashedIp, data: &IpData) -> Result<(), Error> {
    let ip_data = store
        .extra_table("ip_data")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("ip_data")))?;
    let mut txn = store.write_txn()?;
    let key = &ip.0;
    let bytes = data.write_to_vec()?;
    ip_data.put(&mut txn, key, &bytes)?;
    txn.commit()?;
    Ok(())
}

/// Dump all IpData from storage
pub fn dump_ip_data(store: &Store) -> Result<Vec<(HashedIp, IpData)>, Error> {
    let ip_data = store
        .extra_table("ip_data")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("ip_data")))?;
    let txn = store.read_txn()?;
    let mut output: Vec<(HashedIp, IpData)> = Vec::new();
    for i in ip_data.iter(&txn)? {
        let (key, val) = i?;
        let hashedip = HashedIp::from_bytes(key);
        let data = IpData::read_from_buffer(val)?;
        output.push((hashedip, data));
    }
    Ok(output)
}

/// Mark an event as approved or not
pub fn mark_event_approval(store: &Store, id: Id, approval: bool) -> Result<(), Error> {
    let approved_events = store
        .extra_table("approved-events")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-events",
        )))?;
    let mut txn = store.write_txn()?;
    approved_events.put(&mut txn, id.as_slice(), &[approval as u8])?;
    txn.commit()?;
    Ok(())
}

/// Clear an event approval status
pub fn clear_event_approval(store: &Store, id: Id) -> Result<(), Error> {
    let approved_events = store
        .extra_table("approved-events")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-events",
        )))?;
    let mut txn = store.write_txn()?;
    approved_events.delete(&mut txn, id.as_slice())?;
    txn.commit()?;
    Ok(())
}

/// Fetch an event approval status
pub fn get_event_approval(store: &Store, id: Id) -> Result<Option<bool>, Error> {
    let approved_events = store
        .extra_table("approved-events")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-events",
        )))?;
    let txn = store.read_txn()?;
    Ok(approved_events
        .get(&txn, id.as_slice())?
        .map(|u| !u.is_empty() && u[0] != 0))
}

/// Dump all event approval statuses
pub fn dump_event_approvals(store: &Store) -> Result<Vec<(Id, bool)>, Error> {
    let mut output: Vec<(Id, bool)> = Vec::new();
    let approved_events = store
        .extra_table("approved-events")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-events",
        )))?;
    let txn = store.read_txn()?;
    for i in approved_events.iter(&txn)? {
        let (key, val) = i?;
        let id = Id::from_bytes(key.try_into().unwrap());
        let approval: bool = !val.is_empty() && val[0] != 0;
        output.push((id, approval));
    }
    Ok(output)
}

/// Mark a pubkey as approved or not
pub fn mark_pubkey_approval(store: &Store, pubkey: Pubkey, approval: bool) -> Result<(), Error> {
    let approved_pubkeys = store
        .extra_table("approved-pubkeys")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-pubkeys",
        )))?;
    let mut txn = store.write_txn()?;
    approved_pubkeys.put(&mut txn, pubkey.as_slice(), &[approval as u8])?;
    txn.commit()?;
    Ok(())
}

/// Clear a pubkey approval status
pub fn clear_pubkey_approval(store: &Store, pubkey: Pubkey) -> Result<(), Error> {
    let approved_pubkeys = store
        .extra_table("approved-pubkeys")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-pubkeys",
        )))?;
    let mut txn = store.write_txn()?;
    approved_pubkeys.delete(&mut txn, pubkey.as_slice())?;
    txn.commit()?;
    Ok(())
}

/// Fetch a pubkey approval status
pub fn get_pubkey_approval(store: &Store, pubkey: Pubkey) -> Result<Option<bool>, Error> {
    let approved_pubkeys = store
        .extra_table("approved-pubkeys")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-pubkeys",
        )))?;
    let txn = store.read_txn()?;
    Ok(approved_pubkeys
        .get(&txn, pubkey.as_slice())?
        .map(|u| !u.is_empty() && u[0] != 0))
}

/// Dump all pubkey approval statuses
pub fn dump_pubkey_approvals(store: &Store) -> Result<Vec<(Pubkey, bool)>, Error> {
    let mut output: Vec<(Pubkey, bool)> = Vec::new();
    let approved_pubkeys = store
        .extra_table("approved-pubkeys")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable(
            "approved-pubkeys",
        )))?;
    let txn = store.read_txn()?;
    for i in approved_pubkeys.iter(&txn)? {
        let (key, val) = i?;
        let pubkey = Pubkey::from_bytes(key.try_into().unwrap());
        let approval: bool = !val.is_empty() && val[0] != 0;
        output.push((pubkey, approval));
    }
    Ok(output)
}

/// Add authorized user (or change moderator flag)
pub fn add_authorized_user(store: &Store, pubkey: Pubkey, moderator: bool) -> Result<(), Error> {
    let users = store
        .extra_table("users")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("users")))?;
    let mut txn = store.write_txn()?;
    users.put(&mut txn, pubkey.as_slice(), &[moderator as u8])?;
    txn.commit()?;
    Ok(())
}

/// Remove authorized user
pub fn rm_authorized_user(store: &Store, pubkey: Pubkey) -> Result<(), Error> {
    let users = store
        .extra_table("users")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("users")))?;
    let mut txn = store.write_txn()?;
    users.delete(&mut txn, pubkey.as_slice())?;
    txn.commit()?;
    Ok(())
}

/// Get authorized user
pub fn get_authorized_user(store: &Store, pubkey: Pubkey) -> Result<Option<bool>, Error> {
    let users = store
        .extra_table("users")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("users")))?;
    let txn = store.read_txn()?;
    Ok(users
        .get(&txn, pubkey.as_slice())?
        .map(|u| !u.is_empty() && u[0] != 0))
}

/// Dump all authorized users
pub fn dump_authorized_users(store: &Store) -> Result<Vec<(Pubkey, bool)>, Error> {
    let mut output: Vec<(Pubkey, bool)> = Vec::new();
    let users = store
        .extra_table("users")
        .ok_or(Into::<Error>::into(ChorusError::MissingTable("users")))?;
    let txn = store.read_txn()?;
    for i in users.iter(&txn)? {
        let (key, val) = i?;
        let pubkey = Pubkey::from_bytes(key.try_into().unwrap());
        let moderator: bool = !val.is_empty() && val[0] != 0;
        output.push((pubkey, moderator));
    }
    Ok(output)
}

/// Is the pubkey an authorized user?
pub fn is_authorized_user(pubkey: Pubkey) -> bool {
    let store = GLOBALS.store.get().unwrap();
    match get_authorized_user(store, pubkey) {
        Err(_) => false,
        Ok(None) => false,
        Ok(Some(_)) => true,
    }
}

/// Is the pubkey a moderator?
pub fn is_moderator(pubkey: Pubkey) -> bool {
    let store = GLOBALS.store.get().unwrap();
    match get_authorized_user(store, pubkey) {
        Err(_) => false,
        Ok(None) => false,
        Ok(Some(moderator)) => moderator,
    }
}

/// Is the pubkey an admin?
pub fn is_admin(pubkey: Pubkey) -> bool {
    GLOBALS.config.read().admin_keys.contains(&pubkey)
}
