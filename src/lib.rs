pub mod config;
pub mod counting_stream;
pub mod error;
pub mod globals;
pub mod ip;
pub mod nostr;
pub mod reply;
pub mod tls;
pub mod web;

use crate::config::{Config, FriendlyConfig};
use crate::counting_stream::CountingStream;
use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::{HashedIp, HashedPeer, IpData, SessionExit};
use crate::reply::NostrReply;
use futures::{sink::SinkExt, stream::StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_tungstenite::tungstenite;
use hyper_tungstenite::WebSocketStream;
use hyper_util::rt::TokioIo;
use pocket_db::Store;
use pocket_types::{Id, OwnedFilter, Pubkey};
use speedy::{Readable, Writable};
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
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::server::TlsStream;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::Message;

pub trait FullStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl FullStream for CountingStream<TcpStream> {}
impl FullStream for TlsStream<CountingStream<TcpStream>> {}

/// Serve a single network connection
pub async fn serve(stream: Box<dyn FullStream>, peer: HashedPeer) {
    // Serve the network stream with our http server and our ChorusService
    let service = ChorusService { peer };

    let io = hyper_util::rt::TokioIo::new(stream);

    let mut http1builder = http1::Builder::new();
    http1builder.half_close(true);
    http1builder.keep_alive(true);
    http1builder.header_read_timeout(Duration::from_secs(5));
    let connection = http1builder.serve_connection(io, service).with_upgrades();

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
    type Response = Response<Full<Bytes>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    // This is called for each HTTP request made by the client
    // NOTE: it is not called for each websocket message once upgraded.
    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let mut peer = self.peer;

        // If chorus is behind a proxy that sets an "X-Real-Ip" header, we use
        // that ip address instead (otherwise their log file will just say "127.0.0.1"
        // for every peer)
        if peer.ip().is_loopback() {
            if let Some(rip) = req.headers().get("x-real-ip") {
                if let Ok(ripstr) = rip.to_str() {
                    if let Ok(ipaddr) = ripstr.parse::<IpAddr>() {
                        let hashed_ip = HashedIp::new(ipaddr);
                        peer = HashedPeer::from_parts(hashed_ip, peer.port());
                    }
                }
            }
        }

        Box::pin(async move { handle_http_request(peer, req).await })
    }
}

async fn handle_http_request(
    peer: HashedPeer,
    mut request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Error> {
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
                .body(Full::new(Bytes::new()))?);
        }
    }

    if hyper_tungstenite::is_upgrade_request(&request) {
        let web_socket_config = WebSocketConfig {
            max_write_buffer_size: 1024 * 1024,  // 1 MB
            max_message_size: Some(1024 * 1024), // 1 MB
            max_frame_size: Some(1024 * 1024),   // 1 MB
            ..Default::default()
        };
        let (response, websocket) =
            hyper_tungstenite::upgrade(&mut request, Some(web_socket_config))?;
        tokio::spawn(async move {
            // Await the websocket upgrade process
            match websocket.await {
                Ok(websocket) => {
                    // Build a websocket service
                    let mut ws_service = WebSocketService {
                        peer,
                        subscriptions: HashMap::new(),
                        // We start with a 1-page buffer, and grow it if needed.
                        buffer: vec![0; 4096],
                        websocket,
                        challenge: TextNonce::new().into_string(),
                        user: None,
                        error_punishment: 0.0,
                        replied: false,
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
                            ChorusError::ErrorClose => {
                                session_exit = SessionExit::TooManyErrors;
                                msg = "Errored Out";
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

                    // Decrement count of active websockets
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
                    // if GLOBALS.config.read().enable_ip_blocking {
                    let mut ban_seconds = 0;
                    let minimum_ban_seconds = GLOBALS.config.read().minimum_ban_seconds;
                    if let Ok(mut ip_data) = get_ip_data(GLOBALS.store.get().unwrap(), peer.ip()) {
                        ban_seconds =
                            ip_data.update_on_session_close(session_exit, minimum_ban_seconds);
                        let _ = update_ip_data(GLOBALS.store.get().unwrap(), peer.ip(), &ip_data);
                    }

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
        });
        Ok(response)
    } else {
        web::serve_http(peer, request).await
    }
}

struct WebSocketService {
    pub peer: HashedPeer,
    pub subscriptions: HashMap<String, Vec<OwnedFilter>>,
    pub buffer: Vec<u8>,
    pub websocket: WebSocketStream<TokioIo<Upgraded>>,
    pub challenge: String,
    pub user: Option<Pubkey>,
    pub error_punishment: f32,
    pub replied: bool,
}

impl WebSocketService {
    async fn handle_websocket_stream(&mut self) -> Result<(), Error> {
        // Subscribe to the shutting down channel
        let mut shutting_down = GLOBALS.shutting_down.subscribe();

        // Subscribe to the new_events broadcast channel
        let mut new_events = GLOBALS.new_events.subscribe();

        // Offer AUTH to clients right off the bat
        let reply = NostrReply::Auth(self.challenge.clone());
        self.websocket.send(Message::text(reply.as_json())).await?;

        let mut last_message_at = Instant::now();

        let timeout_seconds = GLOBALS.config.read().timeout_seconds;

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let _ = interval.tick().await; // consume the first tick
        tokio::pin!(interval);

        loop {
            tokio::select! {
                instant = interval.tick() => {
                    // Drop them if they have no subscriptions
                    if self.subscriptions.is_empty() {
                        // And they are idle for timeout_seconds with no subscriptions
                        if last_message_at + Duration::from_secs(timeout_seconds) < instant {
                            self.websocket.send(Message::Close(None)).await?;
                            return Err(ChorusError::TimedOut.into());
                        }
                    }
                }
                message_option = self.websocket.next() => {
                    last_message_at = Instant::now();
                    match message_option {
                        Some(message) => {
                            let message = message?;
                            if let Err(e) = self.handle_websocket_message(message).await {
                                if let Err(e) = self.websocket.close(None).await {
                                    log::info!(target: "Client", "{}: Err on websocket close: {e}", self.peer);
                                }
                                return Err(e);
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
                    // Shutdown the websocket gracefully
                    self.websocket.send(Message::Close(None)).await?;
                    break;
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
        let authorized_user = nostr::authorized_user(&self.user);

        'subs: for (subid, filters) in self.subscriptions.iter() {
            for filter in filters.iter() {
                if filter.event_matches(event)?
                    && nostr::screen_outgoing_event(event, &event_flags, authorized_user)
                {
                    let message = NostrReply::Event(subid, event);
                    self.websocket
                        .send(Message::text(message.as_json()))
                        .await?;
                    continue 'subs;
                }
            }
        }

        Ok(())
    }

    async fn handle_websocket_message(&mut self, message: Message) -> Result<(), Error> {
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
                            log::warn!(target: "Client", "{}:   truncated msg was {} ...", self.peer, &msg[..2048]);
                        }
                    }
                    if !self.replied {
                        let reply = NostrReply::Notice(format!("error: {}", e));
                        self.websocket.send(Message::text(reply.as_json())).await?;
                    }
                    if self.error_punishment >= 1.0 {
                        let reply = NostrReply::Notice("Closing due to error(s)".into());
                        self.websocket.send(Message::text(reply.as_json())).await?;
                        return Err(ChorusError::ErrorClose.into());
                    }
                }
            }
            Message::Binary(msg) => {
                let reply = NostrReply::Notice(
                    "binary messages are not processed by this relay".to_owned(),
                );
                self.websocket.send(Message::text(reply.as_json())).await?;
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
    Ok(approved_events.get(&txn, id.as_slice())?.map(|u| u[0] != 0)) // FIXME in case data is zero length this will panic
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
        let approval: bool = val[0] != 0; // FIXME in case data is zero length this will panic
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
        .map(|u| u[0] != 0)) // FIXME in case data is zero length this will panic
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
        let approval: bool = val[0] != 0; // FIXME in case data is zero length this will panic
        output.push((pubkey, approval));
    }
    Ok(output)
}
