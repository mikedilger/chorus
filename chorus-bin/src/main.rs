pub mod globals;
pub mod nostr;
pub mod tls;
pub mod web;

use crate::globals::GLOBALS;
use crate::tls::MaybeTlsStream;
use chorus_lib::config::{Config, FriendlyConfig};
use chorus_lib::error::{ChorusError, Error};
use chorus_lib::ip::{HashedIp, HashedPeer, SessionExit};
use chorus_lib::reply::NostrReply;
use chorus_lib::store::Store;
use chorus_lib::types::{OwnedFilter, Pubkey};
use futures::{sink::SinkExt, stream::StreamExt};
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::{Body, Request, Response};
use hyper_tungstenite::{tungstenite, WebSocketStream};
use std::collections::HashMap;
use std::env;
use std::error::Error as StdError;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Read;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;
use textnonce::TextNonce;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::Instant;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::Message;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    // Read config file
    let mut file = OpenOptions::new().read(true).open(config_path.clone())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let friendly_config: FriendlyConfig = toml::from_str(&contents)?;
    let config: Config = friendly_config.into_config()?;

    env_logger::Builder::new()
        .filter_level(config.library_log_level)
        .filter(Some("Server"), config.server_log_level)
        .filter(Some("Client"), config.client_log_level)
        .format_target(true)
        .format_module_path(false)
        .format_timestamp_millis()
        .init();

    log::debug!(target: "Server", "Loaded config file.");

    // Setup store
    let store = Store::new(&config)?;
    let _ = GLOBALS.store.set(store);

    // TLS setup
    let maybe_tls_acceptor = if config.use_tls {
        log::info!(target: "Server", "Using TLS");
        Some(tls::tls_acceptor(&config)?)
    } else {
        log::info!(target: "Server", "Not using TLS");
        None
    };

    // Bind listener to port
    let listener = TcpListener::bind((&*config.ip_address, config.port)).await?;
    log::info!(target: "Server", "Running on {}:{}", config.ip_address, config.port);

    // Store config into GLOBALS
    *GLOBALS.config.write() = config;

    let mut interrupt_signal = signal(SignalKind::interrupt())?;
    let mut quit_signal = signal(SignalKind::quit())?;
    let mut terminate_signal = signal(SignalKind::terminate())?;
    let mut hup_signal = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            // Exits gracefully upon exit-type signals
            v = interrupt_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGINT");
                break;
            },
            v = quit_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGQUIT");
                break;
            },
            v = terminate_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGTERM");
                break;
            },

            // Reload config on HUP
            v = hup_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGHUP: Reloading configuration");

                // Reload the config file
                let mut file = OpenOptions::new().read(true).open(config_path.clone())?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let friendly_config: FriendlyConfig = toml::from_str(&contents)?;
                let config: Config = friendly_config.into_config()?;

                *GLOBALS.config.write() = config;

                print_stats();
            },

            // Accepts network connections and spawn a task to serve each one
            v = listener.accept() => {
                let (tcp_stream, hashed_peer) = {
                    let (tcp_stream, peer_addr) = v?;
                    let hashed_peer = HashedPeer::new(peer_addr);
                    (tcp_stream, hashed_peer)
                };

                let ip_data = GLOBALS.store.get().unwrap().get_ip_data(hashed_peer.ip())?;
                if ip_data.is_banned() {
                    log::debug!(target: "Client",
                                "{}: Blocking reconnection until {}",
                                hashed_peer.ip(),
                                ip_data.ban_until);
                    continue;
                }

                if let Some(tls_acceptor) = &maybe_tls_acceptor {
                    let tls_acceptor_clone = tls_acceptor.clone();
                    tokio::spawn(async move {
                        match tls_acceptor_clone.accept(tcp_stream).await {
                            Err(e) => log::error!(
                                target: "Client",
                                "{}: {}", hashed_peer, e
                            ),
                            Ok(tls_stream) => {
                                if let Err(e) = serve(MaybeTlsStream::Rustls(tls_stream), hashed_peer).await {
                                    log::error!(
                                        target: "Client",
                                        "{}: {}", hashed_peer, e
                                    );
                                }
                            }
                        }
                    });
                } else {
                    serve(MaybeTlsStream::Plain(tcp_stream), hashed_peer).await?;
                }
            }
        };
    }

    // Pre-sync in case something below hangs up
    let _ = GLOBALS.store.get().unwrap().sync();

    // Set the shutting down signal
    let _ = GLOBALS.shutting_down.send(true);

    // Wait for active websockets to shutdown gracefully
    let mut num_clients = GLOBALS.num_clients.load(Ordering::Relaxed);
    if num_clients != 0 {
        log::info!(target: "Server", "Waiting for {num_clients} websockets to shutdown...");

        // We will check if all clients have shutdown every 25ms
        let interval = tokio::time::interval(Duration::from_millis(25));
        tokio::pin!(interval);

        while num_clients != 0 {
            // If we get another shutdown signal, stop waiting for websockets
            tokio::select! {
                v = interrupt_signal.recv() => if v.is_some() {
                    break;
                },
                v = quit_signal.recv() => if v.is_some() {
                    break;
                },
                v = terminate_signal.recv() => if v.is_some() {
                    break;
                },
                _instant = interval.tick() => {
                    num_clients = GLOBALS.num_clients.load(Ordering::Relaxed);
                    continue;
                }
            }
        }
    }

    log::info!(target: "Server", "Syncing and shutting down.");
    let _ = GLOBALS.store.get().unwrap().sync();

    print_stats();

    Ok(())
}

fn print_stats() {
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

// Serve a single network connection
async fn serve(stream: MaybeTlsStream<TcpStream>, peer: HashedPeer) -> Result<(), Error> {
    // Serve the network stream with our http server and our HttpService
    let service = HttpService { peer };

    let connection = GLOBALS
        .http_server
        .serve_connection(stream, service)
        .with_upgrades();

    tokio::spawn(async move {
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
    });

    Ok(())
}

// This is our per-connection HTTP service
struct HttpService {
    peer: HashedPeer,
}

impl Service<Request<Body>> for HttpService {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // This is called for each HTTP request made by the client
    // NOTE: it is not called for each websocket message once upgraded.
    fn call(&mut self, req: Request<Body>) -> Self::Future {
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
    mut request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let ua = match request.headers().get("user-agent") {
        Some(ua) => ua.to_str().unwrap_or("NON-UTF8-HEADER").to_owned(),
        None => "".to_owned(),
    };

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

                    // Increment count of active websockets
                    let old_num_websockets = GLOBALS.num_clients.fetch_add(1, Ordering::SeqCst);

                    // we cheat somewhat and log these websocket open and close messages
                    // as server messages
                    log::info!(
                        target: "Server",
                        "{}: TOTAL={}, New Connection: {}",
                        peer,
                        old_num_websockets + 1,
                        ua
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
                    let old_num_websockets = GLOBALS.num_clients.fetch_sub(1, Ordering::SeqCst);

                    // Update ip data (including ban time)
                    let mut ban_seconds = 0;
                    if let Ok(mut ip_data) = GLOBALS.store.get().unwrap().get_ip_data(peer.ip()) {
                        ban_seconds = ip_data.update_on_session_close(session_exit);
                        let _ = GLOBALS
                            .store
                            .get()
                            .unwrap()
                            .update_ip_data(peer.ip(), &ip_data);
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
        // check for Accept header of application/nostr+json
        if let Some(accept) = request.headers().get("Accept") {
            if let Ok(s) = accept.to_str() {
                if s == "application/nostr+json" {
                    return web::serve_nip11(peer).await;
                }
            }
        }

        web::serve_http(peer, request).await
    }
}

struct WebSocketService {
    pub peer: HashedPeer,
    pub subscriptions: HashMap<String, Vec<OwnedFilter>>,
    pub buffer: Vec<u8>,
    pub websocket: WebSocketStream<Upgraded>,
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

        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let _ = interval.tick().await; // consume the first tick
        tokio::pin!(interval);

        loop {
            tokio::select! {
                instant = interval.tick() => {
                    // Drop them if they have no subscriptions
                    if self.subscriptions.is_empty() {
                        // And they are idle for 5 seconds with no subscriptions
                        if last_message_at + Duration::from_secs(5) < instant {
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
    async fn handle_new_event(&mut self, new_event_offset: usize) -> Result<(), Error> {
        if self.subscriptions.is_empty() {
            return Ok(());
        }

        if let Some(event) = GLOBALS
            .store
            .get()
            .unwrap()
            .get_event_by_offset(new_event_offset)?
        {
            let event_flags = nostr::event_flags(&event, &self.user);
            let authorized_user = nostr::authorized_user(&self.user);

            'subs: for (subid, filters) in self.subscriptions.iter() {
                for filter in filters.iter() {
                    if filter.as_filter()?.event_matches(&event)?
                        && nostr::screen_outgoing_event(&event, &event_flags, authorized_user)
                    {
                        let message = NostrReply::Event(subid, event);
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
        match message {
            Message::Text(msg) => {
                log::trace!(target: "Client", "{}: <= {}", self.peer, msg);
                self.replied = false;
                // This is defined in nostr.rs
                if let Err(e) = self.handle_nostr_message(&msg).await {
                    self.error_punishment += e.inner.punishment();
                    log::error!(target: "Client", "{}: {e}", self.peer);
                    if !matches!(e, ChorusError::AuthRequired) {
                        if msg.len() < 2048 {
                            log::error!(target: "Client", "{}:   msg was {}", self.peer, msg);
                        } else {
                            log::error!(target: "Client", "{}:   truncated msg was {} ...", self.peer, &msg[..2048]);
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
                        "{}: Received close message with code {} and message: {}",
                        self.peer,
                        msg.code,
                        msg.reason
                    );
                } else {
                    log::debug!(target: "Client", "{}: Received close message", self.peer);
                }
            }
            Message::Frame(_msg) => {
                unreachable!();
            }
        }

        Ok(())
    }
}
