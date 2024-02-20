include!("macros.rs");

pub mod config;
pub mod error;
pub mod globals;
pub mod nostr;
pub mod reply;
pub mod store;
pub mod tls;
pub mod types;
pub mod web;

use crate::config::{Config, FriendlyConfig};
use crate::error::{ChorusError, Error};
use crate::globals::{Globals, GLOBALS};
use crate::reply::NostrReply;
use crate::store::Store;
use crate::tls::MaybeTlsStream;
use crate::types::{OwnedFilter, Pubkey, Time};
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
use std::net::SocketAddr;
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
    console_subscriber::init();

    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    // Read config file
    let mut file = OpenOptions::new().read(true).open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let friendly_config: FriendlyConfig = ron::from_str(&contents)?;
    let config: Config = friendly_config.into_config()?;
    tracing::debug!("Loaded config file.");

    // Setup store
    let store = Store::new(&config.data_directory, config.allow_scraping)?;
    let _ = GLOBALS.store.set(store);

    // TLS setup
    let maybe_tls_acceptor = if config.use_tls {
        tracing::info!("Using TLS");
        Some(tls::tls_acceptor(&config)?)
    } else {
        tracing::info!("Not using TLS");
        None
    };

    // Bind listener to port
    let listener = TcpListener::bind((&*config.ip_address, config.port)).await?;
    tracing::info!("Running on {}:{}", config.ip_address, config.port);

    // Store config into GLOBALS
    let _ = GLOBALS.config.set(config);

    let mut interrupt_signal = signal(SignalKind::interrupt())?;
    let mut quit_signal = signal(SignalKind::quit())?;
    let mut terminate_signal = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            // Exits gracefully upon exit-type signals
            v = interrupt_signal.recv() => if v.is_some() {
                tracing::info!("SIGINT");
                break;
            },
            v = quit_signal.recv() => if v.is_some() {
                tracing::info!("SIGQUIT");
                break;
            },
            v = terminate_signal.recv() => if v.is_some() {
                tracing::info!("SIGTERM");
                break;
            },

            // Accepts network connections and spawn a task to serve each one
            v = listener.accept() => {
                let (tcp_stream, peer_addr) = v?;
                let ipaddr = peer_addr.ip();

                if let Some(ban_until) = GLOBALS.banlist.read().await.get(&ipaddr) {
                    let now = Time::now();
                    if *ban_until > now {
                        tracing::debug!("{peer_addr}: Blocking reconnection until {ban_until}");
                        continue;
                    }
                }

                if let Some(tls_acceptor) = &maybe_tls_acceptor {
                    let tls_acceptor_clone = tls_acceptor.clone();
                    tokio::spawn(async move {
                        match tls_acceptor_clone.accept(tcp_stream).await {
                            Err(e) => tracing::error!("{}", e),
                            Ok(tls_stream) => {
                                if let Err(e) = serve(MaybeTlsStream::Rustls(tls_stream), peer_addr).await {
                                    tracing::error!("{}", e);
                                }
                            }
                        }
                    });
                } else {
                    serve(MaybeTlsStream::Plain(tcp_stream), peer_addr).await?;
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
        tracing::info!("Waiting for {num_clients} websockets to shutdown...");

        // We will check if all clients have shutdown every 25ms
        let mut interval = tokio::time::interval(Duration::from_millis(25));
        let _ = interval.tick(); // consume the first tick
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

    tracing::info!("Syncing and shutting down.");
    let _ = GLOBALS.store.get().unwrap().sync();

    Ok(())
}

// Serve a single network connection
async fn serve(stream: MaybeTlsStream<TcpStream>, peer_addr: SocketAddr) -> Result<(), Error> {
    // Serve the network stream with our http server and our HttpService
    let service = HttpService { peer: peer_addr };

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
                    tracing::error!("{:?}", src);
                }
            } else {
                // Print in less detail
                let e: Error = he.into();
                tracing::error!("{}", e);
            }
        }
    });

    Ok(())
}

// This is our per-connection HTTP service
struct HttpService {
    peer: SocketAddr,
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
        let peer = self.peer;
        Box::pin(async move { handle_http_request(peer, req).await })
    }
}

async fn handle_http_request(
    peer: SocketAddr,
    mut request: Request<Body>,
) -> Result<Response<Body>, Error> {
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
                        errcount: 0,
                    };

                    // Increment count of active websockets
                    let old_num_websockets = GLOBALS.num_clients.fetch_add(1, Ordering::SeqCst);

                    tracing::info!(
                        "{}: websocket started (making {} active websockets)",
                        peer,
                        old_num_websockets + 1
                    );

                    // Everybody gets a 4-second ban on disconnect to prevent
                    // rapid reconnection
                    let mut ban_seconds: u64 = 4;

                    // Handle the websocket
                    if let Err(e) = ws_service.handle_websocket_stream().await {
                        match e.inner {
                            ChorusError::Tungstenite(tungstenite::error::Error::Protocol(
                                tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                            )) => {
                                // So they disconnected ungracefully.
                                // No big deal, no extra ban for that.
                            }
                            ChorusError::TooManyErrors => {
                                ban_seconds = 60;
                            }
                            _ => {
                                tracing::error!("{}: {}", peer, e);
                                ban_seconds = 15;
                            }
                        }
                    }

                    // Decrement count of active websockets
                    let old_num_websockets = GLOBALS.num_clients.fetch_sub(1, Ordering::SeqCst);

                    tracing::info!(
                        "{}: websocket ended (making {} active websockets)",
                        peer,
                        old_num_websockets - 1
                    );

                    // Ban for the appropriate duration
                    Globals::ban(peer.ip(), ban_seconds).await;
                }
                Err(e) => {
                    tracing::error!("{}", e);
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
    pub peer: SocketAddr,
    pub subscriptions: HashMap<String, Vec<OwnedFilter>>,
    pub buffer: Vec<u8>,
    pub websocket: WebSocketStream<Upgraded>,
    pub challenge: String,
    pub user: Option<Pubkey>,
    pub errcount: usize,
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

        'handle: loop {
            tokio::select! {
                instant = interval.tick() => {
                    // Drop them if they have no subscriptions
                    if self.subscriptions.is_empty() {
                        // And they are idle for 5 seconds with no subscriptions
                        if last_message_at + Duration::from_secs(5) < instant {
                            self.websocket.send(Message::Close(None)).await?;
                            break 'handle;
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
                                    tracing::info!("Err on websocket close: {e}");
                                }
                                return Err(e);
                            }
                        },
                        None => break 'handle, // the websocket is closed
                    }
                },
                offset_result = new_events.recv() => {
                    let offset = offset_result?;
                    self.handle_new_event(offset).await?;
                },
                _r = shutting_down.changed() => {
                    // Shutdown the websocket gracefully
                    self.websocket.send(Message::Close(None)).await?;
                    break 'handle;
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
            let authorized_user = nostr::authorized_user(&self.user).await;

            'subs: for (subid, filters) in self.subscriptions.iter() {
                for filter in filters.iter() {
                    if filter.as_filter()?.event_matches(&event)?
                        && nostr::screen_outgoing_event(&event, &event_flags, authorized_user)
                    {
                        let message = NostrReply::Event(subid, event.clone());
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
                tracing::trace!("{}: <= {}", self.peer, msg);
                // This is defined in nostr.rs
                if let Err(e) = self.handle_nostr_message(&msg).await {
                    self.errcount += 1;
                    tracing::error!("{}: {e}", self.peer);
                    if msg.len() < 2048 {
                        tracing::error!("{}: msg was {}", self.peer, msg);
                    } else {
                        tracing::error!("{}: msg was {} ...", self.peer, &msg[..2048]);
                    }
                    let reply = NostrReply::Notice(format!("error: {}", e));
                    self.websocket.send(Message::text(reply.as_json())).await?;
                    if self.errcount >= 3 {
                        let reply = NostrReply::Notice(
                            "Too many errors (3). Banned for 60 seconds.".into(),
                        );
                        self.websocket.send(Message::text(reply.as_json())).await?;
                        return Err(ChorusError::TooManyErrors.into());
                    }
                }
            }
            Message::Binary(msg) => {
                let reply = NostrReply::Notice(
                    "binary messages are not processed by this relay".to_owned(),
                );
                self.websocket.send(Message::text(reply.as_json())).await?;
                tracing::info!(
                    "{}: Received unhandled binary message: {:02X?}",
                    self.peer,
                    msg
                );
            }
            Message::Ping(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                tracing::debug!("{}: Received ping message: {:02X?}", self.peer, msg);
            }
            Message::Pong(msg) => {
                tracing::debug!("{}: Received pong message: {:02X?}", self.peer, msg);
            }
            Message::Close(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                if let Some(msg) = &msg {
                    tracing::debug!(
                        "{}: Received close message with code {} and message: {}",
                        self.peer,
                        msg.code,
                        msg.reason
                    );
                } else {
                    tracing::debug!("{}: Received close message", self.peer);
                }
            }
            Message::Frame(_msg) => {
                unreachable!();
            }
        }

        Ok(())
    }
}
