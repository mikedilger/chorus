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

use crate::config::Config;
use crate::error::Error;
use crate::globals::GLOBALS;
use crate::reply::NostrReply;
use crate::store::Store;
use crate::tls::MaybeTlsStream;
use futures::{sink::SinkExt, stream::StreamExt};
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::{Body, Request, Response};
use hyper_tungstenite::{tungstenite, WebSocketStream};
use std::env;
use std::error::Error as StdError;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Read;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
use tungstenite::Message;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

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
    let config: Config = ron::from_str(&contents)?;
    log::debug!("Loaded config file.");

    // Setup store
    let store = Store::new(&config.data_directory)?;
    let _ = GLOBALS.store.set(store);

    // TLS setup
    let maybe_tls_acceptor = if config.use_tls {
        log::info!("Using TLS");
        Some(tls::tls_acceptor(&config)?)
    } else {
        log::info!("Not using TLS");
        None
    };

    // Bind listener to port
    let listener = TcpListener::bind((&*config.ip_address, config.port)).await?;
    log::info!("Running on {}:{}", config.ip_address, config.port);

    // Store config into GLOBALS
    *GLOBALS.config.write().await = config;

    // Accepts network connections and spawn a task to serve each one
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;

        if let Some(tls_acceptor) = &maybe_tls_acceptor {
            let tls_acceptor_clone = tls_acceptor.clone();
            tokio::spawn(async move {
                match tls_acceptor_clone.accept(tcp_stream).await {
                    Err(e) => log::error!("{}", e),
                    Ok(tls_stream) => {
                        if let Err(e) = serve(MaybeTlsStream::Rustls(tls_stream), peer_addr).await {
                            log::error!("{}", e);
                        }
                    }
                }
            });
        } else {
            serve(MaybeTlsStream::Plain(tcp_stream), peer_addr).await?;
        }
    }
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
                    log::error!("{:?}", src);
                }
            } else {
                // Print in less detail
                let e: Error = he.into();
                log::error!("{}", e);
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
        let (response, websocket) = hyper_tungstenite::upgrade(&mut request, None)?;
        tokio::spawn(async move {
            // Await the websocket upgrade process
            match websocket.await {
                Ok(websocket) => {
                    log::info!("{}: websocket started", peer);

                    // Build a websocket service
                    let mut ws_service = WebSocketService { peer, websocket };

                    // Handle the websocket
                    if let Err(e) = ws_service.handle_websocket_stream().await {
                        match e {
                            Error::Tungstenite(tungstenite::error::Error::Protocol(
                                tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                            )) => {
                                // swallow
                            }
                            e => log::error!("{}: {}", peer, e),
                        }
                    }

                    log::info!("{}: websocket ended", peer);
                }
                Err(e) => {
                    log::error!("{}", e);
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
    pub websocket: WebSocketStream<Upgraded>,
}

impl WebSocketService {
    async fn handle_websocket_stream(&mut self) -> Result<(), Error> {
        loop {
            // We will add more to this later
            tokio::select! {
                message_option = self.websocket.next() => {
                    match message_option {
                        Some(message) => {
                            let message = message?;
                            self.handle_websocket_message(message).await?;
                        },
                        None => break, // websocket must be closed
                    }
                },
            }
        }

        Ok(())
    }

    async fn handle_websocket_message(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::Text(msg) => {
                log::debug!("{}: <= {}", self.peer, msg);
                // This is defined in nostr.rs
                if let Err(e) = self.handle_nostr_message(msg).await {
                    log::error!("{e}");
                    let reply = NostrReply::Notice(format!("error: {}", e));
                    self.websocket.send(Message::text(reply.as_json())).await?;
                }
            }
            Message::Binary(msg) => {
                let reply = NostrReply::Notice(
                    "binary messages are not processed by this relay".to_owned(),
                );
                self.websocket.send(Message::text(reply.as_json())).await?;
                log::info!(
                    "{}: Received unhandled binary message: {:02X?}",
                    self.peer,
                    msg
                );
            }
            Message::Ping(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                log::debug!("{}: Received ping message: {:02X?}", self.peer, msg);
            }
            Message::Pong(msg) => {
                log::debug!("{}: Received pong message: {:02X?}", self.peer, msg);
            }
            Message::Close(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                if let Some(msg) = &msg {
                    log::debug!(
                        "{}: Received close message with code {} and message: {}",
                        self.peer,
                        msg.code,
                        msg.reason
                    );
                } else {
                    log::debug!("{}: Received close message", self.peer);
                }
            }
            Message::Frame(_msg) => {
                unreachable!();
            }
        }

        Ok(())
    }
}
