pub mod config;
pub mod error;
pub mod globals;
pub mod nostr;
pub mod session;
pub mod store;
pub mod tls;
pub mod web;

use crate::config::Config;
use crate::error::Error;
use crate::globals::GLOBALS;
use crate::session::Session;
use crate::store::Store;
use crate::tls::MaybeTlsStream;
use futures::{sink::SinkExt, stream::StreamExt};
use hyper::service::Service;
use hyper::{Body, Request, Response};
use hyper_tungstenite::{tungstenite, HyperWebsocket};
use nostr_types::{ClientMessage, RelayMessage};
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

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        log::info!("{}: connected", peer_addr);

        if let Some(tls_acceptor) = &maybe_tls_acceptor {
            let tls_acceptor_clone = tls_acceptor.clone();
            tokio::spawn(async move {
                match tls_acceptor_clone.accept(tcp_stream).await {
                    Err(e) => log::error!("{}", e),
                    Ok(tls_stream) => {
                        if let Err(e) =
                            serve(MaybeTlsStream::Rustls(Box::new(tls_stream)), peer_addr).await
                        {
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

async fn serve(stream: MaybeTlsStream<TcpStream>, peer_addr: SocketAddr) -> Result<(), Error> {
    let connection = GLOBALS
        .http_server
        .serve_connection(stream, Svc { peer: peer_addr })
        .with_upgrades();

    tokio::spawn(async move {
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
        log::info!("{}: disconnected", peer_addr);
    });

    Ok(())
}

struct Svc {
    peer: SocketAddr,
}

impl Service<Request<Body>> for Svc {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let peer = self.peer;
        let session = Session::new(self.peer);
        let session_id = GLOBALS.get_next_session_id();
        GLOBALS.sessions.insert(session_id, session);
        Box::pin(async move { handle(session_id, peer, req).await })
    }
}

async fn handle(
    session_id: u64,
    peer: SocketAddr,
    mut request: Request<Body>,
) -> Result<Response<Body>, Error> {
    if hyper_tungstenite::is_upgrade_request(&request) {
        let (response, websocket) = hyper_tungstenite::upgrade(&mut request, None)?;
        tokio::spawn(async move {
            if let Err(e) = handle_websocket(session_id, peer, websocket).await {
                log::error!("{}: {}", peer, e);
            }
        });
        Ok(response)
    } else {
        // check for Accept header of application/nostr+json
        if let Some(accept) = request.headers().get("Accept") {
            if let Ok(s) = accept.to_str() {
                if s == "application/nostr+json" {
                    return web::serve_nip11(session_id, peer).await;
                }
            }
        }
        Ok(web::serve_http(session_id, peer, request).await?)
    }
}

async fn handle_websocket(
    session_id: u64,
    peer: SocketAddr,
    websocket: HyperWebsocket,
) -> Result<(), Error> {
    let mut websocket = websocket.await?;
    while let Some(message) = websocket.next().await {
        match message? {
            Message::Text(msg) => {
                log::debug!("{}: {}", peer, msg);
                let client_msg: ClientMessage = serde_json::from_str(&msg)?;
                let reply = nostr::handle(session_id, peer, client_msg).await?;
                let reply_string = serde_json::to_string(&reply)?;
                websocket.send(Message::text(&reply_string)).await?;
            }
            Message::Binary(msg) => {
                log::info!("{}: Received unhandled binary message: {:02X?}", peer, msg);
                let notice = RelayMessage::Notice(
                    "Binary messages are not processed by this relay.".to_string(),
                );
                let string = serde_json::to_string(&notice)?;
                websocket.send(Message::binary(string.as_bytes())).await?;
            }
            Message::Ping(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                log::debug!("{}: Received ping message: {:02X?}", peer, msg);
            }
            Message::Pong(msg) => {
                log::debug!("{}: Received pong message: {:02X?}", peer, msg);
            }
            Message::Close(msg) => {
                // No need to send a reply: tungstenite takes care of this for you.
                if let Some(msg) = &msg {
                    log::debug!(
                        "{}: Received close message with code {} and message: {}",
                        peer,
                        msg.code,
                        msg.reason
                    );
                } else {
                    log::debug!("{}: Received close message", peer);
                }
            }
            Message::Frame(_msg) => {
                unreachable!();
            }
        }
    }

    Ok(())
}
