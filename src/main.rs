include!("macros.rs");

pub mod config;
pub mod error;
pub mod globals;
pub mod store;
pub mod tls;
pub mod types;
pub mod web;

use crate::config::Config;
use crate::error::Error;
use crate::globals::GLOBALS;
use crate::store::Store;
use hyper::{Body, Request, Response};
use rustls::{Certificate, PrivateKey};
use std::env;
use std::error::Error as StdError;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};

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
    let tls_acceptor = {
        let certs: Vec<Certificate> =
            rustls_pemfile::certs(&mut BufReader::new(File::open(&config.certchain_pem_path)?))?
                .drain(..)
                .map(Certificate)
                .collect();

        let mut keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(
            File::open(&config.key_pem_path)?,
        ))?
        .drain(..)
        .rev()
        .map(PrivateKey)
        .collect();

        let key = match keys.pop() {
            Some(k) => k,
            None => return Err(Error::NoPrivateKey),
        };

        let tls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        TlsAcceptor::from(Arc::new(tls_config))
    };

    // Bind listener to port
    let listener = TcpListener::bind((&*config.ip_address, config.port)).await?;
    log::info!("Running on {}:{}", config.ip_address, config.port);

    // Store config into GLOBALS
    *GLOBALS.config.write().await = config;

    let mut http_server = hyper::server::conn::Http::new();
    http_server.http1_only(true);
    http_server.http1_keep_alive(true);

    // Accepts network connections and spawn a task to serve each one
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;

        let acceptor = tls_acceptor.clone();
        let http_server_clone = http_server.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Err(e) => log::error!("{}", e),
                Ok(tls_stream) => {
                    let connection = http_server_clone
                        .serve_connection(tls_stream, hyper::service::service_fn(handle_request));
                    tokio::spawn(async move {
                        // If our service exits with an error, log the error
                        if let Err(he) = connection.await {
                            if let Some(src) = he.source() {
                                if &*format!("{}", src)
                                    == "Transport endpoint is not connected (os error 107)"
                                {
                                    // do nothing
                                } else {
                                    // Print in detail
                                    log::info!("{:?}", src);
                                }
                            } else {
                                // Print in less detail
                                let e: Error = he.into();
                                log::info!("{}", e);
                            }
                        }
                    });
                }
            }
        });
    }
}

async fn handle_request(_request: Request<Body>) -> Result<Response<Body>, Error> {
    web::serve_http().await
}
