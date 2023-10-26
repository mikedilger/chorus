include!("macros.rs");

pub mod config;
pub mod error;
pub mod globals;
pub mod store;
pub mod types;
pub mod web;

use crate::config::Config;
use crate::error::Error;
use crate::globals::GLOBALS;
use crate::store::Store;
use hyper::{Body, Request, Response};
use std::env;
use std::error::Error as StdError;
use std::fs::OpenOptions;
use std::io::Read;
use tokio::net::TcpListener;

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

        let connection =
            http_server.serve_connection(tcp_stream, hyper::service::service_fn(handle_request));

        tokio::spawn(async move {
            // If our service exits with an error, log the error
            if let Err(he) = connection.await {
                if let Some(src) = he.source() {
                    if &*format!("{}", src) == "Transport endpoint is not connected (os error 107)"
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

async fn handle_request(_request: Request<Body>) -> Result<Response<Body>, Error> {
    web::serve_http().await
}
