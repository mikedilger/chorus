use crate::config::{Config, FriendlyConfig};
use crate::store::Store;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub store: OnceLock<Store>,
    pub http_server: Http,
    pub rid: OnceLock<String>,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        let mut http_server = hyper::server::conn::Http::new();
        http_server.http1_only(true);
        http_server.http1_keep_alive(true);

        Globals {
            config: RwLock::new(FriendlyConfig::default().into_config().unwrap()),
            store: OnceLock::new(),
            http_server,
            rid: OnceLock::new(),
        }
    };
}
