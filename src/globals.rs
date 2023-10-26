use crate::config::Config;
use crate::store::Store;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub store: OnceLock<Store>,
    pub http_server: Http,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        let mut http_server = hyper::server::conn::Http::new();
        http_server.http1_only(true);
        http_server.http1_keep_alive(true);

        Globals {
            config: RwLock::new(Config::default()),
            store: OnceLock::new(),
            http_server,
        }
    };
}
