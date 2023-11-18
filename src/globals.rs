use crate::config::Config;
use crate::store::Store;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub http_server: Http,
    pub store: OnceLock<Store>,
    pub next_session_id: AtomicU64,
}

impl Globals {
    pub fn get_next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        let mut http_server = hyper::server::conn::Http::new();
        http_server.http1_only(true);
        http_server.http1_keep_alive(true);

        Globals {
            config: RwLock::new(Config::default()),
            http_server,
            store: OnceLock::new(),
            next_session_id: AtomicU64::new(0),
        }
    };
}
