use crate::config::Config;
use crate::session::Session;
use crate::store::Store;
use dashmap::DashMap;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub http_server: Http,
    pub store: OnceLock<Store>,
    pub next_session_id: AtomicU64,
    pub sessions: DashMap<u64, Session>,
}

impl Globals {
    pub fn get_next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn get_session_peer(&self, session_id: u64) -> Option<SocketAddr> {
        self.sessions.get(&session_id).map(|s| s.peer)
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
            sessions: DashMap::new(),
        }
    };
}
