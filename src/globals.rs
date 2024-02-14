use crate::config::{Config, FriendlyConfig};
use crate::store::Store;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use std::sync::OnceLock;
use tokio::sync::broadcast::Sender;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub store: OnceLock<Store>,
    pub http_server: Http,
    pub rid: OnceLock<String>,

    /// This is a broadcast channel where new incoming events are advertised by their offset.
    /// Every handler needs to listen to it and check if the incoming event matches any
    /// subscribed fitlers for their client, and if so, send the event to their client under
    /// that subscription.
    pub new_events: Sender<usize>,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        let mut http_server = hyper::server::conn::Http::new();
        http_server.http1_only(true);
        http_server.http1_keep_alive(true);

        let (sender, _) = tokio::sync::broadcast::channel(512);

        Globals {
            config: RwLock::new(FriendlyConfig::default().into_config().unwrap()),
            store: OnceLock::new(),
            http_server,
            rid: OnceLock::new(),
            new_events: sender,
        }
    };
}
