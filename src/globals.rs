use crate::config::{Config, FriendlyConfig};
use crate::store::Store;
use crate::types::Time;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::OnceLock;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::watch::Sender as WatchSender;
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
    pub new_events: BroadcastSender<usize>,

    pub num_clients: AtomicUsize,
    pub shutting_down: WatchSender<bool>,
    pub banlist: RwLock<HashMap<IpAddr, Time>>,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        let mut http_server = hyper::server::conn::Http::new();
        http_server.http1_only(true);
        http_server.http1_keep_alive(true);

        let (new_events, _) = tokio::sync::broadcast::channel(512);
        let (shutting_down, _) = tokio::sync::watch::channel(false);

        Globals {
            config: RwLock::new(FriendlyConfig::default().into_config().unwrap()),
            store: OnceLock::new(),
            http_server,
            rid: OnceLock::new(),
            new_events,
            num_clients: AtomicUsize::new(0),
            shutting_down,
            banlist: RwLock::new(HashMap::new()),
        }
    };
}

impl Globals {
    pub async fn ban(ipaddr: std::net::IpAddr, seconds: u64) {
        let mut until = Time::now();
        until.0 += seconds;
        if let Some(current_ban) = GLOBALS.banlist.read().await.get(&ipaddr) {
            until.0 = current_ban.0.max(until.0);
        }
        GLOBALS.banlist.write().await.insert(ipaddr, until);
    }
}
