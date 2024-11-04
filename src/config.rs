use crate::error::Error;
use hyper::http::uri::{Authority, Scheme, Uri};
use pocket_types::Pubkey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Host;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FriendlyConfig {
    pub data_directory: String,
    pub ip_address: String,
    pub port: u16,
    pub hostname: String,
    pub chorus_is_behind_a_proxy: bool,
    pub use_tls: bool,
    pub certchain_pem_path: String,
    pub key_pem_path: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub contact: Option<String>,
    pub public_key_hex: Option<String>,
    pub open_relay: bool,
    pub user_hex_keys: Vec<String>,
    pub moderator_hex_keys: Vec<String>,
    pub verify_events: bool,
    pub allow_scraping: bool,
    pub allow_scrape_if_limited_to: u32,
    pub allow_scrape_if_max_seconds: u64,
    pub max_subscriptions: usize,
    pub serve_ephemeral: bool,
    pub serve_relay_lists: bool,
    pub server_log_level: String,
    pub library_log_level: String,
    pub client_log_level: String,
    pub enable_ip_blocking: bool,
    pub minimum_ban_seconds: u64,
    pub timeout_seconds: u64,
    pub max_connections_per_ip: usize,
    pub throttling_bytes_per_second: usize,
    pub throttling_burst: usize,
}

impl Default for FriendlyConfig {
    fn default() -> FriendlyConfig {
        FriendlyConfig {
            data_directory: "/opt/chorus/var/chorus".to_string(),
            ip_address: "127.0.0.1".to_string(),
            port: 443,
            hostname: "localhost".to_string(),
            chorus_is_behind_a_proxy: false,
            use_tls: true,
            certchain_pem_path: "/opt/chorus/etc/tls/fullchain.pem".to_string(),
            key_pem_path: "/opt/chorus/etc/tls/privkey.pem".to_string(),
            name: Some("Chorus Default".to_string()),
            description: Some("A default config of the Chorus relay".to_string()),
            icon_url: None,
            contact: None,
            public_key_hex: None,
            open_relay: false,
            user_hex_keys: vec![],
            moderator_hex_keys: vec![],
            verify_events: true,
            allow_scraping: false,
            allow_scrape_if_limited_to: 100,
            allow_scrape_if_max_seconds: 7200,
            max_subscriptions: 128,
            serve_ephemeral: true,
            serve_relay_lists: true,
            server_log_level: "Info".to_string(),
            library_log_level: "Info".to_string(),
            client_log_level: "Info".to_string(),
            enable_ip_blocking: true,
            minimum_ban_seconds: 1,
            timeout_seconds: 60,
            max_connections_per_ip: 5,
            throttling_bytes_per_second: 1024 * 1024,
            throttling_burst: 1024 * 1024 * 16,
        }
    }
}

impl FriendlyConfig {
    pub fn into_config(self) -> Result<Config, Error> {
        let FriendlyConfig {
            data_directory,
            ip_address,
            port,
            hostname,
            chorus_is_behind_a_proxy,
            use_tls,
            certchain_pem_path,
            key_pem_path,
            name,
            description,
            icon_url,
            contact,
            public_key_hex,
            open_relay,
            user_hex_keys,
            moderator_hex_keys,
            verify_events,
            allow_scraping,
            allow_scrape_if_limited_to,
            allow_scrape_if_max_seconds,
            max_subscriptions,
            serve_ephemeral,
            serve_relay_lists,
            server_log_level,
            library_log_level,
            client_log_level,
            enable_ip_blocking,
            minimum_ban_seconds,
            timeout_seconds,
            max_connections_per_ip,
            throttling_bytes_per_second,
            throttling_burst,
        } = self;

        let mut public_key: Option<Pubkey> = None;
        if let Some(pkh) = public_key_hex {
            public_key = Some(Pubkey::read_hex(pkh.as_bytes())?);
        };

        let mut user_keys: Vec<Pubkey> = Vec::with_capacity(user_hex_keys.len());
        for pkh in user_hex_keys.iter() {
            user_keys.push(Pubkey::read_hex(pkh.as_bytes())?);
        }

        let mut moderator_keys: Vec<Pubkey> = Vec::with_capacity(moderator_hex_keys.len());
        for pkh in moderator_hex_keys.iter() {
            moderator_keys.push(Pubkey::read_hex(pkh.as_bytes())?);
        }

        let hostname = Host::parse(&hostname)?;

        let server_log_level =
            log::LevelFilter::from_str(&server_log_level).unwrap_or(log::LevelFilter::Info);
        let library_log_level =
            log::LevelFilter::from_str(&library_log_level).unwrap_or(log::LevelFilter::Info);
        let client_log_level =
            log::LevelFilter::from_str(&client_log_level).unwrap_or(log::LevelFilter::Info);

        Ok(Config {
            data_directory,
            ip_address,
            port,
            hostname,
            chorus_is_behind_a_proxy,
            use_tls,
            certchain_pem_path,
            key_pem_path,
            name,
            description,
            icon_url,
            contact,
            public_key,
            open_relay,
            user_keys,
            user_hex_keys,
            moderator_keys,
            moderator_hex_keys,
            verify_events,
            allow_scraping,
            allow_scrape_if_limited_to,
            allow_scrape_if_max_seconds,
            max_subscriptions,
            serve_ephemeral,
            serve_relay_lists,
            server_log_level,
            library_log_level,
            client_log_level,
            enable_ip_blocking,
            minimum_ban_seconds,
            timeout_seconds,
            max_connections_per_ip,
            throttling_bytes_per_second,
            throttling_burst,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_directory: String,
    pub ip_address: String,
    pub port: u16,
    pub hostname: Host,
    pub chorus_is_behind_a_proxy: bool,
    pub use_tls: bool,
    pub certchain_pem_path: String,
    pub key_pem_path: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub contact: Option<String>,
    pub public_key: Option<Pubkey>,
    pub open_relay: bool,
    pub user_keys: Vec<Pubkey>,
    pub user_hex_keys: Vec<String>,
    pub moderator_keys: Vec<Pubkey>,
    pub moderator_hex_keys: Vec<String>,
    pub verify_events: bool,
    pub allow_scraping: bool,
    pub allow_scrape_if_limited_to: u32,
    pub allow_scrape_if_max_seconds: u64,
    pub max_subscriptions: usize,
    pub serve_ephemeral: bool,
    pub serve_relay_lists: bool,
    pub server_log_level: log::LevelFilter,
    pub library_log_level: log::LevelFilter,
    pub client_log_level: log::LevelFilter,
    pub enable_ip_blocking: bool,
    pub minimum_ban_seconds: u64,
    pub timeout_seconds: u64,
    pub max_connections_per_ip: usize,
    pub throttling_bytes_per_second: usize,
    pub throttling_burst: usize,
}

impl Default for Config {
    fn default() -> Config {
        let friendly = FriendlyConfig::default();

        // We know the default config passes into_config without error:
        friendly.into_config().unwrap()
    }
}

impl Config {
    pub fn url(&self, inner: Uri, http: bool) -> Result<Uri, Error> {
        let mut uri_parts = inner.into_parts();
        let scheme = match (self.use_tls, http) {
            (false, false) => Scheme::from_str("ws").unwrap(),
            (true, false) => Scheme::from_str("wss").unwrap(),
            (false, true) => Scheme::HTTP,
            (true, true) => Scheme::HTTPS,
        };
        uri_parts.scheme = Some(scheme);
        let authority = Authority::from_str(&format!("{}:{}", self.hostname, self.port))?;
        uri_parts.authority = Some(authority);
        Ok(Uri::from_parts(uri_parts)?)
    }
}
