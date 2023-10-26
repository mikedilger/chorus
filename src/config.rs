use nostr_types::PublicKey;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ip_address: String,
    pub port: u16,
    pub use_tls: bool,
    pub certchain_pem_path: String,
    pub key_pem_path: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub public_key: Option<PublicKey>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ip_address: "127.0.0.1".to_string(),
            port: 80,
            use_tls: false,
            certchain_pem_path: "./tls/fullchain.pem".to_string(),
            key_pem_path: "./tls/privkey.pem".to_string(),
            name: None,
            description: None,
            public_key: None,
        }
    }
}
