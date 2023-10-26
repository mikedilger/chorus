use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ip_address: String,
    pub port: u16,
    pub certchain_pem_path: String,
    pub key_pem_path: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ip_address: "127.0.0.1".to_string(),
            port: 80,
            certchain_pem_path: "./tls/fullchain.pem".to_string(),
            key_pem_path: "./tls/privkey.pem".to_string(),
        }
    }
}
