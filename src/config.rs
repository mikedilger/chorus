use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_directory: String,
    pub ip_address: String,
    pub port: u16,
    pub use_tls: bool,
    pub certchain_pem_path: String,
    pub key_pem_path: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub public_key_hex: Option<String>,
    pub user_hex_keys: Vec<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            data_directory: "/tmp".to_string(),
            ip_address: "127.0.0.1".to_string(),
            port: 80,
            use_tls: false,
            certchain_pem_path: "./tls/fullchain.pem".to_string(),
            key_pem_path: "./tls/privkey.pem".to_string(),
            name: None,
            description: None,
            public_key_hex: None,
            user_hex_keys: vec![],
        }
    }
}
