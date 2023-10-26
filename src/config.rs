use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_directory: String,
    pub ip_address: String,
    pub port: u16,
    pub name: Option<String>,
    pub description: Option<String>,
    pub public_key_hex: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            data_directory: "/tmp".to_string(),
            ip_address: "127.0.0.1".to_string(),
            port: 80,
            name: None,
            description: None,
            public_key_hex: None,
        }
    }
}
