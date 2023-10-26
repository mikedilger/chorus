use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ip_address: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ip_address: "127.0.0.1".to_string(),
            port: 80,
        }
    }
}
