use crate::config::Config;
use crate::store::Store;
use lazy_static::lazy_static;
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub store: OnceLock<Store>,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        Globals {
            config: RwLock::new(Config::default()),
            store: OnceLock::new(),
        }
    };
}
