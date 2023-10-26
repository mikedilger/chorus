use crate::config::Config;
use lazy_static::lazy_static;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        Globals {
            config: RwLock::new(Config::default()),
        }
    };
}
