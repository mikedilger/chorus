use crate::config::Config;
use hyper::server::conn::Http;
use lazy_static::lazy_static;
use tokio::sync::RwLock;

pub struct Globals {
    pub config: RwLock<Config>,
    pub http_server: Http,
}

lazy_static! {
    pub static ref GLOBALS: Globals = {
        let mut http_server = hyper::server::conn::Http::new();
        http_server.http1_only(true);
        http_server.http1_keep_alive(true);

        Globals {
            config: RwLock::new(Config::default()),
            http_server,
        }
    };
}
