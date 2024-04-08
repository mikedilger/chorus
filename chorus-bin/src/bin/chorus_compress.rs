use chorus_lib::config::{Config, FriendlyConfig};
use chorus_lib::error::Error;
use chorus_lib::store::Store;
use std::env;
use std::fs::OpenOptions;
use std::io::Read;

fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus_compress <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    // Read config file
    let mut file = OpenOptions::new().read(true).open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let friendly_config: FriendlyConfig = toml::from_str(&contents)?;
    let config: Config = friendly_config.into_config()?;

    env_logger::Builder::new()
        .filter_level(config.library_log_level)
        .filter(Some("Server"), config.server_log_level)
        .filter(Some("Client"), config.client_log_level)
        .format_target(true)
        .format_module_path(false)
        .format_timestamp_millis()
        .init();

    log::debug!(target: "Server", "Loaded config file.");

    Store::rebuild(&config)?;

    Ok(())
}
