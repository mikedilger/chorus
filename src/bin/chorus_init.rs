use chorus::error::Error;
use chorus::globals::GLOBALS;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    let config = chorus::load_config(&config_path)?;

    chorus::setup_logging(&config);

    // Log host name
    log::info!(target: "Server", "HOSTNAME = {}", config.hostname);

    chorus::setup_store(&config)?;

    let _ = GLOBALS.store.get().unwrap().sync();

    Ok(())
}
