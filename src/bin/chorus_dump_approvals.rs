use chorus::error::Error;
use std::env;

fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus_moderate <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    let mut config = chorus::load_config(config_path)?;

    // Force allow of scraping (this program is a scraper)
    config.allow_scraping = true;

    chorus::setup_logging(&config);
    chorus::setup_store(&config)?;

    for (id, approved) in chorus::dump_event_approvals()? {
        println!("ID {} = {}", id, approved);
    }

    for (pubkey, approved) in chorus::dump_pubkey_approvals()? {
        println!("PUBKEY {} = {}", pubkey, approved);
    }

    Ok(())
}
