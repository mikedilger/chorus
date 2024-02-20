use chorus_lib::config::{Config, FriendlyConfig};
use chorus_lib::error::Error;
use chorus_lib::store::Store;
use chorus_lib::types::{Event, Filter};
use std::env;
use std::fs::OpenOptions;
use std::io::Read;

fn main() -> Result<(), Error> {
    env_logger::builder()
        .format_target(false)
        .format_module_path(false)
        .format_timestamp_millis()
        .init();

    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    // Read config file
    let mut file = OpenOptions::new().read(true).open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let friendly_config: FriendlyConfig = ron::from_str(&contents)?;
    let mut config: Config = friendly_config.into_config()?;
    log::debug!("Loaded config file.");

    // Force allow of scraping (this program is a scraper)
    config.allow_scraping = true;

    // Setup store
    let store = Store::new(&config.data_directory, config.allow_scraping)?;

    let mut buffer: [u8; 128] = [0; 128];
    let (_incount, _outcount, filter) = Filter::from_json(b"{}", &mut buffer)?;
    let screen = |_: &Event<'_>| -> bool { true };

    let mut events = store.find_events(filter, screen)?;
    for event in events.drain(..) {
        let bytes = event.as_json()?;
        let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
        println!("{s}");
    }

    Ok(())
}
