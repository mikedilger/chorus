use chorus_lib::config::{Config, FriendlyConfig};
use chorus_lib::error::Error;
use chorus_lib::store::Store;
use chorus_lib::types::{Event, Filter, Kind};
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Write};

fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus_moderate <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    // Read config file
    let mut file = OpenOptions::new().read(true).open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let friendly_config: FriendlyConfig = toml::from_str(&contents)?;
    let mut config: Config = friendly_config.into_config()?;

    env_logger::Builder::new()
        .filter_level(config.library_log_level)
        .filter(Some("Server"), config.server_log_level)
        .filter(Some("Client"), config.client_log_level)
        .format_target(true)
        .format_module_path(false)
        .format_timestamp_millis()
        .init();

    log::debug!(target: "Server", "Loaded config file.");

    // Force allow of scraping (this program is a scraper)
    config.allow_scraping = true;

    // Setup store
    let store = Store::new(&config)?;

    let mut buffer: [u8; 128] = [0; 128];
    let (_incount, _outcount, filter) = Filter::from_json(b"{}", &mut buffer)?;
    let screen = |_: &Event<'_>| -> bool { true };

    let mut events = store.find_events(filter, screen, &config)?;

    let mut stdout = std::io::stdout();
    let stdin = std::io::stdin();
    let mut input = String::new();

    'eventloop: for event in events.drain(..) {
        // Skip DMs which don't need approval
        if event.kind() == Kind(4) || event.kind() == Kind(1059) {
            continue;
        }

        // Skip relay lists which don't need approval
        if event.kind() == Kind(10002) {
            continue;
        }

        // Skip ephemeral events which don't need approval
        if event.kind().is_ephemeral() {
            continue;
        }

        // Skip if the author is authorized user
        if config.user_keys.contains(&event.pubkey()) {
            continue;
        }

        //let bytes = event.as_json()?;
        //let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
        //println!("{s}");

        // Skip if event marked approved
        if matches!(store.get_event_approval(event.id()), Ok(Some(true))) {
            continue;
        }

        // Skip if pubkey marked approved
        if matches!(store.get_pubkey_approval(event.pubkey()), Ok(Some(true))) {
            continue;
        }

        println!("---------------------------------------------------------------");
        println!("id={} pubkey={}", event.id(), event.pubkey());
        println!("{}", String::from_utf8_lossy(event.content()));
        println!("---------------------------------------------------------------");

        println!(">> Pubkey:  (p) approve, (P) ban and delete");
        println!(">> Id:      (i) approve, (I) ban and delete");
        println!(">> other:   (s) skip, (q) quit");

        loop {
            print!(">> ");
            let _ = stdout.flush();
            stdin.read_line(&mut input)?;
            if input.is_empty() {
                continue;
            }
            match input.bytes().next().unwrap() {
                b'p' => {
                    store.mark_pubkey_approval(event.pubkey(), true)?;
                    println!("User approved.");
                    break;
                }
                b'P' => {
                    store.mark_pubkey_approval(event.pubkey(), false)?;
                    store.delete_event(event.id())?;
                    println!("User banned.");
                    break;
                }
                b'i' => {
                    store.mark_event_approval(event.id(), true)?;
                    println!("Event approved.");
                    break;
                }
                b'I' => {
                    store.mark_event_approval(event.id(), false)?;
                    store.delete_event(event.id())?;
                    println!("Event banned.");
                    break;
                }
                b's' => break,
                b'q' => break 'eventloop,
                _ => {
                    println!("?");
                }
            }
        }
    }

    Ok(())
}
