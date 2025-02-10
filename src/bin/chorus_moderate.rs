use chorus::error::Error;
use pocket_types::{Event, Filter, Kind};
use std::env;
use std::io::Write;

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

    // These kinds don't need approval:
    let allowed_kinds = [
        Kind::from(4),     // Encrypted Direct Message
        Kind::from(1059),  // Giftwrap
        Kind::from(10002), // Relay list
        Kind::from(10050), // DM Relay list
        Kind::from(0),     // Metadata
        Kind::from(3),     // Following list
        Kind::from(7),     // Reaction
    ];

    let store = chorus::setup_store(&config)?;

    let mut buffer: [u8; 128] = [0; 128];
    let (_incount, _outcount, filter) = Filter::from_json(b"{}", &mut buffer)?;
    let screen = |_: &Event| -> bool { true };

    let mut events = store.find_events(
        filter,
        config.allow_scraping,
        config.allow_scrape_if_limited_to,
        config.allow_scrape_if_max_seconds,
        screen,
    )?;

    let mut stdout = std::io::stdout();
    let stdin = std::io::stdin();
    let mut input = String::new();

    'eventloop: for event in events.drain(..) {
        if allowed_kinds.contains(&event.kind()) {
            continue;
        }

        // Skip ephemeral events which don't need approval
        if event.kind().is_ephemeral() {
            continue;
        }

        // Skip if the author is authorized user
        if chorus::is_authorized_user(event.pubkey()) {
            continue;
        }

        //let bytes = event.as_json()?;
        //let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
        //println!("{s}");

        // Skip if event marked approved
        if matches!(
            chorus::get_event_approval(&store, event.id()),
            Ok(Some(true))
        ) {
            continue;
        }

        // Skip if pubkey marked approved
        if matches!(
            chorus::get_pubkey_approval(&store, event.pubkey()),
            Ok(Some(true))
        ) {
            continue;
        }

        // Delete if pubkey marked banned
        if matches!(
            chorus::get_pubkey_approval(&store, event.pubkey()),
            Ok(Some(false))
        ) {
            store.remove_event(event.id())?;
            continue;
        }

        println!("---------------------------------------------------------------");
        println!("kind={} id={}", event.kind(), event.id());
        println!("{}", String::from_utf8_lossy(event.content()));
        println!("---------------------------------------------------------------");

        println!("   Pubkey:  (p) approve, (P) ban and delete");
        println!("   Id:      (i) approve, (I) ban and delete");
        println!("   other:   (s) skip, (q) quit");

        loop {
            print!(">> ");
            let _ = stdout.flush();
            input.clear();
            stdin.read_line(&mut input)?;
            if input.is_empty() {
                continue;
            }
            match input.bytes().next().unwrap() {
                b'p' => {
                    chorus::mark_pubkey_approval(&store, event.pubkey(), true)?;
                    println!("User approved.");
                    break;
                }
                b'P' => {
                    chorus::mark_pubkey_approval(&store, event.pubkey(), false)?;
                    store.remove_event(event.id())?;
                    println!("User banned.");
                    break;
                }
                b'i' => {
                    chorus::mark_event_approval(&store, event.id(), true)?;
                    println!("Event approved.");
                    break;
                }
                b'I' => {
                    chorus::mark_event_approval(&store, event.id(), false)?;
                    store.remove_event(event.id())?;
                    println!("Event banned.");
                    break;
                }
                b's' => {
                    println!("Skipped.");
                    break;
                }
                b'q' => break 'eventloop,
                _ => {
                    println!("?");
                }
            }
        }
    }

    Ok(())
}
