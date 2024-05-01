use chorus::error::Error;
use std::env;

fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus_compress <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    let config = chorus::load_config(config_path)?;

    chorus::setup_logging(&config);

    let store = chorus::setup_store(&config)?;

    let _store = unsafe { store.rebuild()? };

    Ok(())
}
