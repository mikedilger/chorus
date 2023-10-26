pub mod event_store;
pub use event_store::EventStore;

use crate::error::Error;
use crate::types::Id;
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use std::fs;

#[derive(Debug)]
pub struct Store {
    events: EventStore,
    env: Env,
    ids: Database<Id, usize>,
}

impl Store {
    pub fn new(data_directory: &str) -> Result<Store, Error> {
        let mut builder = EnvOpenOptions::new();
        unsafe {
            builder.flags(EnvFlags::NO_TLS);
        }
        builder.max_dbs(32);
        builder.map_size(1048576 * 1024 * 24); // 24 GB

        let dir = format!("{}/lmdb", data_directory);
        fs::create_dir_all(&dir)?;

        let env = match builder.open(&dir) {
            Ok(env) => env,
            Err(e) => {
                log::error!("Unable to open LMDB at {}", dir);
                return Err(e.into());
            }
        };

        // Open/Create maps
        let mut txn = env.write_txn()?;
        let ids = env
            .database_options()
            .types::<Id, usize>()
            .create(&mut txn)?;
        txn.commit()?;

        log::info!("Store is setup");

        let event_map_file = format!("{}/event.map", data_directory);

        Ok(Store {
            events: EventStore::new(event_map_file)?,
            env,
            ids,
        })
    }
}
