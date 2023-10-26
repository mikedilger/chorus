pub mod event_store;
pub use event_store::EventStore;

use crate::error::Error;
use heed::types::{CowSlice, OwnedType};
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use nostr_types::Event;
use std::fs;

#[derive(Debug)]
pub struct Store {
    pub events: EventStore,
    pub env: Env,
    pub id_map: Database<CowSlice<u8>, OwnedType<usize>>,
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
        let id_map = env
            .database_options()
            .types::<CowSlice<u8>, OwnedType<usize>>()
            .create(&mut txn)?;
        txn.commit()?;

        log::info!("Store is setup");

        let event_map_file = format!("{}/event.map", data_directory);

        Ok(Store {
            events: EventStore::new(event_map_file)?,
            env,
            id_map,
        })
    }

    pub fn store_event(&self, event: &Event) -> Result<(), Error> {
        // TBD: should we validate the event?
        let mut txn = self.env.write_txn()?;

        // Only if it doesn't already exist
        if self.id_map.get(&txn, event.id.as_slice())?.is_none() {
            let offset = self.events.store_event(event)?;
            self.id_map.put(&mut txn, event.id.as_slice(), &offset)?;
        } else {
            log::debug!("Existing event not stored");
        }

        txn.commit()?;

        Ok(())
    }
}
