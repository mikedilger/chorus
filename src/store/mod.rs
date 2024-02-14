pub mod event_store;
pub use event_store::EventStore;

use crate::error::Error;
use crate::types::Event;
use heed::types::{OwnedType, UnalignedSlice};
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use std::fs;

#[derive(Debug)]
pub struct Store {
    events: EventStore,
    env: Env,
    ids: Database<UnalignedSlice<u8>, OwnedType<usize>>,
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
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("ids")
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

    pub fn store_event(&self, event: &Event) -> Result<usize, Error> {
        // TBD: should we validate the event?

        let mut txn = self.env.write_txn()?;
        let offset;

        // Only if it doesn't already exist
        if self.ids.get(&txn, event.id().0.as_slice())?.is_none() {
            offset = self.events.store_event(event)?;

            // Index by id
            self.ids.put(&mut txn, event.id().0.as_slice(), &offset)?;
            txn.commit()?;
        } else {
            return Err(Error::Duplicate);
        }

        Ok(offset)
    }
}
