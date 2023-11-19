pub mod event_store;
pub use event_store::EventStore;

use crate::error::Error;
use heed::types::{CowSlice, OwnedType};
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use nostr_types::{Event, Id, PublicKey, Unixtime};
use std::fs;

#[derive(Debug)]
pub struct Store {
    pub events: EventStore,
    pub env: Env,
    pub id_index: Database<CowSlice<u8>, OwnedType<usize>>,
    pub createdat_index: Database<CowSlice<u8>, OwnedType<usize>>,
    pub author_index: Database<CowSlice<u8>, OwnedType<usize>>,
    pub kind_index: Database<CowSlice<u8>, OwnedType<usize>>,
    pub tag_index: Database<CowSlice<u8>, OwnedType<usize>>,
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
        let id_index = env
            .database_options()
            .types::<CowSlice<u8>, OwnedType<usize>>()
            .create(&mut txn)?;
        let createdat_index = env
            .database_options()
            .types::<CowSlice<u8>, OwnedType<usize>>()
            .create(&mut txn)?;
        let author_index = env
            .database_options()
            .types::<CowSlice<u8>, OwnedType<usize>>()
            .create(&mut txn)?;
        let kind_index = env
            .database_options()
            .types::<CowSlice<u8>, OwnedType<usize>>()
            .create(&mut txn)?;
        let tag_index = env
            .database_options()
            .types::<CowSlice<u8>, OwnedType<usize>>()
            .create(&mut txn)?;

        txn.commit()?;

        log::info!("Store is setup");

        let event_map_file = format!("{}/event.map", data_directory);

        Ok(Store {
            events: EventStore::new(event_map_file)?,
            env,
            id_index,
            createdat_index,
            author_index,
            kind_index,
            tag_index,
        })
    }

    pub fn store_event(&self, event: &Event) -> Result<(), Error> {
        // TBD: should we validate the event?
        let mut txn = self.env.write_txn()?;

        // Only if it doesn't already exist
        if self.id_index.get(&txn, event.id.as_slice())?.is_none() {
            // Store into event_store
            let offset = self.events.store_event(event)?;

            // Index into id_index
            self.id_index
                .put(&mut txn, Self::id_index_key(event), &offset)?;

            // Index into createdat_index
            self.createdat_index
                .put(&mut txn, &Self::createdat_index_key(event), &offset)?;

            // Index into author_index
            self.author_index
                .put(&mut txn, &Self::author_index_key(event), &offset)?;

            // Index into kind_index
            self.kind_index
                .put(&mut txn, &Self::kind_index_key(event), &offset)?;

            // Index into tag index
            for tag in event.tags.iter() {
                let tn = tag.tagname();
                if tn.len() == 1 {
                    let letter = tn.as_bytes()[0];
                    let tv = tag.value(1)?;
                    self.tag_index.put(
                        &mut txn,
                        &Self::tag_index_key(letter, &tv, event.created_at, event.id),
                        &offset,
                    )?;
                }
            }
        } else {
            log::debug!("Existing event not stored");
        }

        txn.commit()?;

        Ok(())
    }

    // id
    fn id_index_key(event: &Event) -> &[u8] {
        event.id.as_slice()
    }

    // reverse(created_at) + id
    fn createdat_index_key(event: &Event) -> Vec<u8> {
        let mut key: Vec<u8> =
            Vec::with_capacity(std::mem::size_of::<i64>() + std::mem::size_of::<Id>());
        key.extend((i64::MAX - event.created_at.0).to_be_bytes().as_slice());
        key.extend(event.id.as_slice());
        key
    }

    // author + reverse(created_at) + id
    fn author_index_key(event: &Event) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<PublicKey>()
                + std::mem::size_of::<i64>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(event.pubkey.as_bytes());
        key.extend((i64::MAX - event.created_at.0).to_be_bytes().as_slice());
        key.extend(event.id.as_slice());
        key
    }

    // kind + reverse(created_at) + id
    fn kind_index_key(event: &Event) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<u32>() + std::mem::size_of::<i64>() + std::mem::size_of::<Id>(),
        );
        let ek: u32 = event.kind.into();
        key.extend(ek.to_be_bytes().as_slice());
        key.extend((i64::MAX - event.created_at.0).to_be_bytes().as_slice());
        key.extend(event.id.as_slice());
        key
    }

    // tagletter + tagvalue_padded_214 + created_at + id   (= 255)
    fn tag_index_key(tag: u8, value: &str, created_at: Unixtime, id: Id) -> Vec<u8> {
        let padlen = 214;
        let size = 1 + padlen + std::mem::size_of::<i64>() + std::mem::size_of::<Id>();
        assert_eq!(size, 255);
        let mut key: Vec<u8> = Vec::with_capacity(size);
        key.push(tag);
        if value.len() <= padlen {
            key.extend(value.as_bytes());
            key.extend(core::iter::repeat(0).take(padlen - value.len()));
        } else {
            key.extend(&value.as_bytes()[..214]);
        }
        key.extend((i64::MAX - created_at.0).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }
}
