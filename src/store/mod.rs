pub mod event_store;
pub use event_store::EventStore;

use crate::error::{ChorusError, Error};
use crate::types::{Event, Filter, Id, Kind, Pubkey, Time};
use heed::types::{OwnedType, UnalignedSlice};
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use std::fs;
use std::ops::Bound;

#[derive(Debug)]
pub struct Store {
    events: EventStore,
    env: Env,
    ids: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    akci: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    atci: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ktci: Database<UnalignedSlice<u8>, OwnedType<usize>>,
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
        let akci = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("akci")
            .create(&mut txn)?;
        let atci = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("atci")
            .create(&mut txn)?;
        let ktci = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("ktci")
            .create(&mut txn)?;
        txn.commit()?;

        log::info!("Store is setup");

        let event_map_file = format!("{}/event.map", data_directory);

        Ok(Store {
            events: EventStore::new(event_map_file)?,
            env,
            ids,
            akci,
            atci,
            ktci,
        })
    }

    pub fn store_event(&self, event: &Event) -> Result<usize, Error> {
        // TBD: should we validate the event?

        let mut txn = self.env.write_txn()?;
        let offset;

        // Only if it doesn't already exist
        if self.ids.get(&txn, event.id().0.as_slice())?.is_none() {
            offset = self.events.store_event(event)?;

            // Do not index ephemeral events
            if !event.kind().is_ephemeral() {
                // Index by id
                self.ids.put(&mut txn, event.id().0.as_slice(), &offset)?;

                // Index by author and kind (with created_at and id)
                self.akci.put(
                    &mut txn,
                    &Self::key_akci(event.pubkey(), event.kind(), event.created_at(), event.id()),
                    &offset,
                )?;

                for mut tsi in event.tags()?.iter() {
                    if let Some(tagname) = tsi.next() {
                        // FIXME make sure it is a letter too
                        if tagname.len() == 1 {
                            if let Some(tagvalue) = tsi.next() {
                                // Index by author and tag (with created_at and id)
                                self.atci.put(
                                    &mut txn,
                                    &Self::key_atci(
                                        event.pubkey(),
                                        tagname[0],
                                        tagvalue,
                                        event.created_at(),
                                        event.id(),
                                    ),
                                    &offset,
                                )?;

                                // Index by kind and tag (with created_at and id)
                                self.ktci.put(
                                    &mut txn,
                                    &Self::key_ktci(
                                        event.kind(),
                                        tagname[0],
                                        tagvalue,
                                        event.created_at(),
                                        event.id(),
                                    ),
                                    &offset,
                                )?;
                            }
                        }
                    }
                }
            }

            txn.commit()?;
        } else {
            return Err(ChorusError::Duplicate.into());
        }

        Ok(offset)
    }

    /// Get an event by offset
    pub fn get_event_by_offset(&self, offset: usize) -> Result<Option<Event>, Error> {
        self.events.get_event_by_offset(offset)
    }

    /// Get an event by Id
    pub fn get_event_by_id(&self, id: Id) -> Result<Option<Event>, Error> {
        let txn = self.env.read_txn()?;
        if let Some(offset) = self.ids.get(&txn, id.0.as_slice())? {
            self.events.get_event_by_offset(offset)
        } else {
            Ok(None)
        }
    }

    pub fn find_events(&self, filter: Filter) -> Result<Vec<Event>, Error> {
        let mut output: Vec<Event> = Vec::new();

        if filter.num_ids() > 0 {
            // Fetch by id
            for id in filter.ids() {
                if let Some(event) = self.get_event_by_id(id)? {
                    // and check each against the rest of the filter
                    if filter.event_matches(&event)? {
                        output.push(event);
                    }
                }
                // Stop if limited
                if output.len() >= filter.limit() as usize {
                    return Ok(output);
                }
            }
        } else if filter.num_authors() > 0 && filter.num_kinds() > 0 {
            for author in filter.authors() {
                for kind in filter.kinds() {
                    let start_prefix = Self::key_akci(
                        author,
                        kind,
                        filter.until(), // scan goes backwards in time
                        Id([0; 32]),
                    );
                    let end_prefix = Self::key_akci(
                        author,
                        kind,
                        filter.since(), // scan goes backwards in time
                        Id([255; 32]),
                    );
                    let range = (
                        Bound::Included(&*start_prefix),
                        Bound::Excluded(&*end_prefix),
                    );
                    let txn = self.env.read_txn()?;
                    let iter = self.akci.range(&txn, &range)?;
                    for result in iter {
                        let (_key, offset) = result?;
                        if let Some(event) = self.events.get_event_by_offset(offset)? {
                            // check against the rest of the filter
                            if filter.event_matches(&event)? {
                                output.push(event);
                            }
                        }
                        // Stop if limited
                        if output.len() >= filter.limit() as usize {
                            return Ok(output);
                        }
                    }
                }
            }
        } else if filter.num_authors() > 0 && !filter.tags()?.is_empty() {
            for author in filter.authors() {
                let tags = filter.tags()?;
                for mut tag in tags.iter() {
                    if let Some(tag0) = tag.next() {
                        if let Some(tagvalue) = tag.next() {
                            let start_prefix = Self::key_atci(
                                author,
                                tag0[0],
                                tagvalue,
                                filter.until(), // scan goes backwards in time
                                Id([0; 32]),
                            );
                            let end_prefix = Self::key_atci(
                                author,
                                tag0[0],
                                tagvalue,
                                filter.since(), // scan goes backwards in time
                                Id([255; 32]),
                            );
                            let range = (
                                Bound::Included(&*start_prefix),
                                Bound::Excluded(&*end_prefix),
                            );
                            let txn = self.env.read_txn()?;
                            let iter = self.akci.range(&txn, &range)?;
                            for result in iter {
                                let (_key, offset) = result?;
                                if let Some(event) = self.events.get_event_by_offset(offset)? {
                                    // check against the rest of the filter
                                    if filter.event_matches(&event)? {
                                        output.push(event);
                                    }
                                }
                                // Stop if limited
                                if output.len() >= filter.limit() as usize {
                                    return Ok(output);
                                }
                            }
                        }
                    }
                }
            }
        } else if filter.num_kinds() > 0 && !filter.tags()?.is_empty() {
            for kind in filter.kinds() {
                let tags = filter.tags()?;
                for mut tag in tags.iter() {
                    if let Some(tag0) = tag.next() {
                        if let Some(tagvalue) = tag.next() {
                            let start_prefix = Self::key_ktci(
                                kind,
                                tag0[0],
                                tagvalue,
                                filter.until(), // scan goes backwards in time
                                Id([0; 32]),
                            );
                            let end_prefix = Self::key_ktci(
                                kind,
                                tag0[0],
                                tagvalue,
                                filter.since(), // scan goes backwards in time
                                Id([255; 32]),
                            );
                            let range = (
                                Bound::Included(&*start_prefix),
                                Bound::Excluded(&*end_prefix),
                            );
                            let txn = self.env.read_txn()?;
                            let iter = self.akci.range(&txn, &range)?;
                            for result in iter {
                                let (_key, offset) = result?;
                                if let Some(event) = self.events.get_event_by_offset(offset)? {
                                    // check against the rest of the filter
                                    if filter.event_matches(&event)? {
                                        output.push(event);
                                    }
                                }
                                // Stop if limited
                                if output.len() >= filter.limit() as usize {
                                    return Ok(output);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            return Err(ChorusError::Scraper.into());
        }

        Ok(output)
    }

    // For looking up event by Author and Kind
    // author(32) + kind(2) + reversecreatedat(8) + id(32)
    #[allow(dead_code)]
    fn key_akci(author: Pubkey, kind: Kind, created_at: Time, id: Id) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Pubkey>()
                + std::mem::size_of::<Kind>()
                + std::mem::size_of::<Time>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(author.as_slice());
        key.extend(kind.0.to_be_bytes());
        key.extend((u64::MAX - created_at.0).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Author and Tag
    // author(32) + tagletter(1) + fixlentag(182) + reversecreatedat(8) + id(32)
    #[allow(dead_code)]
    fn key_atci(author: Pubkey, letter: u8, tag_value: &[u8], created_at: Time, id: Id) -> Vec<u8> {
        const PADLEN: usize = 182;
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Pubkey>()
                + PADLEN
                + std::mem::size_of::<Time>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(author.as_slice());
        key.push(letter);
        if tag_value.len() <= PADLEN {
            key.extend(tag_value);
            key.extend(core::iter::repeat(0).take(PADLEN - tag_value.len()));
        } else {
            key.extend(&tag_value[..PADLEN]);
        }
        key.extend((u64::MAX - created_at.0).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Kind and Tag
    // kind(2) + tagletter(1) + fixlentag(182) + reversecreatedat(8) + id(32)
    #[allow(dead_code)]
    fn key_ktci(kind: Kind, letter: u8, tag_value: &[u8], created_at: Time, id: Id) -> Vec<u8> {
        const PADLEN: usize = 182;
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Kind>()
                + PADLEN
                + std::mem::size_of::<Time>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(kind.0.to_be_bytes());
        key.push(letter);
        if tag_value.len() <= PADLEN {
            key.extend(tag_value);
            key.extend(core::iter::repeat(0).take(PADLEN - tag_value.len()));
        } else {
            key.extend(&tag_value[..PADLEN]);
        }
        key.extend((u64::MAX - created_at.0).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }
}
