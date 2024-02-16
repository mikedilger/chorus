pub mod event_store;
pub use event_store::EventStore;

use crate::error::{ChorusError, Error};
use crate::types::{Event, Filter, Id, Kind, Pubkey, Time};
use heed::byteorder::BigEndian;
use heed::types::{OwnedType, UnalignedSlice, Unit, U64};
use heed::{Database, Env, EnvFlags, EnvOpenOptions, RwTxn};
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
    deleted: Database<U64<BigEndian>, Unit>,
}

impl Store {
    /// Setup persistent storage
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
        let deleted = env
            .database_options()
            .types::<U64<BigEndian>, Unit>()
            .name("deleted")
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
            deleted,
        })
    }

    /// Store an event.
    ///
    /// Returns the offset where the event is stored at, which can be used to fetch
    /// the event via get_event_by_offset().
    ///
    /// If the event already exists, you will get a ChorusError::Duplicate
    ///
    /// If the event is ephemeral, it will be stored and you will get an offset, but
    /// it will not be indexed.
    pub fn store_event(&self, event: &Event) -> Result<usize, Error> {
        // TBD: should we validate the event?

        let mut txn = self.env.write_txn()?;
        let offset;

        // Only if it doesn't already exist
        if self.ids.get(&txn, event.id().0.as_slice())?.is_none() {
            offset = self.events.store_event(event)?;

            if event.kind().is_ephemeral() {
                // Do not index ephemeral events, not even by id.
                // But save them in the deleted table
                let offset_u64 = offset as u64;
                self.deleted.put(&mut txn, &offset_u64, &())?;
            } else {
                // Index the event
                self.index(&mut txn, event, offset)?;
            }

            // If replaceable or parameterized replaceable,
            // find and delete all but the first one in the group
            if event.kind().is_replaceable() || event.kind().is_parameterized_replaceable() {
                self.delete_replaced(&mut txn, event)?;
            }

            txn.commit()?;
        } else {
            return Err(ChorusError::Duplicate.into());
        }

        Ok(offset)
    }

    /// Get an event by its offset.
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

    /// Find all events that match the filter
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
                'kind: for kind in filter.kinds() {
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
                                // If kind is replaceable (and not parameterized)
                                // then don't take any more events for this author-kind
                                // pair.
                                // NOTE that this optimization is difficult to implement
                                // for other replaceable event situations
                                if kind.is_replaceable() {
                                    continue 'kind;
                                }
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

    /// Delete an event by id
    pub fn delete(&self, id: Id) -> Result<(), Error> {
        let txn = self.env.read_txn()?;
        if let Some(offset) = self.ids.get(&txn, id.0.as_slice())? {
            drop(txn);
            self.set_event_as_deleted(offset)?;
        }
        Ok(())
    }

    // Index the event
    fn index(&self, txn: &mut RwTxn<'_>, event: &Event, offset: usize) -> Result<(), Error> {
        // Index by id
        self.ids.put(txn, event.id().0.as_slice(), &offset)?;

        // Index by author and kind (with created_at and id)
        self.akci.put(
            txn,
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
                            txn,
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
                            txn,
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

        Ok(())
    }

    // Remove the event from all indexes (except the 'id' index)
    fn deindex(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        for mut tsi in event.tags()?.iter() {
            if let Some(tagname) = tsi.next() {
                // FIXME make sure it is a letter too
                if tagname.len() == 1 {
                    if let Some(tagvalue) = tsi.next() {
                        // Index by author and tag (with created_at and id)
                        self.atci.delete(
                            txn,
                            &Self::key_atci(
                                event.pubkey(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;

                        // Index by kind and tag (with created_at and id)
                        self.ktci.delete(
                            txn,
                            &Self::key_ktci(
                                event.kind(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;
                    }
                }
            }
        }

        // Index by author and kind (with created_at and id)
        self.akci.delete(
            txn,
            &Self::key_akci(event.pubkey(), event.kind(), event.created_at(), event.id()),
        )?;

        // We leave it in the id map. If someone wants to load the replaced event by id
        // they can still do it.
        // self.ids.delete(&mut txn, event.id().0.as_slice())?;

        Ok(())
    }

    // Set an event as deleted
    // This removes it from indexes (except the id index) and adds it to the deleted table
    fn set_event_as_deleted(&self, offset: usize) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;

        let offset_u64 = offset as u64;

        // Check if it is already deleted
        if self.deleted.get(&txn, &offset_u64)?.is_some() {
            return Ok(());
        }

        // Add to deleted database in case we need to get at it in the future.
        self.deleted.put(&mut txn, &offset_u64, &())?;

        // Get event
        let event = match self.events.get_event_by_offset(offset)? {
            Some(event) => event,
            None => return Ok(()),
        };

        // Remove from indexes
        self.deindex(&mut txn, &event)?;

        txn.commit()?;

        Ok(())
    }

    // If the event is replaceable or parameterized replaceable
    // this deletes all the events in that group except the most recent one.
    fn delete_replaced(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        if event.kind().is_replaceable() {
            let start_prefix = Self::key_akci(
                event.pubkey(),
                event.kind(),
                Time::max(), // database is ordered in reverse time
                Id([0; 32]),
            );
            let end_prefix =
                Self::key_akci(event.pubkey(), event.kind(), Time::min(), Id([255; 32]));
            let range = (
                Bound::Included(&*start_prefix),
                Bound::Excluded(&*end_prefix),
            );
            let iter = self.akci.range(txn, &range)?;
            let mut first = true;
            for result in iter {
                // Keep the first result
                if first {
                    first = false;
                    continue;
                }

                let (_key, offset) = result?;

                // Delete the event
                self.set_event_as_deleted(offset)?;
            }
        } else if event.kind().is_parameterized_replaceable() {
            let tags = event.tags()?;
            if let Some(identifier) = tags.get_value(b"d") {
                let start_prefix =
                    Self::key_atci(event.pubkey(), b'd', identifier, Time::max(), Id([0; 32]));
                let end_prefix =
                    Self::key_atci(event.pubkey(), b'd', identifier, Time::min(), Id([255; 32]));
                let range = (
                    Bound::Included(&*start_prefix),
                    Bound::Excluded(&*end_prefix),
                );
                let iter = self.akci.range(txn, &range)?;
                let mut first = true;
                for result in iter {
                    // Keep the first result
                    if first {
                        first = false;
                        continue;
                    }

                    let (_key, offset) = result?;

                    // Delete the event
                    self.set_event_as_deleted(offset)?;
                }
            }
        }

        Ok(())
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
