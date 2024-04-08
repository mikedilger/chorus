pub mod event_store;
pub use event_store::EventStore;

mod migrations;

use crate::config::Config;
use crate::error::{ChorusError, Error};
use crate::ip::{HashedIp, IpData};
use crate::types::{Event, Filter, Id, Kind, Pubkey, Time};
use heed::types::{OwnedType, UnalignedSlice, Unit, U8};
use heed::{Database, Env, EnvFlags, EnvOpenOptions, RwTxn};
use speedy::{Readable, Writable};
use std::collections::BTreeSet;
use std::fs;
use std::ops::Bound;

#[derive(Debug)]
pub struct Store {
    general: Database<UnalignedSlice<u8>, UnalignedSlice<u8>>,
    events: EventStore,
    env: Env,
    i_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ci_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    tc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ac_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    akc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    atc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ktc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,

    // this is for events deleted by other events
    deleted_events: Database<UnalignedSlice<u8>, Unit>,
    approved_events: Database<UnalignedSlice<u8>, U8>,
    approved_pubkeys: Database<UnalignedSlice<u8>, U8>,
    ip_data: Database<UnalignedSlice<u8>, UnalignedSlice<u8>>,
}

impl Store {
    /// Setup persistent storage
    pub fn new(config: &Config) -> Result<Store, Error> {
        let mut builder = EnvOpenOptions::new();
        unsafe {
            builder.flags(EnvFlags::NO_TLS);
        }
        builder.max_dbs(32);
        builder.map_size(1048576 * 1024 * 24); // 24 GB

        let dir = format!("{}/lmdb", &config.data_directory);
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
        let general = env
            .database_options()
            .types::<UnalignedSlice<u8>, UnalignedSlice<u8>>()
            .create(&mut txn)?;
        let i_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("ids")
            .create(&mut txn)?;
        let ci_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("ci")
            .create(&mut txn)?;
        let tc_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("tci")
            .create(&mut txn)?;
        let ac_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("aci")
            .create(&mut txn)?;
        let akc_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("akci")
            .create(&mut txn)?;
        let atc_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("atci")
            .create(&mut txn)?;
        let ktc_index = env
            .database_options()
            .types::<UnalignedSlice<u8>, OwnedType<usize>>()
            .name("ktci")
            .create(&mut txn)?;
        let deleted_events = env
            .database_options()
            .types::<UnalignedSlice<u8>, Unit>()
            .name("deleted-events")
            .create(&mut txn)?;
        let approved_events = env
            .database_options()
            .types::<UnalignedSlice<u8>, U8>()
            .name("approved-events")
            .create(&mut txn)?;
        let approved_pubkeys = env
            .database_options()
            .types::<UnalignedSlice<u8>, U8>()
            .name("approved-pubkeys")
            .create(&mut txn)?;
        let ip_data = env
            .database_options()
            .types::<UnalignedSlice<u8>, UnalignedSlice<u8>>()
            .name("ip_data")
            .create(&mut txn)?;

        if let Ok(count) = i_index.len(&txn) {
            log::info!("Index: id ({} entries, {} bytes)", count, count * (32 + 8));
        }
        if let Ok(count) = ci_index.len(&txn) {
            log::info!(
                "Index: created_at+id ({} entries, {} bytes)",
                count,
                count * (40 + 8)
            );
        }

        if let Ok(count) = tc_index.len(&txn) {
            log::info!(
                "Index: tag+created_at+id ({} entries, {} bytes)",
                count,
                count * (223 + 8)
            );
        }
        if let Ok(count) = ac_index.len(&txn) {
            log::info!(
                "Index: author+created_at+id ({} entries, {} bytes)",
                count,
                count * (72 + 8)
            );
        }
        if let Ok(count) = akc_index.len(&txn) {
            log::info!(
                "Index: author+kind+created_at+id ({} entries, {} bytes)",
                count,
                count * (74 + 8)
            );
        }
        if let Ok(count) = atc_index.len(&txn) {
            log::info!(
                "Index: author+tags+created_at+id ({} entries, {} bytes)",
                count,
                count * (255 + 8)
            );
        }
        if let Ok(count) = ktc_index.len(&txn) {
            log::info!(
                "Index: kind+tags+created_at+id ({} entries, {} bytes)",
                count,
                count * (225 + 8)
            );
        }

        if let Ok(count) = deleted_events.len(&txn) {
            log::info!("{} deleted events", count);
        }
        if let Ok(count) = ip_data.len(&txn) {
            log::info!("{count} IP addresses reputationally tracked");
        }

        txn.commit()?;

        let event_map_file = format!("{}/event.map", &config.data_directory);
        let events = EventStore::new(event_map_file)?;

        let store = Store {
            general,
            events,
            env,
            i_index,
            ci_index,
            tc_index,
            ac_index,
            akc_index,
            atc_index,
            ktc_index,
            deleted_events,
            approved_events,
            approved_pubkeys,
            ip_data,
        };

        // This is in migrations.rs
        store.migrate()?;

        Ok(store)
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub fn sync(&self) -> Result<(), Error> {
        self.env.force_sync()?;
        Ok(())
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
        if self.i_index.get(&txn, event.id().0.as_slice())?.is_none() {
            // Reject event if it was deleted
            {
                let deleted_key = Self::key_deleted_events(event.id(), event.pubkey());
                if self.deleted_events.get(&txn, &deleted_key)?.is_some() {
                    return Err(ChorusError::Deleted.into());
                }
            }

            // Store the event
            offset = self.events.store_event(event)?;

            // Index the event
            if !event.kind().is_ephemeral() {
                self.index(&mut txn, event, offset)?;
            }

            // If replaceable or parameterized replaceable,
            // find and delete all but the first one in the group
            if event.kind().is_replaceable() || event.kind().is_parameterized_replaceable() {
                self.delete_replaced(&mut txn, event)?;
            }

            // Handle deletion events
            if event.kind() == Kind(5) {
                self.handle_deletion_event(&mut txn, event)?;
            }

            txn.commit()?;
        } else {
            return Err(ChorusError::Duplicate.into());
        }

        Ok(offset)
    }

    fn handle_deletion_event(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        for mut tag in event.tags()?.iter() {
            if let Some(tagname) = tag.next() {
                if tagname == b"e" {
                    if let Some(id_hex) = tag.next() {
                        if let Ok(id) = Id::read_hex(id_hex) {
                            // Add deletion pair to the event_deleted table
                            let deleted_key = Self::key_deleted_events(id, event.pubkey());
                            self.deleted_events.put(txn, &deleted_key, &())?;

                            // Delete pair
                            if let Some(target) = self.get_event_by_id(id)? {
                                if target.pubkey() == event.pubkey() {
                                    self.delete_by_id(txn, id)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get an event by its offset.
    pub fn get_event_by_offset(&self, offset: usize) -> Result<Event, Error> {
        self.events.get_event_by_offset(offset)
    }

    /// Get an event by Id
    pub fn get_event_by_id(&self, id: Id) -> Result<Option<Event>, Error> {
        let txn = self.env.read_txn()?;
        if let Some(offset) = self.i_index.get(&txn, id.0.as_slice())? {
            Some(self.events.get_event_by_offset(offset)).transpose()
        } else {
            Ok(None)
        }
    }

    /// Find all events that match the filter
    pub fn find_events<F>(
        &self,
        filter: Filter,
        screen: F,
        config: &Config,
    ) -> Result<Vec<Event>, Error>
    where
        F: Fn(&Event) -> bool,
    {
        let txn = self.env.read_txn()?;

        // We insert into a BTreeSet to keep them time-ordered
        let mut output: BTreeSet<Event> = BTreeSet::new();

        if filter.num_ids() > 0 {
            // Fetch by id
            for id in filter.ids() {
                // Stop if limited
                if output.len() >= filter.limit() as usize {
                    break;
                }
                if let Some(event) = self.get_event_by_id(id)? {
                    // and check each against the rest of the filter
                    if filter.event_matches(&event)? && screen(&event) {
                        output.insert(event);
                    }
                }
            }
        } else if filter.num_authors() > 0 && filter.num_kinds() > 0 {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for author in filter.authors() {
                for kind in filter.kinds() {
                    let iter = {
                        let start_prefix = Self::key_akc_index(
                            author,
                            kind,
                            filter.until(), // scan goes backwards in time
                            Id([0; 32]),
                        );
                        let end_prefix = Self::key_akc_index(author, kind, since, Id([255; 32]));
                        let range = (
                            Bound::Included(&*start_prefix),
                            Bound::Excluded(&*end_prefix),
                        );
                        self.akc_index.range(&txn, &range)?
                    };

                    // Count how many we have found of this author-kind pair, so we
                    // can possibly update `since`
                    let mut paircount = 0;

                    'per_event: for result in iter {
                        let (_key, offset) = result?;
                        let event = self.events.get_event_by_offset(offset)?;

                        // If we have gone beyond since, we can stop early
                        // (We have to check because `since` might change in this loop)
                        if event.created_at() < since {
                            break 'per_event;
                        }

                        // check against the rest of the filter
                        if filter.event_matches(&event)? && screen(&event) {
                            // Accept the event
                            output.insert(event);
                            paircount += 1;

                            // Stop this pair if limited
                            if paircount >= filter.limit() as usize {
                                // Since we found the limit just among this pair,
                                // potentially move since forward
                                if event.created_at() > since {
                                    since = event.created_at();
                                }
                                break 'per_event;
                            }

                            // If kind is replaceable (and not parameterized)
                            // then don't take any more events for this author-kind
                            // pair.
                            // NOTE that this optimization is difficult to implement
                            // for other replaceable event situations
                            if kind.is_replaceable() {
                                break 'per_event;
                            }
                        }
                    }
                }
            }
        } else if filter.num_authors() > 0 && !filter.tags()?.is_empty() {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for author in filter.authors() {
                let tags = filter.tags()?;
                for mut tag in tags.iter() {
                    if let Some(tag0) = tag.next() {
                        if let Some(tagvalue) = tag.next() {
                            let iter = {
                                let start_prefix = Self::key_atc_index(
                                    author,
                                    tag0[0],
                                    tagvalue,
                                    filter.until(), // scan goes backwards in time
                                    Id([0; 32]),
                                );
                                let end_prefix = Self::key_atc_index(
                                    author,
                                    tag0[0],
                                    tagvalue,
                                    since,
                                    Id([255; 32]),
                                );
                                let range = (
                                    Bound::Included(&*start_prefix),
                                    Bound::Excluded(&*end_prefix),
                                );
                                self.atc_index.range(&txn, &range)?
                            };

                            // Count how many we have found of this author-tag pair, so we
                            // can possibly update `since`
                            let mut paircount = 0;

                            'per_event: for result in iter {
                                let (_key, offset) = result?;
                                let event = self.events.get_event_by_offset(offset)?;

                                // If we have gone beyond since, we can stop early
                                // (We have to check because `since` might change in this loop)
                                if event.created_at() < since {
                                    break 'per_event;
                                }

                                // check against the rest of the filter
                                if filter.event_matches(&event)? && screen(&event) {
                                    // Accept the event
                                    output.insert(event);
                                    paircount += 1;

                                    // Stop this pair if limited
                                    if paircount >= filter.limit() as usize {
                                        // Since we found the limit just among this pair,
                                        // potentially move since forward
                                        if event.created_at() > since {
                                            since = event.created_at();
                                        }
                                        break 'per_event;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if filter.num_kinds() > 0 && !filter.tags()?.is_empty() {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for kind in filter.kinds() {
                let tags = filter.tags()?;
                for mut tag in tags.iter() {
                    if let Some(tag0) = tag.next() {
                        if let Some(tagvalue) = tag.next() {
                            let iter = {
                                let start_prefix = Self::key_ktc_index(
                                    kind,
                                    tag0[0],
                                    tagvalue,
                                    filter.until(), // scan goes backwards in time
                                    Id([0; 32]),
                                );
                                let end_prefix = Self::key_ktc_index(
                                    kind,
                                    tag0[0],
                                    tagvalue,
                                    since,
                                    Id([255; 32]),
                                );
                                let range = (
                                    Bound::Included(&*start_prefix),
                                    Bound::Excluded(&*end_prefix),
                                );
                                self.ktc_index.range(&txn, &range)?
                            };

                            // Count how many we have found of this kind-tag pair, so we
                            // can possibly update `since`
                            let mut paircount = 0;

                            'per_event: for result in iter {
                                let (_key, offset) = result?;
                                let event = self.events.get_event_by_offset(offset)?;

                                // If we have gone beyond since, we can stop early
                                // (We have to check because `since` might change in this loop)
                                if event.created_at() < since {
                                    break 'per_event;
                                }

                                // check against the rest of the filter
                                if filter.event_matches(&event)? && screen(&event) {
                                    // Accept the event
                                    output.insert(event);
                                    paircount += 1;

                                    // Stop this pair if limited
                                    if paircount >= filter.limit() as usize {
                                        // Since we found the limit just among this pair,
                                        // potentially move since forward
                                        if event.created_at() > since {
                                            since = event.created_at();
                                        }
                                        break 'per_event;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if !filter.tags()?.is_empty() {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            let tags = filter.tags()?;
            for mut tag in tags.iter() {
                if let Some(tag0) = tag.next() {
                    if let Some(tagvalue) = tag.next() {
                        let iter = {
                            let start_prefix = Self::key_tc_index(
                                tag0[0],
                                tagvalue,
                                filter.until(), // scan goes backwards in time
                                Id([0; 32]),
                            );
                            let end_prefix =
                                Self::key_tc_index(tag0[0], tagvalue, since, Id([255; 32]));
                            let range = (
                                Bound::Included(&*start_prefix),
                                Bound::Excluded(&*end_prefix),
                            );
                            self.tc_index.range(&txn, &range)?
                        };

                        let mut rangecount = 0;

                        'per_event: for result in iter {
                            let (_key, offset) = result?;
                            let event = self.events.get_event_by_offset(offset)?;

                            if event.created_at() < since {
                                break 'per_event;
                            }

                            // check against the rest of the filter
                            if filter.event_matches(&event)? && screen(&event) {
                                // Accept the event
                                output.insert(event);
                                rangecount += 1;

                                // Stop this limited
                                if rangecount >= filter.limit() as usize {
                                    if event.created_at() > since {
                                        since = event.created_at();
                                    }
                                    break 'per_event;
                                }
                            }
                        }
                    }
                }
            }
        } else if filter.num_authors() > 0 {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for author in filter.authors() {
                let iter = {
                    let start_prefix = Self::key_ac_index(
                        author,
                        filter.until(), // scan goes backwards in time
                        Id([0; 32]),
                    );
                    let end_prefix = Self::key_ac_index(author, since, Id([255; 32]));
                    let range = (
                        Bound::Included(&*start_prefix),
                        Bound::Excluded(&*end_prefix),
                    );
                    self.ac_index.range(&txn, &range)?
                };

                let mut rangecount = 0;

                'per_event: for result in iter {
                    let (_key, offset) = result?;
                    let event = self.events.get_event_by_offset(offset)?;

                    if event.created_at() < filter.since() {
                        break 'per_event;
                    }

                    // check against the rest of the filter
                    if filter.event_matches(&event)? && screen(&event) {
                        // Accept the event
                        output.insert(event);
                        rangecount += 1;

                        // Stop this limited
                        if rangecount >= filter.limit() as usize {
                            if event.created_at() > since {
                                since = event.created_at();
                            }
                            break 'per_event;
                        }
                    }
                }
            }
        } else {
            // SCRAPE:
            let maxtime = filter.until().0.min(Time::now().0);

            let allow = config.allow_scraping
                || filter.limit() <= config.allow_scrape_if_limited_to
                || (maxtime - filter.since().0) < config.allow_scrape_if_max_seconds;
            if !allow {
                return Err(ChorusError::Scraper.into());
            }

            // This is INEFFICIENT as it scans through many events

            let start_prefix = Self::key_ci_index(
                filter.until(), // scan goes backwards
                Id([0; 32]),
            );
            let end_prefix = Self::key_ci_index(filter.since(), Id([255; 32]));
            let range = (
                Bound::Included(&*start_prefix),
                Bound::Excluded(&*end_prefix),
            );

            let iter = self.ci_index.range(&txn, &range)?;
            for result in iter {
                if output.len() >= filter.limit() as usize {
                    break;
                }
                let (_key, offset) = result?;
                let event = self.events.get_event_by_offset(offset)?;

                if filter.event_matches(&event)? && screen(&event) {
                    output.insert(event);
                }
            }
        }

        // Convert to a Vec, reverse time order, and apply limit
        Ok(output
            .iter()
            .rev()
            .take(filter.limit() as usize)
            .copied()
            .collect())
    }

    /// Delete an event by id.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_events record, which is for events
    /// that are deleted by other events
    fn delete_by_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        if let Some(offset) = self.i_index.get(txn, id.0.as_slice())? {
            self.delete_by_offset(txn, offset)?;
        }

        Ok(())
    }

    /// Delete an event by offset.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_events record, which is for events
    /// that are deleted by other events
    fn delete_by_offset(&self, txn: &mut RwTxn<'_>, offset: usize) -> Result<(), Error> {
        // Get event
        let event = self.events.get_event_by_offset(offset)?;

        // Remove from indexes
        self.deindex(txn, &event)?;

        // Also remove from the id index
        self.i_index.delete(txn, event.id().0.as_slice())?;

        Ok(())
    }

    // This deletes an event without marking it as having been deleted by another event
    pub fn delete_event(&self, id: Id) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.delete_by_id(&mut txn, id)?;
        txn.commit()?;
        Ok(())
    }

    // Index the event
    fn index(&self, txn: &mut RwTxn<'_>, event: &Event, offset: usize) -> Result<(), Error> {
        // Index by id
        self.i_index.put(txn, event.id().0.as_slice(), &offset)?;

        // Index by created_at and id
        self.ci_index.put(
            txn,
            &Self::key_ci_index(event.created_at(), event.id()),
            &offset,
        )?;

        // Index by author and kind (with created_at and id)
        self.akc_index.put(
            txn,
            &Self::key_akc_index(event.pubkey(), event.kind(), event.created_at(), event.id()),
            &offset,
        )?;

        self.ac_index.put(
            txn,
            &Self::key_ac_index(event.pubkey(), event.created_at(), event.id()),
            &offset,
        )?;

        for mut tsi in event.tags()?.iter() {
            if let Some(tagname) = tsi.next() {
                // FIXME make sure it is a letter too
                if tagname.len() == 1 {
                    if let Some(tagvalue) = tsi.next() {
                        // Index by tag (with created_at and id)
                        self.tc_index.put(
                            txn,
                            &Self::key_tc_index(
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                            &offset,
                        )?;

                        // Index by author and tag (with created_at and id)
                        self.atc_index.put(
                            txn,
                            &Self::key_atc_index(
                                event.pubkey(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                            &offset,
                        )?;

                        // Index by kind and tag (with created_at and id)
                        self.ktc_index.put(
                            txn,
                            &Self::key_ktc_index(
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
                        self.atc_index.delete(
                            txn,
                            &Self::key_atc_index(
                                event.pubkey(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;

                        // Index by kind and tag (with created_at and id)
                        self.ktc_index.delete(
                            txn,
                            &Self::key_ktc_index(
                                event.kind(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;

                        // Index by tag (with created_at and id)
                        self.tc_index.delete(
                            txn,
                            &Self::key_tc_index(
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

        self.ac_index.delete(
            txn,
            &Self::key_ac_index(event.pubkey(), event.created_at(), event.id()),
        )?;

        self.ci_index
            .delete(txn, &Self::key_ci_index(event.created_at(), event.id()))?;

        self.akc_index.delete(
            txn,
            &Self::key_akc_index(event.pubkey(), event.kind(), event.created_at(), event.id()),
        )?;

        // We leave it in the id map. If someone wants to load the replaced event by id
        // they can still do it.
        // self.i_index.delete(&mut txn, event.id().0.as_slice())?;

        Ok(())
    }

    // If the event is replaceable or parameterized replaceable
    // this deletes all the events in that group except the most recent one.
    fn delete_replaced(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        if event.kind().is_replaceable() {
            let start_prefix = Self::key_akc_index(
                event.pubkey(),
                event.kind(),
                Time::max(), // database is ordered in reverse time
                Id([0; 32]),
            );
            let end_prefix =
                Self::key_akc_index(event.pubkey(), event.kind(), Time::min(), Id([255; 32]));
            let range = (
                Bound::Included(&*start_prefix),
                Bound::Excluded(&*end_prefix),
            );
            let loop_txn = self.env.read_txn()?;
            let iter = self.akc_index.range(&loop_txn, &range)?;
            let mut first = true;
            for result in iter {
                // Keep the first result
                if first {
                    first = false;
                    continue;
                }

                let (_key, offset) = result?;

                // Delete the event
                self.delete_by_offset(txn, offset)?;
            }
        } else if event.kind().is_parameterized_replaceable() {
            let tags = event.tags()?;
            if let Some(identifier) = tags.get_value(b"d") {
                let start_prefix =
                    Self::key_atc_index(event.pubkey(), b'd', identifier, Time::max(), Id([0; 32]));
                let end_prefix = Self::key_atc_index(
                    event.pubkey(),
                    b'd',
                    identifier,
                    Time::min(),
                    Id([255; 32]),
                );
                let range = (
                    Bound::Included(&*start_prefix),
                    Bound::Excluded(&*end_prefix),
                );
                let loop_txn = self.env.read_txn()?;
                let iter = self.atc_index.range(&loop_txn, &range)?;
                let mut first = true;
                for result in iter {
                    // Keep the first result
                    if first {
                        first = false;
                        continue;
                    }

                    let (_key, offset) = result?;

                    // Delete the event
                    self.delete_by_offset(txn, offset)?;
                }
            }
        }

        Ok(())
    }

    pub fn get_ip_data(&self, ip: HashedIp) -> Result<IpData, Error> {
        let key = &ip.0;
        let txn = self.env.read_txn()?;
        let bytes = match self.ip_data.get(&txn, key)? {
            Some(b) => b,
            None => return Ok(Default::default()),
        };
        Ok(IpData::read_from_buffer(bytes)?)
    }

    pub fn update_ip_data(&self, ip: HashedIp, data: &IpData) -> Result<(), Error> {
        let key = &ip.0;
        let mut txn = self.env.write_txn()?;
        let bytes = data.write_to_vec()?;
        self.ip_data.put(&mut txn, key, &bytes)?;
        txn.commit()?;
        Ok(())
    }

    pub fn mark_event_approval(&self, id: Id, approval: bool) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.approved_events
            .put(&mut txn, id.0.as_slice(), &(approval as u8))?;
        txn.commit()?;
        Ok(())
    }

    pub fn clear_event_approval(&self, id: Id) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.approved_events.delete(&mut txn, id.0.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_event_approval(&self, id: Id) -> Result<Option<bool>, Error> {
        let txn = self.env.read_txn()?;
        Ok(self
            .approved_events
            .get(&txn, id.0.as_slice())?
            .map(|u| u != 0))
    }

    pub fn dump_event_approvals(&self) -> Result<Vec<(Id, bool)>, Error> {
        let mut output: Vec<(Id, bool)> = Vec::new();
        let txn = self.env.read_txn()?;
        for i in self.approved_events.iter(&txn)? {
            let (key, val) = i?;
            let id = Id(key.try_into().unwrap());
            let approval: bool = val != 0;
            output.push((id, approval));
        }
        Ok(output)
    }

    pub fn mark_pubkey_approval(&self, pubkey: Pubkey, approval: bool) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.approved_pubkeys
            .put(&mut txn, pubkey.0.as_slice(), &(approval as u8))?;
        txn.commit()?;
        Ok(())
    }

    pub fn clear_pubkey_approval(&self, pubkey: Pubkey) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.approved_pubkeys
            .delete(&mut txn, pubkey.0.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_pubkey_approval(&self, pubkey: Pubkey) -> Result<Option<bool>, Error> {
        let txn = self.env.read_txn()?;
        Ok(self
            .approved_pubkeys
            .get(&txn, pubkey.0.as_slice())?
            .map(|u| u != 0))
    }

    pub fn dump_pubkey_approvals(&self) -> Result<Vec<(Pubkey, bool)>, Error> {
        let mut output: Vec<(Pubkey, bool)> = Vec::new();
        let txn = self.env.read_txn()?;
        for i in self.approved_pubkeys.iter(&txn)? {
            let (key, val) = i?;
            let pubkey = Pubkey(key.try_into().unwrap());
            let approval: bool = val != 0;
            output.push((pubkey, approval));
        }
        Ok(output)
    }

    fn key_ci_index(created_at: Time, id: Id) -> Vec<u8> {
        let mut key: Vec<u8> =
            Vec::with_capacity(std::mem::size_of::<Time>() + std::mem::size_of::<Id>());
        key.extend((u64::MAX - created_at.0).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Tag
    // tagletter(1) + fixlentag(182) + reversecreatedat(8) + id(32)
    fn key_tc_index(letter: u8, tag_value: &[u8], created_at: Time, id: Id) -> Vec<u8> {
        const PADLEN: usize = 182;
        let mut key: Vec<u8> =
            Vec::with_capacity(PADLEN + std::mem::size_of::<Time>() + std::mem::size_of::<Id>());
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

    // For looking up event by Author
    // author(32) + reversecreatedat(8) + id(32)
    fn key_ac_index(author: Pubkey, created_at: Time, id: Id) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Pubkey>() + std::mem::size_of::<Time>() + std::mem::size_of::<Id>(),
        );
        key.extend(author.as_slice());
        key.extend((u64::MAX - created_at.0).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Author and Kind
    // author(32) + kind(2) + reversecreatedat(8) + id(32)
    fn key_akc_index(author: Pubkey, kind: Kind, created_at: Time, id: Id) -> Vec<u8> {
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
    fn key_atc_index(
        author: Pubkey,
        letter: u8,
        tag_value: &[u8],
        created_at: Time,
        id: Id,
    ) -> Vec<u8> {
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
    fn key_ktc_index(
        kind: Kind,
        letter: u8,
        tag_value: &[u8],
        created_at: Time,
        id: Id,
    ) -> Vec<u8> {
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

    fn key_deleted_events(id: Id, pubkey: Pubkey) -> Vec<u8> {
        let mut key: Vec<u8> =
            Vec::with_capacity(std::mem::size_of::<Id>() + std::mem::size_of::<Pubkey>());
        key.extend(id.as_slice());
        key.extend(pubkey.as_slice());
        key
    }
}
