pub mod event_store;
pub use event_store::EventStore;

mod lmdb;
use lmdb::Lmdb;

mod migrations;

use crate::config::Config;
use crate::error::{ChorusError, Error};
use crate::ip::{HashedIp, IpData};
use crate::types::{Event, Filter, Id, Kind, Pubkey, Time};
use heed::RwTxn;
use std::collections::BTreeSet;
use std::fs;

#[derive(Debug)]
pub struct Store {
    lmdb: Lmdb,
    events: EventStore,
}

impl Store {
    /// Setup persistent storage
    pub fn new(config: &Config) -> Result<Store, Error> {
        let dir = format!("{}/lmdb", &config.data_directory);
        let lmdb = Lmdb::new(&dir)?;

        let events_are_aligned = lmdb.get_if_events_are_aligned()?;

        let events = {
            let event_map_file = format!("{}/event.map", &config.data_directory);
            EventStore::new(event_map_file, events_are_aligned)?
        };

        let store = Store { lmdb, events };

        // This is in migrations.rs
        store.migrate()?;

        store.lmdb.log_stats()?;

        Ok(store)
    }

    pub fn rebuild(config: &Config) -> Result<(), Error> {
        let dir = format!("{}/lmdb", &config.data_directory);
        let dir_bak = format!("{}/lmdb.bak", &config.data_directory);
        fs::rename(&dir, &dir_bak)?;
        let old_lmdb = Lmdb::new(&dir_bak)?;
        let new_lmdb = Lmdb::new(&dir)?;

        let old_align = old_lmdb.get_if_events_are_aligned()?;

        let event_map_file = format!("{}/event.map", &config.data_directory);
        let event_map_file_bak = format!("{}/event.map.bak", &config.data_directory);
        fs::rename(&event_map_file, &event_map_file_bak)?;

        let old_event_store = EventStore::new(event_map_file_bak, old_align)?;
        let new_event_store = EventStore::new(event_map_file, true)?;

        let old_store = Store {
            lmdb: old_lmdb,
            events: old_event_store,
        };

        old_store.migrate()?;

        let new_store = Store {
            lmdb: new_lmdb,
            events: new_event_store,
        };

        new_store.migrate()?;

        log::info!("Copying data...");

        let old_txn = old_store.lmdb.read_txn()?;
        let mut new_txn = new_store.lmdb.write_txn()?;

        new_store
            .lmdb
            .set_if_events_are_aligned(&mut new_txn, true)?;

        // Iterate through all IDs and copy and index all of those events
        for i in old_store.lmdb.i_iter(&old_txn)? {
            let (_key, val) = i?;
            //let id = Id(key[0..32].try_into().unwrap());
            let old_offset: usize = val;
            let event = old_store.events.get_event_by_offset(old_offset)?;
            let new_offset = new_store.events.store_event(&event)?;
            new_store.lmdb.index(&mut new_txn, &event, new_offset)?;
        }

        // Copy deleted IDs
        let mut deleted = old_store.lmdb.dump_deleted()?;
        for id in deleted.drain(..) {
            new_store.lmdb.mark_deleted(&mut new_txn, id)?;
        }

        new_txn.commit()?;

        // Copy approved events
        let mut approvals = old_store.dump_event_approvals()?;
        for (id, approval) in approvals.drain(..) {
            new_store.mark_event_approval(id, approval)?;
        }

        // Copy approved pubkeys
        let mut approvals = old_store.dump_pubkey_approvals()?;
        for (pubkey, approval) in approvals.drain(..) {
            new_store.mark_pubkey_approval(pubkey, approval)?;
        }

        // Copy ip data
        let mut ipdata = old_store.lmdb.dump_ip_data()?;
        for (hashedip, ipdata) in ipdata.drain(..) {
            new_store.update_ip_data(hashedip, &ipdata)?;
        }

        new_store.lmdb.sync()?;

        log::info!("done.");

        Ok(())
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub fn sync(&self) -> Result<(), Error> {
        self.lmdb.sync()?;
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

        let mut txn = self.lmdb.write_txn()?;
        let offset;

        // Only if it doesn't already exist
        if self.lmdb.get_offset_by_id(&txn, event.id())?.is_none() {
            // Reject event if it was deleted
            {
                if self.lmdb.is_deleted(&txn, event.id())? {
                    return Err(ChorusError::Deleted.into());
                }
            }

            // Store the event
            offset = self.events.store_event(event)?;

            // Index the event
            if !event.kind().is_ephemeral() {
                self.lmdb.index(&mut txn, event, offset)?;
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
                            self.lmdb.mark_deleted(txn, id)?;

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
        let txn = self.lmdb.read_txn()?;
        if let Some(offset) = self.lmdb.get_offset_by_id(&txn, id)? {
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
        let txn = self.lmdb.read_txn()?;

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
                    let iter = self
                        .lmdb
                        .akc_iter(author, kind, since, filter.until(), &txn)?;

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
                            let iter = self.lmdb.atc_iter(
                                author,
                                tag0[0],
                                tagvalue,
                                since,
                                filter.until(),
                                &txn,
                            )?;

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
                            let iter = self.lmdb.ktc_iter(
                                kind,
                                tag0[0],
                                tagvalue,
                                since,
                                filter.until(),
                                &txn,
                            )?;

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
                        let iter =
                            self.lmdb
                                .tc_iter(tag0[0], tagvalue, since, filter.until(), &txn)?;

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
                let iter = self.lmdb.ac_iter(author, since, filter.until(), &txn)?;

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

            let iter = self.lmdb.ci_iter(filter.since(), filter.until(), &txn)?;
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
    /// This does not add to the deleted_ids record, which is for events
    /// that are deleted by other events
    fn delete_by_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        if let Some(offset) = self.lmdb.get_offset_by_id(txn, id)? {
            self.delete_by_offset(txn, offset)?;
        }

        Ok(())
    }

    /// Delete an event by offset.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_ids record, which is for events
    /// that are deleted by other events
    fn delete_by_offset(&self, txn: &mut RwTxn<'_>, offset: usize) -> Result<(), Error> {
        // Get event
        let event = self.events.get_event_by_offset(offset)?;

        // Remove from indexes
        self.lmdb.deindex(txn, &event)?;

        // Also remove from the id index
        self.lmdb.deindex_id(txn, event.id())?;

        Ok(())
    }

    // This deletes an event without marking it as having been deleted by another event
    pub fn delete_event(&self, id: Id) -> Result<(), Error> {
        let mut txn = self.lmdb.write_txn()?;
        self.delete_by_id(&mut txn, id)?;
        txn.commit()?;
        Ok(())
    }

    // If the event is replaceable or parameterized replaceable
    // this deletes all the events in that group except the most recent one.
    fn delete_replaced(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        if event.kind().is_replaceable() {
            let loop_txn = self.lmdb.read_txn()?;
            let iter = self.lmdb.akc_iter(
                event.pubkey(),
                event.kind(),
                Time::min(),
                Time::max(),
                &loop_txn,
            )?;
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
                let loop_txn = self.lmdb.read_txn()?;
                let iter = self.lmdb.atc_iter(
                    event.pubkey(),
                    b'd',
                    identifier,
                    Time::min(),
                    Time::max(),
                    &loop_txn,
                )?;
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
        self.lmdb.get_ip_data(ip)
    }

    pub fn update_ip_data(&self, ip: HashedIp, data: &IpData) -> Result<(), Error> {
        self.lmdb.update_ip_data(ip, data)
    }

    pub fn mark_event_approval(&self, id: Id, approval: bool) -> Result<(), Error> {
        self.lmdb.mark_event_approval(id, approval)
    }

    pub fn clear_event_approval(&self, id: Id) -> Result<(), Error> {
        self.lmdb.clear_event_approval(id)
    }

    pub fn get_event_approval(&self, id: Id) -> Result<Option<bool>, Error> {
        self.lmdb.get_event_approval(id)
    }

    pub fn dump_event_approvals(&self) -> Result<Vec<(Id, bool)>, Error> {
        self.lmdb.dump_event_approvals()
    }

    pub fn mark_pubkey_approval(&self, pubkey: Pubkey, approval: bool) -> Result<(), Error> {
        self.lmdb.mark_pubkey_approval(pubkey, approval)
    }

    pub fn clear_pubkey_approval(&self, pubkey: Pubkey) -> Result<(), Error> {
        self.lmdb.clear_pubkey_approval(pubkey)
    }

    pub fn get_pubkey_approval(&self, pubkey: Pubkey) -> Result<Option<bool>, Error> {
        self.lmdb.get_pubkey_approval(pubkey)
    }

    pub fn dump_pubkey_approvals(&self) -> Result<Vec<(Pubkey, bool)>, Error> {
        self.lmdb.dump_pubkey_approvals()
    }
}
