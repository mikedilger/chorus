use crate::error::Error;
use crate::ip::{HashedIp, IpData};
use crate::types::{Event, Id, Kind, Pubkey, Time};
use heed::types::{OwnedType, UnalignedSlice, Unit, U8};
use heed::{Database, Env, EnvFlags, EnvOpenOptions, RoIter, RoRange, RoTxn, RwTxn};
use speedy::{Readable, Writable};
use std::fs;
use std::ops::Bound;

mod retired;

const FALSE: &[u8] = &[0];
const TRUE: &[u8] = &[1];

#[derive(Debug)]
pub struct Lmdb {
    env: Env,
    general: Database<UnalignedSlice<u8>, UnalignedSlice<u8>>,
    i_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ci_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    tc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ac_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    akc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    atc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,
    ktc_index: Database<UnalignedSlice<u8>, OwnedType<usize>>,

    // this is for events deleted by other events
    deleted_ids: Database<UnalignedSlice<u8>, Unit>,
    approved_events: Database<UnalignedSlice<u8>, U8>,
    approved_pubkeys: Database<UnalignedSlice<u8>, U8>,
    ip_data: Database<UnalignedSlice<u8>, UnalignedSlice<u8>>,
}

impl Lmdb {
    pub fn new(directory: &str) -> Result<Lmdb, Error> {
        let mut builder = EnvOpenOptions::new();
        unsafe {
            builder.flags(EnvFlags::NO_TLS);
        }
        builder.max_dbs(32);
        builder.map_size(1048576 * 1024 * 24); // 24 GB

        fs::create_dir_all(directory)?;

        let env = match builder.open(directory) {
            Ok(env) => env,
            Err(e) => {
                log::error!("Unable to open LMDB at {}", directory);
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
        let deleted_ids = env
            .database_options()
            .types::<UnalignedSlice<u8>, Unit>()
            .name("deleted-ids")
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
        txn.commit()?;

        let lmdb = Lmdb {
            env,
            general,
            i_index,
            ci_index,
            tc_index,
            ac_index,
            akc_index,
            atc_index,
            ktc_index,
            deleted_ids,
            approved_events,
            approved_pubkeys,
            ip_data,
        };

        Ok(lmdb)
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub fn sync(&self) -> Result<(), Error> {
        self.env.force_sync()?;
        Ok(())
    }

    /// Get a read transaction
    pub fn read_txn(&self) -> Result<RoTxn, Error> {
        Ok(self.env.read_txn()?)
    }

    /// Get a write transaction
    pub fn write_txn(&self) -> Result<RwTxn, Error> {
        Ok(self.env.write_txn()?)
    }

    pub fn log_stats(&self) -> Result<(), Error> {
        let txn = self.read_txn()?;
        if let Ok(count) = self.i_index.len(&txn) {
            log::info!("Index: id ({} entries, {} bytes)", count, count * (32 + 8));
        }
        if let Ok(count) = self.ci_index.len(&txn) {
            log::info!(
                "Index: created_at+id ({} entries, {} bytes)",
                count,
                count * (40 + 8)
            );
        }

        if let Ok(count) = self.tc_index.len(&txn) {
            log::info!(
                "Index: tag+created_at+id ({} entries, {} bytes)",
                count,
                count * (223 + 8)
            );
        }
        if let Ok(count) = self.ac_index.len(&txn) {
            log::info!(
                "Index: author+created_at+id ({} entries, {} bytes)",
                count,
                count * (72 + 8)
            );
        }
        if let Ok(count) = self.akc_index.len(&txn) {
            log::info!(
                "Index: author+kind+created_at+id ({} entries, {} bytes)",
                count,
                count * (74 + 8)
            );
        }
        if let Ok(count) = self.atc_index.len(&txn) {
            log::info!(
                "Index: author+tags+created_at+id ({} entries, {} bytes)",
                count,
                count * (255 + 8)
            );
        }
        if let Ok(count) = self.ktc_index.len(&txn) {
            log::info!(
                "Index: kind+tags+created_at+id ({} entries, {} bytes)",
                count,
                count * (225 + 8)
            );
        }

        if let Ok(count) = self.deleted_ids.len(&txn) {
            log::info!("{} deleted events", count);
        }
        if let Ok(count) = self.ip_data.len(&txn) {
            log::info!("{count} IP addresses reputationally tracked");
        }

        Ok(())
    }

    pub fn get_migration_level(&self, txn: &RoTxn<'_>) -> Result<u32, Error> {
        let zero_bytes = 0_u32.to_be_bytes();
        let migration_level_bytes = self
            .general
            .get(txn, b"migration_level")?
            .unwrap_or(zero_bytes.as_slice());
        Ok(u32::from_be_bytes(
            migration_level_bytes[..4].try_into().unwrap(),
        ))
    }

    pub fn set_migration_level(&self, txn: &mut RwTxn<'_>, level: u32) -> Result<(), Error> {
        self.general
            .put(txn, b"migration_level", level.to_be_bytes().as_slice())?;

        Ok(())
    }

    pub fn get_if_events_are_aligned(&self) -> Result<bool, Error> {
        let txn = self.read_txn()?;
        match self.general.get(&txn, b"events_are_aligned")? {
            None => Ok(false),
            Some(bytes) => match bytes[0] {
                0 => Ok(false),
                _ => Ok(true),
            },
        }
    }

    pub fn set_if_events_are_aligned(
        &self,
        txn: &mut RwTxn<'_>,
        events_are_aligned: bool,
    ) -> Result<(), Error> {
        let slice = match events_are_aligned {
            false => FALSE,
            true => TRUE,
        };
        self.general.put(txn, b"events_are_aligned", slice)?;
        Ok(())
    }

    // Index the event
    pub fn index(&self, txn: &mut RwTxn<'_>, event: &Event, offset: usize) -> Result<(), Error> {
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
    pub fn deindex(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
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

    pub fn deindex_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        self.i_index.delete(txn, id.0.as_slice())?;
        Ok(())
    }

    pub fn get_offset_by_id(&self, txn: &RoTxn<'_>, id: Id) -> Result<Option<usize>, Error> {
        Ok(self.i_index.get(txn, id.0.as_slice())?)
    }

    pub fn is_deleted(&self, txn: &RoTxn<'_>, id: Id) -> Result<bool, Error> {
        Ok(self.deleted_ids.get(txn, id.as_slice())?.is_some())
    }

    pub fn mark_deleted(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        self.deleted_ids.put(txn, id.as_slice(), &())?;
        Ok(())
    }

    pub fn get_ip_data(&self, ip: HashedIp) -> Result<IpData, Error> {
        let key = &ip.0;
        let txn = self.read_txn()?;
        let bytes = match self.ip_data.get(&txn, key)? {
            Some(b) => b,
            None => return Ok(Default::default()),
        };
        Ok(IpData::read_from_buffer(bytes)?)
    }

    pub fn update_ip_data(&self, ip: HashedIp, data: &IpData) -> Result<(), Error> {
        let key = &ip.0;
        let mut txn = self.write_txn()?;
        let bytes = data.write_to_vec()?;
        self.ip_data.put(&mut txn, key, &bytes)?;
        txn.commit()?;
        Ok(())
    }

    pub fn mark_event_approval(&self, id: Id, approval: bool) -> Result<(), Error> {
        let mut txn = self.write_txn()?;
        self.approved_events
            .put(&mut txn, id.0.as_slice(), &(approval as u8))?;
        txn.commit()?;
        Ok(())
    }

    pub fn clear_event_approval(&self, id: Id) -> Result<(), Error> {
        let mut txn = self.write_txn()?;
        self.approved_events.delete(&mut txn, id.0.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_event_approval(&self, id: Id) -> Result<Option<bool>, Error> {
        let txn = self.read_txn()?;
        Ok(self
            .approved_events
            .get(&txn, id.0.as_slice())?
            .map(|u| u != 0))
    }

    pub fn dump_event_approvals(&self) -> Result<Vec<(Id, bool)>, Error> {
        let mut output: Vec<(Id, bool)> = Vec::new();
        let txn = self.read_txn()?;
        for i in self.approved_events.iter(&txn)? {
            let (key, val) = i?;
            let id = Id(key.try_into().unwrap());
            let approval: bool = val != 0;
            output.push((id, approval));
        }
        Ok(output)
    }

    pub fn mark_pubkey_approval(&self, pubkey: Pubkey, approval: bool) -> Result<(), Error> {
        let mut txn = self.write_txn()?;
        self.approved_pubkeys
            .put(&mut txn, pubkey.0.as_slice(), &(approval as u8))?;
        txn.commit()?;
        Ok(())
    }

    pub fn clear_pubkey_approval(&self, pubkey: Pubkey) -> Result<(), Error> {
        let mut txn = self.write_txn()?;
        self.approved_pubkeys
            .delete(&mut txn, pubkey.0.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_pubkey_approval(&self, pubkey: Pubkey) -> Result<Option<bool>, Error> {
        let txn = self.read_txn()?;
        Ok(self
            .approved_pubkeys
            .get(&txn, pubkey.0.as_slice())?
            .map(|u| u != 0))
    }

    pub fn dump_pubkey_approvals(&self) -> Result<Vec<(Pubkey, bool)>, Error> {
        let mut output: Vec<(Pubkey, bool)> = Vec::new();
        let txn = self.read_txn()?;
        for i in self.approved_pubkeys.iter(&txn)? {
            let (key, val) = i?;
            let pubkey = Pubkey(key.try_into().unwrap());
            let approval: bool = val != 0;
            output.push((pubkey, approval));
        }
        Ok(output)
    }

    pub fn i_iter<'a>(
        &'a self,
        txn: &'a RoTxn,
    ) -> Result<RoIter<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        Ok(self.i_index.iter(txn)?)
    }

    pub fn ci_iter<'a>(
        &'a self,
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        let start_prefix = Self::key_ci_index(until, Id([0; 32]));
        let end_prefix = Self::key_ci_index(since, Id([255; 32]));
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.ci_index.range(txn, &range)?)
    }

    pub fn tc_iter<'a>(
        &'a self,
        tagbyte: u8,
        tagvalue: &[u8],
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        let start_prefix = Self::key_tc_index(
            tagbyte,
            tagvalue,
            until, // scan goes backwards in time
            Id([0; 32]),
        );
        let end_prefix = Self::key_tc_index(tagbyte, tagvalue, since, Id([255; 32]));
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.tc_index.range(txn, &range)?)
    }

    pub fn ac_iter<'a>(
        &'a self,
        author: Pubkey,
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        let start_prefix = Self::key_ac_index(author, until, Id([0; 32]));
        let end_prefix = Self::key_ac_index(author, since, Id([255; 32]));
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.ac_index.range(txn, &range)?)
    }

    pub fn akc_iter<'a>(
        &'a self,
        author: Pubkey,
        kind: Kind,
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        let start_prefix = Self::key_akc_index(author, kind, until, Id([0; 32]));
        let end_prefix = Self::key_akc_index(author, kind, since, Id([255; 32]));
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.akc_index.range(txn, &range)?)
    }

    pub fn atc_iter<'a>(
        &'a self,
        author: Pubkey,
        tagbyte: u8,
        tagvalue: &[u8],
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        let start_prefix = Self::key_atc_index(
            author,
            tagbyte,
            tagvalue,
            until, // scan goes backwards in time
            Id([0; 32]),
        );
        let end_prefix = Self::key_atc_index(author, tagbyte, tagvalue, since, Id([255; 32]));
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.atc_index.range(txn, &range)?)
    }

    pub fn ktc_iter<'a>(
        &'a self,
        kind: Kind,
        tagbyte: u8,
        tagvalue: &[u8],
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, UnalignedSlice<u8>, OwnedType<usize>>, Error> {
        let start_prefix = Self::key_ktc_index(
            kind,
            tagbyte,
            tagvalue,
            until, // scan goes backwards in time
            Id([0; 32]),
        );
        let end_prefix = Self::key_ktc_index(kind, tagbyte, tagvalue, since, Id([255; 32]));
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.ktc_index.range(txn, &range)?)
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
}
