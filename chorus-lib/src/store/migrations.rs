use super::Store;
use crate::error::Error;
use crate::types::Id;
use heed::RwTxn;

pub const CURRENT_MIGRATION_LEVEL: u32 = 5;

impl Store {
    pub fn migrate(&self) -> Result<(), Error> {
        let mut txn = self.lmdb.write_txn()?;

        let mut migration_level = self.lmdb.get_migration_level(&txn)?;

        log::info!("Storage migration level = {}", migration_level);

        while migration_level < CURRENT_MIGRATION_LEVEL {
            self.migrate_to(&mut txn, migration_level + 1)?;
            migration_level += 1;

            self.lmdb.set_migration_level(&mut txn, migration_level)?
        }

        txn.commit()?;

        Ok(())
    }

    fn migrate_to(&self, txn: &mut RwTxn<'_>, level: u32) -> Result<(), Error> {
        log::info!("Migrating database to {}", level);
        match level {
            1 => self.migrate_to_1(txn)?,
            2 => self.migrate_to_2(txn)?,
            3 => self.migrate_to_3(txn)?,
            4 => self.migrate_to_4(txn)?,
            5 => self.migrate_to_5(txn)?,
            _ => panic!("Unknown migration level {level}"),
        }

        Ok(())
    }

    // Populate ci_index
    fn migrate_to_1(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        let loop_txn = self.lmdb.read_txn()?;
        let iter = self.lmdb.i_iter(&loop_txn)?;
        for result in iter {
            let (_key, offset) = result?;
            let event = self.events.get_event_by_offset(offset)?;
            self.lmdb.index_ci_only(txn, &event, offset)?;
        }

        Ok(())
    }

    // Populate tc_index and ac_index
    fn migrate_to_2(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        let loop_txn = self.lmdb.read_txn()?;
        let iter = self.lmdb.i_iter(&loop_txn)?;
        for result in iter {
            let (_key, offset) = result?;
            let event = self.events.get_event_by_offset(offset)?;

            // Add to ac_index
            self.lmdb.index_ac_only(txn, &event, offset)?;

            // Add to tc_index
            for mut tsi in event.tags()?.iter() {
                if let Some(tagname) = tsi.next() {
                    if tagname.len() == 1 {
                        if let Some(tagvalue) = tsi.next() {
                            self.lmdb
                                .index_tc_only(txn, tagname[0], tagvalue, &event, offset)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // Clear IP data (we are hashing now)
    fn migrate_to_3(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        self.lmdb.clear_ip_data(txn)?;
        Ok(())
    }

    // Clear deleted_offsets (now retired)
    fn migrate_to_4(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        let deleted_offsets = self.lmdb.deleted_offsets(txn)?;
        deleted_offsets.clear(txn)?;
        Ok(())
    }

    // Move data from deleted_events to deleted_ids
    fn migrate_to_5(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        let deleted_events = self.lmdb.deleted_events(txn)?;

        let mut ids: Vec<Id> = Vec::new();

        for i in deleted_events.iter(txn)? {
            let (key, _val) = i?;
            let id = Id(key[0..32].try_into().unwrap());
            ids.push(id);
        }

        for id in ids.drain(..) {
            self.lmdb.mark_deleted(txn, id)?;
        }

        deleted_events.clear(txn)?;

        Ok(())
    }
}
