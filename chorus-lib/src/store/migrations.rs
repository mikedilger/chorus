use super::Store;
use crate::error::Error;
use heed::RwTxn;

pub const CURRENT_MIGRATION_LEVEL: u32 = 2;

impl Store {
    pub fn migrate(&self) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;

        let mut migration_level = {
            let zero_bytes = 0_u32.to_be_bytes();
            let migration_level_bytes = self
                .general
                .get(&txn, b"migration_level")?
                .unwrap_or(zero_bytes.as_slice());
            u32::from_be_bytes(migration_level_bytes[..4].try_into().unwrap())
        };

        log::info!("Storage migration level = {}", migration_level);

        while migration_level < CURRENT_MIGRATION_LEVEL {
            self.migrate_to(&mut txn, migration_level + 1)?;
            migration_level += 1;
            self.general.put(
                &mut txn,
                b"migration_level",
                migration_level.to_be_bytes().as_slice(),
            )?;
        }

        txn.commit()?;

        Ok(())
    }

    fn migrate_to(&self, txn: &mut RwTxn<'_>, level: u32) -> Result<(), Error> {
        log::info!("Migrating database to {}", level);
        match level {
            1 => self.migrate_to_1(txn)?,
            2 => self.migrate_to_2(txn)?,
            _ => panic!("Unknown migration level {level}"),
        }

        Ok(())
    }

    // Populate ci_index
    fn migrate_to_1(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        let loop_txn = self.env.read_txn()?;
        let iter = self.i_index.iter(&loop_txn)?;
        for result in iter {
            let (_key, offset) = result?;
            if let Some(event) = self.events.get_event_by_offset(offset)? {
                // Index in ci
                self.ci_index.put(
                    txn,
                    &Self::key_ci_index(event.created_at(), event.id()),
                    &offset,
                )?;
            }
        }

        Ok(())
    }

    // Populate tc_index and ac_index
    fn migrate_to_2(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        let loop_txn = self.env.read_txn()?;
        let iter = self.i_index.iter(&loop_txn)?;
        for result in iter {
            let (_key, offset) = result?;
            if let Some(event) = self.events.get_event_by_offset(offset)? {
                // Add to ac_index
                self.ac_index.put(
                    txn,
                    &Self::key_ac_index(event.pubkey(), event.created_at(), event.id()),
                    &offset,
                )?;

                // Add to tc_index
                for mut tsi in event.tags()?.iter() {
                    if let Some(tagname) = tsi.next() {
                        if tagname.len() == 1 {
                            if let Some(tagvalue) = tsi.next() {
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
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
