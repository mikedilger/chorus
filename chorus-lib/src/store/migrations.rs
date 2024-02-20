use super::Store;
use crate::error::Error;
use heed::RwTxn;

pub const CURRENT_MIGRATION_LEVEL: u32 = 1;

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
            _ => panic!("Unknown migration level {level}"),
        }

        Ok(())
    }

    fn migrate_to_1(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        // Build ci database
        let loop_txn = self.env.read_txn()?;
        let iter = self.ids.iter(&loop_txn)?;
        for result in iter {
            let (_key, offset) = result?;
            if let Some(event) = self.events.get_event_by_offset(offset)? {
                // Index in ci
                self.ci
                    .put(txn, &Self::key_ci(event.created_at(), event.id()), &offset)?;
            }
        }

        Ok(())
    }
}
