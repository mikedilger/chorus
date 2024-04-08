use super::Lmdb;
use crate::error::Error;
use crate::types::Event;
use heed::byteorder::BigEndian;
use heed::types::{UnalignedSlice, Unit, U64};
use heed::{Database, RwTxn};

impl Lmdb {
    pub fn deleted_offsets(
        &self,
        txn: &mut RwTxn,
    ) -> Result<Database<U64<BigEndian>, Unit>, Error> {
        Ok(self
            .env
            .database_options()
            .types::<U64<BigEndian>, Unit>()
            .name("deleted_offsets")
            .create(txn)?)
    }

    pub fn deleted_events(
        &self,
        txn: &mut RwTxn,
    ) -> Result<Database<UnalignedSlice<u8>, Unit>, Error> {
        Ok(self
            .env
            .database_options()
            .types::<UnalignedSlice<u8>, Unit>()
            .name("deleted-events")
            .create(txn)?)
    }

    // used in migrate_to_1
    pub fn index_ci_only(
        &self,
        txn: &mut RwTxn<'_>,
        event: &Event,
        offset: usize,
    ) -> Result<(), Error> {
        self.ci_index.put(
            txn,
            &Self::key_ci_index(event.created_at(), event.id()),
            &offset,
        )?;

        Ok(())
    }

    // used in migrate_to_2
    pub fn index_ac_only(
        &self,
        txn: &mut RwTxn<'_>,
        event: &Event,
        offset: usize,
    ) -> Result<(), Error> {
        self.ac_index.put(
            txn,
            &Self::key_ac_index(event.pubkey(), event.created_at(), event.id()),
            &offset,
        )?;

        Ok(())
    }

    // used in migrate_to_2
    pub fn index_tc_only(
        &self,
        txn: &mut RwTxn<'_>,
        tagbyte: u8,
        tagvalue: &[u8],
        event: &Event,
        offset: usize,
    ) -> Result<(), Error> {
        self.tc_index.put(
            txn,
            &Self::key_tc_index(tagbyte, tagvalue, event.created_at(), event.id()),
            &offset,
        )?;

        Ok(())
    }

    // used in migrate_to_3
    pub fn clear_ip_data(&self, txn: &mut RwTxn<'_>) -> Result<(), Error> {
        self.ip_data.clear(txn)?;
        Ok(())
    }
}
