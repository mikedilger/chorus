use crate::error::{ChorusError, Error};
use crate::types::Event;
use mmap_append::MmapAppend;
use std::fs::{File, OpenOptions};
use std::mem;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

/// This is the size of the initial event map, and also how large it grows by
/// when we need to grow it. This should be a multiple of the page size (4096)
// While debugging, we like to use a small value to increase the frequency of
// resizing, to help detect if there are problems in the algorithm.
#[cfg(debug_assertions)]
const EVENT_MAP_CHUNK: usize = 2048;
#[cfg(not(debug_assertions))]
const EVENT_MAP_CHUNK: usize = 4096 * 1024; // grow by 4 megabytes at a time

/// An EventStore is a fast storage facility for events.
#[derive(Debug)]
pub struct EventStore {
    // the Mmap doesn't need us to keep the file, but we keep it for resizing.
    event_map_file: File,
    event_map_file_len: AtomicUsize,

    // This is a linear sequence of events in an append-only memory mapped file which
    // internally remembers the 'end' pointer and internally prevents multiple writers.
    event_map: MmapAppend,
}

impl EventStore {
    /// Create a new `EventStore`. The `event_map_file` is the eventually large file
    /// that holds all the events.
    pub fn new<P: AsRef<Path>>(event_map_file: P) -> Result<EventStore, Error> {
        // Open the event map file, possibly creating if it isn't there
        let event_map_file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .create(true)
            .open(event_map_file)?;

        // Get it's size
        let metadata = event_map_file.metadata()?;
        let mut len = metadata.len() as usize;

        // Determine if we just created it
        // (not long enough for the required end offset)
        let new = len < mem::size_of::<usize>();

        // If brand new:
        if new {
            // grow to initial size
            len = EVENT_MAP_CHUNK;
            event_map_file.set_len(EVENT_MAP_CHUNK as u64)?;
        }

        // Memory map it
        let event_map = unsafe { MmapAppend::new(&event_map_file, new)? };

        log::info!(
            "Event Store: new={:?} end={} len={}",
            new,
            event_map.get_end(),
            len
        );

        Ok(EventStore {
            event_map_file,
            event_map_file_len: AtomicUsize::new(len),
            event_map,
        })
    }

    /// Get the number of bytes used in the event map
    #[inline]
    pub fn read_event_map_end(&self) -> usize {
        self.event_map.get_end()
    }

    /// Get an event by its offset in the map
    pub fn get_event_by_offset(&self, offset: usize) -> Result<Event, Error> {
        if offset >= self.read_event_map_end() {
            return Err(ChorusError::EndOfInput.into());
        }
        let event = Event::delineate(&self.event_map[offset..])?;
        Ok(event)
    }

    // This stores an event
    // It does NOT validate the event.
    // It does NOT check first if the event is already stored, so it could store a duplicate
    // It does NOT record the event into any indexes
    // But it does grow the file if needed and returns the offset where it was stored
    pub fn store_event(&self, event: &Event) -> Result<usize, Error> {
        let event_size = event.length();

        loop {
            let result = self.event_map.append(event_size, |dst| event.macopy(dst));

            match result {
                Ok(offset) => return Ok(offset),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Other {
                        if e.to_string() == "Out of space" {
                            // Determine the new size
                            let new_file_len = {
                                let file_len = self.event_map_file_len.load(Ordering::Relaxed);
                                file_len + EVENT_MAP_CHUNK
                            };

                            // Grow the file
                            self.event_map_file.set_len(new_file_len as u64)?;

                            // Resize the memory map
                            self.event_map.resize(new_file_len)?;

                            // Save this new length
                            self.event_map_file_len
                                .store(new_file_len, Ordering::Relaxed);

                            // Try again
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::store::EventStore;
    use crate::types::Event;

    #[test]
    fn test_event_store() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("mmap");
        let store = EventStore::new(&path).unwrap();

        println!("Event map has {} used bytes", store.read_event_map_end());

        let e1str = br#"{"id":"000000005ccb8402fe9af2ecc72ca1dbbf2dbeb9a0c6353b7f8198a65106f04a","pubkey":"7bdef7be22dd8e59f4600e044aa53a1cf975a9dc7d27df5833bc77db784a5805","created_at":1677930312,"kind":1,"tags":[["p","fe1d10131ca6103715d261f1615a8cd31f6b68a3d1a3272aab8e9e83f787126e"],["e","f76a6f60df029c388e98d4e97c67424cb71e34455302580d3aa48d0be96dfaef","wss://nos.lol","root"],["e","f529676213b123f55117ae9b93ca7dd6c85c872b7c260da7dbf60d71875879f6","wss://brb.io","reply"],["nonce","12912720851603613541","25"]],"content":"https://www.nostr.guru/p/fe1d10131ca6103715d261f1615a8cd31f6b68a3d1a3272aab8e9e83f787126e\nHere I can see only the today contact list.\n\nI tried to query relay.damus.io and nostr.wine but I can get only this last contact list, perhaps they have a time limit; you could ask some relay owner for a backup.\nIf can be useful this is the REQ filter to use:\n{\"kinds\": [3], \"authors\": [\"fe1d10131ca6103715d261f1615a8cd31f6b68a3d1a3272aab8e9e83f787126e\"], \"since\": 1672569529}","sig":"7c72d15cf9b4244cb8c49564d3735d0ac620dca69253956975def12054bc50217307f062f3e9ea879de8bae756c844a9315f03aabbb5f5fd94f9fc9beb76f457"}"#;
        let mut buffer1: Vec<u8> = Vec::with_capacity(4096);
        buffer1.resize(4096, 0);
        let (_insize, event1) = Event::from_json(&e1str[..], &mut buffer1).unwrap();
        let offset1 = store.store_event(&event1).unwrap();

        let e2str = br#"{"id":"00000000a6fa8ee15b17fcc5bb49f09f85c15cddf5349986db09fddc0a123f7d","pubkey":"7cc328a08ddb2afdf9f9be77beff4c83489ff979721827d628a542f32a247c0e","created_at":1678835260,"kind":1,"tags":[["p","0000000033f569c7069cdec575ca000591a31831ebb68de20ed9fb783e3fc287"],["e","52338357568d06379ad2412a2a2033f23f224754d74148bbfc659b872c9477c4","wss://relay.damus.io/","root"],["nonce","9223372036941030112","32"]],"content":"oh shit, it got released?! no wayyy","sig":"ec9bcdcaa843a2a275857999556136d2b3cc47dac52c899d313dd70291b9661590d4c10b13680bbfa685d67d319798cdfa3ca58f61af5f8acffd0e25bca5ab95"}"#;
        let mut buffer2: Vec<u8> = Vec::with_capacity(4096);
        buffer2.resize(4096, 0);
        let (_insize, event2) = Event::from_json(&e2str[..], &mut buffer2).unwrap();
        let offset2 = store.store_event(&event2).unwrap();

        let e3str = br#"{"id":"00000000ad0efde5b63e9b24b12a586dc98df372e1fd6f96ac6ad24ea2ed1350","pubkey":"c5fb6ecc876e0458e3eca9918e370cbcd376901c58460512fe537a46e58c38bb","created_at":1681739201,"kind":7,"tags":[["e","193bd20beb8fc13f4218ea106928c3be81ee3b2ad2b1bdbdd2c55efd859a195a","wss://eden.nostr.land/"],["p","3f770d65d3a764a9c5cb503ae123e62ec7598ad035d836e2a810f3877a745b24"],["client","gossip"],["nonce","2305843009213833122","22"]],"content":"+","sig":"f344111c221d2fea5f006865b98b0767b40ed1cc2907d8a325a8dea4b98414d008296ff4f4bd4666d52ec86ffd4739e807c6655ce43de98b473326e30957fcb2"}"#;
        let mut buffer3: Vec<u8> = Vec::with_capacity(4096);
        buffer3.resize(4096, 0);
        let (_insize, event3) = Event::from_json(&e3str[..], &mut buffer3).unwrap();
        let offset3 = store.store_event(&event3).unwrap();

        println!("Event map has {} used bytes", store.read_event_map_end());

        if let Ok(event) = store.get_event_by_offset(offset1) {
            assert_eq!(event, event1);
        } else {
            panic!("EVENT 1 IS WRONG");
        }

        if let Ok(event) = store.get_event_by_offset(offset2) {
            assert_eq!(event, event2);
        } else {
            panic!("EVENT 2 IS WRONG");
        }

        if let Ok(event) = store.get_event_by_offset(offset3) {
            assert_eq!(event, event3);
        } else {
            panic!("EVENT 3 IS WRONG");
        }
    }
}
