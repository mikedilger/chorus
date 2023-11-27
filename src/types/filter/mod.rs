use super::{Event, Id, Kind, Pubkey, Tags, Time};
use crate::Error;
use std::fmt;

/*
 *  0 [2 bytes] length of entire structure
 *  2 [2 bytes] num_ids
 *  4 [2 bytes] num_authors
 *  6 [2 bytes] num_kinds
 *  8 [4 bytes] limit				u32.   Set to u32::max if limit was not set.
 *  12 [4 bytes] PADDING
 *  16 [8 bytes] since				u64.   Set to 0 if since was not set.
 *  24 [8 bytes] until				u64.   Set to u64::max if until was not set.
 *  32 [ID] array
 *  [Pubkey] array                  starts at 32 + num_ids*32
 *  [Kind] array                    starts at 32 + num_ids*32 + num_authors*32
 *  [Tags] object                   starts at 32 + num_ids*32 + num_authors*32 * num_kinds*2
 */

const NUM_IDS_OFFSET: usize = 2;
const NUM_AUTHORS_OFFSET: usize = 4;
const NUM_KINDS_OFFSET: usize = 6;
const LIMIT_OFFSET: usize = 8;
const SINCE_OFFSET: usize = 16;
const UNTIL_OFFSET: usize = 24;
const ARRAYS_OFFSET: usize = 32;
const ID_SIZE: usize = 32;
const PUBKEY_SIZE: usize = 32;
const KIND_SIZE: usize = 2;

#[derive(Debug, Clone)]
pub struct Filter<'a>(&'a [u8]);

impl<'a> Filter<'a> {
    pub fn delineate(input: &'a [u8]) -> Result<Filter<'a>, Error> {
        if input.len() < ARRAYS_OFFSET {
            return Err(Error::EndOfInput);
        }
        let len = parse_u16!(input, 0) as usize;
        if input.len() < len {
            return Err(Error::EndOfInput);
        }
        Ok(Filter(&input[0..len]))
    }

    pub fn copy(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() < self.0.len() {
            return Err(Error::EndOfInput);
        }
        output[..self.0.len()].copy_from_slice(self.0);
        Ok(())
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn num_ids(&self) -> usize {
        parse_u16!(self.0, NUM_IDS_OFFSET) as usize
    }

    #[inline]
    pub fn ids(&'a self) -> FilterIdIter<'a> {
        FilterIdIter {
            filter: self,
            next: 0,
        }
    }

    #[inline]
    pub fn num_authors(&self) -> usize {
        parse_u16!(self.0, NUM_AUTHORS_OFFSET) as usize
    }

    #[inline]
    fn start_of_authors(&self) -> usize {
        ARRAYS_OFFSET + self.num_ids() * ID_SIZE
    }

    #[inline]
    pub fn authors(&'a self) -> FilterAuthorIter<'a> {
        FilterAuthorIter {
            filter: self,
            start_of_authors: self.start_of_authors(),
            next: 0,
        }
    }

    #[inline]
    pub fn num_kinds(&self) -> usize {
        parse_u16!(self.0, NUM_KINDS_OFFSET) as usize
    }

    #[inline]
    fn start_of_kinds(&self) -> usize {
        ARRAYS_OFFSET + self.num_ids() * ID_SIZE + self.num_authors() * PUBKEY_SIZE
    }

    #[inline]
    pub fn kinds(&'a self) -> FilterKindIter<'a> {
        FilterKindIter {
            filter: self,
            start_of_kinds: self.start_of_kinds(),
            next: 0,
        }
    }

    #[inline]
    fn start_of_tags(&self) -> usize {
        ARRAYS_OFFSET
            + self.num_ids() * ID_SIZE
            + self.num_authors() * PUBKEY_SIZE
            + self.num_kinds() * KIND_SIZE
    }

    #[inline]
    pub fn tags(&'a self) -> Result<Tags<'a>, Error> {
        Tags::delineate(&self.0[self.start_of_tags()..])
    }

    #[inline]
    pub fn limit(&self) -> u32 {
        parse_u32!(self.0, LIMIT_OFFSET)
    }

    #[inline]
    pub fn since(&self) -> Time {
        Time(parse_u64!(self.0, SINCE_OFFSET))
    }

    #[inline]
    pub fn until(&self) -> Time {
        Time(parse_u64!(self.0, UNTIL_OFFSET))
    }

    pub fn event_matches(&self, event: &Event) -> Result<bool, Error> {
        // ids
        if self.num_ids() != 0 && !self.ids().any(|id| id == event.id()) {
            return Ok(false);
        }

        // authors
        if self.num_authors() != 0 && !self.authors().any(|pk| pk == event.pubkey()) {
            return Ok(false);
        }

        // kinds
        if self.num_kinds() != 0 && !self.kinds().any(|kind| kind == event.kind()) {
            return Ok(false);
        }

        // since
        if event.created_at() < self.since() {
            return Ok(false);
        }

        // until
        if event.created_at() > self.until() {
            return Ok(false);
        }

        // tags
        let filter_tags = self.tags()?;
        if !filter_tags.is_empty() {
            let event_tags = event.tags()?;
            if event_tags.is_empty() {
                return Ok(false);
            }

            let mut i = 0;
            while let Some(letter) = filter_tags.get_string(i, 0) {
                let mut j = 1;
                let mut found = false;
                while let Some(value) = filter_tags.get_string(i, j) {
                    if event_tags.matches(letter, value) {
                        found = true;
                        break;
                    }
                    j += 1;
                }
                if !found {
                    return Ok(false);
                }
                i += 1;
            }
        }

        Ok(true)
    }

    pub fn as_json(&self) -> Result<Vec<u8>, Error> {
        let mut output: Vec<u8> = Vec::with_capacity(256);
        output.push(b'{');
        let mut first = true;

        if self.num_ids() > 0 {
            output.extend(br#""ids":["#);
            for (i, id) in self.ids().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                output.push(b'"');
                let pos = output.len();
                output.resize(pos + 64, 0);
                id.write_hex(&mut output[pos..])?;
                output.push(b'"');
            }
            output.push(b']');
            first = false;
        }

        if self.num_authors() > 0 {
            if !first {
                output.push(b',');
            }
            output.extend(br#""authors":["#);
            for (i, pk) in self.authors().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                output.push(b'"');
                let pos = output.len();
                output.resize(pos + 64, 0);
                pk.write_hex(&mut output[pos..])?;
                output.push(b'"');
            }
            output.push(b']');
            first = false;
        }

        if self.num_kinds() > 0 {
            if !first {
                output.push(b',');
            }
            output.extend(br#""kinds":["#);
            for (i, k) in self.kinds().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                output.extend(format!("{}", k.0).as_bytes());
            }
            output.push(b']');
            first = false;
        }

        let tags = self.tags()?;
        if !tags.is_empty() {
            // Filter 'tags' are not an array of arrays, they are just a convenient
            // way to store similar data. They also elide the '#'. So we have to
            // iterate here, we cannot use tags.as_json()
            for tag in tags.iter() {
                if !first {
                    output.push(b',');
                }
                for (i, bytes) in tag.enumerate() {
                    if i == 0 {
                        output.extend(b"\"#");
                        output.extend(bytes);
                        output.extend(b"\":[");
                    } else {
                        if i > 1 {
                            output.push(b',');
                        }
                        output.push(b'"');
                        output.extend(bytes);
                        output.push(b'"');
                    }
                }
                output.push(b']');
                first = false;
            }
        }

        if self.limit() != u32::MAX {
            if !first {
                output.push(b',');
            }
            output.extend(format!(r#""limit":{}"#, self.limit()).as_bytes());
            first = false;
        }

        if self.since() != Time::min() {
            if !first {
                output.push(b',');
            }
            output.extend(format!(r#""since":{}"#, self.since().0).as_bytes());
            first = false;
        }

        if self.until() != Time::max() {
            if !first {
                output.push(b',');
            }
            output.extend(format!(r#""until":{}"#, self.until().0).as_bytes());
        }

        output.push(b'}');

        Ok(output)
    }
}

impl fmt::Display for Filter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(bytes) = self.as_json() {
            let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
            write!(f, "{s}")
        } else {
            write!(f, "{{Corrupted Event}}")
        }
    }
}

#[derive(Debug)]
pub struct FilterIdIter<'a> {
    filter: &'a Filter<'a>,
    next: usize,
}

impl<'a> Iterator for FilterIdIter<'a> {
    type Item = Id;

    fn next(&mut self) -> Option<Self::Item> {
        let num_ids = parse_u16!(self.filter.0, NUM_IDS_OFFSET) as usize;
        if self.next >= num_ids {
            None
        } else {
            let offset = ARRAYS_OFFSET + self.next * ID_SIZE;
            self.next += 1;
            if self.filter.0.len() < offset + ID_SIZE {
                None
            } else {
                Some(Id(self.filter.0[offset..offset + ID_SIZE]
                    .try_into()
                    .unwrap()))
            }
        }
    }
}

#[derive(Debug)]
pub struct FilterAuthorIter<'a> {
    filter: &'a Filter<'a>,
    start_of_authors: usize,
    next: usize,
}

impl<'a> Iterator for FilterAuthorIter<'a> {
    type Item = Pubkey;

    fn next(&mut self) -> Option<Self::Item> {
        let num_authors = parse_u16!(self.filter.0, NUM_AUTHORS_OFFSET) as usize;
        if self.next >= num_authors {
            None
        } else {
            let offset = self.start_of_authors + self.next * PUBKEY_SIZE;
            self.next += 1;
            if self.filter.0.len() < offset + PUBKEY_SIZE {
                None
            } else {
                Some(Pubkey(
                    self.filter.0[offset..offset + PUBKEY_SIZE]
                        .try_into()
                        .unwrap(),
                ))
            }
        }
    }
}

#[derive(Debug)]
pub struct FilterKindIter<'a> {
    filter: &'a Filter<'a>,
    start_of_kinds: usize,
    next: usize,
}

impl<'a> Iterator for FilterKindIter<'a> {
    type Item = Kind;

    fn next(&mut self) -> Option<Self::Item> {
        let num_kinds = parse_u16!(self.filter.0, NUM_KINDS_OFFSET) as usize;
        if self.next >= num_kinds {
            None
        } else {
            let offset = self.start_of_kinds + self.next * KIND_SIZE;
            self.next += 1;
            if self.filter.0.len() < offset + KIND_SIZE {
                None
            } else {
                Some(Kind(parse_u16!(self.filter.0, offset)))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_filter() {
        /*
         * {
         *   "ids": [ "6b43bc2e373b6d9330ff571f3f4e6d897b32d01d65227df3fa41cdf731c63c3a",
         *            "1f47034c9d6d0539382a86ba31766f00f2b8312ab167c036729422ec9e7085e8"],
         *   "authors": [ "52b4a076bcbbbdc3a1aefa3735816cf74993b1b8db202b01c883c58be7fad8bd",
         *                "ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49" ],
         *   "kinds": [ 1, 5, 30023 ],
         *   "since": 1702161345,
         *   "#p": [ "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52" ],
         * }
         */

        // For comparison
        let id1 = Id::read_hex(b"6b43bc2e373b6d9330ff571f3f4e6d897b32d01d65227df3fa41cdf731c63c3a")
            .unwrap();

        let id2 = Id::read_hex(b"1f47034c9d6d0539382a86ba31766f00f2b8312ab167c036729422ec9e7085e8")
            .unwrap();
        let pk1 =
            Pubkey::read_hex(b"52b4a076bcbbbdc3a1aefa3735816cf74993b1b8db202b01c883c58be7fad8bd")
                .unwrap();
        let pk2 =
            Pubkey::read_hex(b"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49")
                .unwrap();
        let tagged =
            Pubkey::read_hex(b"fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52")
                .unwrap();

        let data: Vec<u8> = vec![
            211, 0, // length of structure
            2, 0, // number of IDs
            2, 0, // number of authors
            3, 0, // number of kinds
            255, 255, 255, 255, // limit
            0, 0, 0, 0, // padding
            0xC1, 0xEB, 0x74, 0x65, 0, 0, 0, 0, // since
            255, 255, 255, 255, 255, 255, 255, 255, // until
            0x6b, 0x43, 0xbc, 0x2e, 0x37, 0x3b, 0x6d, 0x93, 0x30, 0xff, 0x57, 0x1f, 0x3f, 0x4e,
            0x6d, 0x89, 0x7b, 0x32, 0xd0, 0x1d, 0x65, 0x22, 0x7d, 0xf3, 0xfa, 0x41, 0xcd, 0xf7,
            0x31, 0xc6, 0x3c, 0x3a, // ID 1
            0x1f, 0x47, 0x03, 0x4c, 0x9d, 0x6d, 0x05, 0x39, 0x38, 0x2a, 0x86, 0xba, 0x31, 0x76,
            0x6f, 0x00, 0xf2, 0xb8, 0x31, 0x2a, 0xb1, 0x67, 0xc0, 0x36, 0x72, 0x94, 0x22, 0xec,
            0x9e, 0x70, 0x85, 0xe8, // ID 2
            0x52, 0xb4, 0xa0, 0x76, 0xbc, 0xbb, 0xbd, 0xc3, 0xa1, 0xae, 0xfa, 0x37, 0x35, 0x81,
            0x6c, 0xf7, 0x49, 0x93, 0xb1, 0xb8, 0xdb, 0x20, 0x2b, 0x01, 0xc8, 0x83, 0xc5, 0x8b,
            0xe7, 0xfa, 0xd8, 0xbd, // Pubkey 1
            0xee, 0x11, 0xa5, 0xdf, 0xf4, 0x0c, 0x19, 0xa5, 0x55, 0xf4, 0x1f, 0xe4, 0x2b, 0x48,
            0xf0, 0x0e, 0x61, 0x8c, 0x91, 0x22, 0x56, 0x22, 0xae, 0x37, 0xb6, 0xc2, 0xbb, 0x67,
            0xb7, 0x6c, 0x4e, 0x49, // Pubkey 2
            1, 0, 5, 0, 71, 117, // 3 kinds
            // Tags
            45, 0, // tags_len
            1, 0, // num_tags
            6, 0, // first tag offset at 6
            2, 0, // 2 fields long
            1, 0,   // 1st field is 1 byte
            112, // "p"
            32, 0, // 2nd field is 32 bytes
            // 2nd field
            0xfa, 0x98, 0x4b, 0xd7, 0xdb, 0xb2, 0x82, 0xf0, 0x7e, 0x16, 0xe7, 0xae, 0x87, 0xb2,
            0x6a, 0x2a, 0x7b, 0x9b, 0x90, 0xb7, 0x24, 0x6a, 0x44, 0x77, 0x1f, 0x0c, 0xf5, 0xae,
            0x58, 0x01, 0x8f, 0x52,
        ];

        let filter = Filter::delineate(&data).unwrap();

        assert_eq!(filter.num_ids(), 2);
        let mut ids = filter.ids();
        assert_eq!(ids.next().unwrap(), id1);
        assert_eq!(ids.next().unwrap(), id2);
        assert!(ids.next().is_none());

        assert_eq!(filter.num_authors(), 2);
        let mut authors = filter.authors();
        assert_eq!(authors.next().unwrap(), pk1);
        assert_eq!(authors.next().unwrap(), pk2);
        assert!(authors.next().is_none());

        assert_eq!(filter.num_kinds(), 3);
        let mut kinds = filter.kinds();
        assert_eq!(kinds.next().unwrap(), Kind(1));
        assert_eq!(kinds.next().unwrap(), Kind(5));
        assert_eq!(kinds.next().unwrap(), Kind(30023));
        assert!(kinds.next().is_none());

        assert_eq!(filter.limit(), u32::MAX);
        assert_eq!(filter.since(), Time(1702161345));
        assert_eq!(filter.until(), Time::max());

        let tags = filter.tags().unwrap();
        assert_eq!(tags.len(), 1);
        let mut iter = tags.iter();
        let mut tag = iter.next().unwrap();
        assert!(iter.next().is_none());
        assert_eq!(tag.next().unwrap(), b"p");
        let p_bytes = tag.next().unwrap();
        assert!(tag.next().is_none());
        let pk = Pubkey(p_bytes.try_into().unwrap());
        assert_eq!(pk, tagged);
    }
}
