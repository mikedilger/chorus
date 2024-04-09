use super::{Id, Kind, Pubkey, Sig, Tags, Time};
use crate::error::{ChorusError, Error};
use crate::types::parse::json_escape::json_escape;
use std::cmp::Ordering;
use std::fmt;

mod json_event;
use json_event::parse_json_event;

/*
 * 0 [4 bytes] length of the event structure
 * 4 [2 bytes] kind
 * 6 [2 bytes] PADDING
 * 8 [8 bytes] created_at
 * 16 [32 bytes] id
 * 48 [32 bytes] pubkey
 * 80 [64 bytes] sig
 * 144 [T bytes] Tags
 * 144+T [4 bytes] content length
 * 144+T+4 [C bytes] content
 * 144+T+4+C <--- beginning of region beyond the event
 */

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Event<'a>(&'a [u8]);

impl<'a> Event<'a> {
    // Parse json into an Event. Returns the count of consumed input bytes and the Event
    pub fn from_json(
        json: &[u8],
        output_buffer: &'a mut [u8],
    ) -> Result<(usize, Event<'a>), Error> {
        let (incount, outcount) = parse_json_event(json, output_buffer)?;
        Ok((incount, Event(&output_buffer[..outcount])))
    }

    // this marks off the slice of bytes that represent an event from a potentially longer input
    pub fn delineate(input: &'a [u8]) -> Result<Event<'a>, Error> {
        if input.len() < 144 + 4 + 4 {
            return Err(ChorusError::EndOfInput.into());
        }
        let len = parse_u32!(input, 0) as usize;
        if input.len() < len {
            return Err(ChorusError::EndOfInput.into());
        }
        Ok(Event(&input[0..len]))
    }

    // This copies
    pub fn copy(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() < self.0.len() {
            return Err(ChorusError::BufferTooSmall.into());
        }
        output[..self.0.len()].copy_from_slice(self.0);
        Ok(())
    }

    // This copies, using the event_store mmap-append api
    pub fn macopy(&self, output: &mut [u8]) -> Result<usize, std::io::Error> {
        if output.len() < self.0.len() {
            return Err(std::io::Error::other(ChorusError::BufferTooSmall));
        }
        output[..self.0.len()].copy_from_slice(self.0);
        Ok(self.0.len())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }

    pub fn length(&self) -> usize {
        self.0.len()
    }

    pub fn kind(&self) -> Kind {
        Kind(parse_u16!(self.0, 4))
    }

    pub fn created_at(&self) -> Time {
        Time(parse_u64!(self.0, 8))
    }

    pub fn id(&self) -> Id {
        Id(self.0[16..16 + 32].try_into().unwrap())
    }

    pub fn pubkey(&self) -> Pubkey {
        Pubkey(self.0[48..48 + 32].try_into().unwrap())
    }

    pub fn sig(&self) -> Sig {
        Sig(self.0[80..80 + 64].try_into().unwrap())
    }

    pub fn tags(&'a self) -> Result<Tags<'a>, Error> {
        Tags::delineate(&self.0[144..])
    }

    pub fn content(&'a self) -> &'a [u8] {
        let t = parse_u16!(self.0, 144) as usize;
        let c = parse_u32!(self.0, 144 + t) as usize;
        &self.0[144 + t + 4..144 + t + 4 + c]
    }

    pub fn as_json(&self) -> Result<Vec<u8>, Error> {
        let mut output: Vec<u8> = Vec::with_capacity(256);
        output.extend(br#"{"id":""#);
        let pos = output.len();
        output.resize(pos + 64, 0);
        self.id().write_hex(&mut output[pos..]).unwrap();
        output.extend(br#"","pubkey":""#);
        let pos = output.len();
        output.resize(pos + 64, 0);
        self.pubkey().write_hex(&mut output[pos..]).unwrap();
        output.extend(br#"","kind":"#);
        output.extend(format!("{}", self.kind().0).as_bytes());
        output.extend(br#","created_at":"#);
        output.extend(format!("{}", self.created_at().0).as_bytes());
        output.extend(br#","tags":"#);
        output.extend(self.tags()?.as_json());
        output.extend(br#","content":""#);
        // This is okay if it is not accurate. It generally avoids
        // lots of little mallocs when the capacity is already allocated
        output.reserve(self.content().len() * 7 / 6);
        let mut output = json_escape(self.content(), output)?;
        output.extend(br#"","sig":""#);
        let pos = output.len();
        output.resize(pos + 128, 0);
        self.sig().write_hex(&mut output[pos..]).unwrap();
        output.extend(br#""}"#);
        Ok(output)
    }

    pub fn verify(&self) -> Result<(), Error> {
        use secp256k1::hashes::{sha256, Hash};
        use secp256k1::schnorr::Signature;
        use secp256k1::{Message, XOnlyPublicKey};

        // This is okay if it is not accurate. It generally avoids
        // lots of little mallocs when the capacity is already allocated
        let escaped_content = Vec::with_capacity(self.content().len() * 7 / 6);
        let escaped_content = json_escape(self.content(), escaped_content)?;

        let signable = format!(
            r#"[0,"{}",{},{},{},"{}"]"#,
            self.pubkey(),
            self.created_at(),
            self.kind(),
            self.tags()?,
            unsafe { std::str::from_utf8_unchecked(&escaped_content[..]) },
        );

        drop(escaped_content);

        let hash = sha256::Hash::hash(signable.as_bytes());

        let hashref = <sha256::Hash as AsRef<[u8]>>::as_ref(&hash);
        if hashref != self.id().as_slice() {
            return Err(ChorusError::BadEventId.into());
        }

        let pubkey = XOnlyPublicKey::from_slice(self.pubkey().as_slice())?;
        let sig = Signature::from_slice(self.sig().as_slice())?;
        let message = Message::from_digest_slice(hashref)?;
        sig.verify(&message, &pubkey)?;

        Ok(())
    }

    pub fn is_expired(&self) -> Result<bool, Error> {
        for mut tag in self.tags()?.iter() {
            if tag.next() == Some(b"expiration") {
                if let Some(expires) = tag.next() {
                    // Interpret string as a u64
                    let mut p = 0;
                    let time = super::parse::json_parse::read_u64(expires, &mut p)?;
                    if time <= Time::now().0 {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(bytes) = self.as_json() {
            let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
            write!(f, "{s}")
        } else {
            write!(f, "{{Corrupted Event}}")
        }
    }
}

impl Eq for Event<'_> {}

impl PartialOrd for Event<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Event<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.created_at().cmp(&other.created_at())
    }
}

#[derive(Debug, Clone)]
pub struct OwnedEvent(pub Vec<u8>);

impl OwnedEvent {
    pub fn as_event(&self) -> Result<Event<'_>, Error> {
        Event::delineate(&self.0)
    }
}

#[cfg(test)]
mod test {
    use super::Event;

    #[test]
    fn test_event_expired() {
        let json = br#"{"id":"8b8b1d98f279b43f571ce55dce7cc51ced0c24e9558bfdaa0be0467f82f64708","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1712693549,"kind":1,"sig":"870497b1a254f2394a692decd46b5cffa044302179a42e985697b488fc408118c9ff7c5578d85393474c1a025f28c869148968ee3229aa24425800ae54f54e51","content":"He got snowed in","tags":[["expiration","1712693529"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();
        assert_eq!(event.is_expired().unwrap(), true); // In the past

        let json = br#"{"id":"120b3d99f889c6147972b0256413e84b0b7b7862a705964b7302f5392677e52a","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1712693868,"kind":1,"sig":"ed0463b822f76f63c392b00d4a66c297f5e13371c800b139f2d40174bf77146201f29ae6e3a9da71a9346416d8b2ba4d2f5a2be693a9e75a91a33abfdc43ec71","content":"He got snowed in","tags":[["expiration","99712693529"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let (_size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();
        assert_eq!(event.is_expired().unwrap(), false); // Too far in the future

        let json = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let (_size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();
        assert_eq!(event.is_expired().unwrap(), false); // Doesn't have the expiration tag
    }
}
