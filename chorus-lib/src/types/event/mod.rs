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
