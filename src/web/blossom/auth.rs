use crate::error::{ChorusError, Error};
use base64::prelude::*;
use http::header::AUTHORIZATION;
use hyper::body::Incoming;
use hyper::Request;
use pocket_types::Event;

fn s_err(s: &str) -> Result<AuthData, Error> {
    Err(ChorusError::BlossomAuthFailure(s.to_owned()).into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthVerb {
    Upload,
    List,
    Delete,
    Mirror,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthData {
    /// If a verb was included, this is it
    pub verb: Option<AuthVerb>,

    /// If an 'x' tag was included, this is the hash
    pub hash: Option<[u8; 32]>,
}

pub fn verify_auth(request: &Request<Incoming>) -> Result<AuthData, Error> {
    // Force every other error into a BlossomAuthFailure error
    match verify_auth_inner(request) {
        Ok(ad) => Ok(ad),
        Err(e) => match e.inner {
            ChorusError::BlossomAuthFailure(_) => Err(e),
            _ => Err(ChorusError::BlossomAuthFailure(format!("{e}")).into()),
        },
    }
}

fn verify_auth_inner(request: &Request<Incoming>) -> Result<AuthData, Error> {
    // Must have AUTHORIZATION header
    let authz = match request.headers().get(AUTHORIZATION) {
        Some(h) => h,
        None => return s_err("Authorization Required"),
    };

    // Authorization header must be type "nostr"
    if !authz.to_str()?.to_ascii_lowercase().starts_with("nostr ") {
        return s_err("You must use the Nostr authorization scheme");
    }

    let base64 = match authz.to_str()?.get(6..) {
        Some(x) => x,
        None => return s_err("Missing auth base64 encoded event"),
    };

    // Authorization header must be base64
    let event_bytes = BASE64_STANDARD.decode(base64)?;

    // Authorization header base64 must decode to a nostr Event
    let mut buffer = vec![0; base64.len()];
    let (_size, event) = Event::from_json(&event_bytes, &mut buffer)?;

    // Nostr event must be valid
    if let Err(e) = event.verify() {
        return s_err(&format!("Authorization event is invalid: {}", e));
    }

    // Nostr event must be signed by a chorus user
    if !crate::is_authorized_user(event.pubkey()) {
        return s_err("You are not an authorized user");
    }

    // Event kind must be 24242
    if event.kind().as_u16() != 24242 {
        return s_err("Authorization event not kind 24242");
    }

    // Event created_at must be in the past (we give 30 seconds leeway)
    use pocket_types::Time;
    let now = Time::now();
    if event.created_at() > now + 30 {
        return s_err("Authorization event too far in the future");
    }

    let tags = event.tags()?;

    // Expiration tag must be in the future
    if let Some(v) = tags.get_value(b"expiration") {
        let u = parse_u64(v)?;
        let expiration = Time::from_u64(u);
        if expiration < now {
            return s_err("Authorization event has expired");
        }
    } else {
        return s_err("Authorization event missing expiration tag");
    }

    // We let the caller check the verb and hash since those are specific
    // to the endpoint (and the 'x' must be checked later on)

    let verb: Option<AuthVerb> = if let Some(t) = tags.get_value(b"t") {
        if t == b"upload" {
            Some(AuthVerb::Upload)
        } else if t == b"list" {
            Some(AuthVerb::List)
        } else if t == b"delete" {
            Some(AuthVerb::Delete)
        } else {
            None
        }
    } else {
        None
    };

    let hash: Option<[u8; 32]> = if let Some(v) = tags.get_value(b"x") {
        let vec = hex::decode(v)?;
        if vec.len() == 32 {
            Some(vec.try_into().unwrap())
        } else {
            return s_err("Authorization event x tag is of the wrong length");
        }
    } else {
        None
    };

    Ok(AuthData { verb, hash })
}

// FIXME, expose these from pocket-types
fn parse_u64(input: &[u8]) -> Result<u64, Error> {
    let mut pos = 0;
    let mut value: u64 = 0;
    let mut any: bool = false;
    while pos < input.len() && b"0123456789".contains(&input[pos]) {
        any = true;
        value = (value * 10) + (input[pos] - 48) as u64;
        pos += 1;
    }
    if !any {
        Err(ChorusError::General("Auth event expiration is not a number".to_string()).into())
    } else {
        Ok(value)
    }
}
