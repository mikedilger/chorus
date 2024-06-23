use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use base64::prelude::*;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::Request;
use pocket_types::Event;
use secp256k1::hashes::{sha256, Hash};
use serde_json::Value;

fn s_err(s: &str) -> Result<Value, Error> {
    Err(ChorusError::ManagementAuthFailure(s.to_owned()).into())
}

pub async fn check_auth(request: Request<Incoming>) -> Result<Value, Error> {
    // Must be POST
    if request.method() != hyper::Method::POST {
        return s_err("Management RPC only supports POST method");
    }

    // Must have AUTHORIZATION header
    let authz = match request.headers().get("Authorization") {
        Some(h) => h,
        None => return s_err("Authorization header not of type nostr"),
    };

    // Authorization header must be type "nostr"
    let value = String::from_utf8(authz.as_bytes().to_owned())?;
    let mut parts = value.split(|b| b == ' ');
    match parts.next() {
        Some(s) => {
            if s.to_lowercase() != "nostr" {
                return s_err("Authorization header not of type nostr");
            }
        }
        None => return s_err("Authorization header missing"),
    }

    // Authorization header second part
    let base64event = match parts.next() {
        Some(s) => s,
        None => return s_err("Authorization header incomplete"),
    };

    // Authorization header must be base64
    let event_bytes = BASE64_STANDARD.decode(base64event)?;

    // Authorization header base64 must decode to a nostr Event
    let mut buffer = Vec::with_capacity(base64event.len());
    buffer.resize(base64event.len(), 0);
    let (_size, event) = Event::from_json(&event_bytes, &mut buffer)?;

    // Nostr event must be valid
    if let Err(e) = event.verify() {
        return s_err(&format!("Authorization event is invalid: {}", e));
    }

    // Event kind must be 27235
    if event.kind().as_u16() != 27235 {
        return s_err("Authorization event not kind 27235");
    }

    // Event created_at must be within 60 seconds of now
    use pocket_types::Time;
    let now = Time::now().as_u64();
    if event.created_at().as_u64() > now + 60 {
        return s_err("Authorization event too far in the future");
    }
    if event.created_at().as_u64() < now - 60 {
        return s_err("Authorization event too far in the past");
    }

    let tags = event.tags()?;

    // Tag 'method' must be POST
    if let Some(method) = tags.get_value(b"method") {
        if method != b"POST" && method != b"post" {
            return s_err(
                "Authorization event did not authorize POST (and only POST is supported here)",
            );
        }
    } else {
        return s_err("Authorization event method missing");
    }

    // Tag 'u' must be the current URL
    if let Some(u) = tags.get_value(b"u") {
        let auth_url = String::from_utf8(u.to_owned())?;
        let actual_url = {
            let uri = GLOBALS.config.read().url(request.uri().to_owned(), true)?;
            format!("{}", uri)
        };

        if actual_url != auth_url {
            return s_err(&format!(
                "Authorization event URL {} does not match requqest URL {}",
                auth_url, actual_url
            ));
        }
    } else {
        return s_err("Authorization event URL missing");
    }

    let body = request.collect().await?.to_bytes();
    let hash = sha256::Hash::hash(&body);
    let hashref = <sha256::Hash as AsRef<[u8]>>::as_ref(&hash);
    let hashrefhex = hex::encode(hashref);

    if let Some(payload) = tags.get_value(b"payload") {
        if hashrefhex.as_bytes() != payload {
            return s_err("Authorization failed: body hash mismatch");
        }
    } else {
        return s_err("Authorization event payload missing");
    }

    Ok(serde_json::from_slice(&body)?)
}
