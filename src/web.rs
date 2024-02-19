use crate::config::Config;
use crate::error::Error;
use crate::globals::GLOBALS;
use hyper::{Body, Request, Response, StatusCode};
use std::net::SocketAddr;

pub async fn serve_http(peer: SocketAddr, request: Request<Body>) -> Result<Response<Body>, Error> {
    log::debug!("{}: HTTP request for {}", peer, request.uri());
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body("This is a nostr relay. Please use a nostr client to connect.".into())?;
    Ok(response)
}

pub async fn serve_nip11(peer: SocketAddr) -> Result<Response<Body>, Error> {
    log::debug!("{}: sent NIP-11", peer);
    let rid = {
        let config = GLOBALS.config.get().unwrap();
        GLOBALS.rid.get_or_init(|| build_rid(config))
    };

    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Content-Type", "application/nostr+json")
        .status(StatusCode::OK)
        .body(rid.clone().into())?;
    Ok(response)
}

fn build_rid(config: &Config) -> String {
    let mut rid: String = String::with_capacity(255);

    const SUPPORTED_NIPS: [u8; 7] = [
        1,  // nostr
        4,  // DMs
        9,  // Event Deletion
        11, // relay information document
        42, // AUTH
        59, // GiftWrap
        65, // Relay List Metadata
    ];
    const _UNSUPPORTED_NIPS: [u8; 7] = [
        26, // Delegated Event Signing
        28, // Public Chat
        40, // Expiration Timestamp
        45, // Counting results
        50, // SEARCH
        94, // File Metadata
        96, // HTTP File Storage Integration
    ];
    const _INAPPLICABLE_NIPS: [u8; 43] = [
        2, 3, 5, 6, 7, 8, 10, 13, 14, 15, 18, 19, 21, 23, 24, 25, 27, 30, 31, 32, 36, 38, 39, 44,
        46, 47, 48, 49, 51, 52, 53, 56, 57, 58, 72, 75, 78, 84, 89, 90, 92, 98, 99,
    ];

    let s = SUPPORTED_NIPS
        .iter()
        .map(|i| format!("{}", i))
        .collect::<Vec<String>>()
        .join(",");
    rid.push_str(&format!("{{\"supported_nips\":[{}],", s));

    let software = env!("CARGO_PKG_NAME");
    rid.push_str("\"software\":\"");
    rid.push_str(software);
    rid.push('\"');

    let version = env!("CARGO_PKG_VERSION");
    rid.push(',');
    rid.push_str("\"version\":\"");
    rid.push_str(version);
    rid.push('\"');

    if let Some(name) = &config.name {
        rid.push(',');
        rid.push_str("\"name\":\"");
        rid.push_str(name);
        rid.push('\"');
    }
    if let Some(description) = &config.description {
        rid.push(',');
        rid.push_str("\"description\":\"");
        rid.push_str(description);
        rid.push('\"');
    }
    if let Some(contact) = &config.contact {
        rid.push(',');
        rid.push_str("\"contact\":\"");
        rid.push_str(contact);
        rid.push('\"');
    }
    if let Some(pubkey) = &config.public_key {
        let mut pkh: [u8; 64] = [0; 64];
        pubkey.write_hex(&mut pkh).unwrap();
        rid.push(',');
        rid.push_str("\"pubkey\":\"");
        rid.push_str(unsafe { std::str::from_utf8_unchecked(pkh.as_slice()) });
        rid.push('\"');
    }
    rid.push('}');

    rid
}
