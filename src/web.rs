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
        let config = GLOBALS.config.read().await;
        GLOBALS.rid.get_or_init(|| build_rid(&config))
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
    rid.push_str("{\"supported_nips\":[1,11],");

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
