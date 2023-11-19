use crate::error::Error;
use crate::globals::GLOBALS;
use hyper::{Body, Request, Response, StatusCode};
use nostr_types::RelayInformationDocument;
use std::net::SocketAddr;

pub async fn serve_nip11(_session_id: u64, peer: SocketAddr) -> Result<Response<Body>, Error> {
    log::debug!("{}: sent NIP-11", peer);
    let rid = {
        let config_ref = GLOBALS.config.read().await;
        RelayInformationDocument {
            name: config_ref.name.clone(),
            description: config_ref.description.clone(),
            pubkey: config_ref.public_key.map(|pk| pk.into()).clone(),
            supported_nips: vec![11],
            software: Some(env!("CARGO_PKG_NAME").to_owned()),
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            ..Default::default()
        }
    };

    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Content-Type", "application/nostr+json")
        .status(StatusCode::OK)
        .body(serde_json::to_string(&rid)?.into())?;
    Ok(response)
}

pub async fn serve_http(_session_id: u64, peer: SocketAddr, request: Request<Body>) -> Result<Response<Body>, Error> {
    log::debug!("{}: HTTP request for {}", peer, request.uri());
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body("This is a nostr relay. Please use a nostr client to connect.".into())?;
    Ok(response)
}
