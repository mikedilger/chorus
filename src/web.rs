use crate::error::Error;
use crate::globals::GLOBALS;
use hyper::{Body, Response, StatusCode};
use nostr_types::RelayInformationDocument;

pub async fn serve_nip11() -> Result<Response<Body>, Error> {
    let rid = {
        let config_ref = GLOBALS.config.read().await;
        let mut rid = RelayInformationDocument::default();
        rid.name = config_ref.name.clone();
        rid.description = config_ref.description.clone();
        rid.pubkey = config_ref.public_key.map(|pk| pk.into()).clone();
        rid.supported_nips = vec![ 11 ];
        rid.software = Some(env!("CARGO_PKG_NAME").to_owned());
        rid.version = Some(env!("CARGO_PKG_VERSION").to_owned());
        rid
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

pub async fn serve_http() -> Result<Response<Body>, Error> {
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body("This is a nostr relay. Please use a nostr client to connect.".into())?;
    Ok(response)
}
