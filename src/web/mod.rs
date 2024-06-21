pub mod nip11;

use crate::error::Error;
use crate::ip::HashedPeer;
use hyper::{Body, Request, Response, StatusCode};

pub async fn serve_http(peer: HashedPeer, request: Request<Body>) -> Result<Response<Body>, Error> {
    log::debug!(target: "Client", "{}: HTTP request for {}", peer, request.uri());
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body("This is a nostr relay. Please use a nostr client to connect.".into())?;
    Ok(response)
}

