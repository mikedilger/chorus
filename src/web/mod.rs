mod management;
mod nip11;

use crate::error::Error;
use crate::ip::HashedPeer;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};

pub async fn serve_http(
    peer: HashedPeer,
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    // check for Accept header of application/nostr+json
    if let Some(accept) = request.headers().get("Accept") {
        if let Ok(s) = accept.to_str() {
            if s == "application/nostr+json" {
                return nip11::serve_nip11(peer).await;
            }
            if s == "application/nostr+json+rpc" {
                return management::handle(peer, request).await;
            }
        }
    }

    log::debug!(target: "Client", "{}: HTTP request for {}", peer, request.uri());
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body(
            Full::new("This is a nostr relay. Please use a nostr client to connect.".into())
                .map_err(|e| e.into())
                .boxed(),
        )?;
    Ok(response)
}
