mod nip11;

use crate::error::Error;
use crate::ip::HashedPeer;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};

pub async fn serve_http(
    peer: HashedPeer,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Error> {
    // check for Accept header of application/nostr+json
    if let Some(accept) = request.headers().get("Accept") {
        if let Ok(s) = accept.to_str() {
            if s == "application/nostr+json" {
                return nip11::serve_nip11(peer).await;
            }
        }
    }

    log::debug!(target: "Client", "{}: HTTP request for {}", peer, request.uri());
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body("This is a nostr relay. Please use a nostr client to connect.".into())?;
    Ok(response)
}
