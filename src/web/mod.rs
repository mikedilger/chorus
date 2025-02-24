mod blossom;
mod management;
mod nip11;

use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::HashedPeer;
use http::Method;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};

pub async fn serve_http(
    peer: HashedPeer,
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    let method = request.method().clone();

    // Handle server-wide OPTIONS requests
    let p = request.uri().path();
    if p == "*" && request.method() == Method::OPTIONS {
        let response = Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization, *")
            .header(
                "Access-Control-Allow-Methods",
                "OPTIONS, GET, HEAD, PUT, DELETE",
            )
            .header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE")
            .status(StatusCode::OK)
            .body(Empty::new().map_err(|e| e.into()).boxed())?;
        return Ok(response);
    }

    // Check if it is a NIP-11 request
    if let Some(accept) = request.headers().get("Accept") {
        if let Ok(s) = accept.to_str() {
            if s == "application/nostr+json" {
                return nip11::serve_nip11(peer).await;
            }
        }
    }

    // Check if it is a NIP-86 Relay Management request
    if let Some(content_type) = request.headers().get("Content-Type") {
        if let Ok(s) = content_type.to_str() {
            if s == "application/nostr+json+rpc" {
                return management::handle(peer, request).await;
            }
        }
    }

    let uri = request.uri().to_owned();

    // Try blossom if enabled
    if GLOBALS.config.read().blossom_directory.is_some() {
        match blossom::handle(request).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                if !matches!(e.inner, ChorusError::SignalNotBlossom) {
                    return Err(e);
                }
            }
        }
    }

    log::debug!(target: "Client", "{}: HTTP request for {}", peer, uri);

    let response = match method {
        Method::OPTIONS => Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization, *")
            .header("Access-Control-Allow-Methods", "*")
            .header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE")
            .status(StatusCode::NO_CONTENT)
            .body(Empty::new().map_err(|e| e.into()).boxed())?,
        Method::HEAD => Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization, *")
            .header("Access-Control-Allow-Methods", "*")
            .status(StatusCode::OK)
            .body(Empty::new().map_err(|e| e.into()).boxed())?,
        Method::GET => Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization, *")
            .header("Access-Control-Allow-Methods", "*")
            .status(StatusCode::OK)
            .body(
                Full::new("This is a nostr relay. Please use a nostr client to connect.".into())
                    .map_err(|e| e.into())
                    .boxed(),
            )?,
        _ => Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization, *")
            .header("Access-Control-Allow-Methods", "*")
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Empty::new().map_err(|e| e.into()).boxed())?,
    };

    Ok(response)
}
