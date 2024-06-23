use crate::error::Error;
use crate::ip::HashedPeer;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};

mod auth;

pub async fn handle(
    _peer: HashedPeer,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Error> {
    let command: Value = match auth::check_auth(request).await {
        Ok(v) => v,
        Err(e) => {
            let result = json!({
                "result": {},
                "error": format!("{}", e)
            });
            return respond(result, StatusCode::UNAUTHORIZED);
        }
    };

    println!("command was {}", command);

    let result = json!({
        "result": {},
        "error": "The Management API is not yet implemented"
    });
    respond(result, StatusCode::NOT_IMPLEMENTED)
}

fn respond(json: serde_json::Value, status: StatusCode) -> Result<Response<Full<Bytes>>, Error> {
    let s: String = serde_json::to_string(&json)?;
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Content-Type", "application/nostr+json")
        .status(status)
        .body(s.into_bytes().into())?;
    Ok(response)
}
