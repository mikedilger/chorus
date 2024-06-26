use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::HashedPeer;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use pocket_types::Pubkey;
use serde_json::{json, Map, Value};
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

    let obj = match command.as_object() {
        Some(o) => o,
        None => return fail("Command was not a JSON object"),
    };

    let method = match obj.get("method") {
        Some(m) => match m.as_str() {
            Some(s) => s.to_owned(),
            None => return fail("Method not a string"),
        },
        None => return fail("Method missing"),
    };

    match &*method {
        "supportedmethods" => {
            return respond(
                json!({
                    "result": ["allowpubkey", "banpubkey", "supportedmethods"]
                }),
                StatusCode::OK,
            )
        }

        // Pubkeys
        "banpubkey" => match get_pubkey_param(obj) {
            Ok(pk) => {
                crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, false)?;
                return worked();
            }
            Err(e) => return fail(&format!("{e}")),
        },
        "allowpubkey" => match get_pubkey_param(obj) {
            Ok(pk) => {
                crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, true)?;
                return worked();
            }
            Err(e) => return fail(&format!("{e}")),
        },
        "listbannedpubkeys" => return fail(&format!("Unsupported method {}", method)),
        "listallowedpubkeys" => return fail(&format!("Unsupported method {}", method)),

        // Events
        "banevent" => return fail(&format!("Unsupported method {}", method)),
        "listbannedevents" => return fail(&format!("Unsupported method {}", method)),
        "allowevent" => return fail(&format!("Unsupported method {}", method)),
        "listallowedevents" => return fail(&format!("Unsupported method {}", method)),
        "listeventsneedingmoderation" => return fail(&format!("Unsupported method {}", method)),

        // Kinds
        "allowkind" => return fail(&format!("Unsupported method {}", method)),
        "disallowkind" => return fail(&format!("Unsupported method {}", method)),
        "listbannedkinds" => return fail(&format!("Unsupported method {}", method)),
        "listallowedkinds" => return fail(&format!("Unsupported method {}", method)),

        // IP addresses
        "blockip" => return fail(&format!("Unsupported method {}", method)),
        "unblockip" => return fail(&format!("Unsupported method {}", method)),
        "listblockedips" => return fail(&format!("Unsupported method {}", method)),

        // Config
        "changerelayname" => return fail(&format!("Unsupported method {}", method)),
        "changerelaydescription" => return fail(&format!("Unsupported method {}", method)),
        "changerelayicon" => return fail(&format!("Unsupported method {}", method)),

        _ => return fail(&format!("Unsupported method {}", method)),
    }

    /*
    let result = json!({
        "result": {},
        "error": "The Management API is not yet implemented"
    });
    respond(result, StatusCode::NOT_IMPLEMENTED)
    */
}

fn fail(msg: &str) -> Result<Response<Full<Bytes>>, Error> {
    let result = json!({
        "result": {},
        "error": msg
    });
    respond(result, StatusCode::BAD_REQUEST)
}

fn worked() -> Result<Response<Full<Bytes>>, Error> {
    let result = json!({
        "result": {},
    });
    respond(result, StatusCode::OK)
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

fn get_pubkey_param(obj: &Map<String, Value>) -> Result<Pubkey, Error> {
    let pubkey_text = obj
        .get("params")
        .ok_or::<Error>(ChorusError::BadRequest("Params field missing".to_owned()).into())?
        .as_array()
        .ok_or::<Error>(ChorusError::BadRequest("Params not an array".to_owned()).into())?
        .get(0)
        .ok_or::<Error>(ChorusError::BadRequest("Missing pubkey parameter".to_owned()).into())?
        .as_str()
        .ok_or::<Error>(
            ChorusError::BadRequest("Pubkey parameter is wrong type".to_owned()).into(),
        )?;
    Ok(Pubkey::read_hex(pubkey_text.as_bytes())?)
}
