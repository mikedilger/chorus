use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::HashedPeer;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use pocket_types::Pubkey;
use serde_json::{json, Map, Value};
mod auth;

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

    match handle_inner(command) {
        Ok(Some(value)) => respond(value, StatusCode::OK),
        Ok(None) => {
            let result = json!({
                "result": {},
            });
            respond(result, StatusCode::OK)
        }
        Err(e) => {
            let (result, status) = match e.inner {
                ChorusError::BadRequest(s) => (
                    json!({
                        "result": {},
                        "error": format!("{}", s)
                    }),
                    StatusCode::BAD_REQUEST,
                ),
                ChorusError::NotImplemented => (
                    json!({
                        "result": {},
                        "error": "not_implemented"
                    }),
                    StatusCode::NOT_IMPLEMENTED,
                ),
                _ => (
                    json!({
                        "result": {},
                        "error": format!("{}", e)
                    }),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ),
            };
            return respond(result, status);
        }
    }
}

pub fn handle_inner(command: Value) -> Result<Option<Value>, Error> {
    let obj = match command.as_object() {
        Some(o) => o,
        None => return Err(ChorusError::BadRequest("Command was not a JSON object").into()),
    };

    let method = match obj.get("method") {
        Some(m) => match m.as_str() {
            Some(s) => s.to_owned(),
            None => return Err(ChorusError::BadRequest("Method not a string").into()),
        },
        None => return Err(ChorusError::BadRequest("Method missing").into()),
    };

    match &*method {
        "supportedmethods" => {
            return Ok(Some(json!({
                "result": ["allowpubkey", "banpubkey", "listallowedpubkeys", "listbannedpubkeys", "supportedmethods"]
            })));
        }

        // Pubkeys
        "banpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, false)?;
            return Ok(None);
        }
        "allowpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, true)?;
            return Ok(None);
        }
        "listbannedpubkeys" => {
            let approvals = crate::dump_pubkey_approvals(GLOBALS.store.get().unwrap())?;
            let pubkeys: Vec<String> = approvals
                .iter()
                .filter_map(|(pk, appr)| {
                    if *appr {
                        None
                    } else {
                        Some(pk.as_hex_string().unwrap())
                    }
                })
                .collect();
            return Ok(Some(json!({
                "result": pubkeys
            })));
        }
        "listallowedpubkeys" => {
            let approvals = crate::dump_pubkey_approvals(GLOBALS.store.get().unwrap())?;
            let pubkeys: Vec<String> = approvals
                .iter()
                .filter_map(|(pk, appr)| {
                    if *appr {
                        Some(pk.as_hex_string().unwrap())
                    } else {
                        None
                    }
                })
                .collect();
            return Ok(Some(json!({
                "result": pubkeys
            })));
        }
        // Events
        "banevent" => return Err(ChorusError::NotImplemented.into()),
        "listbannedevents" => return Err(ChorusError::NotImplemented.into()),
        "allowevent" => return Err(ChorusError::NotImplemented.into()),
        "listallowedevents" => return Err(ChorusError::NotImplemented.into()),
        "listeventsneedingmoderation" => return Err(ChorusError::NotImplemented.into()),

        // Kinds
        "allowkind" => return Err(ChorusError::NotImplemented.into()),
        "disallowkind" => return Err(ChorusError::NotImplemented.into()),
        "listbannedkinds" => return Err(ChorusError::NotImplemented.into()),
        "listallowedkinds" => return Err(ChorusError::NotImplemented.into()),

        // IP addresses
        "blockip" => return Err(ChorusError::NotImplemented.into()),
        "unblockip" => return Err(ChorusError::NotImplemented.into()),
        "listblockedips" => return Err(ChorusError::NotImplemented.into()),

        // Config
        "changerelayname" => return Err(ChorusError::NotImplemented.into()),
        "changerelaydescription" => return Err(ChorusError::NotImplemented.into()),
        "changerelayicon" => return Err(ChorusError::NotImplemented.into()),

        _ => return Err(ChorusError::NotImplemented.into()),
    }
}

fn get_pubkey_param(obj: &Map<String, Value>) -> Result<Pubkey, Error> {
    let pubkey_text = obj
        .get("params")
        .ok_or(ChorusError::BadRequest("Params field missing").into_err())?
        .as_array()
        .ok_or(ChorusError::BadRequest("Params not an array").into_err())?
        .get(0)
        .ok_or(ChorusError::BadRequest("Missing pubkey parameter").into_err())?
        .as_str()
        .ok_or(ChorusError::BadRequest("Pubkey parameter is wrong type").into_err())?;
    Ok(Pubkey::read_hex(pubkey_text.as_bytes())
        .map_err(|_| ChorusError::BadRequest("Pubkey could not be parsed").into_err())?)
}
