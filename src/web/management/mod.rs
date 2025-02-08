use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::HashedPeer;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use pocket_types::{Id, Pubkey};
use serde_json::{json, Map, Value};
mod auth;

fn respond(
    json: serde_json::Value,
    status: StatusCode,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    let s: String = serde_json::to_string(&json)?;
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Content-Type", "application/nostr+json+rpc")
        .status(status)
        .body(
            Full::new(s.into_bytes().into())
                .map_err(|e| e.into())
                .boxed(),
        )?;
    Ok(response)
}

pub async fn handle(
    _peer: HashedPeer,
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
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
            respond(result, status)
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
        "supportedmethods" => Ok(Some(json!({
            "result": [
                "grantadmin",
                "revokeadmin",
                "allowevent",
                "allowpubkey",
                "banevent",
                "banpubkey",
                "listallowedevents",
                "listallowedpubkeys",
                "listbannedevents",
                "listbannedpubkeys",
                "supportedmethods",
                "stats"
            ]
        }))),

        // Pubkeys
        "banpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, false)?;
            Ok(None)
        }
        "allowpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, true)?;
            Ok(None)
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
            Ok(Some(json!({
                "result": pubkeys
            })))
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
            Ok(Some(json!({
                "result": pubkeys
            })))
        }
        // Events
        "banevent" => {
            let id = get_id_param(obj)?;
            crate::mark_event_approval(GLOBALS.store.get().unwrap(), id, false)?;
            Ok(None)
        }
        "allowevent" => {
            let id = get_id_param(obj)?;
            crate::mark_event_approval(GLOBALS.store.get().unwrap(), id, true)?;
            Ok(None)
        }
        "listbannedevents" => {
            let approvals = crate::dump_event_approvals(GLOBALS.store.get().unwrap())?;
            let ids: Vec<String> = approvals
                .iter()
                .filter_map(|(id, appr)| {
                    if *appr {
                        None
                    } else {
                        Some(id.as_hex_string().unwrap())
                    }
                })
                .collect();
            Ok(Some(json!({
                "result": ids
            })))
        }
        "listallowedevents" => {
            let approvals = crate::dump_event_approvals(GLOBALS.store.get().unwrap())?;
            let ids: Vec<String> = approvals
                .iter()
                .filter_map(|(id, appr)| {
                    if *appr {
                        Some(id.as_hex_string().unwrap())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(Some(json!({
                "result": ids
            })))
        }

        "listeventsneedingmoderation" => Err(ChorusError::NotImplemented.into()),

        // Kinds
        "allowkind" => Err(ChorusError::NotImplemented.into()),
        "disallowkind" => Err(ChorusError::NotImplemented.into()),
        "listbannedkinds" => Err(ChorusError::NotImplemented.into()),
        "listallowedkinds" => Err(ChorusError::NotImplemented.into()),

        // IP addresses
        "blockip" => Err(ChorusError::NotImplemented.into()),
        "unblockip" => Err(ChorusError::NotImplemented.into()),
        "listblockedips" => Err(ChorusError::NotImplemented.into()),

        // System
        "stats" => Ok(Some(json!({
            "result": {
                "uptime": GLOBALS.start_time.elapsed().as_secs(),
                "num_connections": &GLOBALS.num_connections,
                "bytes_received": &GLOBALS.bytes_inbound,
                "bytes_sent": &GLOBALS.bytes_outbound,
            },
        }))),

        // Moderation
        "grantadmin" => {
            let pubkey = get_pubkey_param(obj)?;
            crate::mark_pubkey_as_moderator(pubkey, vec![])?;
            Ok(None)
        }

        "revokeadmin" => {
            let pubkey = get_pubkey_param(obj)?;
            crate::clear_pubkey_as_moderator(pubkey, vec![])?;
            Ok(None)
        }

        _ => Err(ChorusError::NotImplemented.into()),
    }
}

fn get_pubkey_param(obj: &Map<String, Value>) -> Result<Pubkey, Error> {
    let pubkey_text = obj
        .get("params")
        .ok_or(ChorusError::BadRequest("Params field missing").into_err())?
        .as_array()
        .ok_or(ChorusError::BadRequest("Params not an array").into_err())?
        .first()
        .ok_or(ChorusError::BadRequest("Missing pubkey parameter").into_err())?
        .as_str()
        .ok_or(ChorusError::BadRequest("Pubkey parameter is wrong type").into_err())?;
    Pubkey::read_hex(pubkey_text.as_bytes())
        .map_err(|_| ChorusError::BadRequest("Pubkey could not be parsed").into_err())
}

fn get_id_param(obj: &Map<String, Value>) -> Result<Id, Error> {
    let id_text = obj
        .get("params")
        .ok_or(ChorusError::BadRequest("Params field missing").into_err())?
        .as_array()
        .ok_or(ChorusError::BadRequest("Params not an array").into_err())?
        .first()
        .ok_or(ChorusError::BadRequest("Missing ID parameter").into_err())?
        .as_str()
        .ok_or(ChorusError::BadRequest("ID parameter is wrong type").into_err())?;
    Id::read_hex(id_text.as_bytes())
        .map_err(|_| ChorusError::BadRequest("ID could not be parsed").into_err())
}
