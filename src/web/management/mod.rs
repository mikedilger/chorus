use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use crate::ip::HashedPeer;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use pocket_db::ScreenResult;
use pocket_types::{Event, Filter, Id, Kind, Pubkey};
use serde::Serialize;
use serde_json::{json, Map, Value};
mod auth;

#[derive(Serialize)]
struct EventResult {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct FullEventResult {
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct PubkeyResult {
    pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

fn respond(
    json: serde_json::Value,
    status: StatusCode,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    let s: String = serde_json::to_string(&json)?;
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "Authorization, *")
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
    let (pubkey, command) = match auth::check_auth(request).await {
        Ok((pk, v)) => (pk, v),
        Err(e) => {
            let result = json!({
                "result": {},
                "error": format!("{}", e)
            });
            return respond(result, StatusCode::UNAUTHORIZED);
        }
    };

    match handle_inner(pubkey, command) {
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

pub fn handle_inner(pubkey: Pubkey, command: Value) -> Result<Option<Value>, Error> {
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
                "supportedmethods",

                "listeventsneedingmoderation",

                "allowevent",
                "banevent",
                "clearevent",
                "removeevent",

                "allowpubkey",
                "banpubkey",
                "clearpubkey",

                "listallowedevents",
                "listbannedevents",
                "listbannedevents2",
                "listallowedpubkeys",
                "listbannedpubkeys",

                "stats",
                "numconnections",
                "uptime",

                "listadmins",
                "listmoderators",
                "grantmoderator",
                "revokemoderator",
                "listusers",
                "grantuser",
                "revokeuser",
            ]
        }))),
        "listeventsneedingmoderation" => {
            // FIXME this scans the entire database, maybe we need to some process
            // that does this in epochs and saves the result.

            let allowed_kinds = [
                Kind::from(4),     // Encrypted Direct Message
                Kind::from(1059),  // Giftwrap
                Kind::from(10002), // Relay list
                Kind::from(10050), // DM Relay list
                Kind::from(0),     // Metadata
                Kind::from(3),     // Following list
                Kind::from(7),     // Reaction
            ];
            let mut buffer: [u8; 128] = [0; 128];
            let filter = {
                let (_incount, _outcount, filter) = Filter::from_json(b"{}", &mut buffer)?;
                filter
            };
            let screen = |e: &Event| -> ScreenResult {
                if allowed_kinds.contains(&e.kind())
                    || e.kind().is_ephemeral()
                    || crate::is_authorized_user(e.pubkey())
                {
                    ScreenResult::Mismatch
                } else {
                    ScreenResult::Match
                }
            };

            let mut need_moderation: Vec<EventResult> = Vec::new();

            let (mut events, _redacted) = GLOBALS
                .store
                .get()
                .unwrap()
                .find_events(filter, true, 0, 0, screen)?;

            for event in events.drain(..) {
                // Skip if pubkey marked (either banned or approved)
                if matches!(
                    crate::get_pubkey_approval(GLOBALS.store.get().unwrap(), event.pubkey()),
                    Ok(Some(_))
                ) {
                    continue;
                }

                // Skip if event marked (either banned or approved)
                if matches!(
                    crate::get_event_approval(GLOBALS.store.get().unwrap(), event.id()),
                    Ok(Some(_))
                ) {
                    continue;
                }

                need_moderation.push(EventResult {
                    id: event.id().as_hex_string(),
                    reason: Some("unmoderated".to_string()),
                });
            }

            Ok(Some(json!({
                "result": need_moderation,
            })))
        }
        "allowevent" => {
            let id = get_id_param(obj)?;
            crate::mark_event_approval(GLOBALS.store.get().unwrap(), id, true)?;
            Ok(None)
        }
        "banevent" => {
            let id = get_id_param(obj)?;
            crate::mark_event_approval(GLOBALS.store.get().unwrap(), id, false)?;
            Ok(None)
        }
        "clearevent" => {
            let id = get_id_param(obj)?;
            crate::clear_event_approval(GLOBALS.store.get().unwrap(), id)?;
            Ok(None)
        }
        "removeevent" => {
            let id = get_id_param(obj)?;
            GLOBALS.store.get().unwrap().remove_event(id)?;
            Ok(None)
        }

        "allowpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, true)?;
            Ok(None)
        }
        "banpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::mark_pubkey_approval(GLOBALS.store.get().unwrap(), pk, false)?;
            Ok(None)
        }
        "clearpubkey" => {
            let pk = get_pubkey_param(obj)?;
            crate::clear_pubkey_approval(GLOBALS.store.get().unwrap(), pk)?;
            Ok(None)
        }

        "listallowedevents" => {
            let approvals = crate::dump_event_approvals(GLOBALS.store.get().unwrap())?;
            let ids: Vec<EventResult> = approvals
                .iter()
                .filter_map(|(id, appr)| {
                    if *appr {
                        Some(EventResult {
                            id: id.as_hex_string(),
                            reason: None,
                        })
                    } else {
                        None
                    }
                })
                .collect();
            Ok(Some(json!({
                "result": ids
            })))
        }
        "listbannedevents" => {
            let approvals = crate::dump_event_approvals(GLOBALS.store.get().unwrap())?;
            let ids: Vec<EventResult> = approvals
                .iter()
                .filter_map(|(id, appr)| {
                    if *appr {
                        None
                    } else {
                        Some(EventResult {
                            id: id.as_hex_string(),
                            reason: None,
                        })
                    }
                })
                .collect();
            Ok(Some(json!({
                "result": ids
            })))
        }
        "listbannedevents2" => {
            let approvals = crate::dump_event_approvals(GLOBALS.store.get().unwrap())?;
            let mut results: Vec<FullEventResult> = Vec::new();
            for (id, appr) in approvals.iter() {
                if ! *appr {
                    if let Some(event) = GLOBALS.store.get().unwrap().get_event_by_id(*id)? {
                        results.push(
                            FullEventResult {
                                event: format!("{event}"),
                                reason: None,
                            }
                        );
                    }
                }
            }
            Ok(Some(json!({
                "result": results
            })))
        }
        "listallowedpubkeys" => {
            let approvals = crate::dump_pubkey_approvals(GLOBALS.store.get().unwrap())?;
            let pubkeys: Vec<PubkeyResult> = approvals
                .iter()
                .filter_map(|(pk, appr)| {
                    if *appr {
                        Some(PubkeyResult {
                            pubkey: pk.as_hex_string(),
                            reason: None,
                        })
                    } else {
                        None
                    }
                })
                .collect();
            Ok(Some(json!({
                "result": pubkeys
            })))
        }
        "listbannedpubkeys" => {
            let approvals = crate::dump_pubkey_approvals(GLOBALS.store.get().unwrap())?;
            let pubkeys: Vec<PubkeyResult> = approvals
                .iter()
                .filter_map(|(pk, appr)| {
                    if *appr {
                        None
                    } else {
                        Some(PubkeyResult {
                            pubkey: pk.as_hex_string(),
                            reason: None,
                        })
                    }
                })
                .collect();
            Ok(Some(json!({
                "result": pubkeys
            })))
        }

        "stats" => {
            let store_stats = GLOBALS.store.get().unwrap().stats()?;
            Ok(Some(json!({
                "result": {
                    "uptime": GLOBALS.start_time.elapsed().as_secs(),
                    "num_connections": &GLOBALS.num_connections,
                    "bytes_received": &GLOBALS.bytes_inbound,
                    "bytes_sent": &GLOBALS.bytes_outbound,
                    "event_bytes": store_stats.event_bytes,
                    "num_events": store_stats.index_stats.i_index_entries,
                    "index_disk_usage": store_stats.index_stats.disk_usage,
                    "index_memory_usage": store_stats.index_stats.memory_usage,
                }
            })))
        }
        "numconnections" => {
            let num = &GLOBALS.num_connections;
            Ok(Some(json!({
                "result": num,
            })))
        }
        "uptime" => {
            let uptime_in_secs = GLOBALS.start_time.elapsed().as_secs();
            Ok(Some(json!({
                "result": uptime_in_secs,
            })))
        }

        "listadmins" => {
            let keys = GLOBALS.config.read().admin_hex_keys.clone();
            Ok(Some(json!({
                "result": keys
            })))
        }
        "listmoderators" => {
            let moderators: Vec<String> =
                crate::dump_authorized_users(GLOBALS.store.get().unwrap())?
                    .iter()
                    .filter_map(|(pk, moderator)| {
                        if *moderator {
                            Some(pk.as_hex_string())
                        } else {
                            None
                        }
                    })
                    .collect();
            Ok(Some(json!({
                "result": moderators
            })))
        }
        "grantmoderator" => {
            if !crate::is_admin(pubkey) {
                Ok(Some(json!({
                    "result": {},
                    "error": "Unauthorized: Only admins can grant moderator status"
                })))
            } else {
                let pk = get_pubkey_param(obj)?;
                crate::add_authorized_user(GLOBALS.store.get().unwrap(), pk, true)?;
                Ok(None)
            }
        }
        "revokemoderator" => {
            if !crate::is_admin(pubkey) {
                Ok(Some(json!({
                    "result": {},
                    "error": "Unauthorized: Only admins can revoke moderator status"
                })))
            } else {
                let pk = get_pubkey_param(obj)?;

                // Do not do this if they aren't already an authorized user
                if !crate::is_authorized_user(pk) {
                    Ok(None)
                } else {
                    crate::add_authorized_user(GLOBALS.store.get().unwrap(), pk, false)?;
                    Ok(None)
                }
            }
        }
        "listusers" => {
            let users: Vec<String> = crate::dump_authorized_users(GLOBALS.store.get().unwrap())?
                .iter()
                .map(|(pk, _moderator)| pk.as_hex_string())
                .collect();
            Ok(Some(json!({
                "result": users
            })))
        }
        "grantuser" => {
            if !crate::is_admin(pubkey) {
                Ok(Some(json!({
                    "result": {},
                    "error": "Unauthorized: Only admins can grant user status"
                })))
            } else {
                let pk = get_pubkey_param(obj)?;
                crate::add_authorized_user(GLOBALS.store.get().unwrap(), pk, false)?;
                Ok(None)
            }
        }
        "revokeuser" => {
            if !crate::is_admin(pubkey) {
                Ok(Some(json!({
                    "result": {},
                    "error": "Unauthorized: Only admins can revoke user status"
                })))
            } else {
                let pk = get_pubkey_param(obj)?;
                crate::rm_authorized_user(GLOBALS.store.get().unwrap(), pk)?;
                Ok(None)
            }
        }

        // Commands we do not support (yet)
        "allowkind" => Err(ChorusError::NotImplemented.into()),
        "disallowkind" => Err(ChorusError::NotImplemented.into()),
        "listbannedkinds" => Err(ChorusError::NotImplemented.into()),
        "listallowedkinds" => Err(ChorusError::NotImplemented.into()),
        "blockip" => Err(ChorusError::NotImplemented.into()),
        "unblockip" => Err(ChorusError::NotImplemented.into()),
        "listblockedips" => Err(ChorusError::NotImplemented.into()),
        "changerelayname" => Err(ChorusError::NotImplemented.into()),
        "changerelaydescription" => Err(ChorusError::NotImplemented.into()),
        "changerelayicon" => Err(ChorusError::NotImplemented.into()),

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
