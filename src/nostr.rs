use crate::error::Error;
use crate::globals::GLOBALS;
use nostr_types::{ClientMessage, RelayMessage};
use std::net::SocketAddr;

pub async fn handle(_session_id: u64, _peer: SocketAddr, msg: ClientMessage) -> Result<RelayMessage, Error> {
    match msg {
        ClientMessage::Event(event) => {
            match GLOBALS.store.get().unwrap().store_event(event.as_ref()) {
                Ok(_) => Ok(RelayMessage::Ok(event.id, true, "stored".to_owned())),
                Err(e) => Ok(RelayMessage::Ok(event.id, false, format!("{}", e))),
            }

            // Serve to any session subscription that is listening for it
            // TBD
        }
        ClientMessage::Req(_subid, _vec_filters) => {
            // Store in session
            // TBD

            // Fetch until EOSE
            // TBD

            // Send EOSE
            // TBD

            Ok(RelayMessage::Notice("REQ is not yet supported".to_string()))
        }
        ClientMessage::Close(_subid) => Ok(RelayMessage::Notice(
            "CLOSE is not yet supported".to_string(),
        )),
        ClientMessage::Auth(_event) => {
            // Not part of NIP-01, not yet handled
            Ok(RelayMessage::Notice(
                "AUTH is not yet supported".to_string(),
            ))
        }
    }
}
