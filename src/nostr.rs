use crate::error::Error;
use crate::session::Session;
use nostr_types::{ClientMessage, RelayMessage};

pub async fn handle(_session: &mut Session, msg: ClientMessage) -> Result<RelayMessage, Error> {
    match msg {
        ClientMessage::Event(_event) => Ok(RelayMessage::Notice(
            "EVENT is not yet supported".to_string(),
        )),
        ClientMessage::Req(_subid, _vec_filters) => {
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
