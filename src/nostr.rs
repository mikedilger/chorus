use crate::error::Error;
use nostr_types::{ClientMessage, RelayMessage};

pub async fn handle(msg: ClientMessage) -> Result<RelayMessage, Error> {
    log::debug!("Received: {}", serde_json::to_string(&msg)?);
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
