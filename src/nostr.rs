use crate::error::Error;
use crate::reply::NostrReply;
use crate::WebSocketService;
use futures::SinkExt;
use hyper_tungstenite::tungstenite::Message;

impl WebSocketService {
    pub async fn handle_nostr_message(&mut self, msg: String) -> Result<(), Error> {
        // If the msg is large, grow the session buffer
        // (it will be freed when they disconnect)
        if msg.len() > 4096 {
            let newlen = 4096 * ((msg.len() / 4096) + 1);
            self.buffer.resize(newlen, 0);
        }

        log::warn!("Received unhandled text message: {}", msg);
        let reply = NostrReply::Notice("NIP-01 is not yet fully supported".to_owned());
        self.websocket.send(Message::text(reply.as_json())).await?;
        Ok(())
    }
}
