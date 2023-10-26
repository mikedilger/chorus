use crate::error::Error;
use futures::sink::SinkExt;
use hyper_tungstenite::{tungstenite, WebSocketStream};
use nostr_types::RelayMessage;
use tokio::io::{AsyncRead, AsyncWrite};
use tungstenite::Message;

pub async fn handle<S>(websocket: &mut WebSocketStream<S>, msg: String) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    log::error!("Received unhandled text message: {}", msg);
    let notice = RelayMessage::Notice("NIP-01 is not yet fully supported".to_string());
    let string = serde_json::to_string(&notice)?;
    websocket.send(Message::text(&string)).await?;
    Ok(())
}
