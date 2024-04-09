use crate::globals::GLOBALS;
use chorus_lib::config::Config;
use chorus_lib::error::Error;
use chorus_lib::ip::HashedPeer;
use hyper::{Body, Request, Response, StatusCode};

pub async fn serve_http(peer: HashedPeer, request: Request<Body>) -> Result<Response<Body>, Error> {
    log::debug!(target: "Client", "{}: HTTP request for {}", peer, request.uri());
    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .status(StatusCode::OK)
        .body("This is a nostr relay. Please use a nostr client to connect.".into())?;
    Ok(response)
}

pub async fn serve_nip11(peer: HashedPeer) -> Result<Response<Body>, Error> {
    log::debug!(target: "Client", "{}: sent NIP-11", peer);
    let rid = {
        let config = &*GLOBALS.config.read();
        GLOBALS.rid.get_or_init(|| build_rid(config))
    };

    let response = Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Content-Type", "application/nostr+json")
        .status(StatusCode::OK)
        .body(rid.clone().into())?;
    Ok(response)
}

fn build_rid(config: &Config) -> String {
    let mut rid: String = String::with_capacity(255);

    const SUPPORTED_NIPS: [u8; 7] = [
        1,  // nostr
        4,  // DMs
        9,  // Event Deletion
        11, // relay information document
        42, // AUTH
        59, // GiftWrap
        65, // Relay List Metadata
    ];
    const _UNSUPPORTED_NIPS: [u8; 8] = [
        26, // Delegated Event Signing
        28, // Public Chat
        29, // Relay-based Groups
        40, // Expiration Timestamp
        45, // Counting results
        50, // SEARCH
        94, // File Metadata
        96, // HTTP File Storage Integration
    ];
    const _INAPPLICABLE_NIPS: [u8; 44] = [
        2, 3, 5, 6, 7, 8, 10, 13, 14, 15, 18, 19, 21, 23, 24, 25, 27, 30, 31, 32, 34, 36, 38, 39,
        44, 46, 47, 48, 49, 51, 52, 53, 56, 57, 58, 72, 75, 78, 84, 89, 90, 92, 98, 99,
    ];

    let s = SUPPORTED_NIPS
        .iter()
        .map(|i| format!("{}", i))
        .collect::<Vec<String>>()
        .join(",");
    rid.push_str(&format!("{{\"supported_nips\":[{}],", s));

    let software = env!("CARGO_PKG_NAME");
    rid.push_str("\"software\":\"");
    rid.push_str(software);
    rid.push('\"');

    let version = env!("CARGO_PKG_VERSION");
    rid.push(',');
    rid.push_str("\"version\":\"");
    rid.push_str(version);
    rid.push('\"');

    if let Some(name) = &config.name {
        rid.push(',');
        rid.push_str("\"name\":\"");
        rid.push_str(name);
        rid.push('\"');
    }
    if let Some(description) = &config.description {
        rid.push(',');
        rid.push_str("\"description\":\"");
        rid.push_str(description);
        rid.push('\"');
    }
    if let Some(contact) = &config.contact {
        rid.push(',');
        rid.push_str("\"contact\":\"");
        rid.push_str(contact);
        rid.push('\"');
    }
    if let Some(pubkey) = &config.public_key {
        let mut pkh: [u8; 64] = [0; 64];
        pubkey.write_hex(&mut pkh).unwrap();
        rid.push(',');
        rid.push_str("\"pubkey\":\"");
        rid.push_str(unsafe { std::str::from_utf8_unchecked(pkh.as_slice()) });
        rid.push('\"');
    }

    // Limitation
    rid.push(',');
    rid.push_str("\"limitation\":{");
    {
        rid.push_str("\"payment_required\":false,\"auth_required\":false,\"restricted_writes\":true,\"max_message_length\":1048576");
        rid.push_str(&format!(
            ",\"max_subscriptions\":{}",
            config.max_subscriptions
        ));
    }
    rid.push('}');

    // Retention
    rid.push(',');
    rid.push_str("\"retention\":[{\"time\": null}]");

    // Services
    rid.push(',');
    rid.push_str("\"services\":{");
    rid.push_str("\"public\":[\"ephemeral\",\"directory\"]");
    rid.push(',');
    rid.push_str("\"private\":[\"outbox\",\"inbox\"]");
    rid.push(',');
    rid.push_str("\"paid\":[]");
    rid.push(',');
    rid.push_str("\"unavailable\":[\"search\"]");
    rid.push('}');

    rid.push('}');

    rid
}
