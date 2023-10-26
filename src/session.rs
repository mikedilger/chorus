use nostr_types::{Filter, PublicKey, SubscriptionId};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Session {
    pub peer: SocketAddr,
    pub auth: Option<PublicKey>,
    pub subscriptions: HashMap<SubscriptionId, Vec<Filter>>,
}

impl Session {
    pub fn new(peer: SocketAddr) -> Session {
        Session {
            peer,
            auth: None,
            subscriptions: HashMap::new(),
        }
    }
}
