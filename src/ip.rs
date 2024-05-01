use pocket_types::Time;
use speedy::{Readable, Writable};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy)]
pub struct HashedIp(pub [u8; 20], bool);

impl std::fmt::Display for HashedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe { write!(f, "{}", std::str::from_utf8_unchecked(self.0.as_slice())) }
    }
}

impl HashedIp {
    pub fn new(ip_addr: IpAddr) -> HashedIp {
        use base64::prelude::*;
        use secp256k1::hashes::{sha256, Hash};
        let bytes = ip_addr.write_to_vec().unwrap();
        let hashvalue: sha256::Hash = Hash::hash(&bytes);
        let tag = BASE64_STANDARD.encode(&hashvalue.as_byte_array()[0..16]);
        HashedIp(
            tag.as_bytes()[..20].try_into().unwrap(),
            ip_addr.is_loopback(),
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> HashedIp {
        HashedIp(bytes[0..20].try_into().unwrap(), false)
    }

    pub fn is_loopback(&self) -> bool {
        self.1
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HashedPeer(pub HashedIp, pub u16);

impl std::fmt::Display for HashedPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl HashedPeer {
    pub fn new(peer_addr: SocketAddr) -> HashedPeer {
        let hashed_ip = HashedIp::new(peer_addr.ip());
        HashedPeer(hashed_ip, peer_addr.port())
    }

    pub fn from_parts(hashed_ip: HashedIp, port: u16) -> HashedPeer {
        HashedPeer(hashed_ip, port)
    }

    pub fn ip(&self) -> HashedIp {
        self.0
    }

    pub fn port(&self) -> u16 {
        self.1
    }
}

// Single-session exit condition
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionExit {
    // No problems
    Ok,

    // Session exited with an error
    ErrorExit,

    // Session exited because of too many nostr command errors
    // (based on a per-session command punishment value that we don't track long term)
    TooManyErrors,

    // Session timed out without an active subscription
    Timeout,
}

// Long term reputation of an IP address
// The values are running totals, updating with (9/10) of old and (1/10) of new.
//
// Used to determine ban time multiplier from short-term violations
#[derive(Debug, Clone, Default, Readable, Writable)]
pub struct IpReputation {
    pub good: f32,
    pub errored: f32,
    pub too_many_errors: f32,
    pub timed_out: f32,
}

impl IpReputation {
    pub fn update(&mut self, session_exit: SessionExit) {
        // Lessen the running totals
        self.good *= 9.0 / 10.0;
        self.errored *= 9.0 / 10.0;
        self.too_many_errors *= 9.0 / 10.0;
        self.timed_out *= 9.0 / 10.0;

        match session_exit {
            SessionExit::Ok => self.good += 1.0,
            SessionExit::ErrorExit => self.errored += 1.0,
            SessionExit::TooManyErrors => self.too_many_errors += 1.0,
            SessionExit::Timeout => self.timed_out += 1.0,
        };
    }

    pub fn ban_multiplier(&self) -> f32 {
        let good_endings = 1.0 + self.good + (self.errored / 2.0);

        let bad_endings = 1.0 + self.timed_out + self.too_many_errors + (self.errored / 2.0);

        bad_endings / good_endings
    }
}

// Memory-only short-term record of IP handling
#[derive(Debug, Clone, Default, Readable, Writable)]
pub struct IpData {
    pub ban_until: u64,
    pub reputation: IpReputation,
}

impl IpData {
    pub fn update_on_session_close(
        &mut self,
        session_exit: SessionExit,
        minimum_ban_seconds: u64,
    ) -> u64 {
        // Update reputation
        self.reputation.update(session_exit);

        // Compute ban_until
        let mut until = Time::now();
        let seconds = self.ban_seconds(session_exit, minimum_ban_seconds);
        until = until + seconds;

        self.ban_until = self.ban_until.max(until.as_u64());

        seconds
    }

    pub fn is_banned(&self) -> bool {
        Time::from_u64(self.ban_until) > Time::now()
    }

    fn ban_seconds(&self, session_exit: SessionExit, minimum_ban_seconds: u64) -> u64 {
        let multiplier = self.reputation.ban_multiplier();

        match session_exit {
            SessionExit::Ok => minimum_ban_seconds,
            SessionExit::Timeout => minimum_ban_seconds,
            SessionExit::ErrorExit => minimum_ban_seconds + (2.0 * multiplier) as u64,
            SessionExit::TooManyErrors => minimum_ban_seconds + (5.0 * multiplier) as u64,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hashed_ip() {
        let ipaddr: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        println!("HashedIP={}", HashedIp::new(ipaddr));

        let socketaddr = std::net::SocketAddr::new(ipaddr, 80);
        println!("HashedPEER={}", HashedPeer::new(socketaddr));
    }
}
