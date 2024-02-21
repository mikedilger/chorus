use crate::types::Time;
use speedy::{Readable, Writable};

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
    pub ban_until: Time,
    pub reputation: IpReputation,
}

impl IpData {
    pub fn update_on_session_close(&mut self, session_exit: SessionExit) -> u64 {
        // Update reputation
        self.reputation.update(session_exit);

        // Compute ban_until
        let mut until = Time::now();
        let seconds = self.ban_seconds(session_exit);
        until.0 += seconds;

        self.ban_until = Time(self.ban_until.0.max(until.0));

        seconds
    }

    pub fn is_banned(&self) -> bool {
        self.ban_until > Time::now()
    }

    fn ban_seconds(&self, session_exit: SessionExit) -> u64 {
        let multiplier = self.reputation.ban_multiplier();

        match session_exit {
            SessionExit::Ok => 2,
            SessionExit::ErrorExit => 2 + (2.0 * multiplier) as u64,
            SessionExit::TooManyErrors => 2 + (5.0 * multiplier) as u64,
            SessionExit::Timeout => 2 + (4.0 * multiplier) as u64,
        }
    }
}
