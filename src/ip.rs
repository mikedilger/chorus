use crate::types::Time;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ban {
    General,
    ErrorExit,
    TooManyErrors,
    Timeout,
}

#[derive(Debug)]
pub struct IpData {
    pub ban_until: Time,
    pub number_of_error_exits: u64,
    pub number_of_too_many_error_bans: u64,
    pub number_of_timeouts: u64,
}

impl IpData {
    pub fn new(ban: Ban) -> (IpData, u64) {
        let mut ipdata = IpData {
            ban_until: Time::now(),
            number_of_error_exits: 0,
            number_of_too_many_error_bans: 0,
            number_of_timeouts: 0,
        };

        let seconds = ipdata.ban(ban);

        (ipdata, seconds)
    }

    pub fn ban(&mut self, ban: Ban) -> u64 {
        // Update numbers
        match ban {
            Ban::ErrorExit => self.number_of_error_exits += 1,
            Ban::TooManyErrors => self.number_of_too_many_error_bans += 1,
            Ban::Timeout => self.number_of_timeouts += 1,
            _ => (),
        };

        // Compute ban_until
        let mut until = Time::now();
        let seconds = self.ban_seconds(ban);
        until.0 += seconds;

        self.ban_until = Time(self.ban_until.0.max(until.0));

        seconds
    }

    fn ban_seconds(&self, thisban: Ban) -> u64 {
        match thisban {
            Ban::General => 2,
            Ban::ErrorExit => 2 + self.number_of_error_exits * 10,
            Ban::TooManyErrors => 2 + self.number_of_too_many_error_bans * 15,
            Ban::Timeout => 2 + self.number_of_timeouts * 5,
        }
    }
}
