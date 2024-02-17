use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub u64);

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Time {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn min() -> Time {
        Time(0)
    }

    pub fn max() -> Time {
        Time(u64::MAX)
    }

    pub fn now() -> Time {
        // Safety: unwrap() can only panic if the system time is before UNIX_EPOCH
        Time(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
    }
}
