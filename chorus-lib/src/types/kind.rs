use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Kind(pub u16);

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Kind {
    // Some kinds a relay may need to treat differently
    pub const SEAL: u16 = 13;
    pub const DM_CHAT: u16 = 14;

    pub fn is_replaceable(&self) -> bool {
        (10000..20000).contains(&self.0) || self.0 == 0 || self.0 == 3
    }

    pub fn is_ephemeral(&self) -> bool {
        (20000..30000).contains(&self.0)
    }

    pub fn is_parameterized_replaceable(&self) -> bool {
        (30000..40000).contains(&self.0)
    }
}
