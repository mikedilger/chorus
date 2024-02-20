use crate::types::Time;

#[derive(Debug)]
pub struct IpData {
    pub ban_until: Time,
    pub number_of_error_bans: usize,
}
