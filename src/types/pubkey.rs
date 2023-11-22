use crate::Error;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn write_hex(&self, output: &mut [u8]) -> Result<(), Error> {
        write_hex!(self.0, output, 32)
    }

    pub fn read_hex(input: &[u8]) -> Result<Pubkey, Error> {
        let mut out: [u8; 32] = [0; 32];
        read_hex!(input, &mut out, 32)?;
        Ok(Pubkey(out))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes: [u8; 64] = [0; 64];
        self.write_hex(&mut bytes).unwrap();
        let hex = unsafe { std::str::from_utf8_unchecked(&bytes) };
        write!(f, "{hex}")
    }
}

#[cfg(test)]
mod test {
    use super::Pubkey;

    #[test]
    fn test_pubkey_hex_functions() {
        let hex = b"1110ee4ff957fa9c55832eaccb4dc1c45bfc6304e1e4e9fa478f53df4b20062d";
        let pubkey = Pubkey::read_hex(hex).unwrap();
        eprintln!("{:?}", pubkey);
        let mut hex2: [u8; 64] = [0; 64];
        pubkey.write_hex(&mut hex2).unwrap();
        assert_eq!(hex, &hex2);
        assert_eq!(format!("{}", pubkey).as_bytes(), hex);
    }
}
