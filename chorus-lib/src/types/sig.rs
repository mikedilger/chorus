use crate::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sig(pub [u8; 64]);

impl Sig {
    pub fn write_hex(&self, output: &mut [u8]) -> Result<(), Error> {
        write_hex!(self.0, output, 64)
    }

    pub fn read_hex(input: &[u8]) -> Result<Sig, Error> {
        let mut out: [u8; 64] = [0; 64];
        read_hex!(input, &mut out, 64)?;
        Ok(Sig(out))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Display for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes: [u8; 128] = [0; 128];
        self.write_hex(&mut bytes).unwrap();
        let hex = unsafe { std::str::from_utf8_unchecked(&bytes) };
        write!(f, "{hex}")
    }
}

#[cfg(test)]
mod test {
    use super::Sig;

    #[test]
    fn test_sig_hex_functions() {
        let hex = b"f4165cd621d387e0f723c3ca7484ca3da9ede00ffc97eb57c3e695384e095dea1a6215e7328b793e878f436f508006f95957c7e6b652e80d4c3c47b9f9110e7d";
        let sig = Sig::read_hex(hex).unwrap();
        eprintln!("{:?}", sig);
        let mut hex2: [u8; 128] = [0; 128];
        sig.write_hex(&mut hex2).unwrap();
        assert_eq!(hex, &hex2);
        assert_eq!(format!("{}", sig).as_bytes(), hex);
    }
}
