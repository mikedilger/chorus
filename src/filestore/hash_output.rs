use crate::{ChorusError, Error};
use std::fmt;
use std::path::{Path, PathBuf};

/// A simple type for a SHA-256 hash output of 32 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HashOutput([u8; 32]);

impl HashOutput {
    pub fn from_engine(engine: bitcoin_hashes::sha256::HashEngine) -> HashOutput {
        use bitcoin_hashes::{sha256, Hash};
        let hashvalue = sha256::Hash::from_engine(engine);
        HashOutput(hashvalue.as_byte_array()[0..32].try_into().unwrap())
    }

    pub fn from_hex(input: &str) -> Result<HashOutput, Error> {
        let bytes = hex::decode(input)?;
        if bytes.len() == 32 {
            Ok(HashOutput(bytes.try_into().unwrap()))
        } else {
            Err(
                ChorusError::General("HashOutput::from_hex() got wrong length string".to_string())
                    .into(),
            )
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> HashOutput {
        HashOutput(bytes)
    }

    pub fn to_pathbuf<P: AsRef<Path>>(&self, base: P) -> PathBuf {
        let s = hex::encode(self.0);
        let mut output: PathBuf = PathBuf::new();
        output.push(base);
        output.push(&s[0..=1]);
        output.push(&s[2..=3]);
        output.push(&s[4..]);
        output
    }
}

impl fmt::Display for HashOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash_output_to_pathbuf() {
        let hash = HashOutput::from_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();

        assert_eq!(
            &format!("{}", hash.to_pathbuf("/tmp").display()),
            "/tmp/e3/b0/c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
