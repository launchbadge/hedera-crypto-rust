use ed25519_dalek::{Signature, Verifier};
use hex;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::hash::Hasher;
use std::str;
use std::str::FromStr;
use thiserror::Error;

const DER_PREFIX: &str = "302a300506032b6570032100";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid public key length: {0}")]
    Length(usize),

    #[error(transparent)]
    Signature(#[from] ed25519_dalek::SignatureError),
}

/// A Public Key on the Hedera™ Network
#[derive(Debug, Eq, PartialEq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl Hash for PublicKey {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.as_bytes().hash(state)
    }
}

impl PublicKey {
    /// Returns a public key.
    ///
    /// # Arguments
    ///
    /// * `data` - An array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
    ///
    pub fn from_bytes(data: &[u8]) -> Result<PublicKey, KeyError> {
        let der_prefix_bytes = hex::decode("302a300506032b6570032100").unwrap();

        let public_key = match data.len() {
            32 => {
                let public_key = PublicKey(
                    ed25519_dalek::PublicKey::from_bytes(&data).map_err(KeyError::Signature)?,
                );
                public_key
            }

            44 if data.starts_with(&der_prefix_bytes) => {
                let public_key = PublicKey(
                    ed25519_dalek::PublicKey::from_bytes(&data[12..44])
                        .map_err(KeyError::Signature)?,
                );
                public_key
            }

            _ => {
                return Err(KeyError::Length(data.len()));
            }
        };

        Ok(public_key)
    }

    /// Return an array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
    ///
    /// # Arguments
    ///
    /// * `public_key` - ed25519_dalek::PublicKey
    ///
    pub fn to_bytes(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Verify a signature on a message with this public key.
    ///
    /// # Arguments
    ///
    /// `&self` - current instance of PublicKey type.
    ///
    /// `message` - slice &[u8]
    ///
    /// `signature` - slice &[u8]
    ///
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let signature = if let Ok(signature) = Signature::try_from(signature) {
            signature
        } else {
            return false;
        };

        self.0.verify(message, &signature).is_ok()
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}{}", DER_PREFIX, hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = KeyError;

    fn from_str(text: &str) -> Result<Self, KeyError> {
        let decoded_public_key = hex::decode(&text).unwrap();
        let public_key = PublicKey::from_bytes(&decoded_public_key)?;

        Ok(public_key)
    }
}

// TODO: Add more tests 
#[cfg(test)]
mod tests {
    use super::{KeyError, PublicKey};

    #[test]
    fn parse_from_bytes() -> Result<(), KeyError> {
        let public_key_bytes: &[u8] = &[
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];

        let public_key = PublicKey::from_bytes(&public_key_bytes)?;

        assert_eq!(&public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[test]
    fn test_to_bytes() -> Result<(), KeyError> {
        let public_key_bytes: &[u8] = &[
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];

        let public_key = PublicKey::from_bytes(&public_key_bytes)?;

        let key_to_bytes = PublicKey::to_bytes(&public_key);

        println!("{:?}", public_key_bytes);
        println!("{:?}", key_to_bytes);
        assert_eq!(key_to_bytes, public_key_bytes);

        Ok(())
    }
}
