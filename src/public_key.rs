use crate::key_error::KeyError;
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

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::str::FromStr;

    use super::{KeyError, PublicKey};

    const PUBLIC_KEY_BYTES: &[u8] = &[
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];

    #[test]
    fn parse_from_bytes() -> Result<(), KeyError> {
        let public_key = gen_public_key()?;

        assert_eq!(&public_key.to_bytes(), PUBLIC_KEY_BYTES);

        Ok(())
    }

    #[test]
    fn test_to_bytes() -> Result<(), KeyError> {
        let public_key = gen_public_key()?;

        let key_to_bytes = PublicKey::to_bytes(&public_key);

        assert_eq!(key_to_bytes, PUBLIC_KEY_BYTES);

        Ok(())
    }

    #[test]
    fn test_verify() -> Result<(), KeyError> {
        let public_key = PublicKey::from_bytes(PUBLIC_KEY_BYTES)?;
        let message = b"hello, world";
        let signature = &[157, 4, 191, 237, 123, 170, 151, 200, 13, 41, 166, 174];

        println!("{}", PublicKey::verify(&public_key, message, signature));
        Ok(())
    }

    #[test]
    fn test_to_string() -> Result<(), KeyError> {
        let public_key = gen_public_key()?;
        let test_string = "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

        assert_eq!(public_key.to_string(), test_string);
        Ok(())
    }

    #[test]
    fn test_from_string() -> Result<(), KeyError> {
        let public_key = gen_public_key()?;

        let key_to_string = public_key.to_string();

        let string_to_key = PublicKey::from_str(&key_to_string).unwrap();

        assert_eq!(string_to_key, public_key);
        Ok(())
    }

    #[test]
    fn test_hash() -> Result<(), KeyError> {
        let public_key = gen_public_key()?;
        let hashed_key = hash_key(&public_key);

        assert_eq!(hashed_key, 17835864368987990728);

        Ok(())
    }

    fn gen_public_key() -> Result<PublicKey, KeyError> {
        let public_key = PublicKey::from_bytes(&PUBLIC_KEY_BYTES)?;
        Ok(public_key)
    }

    fn hash_key<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}
