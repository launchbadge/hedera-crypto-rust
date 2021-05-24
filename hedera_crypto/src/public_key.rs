use ed25519_dalek;
use hex;
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str;
use std::str::FromStr;
use thiserror::Error;

const DER_PREFIX: &str = "302a300506032b6570032100";
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid public key length: {0}")]
    Length(usize),
    #[error(transparent)]
    Signature(#[from] ed25519_dalek::SignatureError),
}

/// A Public Key on the Hedera™ Network
#[derive(Debug, Eq, PartialEq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl PublicKey {
    /// Returns a public key.
    ///
    /// # Arguments
    ///
    /// * `data` - An array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
    ///
    pub fn from_bytes(data: &[u8]) -> Result<PublicKey, KeyError> {
        let der_prefix_bytes = vec_to_array(hex::decode("302a300506032b6570032100").unwrap());

        let public_key = match data.len() {
            32 => {
                let public_key = PublicKey(
                    ed25519_dalek::PublicKey::from_bytes(&data)
                        .map_err(KeyError::Signature)?,
                );
                public_key
            }
            44 if data.starts_with(&der_prefix_bytes) => {
                let public_key = PublicKey(
                    ed25519_dalek::PublicKey::from_bytes(&data[0..12])
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
}

/// Return a string.
impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let to_string = DER_PREFIX.to_string() + &hex::encode(self.to_string());
        write!(f, "{}", to_string)
    }
}

/// Parse a public key from a string og hexidecimal digits.
///
/// The public key map optionally be prefixed with
/// the DER header.
///
/// Returns a public key.
///
/// # Arguments
///
/// * `text` - string
///
impl FromStr for PublicKey {
    type Err = ParseIntError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let decoded_public_key = vec_to_array(hex::decode(&text).unwrap());
        let public_key = PublicKey::from_bytes(&decoded_public_key).unwrap();

        Ok(public_key)
    }
}

/// Verify a signature on a message with this public key.
///
/// Returns a boolean.
///
/// # Arguments
///
/// * `message` - An array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
///
/// * `signature` - ed25519_dalek::Signature
///
fn verify(
    public_key: ed25519_dalek::PublicKey,
    message: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    signature: ed25519_dalek::Signature,
) -> Result<(), ed25519_dalek::ed25519::Error> {
    let verify_hash = ed25519_dalek::Verifier::verify(&public_key, &message, &signature)?;
    Ok(verify_hash)
}

/// # Arguments
///
/// * `v` - vector of generic type T.
///
fn vec_to_array<T>(v: Vec<T>) -> [T; ed25519_dalek::PUBLIC_KEY_LENGTH] {
    v.try_into().unwrap_or_else(|v: Vec<T>| {
        panic!("Expected a Vec of length {} but it was {}", 32, v.len())
    })
}
