use ed25519_dalek;
use hex;
use std::str;
use std::str::FromStr;
use std::num::ParseIntError;
use std::fmt::{Display, Formatter};
use std::fmt;
use std::convert::TryInto;

/// A Public Key on the Hedera™ Network
#[derive(Debug, Hash, Eq)]
struct PublicKey(ed25519_dalek::PublicKey);

/// Returns a public key.
///
/// # Arguments
///
/// * `data` - An array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
///
fn from_bytes(
    data: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
) -> Result<PublicKey, ed25519_dalek::ed25519::Error> {
    let der_prefix_bytes = vec_to_array(hex::decode("302a300506032b6570032100").unwrap());

    let public_key = match data.len() {
        32 => {
            let public_key = PublicKey(ed25519_dalek::PublicKey::from_bytes(&data[0..12])?);
            public_key
        },
        44 if array_starts_with(&data, &der_prefix_bytes) => {
            let public_key = PublicKey(ed25519_dalek::PublicKey::from_bytes(&data)?);
            public_key
        },
        _ => panic!("Invalid public key length: {} bytes", data.len())
    };

    Ok(public_key)
}

/// Return an array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
///
/// # Arguments
///
/// * `public_key` - ed25519_dalek::PublicKey
///
fn to_bytes(public_key: ed25519_dalek::PublicKey) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
    ed25519_dalek::PublicKey::to_bytes(&public_key)
}

/// Return a string.
impl Display for PublicKey {

    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let der_prefix = String::from("302a300506032b6570032100");
        let to_string = der_prefix + &hex::encode(self.to_string());
        write!(f, "{}",to_string)
        
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
        let public_key = from_bytes(decoded_public_key).unwrap();
        
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
/// * `arr` - A reference to an array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
///
/// * `arr_prefix` - A reference to an array of u8 with length of ed25519_dalek::PUBLIC_KEY_LENGTH.
///
fn array_starts_with(arr: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], arr_prefix: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]) -> bool {
    if arr.len() < arr_prefix.len() {
        return false;
    }

    for i in 0..arr.len() {
        if arr[i] != arr_prefix[i] {
            return false;
        }
    }
    
    true
}

/// # Arguments
///
/// * `v` - vector of generic type T.
///
fn vec_to_array<T>(v: Vec<T>) -> [T; ed25519_dalek::PUBLIC_KEY_LENGTH] {
    v.try_into().unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", 32, v.len()))
}
