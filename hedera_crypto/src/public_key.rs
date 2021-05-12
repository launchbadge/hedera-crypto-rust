use ed25519_dalek::ed25519::{Error, Signature};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use ed25519_dalek::{PublicKey, SignatureError, Verifier};
use hex;
use sha2::{Digest, Sha384};

/**
 * param {Unint8Array} data
 * returns {PublicKey}
 */
pub fn from_bytes(data: [u8; PUBLIC_KEY_LENGTH]) -> Result<PublicKey, SignatureError> {
    let _from_bytes: PublicKey = PublicKey::from_bytes(&data)?;
    Ok(_from_bytes)
}

/**
 * param {PublicKey} public_key
 * returns {Uint8Array}
 */
pub fn to_bytes(public_key: PublicKey) -> [u8; PUBLIC_KEY_LENGTH] {
    PublicKey::to_bytes(&public_key)
}

pub trait Display {
    fn to_string(&self) -> String;
}

impl Display for PublicKey {
    /**
     * returns {String}
     */
    fn to_string(&self) -> String {
        let der_prefix = String::from("302a300506032b6570032100");
        der_prefix + &hex::encode(self)
    }
}

pub trait FromStr {
    fn from_string(text: String) -> Result<PublicKey, SignatureError>;
}

impl FromStr for PublicKey {
    /**
     * Parse a public key from a string of hexadecimal digits.
     *
     * The public key may optionally be prefixed with
     * the DER header.
     */
    fn from_string(text: String) -> Result<PublicKey, SignatureError> {
        let decoded_public_key: Vec<u8> = hex::decode(&text).unwrap();
        let public_key: PublicKey = PublicKey::from_bytes(&decoded_public_key)?;

        Ok(public_key)
    }
}

/**
 * Verify a signature on a message with this public key.
 *
 * param {Uint8Array} message
 * param {Uint8Array} signature
 * returns {()}
 */
pub fn verify(
    public_key: PublicKey,
    message: [u8; PUBLIC_KEY_LENGTH],
    signature: Signature,
) -> Result<(), Error> {
    let _verify = Verifier::verify(&public_key, &message, &signature)?;
    Ok(())
}

/**
 * param {Uint8Array} data
 * returns {Uint8Array}
 */
pub fn hash(data: [u8; PUBLIC_KEY_LENGTH]) -> Sha384 {
    let mut hasher = Sha384::new();
    hasher.update(&data);
    hasher
}

/**
 * param {PublicKey} public_key
 * param {PublicKey} other
 * returns {boolean}
 */
pub fn eq(public_key: PublicKey, other: PublicKey) -> bool {
    PublicKey::eq(&public_key, &other)
}
