use cipher::errors::InvalidLength;
use hmac::crypto_mac::MacError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("unsupported hash function: {0}")]
    UnsupportedHashFunction(String),

    #[error("unsupported key derivation function: {0}")]
    UnsupportedKeyDerivationFunction(String),

    #[error("HMAC mismatch; passphrase is incorrect")]
    HmacMismatch(#[from] MacError),

    #[error("invalid length of IV")]
    InvalidIvLength(#[from] InvalidLength),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
