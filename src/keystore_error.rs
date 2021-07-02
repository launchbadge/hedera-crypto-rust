use cipher::errors::InvalidLength;
use std::str::Utf8Error;
use hex::FromHexError;
use thiserror::Error;
use ed25519_dalek::SignatureError;
use serde_json;

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("HMAC mismatch; passphrase is incorrect")]
    HmacError,

    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),

    #[error(transparent)]
    FromHexError(#[from] FromHexError),

    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
}
