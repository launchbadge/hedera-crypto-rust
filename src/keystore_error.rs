use std::str::Utf8Error;

use cipher::errors::InvalidLength;
use ed25519_dalek::SignatureError;
use hex::FromHexError;
use serde_json;
use thiserror::Error;

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
