use ed25519_dalek;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid private key length: {0}")]
    Length(usize),
    #[error(transparent)]
    Signature(#[from] ed25519_dalek::SignatureError),
}