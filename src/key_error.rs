use ed25519_dalek::SignatureError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("this private key does not support key derivation")]
    DeriveError(u32),

    #[error("invalid private key length: {0} bytes")]
    Length(usize),

    #[error(transparent)]
    Signature(#[from] SignatureError),
}
