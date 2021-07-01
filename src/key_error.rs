use ed25519_dalek::SignatureError;
use thiserror::Error;
use pkcs8::Error;
use openssl::error::ErrorStack;


#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("this private key does not support key derivation")]
    DeriveError(u32),

    #[error("invalid private key length: {0} bytes")]
    Length(usize),

    #[error(transparent)]
    Pem(#[from] ErrorStack),

    #[error(transparent)]
    Signature(#[from] SignatureError),
}
