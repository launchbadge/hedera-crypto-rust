use ed25519_dalek::SignatureError;
use openssl::error::ErrorStack;
use pkcs8::Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("this private key does not support key derivation")]
    DeriveError(u32),

    #[error("invalid private key length: {0} bytes")]
    Length(usize),

    // #[error("invalid private key length: {0} bytes")]
    // Pem,

    #[error(transparent)]
    Pem(#[from] ErrorStack),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error("legacy 22-word mnemonics do not support passphrases")]
    Passphrase,

}
