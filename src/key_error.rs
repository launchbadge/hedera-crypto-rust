use ed25519_dalek::SignatureError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("invalid private key length: {0} bytes")]
    Length(usize),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error("legacy 22-word mnemonics do not support passphrases")]
    Passphrase,
}
