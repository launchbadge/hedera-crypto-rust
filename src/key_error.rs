use ed25519_dalek::SignatureError;
use thiserror::Error;

use crate::keystore_error::KeystoreError;
use crate::bad_mnemonic_error::BadMnemonicError;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("this private key does not support key derivation")]
    DeriveError(i64),

    #[error("invalid private key length: {0} bytes")]
    Length(usize),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error("legacy 22-word mnemonics do not support passphrases")]
    PassphraseUnsupported,

    #[error(transparent)]
    Mnemonic(#[from] BadMnemonicError),

    #[error(transparent)]
    Keystore(#[from] KeystoreError),
}
