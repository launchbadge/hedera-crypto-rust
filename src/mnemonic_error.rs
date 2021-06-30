use thiserror::Error;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("the mnemonic has an invalid checksum.")]
    ChecksumMismatch,

    #[error("legacy 22-word mnemonics do not support passphrases")]
    Passphrase,

    #[error("unsupported phrase length {0}, Only 12 and 24 are supported")]
    Length(usize),

    #[error("mnemonic contained words that are not in the standard word list")]
    UnknownWord,

    #[error("word not found in word list: `{0}`")]
    WordNotFound(String),
}
