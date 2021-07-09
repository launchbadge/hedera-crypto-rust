use thiserror::Error;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("the mnemonic has an invalid checksum.")]
    ChecksumMismatch,

    #[error("legacy 22-word mnemonics do not support passphrases")]
    Passphrase,

    #[error("unsupported phrase length {0}, Only 12 and 24 are supported")]
    UnsupportedLength(usize),

    #[error("word not found in word list: index - {index:?}, word - {word:?}")]
    WordNotFound { index: usize, word: String },
}
