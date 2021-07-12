use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BadMnemonicError {
    #[error("checksum byte in mnemonic did not match the rest of the mnemonic\n mnemonic: {words:?}")]
    ChecksumMismatch{ words: Vec<String> },

    #[error("unsupported phrase length {0}, Only 12 and 24 are supported")]
    BadLength(usize),

    #[error("word not found in word list: index - {index:?}, word - {word:?}")]
    UnknownWords { index: usize, word: String },
}
