use std::str::FromStr;

use bip39::{Language, Mnemonic};
use pad::{Alignment, PadStr};
use rand;
use sha2::{Digest, Sha384};
use thiserror::Error;

use crate::legacy_words::LEGACY_WORDS;

#[derive(Debug, Error)]
pub enum MnemError {
    #[error("Legacy 22-word mnemonics do not support passphrases")]
    Passphrase,

    #[error("Invalid entropy length: {0}. Only 12 and 24 are supported.")]
    Length(usize),

    #[error(transparent)]
    MnemonicError(#[from] bip39::Error),
}

// Mnemonic phrase struct
#[derive(Debug)]
pub struct MnemonicWords {
    pub props_words: Mnemonic,
    pub props_legacy: bool,
}

/// Returns a Mnemonic.
///
/// # Arguments
///
/// * `length` - usize length of menwmonic word list (Entropy Length). Only
///              supports lengths of 12 and 24.
///
impl MnemonicWords {
    pub fn generate(length: usize) -> Result<MnemonicWords, MnemError> {
        let mut rng = rand::thread_rng();

        let words = match length {
            12 | 24 => {
                let words = Mnemonic::generate_in_with(&mut rng, Language::English, length)
                    .map_err(MnemError::MnemonicError)?;
                words
            }
            _ => {
                return Err(MnemError::Length(length));
            }
        };

        Ok(MnemonicWords {
            props_words: words,
            props_legacy: false,
        })
    }

    /// Returns a new random 12-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_12() -> Result<MnemonicWords, MnemError> {
        let mnemonic = MnemonicWords::generate(12)?;
        Ok(mnemonic)
    }

    /// Returns a new random 24-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_24() -> Result<MnemonicWords, MnemError> {
        let mnemonic = MnemonicWords::generate(24)?;
        Ok(mnemonic)
    }

    // Construct a mnemonic from a list of words. Handles 12, 22 (legacy), and 24 words.
    //
    // An exception of UnknownWord will be thrown if the mnemonic
    // contains unknown words or fails the checksum. An invalid mnemonic
    // can still be used to create private keys, the exception will
    // contain the failing mnemonic in case you wish to ignore the
    // validation error and continue.
    //
    // Returns Mnemonic
    //
    // # Arguments
    //
    // * `words` - List of strings
    //
    pub fn from_words(word_list: Mnemonic) -> Result<MnemonicWords, MnemError> {
        let word_count = word_list.word_count();

        Ok(MnemonicWords {
            props_words: word_list,
            props_legacy: word_count == 22,
        }) // TODO: Connect to validate()
    }

    // TODO: Need Private Key Library to finish

    /// Recover a private key from this mnemonic phrase, with an optional passphrase.
    ///
    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `&self` - Instance of that current Mnemonic.
    ///
    /// `passphrase` - a string
    ///
    // pub fn to_private_key(&self, passphrase: &str) -> Result<PrivateKey, MmenError>{
    //     if self.props_legacy {
    //         if passphrase.len() > 0 {
    //             return Err(MnemError::Passphrase);
    //         }
    //         return self.to_legacy_private_key();
    //     }
    //     // Private to_private_key() function
    //     return this._to_private_key(passphrase);
    // }

    /// Recover a mnemonic phrase from a string, splitting on spaces.
    /// Handles 12, 22(Legacy), and 24 words.
    ///
    /// Returns Mnemonic.
    ///
    /// # Arguments
    ///
    /// `mnemonic` - a Mnemonic string.
    //
    pub fn from_string(mnemonic: &str) -> Result<MnemonicWords, MnemError> {
        let mnem = Mnemonic::from_str(mnemonic).unwrap();

        let new_mnem = MnemonicWords::from_words(mnem)?;
        Ok(MnemonicWords {
            props_words: new_mnem.props_words,
            props_legacy: false,
        })
    }

    // TODO: Finish Validate

    /// Returns a Menmonic
    ///
    /// # Arguments
    ///
    /// `&self` - Current instance of Mnemonic.
    ///
    pub fn validate(&self) -> Result<&MnemonicWords, MnemError> {
        if self.props_legacy {
            if Mnemonic::word_count(&self.props_words) != 22 {
                return Err(MnemError::Length(Mnemonic::word_count(&self.props_words)));
            }

            let unknown_word_indices: usize = 0;
            // TODO: Figure out how to access indeces of prop_words and compare
            //       with indeces of LEGACY_WORDS to get unknown_word_count

            // for j in 0..LEGACY_WORDS.len() {
            //     if self.props_words.contains(LEGACY_WORDS[j]) {
            //         unknown_word_indices += 1;
            //     }

            // }
        } else {
            if !(self.props_words.word_count() == 12 || self.props_words.word_count() == 24) {
                return Err(MnemError::Length(Mnemonic::word_count(&self.props_words)));
            }
            // TODO: a lot
        }

        Ok(self)
    }

    // TODO: Need Private Key Library to finish

    /// Private function
    ///
    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `passphrase` - string
    ///
    fn _to_private_key() {}

    // TODO: Need Private Key Library to finish

    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `&self` - Current instance of Mnemonic.
    ///
    pub fn to_legacy_private_key(&self) {}
}

/// Returns a u8
///
/// # Arguments
///
/// `bin` - string
///
pub fn binary_to_byte(bin: &str) -> u16 {
    let byte: u16 = bin.parse().unwrap();
    return byte;
}

/// Returns a string
///
/// # Arguments
///
/// `bytes` - A list of numners.
///
pub fn bytes_to_binary(bytes: &[u8]) -> String {
    let mut bytes_to_string: String = "".to_string();

    for byte in bytes {
        bytes_to_string = format!(
            "{}{}",
            bytes_to_string,
            byte.to_string().pad(8, '0', Alignment::Right, true)
        );
    }

    return bytes_to_string;
}

pub fn derive_check_sum_bits(entropy_buffer: &[u8]) -> String {
    let ent = entropy_buffer.len() * 8;
    let cs = ent / 32;

    let hash = Sha384::digest(entropy_buffer);

    let get_binary = bytes_to_binary(&hash);

    return (&get_binary[cs..ent]).to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() -> Result<(), MnemError> {
        // Can't really test generate because it'll alwats be random,
        // but can test props legacy to make sure we get false

        // Maybe there's a way, I dunno
        let generate_test = MnemonicWords::generate(12)?;
        // Outputs Menmonic list of words
        println!("Generate Test: {}", generate_test.props_words);

        assert_ne!(true, generate_test.props_legacy);
        Ok(())
    }

    #[test]
    fn test_generate_12() -> Result<(), MnemError> {
        let generate_12 = MnemonicWords::generate_12()?;

        assert_eq!(Mnemonic::word_count(&generate_12.props_words), 12);
        assert_ne!(true, generate_12.props_legacy);
        Ok(())
    }

    #[test]
    fn test_generate_24() -> Result<(), MnemError> {
        let generate_24 = MnemonicWords::generate_24()?;

        assert_eq!(Mnemonic::word_count(&generate_24.props_words), 24);
        assert_ne!(true, generate_24.props_legacy);
        Ok(())
    }

    // TODO: Finish test
    #[test]
    fn test_from_words() -> Result<(), MnemError> {
        //let words =
        &["hidden dry document virtual squeeze grace daring orphan fancy link size remember"];

        Ok(())
    }

    // TODO: Finish test
    #[test]
    fn test_from_string() -> Result<(), MnemError> {
        let test = "yellow wedding ugly planet awkward trumpet virus spend rather net bamboo burst";
        println!("{:?}", MnemonicWords::from_string(test));
        Ok(())
    }

    // TODO: Finish test
    #[test]
    fn test_validate() -> Result<(), MnemError> {
        Ok(())
    }

    #[test]
    fn test_binary_to_byte() {
        let test_string = "00000005";
        assert_eq!(binary_to_byte(test_string), 5);
    }

    #[test]
    fn test_bytes_to_binary() {
        let test_nums: &[u8] = &[5, 7, 7, 4, 43, 43, 3, 3];
        assert_eq!(
            bytes_to_binary(test_nums),
            "0000000500000007000000070000000400000043000000430000000300000003".to_string()
        )
    }

    #[test]
    fn test_check_sum_bits() {
        let test = derive_check_sum_bits(&[5, 7, 7, 4, 43, 43, 3, 3]);
        assert_eq!(
            test,
            "00002700000089000000170000017400000150000001470000007000000207".to_string()
        )
    }
}
