use crate::bip39_words::BIP39_WORDS;
use crate::derive;
use crate::entropy;
use crate::key_error::KeyError;
use crate::legacy_words::LEGACY_WORDS;
use crate::private_key;
use bip39::{Language, Mnemonic as Bip39Mnemonic};
use math::round;
use pad::{Alignment, PadStr};
use private_key::PrivateKey;
use rand::thread_rng;
use regex::Regex;
use sha2::{Digest, Sha384};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("The mnemonic has an invalid checksum.")]
    CheckSumMismatch,

    #[error("Legacy 22-word mnemonics do not support passphrases")]
    Passphrase,

    #[error("Invalid entropy length: {0}. Only 12 and 24 are supported.")]
    Length(usize),

    #[error("Mnemonic contained words that are not in the standard word list")]
    UnknownWord,

    #[error(transparent)]
    GenerateMnemonic(#[from] bip39::Error),
}

// Mnemonic phrase struct
#[derive(Debug)]
pub struct Mnemonic {
    words: Bip39Mnemonic,
    legacy: bool,
}

impl Mnemonic {
    /// Returns a new random 12 or 24 word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate(length: usize) -> Result<Mnemonic, MnemonicError> {
        let mut rng = thread_rng();

        let words = match length {
            12 | 24 => {
                let words = Bip39Mnemonic::generate_in_with(&mut rng, Language::English, length)
                    .map_err(MnemonicError::GenerateMnemonic)?;
                words
            }
            _ => {
                return Err(MnemonicError::Length(length));
            }
        };

        Ok(Mnemonic {
            words,
            legacy: false,
        })
    }

    /// Returns a new random 12-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_12() -> Result<Mnemonic, MnemonicError> {
        let mnemonic = Mnemonic::generate(12)?;
        Ok(mnemonic)
    }

    /// Returns a new random 24-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_24() -> Result<Mnemonic, MnemonicError> {
        let mnemonic = Mnemonic::generate(24)?;
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
    pub fn from_words(words: Bip39Mnemonic) -> Result<Mnemonic, MnemonicError> {
        let word_count = words.word_count();

        let new_mnemonic = Mnemonic {
            words,
            legacy: word_count == 22,
        };
        let validated_mnemonic = new_mnemonic.validate()?;
        Ok(validated_mnemonic)
    }

    // WIP: Need Private Key Library to finish/ Switch out unwraps()

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
    pub fn to_private_key(&self, passphrase: &str) -> Result<PrivateKey, MnemonicError> {
        if self.legacy {
            if passphrase.len() > 0 {
                return Err(MnemonicError::Length(passphrase.len()));
            }
            return Ok(self.to_legacy_private_key().unwrap());
        }

        // Private to_private_key() function
        // Paceholder Private Key
        Ok(self.passphrase_to_private_key(passphrase).unwrap())
    }

    /// Returns a Menmonic
    ///
    /// # Arguments
    ///
    /// `self` - Current instance of Mnemonic.
    ///
    fn validate(self) -> Result<Self, MnemonicError> {
        if self.legacy {
            if Bip39Mnemonic::word_count(&self.words) != 22 {
                return Err(MnemonicError::Length(Bip39Mnemonic::word_count(
                    &self.words,
                )));
            }

            let mut unknown_word_indices: usize = 0;
            let mnemonic_as_string = format!("{}", self.words);
            let mnem = mnemonic_as_string.split(" ");
            let word_list = mnem.collect::<Vec<&str>>();

            for i in 0..self.words.word_count() {
                for j in 0..LEGACY_WORDS.len() {
                    if word_list[i] == LEGACY_WORDS[j] {
                        unknown_word_indices += 1;
                    }
                }
            }

            if unknown_word_indices > 0 {
                return Err(MnemonicError::UnknownWord);
            }

            let (seed, checksum) = entropy::legacy_1(&self.words);
            let new_check_sum = entropy::crc_8(&seed);

            if checksum != new_check_sum {
                return Err(MnemonicError::CheckSumMismatch);
            }
        } else {
            if !(self.words.word_count() == 12 || self.words.word_count() == 24) {
                return Err(MnemonicError::Length(Bip39Mnemonic::word_count(
                    &self.words,
                )));
            }

            let word_string = format!("{}", self.words);
            let word_list = word_string.split(" ").collect::<Vec<&str>>();

            let mut unknown_indices = Vec::new();

            for i in 0..word_list.len() {
                for j in 0..LEGACY_WORDS.len() {
                    if word_list[i].to_lowercase() == LEGACY_WORDS[j] {
                        println!("{}", word_list[i]);
                        println!("{}", LEGACY_WORDS[j]);
                        unknown_indices.push(i);
                    }
                }
            }

            if unknown_indices.len() > 0 {
                return Err(MnemonicError::UnknownWord);
            }

            let mut bits = String::new();

            for i in 0..word_list.len() {
                for j in 0..BIP39_WORDS.len() {
                    if word_list[i].to_lowercase() == BIP39_WORDS[j] {
                        let temp = format!(
                            "{}{}",
                            bits,
                            j.to_string().pad(11, '0', Alignment::Right, true)
                        );
                        bits = temp;
                    }
                }
            }

            let divider_index = round::floor(bits.len() as f64 / 33.0, 0) * 32.0;

            let entropy_bits = &bits[divider_index as usize..bits.len()];

            let check_sum_bits = &bits[0..divider_index as usize];

            let re = Regex::new(r"(.{1,8})").unwrap();

            let caps = re.captures(entropy_bits).unwrap();

            let match_regex = caps.get(0).map_or("", |m| m.as_str());

            let entropy_bytes = binary_to_byte(match_regex);

            let new_check_sum = derive_check_sum_bits(entropy_bytes);

            if new_check_sum != check_sum_bits {
                return Err(MnemonicError::CheckSumMismatch);
            }
        }

        Ok(Mnemonic {
            words: self.words,
            legacy: self.legacy,
        })
    }

    // WIP: Need Private Key Library to finish
    // Note: needed different naming; received duplication error
    //       from previous to_private_key_function()

    /// Private function
    ///
    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `passphrase` - string
    ///
    fn passphrase_to_private_key(&self, passphrase: &str) -> Result<PrivateKey, MnemonicError> {
        let input = format!("{}", self.words);
        let salt = format!("mnemonic{}", passphrase);

        // let seed;

        // Placeholder Private Key
        let private_key = PrivateKey::generate();
        Ok(private_key)
    }

    // WIP: Finish deriving/returning new private key.
    //      *note - Needs private key function derive to finish
    
    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `&self` - Current instance of Mnemonic.
    //
    pub fn to_legacy_private_key(&self) -> Result<PrivateKey, KeyError> {
        let index: i32 = if self.legacy { -1 } else { 0 };

        let seed: Vec<u8> = if self.legacy {
            let result = entropy::legacy_1(&self.words).0;
            result
        } else {
            // TODO: Change out this unwrap(). Not sure how
            let result = entropy::legacy_2(&self.words).unwrap();
            result
        };

        // TODO: Finish legacy function in derive.rs
        let key_data = derive::legacy(&seed);

        let private_key = PrivateKey::from_bytes(&key_data)?;

        Ok(private_key)
    }
}

impl FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(mnemonic: &str) -> Result<Self, MnemonicError> {
        let mnem = Bip39Mnemonic::from_str(mnemonic).unwrap();
        let new_mnem = Mnemonic::from_words(mnem)?;
        let words = new_mnem.words;

        Ok(Mnemonic {
            words,
            legacy: false,
        })
    }
}

impl Display for Mnemonic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.words)
    }
}

/// Returns a u8
///
/// # Arguments
///
/// `bin` - string
///
pub fn binary_to_byte(bin: &str) -> &[u8] {
    let byte = bin.as_bytes();
    return byte;
}

/// Returns a string
///
/// # Arguments
///
/// `bytes` - A list of numners.
///
pub fn bytes_to_binary(bytes: &[u8]) -> String {
    let mut bytes_to_string = String::new();

    for byte in bytes {
        bytes_to_string = format!(
            "{}{}",
            bytes_to_string,
            byte.to_string().pad(8, '0', Alignment::Right, true)
        );
    }

    return bytes_to_string;
}

/// Returns a string.
///
/// # Arguments
///
/// `entropy_buffer` - Slice of u8 numbers.
///
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
    fn test_generate() -> Result<(), MnemonicError> {
        let generate_test = Mnemonic::generate(12)?;

        println!("Generate Test: {}", generate_test.words);
        assert_eq!(Bip39Mnemonic::word_count(&generate_test.words), 12);
        assert_ne!(true, generate_test.legacy);
        Ok(())
    }

    #[test]
    fn test_generate_12() -> Result<(), MnemonicError> {
        let generate_12 = Mnemonic::generate_12()?;

        assert_eq!(Bip39Mnemonic::word_count(&generate_12.words), 12);
        assert_ne!(true, generate_12.legacy);
        Ok(())
    }

    #[test]
    fn test_generate_24() -> Result<(), MnemonicError> {
        let generate_24 = Mnemonic::generate_24()?;

        assert_eq!(Bip39Mnemonic::word_count(&generate_24.words), 24);
        assert_ne!(true, generate_24.legacy);
        Ok(())
    }

    #[test]
    fn test_from_string() -> Result<(), MnemonicError> {
        let mnem = Mnemonic::generate(12)?;

        // Parse string into list of words
        let mnem_string = format!("{}", mnem);
        let mnem = mnem_string.split(" ");
        let mnem_word_list = mnem.collect::<Vec<&str>>();

        // Should print Mnemonic words
        println!("{}", mnem_string);
        // mnem_word_list should be length of 12
        assert_eq!(mnem_word_list.len(), 12);
        Ok(())
    }

    #[test]
    fn test_binary_to_byte() {
        let test_string = "00000005";
        assert_eq!(
            binary_to_byte(test_string),
            [48, 48, 48, 48, 48, 48, 48, 53]
        );
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

    // WIP: How to test this?
    #[test]
    fn test_from_words() -> Result<(), MnemonicError> {
        let mnem = Mnemonic::generate(12)?;
        let words_test = Mnemonic::from_words(mnem.words)?;
        println!("{:?}", words_test);

        Ok(())
    }

    // WIP: Finish Test
    #[test]
    fn test_passphrase_to_private_key() -> Result<(), MnemonicError> {
        let mnem = Mnemonic::generate(12)?;
        println!("{:?}", Mnemonic::passphrase_to_private_key(&mnem, ""));
        Ok(())
    }

    // WIP: Write test for to_legacy_private_key()
    #[test]
    fn test_to_legacy_private_key() -> Result<(), KeyError> {
        let mnem = Mnemonic::generate_12().unwrap();
        let mnem_to_private_key = Mnemonic::to_legacy_private_key(&mnem)?;
        println!("{:?}", mnem_to_private_key);
        Ok(())
    }

    // TODO: Write test for to_private_key()
    #[test]
    fn test_to_private_key() -> Result<(), MnemonicError> {
        Ok(())
    }
}
