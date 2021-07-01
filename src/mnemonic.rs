use crate::bip39_words::BIP39_WORDS;
use crate::derive;
use crate::entropy;
use crate::key_error::KeyError;
use crate::legacy_words::LEGACY_WORDS;
use crate::mnemonic_error::MnemonicError;
use crate::private_key;
use crate::private_key::to_keypair;
use crate::slip10;
use hmac::Hmac;
use private_key::PrivateKey;
use regex::Regex;
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Eq, PartialEq)]
pub struct Mnemonic {
    words: Vec<String>,
    legacy: bool,
}

#[derive(Debug)]
pub enum LegacyPrivateKeyError {
    WordNotFound(MnemonicError),
    Length(KeyError)
}

impl From<MnemonicError> for LegacyPrivateKeyError {
    fn from(e: MnemonicError) -> Self {
        LegacyPrivateKeyError::WordNotFound(e)
    }
}

impl From<KeyError> for LegacyPrivateKeyError {
    fn from(e: KeyError) -> Self {
        LegacyPrivateKeyError::Length(e)
    }
}

impl Mnemonic {
    /// Returns a new random 12 or 24 word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate(length: usize) -> Result<Mnemonic, MnemonicError> {
        let needed_entropy: usize = match length {
            12 => 16,
            24 => 32,
            _ => return Err(MnemonicError::Length(length)),
        };

        let seed: Vec<u8> = (0..needed_entropy).map(|_| rand::random::<u8>()).collect();

        let entropy_bits = bytes_to_binary(&seed);
        let check_sum_bits = derive_check_sum_bits(&seed);
        let bits = entropy_bits + &check_sum_bits;
        let re = Regex::new(r"(.{1,11})").unwrap();

        let mut chunks: Vec<String> = Vec::new();
        for cap in re.captures_iter(&bits) {
            chunks.push((&cap[1]).to_string());
        }

        if !chunks.is_empty() {
            chunks.clone()
        } else {
            Vec::new()
        };

        let words: Vec<String> = chunks
            .iter()
            .map(|binary| BIP39_WORDS[binary_to_byte(&binary.to_string()) as usize].to_string())
            .collect();

        Ok(Mnemonic {
            words,
            legacy: false,
        })
    }

    /// Returns a new random 12-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_12() -> Result<Mnemonic, MnemonicError> {
        return Mnemonic::generate(12);
    }

    /// Returns a new random 24-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_24() -> Result<Mnemonic, MnemonicError> {
        return Mnemonic::generate(24);
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
    pub fn from_words(words: Vec<String>) -> Result<Mnemonic, MnemonicError> {
        let word_count = words.len();
        let new_mnemonic = Mnemonic {
            words,
            legacy: word_count == 22,
        };

        Ok(new_mnemonic.validate()?)
    }

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
    pub fn to_private_key(&self, passphrase: &str) -> Result<PrivateKey, KeyError> {
        if self.legacy {
            if passphrase.len() > 0 {
                return Err(KeyError::Passphrase);
            }
        }
        Ok(self.passphrase_to_private_key(passphrase)?)
    }

    /// Returns a Menmonic
    ///
    /// # Arguments
    ///
    /// `self` - Current instance of Mnemonic.
    ///
    fn validate(self) -> Result<Self, MnemonicError> {
        if self.legacy {
            if self.words.len() != 22 {
                return Err(MnemonicError::Length(self.words.len()));
            }

            let unknown_word_indices = self
                .words
                .iter()
                .filter_map(|word| match LEGACY_WORDS.binary_search(&&word[..]) {
                    Ok(_) => None,
                    Err(index) => Some(index),
                })
                .collect::<Vec<usize>>();

            if unknown_word_indices.len() > 0 {
                return Err(MnemonicError::UnknownWord);
            }

            let (seed, checksum) = entropy::legacy_1(self.words.clone());
            let new_check_sum = entropy::crc_8(&seed);

            if checksum != new_check_sum {
                return Err(MnemonicError::ChecksumMismatch);
            }
        } else {
            if !(self.words.len() == 12 || self.words.len() == 24) {
                return Err(MnemonicError::Length(self.words.len()));
            }

            let word_list = self.words.iter().map(|x| &x[..]).collect::<Vec<&str>>();

            let unknown_word_indices = self
                .words
                .iter()
                .filter_map(|word| match BIP39_WORDS.binary_search(&&word[..]) {
                    Ok(_) => None,
                    Err(index) => Some(index),
                })
                .collect::<Vec<usize>>();

            if unknown_word_indices.len() > 0 {
                return Err(MnemonicError::UnknownWord);
            }

            let mut bits = String::new();

            for i in 0..word_list.len() {
                for j in 0..BIP39_WORDS.len() {
                    if word_list[i].to_lowercase() == BIP39_WORDS[j] {
                        let temp = format!("{}{:0>11}", bits, format!("{:b}", j));
                        bits = temp;
                    }
                }
            }

            let divider_index = (bits.len() as f64 / 33.0).floor() * 32.0;
            let entropy_bits = &bits[..divider_index as usize];
            let check_sum_bits = &bits[divider_index as usize..];

            let re = Regex::new(r"(.{1,8})").unwrap();

            let mut entropy_bytes = Vec::new();
            for cap in re.captures_iter(&entropy_bits) {
                entropy_bytes.push(binary_to_byte(&cap[1]).to_string().parse::<u8>().unwrap());
            }

            let new_check_sum = derive_check_sum_bits(&entropy_bytes);

            if new_check_sum != check_sum_bits {
                return Err(MnemonicError::ChecksumMismatch);
            }
        }

        Ok(Mnemonic {
            words: self.words,
            legacy: self.legacy,
        })
    }
    // Note: might need different naming; js SDK has two toPrivateKey() functions.
    //       Not sure how to go about this

    /// Private function
    ///
    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `passphrase` - string
    ///
    fn passphrase_to_private_key(&self, passphrase: &str) -> Result<PrivateKey, KeyError> {
        let input = format!("{}", self);
        let salt = format!("mnemonic{}", passphrase);

        let mut seed: [u8; 64] = [0; 64];
        pbkdf2::pbkdf2::<HmacSha512>(input.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        let digest = Sha512::digest(&seed);
        let key_data = &digest[0..32];
        let chain_code = &digest[32..];

        let data = slip10::slip10_derive(key_data, chain_code);

        let new_chain_code = data.1.clone().try_into().unwrap_or_else(|v: Vec<u8>| {
            panic!("Expected a Vec of length {} but it was {}", 32, v.len())
        });

        let keypair = to_keypair(&data.0).unwrap();
        let private_key = PrivateKey {
            keypair,
            chain_code: Some(new_chain_code),
        };

        Ok(private_key)
    }

    /// Returns a Private Key.
    ///
    /// # Arguments
    ///
    /// `&self` - Current instance of Mnemonic.
    //
    pub fn to_legacy_private_key(&self) -> Result<PrivateKey, LegacyPrivateKeyError>{
        let index: i32 = if self.legacy { -1 } else { 0 };

        let seed: Vec<u8> = if self.legacy {
            let result =  entropy::legacy_1(self.words.clone()).0;
            result
        } else {
            let result = entropy::legacy_2(self.words.clone())?;
            result
        };

        let key_data = derive::legacy(&seed, index);
        let private_key = PrivateKey::from_bytes(&key_data)?;

        Ok(private_key)
    }
}

impl FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(mnemonic: &str) -> Result<Self, MnemonicError> {
        let mnem = mnemonic.split(" ");
        let mnem_word_list = mnem.collect::<Vec<&str>>();
        let words: Vec<String> = mnem_word_list.iter().map(|s| s.to_string()).collect();

        Ok(Mnemonic {
            words,
            legacy: false,
        })
    }
}

impl Display for Mnemonic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut comma_separated = String::new();

        for i in &self.words[0..self.words.len() - 1] {
            comma_separated.push_str(&i.to_string());
            comma_separated.push_str(", ");
        }

        comma_separated.push_str(&self.words[self.words.len() - 1].to_string());
        write!(f, "{}", comma_separated)
    }
}

/// Returns a u8
///
/// # Arguments
///
/// `bin` - string
///
pub fn binary_to_byte(bin: &str) -> i32 {
    let binary_to_byte = i32::from_str_radix(bin, 2).unwrap();
    return binary_to_byte;
}

/// Returns a string
///
/// # Arguments
///
/// `bytes` - A list of numners.
///
pub fn bytes_to_binary(bytes: &[u8]) -> String {
    let bytes_to_binary: String = bytes
        .iter()
        .map(|x| format!("{:0>8}", format!("{:b}", x)))
        .collect();

    let pad_string = format!("{:0>8}", bytes_to_binary);

    return pad_string;
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

    let hash = Sha256::digest(entropy_buffer);
    let bin = bytes_to_binary(&hash)[0..cs].to_string();
    return bin;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_generate_12() -> Result<(), MnemonicError> {
        let generate_12 = Mnemonic::generate_12()?;

        assert_eq!(generate_12.words.len(), 12);
        assert_ne!(true, generate_12.legacy);
        Ok(())
    }

    #[test]
    fn test_generate_24() -> Result<(), MnemonicError> {
        let generate_24 = Mnemonic::generate_24()?;

        assert_eq!(generate_24.words.len(), 24);
        assert_ne!(true, generate_24.legacy);
        Ok(())
    }

    #[test]
    fn test_from_string() -> Result<(), MnemonicError> {
        let mnemonic = Mnemonic::from_str(
            "combine quiz usual goddess topple bonus give drive target index love volcano",
        )?;
        assert_eq!(mnemonic.words.len(), 12);
        assert_ne!(true, mnemonic.legacy);
        Ok(())
    }

    #[test]
    fn test_from_words() -> Result<(), MnemonicError> {
        let vec_of_words: Vec<String> = vec![
            "combine".to_string(),
            "quiz".to_string(),
            "usual".to_string(),
            "goddess".to_string(),
            "topple".to_string(),
            "bonus".to_string(),
            "give".to_string(),
            "drive".to_string(),
            "target".to_string(),
            "index".to_string(),
            "love".to_string(),
            "volcano".to_string(),
        ];
        let mnemonic_from_words = Mnemonic::from_words(vec_of_words)?;
        assert_eq!(mnemonic_from_words.words.len(), 12);
        assert_ne!(true, mnemonic_from_words.legacy);
        Ok(())
    }

    #[test]
    fn test_passphrase_to_private_key() -> Result<(), KeyError> {
        let mnem = Mnemonic::generate(12).unwrap();
        let private_key = Mnemonic::passphrase_to_private_key(&mnem, "")?;
        assert_eq!(private_key.to_string().chars().count(), 96);
        Ok(())
    }

    #[test]
    fn test_to_legacy_private_key() -> Result<(), LegacyPrivateKeyError> {
        let mnemonic = Mnemonic::from_str(
            "combine quiz usual goddess topple bonus give drive target index love volcano",
        )
        .unwrap();
        let private_key = Mnemonic::to_legacy_private_key(&mnemonic)?;

        assert_eq!(private_key.to_string(), "302e020100300506032b65700422042059412a6c798fbdad67dd820588135148d7d341920bc8abdeabe8c2269d543101".to_string());
        assert_eq!(private_key.to_string().chars().count(), 96);
        Ok(())
    }

    #[test]
    fn test_to_private_key() -> Result<(), KeyError> {
        let mnemonic = Mnemonic::from_str(
            "combine quiz usual goddess topple bonus give drive target index love volcano",
        )
        .unwrap();
        let private_key = Mnemonic::to_private_key(&mnemonic, "")?;
        assert_eq!(private_key.to_string(), "302e020100300506032b657004220420696e76f750d16a21d11f931e99418f1da9e6078f362b4c7a41f0960714f5df94".to_string());
        assert_eq!(private_key.to_string().chars().count(), 96);
        Ok(())
    }
}
