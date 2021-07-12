use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::{fmt, str};

use hmac::{Hmac, Mac, NewMac};
use itertools::Itertools;
use pbkdf2::pbkdf2;
use private_key::PrivateKey;
use sha2::{Digest, Sha256, Sha512};

use crate::bip39_words::BIP39_WORDS;
use crate::key_error::KeyError;
use crate::legacy_words::LEGACY_WORDS;
use crate::bad_mnemonic_error::BadMnemonicError;
use crate::private_key::to_keypair;
use crate::{derive, entropy, private_key, slip10};

#[derive(Debug, Eq, PartialEq)]
pub struct Mnemonic {
    words: Box<[String]>,
    legacy: bool,
}

impl Mnemonic {
    /// Returns a new random 12 or 24 word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate(length: usize) -> Result<Self, BadMnemonicError> {
        let needed_entropy: usize = match length {
            12 => 16,
            24 => 32,

            _ => return Err(BadMnemonicError::BadLength(length)),
        };

        let seed: Vec<u8> = (0..needed_entropy).map(|_| rand::random::<u8>()).collect();

        let entropy_bits = bytes_to_binary(&seed);
        let check_sum_bits = derive_check_sum_bits(&seed);
        let bits = entropy_bits + &check_sum_bits;
        let collect_bits = bits.chars().collect::<Vec<char>>();
        let mut chunks = collect_bits.chunks(11);

        let mut words: Vec<_> = Vec::new();
        for _ in 0..length {
            // UNWRAP: chunks.next() will always give 11 characters
            let word = chunks.next().unwrap().iter().collect::<String>();
            words.push(BIP39_WORDS[binary_to_byte(&word) as usize].to_string())
        }

        Ok(Self { words: words.into_boxed_slice(), legacy: false })
    }

    /// Returns a new random 12-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_12() -> Result<Self, BadMnemonicError> {
        Self::generate(12)
    }

    /// Returns a new random 24-word mnemonic from the BIP-39
    /// standard English word list.
    ///
    pub fn generate_24() -> Result<Self, BadMnemonicError> {
        Self::generate(24)
    }

    // Construct a mnemonic from a list of words. Handles 12, 22 (legacy), and 24 words.
    //
    // An exception of UnknownWord will be thrown if the mnemonic
    // contains unknown words or fails the checksum. An invalid mnemonic
    // can still be used to create private keys, the exception will
    // contain the failing mnemonic in case you wish to ignore the
    // validation error and continue.
    //
    pub fn from_words<I, T>(words: I) -> Result<Self, BadMnemonicError>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let words =
            words.into_iter().map(|word| word.into()).collect::<Vec<_>>().into_boxed_slice();

        let word_count = words.len();
        let new_mnemonic = Self { words, legacy: word_count == 22 };

        new_mnemonic.validate()?;

        Ok(new_mnemonic)
    }

    /// Recover a private key from this mnemonic phrase, with an optional passphrase.
    ///
    pub fn to_private_key(&self, passphrase: &str) -> Result<PrivateKey, KeyError> {
        if self.legacy {
            if passphrase.len() > 0 {
                return Err(KeyError::PassphraseUnsupported);
            }
        }

        Ok(self.passphrase_to_private_key(passphrase)?)
    }

    fn validate(&self) -> Result<(), BadMnemonicError> {
        if self.legacy {
            if self.words.len() != 22 {
                return Err(BadMnemonicError::BadLength(self.words.len()));
            }

            for (word_index, word) in self.words.iter().enumerate() {
                LEGACY_WORDS.binary_search(&&word.to_lowercase()[..]).map_err(|_| {
                    BadMnemonicError::UnknownWords { index: word_index, word: word.to_string() }
                })?;
            }

            let (seed, checksum) = entropy::legacy_1(&*self.words);
            let new_checksum = entropy::crc_8(&seed);
            if checksum != new_checksum {
                return Err(BadMnemonicError::ChecksumMismatch{ words: self.words.to_vec() });
            }
        } else {
            if !(self.words.len() == 12 || self.words.len() == 24) {
                return Err(BadMnemonicError::BadLength(self.words.len()));
            }

            for (word_index, word) in self.words.iter().enumerate() {
                BIP39_WORDS.binary_search(&&word.to_lowercase()[..]).map_err(|_| {
                    BadMnemonicError::UnknownWords { index: word_index, word: word.to_string() }
                })?;
            }

            let mut bits = String::new();

            for i in 0..self.words.len() {
                for j in 0..BIP39_WORDS.len() {
                    if self.words[i].to_lowercase() == BIP39_WORDS[j] {
                        let temp = format!("{}{:0>11}", bits, format!("{:b}", j));
                        bits = temp;
                    }
                }
            }

            let divider_index = (bits.len() as f64 / 33.0).floor() * 32.0;
            let entropy_bits = &bits[..divider_index as usize];
            let checksum_bits = &bits[divider_index as usize..];

            let needed_entropy: usize = if self.words.len() == 12 { 16 } else { 32 };

            let collect_entropy_bits = entropy_bits.chars().collect::<Vec<char>>();
            let mut entropy_chunks = collect_entropy_bits.chunks(8);

            let mut entropy_bytes: Vec<_> = Vec::new();
            for _ in 0..needed_entropy {
                // UNWRAP: chunks.next() will always give 8 characters
                let entropy = entropy_chunks.next().unwrap().iter().collect::<String>();
                entropy_bytes.push(binary_to_byte(&entropy).to_string().parse::<u8>().unwrap());
            }

            let new_checksum = derive_check_sum_bits(&entropy_bytes);

            if new_checksum != checksum_bits {
                return Err(BadMnemonicError::ChecksumMismatch{ words: self.words.to_vec() });
            }
        }

        Ok(())
    }

    fn passphrase_to_private_key(&self, passphrase: &str) -> Result<PrivateKey, KeyError> {
        let input = self.to_string();
        let salt = format!("mnemonic{}", passphrase);

        let mut seed: [u8; 64] = [0; 64];
        pbkdf2::<Hmac<Sha512>>(input.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        let mut mac = Hmac::<Sha512>::new_from_slice(&b"ed25519 seed"[..]).unwrap();
        mac.update(&seed);

        let mut digest = mac.finalize().into_bytes();
        let (key_data, chain_code) = digest.split_at_mut(32);

        for index in [44, 3030, 0, 0] {
            slip10::derive(key_data, chain_code, index);
        }

        let keypair = to_keypair(&key_data).unwrap();

        // UNWRAP: chain code is guaranteed to be 32 bytes
        let private_key =
            PrivateKey { keypair, chain_code: Some(chain_code.as_ref().try_into().unwrap()) };

        Ok(private_key)
    }

    /// Returns a Private Key through legacy mnemonic deriviation.
    ///
    pub fn to_legacy_private_key(&self) -> Result<PrivateKey, KeyError> {
        let index: i32 = if self.legacy { -1 } else { 0 };

        let seed: [u8; 32] = if self.legacy {
            entropy::legacy_1(&*self.words).0
        } else {
            entropy::legacy_2(&*self.words)?
        };

        let key_data = derive::legacy(&seed, index);
        let private_key = PrivateKey::from_bytes(&key_data)?;

        Ok(private_key)
    }
}

impl FromStr for Mnemonic {
    type Err = BadMnemonicError;

    fn from_str(mnemonic: &str) -> Result<Self, BadMnemonicError> {
        Self::from_words(mnemonic.split(&[',', ' '][..]))
    }
}

impl Display for Mnemonic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.words.iter().format(" "))
    }
}

fn binary_to_byte(bin: &str) -> i32 {
    let binary_to_byte = i32::from_str_radix(bin, 2).unwrap();
    return binary_to_byte;
}

fn bytes_to_binary(bytes: &[u8]) -> String {
    let bytes_to_binary: String =
        bytes.iter().map(|x| format!("{:0>8}", format!("{:b}", x))).collect();

    let pad_string = format!("{:0>8}", bytes_to_binary);

    return pad_string;
}

fn derive_check_sum_bits(entropy_buffer: &[u8]) -> String {
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
    fn should_generate_12_words() -> Result<(), BadMnemonicError> {
        let generate_12 = Mnemonic::generate_12()?;

        assert_eq!(generate_12.words.len(), 12);
        assert_ne!(true, generate_12.legacy);
        Ok(())
    }

    #[test]
    fn should_generate_24_words() -> Result<(), BadMnemonicError> {
        let generate_24 = Mnemonic::generate_24()?;

        assert_eq!(generate_24.words.len(), 24);
        assert_ne!(true, generate_24.legacy);
        Ok(())
    }

    #[test]
    fn generate_12_words_from_string() -> Result<(), BadMnemonicError> {
        let m = Mnemonic::from_str(
            "spy,base,tired,useless,rug,riot,ticket,enroll,disorder,kiwi,client,impulse"
        )?;

        assert_eq!(m.words.len(), 12);
        Ok(())
    }

    #[test]
    fn should_detect_an_invalid_checksum() -> Result<(), BadMnemonicError> {
        let mut m = Mnemonic::generate(24)?;
        m.words.swap(0, m.words.len() - 1);

        let expected = BadMnemonicError::ChecksumMismatch { words: m.words.to_vec() };
        let checksum_mismatch = Mnemonic::from_words(m.words.iter()).unwrap_err();
        assert_eq!(checksum_mismatch, expected);

        Ok(())
    }

    #[test]
    fn should_produce_the_expected_private_key() -> Result<(), KeyError> {
        let mnemonic = Mnemonic::from_str(
            "inmate flip alley wear offer often piece magnet surge toddler submit right radio absent pear floor belt raven price stove replace reduce plate home"
        )?;
        
        let expected_key = "302e020100300506032b657004220420853f15aecd22706b105da1d709b4ac05b4906170c2b9c7495dff9af49e1391da";
        let key = mnemonic.to_private_key("")?;
        assert_eq!(key.to_string(), expected_key.to_string());
        Ok(())
    }

    // WIP: Needs fix for legacy derive
    #[test]
    fn should_produce_expected_legacy_private_key() -> Result<(), KeyError> {
        let legacy_mnemonic = Mnemonic::from_str(
            "jolly,kidnap,Tom,lawn,drunk,chick,optic,lust,mutter,mole,bride,galley,dense,member,sage,neural,widow,decide,curb,aboard,margin,manure"
        )?;

        let legacy_to_private_key = legacy_mnemonic.to_private_key("")?;
        let derive_legacy = legacy_to_private_key.derive(-1)?;

        let expected_legacy_key = "302e020100300506032b657004220420882a565ad8cb45643892b5366c1ee1c1ef4a730c5ce821a219ff49b6bf173ddf";

        assert_eq!(derive_legacy.to_string(), expected_legacy_key.to_string());
        assert_eq!(legacy_mnemonic.words.len(), 22);
        Ok(())
    }

    // WIP: Needs fix for legacy derive
    #[test]
    fn legacy2_mnemonic_should_work() -> Result<(), KeyError> {
        let legacy_mnemonic = Mnemonic::from_str(
            "obvious,favorite,remain,caution,remove,laptop,base,vacant,increase,video,erase,pass,sniff,sausage,knock,grid,argue,salt,romance,way,alone,fever,slush,dune"
        )?;

        let legacy_private_key = legacy_mnemonic.to_legacy_private_key()?;

        let expected_legacy_key = "302e020100300506032b6570042204202b7345f302a10c2a6d55bf8b7af40f125ec41d780957826006d30776f0c441fb";

        assert_eq!(legacy_private_key.to_string(), expected_legacy_key.to_string());
        Ok(())
    }

    // WIP: Needs fix for legacy derive
    #[test]
    fn should_match_my_hbar_wallet_v1() -> Result<(), KeyError> {
        let mnemonic = Mnemonic::from_str(
            "jolly kidnap Tom lawn drunk chick optic lust mutter mole bride galley dense member sage neural widow decide curb aboard margin manure"
        )?;

        let root_private_key = mnemonic.to_legacy_private_key()?;
        let private_key_mhw = root_private_key.derive(1099511627775)?;

        assert_eq!(private_key_mhw.public_key().to_string(), "302a300506032b657003210045f3a673984a0b4ee404a1f4404ed058475ecd177729daa042e437702f7791e9".to_string());
        Ok(())
    }

    // WIP: Needs fix for legacy derive
    #[test]
    fn should_match_hedera_keygen_java_for_a_22_word_legacy_phrase() -> Result<(), KeyError> {
        let mnemonic = Mnemonic::from_str(
            "jolly,kidnap,tom,lawn,drunk,chick,optic,lust,mutter,mole,bride,galley,dense,member,sage,neural,widow,decide,curb,aboard,margin,manure"
        )?;

        let root_private_key = mnemonic.to_legacy_private_key()?;
        let private_key_0 = root_private_key.derive(0)?;
        let private_key_neg_1 = root_private_key.derive(-1)?;

        assert_eq!(private_key_0.to_string(), "302e020100300506032b657004220420fae0002d2716ea3a60c9cd05ee3c4bb88723b196341b68a02d20975f9d049dc6");
        assert_eq!(private_key_neg_1.to_string(), "302e020100300506032b657004220420882a565ad8cb45643892b5366c1ee1c1ef4a730c5ce821a219ff49b6bf173ddf");

        Ok(())
    }

    // WIP: Needs fix for legacy derive
    #[test]
    fn should_match_hedera_keygen_java_for_a_24_word_legacy_phrase() -> Result<(), KeyError> {
        let mnemonic = Mnemonic::from_str(
            "obvious,favorite,remain,caution,remove,laptop,base,vacant,increase,video,erase,pass,sniff,sausage,knock,grid,argue,salt,romance,way,alone,fever,slush,dune"
        )?;

        let root_private_key = mnemonic.to_legacy_private_key()?;
        let private_key_0 = root_private_key.derive(0)?;
        let private_key_neg_1 = root_private_key.derive(-1)?;

        assert_eq!(private_key_0.to_string(), "302e020100300506032b6570042204202b7345f302a10c2a6d55bf8b7af40f125ec41d780957826006d30776f0c441fb");
        assert_eq!(private_key_neg_1.to_string(), "302e020100300506032b657004220420caffc03fdb9853e6a91a5b3c57a5c0031d164ce1c464dea88f3114786b5199e5");

        Ok(())
    }
}
