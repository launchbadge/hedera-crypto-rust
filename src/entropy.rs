use crate::bip39_words::BIP39_WORDS;
use crate::legacy_words::LEGACY_WORDS;
use bip39::Mnemonic as Bip39Mnemonic;
use num_bigint::ToBigInt;
use rand::AsByteSliceMut;
use sha2::Digest;
use sha2::Sha384;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntropyError {
    #[error("Word not found in word list: `{0}`")]
    WordNotFound(String),

    #[error("Checksum Mismatch")]
    ChecksumMismatch,
}

// UTIL FUNCTIONS

/// Returns a result as a Vec<u8>, and a u8 checksum
///
/// # Arguments
///
/// `words` - List of Mnemonic words.
///
pub fn legacy_1(words: &Bip39Mnemonic) -> (Vec<u8>, u8) {
    let mut indices = words
        .word_iter()
        .filter_map(|word| LEGACY_WORDS.binary_search(&word).ok())
        .collect::<Vec<usize>>();

    let legacy_length = LEGACY_WORDS.len() as u16;

    let data = convert_radix(indices.as_byte_slice_mut(), legacy_length, 256);

    let checksum = data[data.len() - 1];

    let result = data[0..data.len() - 1]
        .iter()
        .map(|data| (data ^ checksum) as u8)
        .collect::<Vec<u8>>();

    return (result, checksum);
}

/// Returns Vec<u8>
///
/// # Arguments
///
/// `nums` - Slice of u8 numbers.
///
/// `from_radix` - u16 number.
///
/// `to_radix` - u16 number.
///
pub fn convert_radix(nums: &[u8], from_radix: u16, to_radix: u16) -> Vec<u8> {
    let mut num = 0.to_bigint().unwrap();

    for i in nums {
        num = num * from_radix;
        num = num + i;
    }

    let to_length = 32;

    let result = (0..to_length).iter().rev().map(|value| {
        num = &num / to_radix;
        num % to_radix;
    }).rev().collect::<Vec<u8>>();
    return result;
}

/// Returns vector of u8 numbers.
///
/// # Arguments
///
/// `word` - List of strings.
///
/// `word_list` - List of strings.
///
pub fn legacy_2(words: &Bip39Mnemonic) -> Result<Vec<u8>, EntropyError> {
    let concat_bits_len = words.word_count() * 11;
    let mut concat_bits = Vec::new();

    for _ in 0..concat_bits_len {
        concat_bits.push(false)
    }

    let word_string = format!("{}", words);
    let word_list = word_string.split(" ").collect::<Vec<&str>>();

    let mut word_entries = HashMap::new();

    let mut i = 0;

    // Insert word_entries as key value pairs => (index, word)
    while i < word_list.len() {
        word_entries.insert(i, format!("{}", word_list[i]));

        i += 1;

        if i >= word_list.len() {
            break;
        }
    }

    for (word_index, word) in &word_entries {
        let index = BIP39_WORDS
            .iter()
            .position(|&index| index == word.to_lowercase())
            .unwrap();

        if index <= 0 {
            return Err(EntropyError::WordNotFound(word.to_string()));
        }

        let mut j = 0;

        while j < 11 {
            concat_bits[word_index * 11 + j] = index & (1 << (10 - j)) != 0;

            j += 1;

            if j > 11 {
                break;
            }
        }
    }

    let check_sum_bits_len = concat_bits_len as u8 / 33;
    let entropy_bits_len = concat_bits_len as u8 - check_sum_bits_len;
    let mut entropy = vec![0; entropy_bits_len as usize / 8];

    for i in 0..entropy.len() {
        for j in 0..8 {
            if concat_bits[i * 8 + j] {
                entropy[i] |= 1 << (7 - j);
            }
        }
    }

    let hash = Sha384::digest(&entropy);
    let hash_bits = bytes_to_bits(&hash);

    for i in 0..check_sum_bits_len as usize {
        if concat_bits[entropy_bits_len as usize + i] != hash_bits[i] {
            return Err(EntropyError::ChecksumMismatch);
        }
    }

    // TODO: Remove println when done w/ testing
    println!("{:?}", entropy);
    return Ok(entropy);
}

/// Returns u8 number.
///
/// # Arguments
///
/// `data` - Slice of u8 numbers.
///
pub fn crc_8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xff;

    let mut i = 0;

    while i < data.len() {
        crc ^= data[i];

        let mut j = 0;

        while j < 8 {
            if ((crc >> 1) ^ (crc & 1)) == 0 {
                0;
            } else {
                0xb2;
            }

            j += 1;

            if j >= 8 {
                break;
            }
        }

        i += 1;

        if i >= data.len() {
            break;
        }
    }
    return crc ^ 0xff;
}

/// Returns a list of Booleans.
///
/// # Arguments
///
/// `data` - Slice of u8 numbers
///
pub fn bytes_to_bits(data: &[u8]) -> Vec<bool> {
    let concat_bits_len = data.len() * 8;
    let mut bits = Vec::new();

    for _ in 0..concat_bits_len {
        bits.push(false)
    }

    for i in 0..data.len() {
        for j in 0..8 {
            bits[i * 8 + j] = data[i] & (1 << (7 - j)) != 0;
        }
    }

    return bits;
}
