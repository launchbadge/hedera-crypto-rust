use crate::bip39_words::BIP39_WORDS;
use crate::legacy_words::LEGACY_WORDS;
use crate::mnemonic_error::MnemonicError;
use num_bigint::ToBigInt;
use rand::AsByteSliceMut;
use sha2::{Digest, Sha256};

/// Returns a result as a Vec<u8>, and a u8 checksum
///
/// # Arguments
///
/// `words` - List of Mnemonic words.
///
pub fn legacy_1(words: Vec<String>) -> (Vec<u8>, u8) {
    let mut indices = words
        .iter()
        .filter_map(|word| LEGACY_WORDS.binary_search(&&word[..]).ok())
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

    let mut result = Vec::new();

    for _ in (0..33).rev() {
        let tem = &num / to_radix;
        let rem = num % to_radix;
        num = tem;
        result.push(rem.to_string().parse::<u8>().unwrap());
    }
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
pub fn legacy_2(words: Vec<String>) -> Result<Vec<u8>, MnemonicError> {
    let concat_bits_len = words.len() * 11;

    let mut concat_bits = vec![false; words.len() * 11];

    for (word_index, word) in words.iter().enumerate() {
        let index = BIP39_WORDS
            .binary_search(&&word.to_lowercase()[..])
            .map_err(|_| MnemonicError::WordNotFound(word.to_string()))?;

        for j in 0..11 {
            concat_bits[word_index * 11 + j] = index & (1 << (10 - j)) != 0;
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

    let hash = Sha256::digest(&entropy);
    let hash_bits = bytes_to_bits(&hash);

    for i in 0..check_sum_bits_len as usize {
        if concat_bits[entropy_bits_len as usize + i] != hash_bits[i] {
            return Err(MnemonicError::ChecksumMismatch);
        }
    }
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

    for i in 0..data.len() {
        crc ^= data[i];

        for _ in 0..8 {
            crc = if ((crc >> 1) ^ (crc & 1)) == 0 {
                0
            } else {
                0xb2
            };
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
    let mut bits = vec![false; data.len() * 8];

    for i in 0..data.len() {
        for j in 0..8 {
            bits[i * 8 + j] = data[i] & (1 << (7 - j)) != 0;
        }
    }

    return bits;
}
