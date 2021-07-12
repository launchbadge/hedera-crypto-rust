use std::convert::TryInto;

use num_bigint::ToBigInt;
use sha2::{Digest, Sha256};

use crate::bip39_words::BIP39_WORDS;
use crate::legacy_words::LEGACY_WORDS;
use crate::bad_mnemonic_error::BadMnemonicError;

pub fn legacy_1(words: &[String]) -> ([u8; 32], u8) {
    let indices = words
        .into_iter()
        .filter_map(|word| LEGACY_WORDS.binary_search(&&word.to_lowercase()[..]).ok())
        .collect::<Vec<_>>();
    let data = convert_radix(&indices, LEGACY_WORDS.len() as u16, 256);
    let checksum = data[data.len() - 1];

    let mut result = Vec::new();
    for i in 0..data.len() - 1 {
        result.push(data[i] ^ checksum);
    }
    return (result.try_into().unwrap(), checksum);
}

pub fn legacy_2(words: &[String]) -> Result<[u8; 32], BadMnemonicError> {
    let concat_bits_len = words.len() * 11;
    let mut concat_bits = vec![false; words.len() * 11];

    for (word_index, word) in words.iter().enumerate() {
        let index = BIP39_WORDS.binary_search(&&word.to_lowercase()[..]).map_err(|_| {
            BadMnemonicError::UnknownWords { index: word_index, word: word.to_string() }
        })?;

        for j in 0..11 {
            concat_bits[word_index * 11 + j] = index & (1 << (10 - j)) != 0;
        }
    }

    let check_sum_bits_len = concat_bits_len as u8 / 33;
    let entropy_bits_len = concat_bits_len as u8 - check_sum_bits_len;
    let mut entropy = vec![0; 32];

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
            return Err(BadMnemonicError::ChecksumMismatch{ words: words.to_vec() });
        }
    }
    return Ok(entropy.try_into().unwrap());
}

pub fn convert_radix(nums: &[usize], from_radix: u16, to_radix: u16) -> [u8; 33] {
    let mut num = 0.to_bigint().unwrap();
    for i in nums {
        num = num * from_radix;
        num = num + i;
    }

    let mut result: [u8; 33] = [0; 33];

    for i in (0..33).rev() {
        let tem = &num / to_radix;
        let rem = num % to_radix;
        num = tem;
        result[i] = rem.to_string().parse::<u8>().unwrap();
    }

    return result;
}

pub fn crc_8(data: &[u8]) -> u8 {
    let mut crc = 0xff;
    for i in 0..data.len() - 1 {
        crc ^= data[i];
        for _ in 0..8 {
            crc = (crc >> 1) ^ (if crc & 1 == 0 { 0 } else { 0xb2 });
        }
    }
    return crc ^ 0xff;
}

pub fn bytes_to_bits(data: &[u8]) -> Vec<bool> {
    let mut bits = vec![false; data.len() * 8];

    for i in 0..data.len() {
        for j in 0..8 {
            bits[i * 8 + j] = data[i] & (1 << (7 - j)) != 0;
        }
    }

    return bits;
}
