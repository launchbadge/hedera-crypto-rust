use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::Rng;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;
use sha2::Sha384;
use hmac::{Hmac, Mac, NewMac};

// to generate key
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

// to generate cipher text
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha384>;

pub struct KeyStore();

// create keystore
//      returns JSON String of keystore?
impl KeyStore {
    pub async fn create_keystore(private_key: &[u8], pass: &[u8]) {
        let c_iter: NonZeroU32 = std::num::NonZeroU32::new(262144).unwrap();
        let mut derived_key: Credential = [0u8; CREDENTIAL_LEN];
        let salt = rand::thread_rng().gen::<[u8; 32]>();

        ring::pbkdf2::derive(PBKDF2_ALG, c_iter, &salt, &pass, &mut derived_key);

        let iv = rand::thread_rng().gen::<[u8; 16]>();

        // AES-128-CTR with the first half of the derived key and a random IV
        let cipher = Aes128Cbc::new_from_slices(&derived_key[0..16], &iv).unwrap();
        let mut buffer = [0u8; 32];

        // copy message to the buffer
        let pos = private_key.len();
        buffer[..pos].copy_from_slice(private_key);
        let cipher_text = cipher.encrypt(&mut buffer, pos).unwrap();

        // step 1: encode derived_key[16 .. derived_key.len()] and cipher_text

        // step 2: run the HMAC functions

        let mut mac = HmacSha384::new_from_slice(derived_key[16 .. derived_key.len()])
            .expect("HMAC can take key of any size");
        mac.update(cipher_text);

        let result = mac.finalize();

        // const mac = hmac.hash(
        //     hmac.HashAlgorithm.Sha384,
        //     key.slice(16),
        //     cipherText
        // );
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::KeyStore;

    #[test]
    fn create_keystore() {
        let private_key: &[u8] = &[
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];

        //let keystore = KeyStore::create_keystore(private_key, format!("hello"));

        //assert_eq!(&private_key.to_bytes(), keystore);
    }
}
