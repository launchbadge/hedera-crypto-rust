//use ed25519_dalek::Keypair;
//use hex;
use rand::Rng;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

// constants
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

pub struct KeyStore();

// create keystore
// returns JSON String of keystore?
impl KeyStore {
    pub async fn create_keystore(_private_key: &[u8], pass: &[u8]) {
        let c_iter: NonZeroU32 = std::num::NonZeroU32::new(262144).unwrap();
        let mut dk_len: Credential = [0u8; CREDENTIAL_LEN];
        let salt = rand::thread_rng().gen::<[u8; 32]>();

        let key = ring::pbkdf2::derive(PBKDF2_ALG, c_iter, &salt, &pass, &mut dk_len);

        let iv = rand::thread_rng().gen::<[u8; 16]>();

        // creates cipher initialization vector
        // const cipherText = crypto.createCipheriv(
        //     crypto.CipherAlgorithm.Aes128Ctr,
        //     key.slice(0, 16),
        //     iv,
        //     privateKey
        // ).await();

        // const mac = hmac.hash(
        //     hmac.HashAlgorithm.Sha384,
        //     key.slice(16),
        //     cipherText
        // );
    }

    //pub async fn derive_key(algorithm, password : &[u8], )
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
