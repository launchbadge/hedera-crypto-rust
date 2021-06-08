use ctr::cipher::{NewCipher, StreamCipher};
use hmac::{Hmac, Mac, NewMac};
use pbkdf2;
use rand::Rng;
use sha2::Sha384;
use serde_json;

// CTR mode implementation is generic over block ciphers
// we will create a type alias for convenience
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

// Create alias for HMAC-SHA256
type HmacSha384 = Hmac<Sha384>;

#[derive(serde::Serialize)]
pub struct KDFParams {
    dk_len: i32,
    salt: [u8; 32],
    c: i32,
    prf: String,
}

#[derive(serde::Serialize)]
pub struct Crypto {
    cipher_text: [u8; 32],
    cipher_params: [u8; 16],
    cipher: String,
    kdf: String,
    kdf_params: KDFParams,
}

#[derive(serde::Serialize)]
pub struct KeyStore {
    version: i32,
    crypto: Crypto,
    mac: Vec<u8>,
}

// create keystore
//      returns JSON String of keystore?
impl KeyStore {
    pub fn create_keystore(private_key: &[u8], pass: &[u8]) -> String {
        let c_iter: u32 = 262144;
        let mut derived_key: [u8; 32] = [0; 32];
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let iv = rand::thread_rng().gen::<[u8; 16]>();

        pbkdf2::pbkdf2::<HmacSha384>(pass, &salt, c_iter, &mut derived_key);

        // AES-128-CTR with the first half of the derived key and a random IV
        let mut cipher = Aes128Ctr::new_from_slices(&derived_key[0..16], &iv).unwrap();
        let mut buffer = [0u8; 32];

        // copy message to the buffer
        let pos = private_key.len();
        buffer[..pos].copy_from_slice(private_key);
        // let cipher_text = cipher.encrypt(&mut buffer, pos).unwrap();
        cipher.apply_keystream(&mut buffer);

        let mut mac = HmacSha384::new_from_slice(&derived_key[16..derived_key.len()])
            .expect("HMAC can take key of any size");
        mac.update(&buffer);

        // get auth code in bytes
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        let keystore = KeyStore {
            version: 1,
            crypto: Crypto {
                cipher_text: buffer,
                cipher_params: iv,
                cipher: "AES-128-CTR".to_string(),
                kdf: "pbkdf2".to_string(),
                kdf_params: KDFParams {
                    dk_len: 32,
                    salt: salt,
                    c: 262144,
                    prf: "hmac-sha256".to_string(),
                },
            },
            mac: (&*code_bytes).to_vec(),
        };
        serde_json::to_string(&keystore).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::KeyStore;

    #[test]
    fn create_keystore() {
        let private_key: &[u8] = &[
            -37 as u8, 72 as u8, 75 as u8, -126 as u8, -114 as u8, 100 as u8, -78 as u8, -40 as u8,
            -15 as u8, 44 as u8, -29 as u8, -64 as u8, -96 as u8, -23 as u8, 58 as u8, 11 as u8,
            -116 as u8, -50 as u8, 122 as u8, -15 as u8, -69 as u8, -113 as u8, 57 as u8,
            -55 as u8, 119 as u8, 50 as u8, 57 as u8, 68 as u8, -126 as u8, 83 as u8, -114 as u8,
            16 as u8,
        ];

        //let keystore = KeyStore::create_keystore(private_key, format!("hello"));

        //assert_eq!(&private_key.to_bytes(), keystore);
    }
}
