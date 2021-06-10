use actix_web::web::Json;
use ctr::cipher::{NewCipher, StreamCipher};
use hmac::{Hmac, Mac, NewMac};
use rand::Rng;
use sha2::{Sha256, Sha384};
use std::borrow::Cow;
use std::str;

// CTR mode implementation is generic over block ciphers
// we will create a type alias for convenience
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

// Create alias for HMAC-SHA256
type HmacSha384 = Hmac<Sha384>;
type HmacSha256 = Hmac<Sha256>;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KDFParams {
    dk_len: i32,
    salt: [u8; 32],
    c: u32,
    prf: Cow<'static, str>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Crypto {
    cipher_text: Vec<u8>,
    cipher_params: [u8; 16],
    cipher: Cow<'static, str>,
    kdf: Cow<'static, str>,
    kdf_params: KDFParams,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeyStore {
    version: i32,
    crypto: Crypto,
    mac: Vec<u8>,
}

// create keystore
//      returns JSON buffer that is a keystore
impl KeyStore {
    pub fn create_keystore(private_key: &[u8], pass: &str) -> KeyStore {
        let c_iter: u32 = 262144;
        let mut derived_key: [u8; 32] = [0; 32];
        let pk_len = private_key.len();
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let iv = rand::thread_rng().gen::<[u8; 16]>();

        pbkdf2::pbkdf2::<HmacSha256>(pass.as_bytes(), &salt, c_iter, &mut derived_key);

        // AES-128-CTR with the first half of the derived key and a random IV
        let mut cipher = Aes128Ctr::new_from_slices(&derived_key[0..16], &iv).unwrap();
        let mut buffer = vec![0u8; pk_len];

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
                cipher: Cow::Borrowed("AES-128-CTR"),
                kdf: Cow::Borrowed("pbkdf2"),
                kdf_params: KDFParams {
                    dk_len: 32,
                    salt,
                    c: 262144,
                    prf: Cow::Borrowed("hmac-sha256"),
                },
            },
            mac: (&*code_bytes).to_vec(),
        };
        keystore
    }

    pub fn load_keystore(keystore: Json<KeyStore>, pass: &str) {
        // todo: set up errors
        if keystore.version != 1 {
            panic!("keystore version not supported: {}", keystore.version);
        }

        if keystore.crypto.kdf != *"pbkdf2".to_string() {
            panic!(
                "unsupported key derivation function: {}",
                keystore.crypto.kdf
            );
        }

        if keystore.crypto.kdf_params.prf != *"hmac-sha256" {
            panic!(
                "unsupported key derivation hash function: {}",
                keystore.crypto.kdf_params.prf
            );
        }

        // todo: derive key
        let mut derived_key: [u8; 32] = [0; 32];
        pbkdf2::pbkdf2::<HmacSha256>(
            pass.as_bytes(),
            &keystore.crypto.kdf_params.salt,
            keystore.crypto.kdf_params.c,
            &mut derived_key,
        );

        // todo: verify mac

        // todo: decipher iv

        // todo: return keypair based on deciphered iv
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::KeyStore;
    use actix_web::web::Json;

    #[test]
    fn create_keystore() {
        let mut private_key = [0u8; 32];
        let hex_string = hex::decode_to_slice("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10", &mut private_key as &mut [u8]);

        let keystore: KeyStore = KeyStore::create_keystore(&private_key, "hello");

        println!("hello hello hello {:?}", keystore.crypto.kdf_params.salt);

        let serialized_keystore = serde_json::to_string(&keystore).unwrap();
        println!("{}", serialized_keystore);

        assert_eq!(keystore.version, 1);
    }
}
