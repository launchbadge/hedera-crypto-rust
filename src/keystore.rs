use ctr::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use hmac::{Hmac, Mac, NewMac};
use rand::Rng;
use serde_json;
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
struct KDFParams {
    #[serde(rename(serialize = "dkLen", deserialize = "dkLen"))]
    dk_len: i32,

    salt: String,
    c: u32,
    prf: Cow<'static, str>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename(serialize = "cipherparams", deserialize = "cipherparams"))]
struct CipherParams {
    iv: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Crypto {
    ciphertext: String,

    #[serde(rename(serialize = "cipherparams", deserialize = "cipherparams"))]
    cipher_params: CipherParams,

    cipher: Cow<'static, str>,
    kdf: Cow<'static, str>,

    #[serde(rename(serialize = "kdfparams", deserialize = "kdfparams"))]
    kdf_params: KDFParams,

    mac: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeyStore {
    version: i32,
    crypto: Crypto,
}

// create keystore
//      returns JSON buffer that is a keystore
impl KeyStore {
    pub fn create_keystore(private_key: &[u8], pass: &str) -> String {
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

        let iv_encoded = hex::encode(iv);

        let keystore = KeyStore {
            version: 1,
            crypto: Crypto {
                ciphertext: hex::encode(buffer),
                cipher_params: CipherParams { iv: iv_encoded },
                cipher: Cow::Borrowed("AES-128-CTR"),
                kdf: Cow::Borrowed("pbkdf2"),
                kdf_params: KDFParams {
                    dk_len: 32,
                    salt: hex::encode(salt),
                    c: 262144,
                    prf: Cow::Borrowed("hmac-sha256"),
                },
                mac: hex::encode((&*code_bytes).to_vec()),
            },
        };
        hex::encode(serde_json::to_string(&keystore).unwrap())
    }

    pub fn load_keystore(keystore: &str, pass: &str) -> String {
        let keystore_decode = hex::decode(&keystore).unwrap();
        let keystore_str = str::from_utf8(&keystore_decode).unwrap();

        let keystore_serde: KeyStore = serde_json::from_str(&keystore_str).unwrap();

        // todo: set up errors
        if keystore_serde.version != 1 {
            panic!("keystore version not supported: {}", keystore_serde.version);
        }

        if keystore_serde.crypto.kdf != *"pbkdf2".to_string() {
            panic!(
                "unsupported key derivation function: {}",
                keystore_serde.crypto.kdf
            );
        }

        if keystore_serde.crypto.kdf_params.prf != *"hmac-sha256" {
            panic!(
                "unsupported key derivation hash function: {}",
                keystore_serde.crypto.kdf_params.prf
            );
        }

        // derive key
        let mut derived_key: [u8; 32] = [0; 32];
        pbkdf2::pbkdf2::<HmacSha256>(
            pass.as_bytes(),
            &(hex::decode(keystore_serde.crypto.kdf_params.salt).unwrap()),
            keystore_serde.crypto.kdf_params.c,
            &mut derived_key,
        );

        // verify mac
        let mut key_buffer = hex::decode(&keystore_serde.crypto.ciphertext).unwrap();

        let mut mac = HmacSha384::new_from_slice(&derived_key[16..derived_key.len()])
            .expect("HMAC can take key of any size");
        mac.update(&key_buffer);

        let mac_decode = hex::decode(keystore_serde.crypto.mac).unwrap();

        // compare two vectors to verify hmac:
        match mac.verify(&mac_decode) {
            Err(h_mac) => panic!("HMAC mismatch; passphrase is incorrect",),
            _ => (),
        }

        // todo: decipher iv
        let iv_decode = hex::decode(keystore_serde.crypto.cipher_params.iv).unwrap();

        // decrypt the cipher
        let mut cipher = Aes128Ctr::new_from_slices(&derived_key[0..16], &iv_decode).unwrap();
        cipher.seek(0);
        cipher.apply_keystream(&mut key_buffer);

        // todo: return keypair based on deciphered iv
        hex::encode(key_buffer)
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::KeyStore;

    #[test]
    fn create_keystore() {
        let hex_string = hex::decode("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10").unwrap();

        let _keystore: String = KeyStore::create_keystore(&hex_string, "hello");

        println!("Test create keystore: ");
        assert_eq!("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10", "302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10");
    }

    #[test]
    fn load_keystore() {
        let p_key = "302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";
        let hex_string = hex::decode(p_key).unwrap();

        let keystore: String = KeyStore::create_keystore(&hex_string, "hello");

        let keystore_2: String = KeyStore::load_keystore(&keystore, "hello");

        println!("Test load_keystore: ");
        assert_eq!(keystore_2, p_key);
    }
}
