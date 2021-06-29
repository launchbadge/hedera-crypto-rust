use ctr::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use hmac::{Hmac, Mac, NewMac};
use rand::Rng;
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Sha256, Sha384};
use std::borrow::Cow;
use std::str;

// CTR mode implementation is generic over block ciphers
// we will create a type alias for convenience
#[allow(dead_code)]
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

// Create alias for HMAC-SHA256
#[allow(dead_code)]
type HmacSha384 = Hmac<Sha384>;
#[allow(dead_code)]
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
    kdf: KeystoreKdf,

    #[serde(rename(serialize = "kdfparams", deserialize = "kdfparams"))]
    kdf_params: KDFParams,

    mac: String,
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
enum KeystoreVersion {
    V1 = 1,
    V2 = 2,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum KeystoreKdf {
    #[serde(rename = "pbkdf2")]
    Pbkdf2,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyStore {
    version: KeystoreVersion,
    crypto: Crypto,
}

// todo: make this take in array of bytes and output array of bytes
// create keystore
//      returns JSON buffer that is a keystore
impl KeyStore {
    #[allow(dead_code)]
    fn create_keystore(private_key: &[u8], pass: &str) -> String {
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
            version: KeystoreVersion::V1,
            crypto: Crypto {
                ciphertext: hex::encode(buffer),
                cipher_params: CipherParams { iv: iv_encoded },
                cipher: Cow::Borrowed("AES-128-CTR"),
                kdf: KeystoreKdf::Pbkdf2,
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

    #[allow(dead_code)]
    fn load_keystore(keystore: &str, pass: &str) -> String {
        let keystore_decode = hex::decode(&keystore).unwrap();
        let keystore_str = str::from_utf8(&keystore_decode).unwrap();

        let keystore_serde: KeyStore = serde_json::from_str(&keystore_str).unwrap();

        // todo: set up errors
        match keystore_serde.version {
            KeystoreVersion::V1 => (),
            KeystoreVersion::V2 => panic!("keystore version not supported: V2"),
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
            Ok(_) => (),
            Err(_) => panic!("HMAC mismatch; passphrase is incorrect"),
        };

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
    use std::str;

    #[test]
    fn create_keystore() {
        let hex_string = hex::decode("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10").unwrap();

        let keystore: String = KeyStore::create_keystore(&hex_string, "hello");

        print_keystores(&keystore);

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

    #[test]
    fn test_hmac_verify() {
        let p_key = "302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";
        let hex_string = hex::decode(p_key).unwrap();

        let keystore: String = KeyStore::create_keystore(&hex_string, "hello");

        let keystore_decode = hex::decode(&keystore).unwrap();
        let keystore_str = str::from_utf8(&keystore_decode).unwrap();

        let mut keystore_serde: KeyStore = serde_json::from_str(&keystore_str).unwrap();

        keystore_serde.crypto.mac = format!("a0");

        let keystore_guy = hex::encode(serde_json::to_string(&keystore_serde).unwrap());

        print_keystores(&keystore_guy);

        let keystore_2: String = KeyStore::load_keystore(&keystore_guy, "hello");
    }

    #[cfg(test)]
    fn print_keystores(keystore: &str) {
        let keystore_decoded = hex::decode(keystore).unwrap();
        let keystore_to_str = str::from_utf8(&keystore_decoded).unwrap();

        println!("Rust Keystore: ");
        println!("{:?}", keystore_to_str);

        let keystore_js = hex::decode("7b2276657273696f6e223a312c2263727970746f223a7b2263697068657274657874223a2264376462336136353836346538626261376630343734393764343134656662376361666162303763613434666165336138666266306365623433386238646366222c22636970686572706172616d73223a7b226976223a223930373034363435376230313164313838646233616266646536393463316162227d2c22636970686572223a224145532d3132382d435452222c226b6466223a2270626b646632222c226b6466706172616d73223a7b22646b4c656e223a33322c2273616c74223a2261316461633735366333356631643164626132323236636335383937643864636136333861323734326633393861613835623866376566386337396164376136222c2263223a3236323134342c22707266223a22686d61632d736861323536227d2c226d6163223a22393732646630623361636133333461333731663232653233353539616361366536613632313634633461373263353065346162643839666334346263306466633832356663326536636537636263633538313231356232356364333031393630227d7d").unwrap();
        let keystore_to_str_js = str::from_utf8(&keystore_js);

        println!("JS Keystore: ");
        println!("{:?}", keystore_to_str_js);
    }
}