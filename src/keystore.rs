use std::borrow::Cow;
use std::str;

use aes::Aes128Ctr;
use cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use hmac::{Hmac, Mac, NewMac};
use rand::Rng;
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Sha256, Sha384};

use crate::keystore_error::KeystoreError;
use crate::private_key::PrivateKey;
use crate::KeyError;

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

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
enum KeystoreVersion {
    V1 = 1,
}

// FIXME: KeyStore vs KeystoreVersion
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyStore {
    version: KeystoreVersion,
    crypto: Crypto,
}

// create keystore
//      returns an array that has an encoded serde KeyStore struct
fn create_keystore(private_key: &[u8], pass: &str) -> Result<Vec<u8>, KeystoreError> {
    let c_iter: u32 = 262144;
    let mut derived_key: [u8; 32] = [0; 32];
    let pk_len = private_key.len();
    let salt = rand::thread_rng().gen::<[u8; 32]>();
    let iv = rand::thread_rng().gen::<[u8; 16]>();

    // this line takes a hefty 5 seconds to run. yikes.
    pbkdf2::pbkdf2::<Hmac<Sha256>>(pass.as_bytes(), &salt, c_iter, &mut derived_key);

    // AES-128-CTR with the first half of the derived key and a random IV
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[0..16], &iv)?;
    let mut buffer = vec![0u8; pk_len];

    // copy message to the buffer
    let pos = private_key.len();
    buffer[..pos].copy_from_slice(private_key);
    // let cipher_text = cipher.encrypt(&mut buffer, pos).unwrap();
    cipher.apply_keystream(&mut buffer);

    let mut mac = Hmac::<Sha384>::new_from_slice(&derived_key[16..derived_key.len()])
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

    let keystore_encode_str = serde_json::to_string(&keystore)?;

    Ok(keystore_encode_str.into_bytes())
}

fn load_keystore(data: &[u8], passphrase: &str) -> Result<Vec<u8>, KeystoreError> {
    let keystore: KeyStore = serde_json::from_slice(&data)?;

    if keystore.crypto.kdf != "pbkdf2" {
        return Err(KeystoreError::UnsupportedKeyDerivationFunction(
            keystore.crypto.kdf.to_string(),
        ));
    }

    if keystore.crypto.kdf_params.prf != "hmac-sha256" {
        return Err(KeystoreError::UnsupportedHashFunction(
            keystore.crypto.kdf_params.prf.to_string(),
        ));
    }

    let salt = hex::decode(keystore.crypto.kdf_params.salt)?;

    // derive key
    let mut derived_key: [u8; 32] = [0; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        passphrase.as_bytes(),
        &salt,
        keystore.crypto.kdf_params.c,
        &mut derived_key,
    );

    // verify mac
    let mut key_buffer = hex::decode(&keystore.crypto.ciphertext)?;

    let mut mac = Hmac::<Sha384>::new_from_slice(&derived_key[16..derived_key.len()]).unwrap();
    mac.update(&key_buffer);

    let mac_decode = hex::decode(keystore.crypto.mac)?;

    // compare two vectors to verify hmac:
    mac.verify(&mac_decode)?;

    let iv_decode = hex::decode(keystore.crypto.cipher_params.iv)?;

    // decrypt the cipher
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[0..16], &iv_decode)?;
    cipher.seek(0);
    cipher.apply_keystream(&mut key_buffer);

    Ok(key_buffer)
}

impl PrivateKey {
    pub fn from_keystore(keystore: &[u8], passphrase: &str) -> Result<PrivateKey, KeyError> {
        PrivateKey::from_bytes(&load_keystore(keystore, passphrase)?)
    }

    pub fn to_keystore(&self, passphrase: &str) -> Result<Vec<u8>, KeyError> {
        Ok(create_keystore(self.keypair.secret.as_bytes(), passphrase)?)
    }
}

#[cfg(test)]
mod tests {
    use std::str;

    use crate::keystore;
    use crate::keystore::KeyStore;
    use crate::private_key::PrivateKey;

    #[test]
    fn load_keystore() {
        let p_key = "db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";
        let hex_string = hex::decode(p_key).unwrap();

        let keystore = keystore::create_keystore(&hex_string, "hello").unwrap();
        let keypair = keystore::load_keystore(&keystore, "hello").unwrap();

        let keystore_2_str = hex::encode(keypair);

        assert_eq!(p_key, keystore_2_str);
    }

    #[test]
    fn to_from_keystore() {
        let private_key = PrivateKey::generate();

        let keystore = PrivateKey::to_keystore(&private_key, "pass1").unwrap();
        let p_key_pair = PrivateKey::from_keystore(&keystore, "pass1").unwrap();

        assert_eq!(private_key.to_bytes(), p_key_pair.to_bytes());
    }

    #[test]
    fn wrong_pass_keystore() {
        let private_key = PrivateKey::generate();

        let keystore = PrivateKey::to_keystore(&private_key, "pass1").unwrap();
        let p_key_pair = PrivateKey::from_keystore(&keystore, "pass2");

        let check_pass = match p_key_pair {
            Ok(_) => false,
            Err(_) => true,
        };

        assert!(check_pass);
    }

    #[test]
    fn test_hmac_verify() {
        let p_key = "db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";
        let hex_string = hex::decode(p_key).unwrap();

        let keystore = keystore::create_keystore(&hex_string, "hello").unwrap();

        // let keystore_decode = hex::decode(&keystore).unwrap();
        let keystore_str = str::from_utf8(&keystore).unwrap();

        let mut keystore_serde: KeyStore = serde_json::from_str(&keystore_str).unwrap();

        keystore_serde.crypto.mac = format!("a0");

        let keystore_guy = serde_json::to_string(&keystore_serde).unwrap().into_bytes();

        print_keystores(&keystore_guy);

        let keystore_2 = keystore::load_keystore(&keystore_guy, "hello");

        let check_hmac = match keystore_2 {
            Ok(_) => false,
            Err(_) => true,
        };

        assert!(check_hmac);
    }

    #[test]
    fn js_keystore_to_pkey() {
        let keystore_js = hex::decode("7b2276657273696f6e223a312c2263727970746f223a7b2263697068657274657874223a2264376462336136353836346538626261376630343734393764343134656662376361666162303763613434666165336138666266306365623433386238646366222c22636970686572706172616d73223a7b226976223a223930373034363435376230313164313838646233616266646536393463316162227d2c22636970686572223a224145532d3132382d435452222c226b6466223a2270626b646632222c226b6466706172616d73223a7b22646b4c656e223a33322c2273616c74223a2261316461633735366333356631643164626132323236636335383937643864636136333861323734326633393861613835623866376566386337396164376136222c2263223a3236323134342c22707266223a22686d61632d736861323536227d2c226d6163223a22393732646630623361636133333461333731663232653233353539616361366536613632313634633461373263353065346162643839666334346263306466633832356663326536636537636263633538313231356232356364333031393630227d7d").unwrap();
        let p_key_js = "db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";
        let hex_string = hex::decode(p_key_js).unwrap();

        let p_key = PrivateKey::from_keystore(&keystore_js, "hello").unwrap();

        assert_eq!(hex_string, p_key.to_bytes());
    }

    #[cfg(test)]
    fn print_keystores(keystore: &[u8]) {
        // let keystore_decoded = hex::decode(keystore).unwrap();
        let keystore_to_str = str::from_utf8(&keystore).unwrap();

        println!("Rust Keystore: ");
        println!("{:?}", keystore_to_str);

        let keystore_js = hex::decode("7b2276657273696f6e223a312c2263727970746f223a7b2263697068657274657874223a2264376462336136353836346538626261376630343734393764343134656662376361666162303763613434666165336138666266306365623433386238646366222c22636970686572706172616d73223a7b226976223a223930373034363435376230313164313838646233616266646536393463316162227d2c22636970686572223a224145532d3132382d435452222c226b6466223a2270626b646632222c226b6466706172616d73223a7b22646b4c656e223a33322c2273616c74223a2261316461633735366333356631643164626132323236636335383937643864636136333861323734326633393861613835623866376566386337396164376136222c2263223a3236323134342c22707266223a22686d61632d736861323536227d2c226d6163223a22393732646630623361636133333461333731663232653233353539616361366536613632313634633461373263353065346162643839666334346263306466633832356663326536636537636263633538313231356232356364333031393630227d7d").unwrap();
        let keystore_to_str_js = str::from_utf8(&keystore_js);

        println!("JS Keystore: ");
        println!("{:?}", keystore_to_str_js);
    }
}
