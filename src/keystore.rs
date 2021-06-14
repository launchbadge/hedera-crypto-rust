use actix_web::web::Json;
use ctr::cipher::{NewCipher, StreamCipher};
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
pub struct KDFParams {
    #[serde(rename(serialize = "dkLen", deserialize = "dkLen"))]
    dk_len: i32,
    salt: String,
    c: u32,
    prf: Cow<'static, str>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename(serialize = "cipherparams", deserialize = "cipherparams"))]
pub struct CipherParams {
    iv: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Crypto {
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

    pub fn load_keystore(keystore: Json<KeyStore>, _pass: &str) {
        // let keystore_decode = hex::decode(&keystore).unwrap();
        //
        // let keystore_serde = serde_json::from_str(&keystore_decode).unwrap();

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
        // let mut derived_key: [u8; 32] = [0; 32];
        // pbkdf2::pbkdf2::<HmacSha256>(
        //     pass.as_bytes(),
        //     &(hex::decode(keystore.crypto.kdf_params.salt).unwrap()),
        //     keystore.crypto.kdf_params.c,
        //     &mut derived_key,
        // );

        // todo: verify mac

        // todo: decipher iv

        // todo: return keypair based on deciphered iv
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::KeyStore;
    use actix_web::web::Json;
    use std::str;

    #[test]
    fn create_keystore() {
        let mut private_key = [0u8; 32];
        //let hex_string = hex::decode_to_slice("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10", &mut private_key as &mut [u8]);
        let hex_string = hex::decode("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10").unwrap();

        println!("Hex string: ");
        println!("{:?}", hex_string);

        let keystore: String = KeyStore::create_keystore(&hex_string, "hello");
        let keystore_decode = hex::decode(keystore).unwrap();

        println!("My KeyStore: ");
        println!("{:?}", str::from_utf8(&keystore_decode).unwrap());

        let answer_keystore = "7b2276657273696f6e223a312c2263727970746f223a7b2263697068657274657874223a2264376462336136353836346538626261376630343734393764343134656662376361666162303763613434666165336138666266306365623433386238646366222c22636970686572706172616d73223a7b226976223a223930373034363435376230313164313838646233616266646536393463316162227d2c22636970686572223a224145532d3132382d435452222c226b6466223a2270626b646632222c226b6466706172616d73223a7b22646b4c656e223a33322c2273616c74223a2261316461633735366333356631643164626132323236636335383937643864636136333861323734326633393861613835623866376566386337396164376136222c2263223a3236323134342c22707266223a22686d61632d736861323536227d2c226d6163223a22393732646630623361636133333461333731663232653233353539616361366536613632313634633461373263353065346162643839666334346263306466633832356663326536636537636263633538313231356232356364333031393630227d7d";
        let answer_key = hex::decode(answer_keystore).unwrap();
        println!("JS KeyStore: ");
        println!("{:?}", str::from_utf8(&answer_key).unwrap());

        let keystore_2: String = KeyStore::create_keystore(&private_key, "hello");

        println!("Tests: ");
        assert_eq!("302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10", "302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10");
    }


}
