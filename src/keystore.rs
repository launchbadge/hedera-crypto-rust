//use keystore;
use ed25519_dalek::Keypair;
use hex;
use pbkdf2;
use rand::Rng;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    //fn test_keystore_read() { assert_eq!(keystore.read(""), format!("PrivateKey")); }
}

// constants
const HMAC_SHA256 : String = "hmac-sha256";

//todo define special types

// create keystore
impl KeyStore {

    pub async fn createKeystore(privateKey : u8, String : pass) {
        const dkLen : i32 = 32;
        const c : i32 = 262144;
        const saltLen : i32 = 32;
        let salt = rand::thread_rng().gen::<[u8; dkLen]>().await;

        let key = pbkdf2.deriveKey(
            hmac.HashAlgorithm.Sha256,
            passphrase,
            salt,
            c,
            dkLen
        ).await;

        let iv = rand::thread_rng().gen::<[u8; 16]>().await;

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
}

