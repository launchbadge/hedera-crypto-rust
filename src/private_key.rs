use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::hash::Hasher;
use std::str;
use std::str::FromStr;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use once_cell::sync::Lazy;
use openssl::{rsa::Rsa, pkey::PKey};
use openssl::symm::{Cipher, encrypt};
use rand::{thread_rng, Rng};
use pkcs8::{PrivateKeyDocument, PrivateKeyInfo, EncryptedPrivateKeyDocument, AlgorithmIdentifier};
use const_oid::ObjectIdentifier;

use crate::Mnemonic;
use crate::key_error::KeyError;
use crate::slip10::derive;
use crate::mnemonic::Mnemonic;
use openssl::error::ErrorStack;

const DER_PREFIX: &str = "302e020100300506032b657004220420";
const DER_PREFIX_BYTES: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(DER_PREFIX).unwrap());
const DER_ALGORITHM: &[u8] = [06,09,2B,06,01,04,01,DA,47]

/// A private key on the Hedera™ Network
#[derive(Debug)]
pub struct PrivateKey {
    pub(crate) keypair: Keypair,
    pub(crate) chain_code: Option<[u8; 32]>,
}

pub(crate) fn to_keypair(entropy: &[u8]) -> Result<Keypair, KeyError> {
    let secret = SecretKey::from_bytes(&entropy[0..32]).map_err(KeyError::Signature)?;

    Ok(Keypair {
        public: PublicKey::from(&secret),
        secret,
    })
}

impl PrivateKey {
    pub fn generate() -> Self {
        let mut entropy = [0u8; 64];
        thread_rng().fill(&mut entropy[..]);

        Self {
            keypair: to_keypair(&entropy[0..32]).unwrap(),
            chain_code: Some(<[u8; 32]>::try_from(&entropy[32..64]).unwrap()),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        match data.len() {
            32 => Ok(Self {
                keypair: to_keypair(&data)?,
                chain_code: None,
            }),

            48 if data.starts_with(&DER_PREFIX_BYTES) => Ok(Self {
                keypair: to_keypair(&data[16..])?,
                chain_code: None,
            }),

            64 => Ok(Self {
                keypair: to_keypair(&data[..SECRET_KEY_LENGTH])?,
                chain_code: None,
            }),

            _ => Err(KeyError::Length(data.len())),
        }
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.keypair.secret.to_bytes()
    }

    /// Sign a message with this private key.
    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.keypair.sign(data).to_bytes()
    }

    /// Get the public key associated with this private key.
    ///
    /// The public key can be freely given and used by other parties
    /// to verify the signatures generated by this private key.
    ///
    pub fn public_key(&self) -> crate::PublicKey {
        crate::PublicKey(self.keypair.public)
    }

    /// Derive a new private key at the given wallet index.
    ///
    /// Only currently supported for keys created with `fromMnemonic()`; other keys will throw
    /// an error.
    ///
    /// Returns a Private Key
    ///
    pub fn derive(&self, index: u32) -> Result<Self, KeyError> {
        if self.chain_code == None {
            Err(KeyError::DeriveError(index))
        } else {
            let (key_data, chain_code) = derive(
                &self.keypair.secret.to_bytes(),
                &self.chain_code.unwrap(),
                index,
            );

            let key_pair = to_keypair(&key_data[..SECRET_KEY_LENGTH]);

            Ok(Self {
                keypair: key_pair?,
                chain_code: Some(<[u8; 32]>::try_from(chain_code).unwrap()),
            })
        }
    }
        

    pub fn is_derivable(&self) -> bool {
        self.chain_code != None
    } 

    pub fn from_mnemonic(mnemonic: Mnemonic, passphrase: &str) -> Result<PrivateKey, KeyError> {
        Mnemonic::to_private_key(&mnemonic, passphrase)?
    }

    pub fn from_mnemonic(mnemonic: Mnemonic, passphrase: &str) -> Result<PrivateKey, MnemonicError> {
        println!("from mnemonic");
        Mnemonic::to_private_key(&mnemonic, passphrase)
    }

    //Add file support for pem
    //
    pub fn from_pem(data: &str, passphrase: &str) -> Result<PrivateKey, KeyError> {
        if passphrase.len() > 0 {
            let meh = EncryptedPrivateKeyDocument::from_pem(&data).unwrap();
            let private_doc = EncryptedPrivateKeyDocument::decrypt(&meh, passphrase).unwrap();
            Self::from_bytes(private_doc.as_ref())
        } else {
            let private_doc = PrivateKeyDocument::from_pem(&data).unwrap();
            Self::from_bytes(private_doc.as_ref())
        }
    }

    pub fn to_pem(&self, passphrase: &str) -> Result<Vec<u8>, KeyError> {
        let priv_info = PrivateKeyInfo::new(,&Self::to_bytes(self));
        if passphrase.len() > 0 {
            Ok(key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())?)
        } else {
            Ok(key.private_key_to_pem_pkcs8()?)
        }
    }

    // pub fn from_keystore(keystore_bytes: &[u8]) -> PrivateKey {
    //     let load_keystore = keystore_bytes.load_keystore();
    // }

}

impl Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keypair.secret.as_bytes().hash(state)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.keypair.secret.as_bytes() == other.keypair.secret.as_bytes()
    }
}

impl Eq for PrivateKey {}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.keypair.secret.as_bytes()
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}{}", DER_PREFIX, hex::encode(self))
    }
}

impl FromStr for PrivateKey {
    type Err = KeyError;

    fn from_str(text: &str) -> Result<Self, KeyError> {
        Ok(PrivateKey::from_bytes(&hex::decode(&text)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyError, PrivateKey};
    use ed25519_dalek::{Signature, Signer, SIGNATURE_LENGTH};
    use rand::{thread_rng, Rng};
    use std::str::FromStr;
    use crate::Mnemonic;
    use openssl::pkey::PKey;

    const PRIVATE_KEY_STR: &str = "302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";
    const PRIVATE_KEY_BYTES: &[u8] = &[
        37,
        72,
        75,
        126,
        114,
        100,
        78,
        40,
        15,
        44,
        29,
        64,
        96,
        23,
        58,
        11,
        116,
        50,
        122,
        15,
        69,
        113,
        57,
        55,
        119,
        50,
        57,
        68,
        126,
        83,
        114,
        16
    ];
    const IOS_MNEMONIC_WALLET: &str = 
        "tiny denial casual grass skull spare awkward indoor ethics dash enough flavor good daughter early hard rug staff capable swallow raise flavor empty angle";

    const IOS_WALLET_PRIV_KEY: &str = 
        "5f66a51931e8c99089472e0d70516b6272b94dd772b967f8221e1077f966dbda2b60cf7ee8cf10ecd5a076bffad9a7c7b97df370ad758c0f1dd4ef738e04ceb6";

    const ENCRYPTED_PEM: &str =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n
            MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAi8WY7Gy2tThQICCAAw
            DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEOq46NPss58chbjUn20NoK0EQG1x
            R88hIXcWDOECttPTNlMXWJt7Wufm1YwBibrxmCq1QykIyTYhy1TZMyxyPxlYW6aV
            9hlo4YEh3uEaCmfJzWM=
        \n-----END ENCRYPTED PRIVATE KEY-----";

    const PEM_PASSPHRASE: &str = "this is a passphrase";

    #[test]
    fn test_generate() -> Result<(), KeyError> {
        let private_key = PrivateKey::generate();

        assert_eq!(private_key.keypair.secret.to_bytes().len(), 32 as usize);

        Ok(())
    }

    #[test]
    fn test_from_str() -> Result<(), KeyError> {
        let key = PrivateKey::from_str(&PRIVATE_KEY_STR)?;

        assert_eq!(&key.to_bytes(), PRIVATE_KEY_BYTES);

        Ok(())
    }

    #[test]
    fn test_to_bytes() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_str(PRIVATE_KEY_STR)?;
        assert_eq!(
            &PrivateKey::to_bytes(&private_key),
            &private_key.keypair.secret.to_bytes()
        );

        Ok(())
    }

    #[test]
    fn test_public_key() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_str(PRIVATE_KEY_STR)?;

        assert_eq!(
            PrivateKey::public_key(&private_key).0,
            private_key.keypair.public
        );

        Ok(())
    }

    #[test]
    fn test_to_from_string() -> Result<(), KeyError> {
        assert_eq!(
            PrivateKey::from_str(PRIVATE_KEY_STR)?.to_string(),
            PRIVATE_KEY_STR
        );

        Ok(())
    }

    #[test]
    fn test_sign() -> Result<(), KeyError> {
        let mut entropy = [0u8; 64];
        thread_rng().fill(&mut entropy[..]);
        let key = PrivateKey::from_bytes(&entropy[..32])?;
        let message: &[u8] = b"This is a test";
        let signature: Signature = key.keypair.sign(message);
        let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();

        assert_eq!(PrivateKey::sign(&key, message), signature_bytes);

        Ok(())
    }

    #[test]
    fn test_from_pem() -> Result<(), KeyError> {
        let key = PrivateKey::from_pem(ENCRYPTED_PEM, PEM_PASSPHRASE)?;
        assert_eq!(key.to_string(), PRIVATE_KEY_STR);

        Ok(())
    }

    #[test]
    fn test_to_encrypted_pem() -> Result<(), KeyError> {
        let pem: &[u8] = &PrivateKey::to_pem(PEM_PASSPHRASE)?;
        let pkey = PKey::private_key_from_pem(pem)?;
        Ok(())
    }

    #[test]
    fn test_derive() -> Result<(), KeyError> {
        let ios_wallet_key_bytes = hex::decode(IOS_WALLET_PRIV_KEY).unwrap();
        let ios_mnemonic = Mnemonic::from_str(IOS_MNEMONIC_WALLET);
        let ios_key = PrivateKey::from_mnemonic(ios_mnemonic.unwrap(), "");
        let ios_child_key = PrivateKey::derive(&ios_key, 0)?;

        assert_eq!(ios_child_key.to_bytes().to_vec(), ios_wallet_key_bytes);
        
        Ok(())
    }

    // const iosMnemonic = await Mnemonic.fromString(iosWalletMnemonic);
    // const iosKey = await PrivateKey.fromMnemonic(iosMnemonic, "");
    // const iosChildKey = await iosKey.derive(0);
}
