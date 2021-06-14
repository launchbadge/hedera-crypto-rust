use crate::key_error::KeyError;
use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::{thread_rng, Rng};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::FromStr;

const DER_PREFIX: &str = "302e020100300506032b657004220420";

#[derive(Debug)]
/// A private key on the Hedera™ Network
pub struct PrivateKey {
    keypair: Keypair,
    chain_code: Option<[u8; 32]>,
}
impl PrivateKey {
    pub fn generate() -> PrivateKey {
        let mut entropy = [0u8; 64];
        thread_rng().fill(&mut entropy[..]);
        let secret_key = SecretKey::from_bytes(&entropy[0..32]).unwrap();

        PrivateKey {
            keypair: Keypair {
                public: (&secret_key).into(),
                secret: secret_key,
            },
            chain_code: Some(<[u8; 32]>::try_from(&entropy[32..64]).unwrap()),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<PrivateKey, KeyError> {
        let der_prefix_bytes = hex::decode("302e020100300506032b657004220420").unwrap();
        let private_key = match data.len() {
            32 => {
                let secret_key = SecretKey::from_bytes(&data).map_err(KeyError::Signature)?;
                let private_key = PrivateKey {
                    keypair: Keypair {
                        public: (&secret_key).into(),
                        secret: secret_key,
                    },
                    chain_code: None,
                };
                private_key
            }
            48 if data.starts_with(&der_prefix_bytes) => {
                let secret_key = SecretKey::from_bytes(&data[16..]).map_err(KeyError::Signature)?;
                let private_key = PrivateKey {
                    keypair: Keypair {
                        public: (&secret_key).into(),
                        secret: secret_key,
                    },
                    chain_code: None,
                };
                private_key
            }
            64 => {
                let secret_key = SecretKey::from_bytes(&data[..SECRET_KEY_LENGTH])
                    .map_err(KeyError::Signature)?;
                let private_key = PrivateKey {
                    keypair: Keypair {
                        public: (&secret_key).into(),
                        secret: secret_key,
                    },
                    chain_code: None,
                };
                private_key
            }
            _ => {
                return Err(KeyError::Length(data.len()));
            }
        };
        Ok(private_key)
    }
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.keypair.secret.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let signature: Signature = self.keypair.sign(message);
        let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
        signature_bytes
    }
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.keypair.secret.to_bytes() == other.keypair.secret.to_bytes()
    }
}
impl Eq for PrivateKey {}
impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}",
            DER_PREFIX,
            hex::encode(self.keypair.secret.to_bytes())
        )
    }
}
impl FromStr for PrivateKey {
    type Err = KeyError;
    fn from_str(text: &str) -> Result<Self, KeyError> {
        let decoded_private_key = hex::decode(&text).unwrap();
        let private_key = PrivateKey::from_bytes(&decoded_private_key)?;
        Ok(private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyError, PrivateKey, Signature, Signer, SIGNATURE_LENGTH};
    use rand::{thread_rng, Rng};
    use std::str::FromStr;

    const PRIVATE_KEY_STR: &str = "302e020100300506032b657004220420db484b828e64b2d8f12ce3c0a0e93a0b8cce7af1bb8f39c97732394482538e10";

    #[test]
    fn test_generate() -> Result<(), KeyError> {
        let private_key = PrivateKey::generate();
        assert_eq!(private_key.keypair.secret.to_bytes().len(), 32 as usize);
        Ok(())
    }
    #[test]
    fn test_from_bytes() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_str(PRIVATE_KEY_STR)?;
        assert_eq!(
            PrivateKey::from_bytes(&private_key.keypair.secret.to_bytes())?,
            private_key
        );
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
            PrivateKey::public_key(&private_key),
            private_key.keypair.public
        );
        Ok(())
    }
    #[test]
    fn test_from_str() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_str(PRIVATE_KEY_STR)?;
        let key_string = private_key.to_string();
        assert_eq!(
            PrivateKey::from_str(&key_string)?.to_string(),
            private_key.to_string()
        );
        Ok(())
    }
    #[test]
    fn test_to_string() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_str(PRIVATE_KEY_STR)?;
        let key_string = private_key.to_string();
        assert_eq!(
            PrivateKey::from_str(&key_string)?.to_string(),
            private_key.to_string()
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
}
