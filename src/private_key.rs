use ed25519_dalek::{
    ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature, Signer,
    SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rand_core::OsRng;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::FromStr;
use thiserror::Error;

const DER_PREFIX: &str = "302e020100300506032b657004220420";
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid private key length: {0}")]
    Length(usize),
    #[error(transparent)]
    Signature(#[from] ed25519_dalek::SignatureError),
}

#[derive(Debug)]
/// A Private Key on the Hedera™ Network
pub struct PrivateKey(SecretKey, Option<[u8;32]>);

impl PrivateKey {
    pub fn generate() -> PrivateKey {
        let mut csprng = OsRng {};
        let mut array = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut array);
        let chain_code = rand_core::OsRng.next_32();

        let keypair = Keypair::generate(&mut csprng);
        //fix: should be alphanumeric
        PrivateKey(keypair.secret, chain_code)
    }

    pub fn from_bytes(data: &[u8]) -> Result<PrivateKey, KeyError> {
        let der_prefix_bytes = hex::decode("302e020100300506032b657004220420").unwrap();
        let private_key = match data.len() {
            32 => {
                let private_key =
                    PrivateKey(SecretKey::from_bytes(&data).map_err(KeyError::Signature)?, None);
                private_key
            }
            48 if data.starts_with(&der_prefix_bytes) => {
                let private_key =
                    PrivateKey(SecretKey::from_bytes(&data[16..47]).map_err(KeyError::Signature)?, None);

                private_key
            }
            64 => {
                let private_key = PrivateKey(SecretKey::from_bytes(&data[..SECRET_KEY_LENGTH])?, None);
                private_key
            }
            _ => {
                return Err(KeyError::Length(data.len()));
            }
        };
        Ok(private_key)
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let public_key: PublicKey = (&self.0).into();
        let expanded_private = ExpandedSecretKey::from(&self.0);
        let signature: Signature = expanded_private.sign(message, &public_key);
        let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
        signature_bytes
    }

    pub fn public_key(&self) -> PublicKey {
        let public_key: PublicKey = (&self.0).into();
        public_key
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for PrivateKey {}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}{}", DER_PREFIX, hex::encode(self.0.to_bytes()))
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
    use super::{KeyError, Keypair, PrivateKey, Signature, Signer, SIGNATURE_LENGTH};
    use ed25519_dalek::{SecretKey, SECRET_KEY_LENGTH};
    use rand::{rngs::OsRng, RngCore};
    use rand_core::{OsRng};
    use std::str::FromStr;

    const PRIVATE_KEY_BYTES: &[u8; SECRET_KEY_LENGTH] = &[
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    #[test]
    fn test_from_bytes_32() -> Result<(), KeyError> {
        let private_key = PrivateKey(SecretKey::from_bytes(PRIVATE_KEY_BYTES)?, None);

        assert_eq!(&private_key.to_bytes(), PRIVATE_KEY_BYTES);

        Ok(())
    }

    #[test]
    fn test_from_bytes_48() -> Result<(), KeyError> {
        let string= "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let no_der_str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

        let private_bytes = string.as_bytes();
        let secret_bytes = no_der_str.as_bytes();

        let private_key = PrivateKey::from_bytes(private_bytes)?;
        let secret_key = PrivateKey::from_bytes(secret_bytes)?;

        assert_eq!(private_key, secret_key);
        Ok(())
    }

    #[test]
    fn test_to_bytes() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_bytes(PRIVATE_KEY_BYTES)?;

        assert_eq!(&PrivateKey::to_bytes(&private_key), PRIVATE_KEY_BYTES);

        Ok(())
    }

    #[test]
    fn test_public_key() -> Result<(), KeyError> {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        let secret_to_bytes = keypair.secret.to_bytes();
        let private_from_bytes = PrivateKey::from_bytes(&secret_to_bytes);
        let private_to_bytes = PrivateKey::to_bytes(&private_from_bytes?);
        let private_from_bytes_2 = PrivateKey::from_bytes(&private_to_bytes);

        assert_eq!(
            PrivateKey::public_key(&private_from_bytes_2?),
            keypair.public
        );

        Ok(())
    }

    #[test]
    fn test_from_str() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_bytes(PRIVATE_KEY_BYTES)?;

        let key_string = private_key.to_string();

        assert_eq!(PrivateKey::from_str(&key_string)?, private_key);

        Ok(())
    }

    #[test]
    fn test_to_string() -> Result<(), KeyError> {
        let private_key = PrivateKey::from_bytes(PRIVATE_KEY_BYTES)?;
        let private_str= "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

        assert_eq!(format!("{}", private_key), private_key.to_string());

        Ok(())
    }

    #[test]
    fn test_sign() -> Result<(), KeyError> {
        let mut csprng = rand::rngs::OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let message: &[u8] = b"This is a test";
        let signature: Signature = keypair.sign(message);
        let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();

        assert_eq!(
            PrivateKey::sign(&PrivateKey(keypair.secret, None), message),
            signature_bytes
        );

        Ok(())
    }
}
