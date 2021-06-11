use crate::key_error::KeyError;
use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer,
    SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::FromStr;
use rand::Rng;

const DER_PREFIX: &str = "302e020100300506032b657004220420";

#[derive(Debug)]
/// A private key on the Hedera™ Network
pub struct PrivateKey {
    keypair: Keypair,
    chain_code: Option<[u8; 32]>,
}
impl PrivateKey {
    pub fn generate() -> PrivateKey {
        let random_bytes = rand::thread_rng().gen::<[u8; 64]>();
        let secret_key =  SecretKey::from_bytes(&random_bytes[..SECRET_KEY_LENGTH]).map_err(KeyError::Signature)?;

        PrivateKey {
            keypair: Keypair{secret: secret_key, public: (&secret_key).into()},
            chain_code: Some(random_bytes&[32..]),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<PrivateKey, KeyError> {
        let der_prefix_bytes = hex::decode("302e020100300506032b657004220420").unwrap();
        let private_key = match data.len() {
            32 => {
                let secret_key =  SecretKey::from_bytes(&data).map_err(KeyError::Signature)?;
                let private_key = PrivateKey {
                    keypair: Keypair{secret: secret_key, public: (&secret_key).into()},
                    chain_code: None,
                };
                private_key
            }
            48 if data.starts_with(&der_prefix_bytes) => {
                let secret_key =  SecretKey::from_bytes(&data[der_prefix_bytes..]).map_err(KeyError::Signature)?;
                let private_key = PrivateKey {
                    keypair: Keypair{secret: secret_key, public: (&secret_key).into()},
                    chain_code: None,
                };
                private_key
            }
            64 => {
                let secret_key =  SecretKey::from_bytes(&data[..SECRET_KEY_LENGTH]).map_err(KeyError::Signature)?;
                let private_key = PrivateKey {
                    keypair: Keypair{secret: secret_key, public: (&secret_key).into()},
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
        self.0.to_bytes()
    }
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let message: &[u8] = b"This is a test";
        let secret_key = SecretKey::from_bytes(&self.0);
        let keypair = Keypair{secret: secret_key, public: (&secret_key).into()};
        let signature: Signature = keypair.sign(message);
        let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
        signature_bytes
    }
    pub fn public_key(&self) -> PublicKey {
        (&self.public).into()
    }
}
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
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
// #[cfg(test)]
// mod tests {
//     use super::{KeyError, Keypair, PrivateKey, Signature, Signer, SIGNATURE_LENGTH};
//     use ed25519_dalek::{SecretKey, SECRET_KEY_LENGTH};
//     use rand::rngs::OsRng;
//     use std::str::FromStr;
//     const PRIVATE_KEY_BYTES: &[u8; SECRET_KEY_LENGTH] = &[
//         -37, 72, 75, -126, -114, 100, -78, -40, -15, 44, -29, -64, -96, -23, 58, 11, -116, -50,
//         122, -15, -69, -113, 57, -55, 119, 50, 57, 68, -126, 83, -114, 16,
//     ];
//     #[test]
//     fn test_generate() -> Result<(), KeyError> {
//         let private_key = PrivateKey::generate();
//         assert_eq!(private_key.0.to_bytes().len(), 32 as usize);
//         Ok(())
//     }
//     #[test]
//     fn test_from_bytes() -> Result<(), KeyError> {
//         let private_key = PrivateKey(SecretKey::from_bytes(PRIVATE_KEY_BYTES)?, None);
//         assert_eq!(&private_key.0.to_bytes(), PRIVATE_KEY_BYTES);
//         Ok(())
//     }
//     #[test]
//     fn test_to_bytes() -> Result<(), KeyError> {
//         let private_key = PrivateKey::from_bytes(PRIVATE_KEY_BYTES)?;
//         assert_eq!(&PrivateKey::to_bytes(&private_key), PRIVATE_KEY_BYTES);
//         Ok(())
//     }
//     #[test]
//     fn test_public_key() -> Result<(), KeyError> {
//         let mut csprng = OsRng {};
//         let keypair = Keypair::generate(&mut csprng);
//         let secret_to_bytes = keypair.secret.to_bytes();
//         let private_from_bytes = PrivateKey::from_bytes(&secret_to_bytes);
//         let private_to_bytes = PrivateKey::to_bytes(&private_from_bytes?);
//         let private_from_bytes_2 = PrivateKey::from_bytes(&private_to_bytes);
//         assert_eq!(
//             PrivateKey::public_key(&private_from_bytes_2?),
//             keypair.public
//         );
//         Ok(())
//     }
//     #[test]
//     fn test_from_str() -> Result<(), KeyError> {
//         let private_key = PrivateKey::from_bytes(PRIVATE_KEY_BYTES)?;
//         let key_string = private_key.to_string();
//         assert_eq!(
//             PrivateKey::from_str(&key_string)?.to_string(),
//             private_key.to_string()
//         );
//         Ok(())
//     }
//     #[test]
//     fn test_to_string() -> Result<(), KeyError> {
//         let private_key = PrivateKey::from_bytes(PRIVATE_KEY_BYTES)?;
//         let private_str= "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
//         assert_eq!(private_str, private_key.to_string());
//         Ok(())
//     }
//     #[test]
//     fn test_sign() -> Result<(), KeyError> {
//         let mut csprng = rand::rngs::OsRng {};
//         let keypair: Keypair = Keypair::generate(&mut csprng);
//         let message: &[u8] = b"This is a test";
//         let signature: Signature = keypair.sign(message);
//         let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
//         assert_eq!(
//             PrivateKey::sign(&PrivateKey(keypair.secret, None), message),
//             signature_bytes
//         );
//         Ok(())
//     }
// }
