use bip39::{Mnemonic, Language};
use thiserror::Error;
use rand;

#[derive(Debug, Error)]
pub enum PhraseError {
    // TODO: Figure out the problem with Length
    #[error("Entropy Length Received: {0}. Only 12 and 24 are supported.")]
    BadEntropyLength(usize),
    #[error(transparent)]
    Error(#[from] bip39::Error),
}

// Mnemonic phrase struct
#[derive(Debug)]
pub struct MnemonicWords {
    props_words : Mnemonic,
    props_legacy : bool,
}


impl MnemonicWords {
    pub fn generate(length: usize) -> Result<MnemonicWords, PhraseError>{

        let mut rng = rand::thread_rng();
        // Test to see if correct length
        println!("{}", length);

        let words = match length {
            12 | 24 => {
                println!("start");
                let words = Mnemonic::generate_in_with(&mut rng, Language::English, length).map_err(PhraseError::Error)?;
                words
            }
            _ => {
                return Err(PhraseError::BadEntropyLength(length));
            }
        };
        println!("{:?}", words);


        Ok(MnemonicWords { props_words: words, props_legacy: false })

    }
}

//todo read(password) -> PrivateKey
fn read( password : String ) -> String {
    format!("PrivateKey")
}

//todo write(PrivateKey, password)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let test = MnemonicWords::generate(19).unwrap();
        println!("{:?}", test);
    }
}