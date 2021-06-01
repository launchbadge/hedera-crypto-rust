use bip39::{Mnemonic, Language};
use thiserror::Error;
use rand;

#[derive(Debug, Error)]
pub enum PhraseError {
    #[error("unsupported phrase length {0}, only 12 or 24 are supported")]
    Length(usize),
}

// Mnemonic phrase struct
#[derive(Debug)]
pub struct MnemonicWords {
    props_words : Mnemonic,
    props_legacy : bool,
}


impl MnemonicWords {
    fn generate(length: usize) -> Result<MnemonicWords, PhraseError>{
        
        println!("{}", length);
        let mut rng = rand::thread_rng();
        let words = Mnemonic::generate_in_with(&mut rng, Language::English, length).unwrap();
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
        let test = MnemonicWords::generate(24).unwrap();
        println!("{:?}", test);
    }
}