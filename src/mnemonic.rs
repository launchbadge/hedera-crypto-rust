use ed25519_dalek;
use bip39::Mnemonic;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PhraseError {
    #[error("unsupported phrase length {0}, only 12 or 24 are supported")]
    Length(usize),
}

// Mnemonic phrase struct
pub struct MnemonicWords {
    props_words : Vec<String>,
    props_legacy : bool,
}

/*
impl MnemonicWords {
    fn generate(length: usize) -> Result<MnemonicWords, PhraseError>{
        let mut needed_entropy = 0;

        let needed_entropy = match length {
            12 => needed_entropy = 16,
            24 => needed_entropy = 32,
            _ => return Err(PhraseError::Length(length))
        };
        
        const seed = 

        Ok(MnemonicWords { props_words: , props_legacy: false })

    }
}
*/

//todo read(password) -> PrivateKey
fn read( password : String ) -> String {
    format!("PrivateKey")
}

//todo write(PrivateKey, password)