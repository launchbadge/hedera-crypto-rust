use ed25519_dalek::Keypair;
use bip39::Mnemonic;

// Mnemonic phrase struct
pub struct MnemonicWords {
    props_words : Vec<String>,
    props_legacy : bool,
}

impl MnemonicWords {
    fn generate(length: i32) {
        let mut needed_entropy = 0;

        if length == 12 { needed_entropy = 16; }
        else if length == 24 { needed_entropy = 32; }
        else { /* error */ }

    }
}

//todo read(password) -> PrivateKey
fn read( password : String ) -> String {
    format!("PrivateKey")
}

//todo write(PrivateKey, password)
