//use keystore;
use ed25519_dalek::Keypair;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    fn test_keystore_read() { assert_eq!(keystore.read(""), format!("PrivateKey")); }
}

/*
fn dotest(n: u64, exp: u64) -> () {
    assert_eq!(perimeter(n), exp)
}

#[test]
fn basics_perimeter() {
    dotest(30, 14098308);
    dotest(5, 80);
    dotest(7, 216);
    dotest(20, 114624);
}
 */

use ed25519_dalek::Keypair;
use bip39::Mnemonic;
use rand::Rng;

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

        let seed = rand::thread_rng().gen::<[u8; needed_entropy]>();
    }
}

//todo read(password) -> PrivateKey
fn read( password : String ) -> String {
    format!("PrivateKey")
}

//todo write(PrivateKey, password)
