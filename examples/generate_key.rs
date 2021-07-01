use std::str::FromStr;

use hedera_crypto::{Mnemonic, PrivateKey};

fn main() -> anyhow::Result<()> {
    // generate a 24-word mnemonic
    let mnemonic = Mnemonic::generate_24()?;

    println!("mnemonic = {}", mnemonic);

    // convert to a root key
    let root_key = mnemonic.to_private_key("")?;

    // TODO: derive the root key to index 0 before print
    let key = PrivateKey::derive(&root_key)?;

    println!("private key = {}", root_key);
    println!("public key = {}", root_key.public_key());

    let recovered_mnemonic = Mnemonic::from_str(&format!("{}", mnemonic))?;
    let recovered_root_key = Mnemonic::to_private_key(&recovered_mnemonic, "")?;
    let recovered_key = PrivateKey::derive(&recovered_root_key)?;

    println!("Recovered Key:{}", recovered_key);
    println!("Key: {}", key);
    if recovered_key.to_string() == key.to_string() {
        println!("Pass")
    } else {
        println!("Fail")
    }

    Ok(())
}
