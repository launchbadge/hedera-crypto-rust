use std::str::FromStr;

use hedera_crypto::{Mnemonic, PrivateKey};

fn main() -> anyhow::Result<()> {
    // generate a 24-word mnemonic
    let mnemonic = Mnemonic::generate_24()?;

    println!("mnemonic = {}", mnemonic);

    // convert to a root key
    let root_key = mnemonic.to_private_key("")?;

    // derive index #0
    // WARN: don't hand out your root key
    let key = PrivateKey::derive(&root_key, 0)?;

    println!("private key = {}", root_key);
    println!("public key = {}", root_key.public_key());

    let recovered_mnemonic = Mnemonic::from_str(&format!("{}", mnemonic))?;
    let recovered_root_key = Mnemonic::to_private_key(&recovered_mnemonic, "")?;
    let recovered_key = PrivateKey::derive(&recovered_root_key, 0)?;

    // recover your key from the mnemonic
    // this takes space-separated or comma-separated words
    if recovered_key.to_string() == key.to_string() {
        println!("Pass")
    } else {
        println!("Fail")
    }

    Ok(())
}
