use std::str::FromStr;

use hedera_crypto::{Mnemonic, PrivateKey};

fn main() -> anyhow::Result<()> {
    // generate a 24-word mnemonic
    let keystore_1 = std::fs::read("./keystore.bin")?;
    let key = PrivateKey::from_keystore(&keystore_1, "")?;

    // convert to a root key
    // let root_key = mnemonic.to_private_key("")?;

    // derive index #0
    // WARN: don't hand out your root key
    // let key = root_key.derive(0)?;

    println!("private key = {}", key);
    println!("public key = {}", key.public_key());

    let keystore_2 = key.to_keystore("")?;

    std::fs::write("keystore2.bin", keystore_2)?;

    // [...]

    // recover your key from the mnemonic
    // this takes space-separated or comma-separated words

    // let recovered_mnemonic = Mnemonic::from_str(&mnemonic.to_string())?;
    // let recovered_root_key = recovered_mnemonic.to_private_key("")?;
    // let recovered_key = recovered_root_key.derive(0)?;

    // assert_eq!(recovered_key, key);

    Ok(())
}
