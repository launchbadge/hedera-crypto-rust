use hedera_crypto::Mnemonic;

fn main() -> anyhow::Result<()> {
    // generate a 24-word mnemonic
    let mnemonic = Mnemonic::generate_24()?;

    println!("mnemonic = {}", mnemonic);

    // convert to a root key
    let root_key = mnemonic.to_private_key("")?;

    // TODO: derive the root key to index 0 before print

    println!("private key = {}", root_key);
    println!("public key = {}", root_key.public_key());

    Ok(())
}