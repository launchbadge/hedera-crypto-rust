use hedera_crypto::public_key::{self, Hash};
use std::collections::hash_map::DefaultHasher;
use std::str::FromStr;

use crate::public_key::{KeyError, PublicKey};

const PUBLIC_KEY_BYTES: [u8; 32] = [
    215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218,
    166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
];

#[test]
fn test_to_bytes() {
    let public_key_to_bytes = PublicKey::to_bytes(&gen_public_key().unwrap());

    println!("Public Key Bytes: {:#?}\n", PUBLIC_KEY_BYTES);
    println!("Public Key To Bytes: {:#?}\n", public_key_to_bytes);

    // Passes Test
    assert_eq!(public_key_to_bytes, PUBLIC_KEY_BYTES);
}
#[test]
fn test_from_bytes() {
    println!("Test - from_bytes() ");
    let public_key = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();

    // Passes Test
    assert_eq!(public_key, gen_public_key().unwrap());
}

#[test]
fn test_fmt() {
    let public_key = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();

    let test = format!("{}", public_key);
    println!("{:?}", test);
    // Passes Test
    assert_eq!(
        test,
        "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
}

#[test]
fn test_from_string() {
    println!("Test - from_str() ");

    let public_key = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();
    println!("Initial Public Key: {}", public_key);

    let test = format!("{}", public_key);
    let get_string = PublicKey::from_str(&test).unwrap();
    println!("Public Key From String: {}", get_string);

    // Passes Test
    assert_eq!(get_string, public_key);
}

#[test]
fn hash_test() {
    let test = gen_public_key().unwrap();
    let mut hasher = DefaultHasher::new();
    //let test2 = PublicKey::hash(&test, &mut hasher);
    test.hash(&mut hasher);

    println!("{:?}", test);
}

// Get a public key
fn gen_public_key() -> Result<PublicKey, KeyError> {
    let public_key = PublicKey::from_bytes(&PUBLIC_KEY_BYTES)?;
    Ok(public_key)
}
