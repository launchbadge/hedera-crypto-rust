use hmac::{Hmac, NewMac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

// WIP: This doesn't work right 
pub fn slip10_derive(parent_key: &[u8], chain_code: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let initial_input: Vec<u8> = vec![0];

    let mut input = [&initial_input[..], &parent_key[..]].concat();
    input[32] |= 128;

    let mut digest = HmacSha512::new_from_slice(chain_code).expect("HMAC can take key of any size");
    digest.update(&input);
    let result = digest.finalize();
    let code_bytes = result.into_bytes();
    
    return (code_bytes[0..32].to_vec(), code_bytes[32..64].to_vec());
}
