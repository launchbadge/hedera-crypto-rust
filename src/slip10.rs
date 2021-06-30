use hmac::Hmac;
use sha2::{Digest, Sha512};

type HmacSha512 = Hmac<Sha512>;

// WIP: Not sure about this function
pub fn slip10_derive(parent_key: &[u8], chain_code: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let initial_input: Vec<u8> = vec![0];

    let mut input = [&initial_input[..], &parent_key[..]].concat();
    input[32] |= 128;

    pbkdf2::pbkdf2::<HmacSha512>(parent_key, chain_code, 1, &mut input);

    let digest = Sha512::digest(&input);

    return (digest[0..32].to_vec(), digest[32..64].to_vec());
}
