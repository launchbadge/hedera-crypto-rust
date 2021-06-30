use byteorder::{BigEndian, ByteOrder};
use sha2::{Digest, Sha384};

type HmacSha384 = Hmac<Sha384>;
use hmac::Hmac;

pub fn derive(parent_key: &[u8], chain_code: &[u8], index: u32) -> (Vec<u8>, Vec<u8>) {
    let mut input = Vec::new();

    input.push(0x00);
    input.extend(parent_key);
    BigEndian::write_u32(&mut input[33..], index);

    input[33] |= 128;

    pbkdf2::pbkdf2::<HmacSha384>(parent_key, chain_code, 1, &mut input);

    let digest = Sha384::digest(&input);

    ((&digest[0..32]).to_vec(), (&digest[32..]).to_vec())
}
