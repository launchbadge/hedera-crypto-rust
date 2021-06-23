use hmac::Hmac;
use pbkdf2;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Returns u8 Vector
///
/// # Arguments
///
/// `seed` - u8 vector
///
/// `index` - i32 integer
///
pub fn legacy(seed: &[u8], index: i32) -> Vec<u8> {
    let salt = [0xff];
    let mut buf = Vec::with_capacity(seed.len() + 8);
    buf.extend_from_slice(&seed);
    buf.extend_from_slice(&index.to_be_bytes());

    let mut derived_key: [u8; 32] = [0; 32];
    pbkdf2::pbkdf2::<HmacSha512>(&buf, &salt, 2048, &mut derived_key);
    return derived_key.to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8] = &[
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    #[test]
    fn test_legacy() {
        let legacy = legacy(TEST_SEED, 0);
        assert_eq!(
            legacy,
            [
                60, 129, 234, 118, 66, 190, 0, 29, 70, 223, 185, 180, 215, 16, 148, 77, 104, 37,
                174, 169, 101, 52, 64, 84, 119, 252, 186, 208, 89, 214, 35, 172
            ]
        );
    }
}
