use hex::encode;
use hmac::Hmac;
use pbkdf2::password_hash::SaltString;
use pbkdf2;
use rand_core::OsRng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// WIP

/// Returns u8 Vector
///
/// # Arguments
///
/// `seed` - u8 vector
///
/// `index` - u8
///
pub fn legacy(seed: &[u8]) -> Vec<u8> {
    let password = seed.to_vec();

    let salt = SaltString::generate(&mut OsRng);

    let password_string = encode(password);
    let mut derived_key: [u8; 32] = [0; 32];
    pbkdf2::pbkdf2::<HmacSha256>(
        password_string.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut derived_key,
    );
    return derived_key.to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy() {
        let test: &[u8] = &[
            157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068,
            073, 197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
        ];
        let legacy = legacy(test);
        println!("{:?}", legacy);
    }
}
