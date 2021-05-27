mod public_key;

#[cfg(test)]
mod tests {
    use crate::public_key::{KeyError, PublicKey};
    extern crate ed25519_dalek;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
        assert_eq!(test_from_bytes(), KeyError::Length(data.len()));
    }

    fn test_from_bytes() -> Result<PublicKey, KeyError> {
        let public_key_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let public_key = PublicKey::from_bytes(&public_key_bytes)?;
        println!("{}", public_key);
        Ok(public_key)
    }
}
