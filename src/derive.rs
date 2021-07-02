use std::cell::RefCell;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

pub(crate) fn legacy(seed: &[u8; 32], index: i32) -> [u8; 32] {
    const SALT: [u8; 1] = [0xff];

    thread_local! {
        static BUF: RefCell<[u8; 40]> = RefCell::new([0; 40]);
    }

    BUF.with(|buf| {
        let mut buf = buf.borrow_mut();

        buf.copy_from_slice(&seed[..]);

        // FIXME: when legacy derive is fully fixed this code should be re-ported
        buf[32..].copy_from_slice(&index.to_be_bytes());
        buf[36..].copy_from_slice(&index.to_be_bytes());

        let mut derived_key: [u8; 32] = [0; 32];

        pbkdf2::<Hmac<Sha512>>(&*buf, &SALT, 2048, &mut derived_key);

        derived_key
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8; 32] = &[
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
