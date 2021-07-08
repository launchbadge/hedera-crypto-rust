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
