use std::cell::RefCell;

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;

pub fn derive(key_data: &mut [u8], chain_code: &mut [u8], index: u32) {
    thread_local! {
        static BUF: RefCell<[u8; 37]> = RefCell::new([0; 37]);
    }

    BUF.with(|buf| {
        let mut buf = buf.borrow_mut();

        buf[0] = 0;
        buf[1..33].copy_from_slice(&key_data);

        BigEndian::write_u32(&mut buf[33..], index);

        buf[33] |= 128;

        let mut mac = Hmac::<Sha512>::new_from_slice(chain_code).unwrap();
        mac.update(&*buf);

        let digest = mac.finalize().into_bytes();

        key_data.copy_from_slice(&digest[0..32]);
        chain_code.copy_from_slice(&digest[32..]);
    });
}
