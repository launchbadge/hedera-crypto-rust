use crate::public_key::PublicKey;
use crate::key_list::KeyList;

#[derive(Debug)]
pub enum Key {
    PublicKey(PublicKey),
    KeyList(KeyList),
}