use crate::public_key::PublicKey;
use crate::key_list::KeyList;

// todo: add private key when ready
pub enum Key {
    PublicKey(PublicKey),
    KeyList(KeyList),
}