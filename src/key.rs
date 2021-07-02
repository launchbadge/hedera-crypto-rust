use crate::key_list::KeyList;
use crate::public_key::PublicKey;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Key {
    PublicKey(PublicKey),
    KeyList(KeyList),
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Key::PublicKey(key) => key.fmt(f),
            Key::KeyList(key) => key.fmt(f),
        }
    }
}

impl From<PublicKey> for Key {
    fn from(public_key: PublicKey) -> Self {
        Key::PublicKey(public_key)
    }
}

impl From<KeyList> for Key {
    fn from(list: KeyList) -> Self {
        Key::KeyList(list)
    }
}
