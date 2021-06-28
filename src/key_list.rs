use crate::key::Key;
use itertools::Itertools;
use std::fmt;
use std::iter::FromIterator;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Default)]
pub struct KeyList {
    pub keys: Vec<Key>,
    pub threshold: Option<usize>,
}

impl From<Vec<Key>> for KeyList {
    fn from(keys: Vec<Key>) -> Self {
        KeyList {
            keys,
            threshold: None,
        }
    }
}

impl fmt::Display for KeyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyList")
            .field("threshold", &self.threshold)
            .field("keys", &format!("[{}]", self.keys.iter().format(",")))
            .finish()
    }
}

impl Deref for KeyList {
    type Target = Vec<Key>;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl DerefMut for KeyList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.keys
    }
}

impl<K: Into<Key>> FromIterator<K> for KeyList {
    fn from_iter<I: IntoIterator<Item = K>>(iter: I) -> Self {
        let mut l = Self::new();

        for i in iter {
            l.push(i.into());
        }

        l
    }
}

impl KeyList {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use crate::key::Key;
    use crate::public_key::PublicKey;

    use super::KeyList;

    const PUBLIC_KEY_BYTES: &[u8] = &[
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];

    #[test]
    fn create_key_list_threshold() {
        let key_vec = gen_key_vec();

        let mut key_list = KeyList {
            keys: key_vec,
            threshold: Some(3),
        };

        key_list.threshold = Some(5);

        assert_eq!(key_list.threshold.unwrap(), 5);
    }

    #[test]
    fn test_push() {
        let key_vec = gen_key_vec();
        let mut key_list = KeyList {
            keys: key_vec,
            threshold: Some(3),
        };

        let public_key_3 = PublicKey::from_bytes(PUBLIC_KEY_BYTES).unwrap();

        let key3 = PublicKey::into(public_key_3);

        key_list.push(key3);

        assert_eq!(key_list.keys.len(), 3);
    }

    #[test]
    fn test_display() {}

    fn gen_key_vec() -> Vec<Key> {
        let public_key_1 = PublicKey::from_bytes(PUBLIC_KEY_BYTES).unwrap();
        let public_key_2 = PublicKey::from_bytes(PUBLIC_KEY_BYTES).unwrap();

        let key1 = PublicKey::into(public_key_1);
        let key2 = PublicKey::into(public_key_2);

        vec![key1, key2]
    }
}
