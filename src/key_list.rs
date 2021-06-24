use crate::key::Key;
use std::fmt;
use std::ops::Deref;
use crate::public_key::PublicKey;

#[derive(Debug)]
pub struct KeyList {
    pub keys: Vec<Key>,
    pub threshold: Option<usize>,
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

impl From<Vec<Key>> for KeyList {
    fn from(keys: Vec<Key>) -> Self {
        KeyList {
            keys,
            threshold: None,
        }
    }
}

// todo: fix this trait
impl fmt::Display for KeyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        write!(f, "keys: {:?} threshold: {}", self.keys, self.threshold.unwrap())
    }
}

// deref into a slice of keys
// todo: test this trait
impl Deref for KeyList {
    type Target = [Key];
    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl KeyList {
    pub fn create_key_list(keys: Vec<Key>, threshold: Option<usize>) -> KeyList {
        KeyList{
            keys,
            threshold,
        }
    }

    pub fn set_threshold(&mut self, threshold: usize) -> &mut Self {
        self.threshold = Some(threshold);
        self
    }

    pub fn push(&mut self, key: Key)  {
        self.keys.push(key);
    }
}


#[cfg(test)]
mod tests {
    use crate::public_key::PublicKey;
    use crate::key::Key;

    use super::KeyList;

    const PUBLIC_KEY_BYTES: &[u8] = &[
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];

    #[test]
    fn create_key_list_threshold() {
        let key_vec = gen_key_vec();

        let mut key_list = KeyList::create_key_list(key_vec, Some(3));

        KeyList::set_threshold(&mut key_list, 5);

        assert_eq!(key_list.threshold.unwrap(), 5);
    }

    #[test]
    fn test_push() {
        let key_vec = gen_key_vec();
        let mut key_list = KeyList::create_key_list(key_vec, Some(3));

        let public_key_3 = PublicKey::from_bytes(PUBLIC_KEY_BYTES).unwrap();

        let key3 = PublicKey::into(public_key_3);

        KeyList::push(&mut key_list, key3);

        assert_eq!(key_list.keys.len(), 3);
    }

    #[test]
    fn test_display() {

    }

    fn gen_key_vec() -> Vec<Key> {
        let public_key_1 = PublicKey::from_bytes(PUBLIC_KEY_BYTES).unwrap();
        let public_key_2 = PublicKey::from_bytes(PUBLIC_KEY_BYTES).unwrap();

        let key1 = PublicKey::into(public_key_1);
        let key2 = PublicKey::into(public_key_2);

        vec!(key1, key2)
    }
}