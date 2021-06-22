use crate::key::Key;
use std::fmt;
use std::ops::Deref;

pub struct KeyList {
    pub keys: Vec<Key>,
    pub threshold: Option<usize>,
}

impl Into<Key> for KeyList {
    fn into(self) -> Key {
        Key::KeyList(Self)
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

impl fmt::Display for KeyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        println!("keys: {:?} threshold: {}", self.keys, self.threshold.unwrap())
    }
}

// todo: impliment deref
// deref into a slice of keys
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
    }

    pub fn push(&mut self, key: Key)  {
        self.keys.push(key);
    }
}


#[cfg(test)]
mod tests {
    use super::{KeyError, PublicKey};
    use key_list;

    #[test]
    fn create_key_list_fn () {
        let public_key_1 = gen_public_key().unwrap();
        let public_key_2 = gen_public_key().unwrap();

        key_list = create_key_list(vec!(public_key_1, public_key_2), 3);
    }
}