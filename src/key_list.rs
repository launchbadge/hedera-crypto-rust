use crate::key::Key;

pub struct KeyList {
    keys: Vec<Key>,
    threshold: Result<i32, E>,
}

impl KeyList {
    // todo: of(keys: Vec<Key>) -> KeyList
    pub fn create_key_list(keys: Vec<Key>, threshold: Result<i32, E>) -> KeyList {
        KeyList{
            keys,
            threshold: threshold,
        }
    }

    // todo: from(keys: Vec<Key>, mapFn: ?, T) -> KeyList

    // todo: push(keys: Vec<Key>) -> i32
}
