//use keystore;
use ed25519_dalek::Keypair;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    fn test_keystore_read() { assert_eq!(keystore.read(""), format!("PrivateKey")); }
}

/*
fn dotest(n: u64, exp: u64) -> () {
    assert_eq!(perimeter(n), exp)
}

#[test]
fn basics_perimeter() {
    dotest(30, 14098308);
    dotest(5, 80);
    dotest(7, 216);
    dotest(20, 114624);
}
 */
