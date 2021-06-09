pub enum Key {
    private_key(PrivateKey),
    public_key(PublicKey),
    key_list(KeyList),
}