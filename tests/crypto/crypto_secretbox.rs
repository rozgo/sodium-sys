use sodium_sys::crypto::secretbox;

const TEST_KEY: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
const TEST_NONCE: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147, 246, 123, 253, 41,
                                   159, 169, 32, 114, 64, 251, 167, 179,
                                   178, 91, 200, 139];

#[test]
fn gen_key() {
    use sodium_sys::core::init;
    init();
    let k1 = secretbox::gen_key();
    let k2 = secretbox::gen_key();
    assert!(k1.len() == secretbox::KEYBYTES);
    assert!(k2.len() == secretbox::KEYBYTES);
    assert!(k1 != k2);
}

#[test]
fn gen_nonce() {
    use sodium_sys::core::init;
    init();
    let n1 = secretbox::gen_nonce();
    let n2 = secretbox::gen_nonce();
    assert!(n1.len() == secretbox::NONCEBYTES);
    assert!(n2.len() == secretbox::NONCEBYTES);
    assert!(n1 != n2);
}

#[test]
fn seal() {
    use sodium_sys::core::init;
    init();
    let ciphertext = secretbox::seal(TEST_MESSAGE, TEST_KEY, TEST_NONCE);
    assert!(ciphertext == TEST_CIPHERTEXT);
}

#[test]
fn open() {
    use sodium_sys::core::init;
    init();
    let decrypted = secretbox::open(&TEST_CIPHERTEXT, TEST_KEY, TEST_NONCE);
    assert!(decrypted == TEST_MESSAGE);
}
