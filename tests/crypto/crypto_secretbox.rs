use sodium_sys::utils;
use sodium_sys::crypto::secretbox;

const TEST_KEY: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
const TEST_NONCE: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147, 246, 123, 253, 41,
                                   159, 169, 32, 114, 64, 251, 167, 179,
                                   178, 91, 200, 139];

#[test]
fn seal() {
    ::test_init();
    let ciphertext = secretbox::seal(TEST_MESSAGE, &TEST_KEY, &TEST_NONCE);
    assert!(ciphertext == TEST_CIPHERTEXT);
    utils::free(ciphertext);
}

#[test]
fn open() {
    ::test_init();
    let decrypted = secretbox::open(&TEST_CIPHERTEXT, TEST_KEY, TEST_NONCE);
    assert!(decrypted == TEST_MESSAGE);
    utils::free(decrypted);
}
