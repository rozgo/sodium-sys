use sodium_sys::utils;
use sodium_sys::crypto::secretbox;

const TEST_KEY: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
const TEST_NONCE: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147, 246, 123, 253, 41,
                                   159, 169, 32, 114, 64, 251, 167, 179,
                                   178, 91, 200, 139];
const TEST_DET_CIPHERTEXT: [u8; 4] = [178, 91, 200, 139];
const TEST_NACL_CIPHERTEXT: [u8; 36] = [0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        175, 153, 180, 147,
                                        246, 123, 253, 41,
                                        159, 169, 32, 114,
                                        64, 251, 167, 179,
                                        178, 91, 200, 139];
const TEST_MAC: [u8; secretbox::MACBYTES] = [175, 153, 180, 147,
                                             246, 123, 253, 41,
                                             159, 169, 32, 114,
                                             64, 251, 167, 179];

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
    let decrypted = secretbox::open(&TEST_CIPHERTEXT, &TEST_KEY, &TEST_NONCE).unwrap();
    assert!(decrypted == TEST_MESSAGE);
    utils::free(decrypted);
}

#[test]
fn seal_detached() {
    ::test_init();
    let (ciphertext, mac) = secretbox::seal_detached(TEST_MESSAGE,
                                                     &TEST_KEY,
                                                     &TEST_NONCE);
    assert!(mac == TEST_MAC);
    assert!(ciphertext == TEST_DET_CIPHERTEXT);
    utils::free(ciphertext);
    utils::free(mac);
}

#[test]
fn open_detached() {
    ::test_init();
    let decrypted = secretbox::open_detached(&TEST_DET_CIPHERTEXT,
                                             &TEST_MAC,
                                             &TEST_KEY,
                                             &TEST_NONCE).unwrap();
    assert!(decrypted == TEST_MESSAGE);
    utils::free(decrypted);
}

#[test]
fn seal_nacl() {
    ::test_init();
    let ciphertext = secretbox::seal_nacl(TEST_MESSAGE,
                                          &TEST_KEY,
                                          &TEST_NONCE).unwrap();
    assert!(utils::memcmp(ciphertext, &TEST_NACL_CIPHERTEXT[..]) == 0);
    utils::free(ciphertext);
}

#[test]
fn open_nacl() {
    ::test_init();
    let decrypted = secretbox::open_nacl(&TEST_NACL_CIPHERTEXT,
                                         &TEST_KEY,
                                         &TEST_NONCE).unwrap();
    assert!(&decrypted[secretbox::ZEROBYTES..] == TEST_MESSAGE);
    utils::free(decrypted);
}
