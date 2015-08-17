use sodium_sys::utils;
use sodium_sys::crypto::box_;

const TEST_MYSECRET_KEY: [u8; box_::SECRETKEYBYTES] = [0; box_::SECRETKEYBYTES];
const TEST_MYPUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] = [0; box_::PUBLICKEYBYTES];
const TEST_THEIRSECRET_KEY: [u8; box_::SECRETKEYBYTES] =
    [0; box_::SECRETKEYBYTES];
const TEST_THEIRPUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] =
    [0; box_::PUBLICKEYBYTES];
const TEST_NONCE: [u8; box_::NONCEBYTES] = [0; box_::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [1, 242, 22, 45,
                                   228, 36, 202, 193,
                                   131, 56, 182, 176,
                                   89, 5, 47, 88,
                                   243, 16, 189, 25];
const TEST_DET_CIPHERTEXT: [u8; 4] = [243, 16, 189, 25];
const TEST_MAC: [u8; box_::MACBYTES] = [1, 242, 22, 45,
                                        228, 36, 202, 193,
                                        131, 56, 182, 176,
                                        89, 5, 47, 88];

#[test]
fn seal() {
    ::test_init();

    let ciphertext = box_::seal(TEST_MESSAGE,
                                &TEST_THEIRPUBLIC_KEY,
                                &TEST_MYSECRET_KEY,
                                &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_CIPHERTEXT);
    utils::free(ciphertext);
}

#[test]
fn open() {
    ::test_init();

    let ciphertext = box_::seal(TEST_MESSAGE,
                                &TEST_THEIRPUBLIC_KEY,
                                &TEST_MYSECRET_KEY,
                                &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_CIPHERTEXT);
    let message = box_::open(ciphertext,
                             &TEST_MYPUBLIC_KEY,
                             &TEST_THEIRSECRET_KEY,
                             &TEST_NONCE).unwrap();
    assert!(message == TEST_MESSAGE);
}

#[test]
fn seal_detached() {
    ::test_init();
    let (ciphertext, mac) = box_::seal_detached(TEST_MESSAGE,
                                                &TEST_THEIRPUBLIC_KEY,
                                                &TEST_MYSECRET_KEY,
                                                &TEST_NONCE).unwrap();
    assert!(mac == TEST_MAC);
    assert!(ciphertext == TEST_DET_CIPHERTEXT);
    utils::free(ciphertext);
    utils::free(mac);
}

#[test]
fn open_detached() {
    ::test_init();
    let decrypted = box_::open_detached(&TEST_DET_CIPHERTEXT,
                                        &TEST_MAC,
                                        &TEST_MYPUBLIC_KEY,
                                        &TEST_THEIRSECRET_KEY,
                                        &TEST_NONCE).unwrap();
    assert!(decrypted == TEST_MESSAGE);
    utils::free(decrypted);
}
