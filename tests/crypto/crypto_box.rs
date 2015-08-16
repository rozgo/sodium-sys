use sodium_sys::utils;
use sodium_sys::crypto::box_;

const TEST_SECRET_KEY: [u8; box_::SECRETKEYBYTES] = [0; box_::SECRETKEYBYTES];
const TEST_PUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] = [0; box_::PUBLICKEYBYTES];
const TEST_NONCE: [u8; box_::NONCEBYTES] = [0; box_::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [1, 242, 22, 45,
                                   228, 36, 202, 193,
                                   131, 56, 182, 176,
                                   89, 5, 47, 88,
                                   243, 16, 189, 25];

#[test]
fn seal() {
    ::test_init();

    let ciphertext = box_::seal(TEST_MESSAGE,
                                &TEST_PUBLIC_KEY,
                                &TEST_SECRET_KEY,
                                &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_CIPHERTEXT);
    utils::free(ciphertext);
}
