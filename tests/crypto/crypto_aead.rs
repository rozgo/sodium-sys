use sodium_sys::utils;
use sodium_sys::crypto::aead;

const TEST_KEY: [u8; aead::KEYBYTES] = [0; aead::KEYBYTES];
const TEST_NONCE: [u8; aead::NPUBBYTES] = [0; aead::NPUBBYTES];
#[cfg(feature = "latest")]
const TEST_IETF_NONCE: [u8; aead::IETF_NPUBBYTES] = [0; aead::IETF_NPUBBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_AD: &'static [u8] = b"more data";
const TEST_NO_AD_CT: [u8; 20] = [235, 98, 148, 202,
                                 227, 78, 66, 144,
                                 62, 233, 41, 94,
                                 5, 71, 41, 24,
                                 71, 160, 250, 189];
const TEST_AD_CT: [u8; 20] = [235, 98, 148, 202,
                              182, 137, 177, 0,
                              215, 138, 164, 242,
                              19, 74, 77, 164,
                              153, 1, 183, 26];
#[cfg(feature = "latest")]
const TEST_NO_AD_IETF_CT: [u8; 20] = [235, 98, 148, 202,
                                      153, 80, 180, 13,
                                      73, 134, 189, 0,
                                      190, 33, 234, 79,
                                      52, 151, 255, 221];
#[cfg(feature = "latest")]
const TEST_AD_IETF_CT: [u8; 20] = [235, 98, 148, 202,
                                   129, 180, 133, 205,
                                   65, 115, 124, 254,
                                   69, 98, 174, 194,
                                   96, 240, 229, 187];

#[test]
fn aead_encrypt_no_ad() {
    ::test_init();
    let ciphertext = aead::aead_encrypt(TEST_MESSAGE, None, &TEST_KEY, &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_NO_AD_CT);
    utils::free(ciphertext);
}

#[test]
fn aead_encrypt() {
    ::test_init();
    let ciphertext = aead::aead_encrypt(TEST_MESSAGE,
                                        Some(TEST_AD),
                                        &TEST_KEY,
                                        &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_AD_CT);
    utils::free(ciphertext);
}

#[test]
fn aead_decrypt_no_ad() {
    ::test_init();
    let message = aead::aead_decrypt(&TEST_NO_AD_CT, None, &TEST_KEY, &TEST_NONCE).unwrap();
    assert!(message == b"test");
    utils::free(message);
}

#[test]
fn aead_decrypt() {
    ::test_init();
    let message = aead::aead_decrypt(&TEST_AD_CT, Some(TEST_AD), &TEST_KEY, &TEST_NONCE).unwrap();
    assert!(message == b"test");
    utils::free(message);
}

#[cfg(feature = "latest")]
#[test]
fn aead_encrypt_ietf_no_ad() {
    ::test_init();
    let ciphertext = aead::aead_encrypt_ietf(TEST_MESSAGE,
                                             None,
                                             &TEST_KEY,
                                             &TEST_IETF_NONCE).unwrap();
    assert!(ciphertext == TEST_NO_AD_IETF_CT);
    utils::free(ciphertext);
}

#[cfg(feature = "latest")]
#[test]
fn aead_encrypt_ietf() {
    ::test_init();
    let ciphertext = aead::aead_encrypt_ietf(TEST_MESSAGE,
                                        Some(TEST_AD),
                                        &TEST_KEY,
                                        &TEST_IETF_NONCE).unwrap();
    assert!(ciphertext == TEST_AD_IETF_CT);
    utils::free(ciphertext);
}

#[cfg(feature = "latest")]
#[test]
fn aead_decrypt_ietf_no_ad() {
    ::test_init();
    let message = aead::aead_decrypt_ietf(&TEST_NO_AD_IETF_CT,
                                          None,
                                          &TEST_KEY,
                                          &TEST_IETF_NONCE).unwrap();
    assert!(message == b"test");
    utils::free(message);
}

#[cfg(feature = "latest")]
#[test]
fn aead_decrypt_ietf() {
    ::test_init();
    let message = aead::aead_decrypt_ietf(&TEST_AD_IETF_CT,
                                          Some(TEST_AD),
                                          &TEST_KEY,
                                          &TEST_IETF_NONCE).unwrap();
    assert!(message == b"test");
    utils::free(message);
}
