use sodium_sys::utils;
use sodium_sys::crypto::aead;
use test::Bencher;

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

#[bench]
fn bench_aead_encrypt_no_ad(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = aead::aead_encrypt(TEST_MESSAGE,
                                                None,
                                                &TEST_KEY,
                                                &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[bench]
fn bench_aead_encrypt(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = aead::aead_encrypt(TEST_MESSAGE,
                                                Some(TEST_AD),
                                                &TEST_KEY,
                                                &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[bench]
fn bench_aead_decrypt_no_ad(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = aead::aead_decrypt(&TEST_NO_AD_CT,
                                             None,
                                             &TEST_KEY,
                                             &TEST_NONCE).unwrap();
        utils::free(&mut message);
    });
}

#[bench]
fn bench_aead_decrypt(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = aead::aead_decrypt(&TEST_AD_CT,
                                             Some(TEST_AD),
                                             &TEST_KEY,
                                             &TEST_NONCE).unwrap();
        utils::free(&mut message);
    });
}

#[cfg(feature = "latest")]
#[bench]
fn bench_aead_encrypt_ietf_no_ad(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = aead::aead_encrypt_ietf(TEST_MESSAGE,
                                                     None,
                                                     &TEST_KEY,
                                                     &TEST_IETF_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[cfg(feature = "latest")]
#[bench]
fn bench_aead_encrypt_ietf(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = aead::aead_encrypt_ietf(TEST_MESSAGE,
                                                     Some(TEST_AD),
                                                     &TEST_KEY,
                                                     &TEST_IETF_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[cfg(feature = "latest")]
#[bench]
fn bench_aead_decrypt_ietf_no_ad(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = aead::aead_decrypt_ietf(&TEST_NO_AD_IETF_CT,
                                                  None,
                                                  &TEST_KEY,
                                                  &TEST_IETF_NONCE).unwrap();
        utils::free(&mut message);
    });
}

#[cfg(feature = "latest")]
#[bench]
fn bench_aead_decrypt_ietf(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = aead::aead_decrypt_ietf(&TEST_AD_IETF_CT,
                                                  Some(TEST_AD),
                                                  &TEST_KEY,
                                                  &TEST_IETF_NONCE).unwrap();
        utils::free(&mut message);
    });
}
