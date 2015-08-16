use sodium_sys::utils;
use sodium_sys::crypto::secretbox;
use test::Bencher;

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

#[bench]
fn bench_seal(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = secretbox::seal(TEST_MESSAGE,
                                             &TEST_KEY,
                                             &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = secretbox::open(&TEST_CIPHERTEXT,
                                          &TEST_KEY,
                                          &TEST_NONCE).unwrap();
        utils::free(&mut message);
    });
}

#[bench]
fn bench_seal_detached(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let (mut ciphertext, mut mac) =
            secretbox::seal_detached(TEST_MESSAGE,
                                     &TEST_KEY,
                                     &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
        utils::free(&mut mac);
    });
}

#[bench]
fn bench_open_detached(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = secretbox::open_detached(&TEST_DET_CIPHERTEXT,
                                                   &TEST_MAC,
                                                   &TEST_KEY,
                                                   &TEST_NONCE).unwrap();
        utils::free(&mut message);
    });
}

#[bench]
fn bench_seal_nacl(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = secretbox::seal_nacl(TEST_MESSAGE,
                                                  &TEST_KEY,
                                                  &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open_nacl(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = secretbox::open_nacl(&TEST_NACL_CIPHERTEXT,
                                               &TEST_KEY,
                                               &TEST_NONCE).unwrap();
        utils::free(&mut message);
    });
}
