use sodium_sys::utils;
use sodium_sys::crypto::box_;
use test::Bencher;

const TEST_SECRET_KEY: [u8; box_::SECRETKEYBYTES] = [0; box_::SECRETKEYBYTES];
const TEST_PUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] = [0; box_::PUBLICKEYBYTES];
const TEST_NONCE: [u8; box_::NONCEBYTES] = [0; box_::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [1, 242, 22, 45,
                                   228, 36, 202, 193,
                                   131, 56, 182, 176,
                                   89, 5, 47, 88,
                                   243, 16, 189, 25];

#[bench]
fn bench_seal(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = box_::seal(TEST_MESSAGE,
                                        &TEST_PUBLIC_KEY,
                                        &TEST_SECRET_KEY,
                                        &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = box_::open(&TEST_CIPHERTEXT,
                                     &TEST_PUBLIC_KEY,
                                     &TEST_SECRET_KEY,
                                     &TEST_NONCE).unwrap();
        utils::free(&mut message);
    });
}

#[bench]
fn bench_seal_detached(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let (mut ciphertext, mut mac) =
            box_::seal_detached(TEST_MESSAGE,
                                &TEST_PUBLIC_KEY,
                                &TEST_SECRET_KEY,
                                &TEST_NONCE).unwrap();
        utils::free(&mut ciphertext);
        utils::free(&mut mac);
    });
}
