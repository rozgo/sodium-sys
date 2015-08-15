use sodium_sys::utils;
use sodium_sys::crypto::box_;
use test::Bencher;

const TEST_SECRET_KEY: [u8; box_::SECRETKEYBYTES] = [0; box_::SECRETKEYBYTES];
const TEST_PUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] = [0; box_::PUBLICKEYBYTES];
const TEST_NONCE: [u8; box_::NONCEBYTES] = [0; box_::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";

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
