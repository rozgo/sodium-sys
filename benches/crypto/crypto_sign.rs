use sodium_sys::utils;
use sodium_sys::crypto::sign;
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_MYSECRET_KEY: [u8; sign::SECRETKEYBYTES] = [0; sign::SECRETKEYBYTES];

#[bench]
fn bench_sign(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut sm = sign::sign(TEST_MESSAGE, &TEST_SECRET_KEY).unwrap();
        utils::free(&mut sm);
    });
}
