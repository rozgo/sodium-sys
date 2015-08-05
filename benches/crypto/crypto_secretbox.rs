use sodium_sys::utils;
use sodium_sys::crypto::secretbox;
use test::Bencher;

const TEST_KEY: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
const TEST_NONCE: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147, 246, 123, 253, 41,
                                   159, 169, 32, 114, 64, 251, 167, 179,
                                   178, 91, 200, 139];

#[bench]
fn bench_gen_key(b: &mut Bencher) {
    use sodium_sys::core::init;
    init();
    b.iter(|| {
        let k = secretbox::gen_key();
        utils::free(k);
    });
}

#[bench]
fn bench_gen_nonce(b: &mut Bencher) {
    use sodium_sys::core::init;
    init();
    b.iter(|| {
        let n = secretbox::gen_nonce();
        utils::free(n);
    });
}

#[bench]
fn bench_seal(b: &mut Bencher) {
    use sodium_sys::core::init;
    init();
    b.iter(|| {
        let mut ciphertext = secretbox::seal(TEST_MESSAGE, &TEST_KEY, &TEST_NONCE);
        utils::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    use sodium_sys::core::init;
    init();
    b.iter(|| {
        let mut message = secretbox::open(&TEST_CIPHERTEXT, TEST_KEY, TEST_NONCE);
        utils::free(&mut message);
    });
}
