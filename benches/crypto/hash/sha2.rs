use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::sha2;
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";

#[bench]
fn bench_hash_256(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = sha2::hash256(TEST_MESSAGE).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_512(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = sha2::hash512(TEST_MESSAGE).unwrap();
        secmem::free(&mut hash);
    });
}
