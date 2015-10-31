use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::shorthash;
use test::Bencher;

const TEST_KEY: [u8; shorthash::KEYBYTES] = [0; shorthash::KEYBYTES];

#[bench]
fn bench_hash(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = shorthash::hash(b"test", &TEST_KEY).unwrap();
        secmem::free(&mut hash);
    });
}
