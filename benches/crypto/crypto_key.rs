use sodium_sys::crypto::key;
use sodium_sys::crypto::secretbox;
use test::Bencher;

#[bench]
fn bench_key(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        key::Key::new(secretbox::KEYBYTES)
    });
}
