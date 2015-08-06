use sodium_sys::crypto::key;
use sodium_sys::crypto::secretbox;
use test::Bencher;

#[bench]
fn bench_key(b: &mut Bencher) {
    use sodium_sys::core::init;
    init();
    b.iter(|| {
        key::Key::new(secretbox::KEYBYTES)
    });
}
