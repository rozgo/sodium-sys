use sodium_sys::crypto::symmetrickey::{authenc,key};
use test::Bencher;

#[bench]
fn bench_key(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        key::Key::new(authenc::KEYBYTES)
    });
}
