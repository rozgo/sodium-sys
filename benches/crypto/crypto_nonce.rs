use sodium_sys::crypto::{nonce,secretbox};
use test::Bencher;

#[bench]
fn bench_nonce(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        nonce::Nonce::new(secretbox::NONCEBYTES)
    });
}

#[cfg(feature = "latest")]
#[bench]
fn bench_nonce_increment(b: &mut Bencher) {
    ::test_init();
    let nonce = nonce::Nonce::new(secretbox::NONCEBYTES);
    nonce.activate();
    b.iter(|| {
        nonce.increment()
    });
}
