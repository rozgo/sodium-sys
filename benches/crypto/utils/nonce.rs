use sodium_sys::crypto::utils::nonce;
use sodium_sys::crypto::symmetrickey::authenc;
use test::Bencher;

#[bench]
fn bench_nonce(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        nonce::Nonce::new(authenc::NONCEBYTES)
    });
}

#[cfg(feature = "latest")]
#[bench]
fn bench_nonce_increment(b: &mut Bencher) {
    ::test_init();
    let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
    nonce.activate();
    b.iter(|| {
        nonce.increment()
    });
}
