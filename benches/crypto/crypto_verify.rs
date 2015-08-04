use sodium_sys::crypto::crypto_verify;
use test::Bencher;

#[bench]
fn bench_verify_16(b: &mut Bencher) {
    let a1 = [0; 16];
    let a2 = [0; 16];
    let a3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    b.iter(|| {
        crypto_verify::verify_16(&a1, &a2);
        crypto_verify::verify_16(&a1, &a3)
    });
}
