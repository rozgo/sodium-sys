use sodium_sys::crypto::utils::verify;
use test::Bencher;

#[bench]
fn bench_verify_16(b: &mut Bencher) {
    let a1 = [0; 16];
    let a2 = [0; 16];
    let a3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    b.iter(|| {
        verify::verify_16(&a1, &a2);
        verify::verify_16(&a1, &a3)
    });
}

#[bench]
fn bench_verify_32(b: &mut Bencher) {
    let a1 = [0; 32];
    let a2 = [0; 32];
    let a3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    b.iter(|| {
        verify::verify_32(&a1, &a2);
        verify::verify_32(&a1, &a3)
    });
}

#[bench]
fn bench_verify_64(b: &mut Bencher) {
    let a1 = [0; 64];
    let a2 = [0; 64];
    let a3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    b.iter(|| {
        verify::verify_64(&a1, &a2);
        verify::verify_64(&a1, &a3)
    });
}
