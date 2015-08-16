use sodium_sys::crypto::{keypair,box_};
use test::Bencher;

const TEST_SEED: [u8; box_::SEEDBYTES] = [0; box_::SEEDBYTES];

#[bench]
fn bench_keypair(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        keypair::KeyPair::new(box_::SECRETKEYBYTES, box_::PUBLICKEYBYTES).unwrap()
    });
}

#[bench]
fn bench_keypair_seed(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        keypair::KeyPair::seed(&TEST_SEED, box_::SECRETKEYBYTES, box_::PUBLICKEYBYTES).unwrap()
    });
}

#[bench]
fn bench_keypair_derive(b: &mut Bencher) {
    ::test_init();
    // Setup an initial keypair.
    let ikp = keypair::KeyPair::new(box_::SECRETKEYBYTES,box_::PUBLICKEYBYTES).unwrap();

    // Activate the keys.
    ikp.activate_pk();
    ikp.activate_sk();

    b.iter(|| {
        keypair::KeyPair::derivepk(&mut ikp.sk_bytes_mut(),
                                   box_::SECRETKEYBYTES,
                                   box_::PUBLICKEYBYTES).unwrap()
    });
}
