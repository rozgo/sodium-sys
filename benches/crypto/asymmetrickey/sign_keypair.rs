use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::asymmetrickey::{sign,sign_keypair};
use test::Bencher;

const TEST_SEED: [u8; sign::SEEDBYTES] = [0; sign::SEEDBYTES];

#[bench]
fn bench_keypair(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        sign_keypair::KeyPair::new().unwrap();
    });
}

#[bench]
fn bench_keypair_seed(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        sign_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    });
}

#[bench]
fn bench_keypair_get_seed(b: &mut Bencher) {
    ::test_init();
    let keypair = sign_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();

    b.iter(|| {
        let mut seed = keypair.get_seed().unwrap();
        secmem::free(&mut seed);
    });
}

#[bench]
fn bench_keypair_get_pk(b: &mut Bencher) {
    ::test_init();
    let keypair = sign_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    b.iter(|| {
        let mut pk = keypair.get_pk().unwrap();
        secmem::free(&mut pk);
    });
}
