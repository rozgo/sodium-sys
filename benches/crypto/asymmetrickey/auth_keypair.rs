use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
use test::Bencher;

const TEST_SEED: [u8; authenc::SEEDBYTES] = [0; authenc::SEEDBYTES];
const TEST_OTHER_PK: [u8; authenc::PUBLICKEYBYTES] = [0; authenc::PUBLICKEYBYTES];

#[bench]
fn bench_keypair(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        auth_keypair::KeyPair::new().unwrap()
    });
}

#[bench]
fn bench_keypair_seed(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        auth_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap()
    });
}

#[bench]
fn bench_keypair_derive(b: &mut Bencher) {
    ::test_init();

    // Setup an initial keypair.
    let ikp = auth_keypair::KeyPair::new().unwrap();

    // Activate the keys.
    ikp.activate_pk();
    ikp.activate_sk();

    b.iter(|| {
        auth_keypair::KeyPair::derivepk(&mut ikp.sk_bytes_mut()).unwrap()
    });
}

#[bench]
fn bench_keypair_sharedsecret(b: &mut Bencher) {
    ::test_init();

    // Setup an initial keypair.
    let ikp = auth_keypair::KeyPair::new().unwrap();

    // Activate the keys.
    ikp.activate_pk();
    ikp.activate_sk();

    b.iter(|| {
        let mut ssk = ikp.shared_secret(&TEST_OTHER_PK).unwrap();
        secmem::free(&mut ssk);
    });
}
