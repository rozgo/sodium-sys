use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::asymmetrickey::{sealbox, auth_keypair};
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";

#[bench]
fn bench_seal(b: &mut Bencher) {
    ::test_init();
    let keypair = auth_keypair::KeyPair::new().unwrap();
    keypair.activate_pk();
    keypair.activate_sk();

    b.iter(|| {
        let mut ciphertext = sealbox::seal(TEST_MESSAGE,
                                           keypair.pk_bytes()).unwrap();
        secmem::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    ::test_init();
    let keypair = auth_keypair::KeyPair::new().unwrap();
    keypair.activate_pk();
    keypair.activate_sk();

    let mut ciphertext = sealbox::seal(TEST_MESSAGE,
                                       keypair.pk_bytes()).unwrap();
    b.iter(|| {
        let mut message = sealbox::open(ciphertext,
                                        keypair.pk_bytes(),
                                        keypair.sk_bytes()).unwrap();
        secmem::free(&mut message);
    });

    secmem::free(&mut ciphertext);
}
