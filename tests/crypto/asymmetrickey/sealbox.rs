use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::asymmetrickey::{sealbox, auth_keypair};

const TEST_MESSAGE: &'static [u8] = b"test";

#[test]
fn seal_and_open() {
    ::test_init();
    let keypair = auth_keypair::KeyPair::new().unwrap();
    keypair.activate_pk();
    keypair.activate_sk();

    let ciphertext = sealbox::seal(TEST_MESSAGE, keypair.pk_bytes()).unwrap();
    assert!(ciphertext.len() == sealbox::SEALBYTES + TEST_MESSAGE.len());

    let message = sealbox::open(ciphertext,
                                keypair.pk_bytes(),
                                keypair.sk_bytes()).unwrap();
    assert!(message == TEST_MESSAGE);
    secmem::free(message);
    secmem::free(ciphertext);
}
