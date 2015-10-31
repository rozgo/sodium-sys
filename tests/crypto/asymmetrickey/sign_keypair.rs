use sodium_sys::crypto::asymmetrickey::{sign,sign_keypair};

const TEST_SEED: [u8; sign::SEEDBYTES] = [0; sign::SEEDBYTES];

#[test]
fn keypair() {
    ::test_init();

    let keypair = sign_keypair::KeyPair::new().unwrap();
    keypair.activate_sk();
    keypair.activate_pk();
    assert!(keypair.sk_bytes().len() == sign::SECRETKEYBYTES);
    assert!(keypair.pk_bytes().len() == sign::PUBLICKEYBYTES);
}

#[test]
fn keypair_seed() {
    ::test_init();

    let keypair = sign_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();
    assert!(keypair.sk_bytes().len() == sign::SECRETKEYBYTES);
    assert!(keypair.pk_bytes().len() == sign::PUBLICKEYBYTES);
}

#[test]
fn keypair_get_seed() {
    ::test_init();

    let keypair = sign_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    let seed = keypair.get_seed().unwrap();

    assert!(seed == TEST_SEED);
}

#[test]
fn keypair_get_pk() {
    ::test_init();

    let keypair = sign_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();
    let pk = keypair.get_pk().unwrap();

    assert!(pk == keypair.pk_bytes());
}
