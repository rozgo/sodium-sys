use sodium_sys::crypto::{keypair, box_};

const TEST_SEED: [u8; box_::SEEDBYTES] = [0; box_::SEEDBYTES];

#[test]
fn keypair() {
    ::test_init();
    let keypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
                                        box_::PUBLICKEYBYTES).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();

    assert!(keypair.sk_bytes().len() == box_::SECRETKEYBYTES);
    assert!(keypair.sk_bytes() != [0; box_::SECRETKEYBYTES]);
    assert!(keypair.pk_bytes().len() == box_::PUBLICKEYBYTES);
    assert!(keypair.pk_bytes() != [0; box_::PUBLICKEYBYTES]);
}

#[test]
fn keypair_seed() {
    ::test_init();
    let keypair = keypair::KeyPair::seed(&TEST_SEED,
                                         box_::SECRETKEYBYTES,
                                         box_::PUBLICKEYBYTES).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();

    assert!(keypair.sk_bytes().len() == box_::SECRETKEYBYTES);
    assert!(keypair.sk_bytes() != [0; box_::SECRETKEYBYTES]);
    assert!(keypair.pk_bytes().len() == box_::PUBLICKEYBYTES);
    assert!(keypair.pk_bytes() != [0; box_::PUBLICKEYBYTES]);
}
