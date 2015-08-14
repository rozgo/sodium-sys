use sodium_sys::crypto::{keypair, box_};

const TEST_SEED: [u8; box_::SEEDBYTES] = [0; box_::SEEDBYTES];

#[test]
fn keypair() {
    ::test_init();
    let keypair = keypair::KeyPair::new(box_::SECRETKEYBYTES, box_::PUBLICKEYBYTES).unwrap();
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

#[test]
fn keypair_derivepk() {
    ::test_init();
    let initialkp = keypair::KeyPair::new(box_::SECRETKEYBYTES, box_::PUBLICKEYBYTES).unwrap();

    initialkp.activate_sk();
    initialkp.activate_pk();

    let nkp = keypair::KeyPair::derivepk(&mut initialkp.sk_bytes_mut(),
                                         box_::SECRETKEYBYTES,
                                         box_::PUBLICKEYBYTES).unwrap();

    nkp.activate_pk();
    nkp.activate_sk();

    assert!(nkp.sk_bytes().len() == box_::SECRETKEYBYTES);
    assert!(nkp.sk_bytes() != [0; box_::SECRETKEYBYTES]);
    assert!(nkp.pk_bytes().len() == box_::PUBLICKEYBYTES);
    assert!(nkp.pk_bytes() != [0; box_::PUBLICKEYBYTES]);
    assert!(initialkp.pk_bytes() == nkp.pk_bytes());
}
