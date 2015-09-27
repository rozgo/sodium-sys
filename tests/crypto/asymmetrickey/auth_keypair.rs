use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};

const TEST_SEED: [u8; authenc::SEEDBYTES] = [0; authenc::SEEDBYTES];
const TEST_OTHER_PK: [u8; authenc::PUBLICKEYBYTES] = [0; authenc::PUBLICKEYBYTES];
const TEST_KP_SSK: [u8; authenc::BEFORENMBYTES] = [53, 31, 134, 250,
                                                163, 185, 136, 70,
                                                138, 133, 1, 34,
                                                182, 91, 10, 206,
                                                206, 156, 72, 38,
                                                128, 106, 238, 230,
                                                61, 233, 192, 218,
                                                43, 215, 249, 30];

#[test]
fn keypair() {
    ::test_init();
    let keypair = auth_keypair::KeyPair::new().unwrap();
    keypair.activate_sk();
    keypair.activate_pk();

    assert!(keypair.sk_bytes().len() == authenc::SECRETKEYBYTES);
    assert!(keypair.sk_bytes() != [0; authenc::SECRETKEYBYTES]);
    assert!(keypair.pk_bytes().len() == authenc::PUBLICKEYBYTES);
    assert!(keypair.pk_bytes() != [0; authenc::PUBLICKEYBYTES]);
}

#[test]
fn keypair_seed() {
    ::test_init();
    let keypair = auth_keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();

    assert!(keypair.sk_bytes().len() == authenc::SECRETKEYBYTES);
    assert!(keypair.sk_bytes() != [0; authenc::SECRETKEYBYTES]);
    assert!(keypair.pk_bytes().len() == authenc::PUBLICKEYBYTES);
    assert!(keypair.pk_bytes() != [0; authenc::PUBLICKEYBYTES]);
}

#[test]
fn keypair_derivepk() {
    ::test_init();
    let initialkp = auth_keypair::KeyPair::new().unwrap();

    initialkp.activate_sk();
    initialkp.activate_pk();

    let nkp = auth_keypair::KeyPair::derivepk(&mut initialkp.sk_bytes_mut()).unwrap();

    nkp.activate_pk();
    nkp.activate_sk();

    assert!(nkp.sk_bytes().len() == authenc::SECRETKEYBYTES);
    assert!(nkp.sk_bytes() != [0; authenc::SECRETKEYBYTES]);
    assert!(nkp.pk_bytes().len() == authenc::PUBLICKEYBYTES);
    assert!(nkp.pk_bytes() != [0; authenc::PUBLICKEYBYTES]);
    assert!(initialkp.pk_bytes() == nkp.pk_bytes());
}

#[test]
fn keypair_shared_secret() {
    ::test_init();
    let keypair = auth_keypair::KeyPair::new().unwrap();

    keypair.activate_pk();
    keypair.activate_sk();

    let ssk = keypair.shared_secret(&TEST_OTHER_PK).unwrap();

    assert!(ssk == TEST_KP_SSK);
}
