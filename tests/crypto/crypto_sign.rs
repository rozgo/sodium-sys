use sodium_sys::utils;
use sodium_sys::crypto::sign;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_SEED: [u8; sign::SEEDBYTES] = [0; sign::SEEDBYTES];
const TEST_SIGNEDMESSAGE: [u8; sign::BYTES+4] = [150, 83, 113, 5,
                                                 97, 195, 22, 155,
                                                 122, 149, 119, 160,
                                                 25, 85, 22, 157,
                                                 239, 24, 63, 179,
                                                 174, 40, 46, 5,
                                                 190, 198, 36, 130,
                                                 110, 37, 91, 12,
                                                 62, 237, 227, 236,
                                                 254, 5, 79, 181,
                                                 164, 14, 254, 174,
                                                 240, 64, 175, 170,
                                                 69, 34, 12, 205,
                                                 123, 248, 65, 59,
                                                 165, 49, 242, 79,
                                                 63, 134, 146, 9,
                                                 116, 101, 115, 116];

const TEST_SIGNATURE: [u8; sign::BYTES] = [150, 83, 113, 5,
                                           97, 195, 22, 155,
                                           122, 149, 119, 160,
                                           25, 85, 22, 157,
                                           239, 24, 63, 179,
                                           174, 40, 46, 5,
                                           190, 198, 36, 130,
                                           110, 37, 91, 12,
                                           62, 237, 227, 236,
                                           254, 5, 79, 181,
                                           164, 14, 254, 174,
                                           240, 64, 175, 170,
                                           69, 34, 12, 205,
                                           123, 248, 65, 59,
                                           165, 49, 242, 79,
                                           63, 134, 146, 9];

#[test]
fn keypair() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new().unwrap();
    keypair.activate_sk();
    keypair.activate_pk();
    assert!(keypair.sk_bytes().len() == sign::SECRETKEYBYTES);
    assert!(keypair.pk_bytes().len() == sign::PUBLICKEYBYTES);
}

#[test]
fn keypair_seed() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();
    assert!(keypair.sk_bytes().len() == sign::SECRETKEYBYTES);
    assert!(keypair.pk_bytes().len() == sign::PUBLICKEYBYTES);
}

#[test]
fn keypair_get_seed() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    let seed = keypair.get_seed().unwrap();

    assert!(seed == TEST_SEED);
}

#[test]
fn keypair_get_pk() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();
    keypair.activate_pk();
    let pk = keypair.get_pk().unwrap();

    assert!(pk == keypair.pk_bytes());
}

#[test]
fn sign() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();

    let signedmessage = sign::sign(TEST_MESSAGE,
                                   &mut keypair.sk_bytes_mut()).unwrap();
    println!("{:?}", signedmessage);
    assert!(utils::memcmp(signedmessage, &TEST_SIGNEDMESSAGE) == 0);
    utils::free(signedmessage);
}

#[test]
fn open() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_pk();

    let message = sign::open(&TEST_SIGNEDMESSAGE,
                             &mut keypair.pk_bytes_mut()).unwrap();
    assert!(message == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn sign_detached() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();

    let signature = sign::sign_detached(TEST_MESSAGE,
                                        &mut keypair.sk_bytes_mut()).unwrap();
    println!("{:?}", signature);
    assert!(utils::memcmp(signature, &TEST_SIGNATURE) == 0);
    utils::free(signature);
}

#[test]
fn open_detached() {
    ::test_init();

    let keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_pk();

    let res = sign::open_detached(&TEST_MESSAGE,
                                  &TEST_SIGNATURE,
                                  &mut keypair.pk_bytes_mut());
    assert!(res == 0);
}
