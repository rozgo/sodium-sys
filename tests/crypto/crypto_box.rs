use sodium_sys::utils;
use sodium_sys::crypto::box_;

const TEST_MYSECRET_KEY: [u8; box_::SECRETKEYBYTES] = [0; box_::SECRETKEYBYTES];
const TEST_MYPUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] = [0; box_::PUBLICKEYBYTES];
const TEST_THEIRSECRET_KEY: [u8; box_::SECRETKEYBYTES] =
    [0; box_::SECRETKEYBYTES];
const TEST_THEIRPUBLIC_KEY: [u8; box_::PUBLICKEYBYTES] =
    [0; box_::PUBLICKEYBYTES];
const TEST_SSK: [u8; box_::BEFORENMBYTES] = [0; box_::BEFORENMBYTES];
const TEST_NONCE: [u8; box_::NONCEBYTES] = [0; box_::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [1, 242, 22, 45,
                                   228, 36, 202, 193,
                                   131, 56, 182, 176,
                                   89, 5, 47, 88,
                                   243, 16, 189, 25];
const TEST_DET_CIPHERTEXT: [u8; 4] = [243, 16, 189, 25];
const TEST_MAC: [u8; box_::MACBYTES] = [1, 242, 22, 45,
                                        228, 36, 202, 193,
                                        131, 56, 182, 176,
                                        89, 5, 47, 88];
const TEST_SSK_MAC: [u8; box_::MACBYTES] = [175, 153, 180, 147,
                                            246, 123, 253, 41,
                                            159, 169, 32, 114,
                                            64, 251, 167, 179];
const TEST_SSK_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147,
                                       246, 123, 253, 41,
                                       159, 169, 32, 114,
                                       64, 251, 167, 179,
                                       178, 91, 200, 139];
const TEST_SSK_DET_CIPHERTEXT: [u8; 4] = [178, 91, 200, 139];
const TEST_NACL_CIPHERTEXT: [u8; 36] = [0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        1, 242, 22, 45,
                                        228, 36, 202, 193,
                                        131, 56, 182, 176,
                                        89, 5, 47, 88,
                                        243, 16, 189, 25];
const TEST_NACL_SSK_CIPHERTEXT: [u8; 36] = [0, 0, 0, 0,
                                            0, 0, 0, 0,
                                            0, 0, 0, 0,
                                            0, 0, 0, 0,
                                            175, 153, 180, 147,
                                            246, 123, 253, 41,
                                            159, 169, 32, 114,
                                            64, 251, 167, 179,
                                            178, 91, 200, 139];
const TEST_SEED: [u8; box_::SEEDBYTES] = [0; box_::SEEDBYTES];
const TEST_OTHER_PK: [u8; box_::PUBLICKEYBYTES] = [0; box_::PUBLICKEYBYTES];
const TEST_KP_SSK: [u8; box_::BEFORENMBYTES] = [53, 31, 134, 250,
                                                163, 185, 136, 70,
                                                138, 133, 1, 34,
                                                182, 91, 10, 206,
                                                206, 156, 72, 38,
                                                128, 106, 238, 230,
                                                61, 233, 192, 218,
                                                43, 215, 249, 30];

#[test]
fn seal() {
    ::test_init();

    let ciphertext = box_::seal(TEST_MESSAGE,
                                &TEST_THEIRPUBLIC_KEY,
                                &TEST_MYSECRET_KEY,
                                &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_CIPHERTEXT);
    utils::free(ciphertext);
}

#[test]
fn open() {
    ::test_init();

    let message = box_::open(&TEST_CIPHERTEXT,
                             &TEST_MYPUBLIC_KEY,
                             &TEST_THEIRSECRET_KEY,
                             &TEST_NONCE).unwrap();
    assert!(message == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn seal_detached() {
    ::test_init();
    let (ciphertext, mac) = box_::seal_detached(TEST_MESSAGE,
                                                &TEST_THEIRPUBLIC_KEY,
                                                &TEST_MYSECRET_KEY,
                                                &TEST_NONCE).unwrap();
    assert!(mac == TEST_MAC);
    assert!(ciphertext == TEST_DET_CIPHERTEXT);
    utils::free(ciphertext);
    utils::free(mac);
}

#[test]
fn open_detached() {
    ::test_init();
    let message = box_::open_detached(&TEST_DET_CIPHERTEXT,
                                      &TEST_MAC,
                                      &TEST_MYPUBLIC_KEY,
                                      &TEST_THEIRSECRET_KEY,
                                      &TEST_NONCE).unwrap();
    assert!(message == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn seal_with_ssk() {
    ::test_init();

    let ciphertext = box_::seal_with_ssk(TEST_MESSAGE,
                                         &TEST_SSK,
                                         &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_SSK_CIPHERTEXT);
    utils::free(ciphertext);
}

#[test]
fn open_with_ssk() {
    ::test_init();

    let message = box_::open_with_ssk(&TEST_SSK_CIPHERTEXT,
                                      &TEST_SSK,
                                      &TEST_NONCE).unwrap();
    assert!(message == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn seal_detached_with_ssk() {
    ::test_init();
    let (ciphertext, mac) = box_::seal_detached_with_ssk(TEST_MESSAGE,
                                                         &TEST_SSK,
                                                         &TEST_NONCE).unwrap();
    assert!(mac == TEST_SSK_MAC);
    assert!(ciphertext == TEST_SSK_DET_CIPHERTEXT);
    utils::free(ciphertext);
    utils::free(mac);
}

#[test]
fn open_detached_with_ssk() {
    ::test_init();
    let message = box_::open_detached_with_ssk(&TEST_SSK_DET_CIPHERTEXT,
                                               &TEST_SSK_MAC,
                                               &TEST_SSK,
                                               &TEST_NONCE).unwrap();
    assert!(message == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn seal_nacl() {
    ::test_init();

    let ciphertext = box_::seal_nacl(TEST_MESSAGE,
                                     &TEST_THEIRPUBLIC_KEY,
                                     &TEST_MYSECRET_KEY,
                                     &TEST_NONCE).unwrap();
    assert!(utils::memcmp(ciphertext, &TEST_NACL_CIPHERTEXT[..]) == 0);
    utils::free(ciphertext);
}

#[test]
fn open_nacl() {
    ::test_init();

    let message = box_::open_nacl(&TEST_NACL_CIPHERTEXT,
                                  &TEST_MYPUBLIC_KEY,
                                  &TEST_THEIRSECRET_KEY,
                                  &TEST_NONCE).unwrap();
    assert!(&message[box_::ZEROBYTES..] == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn seal_nacl_with_ssk() {
    ::test_init();

    let ciphertext = box_::seal_nacl_with_ssk(TEST_MESSAGE,
                                              &TEST_SSK,
                                              &TEST_NONCE).unwrap();
    println!("{:?}", ciphertext);
    assert!(utils::memcmp(ciphertext, &TEST_NACL_SSK_CIPHERTEXT[..]) == 0);
    utils::free(ciphertext);
}

#[test]
fn open_nacl_with_ssk() {
    ::test_init();

    let message = box_::open_nacl_with_ssk(&TEST_NACL_SSK_CIPHERTEXT,
                                           &TEST_SSK,
                                           &TEST_NONCE).unwrap();
    assert!(&message[box_::ZEROBYTES..] == TEST_MESSAGE);
    utils::free(message);
}

#[test]
fn keypair() {
    ::test_init();
    let keypair = box_::keypair::KeyPair::new().unwrap();
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
    let keypair = box_::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
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
    let initialkp = box_::keypair::KeyPair::new().unwrap();

    initialkp.activate_sk();
    initialkp.activate_pk();

    let nkp = box_::keypair::KeyPair::derivepk(&mut initialkp.sk_bytes_mut()).unwrap();

    nkp.activate_pk();
    nkp.activate_sk();

    assert!(nkp.sk_bytes().len() == box_::SECRETKEYBYTES);
    assert!(nkp.sk_bytes() != [0; box_::SECRETKEYBYTES]);
    assert!(nkp.pk_bytes().len() == box_::PUBLICKEYBYTES);
    assert!(nkp.pk_bytes() != [0; box_::PUBLICKEYBYTES]);
    assert!(initialkp.pk_bytes() == nkp.pk_bytes());
}

#[test]
fn keypair_shared_secret() {
    ::test_init();
    let keypair = box_::keypair::KeyPair::new().unwrap();

    keypair.activate_pk();
    keypair.activate_sk();

    let ssk = keypair.shared_secret(&TEST_OTHER_PK).unwrap();

    assert!(ssk == TEST_KP_SSK);
}
