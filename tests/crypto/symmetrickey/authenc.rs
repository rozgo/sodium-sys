use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::symmetrickey::authenc;

const TEST_KEY: [u8; authenc::KEYBYTES] = [0; authenc::KEYBYTES];
const TEST_NONCE: [u8; authenc::NONCEBYTES] = [0; authenc::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147, 246, 123, 253, 41,
                                   159, 169, 32, 114, 64, 251, 167, 179,
                                   178, 91, 200, 139];
const TEST_DET_CIPHERTEXT: [u8; 4] = [178, 91, 200, 139];
const TEST_NACL_CIPHERTEXT: [u8; 36] = [0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        175, 153, 180, 147,
                                        246, 123, 253, 41,
                                        159, 169, 32, 114,
                                        64, 251, 167, 179,
                                        178, 91, 200, 139];
const TEST_MAC: [u8; authenc::MACBYTES] = [175, 153, 180, 147,
                                             246, 123, 253, 41,
                                             159, 169, 32, 114,
                                             64, 251, 167, 179];

#[test]
fn seal() {
    ::test_init();
    let ciphertext = authenc::encrypt(TEST_MESSAGE,
                                     &TEST_KEY,
                                     &TEST_NONCE).unwrap();
    assert!(ciphertext == TEST_CIPHERTEXT);
    secmem::free(ciphertext);
}

#[test]
fn open() {
    ::test_init();
    let decrypted = authenc::open(&TEST_CIPHERTEXT,
                                    &TEST_KEY,
                                    &TEST_NONCE).unwrap();
    assert!(decrypted == TEST_MESSAGE);
    secmem::free(decrypted);
}

#[test]
fn seal_detached() {
    ::test_init();
    let (ciphertext, mac) = authenc::encrypt_detached(TEST_MESSAGE,
                                                     &TEST_KEY,
                                                     &TEST_NONCE).unwrap();
    assert!(mac == TEST_MAC);
    assert!(ciphertext == TEST_DET_CIPHERTEXT);
    secmem::free(ciphertext);
    secmem::free(mac);
}

#[test]
fn open_detached() {
    ::test_init();
    let decrypted = authenc::open_detached(&TEST_DET_CIPHERTEXT,
                                             &TEST_MAC,
                                             &TEST_KEY,
                                             &TEST_NONCE).unwrap();
    assert!(decrypted == TEST_MESSAGE);
    secmem::free(decrypted);
}

#[test]
fn seal_nacl() {
    ::test_init();
    let ciphertext = authenc::encrypt_nacl(TEST_MESSAGE,
                                          &TEST_KEY,
                                          &TEST_NONCE).unwrap();
    assert!(secmem::memcmp(ciphertext, &TEST_NACL_CIPHERTEXT[..]) == 0);
    secmem::free(ciphertext);
}

#[test]
fn open_nacl() {
    ::test_init();
    let decrypted = authenc::open_nacl(&TEST_NACL_CIPHERTEXT,
                                         &TEST_KEY,
                                         &TEST_NONCE).unwrap();
    assert!(&decrypted[authenc::ZEROBYTES..] == TEST_MESSAGE);
    secmem::free(decrypted);
}
