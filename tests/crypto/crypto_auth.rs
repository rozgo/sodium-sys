use sodium_sys::utils;
use sodium_sys::crypto::auth;

const TEST_KEY: [u8; auth::KEYBYTES] = [0; auth::KEYBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_MAC: [u8; auth::BYTES] = [41, 197, 250, 176,
                                     119, 192, 9, 185,
                                     230, 103, 107, 47,
                                     8, 42, 122, 179,
                                     176, 70, 43, 65,
                                     172, 247, 95, 7,
                                     91, 90, 123, 172,
                                     86, 25, 236, 129];

#[test]
fn auth() {
    ::test_init();
    let mac = auth::auth(TEST_MESSAGE, &TEST_KEY).unwrap();
    assert!(mac == TEST_MAC);
    utils::free(mac);
}

#[test]
fn auth_verify() {
    ::test_init();
    let mac = auth::auth(TEST_MESSAGE, &TEST_KEY).unwrap();
    let res = auth::auth_verify(TEST_MESSAGE, mac, &TEST_KEY).unwrap();
    assert!(res == 0);
    utils::free(mac);
}
