use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::symmetrickey::hmacsha2;
use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_KEY1: [u8; hmacsha2::HMACSHA256_KEYBYTES] =
    [0; hmacsha2::HMACSHA256_KEYBYTES];
const TEST_KEY2: [u8; hmacsha2::HMACSHA512_KEYBYTES] =
    [0; hmacsha2::HMACSHA512_KEYBYTES];
const TEST_KEY3: [u8; hmacsha2::HMACSHA512256_KEYBYTES] =
    [0; hmacsha2::HMACSHA512256_KEYBYTES];
const TEST_H1: [u8; hmacsha2::HMACSHA256_BYTES] = [
    67, 176, 206, 249,
    146, 101, 249, 227,
    76, 16, 234, 157,
    53, 1, 146, 109,
    39, 179, 159, 87,
    198, 214, 116, 86,
    29, 139, 162, 54,
    231, 168, 25, 251
];
const TEST_H2: [u8; hmacsha2::HMACSHA512_BYTES] = [
    41, 197, 250, 176,
    119, 192, 9, 185,
    230, 103, 107, 47,
    8, 42, 122, 179,
    176, 70, 43, 65,
    172, 247, 95, 7,
    91, 90, 123, 172,
    86, 25, 236, 129,
    201, 216, 187, 46,
    37, 182, 211, 56,
    0, 251, 162, 121,
    238, 73, 42, 199,
    208, 82, 32, 232,
    41, 70, 77, 243,
    202, 142, 0, 41,
    140, 81, 119, 100
];
const TEST_H3: [u8; hmacsha2::HMACSHA512256_BYTES] = [
    41, 197, 250, 176,
    119, 192, 9, 185,
    230, 103, 107, 47,
    8, 42, 122, 179,
    176, 70, 43, 65,
    172, 247, 95, 7,
    91, 90, 123, 172,
    86, 25, 236, 129
];

#[test]
fn auth() {
    ::test_init();

    // SHA256
    let mac1 = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY1, SHA256).unwrap();
    assert!(mac1.len() == hmacsha2::HMACSHA256_BYTES);
    assert!(mac1 == TEST_H1);

    // SHA512
    let mac2 = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY2, SHA512).unwrap();
    assert!(mac2.len() == hmacsha2::HMACSHA512_BYTES);
    assert!(secmem::memcmp(mac2, &TEST_H2) == 0);

    // SHA512256
    let mac3 = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY3, SHA512256).unwrap();
    assert!(mac3.len() == hmacsha2::HMACSHA512256_BYTES);
    assert!(secmem::memcmp(mac3, &TEST_H3) == 0);

    secmem::free(mac1);
    secmem::free(mac2);
    secmem::free(mac3);
}
