use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::symmetrickey::hmacsha2;
use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_MULTI_MESSAGE: &'static [u8] = b"testtest";
const TEST_KEY1: [u8; hmacsha2::HMACSHA256_KEYBYTES] =
    [0; hmacsha2::HMACSHA256_KEYBYTES];
const TEST_KEY2: [u8; hmacsha2::HMACSHA512_KEYBYTES] =
    [0; hmacsha2::HMACSHA512_KEYBYTES];
const TEST_KEY3: [u8; hmacsha2::HMACSHA512256_KEYBYTES] =
    [0; hmacsha2::HMACSHA512256_KEYBYTES];
const TEST_MAC1: [u8; hmacsha2::HMACSHA256_BYTES] = [
    67, 176, 206, 249,
    146, 101, 249, 227,
    76, 16, 234, 157,
    53, 1, 146, 109,
    39, 179, 159, 87,
    198, 214, 116, 86,
    29, 139, 162, 54,
    231, 168, 25, 251
];
const TEST_MAC2: [u8; hmacsha2::HMACSHA512_BYTES] = [
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
const TEST_MAC3: [u8; hmacsha2::HMACSHA512256_BYTES] = [
    41, 197, 250, 176,
    119, 192, 9, 185,
    230, 103, 107, 47,
    8, 42, 122, 179,
    176, 70, 43, 65,
    172, 247, 95, 7,
    91, 90, 123, 172,
    86, 25, 236, 129
];
const TEST_MAC4: [u8; hmacsha2::HMACSHA256_BYTES] = [
    110, 48, 162, 251,
    70, 55, 150, 36,
    200, 135, 108, 67,
    5, 98, 136, 223,
    192, 6, 216, 178,
    131, 12, 33, 180,
    63, 239, 135, 88,
    110, 150, 163, 135
];
const TEST_MAC5: [u8; hmacsha2::HMACSHA512_BYTES] = [
    108, 49, 97, 205,
    150, 222, 0, 163,
    164, 83, 158, 130,
    5, 98, 14, 50,
    129, 93, 143, 200,
    249, 65, 64, 185,
    120, 99, 168, 116,
    212, 76, 68, 187,
    209, 174, 159, 187,
    161, 13, 152, 83,
    190, 207, 7, 251,
    114, 110, 81, 35,
    205, 89, 210, 255,
    57, 246, 231, 231,
    50, 213, 248, 82,
    189, 144, 130, 239
];
const TEST_MAC6: [u8; hmacsha2::HMACSHA512256_BYTES] = [
    108, 49, 97, 205,
    150, 222, 0, 163,
    164, 83, 158, 130,
    5, 98, 14, 50,
    129, 93, 143, 200,
    249, 65, 64, 185,
    120, 99, 168, 116,
    212, 76, 68, 187
];

#[test]
fn auth() {
    ::test_init();

    // SHA256
    let mac1 = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY1, SHA256).unwrap();
    assert!(mac1.len() == hmacsha2::HMACSHA256_BYTES);
    assert!(mac1 == TEST_MAC1);

    // SHA512
    let mac2 = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY2, SHA512).unwrap();
    assert!(mac2.len() == hmacsha2::HMACSHA512_BYTES);
    assert!(secmem::memcmp(mac2, &TEST_MAC2) == 0);

    // SHA512256
    let mac3 = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY3, SHA512256).unwrap();
    assert!(mac3.len() == hmacsha2::HMACSHA512256_BYTES);
    assert!(secmem::memcmp(mac3, &TEST_MAC3) == 0);

    secmem::free(mac1);
    secmem::free(mac2);
    secmem::free(mac3);
}

#[test]
fn verify() {
    ::test_init();

    // SHA256
    let res = hmacsha2::verify(
        TEST_MESSAGE,
        &TEST_MAC1,
        &TEST_KEY1,
        SHA256
    ).unwrap();
    assert!(res == 0);

    // SHA512
    let res = hmacsha2::verify(
        TEST_MESSAGE,
        &TEST_MAC2,
        &TEST_KEY2,
        SHA512
    ).unwrap();
    assert!(res == 0);

    // SHA512256
    let res = hmacsha2::verify(
        TEST_MESSAGE,
        &TEST_MAC3,
        &TEST_KEY3,
        SHA512256
    ).unwrap();
    assert!(res == 0);
}

#[test]
fn multipart() {
    ::test_init();

    // SHA256
    let state_size = hmacsha2::statebytes(SHA256);
    let mut state = secmem::malloc(state_size);
    let _ = hmacsha2::init(&mut state, &TEST_KEY1, SHA256).unwrap();
    let _ = hmacsha2::update(&mut state, TEST_MESSAGE, SHA256).unwrap();
    let _ = hmacsha2::update(&mut state, TEST_MESSAGE, SHA256).unwrap();
    let mac1 = hmacsha2::finalize(&mut state, SHA256).unwrap();
    assert!(mac1.len() == hmacsha2::HMACSHA256_BYTES);
    assert!(mac1 == &TEST_MAC4);

    let res = hmacsha2::verify(
        TEST_MULTI_MESSAGE,
        &TEST_MAC4,
        &TEST_KEY1,
        SHA256
    ).unwrap();
    assert!(res == 0);

    // SHA512
    let state_size = hmacsha2::statebytes(SHA512);
    let mut state = secmem::malloc(state_size);
    let _ = hmacsha2::init(&mut state, &TEST_KEY1, SHA512).unwrap();
    let _ = hmacsha2::update(&mut state, TEST_MESSAGE, SHA512).unwrap();
    let _ = hmacsha2::update(&mut state, TEST_MESSAGE, SHA512).unwrap();
    let mac2 = hmacsha2::finalize(&mut state, SHA512).unwrap();
    assert!(mac2.len() == hmacsha2::HMACSHA512_BYTES);
    assert!(secmem::memcmp(mac2, &TEST_MAC5) == 0);

    let res = hmacsha2::verify(
        TEST_MULTI_MESSAGE,
        &TEST_MAC5,
        &TEST_KEY1,
        SHA512
    ).unwrap();
    assert!(res == 0);

    // SHA512256
    let state_size = hmacsha2::statebytes(SHA512256);
    let mut state = secmem::malloc(state_size);
    let _ = hmacsha2::init(&mut state, &TEST_KEY1, SHA512256).unwrap();
    let _ = hmacsha2::update(&mut state, TEST_MESSAGE, SHA512256).unwrap();
    let _ = hmacsha2::update(&mut state, TEST_MESSAGE, SHA512256).unwrap();
    let mac3 = hmacsha2::finalize(&mut state, SHA512256).unwrap();
    assert!(mac3.len() == hmacsha2::HMACSHA512256_BYTES);
    assert!(secmem::memcmp(mac3, &TEST_MAC6) == 0);

    let res = hmacsha2::verify(
        TEST_MULTI_MESSAGE,
        &TEST_MAC6,
        &TEST_KEY1,
        SHA512256
    ).unwrap();
    assert!(res == 0);
}
