use sodium_sys::crypto::symmetrickey::hmacsha2;
use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
use sodium_sys::crypto::utils::secmem;
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_MULTI_MESSAGE: &'static [u8] = b"testtest";
const TEST_KEY1: [u8; hmacsha2::HMACSHA256_KEYBYTES] =
    [0; hmacsha2::HMACSHA256_KEYBYTES];
const TEST_KEY2: [u8; hmacsha2::HMACSHA512_KEYBYTES] =
    [0; hmacsha2::HMACSHA512_KEYBYTES];
const TEST_KEY3: [u8; hmacsha2::HMACSHA512256_KEYBYTES] =
    [0; hmacsha2::HMACSHA512256_KEYBYTES];

#[bench]
fn bench_auth_256(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mac = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY1, SHA256).unwrap();
        secmem::free(mac);
    });
}

#[bench]
fn bench_auth_512(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mac = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY2, SHA512).unwrap();
        secmem::free(mac);
    });
}

#[bench]
fn bench_auth_512256(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mac = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY3, SHA512256).unwrap();
        secmem::free(mac);
    });
}

#[bench]
fn bench_verify_256(b: &mut Bencher) {
    ::test_init();
    let mac = hmacsha2::auth(TEST_MESSAGE, &TEST_KEY1, SHA256).unwrap();

    b.iter(|| {
        hmacsha2::verify(TEST_MESSAGE, mac, &TEST_KEY1, SHA256)
    });
}
