use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::symmetrickey::auth;
use test::Bencher;

const TEST_KEY: [u8; auth::KEYBYTES] = [0; auth::KEYBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";

#[bench]
fn bench_auth(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut mac = auth::auth(TEST_MESSAGE, &TEST_KEY).unwrap();
        secmem::free(&mut mac);
    });
}

#[bench]
fn bench_auth_verify(b: &mut Bencher) {
    ::test_init();
    let mut mac = auth::auth(TEST_MESSAGE, &TEST_KEY).unwrap();
    b.iter(|| {
        auth::auth_verify(TEST_MESSAGE, mac, &TEST_KEY).unwrap()
    });

    secmem::free(&mut mac);
}
