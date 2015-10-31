use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::shorthash;

const TEST_KEY: [u8; shorthash::KEYBYTES] = [0; shorthash::KEYBYTES];
const TEST_HASH: [u8; 8] = [78, 145, 88, 205, 196, 36, 81, 61];

#[test]
fn hash() {
    ::test_init();

    let hash = shorthash::hash(b"test", &TEST_KEY).unwrap();
    assert!(hash.len() == shorthash::BYTES);
    assert!(hash == TEST_HASH);
    secmem::free(hash);
}
