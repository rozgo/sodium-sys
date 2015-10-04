use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::sha2;
use std::default::Default;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_H1: [u8; sha2::SHA256_BYTES] = [159, 134, 208, 129,
                                           136, 76, 125, 101,
                                           154, 47, 234, 160,
                                           197, 90, 208, 21,
                                           163, 191, 79, 27,
                                           43, 11, 130, 44,
                                           209, 93, 108, 21,
                                           176, 240, 10, 8];
const TEST_H2: [u8; sha2::SHA256_BYTES] = [55, 38, 131, 53,
                                           221, 105, 49, 4,
                                           91, 220, 223, 146,
                                           98, 63, 248, 25,
                                           166, 66, 68, 181,
                                           61, 14, 116, 109,
                                           67, 135, 151, 52,
                                           157, 77, 165, 120];

#[test]
fn hash() {
    ::test_init();

    let hash = sha2::hash256(TEST_MESSAGE).unwrap();
    assert!(hash.len() == sha2::SHA256_BYTES);
    assert!(hash == TEST_H1);
    secmem::free(hash);
}

#[test]
fn init() {
    ::test_init();

    let mut state = Default::default();
    let _ = sha2::init256(&mut state).unwrap();
    assert!(state.state.len() == 8);
    assert!(state.count.len() == 2);
    assert!(state.buf.len() == 64);
}

#[test]
fn update() {
    ::test_init();

    let mut state = Default::default();
    let _ = sha2::init256(&mut state).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    let s1 = state.state;
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    assert!(s1 != state.state);
}

#[test]
fn finalize() {
    ::test_init();

    let mut state = Default::default();
    let _ = sha2::init256(&mut state).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    let hash = sha2::finalize256(&mut state).unwrap();
    assert!(hash == TEST_H2);
}
