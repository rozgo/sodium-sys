use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::sha2;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_H1: [u8; sha2::SHA256_BYTES] = [159, 134, 208, 129,
                                           136, 76, 125, 101,
                                           154, 47, 234, 160,
                                           197, 90, 208, 21,
                                           163, 191, 79, 27,
                                           43, 11, 130, 44,
                                           209, 93, 108, 21,
                                           176, 240, 10, 8];
const TEST_H2: [u8; sha2::SHA512_BYTES] = [238, 38, 176, 221,
                                           74, 247, 231, 73,
                                           170, 26, 142, 227,
                                           193, 10, 233, 146,
                                           63, 97, 137, 128,
                                           119, 46, 71, 63,
                                           136, 25, 165, 212,
                                           148, 14, 13, 178,
                                           122, 193, 133, 248,
                                           160, 225, 213, 248,
                                           79, 136, 188, 136,
                                           127, 214, 123, 20,
                                           55, 50, 195, 4,
                                           204, 95, 169, 173,
                                           142, 111, 87, 245,
                                           0, 40, 168, 255];
const TEST_H3: [u8; sha2::SHA256_BYTES] = [55, 38, 131, 53,
                                           221, 105, 49, 4,
                                           91, 220, 223, 146,
                                           98, 63, 248, 25,
                                           166, 66, 68, 181,
                                           61, 14, 116, 109,
                                           67, 135, 151, 52,
                                           157, 77, 165, 120];
const TEST_H4: [u8; sha2::SHA512_BYTES] = [18, 93, 109, 3,
                                           179, 44, 132, 212,
                                           146, 116, 127, 121,
                                           207, 11, 246, 225,
                                           121, 210, 135, 243,
                                           65, 56, 78, 181,
                                           214, 211, 25, 117,
                                           37, 173, 107, 232,
                                           230, 223, 1, 22,
                                           3, 41, 53, 105,
                                           143, 153, 160, 158,
                                           38, 80, 115, 209,
                                           214, 195, 44, 39,
                                           69, 145, 191, 29,
                                           10, 32, 173, 103,
                                           203, 169, 33, 188];

#[test]
fn hash() {
    ::test_init();

    let hash = sha2::hash256(TEST_MESSAGE).unwrap();
    assert!(hash.len() == sha2::SHA256_BYTES);
    assert!(hash == TEST_H1);
    let hash1 = sha2::hash512(TEST_MESSAGE).unwrap();
    assert!(hash1.len() == sha2::SHA512_BYTES);
    assert!(secmem::memcmp(hash1, &TEST_H2) == 0);
    secmem::free(hash);
    secmem::free(hash1);
}

#[test]
fn init() {
    ::test_init();

    let state_size = sha2::state_size_256().unwrap();
    let mut state = secmem::malloc(state_size);
    let _ = sha2::init256(&mut state).unwrap();
    assert!(state.len() == state_size);

    let state1_size = sha2::state_size_512().unwrap();
    let mut state1 = secmem::malloc(state1_size);
    let _ = sha2::init512(&mut state1).unwrap();
    assert!(state1.len() == state1_size);
}

#[test]
fn update() {
    ::test_init();

    let state_size = sha2::state_size_256().unwrap();
    let mut state = secmem::malloc(state_size);
    let _ = sha2::init256(&mut state).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    assert!(state.len() == state_size);

    let state1_size = sha2::state_size_512().unwrap();
    let mut state1 = secmem::malloc(state1_size);
    let _ = sha2::init512(&mut state1).unwrap();
    let _ = sha2::update512(&mut state1, TEST_MESSAGE).unwrap();
    let _ = sha2::update512(&mut state1, TEST_MESSAGE).unwrap();
    assert!(state1.len() == state1_size);
}

#[test]
fn finalize() {
    ::test_init();

    let state_size = sha2::state_size_256().unwrap();
    let mut state = secmem::malloc(state_size);
    let _ = sha2::init256(&mut state).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    let hash = sha2::finalize256(&mut state).unwrap();
    assert!(hash == TEST_H3);

    let state1_size = sha2::state_size_512().unwrap();
    let mut state1 = secmem::malloc(state1_size);
    let _ = sha2::init512(&mut state1).unwrap();
    let _ = sha2::update512(&mut state1, TEST_MESSAGE).unwrap();
    let _ = sha2::update512(&mut state1, TEST_MESSAGE).unwrap();
    let hash1 = sha2::finalize512(&mut state1).unwrap();
    assert!(secmem::memcmp(hash1, &TEST_H4) == 0);
}
