use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::generichash;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_H1: [u8; generichash::BYTES] = [146, 139, 32, 54,
                                           105, 67, 226, 175,
                                           209, 30, 188, 14,
                                           174, 46, 83, 169,
                                           59, 241, 119, 164,
                                           252, 243, 91, 204,
                                           100, 213, 3, 112,
                                           78, 101, 226, 2];
const TEST_H2: [u8; generichash::BYTES_MIN] = [68, 168, 153, 93,
                                               213, 11, 102, 87,
                                               160, 55, 167, 131,
                                               147, 4, 83, 91];
const TEST_H3: [u8; generichash::BYTES_MAX] = [167, 16, 121, 212,
                                               40, 83, 222, 162,
                                               110, 69, 48, 4,
                                               51, 134, 112, 165,
                                               56, 20, 183, 129,
                                               55, 255, 190, 208,
                                               118, 3, 164, 29,
                                               118, 164, 131, 170,
                                               155, 195, 59, 88,
                                               47, 119, 211, 10,
                                               101, 230, 242, 154,
                                               137, 108, 4, 17,
                                               243, 131, 18, 225,
                                               214, 110, 11, 241,
                                               99, 134, 200, 106,
                                               137, 190, 165, 114];
const TEST_KEY: [u8; generichash::KEYBYTES] = [0; generichash::KEYBYTES];
const TEST_H4: [u8; generichash::BYTES] = [245, 142, 71, 203,
                                           141, 196, 189, 128,
                                           145, 234, 254, 5,
                                           187, 118, 237, 224,
                                           226, 89, 131, 96,
                                           37, 10, 12, 41,
                                           192, 71, 56, 117,
                                           207, 254, 163, 108];
const TEST_H5: [u8; generichash::BYTES_MIN] = [32, 90, 8, 102,
                                               166, 166, 223, 50,
                                               47, 12, 22, 84,
                                               146, 158, 221, 187];
const TEST_H6: [u8; generichash::BYTES_MAX] = [148, 209, 218, 183,
                                               121, 232, 14, 169,
                                               56, 218, 210, 97,
                                               82, 158, 146, 36,
                                               209, 124, 214, 232,
                                               183, 181, 7, 11,
                                               43, 0, 201, 93,
                                               246, 149, 22, 189,
                                               195, 46, 133, 212,
                                               108, 250, 214, 155,
                                               34, 107, 116, 220,
                                               86, 106, 232, 174,
                                               37, 243, 190, 129,
                                               209, 22, 13, 127,
                                               60, 139, 249, 183,
                                               42, 6, 218, 59];
const TEST_H7: [u8; 64] = [55, 42, 83, 185,
                           95, 70, 231, 117,
                           185, 115, 3, 30,
                           64, 184, 68, 242,
                           67, 137, 101, 112,
                           25, 247, 183, 84,
                           10, 159, 4, 150,
                           244, 234, 212, 162,
                           228, 176, 80, 144,
                           150, 100, 97, 31,
                           176, 244, 183, 199,
                           233, 44, 60, 4,
                           200, 71, 135, 190,
                           127, 107, 142, 223,
                           123, 246, 188, 49,
                           133, 107, 108, 118];
#[test]
fn hash_no_key_no_size() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE, None, None).unwrap();
    assert!(hash.len() == generichash::BYTES);
    assert!(hash == TEST_H1);
    secmem::free(hash);
}

#[test]
fn hash_no_key_min_size() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE,
                                 Some(generichash::BYTES_MIN),
                                 None).unwrap();
    assert!(hash.len() == generichash::BYTES_MIN);
    assert!(hash == TEST_H2);
}

#[test]
#[should_panic]
fn hash_no_key_less_than_min() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE,
                                 Some(generichash::BYTES_MIN - 1),
                                 None).unwrap();
    assert!(hash.len() == generichash::BYTES_MIN);
    assert!(hash == TEST_H2);
}

#[test]
fn hash_no_key_max_size() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE,
                                 Some(generichash::BYTES_MAX),
                                 None).unwrap();
    assert!(hash.len() == generichash::BYTES_MAX);
    assert!(secmem::memcmp(hash, &TEST_H3) == 0);
}

#[test]
#[should_panic]
fn hash_no_key_more_than_max() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE,
                                 Some(generichash::BYTES_MAX + 1),
                                 None).unwrap();
    assert!(hash.len() == generichash::BYTES_MAX);
    assert!(secmem::memcmp(hash, &TEST_H3) == 0);
}

#[test]
fn hash_key_no_size() {
    let hash = generichash::hash(TEST_MESSAGE, None, Some(&TEST_KEY)).unwrap();
    assert!(hash.len() == generichash::BYTES);
    assert!(hash == TEST_H4);

    let hash1 = generichash::hash(TEST_MESSAGE, None, Some(&TEST_KEY)).unwrap();
    assert!(hash == hash1);
}

#[test]
fn hash_key_min_size() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE,
                                 Some(generichash::BYTES_MIN),
                                 Some(&TEST_KEY)).unwrap();
    assert!(hash.len() == generichash::BYTES_MIN);
    assert!(hash == TEST_H5);
}

#[test]
fn hash_key_max_size() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE,
                                 Some(generichash::BYTES_MAX),
                                 Some(&TEST_KEY)).unwrap();
    assert!(hash.len() == generichash::BYTES_MAX);
    assert!(secmem::memcmp(hash, &TEST_H6) == 0);
}

#[test]
fn state_size() {
    ::test_init();

    let state_size = generichash::state_size().unwrap();
    let state = secmem::malloc(state_size);
    assert!(state.len() == state_size);
}

#[test]
fn init() {
    ::test_init();

    let state_size = generichash::state_size().unwrap();
    let mut state = secmem::malloc(state_size);
    let outlen = 64;
    let _ = generichash::init(&mut state, outlen, None).unwrap();
    assert!(state.len() == state_size);
}

#[test]
fn update() {
    ::test_init();

    let state_size = generichash::state_size().unwrap();
    let mut state = secmem::malloc(state_size);
    let outlen = 64;
    let _ = generichash::init(&mut state, outlen, None).unwrap();
    let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
    let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
    assert!(state.len() == state_size);
}

#[test]
fn finalize() {
    ::test_init();

    let state_size = generichash::state_size().unwrap();
    let mut state = secmem::malloc(state_size);
    let outlen = 64;
    let _ = generichash::init(&mut state, outlen, None).unwrap();
    let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
    let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
    let hash = generichash::finalize(&mut state, outlen).unwrap();
    assert!(secmem::memcmp(hash, &TEST_H7) == 0);
}
