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

#[test]
fn hash_no_key_no_size() {
    ::test_init();

    let hash = generichash::hash(TEST_MESSAGE, None, None).unwrap();
    println!("{:?}", hash);
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
