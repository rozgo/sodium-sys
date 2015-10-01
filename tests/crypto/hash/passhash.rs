use sodium_sys::crypto::utils::{randombytes, secmem};
use sodium_sys::crypto::hash::passhash;

const TEST_SALT: [u8; passhash::SALTBYTES] = [0; passhash::SALTBYTES];
const TEST_HASH: [u8; 64] = [113, 193, 200, 93,
                             142, 121, 213, 140,
                             67, 245, 67, 70,
                             230, 55, 171, 28,
                             208, 250, 130, 13,
                             11, 114, 54, 97,
                             202, 93, 92, 178,
                             64, 54, 175, 207,
                             153, 37, 92, 45,
                             72, 15, 83, 123,
                             50, 205, 186, 23,
                             13, 85, 125, 198,
                             125, 10, 35, 243,
                             254, 108, 130, 210,
                             124, 229, 152, 137,
                             154, 211, 62, 16];
const TEST_HASH1: [u8; 64] = [47, 107, 42, 1,
                              2, 133, 211, 70,
                              154, 150, 130, 132,
                              102, 202, 46, 8,
                              158, 136, 130, 53,
                              117, 144, 160, 246,
                              148, 71, 25, 132,
                              135, 209, 135, 169,
                              85, 48, 123, 187,
                              180, 127, 62, 171,
                              201, 187, 233, 170,
                              77, 52, 165, 212,
                              134, 150, 174, 130,
                              244, 85, 214, 38,
                              76, 32, 53, 97,
                              159, 36, 2, 89];
#[test]
fn keygen() {
    ::test_init();

    let key = passhash::keygen(b"test", 64, &TEST_SALT, None, None).unwrap();
    assert!(key.len() == 64);
    assert!(secmem::memcmp(key, &TEST_HASH) == 0);
}

#[test]
fn keygen_sensitive() {
    ::test_init();

    let mut salt = [0; passhash::SALTBYTES];
    randombytes::random_byte_array(&mut salt);
    let key = passhash::keygen(b"test",
                               64,
                               &TEST_SALT,
                               Some(passhash::OPSLIMIT_SENSITIVE),
                               Some(passhash::MEMLIMIT_SENSITIVE)).unwrap();
    assert!(key.len() == 64);
    assert!(secmem::memcmp(key, &TEST_HASH1) == 0);
}
