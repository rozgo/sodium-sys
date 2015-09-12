use sodium_sys::utils;
use sodium_sys::crypto::sign;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_MYSECRET_KEY: [u8; sign::SECRETKEYBYTES] = [0; sign::SECRETKEYBYTES];
const TEST_SIGNEDMESSAGE: [u8; sign::BYTES+4] = [150, 83, 113, 5,
                                                 97, 195, 22, 155,
                                                 122, 149, 119, 160,
                                                 25, 85, 22, 157,
                                                 239, 24, 63, 179,
                                                 174, 40, 46, 5,
                                                 190, 198, 36, 130,
                                                 110, 37, 91, 12,
                                                 247, 210, 217, 138,
                                                 216, 38, 85, 132,
                                                 206, 165, 140, 108,
                                                 105, 111, 243, 15,
                                                 219, 186, 34, 39,
                                                 187, 65, 16, 161,
                                                 237, 41, 152, 22,
                                                 36, 138, 140, 9,
                                                 116, 101, 115, 116];
#[test]
fn sign() {
    ::test_init();

    let signedmessage = sign::sign(TEST_MESSAGE, &TEST_MYSECRET_KEY).unwrap();
    assert!(utils::memcmp(signedmessage, &TEST_SIGNEDMESSAGE) == 0);
    utils::free(signedmessage);
}
