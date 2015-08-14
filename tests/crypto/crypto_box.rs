use sodium_sys::utils;
use sodium_sys::crypto::{box_, keypair, nonce};

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [1, 242, 22, 45,
                                   228, 36, 202, 193,
                                   131, 56, 182, 176,
                                   89, 5, 47, 88,
                                   243, 16, 189, 25];

#[test]
fn seal() {
    ::test_init();

    // Create a keypair of all 0's.
    let keypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
                                        box_::PUBLICKEYBYTES).unwrap();
    utils::mprotect_readwrite(keypair.sk_bytes());
    utils::mprotect_readwrite(keypair.pk_bytes());
    utils::memzero(keypair.sk_bytes_mut());
    utils::memzero(keypair.pk_bytes_mut());

    // Create a nonce of all 0's.
    let nonce = nonce::Nonce::new(box_::NONCEBYTES);
    nonce.activate();

    utils::memzero(nonce.bytes_mut());

    let ciphertext = box_::seal(TEST_MESSAGE, keypair, nonce).unwrap();
    println!("{:?}", ciphertext);
    assert!(ciphertext == TEST_CIPHERTEXT);
    utils::free(ciphertext);
}
