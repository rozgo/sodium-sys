use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::symmetrickey::authenc;
use test::Bencher;

const TEST_KEY: [u8; authenc::KEYBYTES] = [0; authenc::KEYBYTES];
const TEST_NONCE: [u8; authenc::NONCEBYTES] = [0; authenc::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147, 246, 123, 253, 41,
                                   159, 169, 32, 114, 64, 251, 167, 179,
                                   178, 91, 200, 139];
const TEST_DET_CIPHERTEXT: [u8; 4] = [178, 91, 200, 139];
const TEST_NACL_CIPHERTEXT: [u8; 36] = [0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        0, 0, 0, 0,
                                        175, 153, 180, 147,
                                        246, 123, 253, 41,
                                        159, 169, 32, 114,
                                        64, 251, 167, 179,
                                        178, 91, 200, 139];
const TEST_MAC: [u8; authenc::MACBYTES] = [175, 153, 180, 147,
                                             246, 123, 253, 41,
                                             159, 169, 32, 114,
                                             64, 251, 167, 179];

#[bench]
fn bench_encrypt(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = authenc::encrypt(TEST_MESSAGE,
                                              &TEST_KEY,
                                              &TEST_NONCE).unwrap();
        secmem::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = authenc::open(&TEST_CIPHERTEXT,
                                        &TEST_KEY,
                                        &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}

#[bench]
fn bench_encrypt_detached(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let (mut ciphertext, mut mac) =
            authenc::encrypt_detached(TEST_MESSAGE,
                                      &TEST_KEY,
                                      &TEST_NONCE).unwrap();
        secmem::free(&mut ciphertext);
        secmem::free(&mut mac);
    });
}

#[bench]
fn bench_open_detached(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = authenc::open_detached(&TEST_DET_CIPHERTEXT,
                                                 &TEST_MAC,
                                                 &TEST_KEY,
                                                 &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}

#[bench]
fn bench_encrypt_nacl(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = authenc::encrypt_nacl(TEST_MESSAGE,
                                                   &TEST_KEY,
                                                   &TEST_NONCE).unwrap();
        secmem::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open_nacl(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = authenc::open_nacl(&TEST_NACL_CIPHERTEXT,
                                             &TEST_KEY,
                                             &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}
