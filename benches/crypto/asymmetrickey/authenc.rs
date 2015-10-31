use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::asymmetrickey::authenc;
use test::Bencher;

const TEST_SECRET_KEY: [u8; authenc::SECRETKEYBYTES] = [0; authenc::SECRETKEYBYTES];
const TEST_PUBLIC_KEY: [u8; authenc::PUBLICKEYBYTES] = [0; authenc::PUBLICKEYBYTES];
const TEST_SSK: [u8; authenc::BEFORENMBYTES] = [0; authenc::BEFORENMBYTES];
const TEST_NONCE: [u8; authenc::NONCEBYTES] = [0; authenc::NONCEBYTES];
const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_MAC: [u8; authenc::MACBYTES] = [1, 242, 22, 45,
                                           228, 36, 202, 193,
                                           131, 56, 182, 176,
                                           89, 5, 47, 88];
const TEST_SSK_MAC: [u8; authenc::MACBYTES] = [175, 153, 180, 147,
                                               246, 123, 253, 41,
                                               159, 169, 32, 114,
                                               64, 251, 167, 179];
const TEST_CIPHERTEXT: [u8; 20] = [1, 242, 22, 45,
                                   228, 36, 202, 193,
                                   131, 56, 182, 176,
                                   89, 5, 47, 88,
                                   243, 16, 189, 25];
const TEST_DET_CIPHERTEXT: [u8; 4] = [243, 16, 189, 25];
const TEST_SSK_CIPHERTEXT: [u8; 20] = [175, 153, 180, 147,
                                       246, 123, 253, 41,
                                       159, 169, 32, 114,
                                       64, 251, 167, 179,
                                       178, 91, 200, 139];
const TEST_SSK_DET_CIPHERTEXT: [u8; 4] = [178, 91, 200, 139];

#[bench]
fn bench_seal(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = authenc::seal(TEST_MESSAGE,
                                           &TEST_PUBLIC_KEY,
                                           &TEST_SECRET_KEY,
                                           &TEST_NONCE).unwrap();
        secmem::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = authenc::open(&TEST_CIPHERTEXT,
                                        &TEST_PUBLIC_KEY,
                                        &TEST_SECRET_KEY,
                                        &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}

#[bench]
fn bench_seal_detached(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let (mut ciphertext, mut mac) =
            authenc::seal_detached(TEST_MESSAGE,
                                   &TEST_PUBLIC_KEY,
                                   &TEST_SECRET_KEY,
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
                                                 &TEST_PUBLIC_KEY,
                                                 &TEST_SECRET_KEY,
                                                 &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}

#[bench]
fn bench_seal_with_ssk(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut ciphertext = authenc::seal_with_ssk(TEST_MESSAGE,
                                                    &TEST_SSK,
                                                    &TEST_NONCE).unwrap();
        secmem::free(&mut ciphertext);
    });
}

#[bench]
fn bench_open_with_ssk(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = authenc::open_with_ssk(&TEST_SSK_CIPHERTEXT,
                                                 &TEST_SSK,
                                                 &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}

#[bench]
fn bench_seal_detached_with_ssk(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let (mut ciphertext, mut mac) =
            authenc::seal_detached_with_ssk(TEST_MESSAGE,
                                            &TEST_SSK,
                                            &TEST_NONCE).unwrap();
        secmem::free(&mut ciphertext);
        secmem::free(&mut mac);
    });
}

#[bench]
fn bench_open_detached_with_ssk(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut message = authenc::open_detached_with_ssk(&TEST_SSK_DET_CIPHERTEXT,
                                                          &TEST_SSK_MAC,
                                                          &TEST_SSK,
                                                          &TEST_NONCE).unwrap();
        secmem::free(&mut message);
    });
}
