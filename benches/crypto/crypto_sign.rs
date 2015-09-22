use sodium_sys::utils;
use sodium_sys::crypto::sign;
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_SEED: [u8; sign::SEEDBYTES] = [0; sign::SEEDBYTES];
const TEST_SIGNEDMESSAGE: [u8; sign::BYTES+4] = [150, 83, 113, 5,
                                                 97, 195, 22, 155,
                                                 122, 149, 119, 160,
                                                 25, 85, 22, 157,
                                                 239, 24, 63, 179,
                                                 174, 40, 46, 5,
                                                 190, 198, 36, 130,
                                                 110, 37, 91, 12,
                                                 62, 237, 227, 236,
                                                 254, 5, 79, 181,
                                                 164, 14, 254, 174,
                                                 240, 64, 175, 170,
                                                 69, 34, 12, 205,
                                                 123, 248, 65, 59,
                                                 165, 49, 242, 79,
                                                 63, 134, 146, 9,
                                                 116, 101, 115, 116];

const TEST_SIGNATURE: [u8; sign::BYTES] = [150, 83, 113, 5,
                                           97, 195, 22, 155,
                                           122, 149, 119, 160,
                                           25, 85, 22, 157,
                                           239, 24, 63, 179,
                                           174, 40, 46, 5,
                                           190, 198, 36, 130,
                                           110, 37, 91, 12,
                                           62, 237, 227, 236,
                                           254, 5, 79, 181,
                                           164, 14, 254, 174,
                                           240, 64, 175, 170,
                                           69, 34, 12, 205,
                                           123, 248, 65, 59,
                                           165, 49, 242, 79,
                                           63, 134, 146, 9];

#[bench]
fn bench_keypair(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut keypair = sign::keypair::KeyPair::new().unwrap();
    });
}

#[bench]
fn bench_keypair_seed(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    });
}

#[bench]
fn bench_sign(b: &mut Bencher) {
    ::test_init();
    let mut keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();

    b.iter(|| {
        let mut sm = sign::sign(TEST_MESSAGE,
                                keypair.sk_bytes_mut()).unwrap();
        utils::free(&mut sm);
    });
}

#[bench]
fn bench_open(b: &mut Bencher) {
    ::test_init();
    let mut keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_pk();

    b.iter(|| {
        let mut m = sign::open(TEST_SIGNEDMESSAGE,
                               keypair.pk_bytes_mut()).unwrap();
        utils::free(&mut m);
    });
}

#[bench]
fn bench_sign_detached(b: &mut Bencher) {
    ::test_init();
    let mut keypair = sign::keypair::KeyPair::new_with_seed(&TEST_SEED).unwrap();
    keypair.activate_sk();

    b.iter(|| {
        let mut s = sign::sign_detached(TEST_MESSAGE,
                                        keypair.sk_bytes_mut()).unwrap();
        utils::free(&mut s);
    });
}
