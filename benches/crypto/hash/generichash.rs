use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::generichash;
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";
const TEST_KEY: [u8; generichash::KEYBYTES] = [0; generichash::KEYBYTES];

#[bench]
fn bench_hash_no_key_no_size(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = generichash::hash(TEST_MESSAGE, None, None).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_no_key_min_size(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = generichash::hash(TEST_MESSAGE,
                                         Some(generichash::BYTES_MIN),
                                         None).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_no_key_max_size(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = generichash::hash(TEST_MESSAGE,
                                         Some(generichash::BYTES_MAX),
                                         None).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_key_no_size(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = generichash::hash(TEST_MESSAGE,
                                         None,
                                         Some(&TEST_KEY)).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_key_min_size(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = generichash::hash(TEST_MESSAGE,
                                         Some(generichash::BYTES_MIN),
                                         Some(&TEST_KEY)).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_key_max_size(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = generichash::hash(TEST_MESSAGE,
                                         Some(generichash::BYTES_MAX),
                                         Some(&TEST_KEY)).unwrap();
        secmem::free(&mut hash);
    });
}
