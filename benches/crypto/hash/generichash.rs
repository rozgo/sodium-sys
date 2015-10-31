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

#[bench]
fn bench_init(b: &mut Bencher) {
    let state_size = generichash::state_size().unwrap();
    let mut state = secmem::malloc(state_size);
    let outlen = 64;

    b.iter(|| {
        let _ = generichash::init(&mut state, outlen, None).unwrap();
    });

    secmem::free(&mut state);
}

#[bench]
fn bench_update(b: &mut Bencher) {
    let state_size = generichash::state_size().unwrap();
    let mut state = secmem::malloc(state_size);
    let outlen = 64;
    let _ = generichash::init(&mut state, outlen, None).unwrap();

    b.iter(|| {
        let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
    });

    secmem::free(&mut state);
}

#[bench]
fn bench_finalize(b: &mut Bencher) {
    let state_size = generichash::state_size().unwrap();
    let mut state = secmem::malloc(state_size);
    let outlen = 64;

    b.iter(|| {
        let _ = generichash::init(&mut state, outlen, None).unwrap();
        let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
        let _ = generichash::update(&mut state, TEST_MESSAGE).unwrap();
        let mut hash = generichash::finalize(&mut state, outlen).unwrap();
        secmem::free(&mut hash);
    });

    secmem::free(&mut state);
}
