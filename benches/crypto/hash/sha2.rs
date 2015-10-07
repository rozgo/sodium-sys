use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::sha2;
use test::Bencher;

const TEST_MESSAGE: &'static [u8] = b"test";

#[bench]
fn bench_hash_256(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = sha2::hash256(TEST_MESSAGE).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_hash_512(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = sha2::hash512(TEST_MESSAGE).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_init_256(b: &mut Bencher) {
    ::test_init();
    let state_size = sha2::state_size_256().unwrap();
    let mut state = secmem::malloc(state_size);

    b.iter(|| {
        let _ = sha2::init256(&mut state).unwrap();
    });
}

#[bench]
fn bench_init_512(b: &mut Bencher) {
    ::test_init();
    let state_size = sha2::state_size_512().unwrap();
    let mut state = secmem::malloc(state_size);

    b.iter(|| {
        let _ = sha2::init512(&mut state).unwrap();
    });
}

#[bench]
fn bench_update_256(b: &mut Bencher) {
    ::test_init();
    let state_size = sha2::state_size_256().unwrap();
    let mut state = secmem::malloc(state_size);
    let _ = sha2::init256(&mut state).unwrap();

    b.iter(|| {
        let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
    });
}

#[bench]
fn bench_update_512(b: &mut Bencher) {
    ::test_init();
    let state_size = sha2::state_size_512().unwrap();
    let mut state = secmem::malloc(state_size);
    let _ = sha2::init512(&mut state).unwrap();

    b.iter(|| {
        let _ = sha2::update512(&mut state, TEST_MESSAGE).unwrap();
    });
}

#[bench]
fn bench_finalize_256(b: &mut Bencher) {
    ::test_init();
    let state_size = sha2::state_size_256().unwrap();
    let mut state = secmem::malloc(state_size);

    b.iter(|| {
        let _ = sha2::init256(&mut state).unwrap();
        let _ = sha2::update256(&mut state, TEST_MESSAGE).unwrap();
        let hash = sha2::finalize256(&mut state).unwrap();
        secmem::free(hash);
    });
}

#[bench]
fn bench_finalize_512(b: &mut Bencher) {
    ::test_init();
    let state_size = sha2::state_size_512().unwrap();
    let mut state = secmem::malloc(state_size);

    b.iter(|| {
        let _ = sha2::init512(&mut state).unwrap();
        let _ = sha2::update512(&mut state, TEST_MESSAGE).unwrap();
        let hash = sha2::finalize512(&mut state).unwrap();
        secmem::free(hash);
    });
}
