use sodium_sys::crypto::utils::secmem;
use sodium_sys::crypto::hash::passhash;
use test::Bencher;

const TEST_SALT: [u8; passhash::SALTBYTES] = [0; passhash::SALTBYTES];

#[bench]
fn bench_keygen(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut key = passhash::keygen(b"test",
                                       64,
                                       &TEST_SALT,
                                       None,
                                       None).unwrap();
        secmem::free(&mut key);
    });
}

#[bench]
fn bench_keygen_sensitive(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut key = passhash::keygen(b"test",
                                       64,
                                       &TEST_SALT,
                                       Some(passhash::OPSLIMIT_SENSITIVE),
                                       Some(passhash::MEMLIMIT_SENSITIVE)).unwrap();
        secmem::free(&mut key);
    });
}

#[bench]
fn bench_pwhash(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = passhash::pwhash(b"test", None, None).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_pwhash_sensitive(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut hash = passhash::pwhash(b"test",
                                        Some(passhash::OPSLIMIT_SENSITIVE),
                                        Some(passhash::MEMLIMIT_SENSITIVE)).unwrap();
        secmem::free(&mut hash);
    });
}

#[bench]
fn bench_pwhash_verify(b: &mut Bencher) {
    ::test_init();

    let mut hash = passhash::pwhash(b"test", None, None).unwrap();

    b.iter(|| {
        let _ = passhash::pwhash_verify(b"test", hash);
    });

    secmem::free(&mut hash);
}

#[bench]
fn bench_pwhash_verify_sensitive(b: &mut Bencher) {
    ::test_init();

    let mut hash = passhash::pwhash(b"test",
                                    Some(passhash::OPSLIMIT_SENSITIVE),
                                    Some(passhash::MEMLIMIT_SENSITIVE)).unwrap();

    b.iter(|| {
        let _ = passhash::pwhash_verify(b"test", hash);
    });

    secmem::free(&mut hash);
}
