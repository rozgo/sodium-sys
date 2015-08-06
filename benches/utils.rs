use sodium_sys::utils;
use test::Bencher;

#[bench]
fn bench_memzero(b: &mut Bencher) {
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    b.iter(|| { utils::memzero(&v) })
}

#[bench]
fn bench_memcmp(b: &mut Bencher) {
    let v0 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v1 = [0, 1, 2, 3, 4, 5, 6, 7];
    b.iter(|| { utils::memcmp(&v0, &v1) });
}

#[bench]
fn bench_bin2hex(b: &mut Bencher) {
    let v = [0, 1, 254, 255];
    b.iter(|| { utils::bin2hex(&v) });
}

#[bench]
fn bench_hex2bin_noignore(b: &mut Bencher) {
    let hex = "0001feff";
    let mut output = Vec::new();
    b.iter(|| { utils::hex2bin(hex.to_string(), &mut output, None) });
}

#[bench]
fn bench_hex2bin_ignore(b: &mut Bencher) {
    let hex = "00:01:fe:ff";
    let mut output = Vec::new();
    b.iter(|| { utils::hex2bin(hex.to_string(), &mut output, Some(String::from(":"))) });
}

#[bench]
fn bench_hex2bin_multiignore(b: &mut Bencher) {
    let hex = "00 01:fe ff";
    let mut output = Vec::new();
    b.iter(|| { utils::hex2bin(hex.to_string(), &mut output, Some(String::from(": "))) });
}

#[bench]
fn bench_mlock_munlock(b: &mut Bencher) {
    ::test_init();
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    b.iter(|| { utils::mlock(&v); utils::munlock(&v) });
}

#[bench]
fn bench_malloc_free(b: &mut Bencher) {
    ::test_init();
    b.iter(|| {
        let mut v = utils::malloc(64);
        utils::free(&mut v)
    });
}

#[bench]
fn bench_allocarray_free(b: &mut Bencher) {
    ::test_init();
    let count = 2;
    let size = 16;

    b.iter(|| {
        let mut v = utils::allocarray(count, size);
        utils::free(&mut v);
    });
}

#[bench]
fn bench_malloc_noaccess_free(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut v = utils::malloc(64);
        utils::mprotect_noaccess(&mut v);
        utils::free(&mut v)
    });
}

#[bench]
fn bench_malloc_readonly_free(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut v = utils::malloc(64);
        utils::mprotect_readonly(&mut v);
        utils::free(&mut v)
    });
}

#[bench]
fn bench_malloc_noaccess_readwrite_free(b: &mut Bencher) {
    ::test_init();

    b.iter(|| {
        let mut v = utils::malloc(64);
        utils::mprotect_noaccess(&mut v);
        utils::mprotect_readwrite(&mut v);
        utils::free(&mut v)
    });
}
