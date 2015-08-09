use sodium_sys::utils;

#[test]
fn memzero() {
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    utils::memzero(&v);
    assert!(v == [0; 8]);
}

#[test]
fn memcmp() {
    let v0 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v1 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v2 = [7, 6, 5, 4, 3, 2, 1, 0];
    assert!(utils::memcmp(&v0,&v1) == 0);
    assert!(utils::memcmp(&v0,&v2) == -1);
    assert!(utils::memcmp(&v1,&v2) == -1);
}

#[test]
fn bin2hex() {
    let v = [0, 1, 254, 255];
    assert!(utils::bin2hex(&v).unwrap() == "0001feff");
}

#[test]
fn hex2bin() {
    let hex = String::from("0001feff");
    let mut output = Vec::new();
    assert!(utils::hex2bin(hex, &mut output, None) == 0);
    assert!(output == [0, 1, 254, 255]);
    let hex = String::from("00:01:fe:ff");
    let ignore = Some(String::from(":"));
    let mut output = Vec::new();
    assert!(utils::hex2bin(hex, &mut output, ignore) == 0);
    assert!(output == [0, 1, 254, 255]);
    let hex = String::from("00 01 fe ff");
    let ignore = Some(String::from(" "));
    let mut output = Vec::new();
    assert!(utils::hex2bin(hex, &mut output, ignore) == 0);
    assert!(output == [0, 1, 254, 255]);
    let hex = String::from("00 01:fe ff");
    let ignore = Some(String::from(": "));
    let mut output = Vec::new();
    assert!(utils::hex2bin(hex, &mut output, ignore) == 0);
    assert!(output == [0, 1, 254, 255]);
}

#[test]
fn mlock_munlock() {
    ::test_init();
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    assert!(utils::mlock(&v) == 0);
    assert!(utils::munlock(&v) == 0);
    assert!(v == [0; 8]);
}

#[test]
fn malloc_free() {
    ::test_init();
    let mut v = utils::malloc(64);
    v[0] = 1;
    assert!(v.len() == 64);
    assert!(v[0] == 1);
    utils::free(&mut v);
}

#[test]
fn allocarray_free() {
    ::test_init();
    let count = 2;
    let size = 16;
    let mut v = utils::allocarray(count, size);
    v[0] = 1;
    v[31] = 255;
    assert!(v.len() == (count * size) as usize);
    assert!(v[0] == 1);
    assert!(v[31] == 255);
    utils::free(&mut v);
}

#[test]
fn malloc_noaccess_free() {
    ::test_init();
    let mut v = utils::malloc(64);
    v[0] = 1;
    assert!(v.len() == 64);
    assert!(v[0] == 1);
    utils::mprotect_noaccess(&mut v);
    // assert!(v[0] == 1);  // If you uncomment this line the program will fail (no read).
    // v[1] = 1;            // If you uncomment this line the program will fail (no write).
    utils::free(&mut v);
}

#[test]
fn malloc_readonly_free() {
    ::test_init();
    let mut v = utils::malloc(64);
    v[0] = 1;
    assert!(v.len() == 64);
    assert!(v[0] == 1);
    utils::mprotect_readonly(&mut v);
    assert!(v[0] == 1);
    // v[1] = 1;  // If you uncomment this line the program will fail (no write).
    utils::free(&mut v);
}

#[test]
fn malloc_noaccess_readwrite_free() {
    ::test_init();
    let mut v = utils::malloc(64);
    v[0] = 1;
    assert!(v.len() == 64);
    assert!(v[0] == 1);
    utils::mprotect_noaccess(&mut v);
    // assert!(v[0] == 1);  // If you uncomment this line the program will fail (no read).
    // v[1] = 1;            // If you uncomment this line the program will fail (no write).
    utils::mprotect_readwrite(&mut v);
    assert!(v[0] == 1);
    v[1] = 1;
    assert!(v[1] == 1);
    utils::free(&mut v);
}

#[cfg(feature = "latest")]
#[test]
fn increment() {
    let mut nonce = [1];
    utils::increment(&mut nonce);
    assert!(nonce == [2]);
}
