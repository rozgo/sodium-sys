pub const crypto_verify_16_BYTES: ::libc::size_t = 16;
pub const crypto_verify_32_BYTES: ::libc::size_t = 32;
pub const crypto_verify_64_BYTES: ::libc::size_t = 64;

extern "C" {
    fn crypto_verify_16_bytes() -> ::libc::size_t;
    fn crypto_verify_16(x: *const ::libc::c_uchar,
                        y: *const ::libc::c_uchar) -> ::libc::c_int;
    fn crypto_verify_32_bytes() -> ::libc::size_t;
    fn crypto_verify_32(x: *const ::libc::c_uchar,
                        y: *const ::libc::c_uchar) -> ::libc::c_int;
    fn crypto_verify_64_bytes() -> ::libc::size_t;
    fn crypto_verify_64(x: *const ::libc::c_uchar,
                        y: *const ::libc::c_uchar) -> ::libc::c_int;
}

pub fn verify_16_bytes() -> ::libc::size_t {
    unsafe {
        crypto_verify_16_bytes()
    }
}

pub fn verify_16(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_16(a.as_ptr(), b.as_ptr())
    }
}

pub fn verify_32_bytes() -> ::libc::size_t {
    unsafe {
        crypto_verify_32_bytes()
    }
}

pub fn verify_32(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_32(a.as_ptr(), b.as_ptr())
    }
}

pub fn verify_64_bytes() -> ::libc::size_t {
    unsafe {
        crypto_verify_64_bytes()
    }
}

pub fn verify_64(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_64(a.as_ptr(), b.as_ptr())
    }
}

#[test]
fn test_verify_16_bytes() {
    assert!(verify_16_bytes() == crypto_verify_16_BYTES);
}

#[test]
fn test_verify_32_bytes() {
    assert!(verify_32_bytes() == crypto_verify_32_BYTES);
}

#[test]
fn test_verify_64_bytes() {
    assert!(verify_64_bytes() == crypto_verify_64_BYTES);
}

#[test]
fn test_verify_16() {
    let a = [0; 16];
    let b = [0; 16];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(verify_16(&a, &b) == 0);
    assert!(verify_16(&a, &c) == -1);
}

#[test]
fn test_verify_32() {
    let a = [0; 32];
    let b = [0; 32];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(verify_32(&a, &b) == 0);
    assert!(verify_32(&a, &c) == -1);
}

#[test]
fn test_verify_64() {
    let a = [0; 64];
    let b = [0; 64];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(verify_64(&a, &b) == 0);
    assert!(verify_64(&a, &c) == -1);
}
