//! Byte sequence verification.
use libc::{c_int, c_uchar, size_t};

pub const crypto_verify_16_BYTES: size_t = 16;
pub const crypto_verify_32_BYTES: size_t = 32;
pub const crypto_verify_64_BYTES: size_t = 64;

extern "C" {
    fn crypto_verify_16_bytes() -> size_t;
    fn crypto_verify_16(x: *const c_uchar,
                        y: *const c_uchar) -> c_int;
    fn crypto_verify_32_bytes() -> size_t;
    fn crypto_verify_32(x: *const c_uchar,
                        y: *const c_uchar) -> c_int;
    fn crypto_verify_64_bytes() -> size_t;
    fn crypto_verify_64(x: *const c_uchar,
                        y: *const c_uchar) -> c_int;
}

pub fn verify_16_bytes() -> size_t {
    unsafe {
        crypto_verify_16_bytes()
    }
}

pub fn verify_16(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_16(a.as_ptr(), b.as_ptr())
    }
}

pub fn verify_32_bytes() -> size_t {
    unsafe {
        crypto_verify_32_bytes()
    }
}

pub fn verify_32(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_32(a.as_ptr(), b.as_ptr())
    }
}

pub fn verify_64_bytes() -> size_t {
    unsafe {
        crypto_verify_64_bytes()
    }
}

pub fn verify_64(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_64(a.as_ptr(), b.as_ptr())
    }
}
