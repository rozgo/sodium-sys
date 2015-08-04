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
