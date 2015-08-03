// sodium/crypto_verify_16.h
#[allow(non_upper_case_globals)]
pub const crypto_verify_16_BYTES: ::libc::size_t = 16;

extern "C" {
    fn crypto_verify_16_bytes() -> ::libc::size_t;
    fn crypto_verify_16(x: *const ::libc::c_uchar,
                        y: *const ::libc::c_uchar) -> ::libc::c_int;
}

pub fn ss_verify_16_bytes() -> ::libc::size_t {
    unsafe {
        crypto_verify_16_bytes()
    }
}

pub fn ss_verify_16(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        crypto_verify_16(a.as_ptr(), b.as_ptr())
    }
}

#[test]
fn test_ss_verify_16_bytes() {
    assert!(ss_verify_16_bytes() == crypto_verify_16_BYTES);
}

#[test]
fn test_ss_verify_16() {
    let a = [0; 16];
    let b = [0; 16];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(ss_verify_16(&a, &b) == 0);
    assert!(ss_verify_16(&a, &c) == -1);
}
