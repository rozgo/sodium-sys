extern "C" {
    pub fn crypto_verify_16_bytes() -> ::libc::size_t;
    pub fn crypto_verify_16(x: *const ::libc::c_uchar,
                            y: *const ::libc::c_uchar) -> ::libc::c_int;
}
