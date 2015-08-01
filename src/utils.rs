extern "C" {
    fn sodium_memzero(pnt: *mut ::libc::c_void, len: ::libc::size_t) -> ();
    fn sodium_memcmp(b1_: *const ::libc::c_void,
                     b2_: *const ::libc::c_void,
                     len: ::libc::size_t) -> ::libc::c_int;
    //pub fn sodium_bin2hex(hex: *mut ::libc::c_char, hex_maxlen: ::libc::size_t,
    //                      bin: *const ::libc::c_uchar, bin_len: ::libc::size_t)
    //                      -> *mut ::libc::c_char;
    //pub fn sodium_hex2bin(bin: *mut ::libc::c_uchar, bin_maxlen: ::libc::size_t,
    //                      hex: *const ::libc::c_char, hex_len: ::libc::size_t,
    //                      ignore: *const ::libc::c_char, bin_len: *mut ::libc::size_t,
    //                      hex_end: *mut *const ::libc::c_char)
    //                        -> ::libc::c_int;
    fn sodium_mlock(addr: *mut ::libc::c_void, len: ::libc::size_t) -> ::libc::c_int;
    fn sodium_munlock(addr: *mut ::libc::c_void, len: ::libc::size_t) -> ::libc::c_int;
    //pub fn sodium_malloc(size: ::libc::size_t) -> *mut ::libc::c_void;
    //pub fn sodium_allocarray(count: ::libc::size_t, size: ::libc::size_t)
    // -> *mut ::libc::c_void;
    //pub fn sodium_free(ptr: *mut ::libc::c_void) -> ();
    //pub fn sodium_mprotect_noaccess(ptr: *mut ::libc::c_void) -> ::libc::c_int;
    //pub fn sodium_mprotect_readonly(ptr: *mut ::libc::c_void) -> ::libc::c_int;
    //pub fn sodium_mprotect_readwrite(ptr: *mut ::libc::c_void) -> ::libc::c_int;
    //pub fn sodium_increment(n: *mut ::libc::c_uchar, nlen: ::libc::size_t) -> ();
}

pub fn barnacl_sodium_memzero(mem: &[u8]) {
    unsafe {
        sodium_memzero(mem.as_ptr() as *mut ::libc::c_void, mem.len() as ::libc::size_t);
    }
}

pub fn barnacl_sodium_memcmp(m1: &[u8], m2: &[u8]) -> i32 {
    if m1.len() == m2.len() {
        unsafe {
            sodium_memcmp(m1.as_ptr() as *const ::libc::c_void,
                          m2.as_ptr() as *const ::libc::c_void,
                          m1.len() as ::libc::size_t)
        }
    } else {
        -1
    }
}

pub fn barnacl_sodium_mlock(mem: &[u8]) -> i32 {
    unsafe {
        sodium_mlock(mem.as_ptr() as *mut ::libc::c_void, mem.len() as ::libc::size_t)
    }
}

pub fn barnacl_sodium_munlock(mem: &[u8]) -> i32 {
    unsafe {
        sodium_munlock(mem.as_ptr() as *mut ::libc::c_void, mem.len() as ::libc::size_t)
    }
}

#[test]
fn test_barnacl_sodium_memzero() {
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    barnacl_sodium_memzero(&v);
    assert!(v == [0; 8]);
}

#[test]
fn test_barnacl_sodium_memcmp() {
    let v0 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v1 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v2 = [7, 6, 5, 4, 3, 2, 1, 0];
    assert!(barnacl_sodium_memcmp(&v0,&v1) == 0);
    assert!(barnacl_sodium_memcmp(&v0,&v2) != 0);
    assert!(barnacl_sodium_memcmp(&v1,&v2) != 0);
}

#[test]
fn test_barnacl_sodium_mlock_munlock() {
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    assert!(barnacl_sodium_mlock(&v) == 0);
    assert!(barnacl_sodium_munlock(&v) == 0);
    assert!(v == [0; 8]);
}
