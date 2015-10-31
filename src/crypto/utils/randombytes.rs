//! Utility functions for generating random values and byte sequences.
use libc::{c_void, size_t, uint32_t};

extern "C" {
    fn randombytes_buf(buf: *mut c_void, size: size_t) -> ();
    fn randombytes_random() -> uint32_t;
    fn randombytes_uniform(upper_bound: uint32_t) -> uint32_t;
}

/// The *random()* function returns an unpredictable value between 0 and
/// 0xffffffff (included).
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::randombytes;
///
/// let r0 = randombytes::random();
/// let r1 = randombytes::random();
/// assert!(r0 != r1);
/// ```
pub fn random() -> uint32_t {
    unsafe {
        randombytes_random()
    }
}

/// The *uniform()* function returns an unpredictable value between 0 and
/// upper_bound (excluded). Unlike *random()* % upper_bound, it does its best
/// to guarantee a uniform distribution of the possible output values.
///
/// The *uniform()* function safely wraps the *randombytes_uniform()* function.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::randombytes;
///
/// let r0 = randombytes::uniform(10);
/// assert!(r0 < 10);
/// ```
pub fn uniform(upper_bound: uint32_t) -> uint32_t {
    unsafe {
        randombytes_uniform(upper_bound)
    }
}

/// The *random_byte_array()* function fills the given mutable byte array with
/// an unpredictable sequence of bytes.
///
/// The *random_byte_array()* function safely wrap the *randombytes_buf()*
/// function.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::randombytes;
///
/// let mut ra0 = [0; 16];
/// randombytes::random_byte_array(&mut ra0);
/// assert!(ra0 != [0; 16]);
/// ```
pub fn random_byte_array(buf: &mut [u8]) {
    unsafe {
        randombytes_buf(buf.as_mut_ptr() as *mut c_void,
                        buf.len() as size_t);
    }
}
