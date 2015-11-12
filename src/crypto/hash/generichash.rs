//! This module computes a fixed-length fingerprint for an arbitrary long
//! message.
//!
//! Sample use cases:
//!
//! - File integrity checking
//! - Creating unique identifiers to index arbitrary long data
use libc::{c_int, c_uchar, c_ulonglong, size_t};
use SSError::{self, HASH};
use crypto::utils::secmem;
use std::ptr;

pub const BYTES_MIN: usize = 16;
pub const BYTES_MAX: usize = 64;
pub const BYTES: usize = 32;
pub const KEYBYTES_MIN: usize = 16;
pub const KEYBYTES_MAX: usize = 64;
pub const KEYBYTES: usize = 32;

extern "C" {
    fn crypto_generichash_statebytes() -> c_int;
    fn crypto_generichash(out: *mut c_uchar,
                          outlen: size_t,
                          in_: *const c_uchar,
                          inlen: c_ulonglong,
                          key: *const c_uchar,
                          keylen: size_t) -> c_int;
    fn crypto_generichash_init(state: *mut c_uchar,
                               key: *const c_uchar,
                               keylen: size_t,
                               outlen: size_t) -> c_int;
    fn crypto_generichash_update(state: *mut c_uchar,
                                 in_: *const c_uchar,
                                 inlen: c_ulonglong) -> c_int;
    fn crypto_generichash_final(state: *mut c_uchar,
                                out: *mut c_uchar,
                                outlen: size_t) -> c_int;
}

/// The *hash()* function calculates a fingerprint of the message. The output
/// size can be chosen by the application.
///
/// The minimum recommended output size is *BYTES*. This size makes it
/// practically impossible for two messages to produce the same fingerprint.
///
/// But for specific use cases, the size can be any value between *BYTES_MIN*
/// (included) and *BYTES_MAX* (included).  This can be specified in the
/// optional *s* argument.  If *s* is not supplied the output length will be
/// *BYTES* long.
///
/// An optional key can an also be specified. A message will always have the
/// same fingerprint for a given key, but different keys used to hash the same
/// message are very likely to produce distinct fingerprints.
///
/// If no key is supplied, a message will always have the same fingerprint,
/// similar to the MD5 or SHA-1 functions for which *hash()* is a faster and
/// more secure alternative.
///
/// In particular, the key can be used to make sure that different applications
/// generate different fingerprints even if they process the same data.
///
/// The recommended key size is *KEYBYTE* bytes.
///
/// However, the key size can by any value between *KEYBYTES_MIN* (included) and
/// *KEYBYTES_MAX* (included).
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::generichash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let hash = generichash::hash(b"test", None, None).unwrap();
/// assert!(hash.len() == generichash::BYTES);
///
/// // Generate a minimum length hash
/// let shash = generichash::hash(b"test",
///                               Some(generichash::BYTES_MIN),
///                               None).unwrap();
/// assert!(shash.len() == generichash::BYTES_MIN);
///
/// // Generate a maximum length hash
/// let lhash = generichash::hash(b"test",
///                               Some(generichash::BYTES_MAX),
///                               None).unwrap();
/// assert!(lhash.len() == generichash::BYTES_MAX);
///
/// // Generate a hash with a key.
/// let key: [u8; generichash::KEYBYTES] = [0; generichash::KEYBYTES];
/// let khash = generichash::hash(b"test",
///                               None,
///                               Some(&key)).unwrap();
/// assert!(khash.len() == generichash::BYTES);
///
/// // Compare two hashes generated with same key.
/// let khash1 = generichash::hash(b"test",
///                                None,
///                                Some(&key)).unwrap();
/// assert!(khash == khash1);
/// ```
pub fn hash<'a>(message: &'a [u8],
                s: Option<usize>,
                k: Option<&[u8]>) -> Result<&'a [u8], SSError> {
    let outlen = match s {
        Some(s) => {
            assert!(s >= BYTES_MIN);
            assert!(s <= BYTES_MAX);
            s
        },
        None    => BYTES,
    };

    let (key, keylen) = match k {
        Some(k) => {
            assert!(k.len() >= KEYBYTES_MIN);
            assert!(k.len() <= KEYBYTES_MAX);
            (k.as_ptr(), k.len() as size_t)
        },
        None    => (ptr::null(), 0 as size_t),
    };

    let mut hash = secmem::malloc(outlen);
    let res: i32;

    unsafe {
        res = crypto_generichash(hash.as_mut_ptr(),
                                 outlen as size_t,
                                 message.as_ptr(),
                                 message.len() as c_ulonglong,
                                 key,
                                 keylen);
    }

    if res == 0 {
        secmem::mprotect_readonly(hash);
        Ok(hash)
    } else {
        Err(HASH("Unable to hash message"))
    }
}

/// The *state_size()* function should be used in conjunction with
/// *utils::malloc()* to allocate the memory for the generic hash state at
/// runtime.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::generichash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = generichash::state_size().unwrap();
/// let state = secmem::malloc(state_size);
/// assert!(state.len() == state_size);
/// ```
pub fn state_size() -> Result<usize, SSError> {
    let res: i32;

    unsafe {
        res = crypto_generichash_statebytes();
    }

    if res > 0 {
        Ok(res as usize)
    } else {
        Err(HASH("Unable to determind state size"))
    }
}

/// Initialize the sha256 multi-part hash.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::generichash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = generichash::state_size().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let outlen = 64;
/// let _ = generichash::init(&mut state, outlen, None).unwrap();
/// assert!(state.len() == state_size);
/// ```
pub fn init<'a>(state: &'a mut [u8],
                s: usize,
                k: Option<&[u8]>) -> Result<(), SSError> {
    assert!(s >= BYTES_MIN);
    assert!(s <= BYTES_MAX);

    let (key, keylen) = match k {
        Some(k) => {
            assert!(k.len() >= KEYBYTES_MIN);
            assert!(k.len() <= KEYBYTES_MAX);
            (k.as_ptr(), k.len() as size_t)
        },
        None    => (ptr::null(), 0 as size_t),
    };

    let res: i32;

    unsafe {
        res = crypto_generichash_init(state.as_mut_ptr(),
                                      key,
                                      keylen,
                                      s as size_t);
    }

    if res == 0 {
        Ok(())
    } else {
        Err(HASH("Unable to initialize hash state"))
    }
}

/// Update the sha256 multi-part hash.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::generichash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = generichash::state_size().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let outlen = 64;
/// let _ = generichash::init(&mut state, outlen, None).unwrap();
///
/// // Update the hash state
/// let _ = generichash::update(&mut state, b"test").unwrap();
/// let _ = generichash::update(&mut state, b"test").unwrap();
/// ```
pub fn update<'a>(state: &'a mut [u8],
                  in_: &[u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_generichash_update(state.as_mut_ptr(),
                                        in_.as_ptr(),
                                        in_.len() as c_ulonglong);
    }

    if res == 0 {
        Ok(())
    } else {
        Err(HASH("Unable to update hash state"))
    }
}

/// Finalize and return the sha256 multi-part hash.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::generichash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = generichash::state_size().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let outlen = 64;
/// let _ = generichash::init(&mut state, outlen, None).unwrap();
///
/// // Update the hash state
/// let _ = generichash::update(&mut state, b"test").unwrap();
/// let _ = generichash::update(&mut state, b"test").unwrap();
///
/// // Finalize the hash.
/// let hash = generichash::finalize(&mut state, outlen).unwrap();
/// assert!(hash.len() == outlen);
/// ```
pub fn finalize<'a>(state: &'a mut [u8],
                    s: usize) -> Result<&'a [u8], SSError> {
    assert!(s >= BYTES_MIN);
    assert!(s <= BYTES_MAX);

    let out = secmem::malloc(s);

    let res: i32;

    unsafe {
        res = crypto_generichash_final(state.as_mut_ptr(),
                                       out.as_mut_ptr(),
                                       s as size_t);
    }

    if res == 0 {
        secmem::mprotect_readonly(out);
        Ok(out)
    } else {
        Err(HASH("Unable to update hash state"))
    }
}
