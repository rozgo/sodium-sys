//! The SHA-256 and SHA-512 functions are provided for interoperability with
//! other applications.
//!
//! These functions are not keyed and are thus deterministic. In addition, they
//! are vulnerable to length extension attacks.
//!
//! A message can be hashed in a single pass, but a streaming API is also
//! available to process a message as a sequence of multiple chunks.
//!
//! If you are looking for a generic hash function and not specifically SHA-2,
//! using *generichash()* (BLAKE2b) might be a better choice.
use crypto::utils::secmem;
use libc::{c_int, c_uchar, c_ulonglong, uint64_t};
use SSError::{self, HASH};
use std::{mem, ptr};

#[repr(C)]
#[derive(Copy)]
pub struct SHA256State {
    pub state: [uint64_t; 8],
    pub count: [uint64_t; 2],
    pub buf: [c_uchar; 64],
}

impl Default for SHA256State {
    fn default() -> SHA256State {
        SHA256State {
            state: [0; 8],
            count: [0; 2],
            buf: [0; 64]
        }
    }
}

impl Clone for SHA256State {
    fn clone(&self) -> SHA256State {
        unsafe {
            let mut x: SHA256State = mem::uninitialized();
            ptr::copy::<SHA256State>(mem::transmute(self),
                                     mem::transmute(&mut x),
                                     mem::size_of::<SHA256State>());
            x
        }
    }
}

#[repr(C)]
#[derive(Copy)]
pub struct SHA512State {
    pub state: [uint64_t; 8],
    pub count: [uint64_t; 2],
    pub buf: [c_uchar; 128],
}

impl Default for SHA512State {
    fn default() -> SHA512State {
        SHA512State {
            state: [0; 8],
            count: [0; 2],
            buf: [0; 128]
        }
    }
}

impl Clone for SHA512State {
    fn clone(&self) -> SHA512State {
        unsafe {
            let mut x: SHA512State = mem::uninitialized();
            ptr::copy::<SHA512State>(mem::transmute(self),
                                     mem::transmute(&mut x),
                                     mem::size_of::<SHA512State>());
            x
        }
    }
}

// 64 bytes.
pub const SHA512_BYTES: usize = 64;
// 32 bytes.
pub const SHA256_BYTES: usize = 32;

extern "C" {
    fn crypto_hash_sha256(out: *mut c_uchar,
                          in_: *const c_uchar,
                          inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha256_init(state: *mut SHA256State) -> c_int;
    fn crypto_hash_sha256_update(state: *mut SHA256State,
                                 in_: *const c_uchar,
                                 inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha256_final(state: *mut SHA256State,
                                out: *mut c_uchar) -> c_int;
    fn crypto_hash_sha512(out: *mut c_uchar,
                          in_: *const c_uchar,
                          inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha512_init(state: *mut SHA512State) -> c_int;
    fn crypto_hash_sha512_update(state: *mut SHA512State,
                                 in_: *const c_uchar,
                                 inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha512_final(state: *mut SHA512State,
                                out: *mut c_uchar) -> c_int;
}

/// The *hash256()* function creates the SHA-256 hash for the given message.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let hash = sha2::hash256(b"test").unwrap();
/// assert!(hash.len() == sha2::SHA256_BYTES);
/// ```
pub fn hash256<'a>(message: &'a [u8]) -> Result<&'a [u8], SSError> {
    let mut out = secmem::malloc(SHA256_BYTES);

    let res: i32;

    unsafe {
        res = crypto_hash_sha256(out.as_mut_ptr(),
                                 message.as_ptr(),
                                 message.len() as c_ulonglong);
    }

    if res == 0 {
        Ok(out)
    } else {
        Err(HASH("Unable to hash message"))
    }
}

/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
/// use std::default::Default;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let mut state = Default::default();
/// let _ = sha2::init256(&mut state).unwrap();
/// ```
pub fn init256<'a>(state: &'a mut SHA256State) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha256_init(state);
    }

    if res == 0 {
        Ok(())
    } else {
        Err(HASH("Unable to initialize hash state"))
    }
}

/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
/// use std::default::Default;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let mut state = Default::default();
/// let _ = sha2::init256(&mut state).unwrap();
///
/// // Update the hash state.
/// let message = b"test";
/// let _ = sha2::update256(&mut state, message);
/// let message1 = b"testsomemore";
/// let _ = sha2::update256(&mut state, message1);
/// ```
pub fn update256<'a>(state: &'a mut SHA256State,
                     in_: &[u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha256_update(state,
                                        in_.as_ptr(),
                                        in_.len() as c_ulonglong);
    }

    if res == 0 {
        Ok(())
    } else {
        Err(HASH("Unable to update hash state"))
    }
}

/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
/// use std::default::Default;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let mut state = Default::default();
/// let _ = sha2::init256(&mut state).unwrap();
///
/// // Update the hash state.
/// let message = b"test";
/// let _ = sha2::update256(&mut state, message);
/// let message1 = b"testsomemore";
/// let _ = sha2::update256(&mut state, message1);
///
/// // Finalize the hash.
/// let hash = sha2::finalize256(&mut state).unwrap();
/// assert!(hash.len() == sha2::SHA256_BYTES);
/// ```
pub fn finalize256<'a>(state: &'a mut SHA256State)
    -> Result<&'a [u8], SSError> {
    let out = secmem::malloc(SHA256_BYTES);

    let res: i32;

    unsafe {
        res = crypto_hash_sha256_final(state, out.as_mut_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(out);
        Ok(out)
    } else {
        Err(HASH("Unable to update hash state"))
    }
}

/// The *hash512()* function creates the SHA-256 hash for the given message.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let hash = sha2::hash512(b"test").unwrap();
/// assert!(hash.len() == sha2::SHA512_BYTES);
/// ```
pub fn hash512<'a>(message: &'a [u8]) -> Result<&'a [u8], SSError> {
    let mut out = secmem::malloc(SHA512_BYTES);

    let res: i32;

    unsafe {
        res = crypto_hash_sha512(out.as_mut_ptr(),
                                 message.as_ptr(),
                                 message.len() as c_ulonglong);
    }

    if res == 0 {
        Ok(out)
    } else {
        Err(HASH("Unable to hash message"))
    }
}

/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
/// use std::default::Default;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let mut state = Default::default();
/// let _ = sha2::init512(&mut state).unwrap();
/// ```
pub fn init512<'a>(state: &'a mut SHA512State) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha512_init(state);
    }

    if res == 0 {
        Ok(())
    } else {
        Err(HASH("Unable to initialize hash state"))
    }
}

/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
/// use std::default::Default;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let mut state = Default::default();
/// let _ = sha2::init512(&mut state).unwrap();
///
/// // Update the hash state.
/// let message = b"test";
/// let _ = sha2::update512(&mut state, message);
/// let message1 = b"testsomemore";
/// let _ = sha2::update512(&mut state, message1);
/// ```
pub fn update512<'a>(state: &'a mut SHA512State,
                     in_: &[u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha512_update(state,
                                        in_.as_ptr(),
                                        in_.len() as c_ulonglong);
    }

    if res == 0 {
        Ok(())
    } else {
        Err(HASH("Unable to update hash state"))
    }
}

/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::sha2;
/// use std::default::Default;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let mut state = Default::default();
/// let _ = sha2::init512(&mut state).unwrap();
///
/// // Update the hash state.
/// let message = b"test";
/// let _ = sha2::update512(&mut state, message);
/// let message1 = b"testsomemore";
/// let _ = sha2::update512(&mut state, message1);
///
/// // Finalize the hash.
/// let hash = sha2::finalize512(&mut state).unwrap();
/// assert!(hash.len() == sha2::SHA512_BYTES);
/// ```
pub fn finalize512<'a>(state: &'a mut SHA512State)
    -> Result<&'a [u8], SSError> {
    let out = secmem::malloc(SHA512_BYTES);

    let res: i32;

    unsafe {
        res = crypto_hash_sha512_final(state, out.as_mut_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(out);
        Ok(out)
    } else {
        Err(HASH("Unable to update hash state"))
    }
}
