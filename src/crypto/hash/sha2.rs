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
use libc::{c_int, c_uchar, c_ulonglong, size_t};
use SSError::{self, HASH};

// 64 bytes.
pub const SHA512_BYTES: usize = 64;
// 32 bytes.
pub const SHA256_BYTES: usize = 32;

extern "C" {
    fn crypto_hash_sha256_statebytes() -> size_t;
    fn crypto_hash_sha256(out: *mut c_uchar,
                          in_: *const c_uchar,
                          inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha256_init(state: *mut c_uchar) -> c_int;
    fn crypto_hash_sha256_update(state: *mut c_uchar,
                                 in_: *const c_uchar,
                                 inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha256_final(state: *mut c_uchar,
                                out: *mut c_uchar) -> c_int;
    fn crypto_hash_sha512_statebytes() -> size_t;
    fn crypto_hash_sha512(out: *mut c_uchar,
                          in_: *const c_uchar,
                          inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha512_init(state: *mut c_uchar) -> c_int;
    fn crypto_hash_sha512_update(state: *mut c_uchar,
                                 in_: *const c_uchar,
                                 inlen: c_ulonglong) -> c_int;
    fn crypto_hash_sha512_final(state: *mut c_uchar,
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

/// The *state_size_256()* function should be used in conjunction with
/// *utils::malloc()* to allocate the memory for the hash state for SHA256 at
/// runtime.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_256().unwrap();
/// let state = secmem::malloc(state_size);
/// assert!(state.len() == state_size);
/// ```
pub fn state_size_256() -> Result<usize, SSError> {
    let res: size_t;

    unsafe {
        res = crypto_hash_sha256_statebytes();
    }

    if res > 0 {
        Ok(res as usize)
    } else {
        Err(HASH("Unable to determind state size"))
    }
}

/// The *state_size_512()* function should be used in conjunction with
/// *utils::malloc()* to allocate the memory for the hash state for SHA256 at
/// runtime.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_512().unwrap();
/// let state = secmem::malloc(state_size);
/// assert!(state.len() == state_size);
/// ```
pub fn state_size_512() -> Result<usize, SSError> {
    let res: size_t;

    unsafe {
        res = crypto_hash_sha512_statebytes();
    }

    if res > 0 {
        Ok(res as usize)
    } else {
        Err(HASH("Unable to determind state size"))
    }
}
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_256().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let _ = sha2::init256(&mut state).unwrap();
/// ```
pub fn init256<'a>(state: &'a mut [u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha256_init(state.as_mut_ptr());
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
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_256().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let _ = sha2::init256(&mut state).unwrap();
///
/// // Update the hash state.
/// let message = b"test";
/// let _ = sha2::update256(&mut state, message);
/// let message1 = b"testsomemore";
/// let _ = sha2::update256(&mut state, message1);
/// ```
pub fn update256<'a>(state: &'a mut [u8], in_: &[u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha256_update(state.as_mut_ptr(),
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
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_256().unwrap();
/// let mut state = secmem::malloc(state_size);
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
pub fn finalize256<'a>(state: &'a mut [u8]) -> Result<&'a [u8], SSError> {
    let out = secmem::malloc(SHA256_BYTES);

    let res: i32;

    unsafe {
        res = crypto_hash_sha256_final(state.as_mut_ptr(), out.as_mut_ptr());
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
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_512().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let _ = sha2::init512(&mut state).unwrap();
/// ```
pub fn init512<'a>(state: &'a mut [u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha512_init(state.as_mut_ptr());
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
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_512().unwrap();
/// let mut state = secmem::malloc(state_size);
/// let _ = sha2::init512(&mut state).unwrap();
///
/// // Update the hash state.
/// let message = b"test";
/// let _ = sha2::update512(&mut state, message);
/// let message1 = b"testsomemore";
/// let _ = sha2::update512(&mut state, message1);
/// ```
pub fn update512<'a>(state: &'a mut [u8], in_: &[u8]) -> Result<(), SSError> {
    let res: i32;

    unsafe {
        res = crypto_hash_sha512_update(state.as_mut_ptr(),
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
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::hash::sha2;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = sha2::state_size_512().unwrap();
/// let mut state = secmem::malloc(state_size);
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
pub fn finalize512<'a>(state: &'a mut [u8]) -> Result<&'a [u8], SSError> {
    let out = secmem::malloc(SHA512_BYTES);

    let res: i32;

    unsafe {
        res = crypto_hash_sha512_final(state.as_mut_ptr(), out.as_mut_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(out);
        Ok(out)
    } else {
        Err(HASH("Unable to update hash state"))
    }
}
