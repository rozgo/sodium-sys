//! Many applications and programming language implementations were recently
//! found to be vulnerable to denial-of-service attacks when a hash function
//! with weak security guarantees, such as Murmurhash 3, was used to construct a
//! hash table.
//!
//! In order to address this, Sodium provides the crypto_shorthash() function,
//! which outputs short but unpredictable (without knowing the secret key)
//! values suitable for picking a list in a hash table for a given key.
//!
//! This function is optimized for short inputs.
//!
//! The output of this function is only 64 bits. Therefore, it should not be
//! considered collision-resistant.
//!
//! Use cases:
//!
//! - Hash tables
//! - Probabilistic data structures such as Bloom filters
//! - Integrity checking in interactive protocols
use libc::{c_int, c_uchar, c_ulonglong};
use SSError::{self, HASH};
use crypto::utils::secmem;

pub const BYTES: usize = 8;
pub const KEYBYTES: usize = 16;

extern "C" {
    fn crypto_shorthash(out: *mut c_uchar,
                        in_: *const c_uchar,
                        inlen: c_ulonglong,
                        k: *const c_uchar) -> c_int;
}

/// Compute a fixed-size (*BYTES* bytes) fingerprint for the message using the
/// key k.
///
/// The k is *KEYBYTES* bytes and can be created using *random_byte_array()*.
///
/// The same message hashed with the same key will always produce the same
/// output.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,randombytes};
/// use sodium_sys::crypto::hash::shorthash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let mut key = [0; shorthash::KEYBYTES];
/// randombytes::random_byte_array(&mut key);
/// let hash = shorthash::hash(b"test", &key).unwrap();
/// assert!(hash.len() == shorthash::BYTES);
/// ```
pub fn hash<'a>(message: &'a [u8], k: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(k.len() == KEYBYTES);

    let mut hash = secmem::malloc(BYTES);
    let res: i32;

    unsafe {
        res = crypto_shorthash(hash.as_mut_ptr(),
                               message.as_ptr(),
                               message.len() as c_ulonglong,
                               k.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(hash);
        Ok(hash)
    } else {
        Err(HASH("Unable to hash message"))
    }
}
