//! Secret keys used to encrypt or sign confidential data have to be chosen from
//! a very large keyspace. However, passwords are usually short, human-generated
//! strings, making dictionary attacks practical.
//!
//! The pwhash operation derives a secret key of any size from a password and a
//!salt.
//!
//! - The generated key has the size defined by the application, no matter what
//! the password length is.
//! - The same password hashed with same parameters will always produce the same
//! key.
//! - The same password hashed with different salts will produce different keys.
//! - The function deriving a key from a password and a salt is CPU intensive
//! and intentionally requires a fair amount of memory. Therefore, it mitigates
//! brute-force attacks by requiring a significant effort to verify each
//! password.
//!
//! Common use cases:
//!
//! - Protecting an on-disk secret key with a password,
//! - Password storage, or rather: storing what it takes to verify a password
//! without having to store the actual password.
//!
use libc::{
    c_int,
    c_uchar,
    c_ulonglong,
    size_t,
    uint8_t,
    // uint32_t,
    // uint64_t
};
use SSError::{
    self,
    // HASH,
    KEYGEN
};
use crypto::utils::secmem;

pub const SALTBYTES: usize = 32;
pub const STRBYTES: usize = 102;
pub const STRPREFIX: &'static str = "$7$";
pub const OPSLIMIT_INTERACTIVE: usize = 524288;
pub const MEMLIMIT_INTERACTIVE: usize = 16777216;
pub const OPSLIMIT_SENSITIVE: usize = 33554432;
pub const MEMLIMIT_SENSITIVE: usize = 1073741824;

extern "C" {
    fn crypto_pwhash_scryptsalsa208sha256(out: *mut uint8_t,
                                          outlen: c_ulonglong,
                                          passwd: *const uint8_t,
                                          passwdlen: c_ulonglong,
                                          salt: *const c_uchar,
                                          opslimit: c_ulonglong,
                                          memlimit: size_t) -> c_int;
    // fn crypto_pwhash_scryptsalsa208sha256_str(out: *mut uint8_t,
    //                                           passwd: *const uint8_t,
    //                                           passwdlen: c_ulonglong,
    //                                           opslimit: c_ulonglong,
    //                                           memlimit: size_t) -> c_int;
    // fn crypto_pwhash_scryptsalsa208sha256_str_verify(str_: *const uint8_t,
    //                                                  passwd: *const uint8_t,
    //                                                  passwdlen: c_ulonglong)
    //                                                  -> c_int;
    // fn crypto_pwhash_scryptsalsa208sha256_ll(passwd: *const uint8_t,
    //                                          passwdlen: size_t,
    //                                          salt: *const uint8_t,
    //                                          saltlen: size_t,
    //                                          N: uint64_t,
    //                                          r: uint32_t,
    //                                          p: uint32_t,
    //                                          buf: *mut uint8_t,
    //                                          buflen: size_t) -> c_int;
}

///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,randombytes};
/// use sodium_sys::crypto::hash::passhash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let mut salt = [0; passhash::SALTBYTES];
/// randombytes::random_byte_array(&mut salt);
/// let key = passhash::keygen(b"test", 64, &salt, None, None).unwrap();
/// assert!(key.len() == 64);
/// ```
pub fn keygen<'a>(password: &'a [u8],
                  keylen: usize,
                  salt: &[u8],
                  opslimit: Option<usize>,
                  memlimit: Option<usize>) -> Result<&'a [u8], SSError> {
    assert!(salt.len() == SALTBYTES);

    let ops = match opslimit {
        Some(ol) => ol,
        None     => OPSLIMIT_INTERACTIVE,
    };

    let mem = match memlimit {
        Some(ml) => ml,
        None     => MEMLIMIT_INTERACTIVE,
    };

    let mut key = secmem::malloc(keylen);
    let res: i32;

    unsafe {
        res = crypto_pwhash_scryptsalsa208sha256(key.as_mut_ptr(),
                                                 keylen as c_ulonglong,
                                                 password.as_ptr(),
                                                 password.len() as c_ulonglong,
                                                 salt.as_ptr(),
                                                 ops as c_ulonglong,
                                                 mem as size_t);
    }

    if res == 0 {
        Ok(key)
    } else {
        Err(KEYGEN("Unable to generate key"))
    }
}
