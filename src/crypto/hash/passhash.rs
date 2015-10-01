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
//! # Notes
//! Do not forget to initialize the library with *init()*. The *pwhash*
//! functions will still work without doing so, but possibly way slower.
//!
//! Do not use constants (including OPSLIMIT_* and MEMLIMIT_*) in order to
//! verify a password. Save the parameters along with the hash instead, and use
//! these saved parameters for the verification.
//!
//! Alternatively, use *pwhash()* and *pwhash_verify()*, that automatically take
//! care of including and extracting the parameters.
//!
//! By doing so, passwords can be rehashed using different parameters if
//! required later on.
//!
//! Cleartext passwords should not stay in memory longer than needed.
//!
//! It is highly recommended to use *mlock()* to lock memory regions storing
//! cleartext passwords, and to call *munlock()* right after *pwhash()* and
//! *pwhash_verify()* return.
//!
//! By design, a password whose length is 65 bytes or more is reduced to
//! SHA-256(password). This can have security implications if the password is
//! present in another password database using raw, unsalted SHA-256. Or when
//! upgrading passwords previously hashed with unsalted SHA-256 to scrypt.
//!
//! If this is a concern, passwords should be pre-hashed before being hashed
//! using scrypt:
//!
//! # Guidelines for choosing scrypt parameters
//!
//! Start by determining how much memory can be used the scrypt function. What
//! will be the highest number of threads/processes evaluating the function
//! simultaneously (ideally, no more than 1 per CPU core)? How much physical
//! memory is guaranteed to be available?
//!
//! memlimit should be a power of 2. Do not use anything less than 16 Mb, even
//! for interactive use.
//!
//! Then, a reasonable starting point for opslimit is memlimit / 32.
//!
//! Measure how long the scrypt function needs in order to hash a password. If
//! this it is way too long for your application, reduce memlimit and adjust
//! opslimit using the above formula.
//!
//! If the function is so fast that you can afford it to be more computationally
//! intensive without any usability issues, increase opslimit.
//!
//! For online use (e.g. login in on a website), a 1 second computation is
//! likely to be the acceptable maximum.
//!
//! For interactive use (e.g. a desktop application), a 5 second pause after
//! having entered a password is acceptable if the password doesn't need to be
//! entered more than once per session.
//!
//! For non-interactive use and infrequent use (e.g. restoring an encrypted
//! backup), an even slower computation can be an option.
//!
//! But the best defense against brute-force password cracking remains using
//! strong passwords. Libraries such as passwdqc can help enforce this.
use libc::{
    c_int,
    c_uchar,
    c_ulonglong,
    size_t,
    uint8_t,
    uint32_t,
    uint64_t
};
use SSError::{self, HASH, KEYGEN};
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
    fn crypto_pwhash_scryptsalsa208sha256_str(out: *mut uint8_t,
                                              passwd: *const uint8_t,
                                              passwdlen: c_ulonglong,
                                              opslimit: c_ulonglong,
                                              memlimit: size_t) -> c_int;
    fn crypto_pwhash_scryptsalsa208sha256_str_verify(str_: *const uint8_t,
                                                     passwd: *const uint8_t,
                                                     passwdlen: c_ulonglong)
                                                     -> c_int;
    fn crypto_pwhash_scryptsalsa208sha256_ll(passwd: *const uint8_t,
                                             passwdlen: size_t,
                                             salt: *const uint8_t,
                                             saltlen: size_t,
                                             N: uint64_t,
                                             r: uint32_t,
                                             p: uint32_t,
                                             buf: *mut uint8_t,
                                             buflen: size_t) -> c_int;
}

/// The *keygen()* function derives a key of the given length from a password
/// and a salt.
///
/// The computed key is returned.
///
/// opslimit represents a maximum amount of computations to perform. Raising
/// this number will make the function require more CPU cycles to compute a key.
///
/// memlimit is the maximum amount of RAM that the function will use, in bytes.
/// It is highly recommended to allow the function to use at least 16 megabytes.
///
/// For interactive, online operations, *OPSLIMIT_INTERACTIVE* and
/// *MEMLIMIT_INTERACTIVE* provide a safe base line for these two parameters.
/// However, using higher values may improve security.
///
/// For highly sensitive data, *OPSLIMIT_SENSITIVE* and *MEMLIMIT_SENSITIVE* can
/// be used as an alternative. But with these parameters, deriving a key takes
/// about 2 seconds on a 2.8 Ghz Core i7 CPU and requires up to 1 gigabyte of
/// dedicated RAM.
///
/// The salt should be unpredictable. *randombytes::random_byte_array()* is the
/// easiest way to fill the salt.
///
/// Keep in mind that in order to produce the same key from the same password,
/// the same salt, and the same values for opslimit and memlimit have to be
/// used. Therefore, these parameters have to be stored for each user.
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

/// The *pwhash()* function creates an ASCII encoded string, which includes:
///
/// - The result of a memory-hard, CPU-intensive hash function applied to the
/// password.
/// - The automatically generated salt used for the previous computation.
/// - The other parameters required to verify the password: opslimit and
/// memlimit.
///
/// *OPSLIMIT_INTERACTIVE* and *MEMLIMIT_INTERACTIVE* are safe baseline values
/// to use for opslimit and memlimit.
///
/// The output string is zero-terminated, includes only ASCII characters and can
/// be safely stored into SQL databases and other data stores. No extra
/// information has to be stored in order to verify the password.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::passhash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let hash = passhash::pwhash(b"test", None, None).unwrap();
/// assert!(hash.len() == passhash::STRBYTES);
///
/// // Generate a more secure hash.
/// let hash = passhash::pwhash(b"test",
///                             Some(passhash::OPSLIMIT_SENSITIVE),
///                             Some(passhash::MEMLIMIT_SENSITIVE)).unwrap();
/// assert!(hash.len() == passhash::STRBYTES);
/// ```
pub fn pwhash<'a>(password: &'a [u8],
                  opslimit: Option<usize>,
                  memlimit: Option<usize>) -> Result<&'a [u8], SSError> {
    let ops = match opslimit {
        Some(ol) => ol,
        None     => OPSLIMIT_INTERACTIVE,
    };

    let mem = match memlimit {
        Some(ml) => ml,
        None     => MEMLIMIT_INTERACTIVE,
    };

    let plen = password.len() as c_ulonglong;
    let mut out = secmem::malloc(STRBYTES);
    let res: i32;

    unsafe {
        res = crypto_pwhash_scryptsalsa208sha256_str(out.as_mut_ptr(),
                                                     password.as_ptr(),
                                                     plen,
                                                     ops as c_ulonglong,
                                                     mem as size_t);
    }

    if res == 0 {
        Ok(out)
    } else {
        Err(HASH("Unable to hash password"))
    }
}

/// The *pwhash_verify()* function verifies that the given hash is a valid
/// password verification string (as generated by *pwhash()*) for the given
/// password.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::hash::passhash;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Generate the hash.
/// let hash = passhash::pwhash(b"test", None, None).unwrap();
/// assert!(hash.len() == passhash::STRBYTES);
///
/// // Verify the hash
/// let isvalid = passhash::pwhash_verify(b"test", hash);
/// assert!(isvalid);
///
/// // Generate a more secure hash.
/// let hash1 = passhash::pwhash(b"test",
///                             Some(passhash::OPSLIMIT_SENSITIVE),
///                             Some(passhash::MEMLIMIT_SENSITIVE)).unwrap();
/// assert!(hash1.len() == passhash::STRBYTES);
///
/// // Verify the hash
/// let isvalid = passhash::pwhash_verify(b"test", hash1);
/// assert!(isvalid);
/// ```
pub fn pwhash_verify(password: &[u8], hash: &[u8]) -> bool {
    assert!(hash.len() == STRBYTES);
    let plen = password.len() as c_ulonglong;
    let res: i32;

    unsafe {
        res = crypto_pwhash_scryptsalsa208sha256_str_verify(hash.as_ptr(),
                                                            password.as_ptr(),
                                                            plen);
    }

    if res == 0 {
        true
    } else {
        false
    }
}

/// The traditional, low-level scrypt API is also available
pub fn scrypt<'a>(password: &'a [u8],
                  salt: &[u8],
                  n: u64,
                  r: u32,
                  p: u32,
                  outlen: usize) -> Result<&'a [u8], SSError> {
    let mut out = secmem::malloc(outlen);
    let plen = password.len() as size_t;
    let slen = salt.len() as size_t;
    let res: i32;

    unsafe {
        res = crypto_pwhash_scryptsalsa208sha256_ll(password.as_ptr(),
                                                    plen,
                                                    salt.as_ptr(),
                                                    slen,
                                                    n as uint64_t,
                                                    r as uint32_t,
                                                    p as uint32_t,
                                                    out.as_mut_ptr(),
                                                    outlen as size_t);
    }

    if res == 0 {
        Ok(out)
    } else {
        Err(HASH("Unable to hash password"))
    }
}
