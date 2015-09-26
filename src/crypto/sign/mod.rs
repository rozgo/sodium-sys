//! In this system, a signer generates a key pair:
//!
//! * A secret key, that will be used to append a signature to any number of
//! messages
//! * A public key, that anybody can use to verify that the signature appended
//! to a message was actually issued by the creator of the public key.
//!
//! Verifiers need to already know and ultimately trust a public key before
//! messages signed using it can be verified.
//!
//! Warning: this is different from authenticated encryption. Appending a
//! signature does not change the representation of the message itself.
use libc::{c_int, c_uchar, c_ulonglong};
use SSError::{self, SIGN, VERIFYSIGNED};
use utils;

pub mod keypair;

// 64 bytes for ed25519
pub const BYTES: usize = 64;
// 32 bytes for ed25519
pub const SEEDBYTES: usize = 32;
// 32 bytes for ed25519
pub const PUBLICKEYBYTES: usize = 32;
// 64 bytes for ed25519
pub const SECRETKEYBYTES: usize = 64;

extern "C" {
    fn crypto_sign(sm: *mut c_uchar,
                   smlen_p: *mut c_ulonglong,
                   m: *const c_uchar,
                   mlen: c_ulonglong,
                   sk: *const c_uchar) -> c_int;
    fn crypto_sign_open(m: *mut c_uchar,
                        mlen_p: *mut c_ulonglong,
                        sm: *const c_uchar,
                        smlen: c_ulonglong,
                        pk: *const c_uchar) -> c_int;
    fn crypto_sign_detached(sig: *mut c_uchar,
                            siglen_p: *mut c_ulonglong,
                            m: *const c_uchar,
                            mlen: c_ulonglong,
                            sk: *const c_uchar) -> c_int;
    fn crypto_sign_verify_detached(sig: *const c_uchar,
                                   m: *const c_uchar,
                                   mlen: c_ulonglong,
                                   pk: *const c_uchar) -> c_int;
}

/// The *sign()* function prepends a signature to a message, using a secret key.
///
/// # Examples
///
/// ```
/// use sodium_sys::core;
/// use sodium_sys::crypto::sign;
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let keypair = sign::keypair::KeyPair::new().unwrap();
/// keypair.activate_sk();
/// keypair.activate_pk();
///
/// // Generate the signed message.
/// let signedmessage = sign::sign(b"test", keypair.sk_bytes()).unwrap();
///
/// println!("{:?}", signedmessage);
/// ```
pub fn sign<'a>(message: &[u8], sk: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(sk.len() == SECRETKEYBYTES);

    let mut signedmessage = utils::malloc(BYTES + message.len());
    let smlen: u64 = 0;

    let res: i32;

    unsafe {
        res = crypto_sign(signedmessage.as_mut_ptr(),
                          smlen as *mut c_ulonglong,
                          message.as_ptr(),
                          message.len() as c_ulonglong,
                          sk.as_ptr());
    }

    if res == 0 {
        Ok(signedmessage)
    } else {
        Err(SIGN("Unable to sign message!"))
    }
}

/// The *open()* function verifies a signature and returns the message with the
/// signature stripped if successful.
///
/// pk is the public key of the sender that signed the message.
///
/// # Examples
///
/// ```
/// use sodium_sys::core;
/// use sodium_sys::crypto::sign;
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let keypair = sign::keypair::KeyPair::new().unwrap();
/// keypair.activate_sk();
/// keypair.activate_pk();
///
/// // Generate the signed message.
/// let signedmessage = sign::sign(b"test", keypair.sk_bytes()).unwrap();
/// let message = sign::open(signedmessage, keypair.pk_bytes()).unwrap();
///
/// assert!(message == b"test");
/// ```
pub fn open<'a>(signedmessage: &[u8],
                pk: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);

    let mut message = utils::malloc(signedmessage.len() - BYTES);
    let mlen: u64 = 0;

    let res: i32;

    unsafe {
        res = crypto_sign_open(message.as_mut_ptr(),
                                   mlen as *mut c_ulonglong,
                                   signedmessage.as_ptr(),
                                   signedmessage.len() as c_ulonglong,
                                   pk.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(VERIFYSIGNED("Unable to verify signed message!"))
    }
}

/// The *sign_detached()* function generates a signature for message, using a
/// secret key.
///
/// # Examples
///
/// ```
/// use sodium_sys::core;
/// use sodium_sys::crypto::sign;
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let keypair = sign::keypair::KeyPair::new().unwrap();
/// keypair.activate_sk();
/// keypair.activate_pk();
///
/// // Generate the signature.
/// let signature = sign::sign_detached(b"test", keypair.sk_bytes()).unwrap();
///
/// println!("{:?}", signature);
/// ```
pub fn sign_detached<'a>(message: &[u8],
                         sk: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(sk.len() == SECRETKEYBYTES);

    let mut signature = utils::malloc(BYTES);
    let smlen: u64 = 0;

    let res: i32;

    unsafe {
        res = crypto_sign_detached(signature.as_mut_ptr(),
                                   smlen as *mut c_ulonglong,
                                   message.as_ptr(),
                                   message.len() as c_ulonglong,
                                   sk.as_ptr());
    }

    if res == 0 {
        Ok(signature)
    } else {
        Err(SIGN("Unable to generate signature!"))
    }
}

/// The *open_detached()* function verifies a signature is valid for a message
/// and returns 0 on success, or -1 otherwise.
///
/// pk is the public key of the sender that signed the message.
///
/// # Examples
///
/// ```
/// use sodium_sys::core;
/// use sodium_sys::crypto::sign;
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let keypair = sign::keypair::KeyPair::new().unwrap();
/// keypair.activate_sk();
/// keypair.activate_pk();
///
/// // Generate the signature.
/// let signature = sign::sign_detached(b"test", keypair.sk_bytes()).unwrap();
/// let res = sign::open_detached(b"test", signature, keypair.pk_bytes());
///
/// assert!(res == 0);
/// ```
pub fn open_detached(message: &[u8],
                     signature: &[u8],
                     pk: &[u8]) -> i32 {
    assert!(signature.len() == BYTES);
    assert!(pk.len() == PUBLICKEYBYTES);

    let res: i32;

    unsafe {
        res = crypto_sign_verify_detached(signature.as_ptr(),
                                          message.as_ptr(),
                                          message.len() as c_ulonglong,
                                          pk.as_ptr());
    }

    res
}
