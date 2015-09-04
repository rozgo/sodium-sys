//! Using public-key authenticated encryption, Bob can encrypt a confidential
//! message specifically for Alice, using Alice's public key.
//!
//! Using Bob's public key, Alice can verify that the encrypted message was
//! actually created by Bob and was not tampered with, before eventually
//! decrypting it.
//!
//! Alice only needs Bob's public key, the nonce and the ciphertext. Bob should
//! never ever share his secret key, even with Alice.
//!
//! And in order to send messages to Alice, Bob only needs Alice's public key.
//! Alice should never ever share her secret key either, even with Bob.
//!
//! Alice can reply to Bob using the same system, without having to generate a
//! distinct key pair.
//!
//! The nonce doesn't have to be confidential, but it should be used with just
//! one invokation of *open_easy()* for a particular pair of public and secret
//! keys.
//!
//! One easy way to generate a nonce is to use the Nonce struct, considering the
//! size of nonces the risk of any random collisions is negligible. For some
//! applications, if you wish to use nonces to detect missing messages or to
//! ignore replayed messages, it is also ok to use a simple incrementing counter
//! as a nonce.
//!
//! When doing so you must ensure that the same value can never be re-used (for
//! example you may have multiple threads or even hosts generating messages
//! using the same key pairs).
//!
//! This system provides mutual authentication. However, a typical use case is
//! to secure communications between a server, whose public key is known in
//! advance, and clients connecting anonymously.
use libc::{c_int, c_uchar, c_ulonglong};
use SSError::{self, DECRYPT, ENCRYPT};
use utils;

mod crypto_box_curve25519xsalsa20poly1305;

// 32 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const SEEDBYTES: usize = crypto_box_curve25519xsalsa20poly1305::SEEDBYTES;
// 32 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const PUBLICKEYBYTES: usize =
    crypto_box_curve25519xsalsa20poly1305::PUBLICKEYBYTES;
// 32 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const SECRETKEYBYTES: usize =
    crypto_box_curve25519xsalsa20poly1305::SECRETKEYBYTES;
// 32 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const BEFORENMBYTES: usize =
    crypto_box_curve25519xsalsa20poly1305::BEFORENMBYTES;
// 24 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const NONCEBYTES: usize = crypto_box_curve25519xsalsa20poly1305::NONCEBYTES;
// 32 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const ZEROBYTES: usize = crypto_box_curve25519xsalsa20poly1305::ZEROBYTES;
// 16 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const BOXZEROBYTES: usize =
    crypto_box_curve25519xsalsa20poly1305::BOXZEROBYTES;
// 16 bytes for crypto_box_curve25519xsalsa20poly1305.
pub const MACBYTES: usize = crypto_box_curve25519xsalsa20poly1305::MACBYTES;

extern "C" {
    fn crypto_box_easy(c: *mut c_uchar,
                       m: *const c_uchar,
                       mlen: c_ulonglong,
                       n: *const c_uchar,
                       pk: *const c_uchar,
                       sk: *const c_uchar) -> c_int;
    fn crypto_box_open_easy(m: *mut c_uchar,
                            c: *const c_uchar,
                            clen: c_ulonglong,
                            n: *const c_uchar,
                            pk: *const c_uchar,
                            sk: *const c_uchar) -> c_int;
    fn crypto_box_detached(c: *mut c_uchar,
                           mac: *mut c_uchar,
                           m: *const c_uchar,
                           mlen: c_ulonglong,
                           n: *const c_uchar,
                           pk: *const c_uchar,
                           sk: *const c_uchar) -> c_int;
    fn crypto_box_open_detached(m: *mut c_uchar,
                                c: *const c_uchar,
                                mac: *const c_uchar,
                                clen: c_ulonglong,
                                n: *const c_uchar,
                                pk: *const c_uchar,
                                sk: *const c_uchar) -> c_int;
    pub fn crypto_box_easy_afternm(c: *mut c_uchar, m: *const c_uchar,
                                   mlen: c_ulonglong, n: *const c_uchar,
                                   k: *const c_uchar) -> c_int;
    pub fn crypto_box_open_easy_afternm(m: *mut c_uchar, c: *const c_uchar,
                                        clen: c_ulonglong, n: *const c_uchar,
                                        k: *const c_uchar) -> c_int;
    pub fn crypto_box_detached_afternm(c: *mut c_uchar, mac: *mut c_uchar,
                                       m: *const c_uchar, mlen: c_ulonglong,
                                       n: *const c_uchar, k: c_uchar) -> c_int;
    pub fn crypto_box_open_detached_afternm(m: *mut c_uchar, c: *const c_uchar,
                                            mac: *const c_uchar,
                                            clen: c_ulonglong, n: *const c_uchar,
                                            k: *const c_uchar) -> c_int;
}

/// The *seal()* function encrypts a message with a recipient's public key, a
/// sender's secret key and a nonce.
///
/// This function writes the authentication tag immediately followed by the
/// encrypted message.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core, utils};
/// use sodium_sys::crypto::{keypair, nonce, box_};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                       box_::PUBLICKEYBYTES).unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                          box_::PUBLICKEYBYTES).unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(box_::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = box_::seal(b"test",
///                             theirkeypair.pk_bytes(),
///                             mykeypair.sk_bytes(),
///                             nonce.bytes()).unwrap();
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
/// ```
pub fn seal<'a>(message: &[u8],
                pk: &[u8],
                sk: &[u8],
                nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = utils::malloc(MACBYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_box_easy(ciphertext.as_mut_ptr(),
                              message.as_ptr(),
                              message.len() as c_ulonglong,
                              nonce.as_ptr(),
                              pk.as_ptr(),
                              sk.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

/// The *open()* function verifies and decrypts a ciphertext produced by
/// *seal()*.
///
/// The nonce has to match the nonce used to encrypt and authenticate the
/// message.
///
/// pk is the public key of the sender that encrypted the message. sk is the
/// secret key of the recipient that is willing to verify and decrypt it.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core, utils};
/// use sodium_sys::crypto::{keypair, nonce, box_};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                       box_::PUBLICKEYBYTES).unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                          box_::PUBLICKEYBYTES).unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(box_::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = box_::seal(b"test",
///                             theirkeypair.pk_bytes(),
///                             mykeypair.sk_bytes(),
///                             nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = box_::open(ciphertext,
///                          mykeypair.pk_bytes(),
///                          theirkeypair.sk_bytes(),
///                          nonce.bytes()).unwrap();
/// assert!(b"test" == message);
/// ```
pub fn open<'a>(ciphertext: &[u8],
                pk: &[u8],
                sk: &[u8],
                nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = utils::malloc(ciphertext.len() - MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_box_open_easy(message.as_mut_ptr(),
                                   ciphertext.as_ptr(),
                                   ciphertext.len() as c_ulonglong,
                                   nonce.as_ptr(),
                                   pk.as_ptr(),
                                   sk.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext!"))
    }
}

pub type SealDetachedResult<'a> = Result<(&'a mut [u8], &'a mut [u8]), SSError>;
/// This function encrypts a message with a recipients public key, your secret
/// key and a nonce, and returns a tuple of byte arrays. The first element is
/// the ciphertext, the second is the mac.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core, utils};
/// use sodium_sys::crypto::{keypair, nonce, box_};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                       box_::PUBLICKEYBYTES).unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                          box_::PUBLICKEYBYTES).unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(box_::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = box_::seal_detached(b"test",
///                                            theirkeypair.pk_bytes(),
///                                            mykeypair.sk_bytes(),
///                                            nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// println!("{:?}", mac);
/// ```
pub fn seal_detached<'a>(message: &[u8],
                         pk: &[u8],
                         sk: &[u8],
                         nonce: &[u8]) -> SealDetachedResult<'a> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = utils::malloc(message.len());
    let mut mac = utils::malloc(MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_box_detached(ciphertext.as_mut_ptr(),
                                  mac.as_mut_ptr(),
                                  message.as_ptr(),
                                  message.len() as c_ulonglong,
                                  nonce.as_ptr(),
                                  pk.as_ptr(),
                                  sk.as_ptr());

    }

    if res == 0 {
        utils::mprotect_readonly(ciphertext);
        utils::mprotect_readonly(mac);
        Ok((ciphertext, mac))
    } else {
        Err(ENCRYPT("Unable to encrypt message"))
    }
}

/// This function verifies and decrypts an encrypted message after verifying
/// the given mac, and returns the decrypted message result.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core, utils};
/// use sodium_sys::crypto::{box_, keypair, nonce};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                       box_::PUBLICKEYBYTES).unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another their keypair and activate for use (normally this would be
/// // supplied).
/// let theirkeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                          box_::PUBLICKEYBYTES).unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(box_::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = box_::seal_detached(b"test",
///                                            theirkeypair.pk_bytes(),
///                                            mykeypair.sk_bytes(),
///                                            nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let decrypted = box_::open_detached(ciphertext,
///                                     mac,
///                                     mykeypair.pk_bytes(),
///                                     theirkeypair.sk_bytes(),
///                                     nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open_detached<'a>(ciphertext: &[u8],
                         mac: &[u8],
                         pk: &[u8],
                         sk: &[u8],
                         nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(mac.len() == MACBYTES);
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = utils::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_box_open_detached(message.as_mut_ptr(),
                                       ciphertext.as_ptr(),
                                       mac.as_ptr(),
                                       ciphertext.len() as c_ulonglong,
                                       nonce.as_ptr(),
                                       pk.as_ptr(),
                                       sk.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext"))
    }
}

/// The *seal_with_ssk()* function encrypts a message with a pre-calculated
/// shared secret key and a nonce.
///
/// This function writes the authentication tag immediately followed by the
/// encrypted message.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core, utils};
/// use sodium_sys::crypto::{keypair, nonce, box_};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                       box_::PUBLICKEYBYTES).unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                          box_::PUBLICKEYBYTES).unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(box_::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = box_::seal_with_ssk(b"test",
///                                      ssk,
///                                      nonce.bytes()).unwrap();
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
/// ```
pub fn seal_with_ssk<'a>(message: &[u8],
                         ssk: &[u8],
                         nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = utils::malloc(MACBYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_box_easy_afternm(ciphertext.as_mut_ptr(),
                                      message.as_ptr(),
                                      message.len() as c_ulonglong,
                                      nonce.as_ptr(),
                                      ssk.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

/// The *open_with_ssk()* function verifies and decrypts a ciphertext produced
/// by *seal_with_ssk()*.
///
/// The nonce has to match the nonce used to encrypt and authenticate the
/// message.
///
/// ssk is the shared secret key.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core, utils};
/// use sodium_sys::crypto::{keypair, nonce, box_};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                       box_::PUBLICKEYBYTES).unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
///                                          box_::PUBLICKEYBYTES).unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(box_::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = box_::seal_with_ssk(b"test",
///                                      ssk,
///                                      nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = box_::open_with_ssk(ciphertext,
///                                   ssk,
///                                   nonce.bytes()).unwrap();
/// assert!(b"test" == message);
/// ```
pub fn open_with_ssk<'a>(ciphertext: &[u8],
                         ssk: &[u8],
                         nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = utils::malloc(ciphertext.len() - MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_box_open_easy_afternm(message.as_mut_ptr(),
                                           ciphertext.as_ptr(),
                                           ciphertext.len() as c_ulonglong,
                                           nonce.as_ptr(),
                                           ssk.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext!"))
    }
}
