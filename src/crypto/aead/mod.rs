//! Secret Key Authenticated Encryption with Associated Data
//!
//! This operation:
//!
//! - Encrypts a message with a key and a nonce to keep it confidential
//! - Computes an authentication tag. This tag is used to make sure that the message, as well as
//!   optional, non-confidential (non-encrypted) data, haven't been tampered with.
//! A typical use case for associated data is to store protocol-specific metadata about the
//! message, such as its length and encoding.
//!
//! The chosen construction uses encrypt-then-MAC and decryption will never be performed, even
//! partially, before verification.
//!
//! # Notes
//!
//! The nonce is 64 bits long. In order to prevent nonce reuse, if a key is being reused, it is
//! recommended to increment the previous nonce instead of generating a random nonce for each
//! message.
//!
//! The API conforms to the proposed API for the
//! [CAESAR](http://competitions.cr.yp.to/caesar.html) competition.
//!
//! The construction conforms to the [ChaCha20 and Poly1305 based Cipher Suites for TLS draft]
//! (https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04), and
//! Sodium's implementation is fully interoperable with other current implementations.
//!
//! The [ChaCha20 and Poly1305 for IETF protocols](https://tools.ietf.org/html/rfc7539) RFC
//! published later slightly changes the construction. That construction is also available by
//! building sodium-sys with the latest feature as *aead_encrypt_ietf()* and *aead_decrypt_ietf()*.
//! It features a longer nonce, which is IETF_NONCEBYTES bytes long.
//!
//! A high-level *aead_*()* API is intentionally not defined until the
//! [CAESAR](http://competitions.cr.yp.to/caesar.html) competition is over.
use libc::{c_int,c_uchar, c_ulonglong};
use SSError::{self, DECRYPT, ENCRYPT};
use std::ptr;
use utils;


/// 32 bytes.
pub const KEYBYTES: usize = 32;
/// 0 bytes.
// pub const NSECBYTES: usize = 0;
/// 8 bytes.
pub const NPUBBYTES: usize = 8;
#[cfg(feature = "latest")]
/// 12 bytes.
pub const IETF_NPUBBYTES: usize = 12;
/// 16 bytes.
pub const ABYTES: usize = 16;

extern "C" {
    fn crypto_aead_chacha20poly1305_encrypt(c: *mut c_uchar,
                                            clen: *mut c_ulonglong,
                                            m: *const c_uchar,
                                            mlen: c_ulonglong,
                                            ad: *const c_uchar,
                                            adlen: c_ulonglong,
                                            nsec: *const c_uchar,
                                            npub: *const c_uchar,
                                            k: *const c_uchar) -> c_int;
    fn crypto_aead_chacha20poly1305_decrypt(m: *mut c_uchar,
                                            mlen: *mut c_ulonglong,
                                            nsec: *mut c_uchar,
                                            c: *const c_uchar,
                                            clen: c_ulonglong,
                                            ad: *const c_uchar,
                                            adlen: c_ulonglong,
                                            npub: *const c_uchar,
                                            k: *const c_uchar) -> c_int;
    #[cfg(feature = "latest")]
    fn crypto_aead_chacha20poly1305_ietf_encrypt(c: *mut c_uchar,
                                                 clen: *mut c_ulonglong,
                                                 m: *const c_uchar,
                                                 mlen: c_ulonglong,
                                                 ad: *const c_uchar,
                                                 adlen: c_ulonglong,
                                                 nsec: *const c_uchar,
                                                 npub: *const c_uchar,
                                                 k: *const c_uchar) -> c_int;
    #[cfg(feature = "latest")]
    fn crypto_aead_chacha20poly1305_ietf_decrypt(m: *mut c_uchar,
                                                 mlen: *mut c_ulonglong,
                                                 nsec: *mut c_uchar,
                                                 c: *const c_uchar,
                                                 clen: c_ulonglong,
                                                 ad: *const c_uchar,
                                                 adlen: c_ulonglong,
                                                 npub: *const c_uchar,
                                                 k: *const c_uchar) -> c_int;
}

/// The *aead_encrypt()* function encrypts a message using a secret key and a public nonce.
///
/// The encrypted message, as well as a tag authenticating both the confidential message and
/// non-confidential data, are put into the output byte sequence.
///
/// Associated data is optional and can be None if no associated data are required..  Also, the
/// associated data should be less than ABYTES in length.
///
/// The public nonce should never ever be reused with the same key. The recommended way to
/// generate it is to use the Nonce struct for the first message, and increment it for each
/// subsequent message using the same key.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,utils};
/// use sodium_sys::crypto::{key,nonce,aead};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(aead::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(aead::NPUBBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = aead::aead_encrypt(b"test", None, key.bytes(), nonce.bytes()).unwrap();
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
///
/// // Generate the ciphertext with additional data and protect it as readonly.
/// let ciphertext = aead::aead_encrypt(b"test",
///                                     Some(b"more data"),
///                                     key.bytes(),
///                                     nonce.bytes()).unwrap();
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
/// ```
pub fn aead_encrypt<'a>(message: &[u8],
                        add_data: Option<&[u8]>,
                        key: &[u8],
                        nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NPUBBYTES);

    if add_data.is_some() {
        assert!(add_data.unwrap().len() <= ABYTES);
    }

    let (ad_ptr, ad_len) = match add_data {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None     => (ptr::null(), 0),
    };

    let mut ciphertext = utils::malloc(ABYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_aead_chacha20poly1305_encrypt(ciphertext.as_mut_ptr(),
                                                   ptr::null_mut(),
                                                   message.as_ptr(),
                                                   message.len() as c_ulonglong,
                                                   ad_ptr,
                                                   ad_len as c_ulonglong,
                                                   ptr::null(),
                                                   nonce.as_ptr(),
                                                   key.as_ptr());
    }

    if res == 0 {
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message and associated data"))
    }
}

/// The *aead_decrypt()* function verifies that the ciphertext (as produced by *aead_encrypt()*)
/// includes a valid tag using a secret key, a public nonce, and optional associated data.
///
/// Associated data is optional and can be None if no associated data are required.  Also, the
/// associated data should be less than ABYTES in length.
///
/// The function returns a result containing decrypted message.
///
/// # Examples
///
/// ```
/// ```
pub fn aead_decrypt<'a>(ciphertext: &[u8],
                        add_data: Option<&[u8]>,
                        key: &[u8],
                        nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NPUBBYTES);

    if add_data.is_some() {
        assert!(add_data.unwrap().len() <= ABYTES);
    }

    let (ad_ptr, ad_len) = match add_data {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None     => (ptr::null(), 0),
    };

    let mut message = utils::malloc(ciphertext.len() - ABYTES);

    let res: i32;

    unsafe {
        res = crypto_aead_chacha20poly1305_decrypt(message.as_mut_ptr(),
                                                   ptr::null_mut(),
                                                   ptr::null_mut(),
                                                   ciphertext.as_ptr(),
                                                   ciphertext.len() as c_ulonglong,
                                                   ad_ptr,
                                                   ad_len as c_ulonglong,
                                                   nonce.as_ptr(),
                                                   key.as_ptr());
    }

    if res == 0 {
        Ok(message)
    } else {
        Err(DECRYPT("Error decrypting ciphertext with associated data"))
    }
}

#[cfg(feature = "latest")]
/// The *aead_encrypt_ietf()* function encrypts a message using a secret key and a public nonce.
///
/// The encrypted message, as well as a tag authenticating both the confidential message and
/// non-confidential data, are put into the output byte sequence.
///
/// Associated data is optional and can be None if no associated data are required..  Also, the
/// associated data should be less than ABYTES in length.
///
/// The public nonce should never ever be reused with the same key. The recommended way to
/// generate it is to use the Nonce struct for the first message, and increment it for each
/// subsequent message using the same key.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,utils};
/// use sodium_sys::crypto::{key,nonce,aead};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(aead::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(aead::IETF_NPUBBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = aead::aead_encrypt_ietf(b"test", None, key.bytes(), nonce.bytes()).unwrap();
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
///
/// // Generate the ciphertext with additional data and protect it as readonly.
/// let ciphertext = aead::aead_encrypt_ietf(b"test",
///                                          Some(b"more data"),
///                                          key.bytes(),
///                                          nonce.bytes()).unwrap();
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
/// ```
pub fn aead_encrypt_ietf<'a>(message: &[u8],
                             add_data: Option<&[u8]>,
                             key: &[u8],
                             nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == IETF_NPUBBYTES);

    if add_data.is_some() {
        assert!(add_data.unwrap().len() <= ABYTES);
    }

    let (ad_ptr, ad_len) = match add_data {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None     => (ptr::null(), 0),
    };

    let mut ciphertext = utils::malloc(ABYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext.as_mut_ptr(),
                                                        ptr::null_mut(),
                                                        message.as_ptr(),
                                                        message.len() as c_ulonglong,
                                                        ad_ptr,
                                                        ad_len as c_ulonglong,
                                                        ptr::null(),
                                                        nonce.as_ptr(),
                                                        key.as_ptr());
    }

    if res == 0 {
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message and associated data"))
    }
}

#[cfg(feature = "latest")]
/// The *aead_decrypt_ietf()* function verifies that the ciphertext (as produced by
/// *aead_encrypt()*) includes a valid tag using a secret key, a public nonce, and optional
/// associated data.
///
/// Associated data is optional and can be None if no associated data are required.  Also, the
/// associated data should be less than ABYTES in length.
///
/// The function returns a result containing decrypted message.
///
/// # Examples
///
/// ```
/// ```
pub fn aead_decrypt_ietf<'a>(ciphertext: &[u8],
                             add_data: Option<&[u8]>,
                             key: &[u8],
                             nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == IETF_NPUBBYTES);

    if add_data.is_some() {
        assert!(add_data.unwrap().len() <= ABYTES);
    }

    let (ad_ptr, ad_len) = match add_data {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None     => (ptr::null(), 0),
    };

    let mut message = utils::malloc(ciphertext.len() - ABYTES);

    let res: i32;

    unsafe {
        res = crypto_aead_chacha20poly1305_ietf_decrypt(message.as_mut_ptr(),
                                                        ptr::null_mut(),
                                                        ptr::null_mut(),
                                                        ciphertext.as_ptr(),
                                                        ciphertext.len() as c_ulonglong,
                                                        ad_ptr,
                                                        ad_len as c_ulonglong,
                                                        nonce.as_ptr(),
                                                        key.as_ptr());
    }

    if res == 0 {
        Ok(message)
    } else {
        Err(DECRYPT("Error decrypting ciphertext with associated data"))
    }
}
