//! Secret Key Authenticated Encryption
//!
//! Encrypts a message with a key and a nonce to keep it confidential
//! Computes an authentication tag. This tag is used to make sure that the message hasn't been
//! tampered with before decrypting it.
//! A single key is used both to encrypt/sign and verify/decrypt messages. For this reason, it is
//! critical to keep the key confidential.
//! The nonce doesn't have to be confidential, but it should never ever be reused with the same
//! key.
use ::SSError;
use ::SSError::DECRYPT;
use utils;

pub mod crypto_secretbox_xsalsa20poly1305;

pub const KEYBYTES: usize = crypto_secretbox_xsalsa20poly1305::KEYBYTES;
pub const NONCEBYTES: usize = crypto_secretbox_xsalsa20poly1305::NONCEBYTES;
pub const MACBYTES: usize = crypto_secretbox_xsalsa20poly1305::MACBYTES;
pub const PRIMITIVE: &'static str = "xsalsa20poly1305";
pub const ZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::ZEROBYTES;
pub const BOXZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::BOXZEROBYTES;

extern "C" {
    fn crypto_secretbox_easy(c: *mut ::libc::c_uchar, m: *const ::libc::c_uchar,
                             mlen: ::libc::c_ulonglong, n: *const ::libc::c_uchar,
                             k: *const ::libc::c_uchar) -> ::libc::c_int;
    fn crypto_secretbox_open_easy(m: *mut ::libc::c_uchar, c: *const ::libc::c_uchar,
                                  clen: ::libc::c_ulonglong, n: *const ::libc::c_uchar,
                                  k: *const ::libc::c_uchar) -> ::libc::c_int;
}

/// The *seal()* function encrypts a message with a key and a nonce.
///
/// The key should be KEYBYTES bytes and the nonce should be NONCEBYTES bytes.
///
/// This function writes the authentication tag, whose length is MACBYTES bytes, immediately
/// followed by the encrypted message, whose length is the same as the plaintext.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,utils};
/// use sodium_sys::crypto::{key,nonce,secretbox};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(secretbox::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let mut nonce = nonce::Nonce::new(secretbox::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = secretbox::seal(b"test", key.bytes(), nonce.bytes());
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
/// ```
pub fn seal<'a>(message: &[u8], key: &[u8], nonce: &[u8]) -> &'a mut [u8] {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut ciphertext = utils::malloc(MACBYTES + message.len());

    unsafe {
        crypto_secretbox_easy(ciphertext.as_mut_ptr() as *mut ::libc::c_uchar,
                              message.as_ptr() as *const ::libc::c_uchar,
                              message.len() as ::libc::c_ulonglong,
                              nonce.as_ptr() as *const ::libc::c_uchar,
                              key.as_ptr() as *const ::libc::c_uchar);

    }

    utils::mprotect_readonly(ciphertext);
    ciphertext
}

/// The *open()* function verifies and decrypts a ciphertext produced by *seal()*.
///
/// The nonce and the key have to match the used to encrypt and authenticate the message.
///
/// The decrypted message is returned on success.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,utils};
/// use sodium_sys::crypto::{key,nonce,secretbox};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(secretbox::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let mut nonce = nonce::Nonce::new(secretbox::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = secretbox::seal(b"test", key.bytes(), nonce.bytes());
/// utils::mprotect_readonly(ciphertext);
///
/// // Decrypt the ciphertext.
/// let decrypted = secretbox::open(ciphertext, key.bytes(), nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open<'a>(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut message = utils::malloc(ciphertext.len() - MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_secretbox_open_easy(message.as_mut_ptr(),
                                         ciphertext.as_ptr(),
                                         ciphertext.len() as ::libc::c_ulonglong,
                                         nonce.as_ptr(),
                                         key.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext"))
    }
}
