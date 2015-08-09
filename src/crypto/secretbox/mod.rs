//! Secret Key Authenticated Encryption
//!
//! Encrypts a message with a key and a nonce to keep it confidential
//! Computes an authentication tag. This tag is used to make sure that the
//! message hasn't been tampered with before decrypting it.
//! A single key is used both to encrypt/sign and verify/decrypt messages.
//! For this reason, it is critical to keep the key confidential.
//! The nonce doesn't have to be confidential, but it should never ever be
//! reused with the same
//! key.
use libc::{c_uchar,c_int,c_ulonglong};
use SSError;
use SSError::{DECRYPT,ENCRYPT};
use utils;

pub mod crypto_secretbox_xsalsa20poly1305;

pub const KEYBYTES: usize = crypto_secretbox_xsalsa20poly1305::KEYBYTES;
pub const NONCEBYTES: usize = crypto_secretbox_xsalsa20poly1305::NONCEBYTES;
pub const MACBYTES: usize = crypto_secretbox_xsalsa20poly1305::MACBYTES;
pub const PRIMITIVE: &'static str = "xsalsa20poly1305";
pub const ZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::ZEROBYTES;
pub const BOXZEROBYTES: usize =
                        crypto_secretbox_xsalsa20poly1305::BOXZEROBYTES;

extern "C" {
    fn crypto_secretbox_easy(c: *mut c_uchar,
                             m: *const c_uchar,
                             mlen: c_ulonglong,
                             n: *const c_uchar,
                             k: *const c_uchar) ->
                             c_int;
    fn crypto_secretbox_open_easy(m: *mut c_uchar,
                                  c: *const c_uchar,
                                  clen: c_ulonglong,
                                  n: *const c_uchar,
                                  k: *const c_uchar) ->
                                  c_int;
    fn crypto_secretbox_detached(c: *mut c_uchar,
                                 mac: *mut c_uchar,
                                 m: *const c_uchar,
                                 mlen: c_ulonglong,
                                 n: *const c_uchar,
                                 k: *const c_uchar) ->
                                 c_int;
    fn crypto_secretbox_open_detached(m: *mut c_uchar,
                                      c: *const c_uchar,
                                      mac: *const c_uchar,
                                      clen: c_ulonglong,
                                      n: *const c_uchar,
                                      k: *const c_uchar) ->
                                      c_int;
    fn crypto_secretbox(c: *mut c_uchar,
                        m: *const c_uchar,
                        mlen: c_ulonglong,
                        n: *const c_uchar,
                        k: *const c_uchar) -> c_int;
    fn crypto_secretbox_open(m: *mut c_uchar,
                             c: *const c_uchar,
                             clen: c_ulonglong,
                             n: *const c_uchar,
                             k: *const c_uchar) -> c_int;
}

/// The *seal()* function encrypts a message with a key and a nonce.
///
/// The key should be KEYBYTES bytes and the nonce should be NONCEBYTES
/// bytes.
///
/// This function writes the authentication tag, whose length is MACBYTES
/// bytes, immediately followed by the encrypted message, whose length is the
/// same as the plaintext.
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
        crypto_secretbox_easy(ciphertext.as_mut_ptr() as
                              *mut c_uchar,
                              message.as_ptr() as *const c_uchar,
                              message.len() as c_ulonglong,
                              nonce.as_ptr() as *const c_uchar,
                              key.as_ptr() as *const c_uchar);

    }

    utils::mprotect_readonly(ciphertext);
    ciphertext
}

/// The *open()* function verifies and decrypts a ciphertext produced by
/// *seal()*.
///
/// The nonce and the key have to match the used to encrypt and authenticate
/// the message.
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
/// let decrypted = secretbox::open(ciphertext,
///                                 key.bytes(),
///                                 nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open<'a>(ciphertext: &[u8],
                key: &[u8],
                nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut message = utils::malloc(ciphertext.len() - MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_secretbox_open_easy(message.as_mut_ptr(),
                                         ciphertext.as_ptr(),
                                         ciphertext.len() as
                                         c_ulonglong,
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

/// This function encrypts a message with a key and a nonce, and returns a tuple
/// of byte arrays. The first element is the ciphertext, the second is the mac.
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
/// let (ciphertext,mac) = secretbox::seal_detached(b"test",
///                                                 key.bytes(),
///                                                 nonce.bytes());
/// utils::mprotect_readonly(ciphertext);
/// utils::mprotect_readonly(mac);
/// println!("{:?}", ciphertext);
/// println!("{:?}", mac);
/// ```
pub fn seal_detached<'a>(message: &[u8],
                         key: &[u8],
                         nonce: &[u8]) -> (&'a mut [u8], &'a mut [u8]) {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut ciphertext = utils::malloc(message.len());
    let mut mac = utils::malloc(MACBYTES);

    unsafe {
        crypto_secretbox_detached(ciphertext.as_mut_ptr() as
                                  *mut c_uchar,
                                  mac.as_mut_ptr() as *mut c_uchar,
                                  message.as_ptr() as *const c_uchar,
                                  message.len() as c_ulonglong,
                                  nonce.as_ptr() as *const c_uchar,
                                  key.as_ptr() as *const c_uchar);

    }

    utils::mprotect_readonly(ciphertext);
    utils::mprotect_readonly(mac);

    (ciphertext, mac)
}

/// This function verifies and decrypts an encrypted message after verifying
/// the given mac, and returns the decrypted message result.
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
/// // Generate the ciphertext and mac and protect them as readonly.
/// let (ciphertext, mac) = secretbox::seal_detached(b"test",
///                                                  key.bytes(),
///                                                  nonce.bytes());
/// utils::mprotect_readonly(ciphertext);
/// utils::mprotect_readonly(mac);
///
/// // Decrypt the ciphertext.
/// let decrypted = secretbox::open_detached(ciphertext,
///                                          mac,
///                                          key.bytes(),
///                                          nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open_detached<'a>(ciphertext: &[u8],
                         mac: &[u8],
                         key: &[u8],
                         nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(mac.len() == MACBYTES);
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut message = utils::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox_open_detached(message.as_mut_ptr(),
                                             ciphertext.as_ptr(),
                                             mac.as_ptr(),
                                             ciphertext.len() as
                                             c_ulonglong,
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

pub fn seal_nacl<'a>(message: &[u8],
                     key: &[u8],
                     nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut padded = utils::malloc(ZEROBYTES + message.len());

    for i in 0..ZEROBYTES {
        padded[i] = 0;
    }

    for (i,b) in (ZEROBYTES..(ZEROBYTES+message.len())).zip(message.iter()) {
        padded[i] = *b;
    }

    let mut ciphertext = utils::malloc(padded.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox(ciphertext.as_mut_ptr() as *mut c_uchar,
                               padded.as_ptr() as *const c_uchar,
                               padded.len() as c_ulonglong,
                               nonce.as_ptr() as *const c_uchar,
                               key.as_ptr() as *const c_uchar);

    }

    utils::free(padded);

    if res == 0 {
        utils::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

pub fn open_nacl<'a>(ciphertext: &[u8],
                     key: &[u8],
                     nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut message = utils::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox_open(message.as_mut_ptr(),
                                    ciphertext.as_ptr(),
                                    ciphertext.len() as c_ulonglong,
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
