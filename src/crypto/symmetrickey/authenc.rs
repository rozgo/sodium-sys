//! Authenticated Encryption
//! Symmetric (Secret) Key Authenticated Encryption
//!
//! Encrypts a message with a key and a nonce to keep it confidential
//! Computes an authentication tag. This tag is used to make sure that the
//! message hasn't been tampered with before decrypting it.
//! A single key is used both to encrypt/sign and verify/decrypt messages.
//! For this reason, it is critical to keep the key confidential.
//! The nonce doesn't have to be confidential, but it should never ever be
//! reused with the same key.
use libc::{c_uchar, c_int, c_ulonglong};
use SSError::{self, DECRYPT, ENCRYPT};
use crypto::utils::secmem;

/// 32 bytes.
pub const KEYBYTES: usize = 32;
/// 24 bytes.
pub const NONCEBYTES: usize = 24;
/// 32 bytes.
pub const ZEROBYTES: usize = 32;
/// 16 bytes.
pub const BOXZEROBYTES: usize = 16;
/// ZEROBYTES - BOXZEROBYTES (16 bytes).
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES;

extern "C" {
    fn crypto_secretbox_easy(c: *mut c_uchar,
                             m: *const c_uchar,
                             mlen: c_ulonglong,
                             n: *const c_uchar,
                             k: *const c_uchar) -> c_int;
    fn crypto_secretbox_open_easy(m: *mut c_uchar,
                                  c: *const c_uchar,
                                  clen: c_ulonglong,
                                  n: *const c_uchar,
                                  k: *const c_uchar) -> c_int;
    fn crypto_secretbox_detached(c: *mut c_uchar,
                                 mac: *mut c_uchar,
                                 m: *const c_uchar,
                                 mlen: c_ulonglong,
                                 n: *const c_uchar,
                                 k: *const c_uchar) -> c_int;
    fn crypto_secretbox_open_detached(m: *mut c_uchar,
                                      c: *const c_uchar,
                                      mac: *const c_uchar,
                                      clen: c_ulonglong,
                                      n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;
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

/// The *encrypt()* function encrypts a message with a key and a nonce.
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::symmetrickey::{authenc,key};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(authenc::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::encrypt(b"test",
///                                   key.bytes(),
///                                   nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// ```
pub fn encrypt<'a>(message: &[u8],
                key: &[u8],
                nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = secmem::malloc(MACBYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox_easy(ciphertext.as_mut_ptr(),
                                    message.as_ptr(),
                                    message.len() as c_ulonglong,
                                    nonce.as_ptr(),
                                    key.as_ptr());

    }

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message"))
    }

}

/// The *open()* function verifies and decrypts a ciphertext produced by
/// *encrypt()*.
///
/// The nonce and the key have to match the used to encrypt and authenticate
/// the message.
///
/// The decrypted message is returned on success.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::symmetrickey::{authenc,key};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(authenc::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::encrypt(b"test",
///                                   key.bytes(),
///                                   nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let decrypted = authenc::open(ciphertext,
///                               key.bytes(),
///                               nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open<'a>(ciphertext: &[u8],
                key: &[u8],
                nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut message = secmem::malloc(ciphertext.len() - MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_secretbox_open_easy(message.as_mut_ptr(),
                                         ciphertext.as_ptr(),
                                         ciphertext.len() as c_ulonglong,
                                         nonce.as_ptr(),
                                         key.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext"))
    }
}

pub type EncryptDetachedResult<'a> = Result<(&'a mut [u8], &'a mut [u8]), SSError>;
/// This function encrypts a message with a key and a nonce, and returns a tuple
/// of byte arrays. The first element is the ciphertext, the second is the mac.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::symmetrickey::{authenc,key};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(authenc::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = authenc::encrypt_detached(b"test",
///                                                  key.bytes(),
///                                                  nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// println!("{:?}", mac);
/// ```
pub fn encrypt_detached<'a>(message: &[u8],
                         key: &[u8],
                         nonce: &[u8]) -> EncryptDetachedResult<'a> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = secmem::malloc(message.len());
    let mut mac = secmem::malloc(MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_secretbox_detached(ciphertext.as_mut_ptr(),
                                        mac.as_mut_ptr(),
                                        message.as_ptr(),
                                        message.len() as c_ulonglong,
                                        nonce.as_ptr(),
                                        key.as_ptr());

    }

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
        secmem::mprotect_readonly(mac);
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::symmetrickey::{authenc,key};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(authenc::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and mac and protect them as readonly.
/// let (ciphertext, mac) = authenc::encrypt_detached(b"test",
///                                                   key.bytes(),
///                                                   nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let decrypted = authenc::open_detached(ciphertext,
///                                        mac,
///                                        key.bytes(),
///                                        nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open_detached<'a>(ciphertext: &[u8],
                         mac: &[u8],
                         key: &[u8],
                         nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(mac.len() == MACBYTES);
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox_open_detached(message.as_mut_ptr(),
                                             ciphertext.as_ptr(),
                                             mac.as_ptr(),
                                             ciphertext.len() as c_ulonglong,
                                             nonce.as_ptr(),
                                             key.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext"))
    }
}

/// The *encrypt_nacl()* function encrypts and authenticates a message using a
/// secret key and a nonce. The *encrypt_nacl()* function returns Result containing
/// a byte sequence containing the ciphertext.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::symmetrickey::{authenc,key};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(authenc::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::encrypt_nacl(b"test",
///                                        key.bytes(),
///                                        nonce.bytes()).unwrap();
///
/// println!("{:?}", ciphertext);
/// ```
pub fn encrypt_nacl<'a>(message: &[u8],
                     key: &[u8],
                     nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut padded = secmem::malloc(ZEROBYTES + message.len());

    for i in 0..ZEROBYTES {
        padded[i] = 0;
    }

    for (i,b) in (ZEROBYTES..(ZEROBYTES+message.len())).zip(message.iter()) {
        padded[i] = *b;
    }

    let mut ciphertext = secmem::malloc(padded.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox(ciphertext.as_mut_ptr(),
                               padded.as_ptr(),
                               padded.len() as c_ulonglong,
                               nonce.as_ptr(),
                               key.as_ptr());

    }

    secmem::free(padded);

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

/// The *open_nacl()* function verifies and decrypts a ciphertext using a secret
/// key and a nonce. The *open_nacl()* function returns a Result containing a
/// byte sequence representing the plaintext.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::symmetrickey::{authenc,key};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(authenc::KEYBYTES);
/// key.activate();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::encrypt_nacl(b"test",
///                                        key.bytes(),
///                                        nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let decrypted = authenc::open_nacl(ciphertext,
///                                    key.bytes(),
///                                    nonce.bytes()).unwrap();
/// assert!(&decrypted[authenc::ZEROBYTES..] == b"test");
/// ```
pub fn open_nacl<'a>(ciphertext: &[u8],
                     key: &[u8],
                     nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_secretbox_open(message.as_mut_ptr(),
                                    ciphertext.as_ptr(),
                                    ciphertext.len() as c_ulonglong,
                                    nonce.as_ptr(),
                                    key.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext"))
    }
}
