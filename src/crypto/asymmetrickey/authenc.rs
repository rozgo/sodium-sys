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
use crypto::utils::secmem;

// 32 bytes.
pub const SEEDBYTES: usize = 32;
// 32 bytes.
pub const PUBLICKEYBYTES: usize = 32;
// 32 bytes.
pub const SECRETKEYBYTES: usize = 32;
// 32 bytes.
pub const BEFORENMBYTES: usize = 32;
// 24 bytes.
pub const NONCEBYTES: usize = 24;
// 32 bytes.
pub const ZEROBYTES: usize = 32;
// 16 bytes.
pub const BOXZEROBYTES: usize = 16;
// 16 bytes.
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES;

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
    fn crypto_box_easy_afternm(c: *mut c_uchar,
                               m: *const c_uchar,
                               mlen: c_ulonglong,
                               n: *const c_uchar,
                               k: *const c_uchar) -> c_int;
    fn crypto_box_open_easy_afternm(m: *mut c_uchar,
                                    c: *const c_uchar,
                                    clen: c_ulonglong,
                                    n: *const c_uchar,
                                    k: *const c_uchar) -> c_int;
    fn crypto_box_detached_afternm(c: *mut c_uchar,
                                   mac: *mut c_uchar,
                                   m: *const c_uchar,
                                   mlen: c_ulonglong,
                                   n: *const c_uchar,
                                   k: *const c_uchar) -> c_int;
    fn crypto_box_open_detached_afternm(m: *mut c_uchar,
                                        c: *const c_uchar,
                                        mac: *const c_uchar,
                                        clen: c_ulonglong,
                                        n: *const c_uchar,
                                        k: *const c_uchar) -> c_int;
    fn crypto_box(c: *mut c_uchar,
                  m: *const c_uchar,
                  mlen: c_ulonglong,
                  n: *const c_uchar,
                  pk: *const c_uchar,
                  sk: *const c_uchar) -> c_int;
    fn crypto_box_open(m: *mut c_uchar,
                       c: *const c_uchar,
                       clen: c_ulonglong,
                       n: *const c_uchar,
                       pk: *const c_uchar,
                       sk: *const c_uchar) -> c_int;
    fn crypto_box_afternm(c: *mut c_uchar,
                          m: *const c_uchar,
                          mlen: c_ulonglong,
                          n: *const c_uchar,
                          k: *const c_uchar) -> c_int;
    fn crypto_box_open_afternm(m: *mut c_uchar,
                               c: *const c_uchar,
                               clen: c_ulonglong,
                               n: *const c_uchar,
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal(b"test",
///                                theirkeypair.pk_bytes(),
///                                mykeypair.sk_bytes(),
///                                nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// ```
pub fn seal<'a>(message: &[u8],
                pk: &[u8],
                sk: &[u8],
                nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = secmem::malloc(MACBYTES + message.len());

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
        secmem::mprotect_readonly(ciphertext);
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal(b"test",
///                                theirkeypair.pk_bytes(),
///                                mykeypair.sk_bytes(),
///                                nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = authenc::open(ciphertext,
///                             mykeypair.pk_bytes(),
///                             theirkeypair.sk_bytes(),
///                             nonce.bytes()).unwrap();
/// assert!(b"test" == message);
/// ```
pub fn open<'a>(ciphertext: &[u8],
                pk: &[u8],
                sk: &[u8],
                nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len() - MACBYTES);

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
        secmem::mprotect_readonly(message);
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = authenc::seal_detached(b"test",
///                                               theirkeypair.pk_bytes(),
///                                               mykeypair.sk_bytes(),
///                                               nonce.bytes()).unwrap();
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

    let mut ciphertext = secmem::malloc(message.len());
    let mut mac = secmem::malloc(MACBYTES);

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
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another their keypair and activate for use (normally this would be
/// // supplied).
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = authenc::seal_detached(b"test",
///                                               theirkeypair.pk_bytes(),
///                                               mykeypair.sk_bytes(),
///                                               nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let decrypted = authenc::open_detached(ciphertext,
///                                        mac,
///                                        mykeypair.pk_bytes(),
///                                        theirkeypair.sk_bytes(),
///                                        nonce.bytes()).unwrap();
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

    let mut message = secmem::malloc(ciphertext.len());

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
        secmem::mprotect_readonly(message);
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal_with_ssk(b"test",
///                                         ssk,
///                                         nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// ```
pub fn seal_with_ssk<'a>(message: &[u8],
                         ssk: &[u8],
                         nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = secmem::malloc(MACBYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_box_easy_afternm(ciphertext.as_mut_ptr(),
                                      message.as_ptr(),
                                      message.len() as c_ulonglong,
                                      nonce.as_ptr(),
                                      ssk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
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
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal_with_ssk(b"test",
///                                         ssk,
///                                         nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = authenc::open_with_ssk(ciphertext,
///                                      ssk,
///                                      nonce.bytes()).unwrap();
/// assert!(b"test" == message);
/// ```
pub fn open_with_ssk<'a>(ciphertext: &[u8],
                         ssk: &[u8],
                         nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len() - MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_box_open_easy_afternm(message.as_mut_ptr(),
                                           ciphertext.as_ptr(),
                                           ciphertext.len() as c_ulonglong,
                                           nonce.as_ptr(),
                                           ssk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext!"))
    }
}

/// This function encrypts a message with a shared secret key, and a nonce, and
/// returns a tuple of byte arrays. The first element is the ciphertext, the
/// second is the mac.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = authenc::seal_detached_with_ssk(b"test",
///                                                        ssk,
///                                                        nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// println!("{:?}", mac);
/// ```
pub fn seal_detached_with_ssk<'a>(message: &[u8],
                                  ssk: &[u8],
                                  nonce: &[u8]) -> SealDetachedResult<'a> {
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut ciphertext = secmem::malloc(message.len());
    let mut mac = secmem::malloc(MACBYTES);

    let res: i32;

    unsafe {
        res = crypto_box_detached_afternm(ciphertext.as_mut_ptr(),
                                          mac.as_mut_ptr(),
                                          message.as_ptr(),
                                          message.len() as c_ulonglong,
                                          nonce.as_ptr(),
                                          ssk.as_ptr());

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
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another their keypair and activate for use (normally this would be
/// // supplied).
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let (ciphertext,mac) = authenc::seal_detached_with_ssk(b"test",
///                                                        ssk,
///                                                        nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let decrypted = authenc::open_detached_with_ssk(ciphertext,
///                                                 mac,
///                                                 ssk,
///                                                 nonce.bytes()).unwrap();
/// assert!(decrypted == b"test");
/// ```
pub fn open_detached_with_ssk<'a>(ciphertext: &[u8],
                                  mac: &[u8],
                                  ssk: &[u8],
                                  nonce: &[u8]) -> Result<&'a mut [u8], SSError> {
    assert!(mac.len() == MACBYTES);
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_box_open_detached_afternm(message.as_mut_ptr(),
                                               ciphertext.as_ptr(),
                                               mac.as_ptr(),
                                               ciphertext.len() as c_ulonglong,
                                               nonce.as_ptr(),
                                               ssk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext"))
    }
}

/// The *seal_nacl()* function encrypts a message with a recipient's public key,
/// a sender's secret key and a nonce.
///
/// This function outputs the ciphertext.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal_nacl(b"test",
///                                     theirkeypair.pk_bytes(),
///                                     mykeypair.sk_bytes(),
///                                     nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// ```
pub fn seal_nacl<'a>(message: &[u8],
                     pk: &[u8],
                     sk: &[u8],
                     nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
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
        res = crypto_box(ciphertext.as_mut_ptr(),
                         padded.as_ptr(),
                         padded.len() as c_ulonglong,
                         nonce.as_ptr(),
                         pk.as_ptr(),
                         sk.as_ptr());
    }

    secmem::free(padded);

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

/// The *open_nacl()* function decrypts a ciphertext produced by *seal_nacl()*.
///
/// The nonce has to match the nonce used to encrypt the message.
///
/// pk is the public key of the sender that encrypted the message. sk is the
/// secret key of the recipient that is willing to verify and decrypt it.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal_nacl(b"test",
///                                     theirkeypair.pk_bytes(),
///                                     mykeypair.sk_bytes(),
///                                     nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = authenc::open_nacl(ciphertext,
///                                  mykeypair.pk_bytes(),
///                                  theirkeypair.sk_bytes(),
///                                  nonce.bytes()).unwrap();
/// assert!(&message[authenc::ZEROBYTES..] == b"test");
/// ```
pub fn open_nacl<'a>(ciphertext: &[u8],
                     pk: &[u8],
                     sk: &[u8],
                     nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_box_open(message.as_mut_ptr(),
                              ciphertext.as_ptr(),
                              ciphertext.len() as c_ulonglong,
                              nonce.as_ptr(),
                              pk.as_ptr(),
                              sk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext!"))
    }
}

/// The *seal_nacl_with_ssk()* function encrypts a message with a shared secret
/// key and a nonce.
///
/// This function outputs the ciphertext.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal_nacl_with_ssk(b"test",
///                                              ssk,
///                                              nonce.bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// ```
pub fn seal_nacl_with_ssk<'a>(message: &[u8],
                              ssk: &[u8],
                              nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(ssk.len() == BEFORENMBYTES);
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
        res = crypto_box_afternm(ciphertext.as_mut_ptr(),
                                 padded.as_ptr(),
                                 padded.len() as c_ulonglong,
                                 nonce.as_ptr(),
                                 ssk.as_ptr());
    }

    secmem::free(padded);

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

/// The *open_nacl_with_ssk()* function decrypts a ciphertext produced by
/// *seal_nacl_with_ssk()*.
///
/// The nonce has to match the nonce used to encrypt the message.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init,nonce};
/// use sodium_sys::crypto::asymmetrickey::{authenc,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the keypair and activate for use.
/// let mykeypair = auth_keypair::KeyPair::new().unwrap();
/// mykeypair.activate_sk();
/// mykeypair.activate_pk();
///
/// // Create another keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_sk();
/// theirkeypair.activate_pk();
///
/// // Create the nonce and activate for use.
/// let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
/// nonce.activate();
///
/// // Generate the shared secret key.
/// let ssk = mykeypair.shared_secret(theirkeypair.pk_bytes()).unwrap();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = authenc::seal_nacl_with_ssk(b"test",
///                                              ssk,
///                                              nonce.bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = authenc::open_nacl_with_ssk(ciphertext,
///                                           ssk,
///                                           nonce.bytes()).unwrap();
/// assert!(&message[authenc::ZEROBYTES..] == b"test");
/// ```
pub fn open_nacl_with_ssk<'a>(ciphertext: &[u8],
                              ssk: &[u8],
                              nonce: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(ssk.len() == BEFORENMBYTES);
    assert!(nonce.len() == NONCEBYTES);

    let mut message = secmem::malloc(ciphertext.len());

    let res: i32;

    unsafe {
        res = crypto_box_open_afternm(message.as_mut_ptr(),
                                      ciphertext.as_ptr(),
                                      ciphertext.len() as c_ulonglong,
                                      nonce.as_ptr(),
                                      ssk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext!"))
    }
}
