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
use crypto::{keypair, nonce};
use SSError::{self, ENCRYPT};
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
    pub fn crypto_box_easy(c: *mut c_uchar, m: *const c_uchar,
                           mlen: c_ulonglong, n: *const c_uchar,
                           pk: *const c_uchar, sk: *const c_uchar) -> c_int;
    pub fn crypto_box_open_easy(m: *mut c_uchar, c: *const c_uchar,
                                clen: c_ulonglong, n: *const c_uchar,
                                pk: *const c_uchar, sk: *const c_uchar)
                                -> c_int;
    pub fn crypto_box_detached(c: *mut c_uchar, mac: *mut c_uchar,
                               m: *const c_uchar, mlen: c_ulonglong,
                               n: *const c_uchar, pk: *const c_uchar,
                               sk: *const c_uchar) -> c_int;
    pub fn crypto_box_open_detached(m: *mut c_uchar, c: *const c_uchar,
                                    mac: *const c_uchar,
                                    clen: c_ulonglong,
                                    n: *const c_uchar,
                                    pk: *const c_uchar,
                                    sk: *const c_uchar) -> c_int;
}

pub fn seal<'a>(message: &[u8],
                keypair: keypair::KeyPair,
                nonce: nonce::Nonce) -> Result<&'a [u8], SSError> {
    assert!(keypair.pk_bytes().len() == PUBLICKEYBYTES);
    assert!(keypair.sk_bytes().len() == SECRETKEYBYTES);
    assert!(nonce.bytes().len() == NONCEBYTES);

    let mut ciphertext = utils::malloc(MACBYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_box_easy(ciphertext.as_mut_ptr(),
                              message.as_ptr(),
                              message.len() as c_ulonglong,
                              nonce.bytes().as_ptr(),
                              keypair.pk_bytes().as_ptr(),
                              keypair.sk_bytes().as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }

}
