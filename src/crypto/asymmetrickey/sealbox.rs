//! Sealed boxes are designed to anonymously send messages to a recipient given
//! its public key.
//!
//! Only the recipient can decrypt these messages, using its private key. While
//! the recipient can verify the integrity of the message, it cannot verify the
//! identity of the sender.
//!
//! A message is encrypted using an ephemeral key pair, whose secret part is
//! destroyed right after the encryption process.
//!
//! Without knowing the secret key used for a given message, the sender cannot
//! decrypt its own message later. And without additional data, a message cannot
//! be correlated with the identity of its sender.
use libc::{c_int, c_uchar, c_ulonglong};

extern "C" {
    pub fn crypto_box_seal(out: *mut c_uchar,
                           in_: *const c_uchar,
                           inlen: c_ulonglong,
                           pk: *const c_uchar) -> c_int;
    pub fn crypto_box_seal_open(out: *mut c_uchar,
                                in_: *const c_uchar,
                                inlen: c_ulonglong,
                                pk: *const c_uchar) -> c_int;
}
