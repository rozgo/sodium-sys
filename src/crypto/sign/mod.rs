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

extern "C" {
    pub fn crypto_sign(sm: *mut c_uchar,
                       smlen_p: *mut c_ulonglong,
                       m: *const c_uchar,
                       mlen: c_ulonglong,
                       sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_open(m: *mut c_uchar,
                            mlen_p: *mut c_ulonglong,
                            sm: *const c_uchar,
                            smlen: c_ulonglong,
                            pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_detached(sig: *mut c_uchar,
                                siglen_p: *mut c_ulonglong,
                                m: *const c_uchar,
                                mlen: c_ulonglong,
                                sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_verify_detached(sig: *const c_uchar,
                                       m: *const c_uchar,
                                       mlen: c_ulonglong,
                                       pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_seed(seed: *mut c_uchar,
                                          sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_pk(pk: *mut c_uchar,
                                        sk: *const c_uchar) -> c_int;
}
