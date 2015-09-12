//! [Sodium](https://github.com/jedisct1/libsodium) is a modern, easy-to-use
//! software library for encryption, decryption, signatures, password hashing
//! and more.
//!
//! It is a portable, cross-compilable, installable, packageable fork of
//! [NaCl](http://nacl.cr.yp.to), with a compatible API, and an extended API to
//! improve usability even further.
//!
//! Its goal is to provide all of the core operations needed to build
//! higher-level cryptographic tools.
//!
//! Sodium supports a variety of compilers and operating systems, including
//! Windows (with MinGW or Visual Studio, x86 and x64), iOS and Android.
//!
//! The design choices emphasize security, and "magic constants" have clear
//! rationales.
//!
//! And despite the emphasis on high security, primitives are faster
//! across-the-board than most implementations of the NIST standards.
//!
//! Version 1.0.3 was released on May 9, 2015.
//! Building feature "latest" will build with version 1.0.4.
//!
//! [sodium-sys](https://github.com/rustyhorde/sodium-sys) is rust bindings for
//! [Sodium](https://github.com/jedisct1/libsodium).
#![allow(non_upper_case_globals)]
extern crate libc;
#[cfg(test)]
extern crate regex;

use std::ffi::NulError;
use std::str;
use std::string;

pub mod core;
pub mod randombytes;
pub mod utils;
pub mod version;

/// Crypography library modules.
pub mod crypto {
    pub mod aead;
    pub mod auth;
    pub mod box_;
    pub mod key;
    pub mod nonce;
    pub mod secretbox;
    pub mod sign;
    pub mod verify;
}

pub use self::SSError::*;

#[derive(Debug)]
/// A sodium-sys error.  This is used to wrap various other errors to unify
/// the Result returns from the library.
pub enum SSError {
    /// An error returned from ```CString::new``` to indicate that a nul byte
    /// was found in the vector provided.
    CSTR(NulError),
    /// An error returned from functions that decrypt ciphertext.
    DECRYPT(&'static str),
    /// An error returned from functions that encrypt messages.
    ENCRYPT(&'static str),
    /// An error returned from functions the generate keypairs.
    KEYGEN(&'static str),
    /// An error returned from functions that generate MACs.
    MAC(&'static str),
    /// An error returned from signing functions.
    SIGN(&'static str),
    /// Errors which can occur when attempting to interpret a byte slice as a
    /// str.
    STR(str::Utf8Error),
    /// A possible error value from the String::from_utf8 function.
    STRING(string::FromUtf8Error),
}

impl From<NulError> for SSError {
    fn from(err: NulError) -> SSError {
        CSTR(err)
    }
}

impl From<str::Utf8Error> for SSError {
    fn from(err: str::Utf8Error) -> SSError {
        STR(err)
    }
}

impl From<string::FromUtf8Error> for SSError {
    fn from(err: string::FromUtf8Error) -> SSError {
        STRING(err)
    }
}
