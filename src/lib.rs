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

pub mod crypto {
    pub mod key;
    pub mod nonce;
    pub mod secretbox;
    pub mod verify;
}

pub use self::SSError::*;

#[derive(Debug)]
pub enum SSError {
    CSTR(NulError),
    DECRYPT(&'static str),
    STR(str::Utf8Error),
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
