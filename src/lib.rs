//! [Sodium](https://github.com/jedisct1/libsodium) is a modern, easy-to-use software library for
//! encryption, decryption, signatures, password hashing and more.
//!
//! It is a portable, cross-compilable, installable, packageable fork of
//! [NaCl](http://nacl.cr.yp.to), with a compatible API, and an extended API to improve usability
//! even further.
//!
//! Its goal is to provide all of the core operations needed to build higher-level cryptographic
//! tools.
//!
//! Sodium supports a variety of compilers and operating systems, including Windows (with MinGW or
//! Visual Studio, x86 and x64), iOS and Android.
//!
//! The design choices emphasize security, and "magic constants" have clear rationales.
//!
//! And despite the emphasis on high security, primitives are faster across-the-board than most
//! implementations of the NIST standards.
//!
//! Version 1.0.3 was released on May 9, 2015.
//!
//! [sodium-sys](https://github.com/rustyhorde/sodium-sys) is rust bindings for
//! [Sodium](https://github.com/jedisct1/libsodium).
#![allow(non_camel_case_types)]
extern crate libc;
#[cfg(test)] extern crate regex;

use std::ffi::NulError;
use std::str::Utf8Error;

mod core;
mod crypto_verify_16;
mod utils;

pub use core::*;
pub use crypto_verify_16::*;
pub use utils::*;

pub use self::SSError::*;

#[derive(Debug)]
pub enum SSError {
    CSTR(NulError),
    STR(Utf8Error),
}

impl From<NulError> for SSError {
    fn from(err: NulError) -> SSError {
        CSTR(err)
    }
}

impl From<Utf8Error> for SSError {
    fn from(err: Utf8Error) -> SSError {
        STR(err)
    }
}
