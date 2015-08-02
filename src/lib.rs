#![allow(non_camel_case_types)]
extern crate libc;

use std::ffi::NulError;
use std::str::Utf8Error;

mod core;
mod crypto_verify_16;
mod utils;

pub use core::sodium_init;
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
