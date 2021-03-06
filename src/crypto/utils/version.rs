//! libsodium version information.
use libc::{c_char, c_int};
use std::ffi::CStr;
use std::str;

extern "C" {
    fn sodium_version_string() -> *const c_char;
    fn sodium_library_version_major() -> c_int;
    fn sodium_library_version_minor() -> c_int;
}

/// Get the libsodium version as a string.
pub fn version<'a>() -> Result<&'a str, ::SSError> {
    unsafe {
        let slice = CStr::from_ptr(sodium_version_string()).to_bytes();
        Ok(try!(str::from_utf8(slice)))
    }
}

/// The major library version number.
pub fn library_version_major() -> i32 {
    unsafe {
        sodium_library_version_major()
    }
}

/// The minor library version number.
pub fn library_version_minor() -> i32 {
    unsafe {
        sodium_library_version_minor()
    }
}
