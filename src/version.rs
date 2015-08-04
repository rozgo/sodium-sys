use std::ffi::CStr;
use std::str;

extern "C" {
    // sodium/version.h
    fn sodium_version_string() -> *const ::libc::c_char;
    fn sodium_library_version_major() -> ::libc::c_int;
    fn sodium_library_version_minor() -> ::libc::c_int;
}

pub fn version<'a>() -> Result<&'a str, ::SSError> {
    unsafe {
        let slice = CStr::from_ptr(sodium_version_string()).to_bytes();
        Ok(try!(str::from_utf8(slice)))
    }
}

pub fn library_version_major() -> i32 {
    unsafe {
        sodium_library_version_major()
    }
}

pub fn library_version_minor() -> i32 {
    unsafe {
        sodium_library_version_minor()
    }
}
