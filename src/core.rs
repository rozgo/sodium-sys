extern "C" {
    fn sodium_init() -> ::libc::c_int;
}

/// *init()* initializes the library and should be called before any other function
/// provided by sodium_sys. The function can be called more than once, but it should not be
/// executed by multiple threads simultaneously. Add appropriate locks around the function call
/// if this scenario can happen in your application.
///
/// After this function returns, all of the other functions provided by sodium_sys will be
/// thread-safe.
///
/// *sodium_init()* doesn't perform any memory allocations. However, on Unix systems, it opens
/// */dev/urandom* and keeps the descriptor open so that the device remains accessible after a
/// *chroot()* call. Multiple calls to *sodium_init()* do not cause additional descriptors to
/// be opened.
///
/// *init()* safely wraps *sodium_init()*.
///
/// # Examples
///
/// ```
/// use sodium_sys::core;
///
/// assert!(core::init() == 0);
/// ```
pub fn init() -> i32 {
    unsafe {
        sodium_init()
    }
}

#[test]
fn test_init() {
    assert!(init() == 0);
}
