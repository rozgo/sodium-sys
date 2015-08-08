use std::ffi::{CStr, CString};
use std::slice;
use std::str;

extern "C" {
    // sodium/utils.h
    fn sodium_memzero(pnt: *mut ::libc::c_void, len: ::libc::size_t) -> ();
    fn sodium_memcmp(b1_: *const ::libc::c_void,
                     b2_: *const ::libc::c_void,
                     len: ::libc::size_t)
                     -> ::libc::c_int;
    fn sodium_bin2hex(hex: *mut ::libc::c_char,
                      hex_maxlen: ::libc::size_t,
                      bin: *const ::libc::c_uchar,
                      bin_len: ::libc::size_t)
                      -> *mut ::libc::c_char;
    fn sodium_hex2bin(bin: *mut ::libc::c_uchar,
                      bin_maxlen: ::libc::size_t,
                      hex: *const ::libc::c_char,
                      hex_len: ::libc::size_t,
                      ignore: *const ::libc::c_char,
                      bin_len: *mut ::libc::size_t,
                      hex_end: *mut *const ::libc::c_char)
                       -> ::libc::c_int;
    fn sodium_mlock(addr: *mut ::libc::c_void,
                    len: ::libc::size_t)
                    -> ::libc::c_int;
    fn sodium_munlock(addr: *mut ::libc::c_void,
                      len: ::libc::size_t)
                      -> ::libc::c_int;
    fn sodium_malloc(size: ::libc::size_t) -> *mut ::libc::c_void;
    fn sodium_allocarray(count: ::libc::size_t,
                         size: ::libc::size_t)
                         -> *mut ::libc::c_void;
    fn sodium_free(ptr: *mut ::libc::c_void) -> ();
    fn sodium_mprotect_noaccess(ptr: *mut ::libc::c_void) -> ::libc::c_int;
    fn sodium_mprotect_readonly(ptr: *mut ::libc::c_void) -> ::libc::c_int;
    fn sodium_mprotect_readwrite(ptr: *mut ::libc::c_void) -> ::libc::c_int;
    #[cfg(feature = "latest")]
    fn sodium_increment(n: *mut ::libc::c_uchar, nlen: ::libc::size_t) -> ();
}

/// After use, sensitive data should be overwritten, but *memset()* and
/// hand-written code can be silently stripped out by an optimizing compiler or
/// by the linker.
///
/// The *memzero()* function tries to effectively zero the bytes in *mem*, even
/// if optimizations are being applied to the code.  This function safely wraps
/// a call to *sodium_memzero()*.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils::memzero;
///
/// let v = [0, 1, 2, 3, 4, 5, 6, 7];
/// memzero(&v);
/// assert!(v == [0; 8]);
/// ```
pub fn memzero(mem: &[u8]) {
    unsafe {
        sodium_memzero(mem.as_ptr() as *mut ::libc::c_void,
                       mem.len() as ::libc::size_t);
    }
}

/// When a comparison involves secret data (e.g. key, authentication tag), is it
/// critical to use a constant-time comparison function in order to mitigate
/// side-channel attacks.
///
/// The *memcmp()* function can be used for this purpose.
///
/// The function returns 0 if the bytes pointed to by *m1* match the bytes
/// pointed to by *m2*. Otherwise, it returns -1.
///
/// Note: *memcmp* safely wraps *sodium_memcmp*.  *sodium_memcmp()* is not a
/// lexicographic comparator and is not a generic replacement for *memcmp()*.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils::memcmp;
///
/// let v0 = [0, 1, 2, 3, 4, 5, 6, 7];
/// let v1 = [0, 1, 2, 3, 4, 5, 6, 7];
/// let v2 = [7, 6, 5, 4, 3, 2, 1, 0];
/// assert!(memcmp(&v0,&v1) == 0);
/// assert!(memcmp(&v0,&v2) == -1);
/// assert!(memcmp(&v1,&v2) == -1);
/// ```
pub fn memcmp(m1: &[u8], m2: &[u8]) -> i32 {
    if m1.len() == m2.len() {
        unsafe {
            sodium_memcmp(m1.as_ptr() as *const ::libc::c_void,
                          m2.as_ptr() as *const ::libc::c_void,
                          m1.len() as ::libc::size_t)
        }
    } else {
        -1
    }
}

/// The *bin2hex()* function converts a byte sequence into a hexadecimal string.
///
/// The *bin2hex()* function safely wraps the *sodium_bin2hex()* function.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils::bin2hex;
///
/// let v = [0, 1, 254, 255];
/// assert!(bin2hex(&v).unwrap() == "0001feff");
/// ```
pub fn bin2hex(mem: &[u8]) -> Result<String, ::SSError> {
    let hlen = (mem.len() * 2) + 1;
    let mut bufvec: Vec<i8> = Vec::with_capacity(hlen);
    for _ in 0..hlen {
        bufvec.push(0);
    }
    let mut buf = &mut bufvec[..];
    unsafe {
        let buf_ptr = sodium_bin2hex(buf.as_mut_ptr(),
                                     buf.len() as ::libc::size_t,
                                     mem.as_ptr(),
                                     mem.len() as ::libc::size_t);
        let slice = CStr::from_ptr(buf_ptr).to_bytes();
        Ok(try!(str::from_utf8(slice)).to_string())
    }
}

/// The *hex2bin()* function parses a hexadecimal string and converts it to a
/// byte sequence.
///
/// *ignore* is a string of characters to skip. For example, the string ": "
/// allows columns and spaces to be present at any locations in the hexadecimal
/// string. These characters will just be ignored. As a result, "69:FC",
/// "69 FC", "69 : FC" and "69FC" will be valid inputs, and will produce the
/// same output.
///
/// *ignore* can be set to None in order to disallow any non-hexadecimal
/// character.
///
/// The function returns -1 on failure. It returns 0 on success and sets
/// *output* to the byte sequence.
///
/// It evaluates in constant time for a given length and format.
///
/// *hex2bin()* safely wraps the *sodium_hex2bin()* function.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils::hex2bin;
///
/// let hex = String::from("0001feff");
/// let mut output = Vec::new();
/// assert!(hex2bin(hex, &mut output, None) == 0);
/// assert!(output == [0, 1, 254, 255]);
///
/// let hex = String::from("00:01:fe:ff");
/// let ignore = Some(String::from(":"));
/// let mut output = Vec::new();
/// assert!(hex2bin(hex, &mut output, ignore) == 0);
/// assert!(output == [0, 1, 254, 255]);
///
/// let hex = String::from("00 01 fe ff");
/// let ignore = Some(String::from(" "));
/// let mut output = Vec::new();
/// assert!(hex2bin(hex, &mut output, ignore) == 0);
/// assert!(output == [0, 1, 254, 255]);
///
/// let hex = String::from("00 01:fe ff");
/// let ignore = Some(String::from(": "));
/// let mut output = Vec::new();
/// assert!(hex2bin(hex, &mut output, ignore) == 0);
/// assert!(output == [0, 1, 254, 255]);
/// ```
pub fn hex2bin(hex: String,
              output: &mut Vec<u8>,
              ignore: Option<String>) -> i32 {
    let mut base = hex.clone();
    let igstr = match ignore {
        Some(i) => {
            for c in i.chars() {
                base = base.replace(&c.to_string()[..], "");
            }
            CString::new(i).unwrap()
        },
        None    => CString::new("").unwrap(),
    };

    let chex_len = hex.len() + 1;
    let blen = base.len() / 2;
    let chex = CString::new(hex).unwrap();
    let mut bufvec: Vec<u8> = Vec::with_capacity(blen);
    for _ in 0..blen {
        bufvec.push(0);
    }
    let mut buf = &mut bufvec[..];
    let mut b: [::libc::size_t; 1] = [0];
    let hex_end: [i8; 1] = [0];

    unsafe {
        let res = sodium_hex2bin(buf.as_mut_ptr(),
                                 buf.len() as ::libc::size_t,
                                 chex.as_ptr(),
                                 chex_len as ::libc::size_t,
                                 igstr.as_ptr(),
                                 b.as_mut_ptr(),
                                 hex_end.as_ptr() as *mut *const i8);

        for b in buf.iter() {
            output.push(*b);
        }

        res
    }


}

/// The *mlock()* function locks the bytes of the given array. This can help
/// avoid swapping sensitive data to disk.
///
/// In addition, it is recommended to totally disable swap partitions on
/// machines processing senstive data, or, as a second choice, use encrypted
/// swap partitions.
///
/// For similar reasons, on Unix systems, one should also disable core dumps
/// when running crypto code outside a development environment. This can be
/// achieved using a shell built-in such as ulimit or programatically using
/// ```setrlimit(RLIMIT_CORE, &(struct rlimit) {0, 0})```. On operating systems
/// where this feature is implemented, kernel crash dumps should also be
/// disabled.
///
/// *mlock()* safely wraps *sodium_mlock()* which wraps *mlock()* and
/// *VirtualLock()*. Note: Many systems place limits on the amount of memory
/// that may be locked by a process. Care should be taken to raise those limits
/// (e.g. Unix ulimits) where neccessary. *mlock()* will return -1 when any
/// limit is reached.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils::mlock;
///
/// let v = [0, 1, 2, 3, 4, 5, 6, 7];
/// assert!(mlock(&v) == 0);
/// ```
pub fn mlock(mem: &[u8]) -> i32 {
    unsafe {
        sodium_mlock(mem.as_ptr() as *mut ::libc::c_void,
                     mem.len() as ::libc::size_t)
    }
}

/// The *munlock()* function should be called after locked memory is not being
/// used any more. It will zero the bytes in the array before actually flagging
/// the pages as swappable again. Calling *memzero()* prior to *munlock()* is
/// thus not required.
///
/// On systems where it is supported, *sodium_mlock()* also wraps *madvise()*
/// and advises the kernel not to include the locked memory in coredumps.
/// *ss_unlock()* also undoes this additional protection.
///
/// *munlock* safely wraps *sodium_munlock*.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils::{mlock, munlock};
///
/// let v = [0, 1, 2, 3, 4, 5, 6, 7];
/// assert!(mlock(&v) == 0);
/// assert!(munlock(&v) == 0);
/// assert!(v == [0; 8]);
/// ```
pub fn munlock(mem: &[u8]) -> i32 {
    unsafe {
        sodium_munlock(mem.as_ptr() as *mut ::libc::c_void,
                       mem.len() as ::libc::size_t)
    }
}

/// The *malloc()* function returns a mutable array of bytes.
///
/// The allocated region is placed at the end of a page boundary, immediately
/// followed by a guard page. As a result, accessing memory past the end of the
/// region will immediately terminate the application.
///
/// A canary is also placed right before the returned pointer. Modification of
/// this canary are detected when trying to free the allocated region with
/// *free()*, and also cause the application to immediately terminate.
///
/// An additional guard page is placed before this canary to make it less
/// likely for sensitive data to be accessible when reading past the end of an
/// unrelated region.
///
/// The allocated region is filled with 0xd0 bytes in order to help catch bugs
/// due to initialized data.
///
/// In addition, *sodium_mlock()* is called on the region to help avoid it being
/// swapped to disk. On operating systems supporting MAP_NOCORE or
/// MADV_DONTDUMP, memory allocated this way will also not be part of core
/// dumps.
///
/// The returned address will not be aligned if the allocation size is not a
/// multiple of the
/// required alignment.
///
/// For this reason, *malloc()* should not be used with packed or
/// variable-length structures, unless the size given to *malloc()* is rounded
/// up in order to ensure proper alignment.
///
/// All the structures used by libsodium can safely be allocated using
/// *sodium_malloc()*, the only one requiring extra care being
/// crypto_generichash_state, whose size needs to be rounded up to a multiple
/// of 64 bytes.
///
/// # Examples
///
/// ```
/// use sodium_sys::core::init;
/// use sodium_sys::utils::{malloc,free};
///
/// let _ = init();
/// let mut v = malloc(64);
/// v[0] = 1;
/// assert!(v.len() == 64);
/// assert!(v[0] == 1);
/// free(v);
/// ```
pub fn malloc<'a>(size: usize) -> &'a mut [u8] {
    unsafe {
        let ptr = sodium_malloc(size as ::libc::size_t) as *mut u8;
        assert!(!ptr.is_null());
        slice::from_raw_parts_mut(ptr, size)
    }
}

/// The *allocarray()* function returns a mutable byte array.
///
/// It provides the same guarantees as *malloc()* but also protects against
/// arithmetic overflows when count * size exceeds SIZE_MAX.
///
/// *allocarray()* safely wraps *sodium_allocarray()*.
///
/// # Examples
///
/// ```
/// use sodium_sys::core::init;
/// use sodium_sys::utils::{allocarray,free};
///
/// let _ = init();
/// let mut v = allocarray(2, 16);
/// v[0] = 1;
/// assert!(v.len() == 32);
/// assert!(v[0] == 1);
/// free(v);
/// ```
pub fn allocarray<'a>(count: ::libc::size_t,
                      size: ::libc::size_t) -> &'a mut [u8] {
    unsafe {
        let ptr = sodium_allocarray(count, size) as *mut u8;
        assert!(!ptr.is_null());
        slice::from_raw_parts_mut(ptr, (count * size) as usize)
    }
}

/// The *free()* function unlocks and deallocates memory allocated using
/// *malloc()* or *allocarray()*.
///
/// Prior to this, the canary is checked in order to detect possible buffer
/// underflows and terminate the process if required.
///
/// *free()* also fills the memory region with zeros before the deallocation.
///
/// This function can be called even if the region was previously protected
/// using *mprotect_readonly()*; the protection will automatically be changed
/// as needed.
///
/// The *free()* function safely wraps the *sodium_free* function.
///
/// # Examples
///
/// ```
/// use sodium_sys::core::init;
/// use sodium_sys::utils::{malloc,free};
///
/// let _ = init();
/// let mut v = malloc(128);
/// v[0] = 1;
/// v[127] = 255;
/// assert!(v.len() == 128);
/// assert!(v[0] == 1);
/// assert!(v[127] == 255);
/// free(v);
/// ```
pub fn free(mem: &[u8]) {
    unsafe {
        sodium_free(mem.as_ptr() as *mut ::libc::c_void);
    }
}

/// The *mprotect_noaccess()* function makes a region allocated using *malloc()*
///  or *allocarray()* inaccessible. It cannot be read or written, but the data
/// are preserved.
///
/// This function can be used to make confidential data inacessible except when
/// actually needed for a specific operation.
///
/// *mprotect_noaccess()* safely wraps the *sodium_mprotect_noaccess()*
/// function.
///
/// # Examples
///
/// ```
/// use sodium_sys::core::init;
/// use sodium_sys::utils::{free,malloc,mprotect_noaccess};
///
/// let _ = init();
/// let mut v = malloc(64);
/// v[0] = 1;
/// assert!(v.len() == 64);
/// assert!(v[0] == 1);
/// mprotect_noaccess(&mut v);
/// // If you uncomment the following line the program will fail (no read).
/// // assert!(v[0] == 1);
/// // If you uncomment the following line the program will fail (no write).
/// // v[1] = 1;
/// free(&mut v);
/// ```
pub fn mprotect_noaccess(mem: &[u8]) {
    unsafe {
        sodium_mprotect_noaccess(mem.as_ptr() as *mut ::libc::c_void);
    }
}

/// The *mprotect_readonly()* function marks a region allocated using *malloc()*
/// or *allocarray()* as read-only.
///
/// Attempting to modify the data will cause the process to terminate.
///
/// # Examples
///
/// ```
/// use sodium_sys::core::init;
/// use sodium_sys::utils::{free,malloc,mprotect_readonly};
///
/// let _ = init();
/// let mut v = malloc(64);
/// v[0] = 1;
/// assert!(v.len() == 64);
/// assert!(v[0] == 1);
/// mprotect_readonly(&mut v);
/// assert!(v[0] == 1);
/// // If you uncomment the following line the program will fail (no write).
/// // v[1] = 1;
/// free(&mut v);
/// ```
pub fn mprotect_readonly(mem: &[u8]) {
    unsafe {
        sodium_mprotect_readonly(mem.as_ptr() as *mut ::libc::c_void);
    }
}

/// The *mprotect_readwrite()* function marks a region allocated using
/// *malloc()* or *allocarray()* as readable and writable, after having been
/// protected using *mprotect_readonly()* or *mprotect_noaccess()*.
///
/// # Examples
///
/// ```
/// use sodium_sys::core::init;
/// use sodium_sys::utils::{free,malloc,mprotect_noaccess,mprotect_readwrite};
///
/// let _ = init();
/// let mut v = malloc(64);
/// v[0] = 1;
/// assert!(v.len() == 64);
/// assert!(v[0] == 1);
/// mprotect_noaccess(&mut v);
/// // If you uncomment the following line the program will fail (no read).
/// // assert!(v[0] == 1);
/// // If you uncomment the following line the program will fail (no write).
/// // v[1] = 1;
/// mprotect_readwrite(&mut v);
/// assert!(v[0] == 1);
/// v[1] = 1;
/// assert!(v[1] == 1);
/// free(&mut v);
/// ```
pub fn mprotect_readwrite(mem: &[u8]) {
    unsafe {
        sodium_mprotect_readwrite(mem.as_ptr() as *mut ::libc::c_void);
    }
}

#[cfg(feature = "latest")]
/// The *increment()* function takes a pointer to an arbitrary length unsigned
/// number, and increments it.
///
/// It runs in constant-time for a given length, and considers the number to be
/// encoded in little-endian format.
///
/// *increment()* can be used to increment nonces.
///
/// # Examples
///
/// ```
/// use sodium_sys::utils;
///
/// let mut nonce = [0];
/// utils::increment(&mut nonce);
/// assert!(nonce == [1]);
/// utils::increment(&mut nonce);
/// assert!(nonce == [2]);
/// ```
pub fn increment(n: &mut [u8]) {
    unsafe {
        sodium_increment(n.as_mut_ptr(), n.len() as ::libc::size_t);
    }
}
