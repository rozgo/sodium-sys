//! Secret Key Message Authentication
//!
//! This operation computes an authentication tag for a message and a secret
//! key, and provides a way to verify that a given tag is valid for a given
//! message and a key.
//!
//! The function computing the tag deterministic: the same (message, key) tuple
//! will always produce the same output.
//!
//! However, even if the message is public, knowing the key is required in order
//! to be able to compute a valid tag. Therefore, the key should remain
//! confidential. The tag, however, can be public.
//!
//! A typical use case is:
//!
//! - A prepares a message, add an authentication tag, sends it to B
//! - A doesn't store the message
//! - Later on, B sends the message and the authentication tag to A
//! - A uses the authentication tag to verify that it created this message.
//! This operation does not encrypt the message. It only computes and verifies
//! an authentication tag.
use libc::{c_int,c_uchar,c_ulonglong};
use SSError::{self,MAC};
use utils;

/// 32 bytes.
pub const BYTES: usize = 32;
/// 32 bytes.
pub const KEYBYTES: usize = 32;

extern "C" {
    fn crypto_auth(out: *mut c_uchar, in_: *const c_uchar,
                   inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    fn crypto_auth_verify(h: *const c_uchar, in_: *const c_uchar,
                          inlen: c_ulonglong, k: *const c_uchar) -> c_int;
}

/// The *auth()* function computes a tag for the message and a key. The key
/// should be KEYBYTES bytes. The function return the tag byte sequence.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,utils};
/// use sodium_sys::crypto::{auth,key};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(auth::KEYBYTES);
/// key.activate();
///
/// // Generate the MAC and protect it as readonly.
/// let mac = auth::auth(b"test", key.bytes()).unwrap();
///
/// utils::mprotect_readonly(mac);
/// println!("{:?}", mac);
/// ```
pub fn auth<'a>(message: &[u8], key: &[u8]) -> Result<&'a mut[u8], SSError> {
    assert!(key.len() == KEYBYTES);

    let mut output = utils::malloc(BYTES);

    let res: i32;

    unsafe {
        res = crypto_auth(output.as_mut_ptr(),
                          message.as_ptr(),
                          message.len() as c_ulonglong,
                          key.as_ptr());
    }

    if res == 0 {
        utils::mprotect_readonly(output);
        Ok(output)
    } else {
        Err(MAC("Unable to generate MAC"))
    }
}

/// The *auth_verify()* function verifies that the mac is a valid mac for the
/// given message and the key k.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,utils};
/// use sodium_sys::crypto::{auth,key};
///
/// // Initialize sodium_sys
/// core::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(auth::KEYBYTES);
/// key.activate();
///
/// // Generate the MAC and protect it as readonly.
/// let mac = auth::auth(b"test", key.bytes()).unwrap();
/// utils::mprotect_readonly(mac);

/// // Verify the MAC and message.
/// let res = auth::auth_verify(b"test", mac, key.bytes()).unwrap();
/// assert!(res == 0);
/// ```
pub fn auth_verify<'a>(message: &[u8],
                       mac: &[u8],
                       key: &[u8]) -> Result<i32, SSError> {
    assert!(key.len() == KEYBYTES);
    assert!(mac.len() == BYTES);

    let res: i32;

    unsafe {
        res = crypto_auth_verify(mac.as_ptr(),
                                 message.as_ptr(),
                                 message.len() as c_ulonglong,
                                 key.as_ptr());
    }

    if res == 0 {
        Ok(res)
    } else {
        Err(MAC("Unable to generate MAC"))
    }
}
