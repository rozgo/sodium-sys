//! Keyed message authentication using HMAC-SHA-256, HMAC-SHA-512 and
//! HMAC-SHA512/256 (truncated HMAC-SHA-512) are provided.
//!
//! If required, a streaming API is available to process a message as a sequence
//! of multiple chunks.
use crypto::utils::secmem;
use libc::{
    c_int,
    c_uchar,
    c_ulonglong,
    size_t
};
use self::Family::*;
use SSError::{
    self,
    MAC
};

pub enum Family {
    SHA256,
    SHA512,
    SHA512256,
}

pub const HMACSHA256_BYTES: usize = 32;
pub const HMACSHA256_KEYBYTES: usize = 32;
pub const HMACSHA512_BYTES: usize = 64;
pub const HMACSHA512_KEYBYTES: usize = 32;
pub const HMACSHA512256_BYTES: usize = 32;
pub const HMACSHA512256_KEYBYTES: usize = 32;

extern "C" {
    fn crypto_auth_hmacsha256_statebytes() -> size_t;
    fn crypto_auth_hmacsha512_statebytes() -> size_t;
    fn crypto_auth_hmacsha512256_statebytes() -> size_t;
    fn crypto_auth_hmacsha256_bytes() -> size_t;
    fn crypto_auth_hmacsha512_bytes() -> size_t;
    fn crypto_auth_hmacsha512256_bytes() -> size_t;
    fn crypto_auth_hmacsha256_keybytes() -> size_t;
    fn crypto_auth_hmacsha512_keybytes() -> size_t;
    fn crypto_auth_hmacsha512256_keybytes() -> size_t;
    fn crypto_auth_hmacsha256(
        out: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong,
        k: *const c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha512(
        out: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong,
        k: *const c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha512256(
        out: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong,
        k: *const c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha256_verify(
        h: *const c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong,
        k: *const c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha512_verify(
        h: *const c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong,
        k: *const c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha512256_verify(
        h: *const c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong,
        k: *const c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha256_init(
        state: *mut c_uchar,
        key: *const c_uchar,
        keylen: size_t
    )
    -> c_int;
    fn crypto_auth_hmacsha512_init(
        state: *mut c_uchar,
        key: *const c_uchar,
        keylen: size_t
    )
    -> c_int;
    fn crypto_auth_hmacsha512256_init(
        state: *mut c_uchar,
        key: *const c_uchar,
        keylen: size_t
    )
    -> c_int;
    fn crypto_auth_hmacsha256_update(
        state: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong
    )
    -> c_int;
    fn crypto_auth_hmacsha512_update(
        state: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong
    )
    -> c_int;
    fn crypto_auth_hmacsha512256_update(
        state: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_ulonglong
    )
    -> c_int;
    fn crypto_auth_hmacsha256_final(
        state: *mut c_uchar,
        out: *mut c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha512_final(
        state: *mut c_uchar,
        out: *mut c_uchar
    )
    -> c_int;
    fn crypto_auth_hmacsha512256_final(
        state: *mut c_uchar,
        out: *mut c_uchar
    )
    -> c_int;
}

/// The *bytes()* function returns the currently configured hash length in bytes
/// for the HMAC-SHA2 family of operations.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::symmetrickey::hmacsha2;
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Get the hash length in bytes for HMAC-SHA256
/// let hlen = hmacsha2::bytes(SHA256);
/// assert!(hlen == hmacsha2::HMACSHA256_BYTES);
///
/// // Get the hash length in bytes for HMAC-SHA512
/// let hlen = hmacsha2::bytes(SHA512);
/// assert!(hlen == hmacsha2::HMACSHA512_BYTES);
///
/// // Get the hash length in bytes for HMAC-SHA512256
/// let hlen = hmacsha2::bytes(SHA512256);
/// assert!(hlen == hmacsha2::HMACSHA512256_BYTES);
/// ```
pub fn bytes(family: Family) -> usize {
    unsafe {
        match family {
            SHA256 => crypto_auth_hmacsha256_bytes() as usize,
            SHA512 => crypto_auth_hmacsha512_bytes() as usize,
            SHA512256 => crypto_auth_hmacsha512256_bytes() as usize,
        }
    }
}

/// The *keybytes()* function returns the currently configured key length in
/// bytes for the HMAC-SHA2 family of operations.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::symmetrickey::hmacsha2;
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Get the key length in bytes for HMAC-SHA256
/// let klen = hmacsha2::keybytes(SHA256);
/// assert!(klen == hmacsha2::HMACSHA256_KEYBYTES);
///
/// // Get the hash length in bytes for HMAC-SHA512
/// let klen = hmacsha2::keybytes(SHA512);
/// assert!(klen == hmacsha2::HMACSHA512_KEYBYTES);
///
/// // Get the hash length in bytes for HMAC-SHA512256
/// let klen = hmacsha2::keybytes(SHA512256);
/// assert!(klen == hmacsha2::HMACSHA512256_KEYBYTES);
/// ```
pub fn keybytes(family: Family) -> usize {
    unsafe {
        match family {
            SHA256 => crypto_auth_hmacsha256_keybytes() as usize,
            SHA512 => crypto_auth_hmacsha512_keybytes() as usize,
            SHA512256 => crypto_auth_hmacsha512256_keybytes() as usize,
        }
    }
}

/// The *statebytes()* function returns the length in bytes for the state
/// structure for the HMAC-SHA2 family of operations.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::symmetrickey::hmacsha2;
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Get the state length in bytes for HMAC-SHA256
/// let _ = hmacsha2::statebytes(SHA256);
///
/// // Get the state length in bytes for HMAC-SHA512
/// let _ = hmacsha2::statebytes(SHA512);
///
/// // Get the state length in bytes for HMAC-SHA512256
/// let _ = hmacsha2::statebytes(SHA512256);
/// ```
pub fn statebytes(family: Family) -> usize {
    unsafe {
        match family {
            SHA256 => crypto_auth_hmacsha256_statebytes() as usize,
            SHA512 => crypto_auth_hmacsha512_statebytes() as usize,
            SHA512256 => crypto_auth_hmacsha512256_statebytes() as usize,
        }
    }
}

/// The *auth()* function computes a tag for the message and a key. The key
/// should be KEYBYTES bytes. The function returns the tag byte sequence.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::symmetrickey::{hmacsha2,key};
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA256_KEYBYTES);
/// key.activate();
///
/// // Generate the MAC.
/// let mac = hmacsha2::auth(b"test", key.bytes(), SHA256).unwrap();
/// assert!(mac.len() == hmacsha2::HMACSHA256_BYTES);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512_KEYBYTES);
/// key.activate();
///
/// // Generate the MAC.
/// let mac = hmacsha2::auth(b"test", key.bytes(), SHA512).unwrap();
/// assert!(mac.len() == hmacsha2::HMACSHA512_BYTES);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512256_KEYBYTES);
/// key.activate();
///
/// // Generate the MAC.
/// let mac = hmacsha2::auth(b"test", key.bytes(), SHA512256).unwrap();
/// assert!(mac.len() == hmacsha2::HMACSHA512256_BYTES);
/// ```
pub fn auth<'a>(
    message: &[u8],
    key: &[u8],
    family: Family
)
-> Result<&'a mut[u8], SSError>
{
    let (res, output) = match family {
        SHA256 => {
            assert!(key.len() == HMACSHA256_KEYBYTES);
            let mut output = secmem::malloc(HMACSHA256_BYTES);
            let res: i32;

            unsafe {
                res = crypto_auth_hmacsha256(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr()
                );
            }
            (res, output)
        },
        SHA512 => {
            assert!(key.len() == HMACSHA512_KEYBYTES);
            let mut output = secmem::malloc(HMACSHA512_BYTES);
            let res: i32;

            unsafe {
                res = crypto_auth_hmacsha512(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr()
                );
            }
            (res, output)
        },
        SHA512256 => {
            assert!(key.len() == HMACSHA512256_KEYBYTES);
            let mut output = secmem::malloc(HMACSHA512256_BYTES);
            let res: i32;

            unsafe {
                res = crypto_auth_hmacsha512256(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr()
                );
            }
            (res, output)
        },
    };

    if res == 0 {
        secmem::mprotect_readonly(output);
        Ok(output)
    } else {
        Err(MAC("Unable to generate MAC"))
    }
}

/// The *verify()* function verifies that the mac is a valid mac for the given
/// message and key.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::symmetrickey::{hmacsha2,key};
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA256_KEYBYTES);
/// key.activate();
///
/// // Generate the MAC.
/// let mac = hmacsha2::auth(b"test", key.bytes(), SHA256).unwrap();
/// assert!(mac.len() == hmacsha2::HMACSHA256_BYTES);
///
/// // Verify the MAC and message.
/// let res = hmacsha2::verify(b"test", mac, key.bytes(), SHA256).unwrap();
/// assert!(res == 0);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512_KEYBYTES);
/// key.activate();
///
/// // Generate the MAC.
/// let mac = hmacsha2::auth(b"test", key.bytes(), SHA512).unwrap();
/// assert!(mac.len() == hmacsha2::HMACSHA512_BYTES);
///
/// // Verify the MAC and message.
/// let res = hmacsha2::verify(b"test", mac, key.bytes(), SHA512).unwrap();
/// assert!(res == 0);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512256_KEYBYTES);
/// key.activate();
///
/// // Generate the MAC.
/// let mac = hmacsha2::auth(b"test", key.bytes(), SHA512256).unwrap();
/// assert!(mac.len() == hmacsha2::HMACSHA512256_BYTES);
///
/// // Verify the MAC and message.
/// let res = hmacsha2::verify(b"test", mac, key.bytes(), SHA512256).unwrap();
/// assert!(res == 0);
/// ```
pub fn verify<'a>(
    message: &[u8],
    mac: &[u8],
    key: &[u8],
    family: Family
)
-> Result<i32, SSError>
{
    let res = match family {
        SHA256    => {
            assert!(key.len() == HMACSHA256_KEYBYTES);
            assert!(mac.len() == HMACSHA256_BYTES);
            unsafe {
                crypto_auth_hmacsha256_verify(
                    mac.as_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr()
                ) as i32
            }
        },
        SHA512    => {
            assert!(key.len() == HMACSHA512_KEYBYTES);
            assert!(mac.len() == HMACSHA512_BYTES);
            unsafe {
                crypto_auth_hmacsha512_verify(
                    mac.as_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr()
                ) as i32
            }
        },
        SHA512256 => {
            assert!(key.len() == HMACSHA512256_KEYBYTES);
            assert!(mac.len() == HMACSHA512256_BYTES);
            unsafe {
                crypto_auth_hmacsha512256_verify(
                    mac.as_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr()
                ) as i32
            }
        },
    };

    if res == 0 {
        Ok(res)
    } else {
        Err(MAC("Unable to generate MAC"))
    }
}

///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::symmetrickey::{hmacsha2, key};
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA256);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA256_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA256).unwrap();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA512);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA512).unwrap();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA512256);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512256_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA512256).unwrap();
/// ```
pub fn init<'a>
(
    state: &'a mut [u8],
    key: &'a [u8],
    family: Family
)
-> Result<(), SSError>
{
    let res: i32;

    unsafe {
        res = match family {
            SHA256    => crypto_auth_hmacsha256_init(
                            state.as_mut_ptr(),
                            key.as_ptr(),
                            key.len() as c_ulonglong
                        ),
            SHA512    => crypto_auth_hmacsha512_init(
                            state.as_mut_ptr(),
                            key.as_ptr(),
                            key.len() as c_ulonglong
                        ),
            SHA512256 => crypto_auth_hmacsha512256_init(
                            state.as_mut_ptr(),
                            key.as_ptr(),
                            key.len() as c_ulonglong
                        ),
        };
    }

    if res == 0 {
        Ok(())
    } else {
        Err(MAC("Unable to initialize hash state"))
    }
}

///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::symmetrickey::{hmacsha2, key};
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA256);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA256_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA256).unwrap();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA512);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA512).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512).unwrap();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA512256);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512256_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA512256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512256).unwrap();
/// ```
pub fn update<'a>(
    state: &'a mut [u8],
    in_: &[u8],
    family: Family
)
-> Result<(), SSError>
{
    let res: i32;

    unsafe {
        res = match family {
            SHA256    => crypto_auth_hmacsha256_update(
                            state.as_mut_ptr(),
                            in_.as_ptr(),
                            in_.len() as c_ulonglong
                        ),
            SHA512    => crypto_auth_hmacsha512_update(
                            state.as_mut_ptr(),
                            in_.as_ptr(),
                            in_.len() as c_ulonglong
                        ),
            SHA512256 => crypto_auth_hmacsha512256_update(
                            state.as_mut_ptr(),
                            in_.as_ptr(),
                            in_.len() as c_ulonglong
                        ),
        };
    }

    if res == 0 {
        Ok(())
    } else {
        Err(MAC("Unable to update hash state"))
    }
}

///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::{init, secmem};
/// use sodium_sys::crypto::symmetrickey::{hmacsha2, key};
/// use sodium_sys::crypto::symmetrickey::hmacsha2::Family::*;
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA256);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA256_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA256).unwrap();
/// let hash = hmacsha2::finalize(&mut state, SHA256).unwrap();
/// assert!(hash.len() == hmacsha2::HMACSHA256_BYTES);
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA512);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA512).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512).unwrap();
/// let hash = hmacsha2::finalize(&mut state, SHA512).unwrap();
/// assert!(hash.len() == hmacsha2::HMACSHA512_BYTES);
///
/// // Initialize the hash state.
/// let state_size = hmacsha2::statebytes(SHA512256);
/// let mut state = secmem::malloc(state_size);
///
/// // Create the key and activate for use.
/// let key = key::Key::new(hmacsha2::HMACSHA512256_KEYBYTES);
/// key.activate();
///
/// let _ = hmacsha2::init(&mut state, key.bytes(), SHA512256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512256).unwrap();
/// let _ = hmacsha2::update(&mut state, b"test", SHA512256).unwrap();
/// let hash = hmacsha2::finalize(&mut state, SHA512256).unwrap();
/// assert!(hash.len() == hmacsha2::HMACSHA512256_BYTES);
/// ```
pub fn finalize<'a>(
    state: &'a mut [u8],
    family: Family
)
-> Result<&'a [u8], SSError>
{
    let (res, out) = match family {
        SHA256    => {
            let out = secmem::malloc(HMACSHA256_BYTES);
            let res: i32;

            unsafe {
                res = crypto_auth_hmacsha256_final(
                    state.as_mut_ptr(),
                    out.as_mut_ptr()
                );
            }
            (res, out)
        },
        SHA512    => {
            let out = secmem::malloc(HMACSHA512_BYTES);
            let res: i32;

            unsafe {
                res = crypto_auth_hmacsha512_final(
                    state.as_mut_ptr(),
                    out.as_mut_ptr()
                );
            }
            (res, out)
        },
        SHA512256 => {
            let out = secmem::malloc(HMACSHA512256_BYTES);
            let res: i32;

            unsafe {
                res = crypto_auth_hmacsha512256_final(
                    state.as_mut_ptr(),
                    out.as_mut_ptr()
                );
            }
            (res, out)
        },
    };

    if res == 0 {
        secmem::mprotect_readonly(out);
        Ok(out)
    } else {
        Err(MAC("Unable to update hash state"))
    }
}
