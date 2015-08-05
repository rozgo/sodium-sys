
use randombytes;
use utils;

pub mod crypto_secretbox_xsalsa20poly1305;

pub const KEYBYTES: usize = crypto_secretbox_xsalsa20poly1305::KEYBYTES;
pub const NONCEBYTES: usize = crypto_secretbox_xsalsa20poly1305::NONCEBYTES;
pub const MACBYTES: usize = crypto_secretbox_xsalsa20poly1305::MACBYTES;
pub const PRIMITIVE: &'static str = "xsalsa20poly1305";
pub const ZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::ZEROBYTES;
pub const BOXZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::BOXZEROBYTES;

extern "C" {
    fn crypto_secretbox_easy(c: *mut ::libc::c_uchar, m: *const ::libc::c_uchar,
                             mlen: ::libc::size_t, n: *const ::libc::c_uchar,
                             k: *const ::libc::c_uchar) -> ::libc::c_int;
    fn crypto_secretbox_open_easy(m: *mut ::libc::c_uchar, c: *const ::libc::c_uchar,
                                  clen: ::libc::size_t, n: *const ::libc::c_uchar,
                                  k: *const ::libc::c_uchar) -> ::libc::c_int;
}

pub fn gen_key<'a>() -> &'a mut [u8] {
    let mut key = utils::malloc(KEYBYTES);
    randombytes::random_byte_array(&mut key);
    utils::mprotect_readonly(key);
    key
}

pub fn gen_nonce<'a>() -> &'a [u8] {
    let nonce = utils::malloc(NONCEBYTES);
    randombytes::random_byte_array(&mut nonce);
    utils::mprotect_readonly(nonce);
    nonce
}

/// The *seal()* function encrypts a message with a key and a nonce.
///
/// The key should be KEYBYTES bytes and the nonce should be NONCEBYTES bytes.
///
/// This function writes the authentication tag, whose length is MACBYTES bytes, immediately
/// followed by the encrypted message, whose length is the same as the plaintext.
///
/// # Examples
///
/// ```
/// use sodium_sys::{core,randombytes,utils};
/// use sodium_sys::crypto::secretbox;
///
/// core::init();
/// let mut key = utils::malloc(secretbox::KEYBYTES);
/// let mut nonce = utils::malloc(secretbox::NONCEBYTES);
/// randombytes::random_byte_array(&mut key);
/// randombytes::random_byte_array(&mut nonce);
/// utils::mprotect_readonly(&mut key);
/// utils::mprotect_readonly(&mut nonce);
/// let ciphertext = secretbox::seal(b"test", key, nonce);
/// utils::mprotect_readonly(ciphertext);
/// println!("{:?}", ciphertext);
/// utils::free(&key);
/// utils::free(&nonce);
/// ```
pub fn seal<'a>(message: &[u8], key: &[u8], nonce: &[u8]) -> &'a mut [u8] {
    assert!(key.len() == KEYBYTES);
    assert!(nonce.len() == NONCEBYTES);
    let mut ciphertext = utils::malloc(MACBYTES + message.len());

    unsafe {
        crypto_secretbox_easy(ciphertext.as_mut_ptr(),
                              message.as_ptr(),
                              message.len() as ::libc::size_t,
                              nonce.as_ptr(),
                              key.as_ptr());

    }

    utils::mprotect_readonly(ciphertext);
    ciphertext
}

pub fn open<'a>(ciphertext: &[u8], key: [u8; KEYBYTES], nonce: [u8; NONCEBYTES]) -> &'a mut [u8] {
    let mut message = utils::malloc(ciphertext.len() - MACBYTES);

    unsafe {
        crypto_secretbox_open_easy(message.as_mut_ptr(),
                                   ciphertext.as_ptr(),
                                   ciphertext.len() as ::libc::size_t,
                                   nonce.as_ptr(),
                                   key.as_ptr());
    }

    utils::mprotect_readonly(message);
    message
}
