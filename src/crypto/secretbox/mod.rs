use ::utils;

pub mod crypto_secretbox_xsalsa20poly1305;

// sodium/crypto_secretbox.h
pub const KEYBYTES: usize = crypto_secretbox_xsalsa20poly1305::KEYBYTES;
pub const NONCEBYTES: usize = crypto_secretbox_xsalsa20poly1305::NONCEBYTES;
pub const MACBYTES: usize = crypto_secretbox_xsalsa20poly1305::MACBYTES;
pub const PRIMITIVE: &'static str = "xsalsa20poly1305";
pub const ZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::ZEROBYTES;
pub const BOXZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305::BOXZEROBYTES;

#[allow(dead_code)]
extern "C" {
    fn crypto_secretbox_easy(c: *mut ::libc::c_uchar, m: *const ::libc::c_uchar,
                             mlen: ::libc::size_t, n: *const ::libc::c_uchar,
                             k: *const ::libc::c_uchar) -> ::libc::c_int;
    fn crypto_secretbox_open_easy(m: *mut ::libc::c_uchar, c: *const ::libc::c_uchar,
                                  clen: ::libc::size_t, n: *const ::libc::c_uchar,
                                  k: *const ::libc::c_uchar) -> ::libc::c_int;
}

pub fn seal<'a>(message: &[u8], key: [u8; KEYBYTES], nonce: [u8; NONCEBYTES]) -> &'a [u8] {
    let mut ciphertext = utils::malloc((MACBYTES + message.len()) as ::libc::size_t);

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

pub fn open<'a>(ciphertext: &[u8], key: [u8; KEYBYTES], nonce: [u8; NONCEBYTES]) -> &'a [u8] {
    let mut message = utils::malloc((ciphertext.len() - MACBYTES) as ::libc::size_t);

    unsafe {
        crypto_secretbox_open_easy(message.as_mut_ptr(),
                                   ciphertext.as_ptr(),
                                   ciphertext.len() as ::libc::size_t,
                                   nonce.as_ptr(),
                                   key.as_ptr());
    }

    message
}
