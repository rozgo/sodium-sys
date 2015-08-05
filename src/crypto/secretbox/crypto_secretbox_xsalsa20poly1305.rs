// sodium/crypto_secretbox_xsalsa20poly1305.h
pub const KEYBYTES: usize = 32;
pub const NONCEBYTES: usize = 24;
pub const ZEROBYTES: usize = 32;
pub const BOXZEROBYTES: usize = 16;
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES;
