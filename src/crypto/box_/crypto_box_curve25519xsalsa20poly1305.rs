//! crypto_box_curve25519xsalsa20poly1305 constants.

// 32 bytes.
pub const SEEDBYTES: usize = 32;
// 32 bytes.
pub const PUBLICKEYBYTES: usize = 32;
// 32 bytes.
pub const SECRETKEYBYTES: usize = 32;
// 32 bytes.
pub const BEFORENMBYTES: usize = 32;
// 24 bytes.
pub const NONCEBYTES: usize = 24;
// 32 bytes.
pub const ZEROBYTES: usize = 32;
// 16 bytes.
pub const BOXZEROBYTES: usize = 16;
// 16 bytes.
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES;
