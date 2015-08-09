//! xsalsa20poly1305 constants
/// 32 bytes.
pub const KEYBYTES: usize = 32;
/// 24 bytes.
pub const NONCEBYTES: usize = 24;
/// 32 bytes.
pub const ZEROBYTES: usize = 32;
/// 16 bytes.
pub const BOXZEROBYTES: usize = 16;
/// ZEROBYTES - BOXZEROBYTES (16 bytes).
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES;
