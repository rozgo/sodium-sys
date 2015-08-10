//! chacha120poly1305 constants

/// 32 bytes.
pub const KEYBYTES: usize = 32;
/// 0 bytes.
// pub const NSECBYTES: usize = 0;
/// 8 bytes.
pub const NPUBBYTES: usize = 8;
#[cfg(feature = "latest")]
/// 12 bytes.
pub const IETF_NPUBBYTES: usize = 12;
/// 16 bytes.
pub const ABYTES: usize = 16;
