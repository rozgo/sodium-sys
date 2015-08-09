//! Memory safe secret key implementation.
use randombytes;
use utils;

/// The key structure contains information necessary to create slices from raw
/// parts.
pub struct Key {
    key_ptr: *mut u8,
    size: usize,
}

impl Key {
    /// Create a new key of the given size.  The key is malloc'd with the
    /// libsodium malloc function to ensure safety, filled with random bytes via
    /// *random_byte_array()*, and then set to no access via
    /// *mprotect_noaccess()* to ensure the data is not inadvertently (or
    /// maliciously) altered.  Note in order to use the key, the caller must
    /// use *activate()*.
    pub fn new(size: usize) -> Key {
        let mut key = utils::malloc(size);
        randombytes::random_byte_array(&mut key);
        utils::mprotect_noaccess(key);

        Key {
            key_ptr: key.as_mut_ptr(),
            size: size,
        }
    }

    /// Convert the key to a byte sequence.
    pub fn bytes(&self) -> &[u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts(self.key_ptr, self.size)
        }
    }

    /// Convert the key to a mutable byte sequence.
    pub fn bytes_mut(&self) -> &mut [u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts_mut(self.key_ptr, self.size)
        }
    }

    /// Activate the key for use via *mprotect_readonly()*.  Note that once a
    /// key is created it cannot be modified in memory, only read.
    pub fn activate(&self) {
        utils::mprotect_readonly(self.bytes());
    }

    /// De-activate the key via *mprotect_noaccess()*.  Use this when the key
    /// isn't currently being used, but may be at a later time.
    pub fn deactivate(&self) {
        utils::mprotect_noaccess(self.bytes());
    }
}

impl Drop for Key {
    /// Free the key memory if the pointer is not null.  libsodium *free()* is
    /// used here.
    fn drop(&mut self) {
        // Guard against the ref having already been dropped
        if self.key_ptr.is_null() { return; }
        utils::free(self.bytes());
    }
}
