//! Memory safe nonce implementation.
use crypto::utils::{randombytes,secmem};

/// The nonce structure contains information necessary to create slices from raw
/// parts.
pub struct Nonce {
    nonce_ptr: *mut u8,
    size: usize,
}

impl Nonce {
    /// Create a new nonce of the given size.  The key is malloc'd with
    /// the libsodium malloc function to ensure safety, filled with random bytes
    /// via *random_byte_array()*, and then set to no access via
    /// *mprotect_noaccess()* to ensure the data is not inadvertently (or
    /// maliciously) altered.  Note in order to use the key, the caller must
    /// use *activate()*.
    pub fn new(size: usize) -> Nonce {
        let mut nonce = secmem::malloc(size);
        randombytes::random_byte_array(&mut nonce);
        secmem::mprotect_noaccess(nonce);

        Nonce {
            nonce_ptr: nonce.as_mut_ptr(),
            size: size,
        }
    }

    /// Convert the nonce to a byte sequence.
    pub fn bytes(&self) -> &[u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts(self.nonce_ptr, self.size)
        }
    }

    /// Convert the nonce to a mutable byte sequence.
    pub fn bytes_mut(&self) -> &mut [u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts_mut(self.nonce_ptr, self.size)
        }
    }

    /// Activate the nonce for use via *mprotect_readwrite()*.
    pub fn activate(&self) {
        secmem::mprotect_readwrite(self.bytes());
    }

    /// De-activate the nonce via *mprotect_noaccess()*.  Use this when the
    /// nonce isn't currently being used, but may be at a later time.
    pub fn deactivate(&self) {
        secmem::mprotect_noaccess(self.bytes());
    }

    #[cfg(feature = "latest")]
    /// Increment the nonce via libsodium *increment()*.  Note the nonce must be
    /// writable (by calling *activate()* for this to succeed.
    pub fn increment(&self) {
        secmem::increment(self.bytes_mut());
    }
}

impl Drop for Nonce {
    /// Free the nonce memory if the pointer is not null.  libsodium *free()* is
    /// used here.
    fn drop(&mut self) {
        // Guard against the ref having already been dropped
        if self.nonce_ptr.is_null() { return; }
        secmem::free(self.bytes());
    }
}
