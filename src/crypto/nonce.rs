use randombytes;
use utils;

pub struct Nonce {
    nonce_ptr: *mut u8,
    size: usize,
}

impl Nonce {
    pub fn new(size: usize) -> Nonce {
        let mut nonce = utils::malloc(size);
        randombytes::random_byte_array(&mut nonce);
        utils::mprotect_noaccess(nonce);

        Nonce {
            nonce_ptr: nonce.as_mut_ptr(),
            size: size,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts(self.nonce_ptr, self.size)
        }
    }

    pub fn bytes_mut(&self) -> &mut [u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts_mut(self.nonce_ptr, self.size)
        }
    }

    pub fn activate(&self) {
        utils::mprotect_readwrite(self.bytes());
    }

    pub fn deactivate(&self) {
        utils::mprotect_noaccess(self.bytes());
    }

    #[cfg(feature = "latest")]
    pub fn increment(&self) {
        utils::increment(self.bytes_mut());
    }
}

impl Drop for Nonce {
    fn drop(&mut self) {
        // Guard against the ref having already been dropped
        if self.nonce_ptr.is_null() { return; }
        utils::free(self.bytes());
    }
}
