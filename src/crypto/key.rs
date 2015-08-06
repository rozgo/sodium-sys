use randombytes;
use utils;

pub struct Key {
    key_ptr: *mut u8,
    size: usize,
}

impl Key {
    pub fn new(size: usize) -> Key {
        let mut key = utils::malloc(size);
        randombytes::random_byte_array(&mut key);
        utils::mprotect_noaccess(key);

        Key {
            key_ptr: key.as_mut_ptr(),
            size: size,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts(self.key_ptr, self.size)
        }
    }

    pub fn bytes_mut(&self) -> &mut [u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts_mut(self.key_ptr, self.size)
        }
    }

    pub fn activate(&self) {
        utils::mprotect_readonly(self.bytes());
    }

    pub fn deactivate(&self) {
        utils::mprotect_noaccess(self.bytes());
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Guard against the ref having already been dropped
        if self.key_ptr.is_null() { return; }
        utils::free(self.bytes());
    }
}
