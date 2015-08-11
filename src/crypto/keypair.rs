//! Memory safe keypair implementation.
use libc::{c_int, c_uchar};
use SSError::{self, KEYGEN};
use utils;

/// The key structure contains information necessary to create slices from raw
/// parts.
pub struct KeyPair {
    s_key_ptr: *mut u8,
    s_size: usize,
    p_key_ptr: *mut u8,
    p_size: usize,
}

extern "C" {
    fn crypto_box_seed_keypair(pk: *mut c_uchar,
                               sk: *mut c_uchar,
                               seed: *const c_uchar) -> c_int;
    fn crypto_box_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
}

impl KeyPair {
    /// Create a new keypair with the given sizes.  The keys are generated with
    /// the *crypto_box_keypair()* function to ensure safety and then set to no
    /// access via *mprotect_noaccess()* to ensure the data is not inadvertently
    /// (or maliciously) altered.  Note in order to use the keypair, the caller
    /// must use *activate_sk()* and *activate_pk()*.
    pub fn new(sk_size: usize, pk_size: usize) -> Result<KeyPair, SSError> {
        let mut sk = utils::malloc(sk_size);
        let mut pk = utils::malloc(pk_size);

        let res: i32;

        unsafe {
            res = crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }

        if res == 0 {
            utils::mprotect_noaccess(sk);
            utils::mprotect_noaccess(pk);

            Ok(KeyPair {
                s_key_ptr: sk.as_mut_ptr(),
                s_size: sk_size,
                p_key_ptr: pk.as_mut_ptr(),
                p_size: pk_size,
            })
        } else {
            Err(KEYGEN("Unable to generate keypair"))
        }
    }

    /// Create a new keypair with the given sizes and the given seed key.  The
    /// keys are generated with the *crypto_box_seed_keypair()* function to
    /// ensure safety and then set to no access via *mprotect_noaccess()* to
    /// ensure the data is not inadvertently (or maliciously) altered.  Note in
    /// order to use the keypair, the caller must use *activate_sk()* and
    /// *activate_pk()*.
    pub fn seed(seed: &[u8],
                sk_size: usize,
                pk_size: usize) -> Result<KeyPair, SSError> {
        let mut sk = utils::malloc(sk_size);
        let mut pk = utils::malloc(pk_size);

        let res: i32;

        unsafe {
            res = crypto_box_seed_keypair(pk.as_mut_ptr(),
                                          sk.as_mut_ptr(),
                                          seed.as_ptr());
        }

        if res == 0 {
            utils::mprotect_noaccess(sk);
            utils::mprotect_noaccess(pk);

            Ok(KeyPair {
                s_key_ptr: sk.as_mut_ptr(),
                s_size: sk_size,
                p_key_ptr: pk.as_mut_ptr(),
                p_size: pk_size,
            })
        } else {
            Err(KEYGEN("Unable to generate keypair"))
        }
    }

    /// Convert the secret key to a byte sequence.
    pub fn sk_bytes(&self) -> &[u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts(self.s_key_ptr, self.s_size)
        }
    }

    /// Convert the secret key to a mutable byte sequence.
    pub fn sk_bytes_mut(&self) -> &mut [u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts_mut(self.s_key_ptr, self.s_size)
        }
    }

    /// Activate the secret key for use via *mprotect_readonly()*.  Note that
    /// once a secret key is created it cannot be modified in memory, only read.
    pub fn activate_sk(&self) {
        utils::mprotect_readonly(self.sk_bytes());
    }

    /// De-activate the secret key via *mprotect_noaccess()*.  Use this when the
    /// key isn't currently being used, but may be at a later time.
    pub fn deactivate_sk(&self) {
        utils::mprotect_noaccess(self.sk_bytes());
    }

    /// Convert the public key to a byte sequence.
    pub fn pk_bytes(&self) -> &[u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts(self.p_key_ptr, self.p_size)
        }
    }

    /// Convert the public key to a mutable byte sequence.
    pub fn pk_bytes_mut(&self) -> &mut [u8] {
        use std::slice;
        unsafe {
            slice::from_raw_parts_mut(self.p_key_ptr, self.p_size)
        }
    }

    /// Activate the public key for use via *mprotect_readonly()*.  Note that
    /// once a public key is created it cannot be modified in memory, only read.
    pub fn activate_pk(&self) {
        utils::mprotect_readonly(self.pk_bytes());
    }

    /// De-activate the public key via *mprotect_noaccess()*.  Use this when the
    /// key isn't currently being used, but may be at a later time.
    pub fn deactivate_pk(&self) {
        utils::mprotect_noaccess(self.pk_bytes());
    }
}

impl Drop for KeyPair {
    /// Free the keypair memory if the pointer is not null.  libsodium *free()*
    /// is used here.
    fn drop(&mut self) {
        // Guard against the ref having already been dropped
        if !self.s_key_ptr.is_null() { utils::free(self.sk_bytes()); }
        if !self.p_key_ptr.is_null() { utils::free(self.pk_bytes()); }
    }
}