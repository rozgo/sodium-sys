//! Memory safe keypair implementation.
use libc::{c_int, c_uchar};
use SSError::{self, KEYGEN};
use utils;

pub const BEFORENMBYTES: usize = 32;

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
    fn crypto_scalarmult_base(q: *mut c_uchar, n: *const c_uchar) -> c_int;
    fn crypto_box_beforenm(k: *mut c_uchar,
                           pk: *const c_uchar,
                           sk: *const c_uchar) -> c_int;
}

impl KeyPair {
    /// Create a new keypair with the given sizes.  The keys are generated with
    /// the *crypto_box_keypair()* function to ensure safety and then set to no
    /// access via *mprotect_noaccess()* to ensure the data is not inadvertently
    /// (or maliciously) altered.  Note in order to use the keypair, the caller
    /// must use *activate_sk()* and *activate_pk()*.
    ///
    /// # Examples
    ///
    /// ```
    /// use sodium_sys::core;
    /// use sodium_sys::crypto::{box_, keypair};
    ///
    /// // Initialize the sodium-sys library.
    /// core::init();
    ///
    /// // Create a keypair for the box_ module.
    /// let keypair = keypair::KeyPair::new(box_::SECRETKEYBYTES,
    ///                                     box_::PUBLICKEYBYTES).unwrap();
    ///
    /// // Activate the keys for use (they are created as no access).
    /// keypair.activate_sk();
    /// keypair.activate_pk();
    ///
    /// // Validate.
    /// assert!(keypair.sk_bytes().len() == box_::SECRETKEYBYTES);
    /// assert!(keypair.sk_bytes() != [0; box_::SECRETKEYBYTES]);
    /// assert!(keypair.pk_bytes().len() == box_::PUBLICKEYBYTES);
    /// assert!(keypair.pk_bytes() != [0; box_::PUBLICKEYBYTES]);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use sodium_sys::core;
    /// use sodium_sys::crypto::{box_, keypair};
    ///
    /// // Initialize the sodium-sys library.
    /// core::init();
    ///
    /// // Test seed key (don't use all zeros, it's a bad idea).
    /// const TEST_SEED_KEY: [u8; box_::SEEDBYTES] = [0; box_::SEEDBYTES];
    ///
    /// // Create a keypair for the box_ module.
    /// let keypair = keypair::KeyPair::seed(&TEST_SEED_KEY,
    ///                                      box_::SECRETKEYBYTES,
    ///                                      box_::PUBLICKEYBYTES).unwrap();
    ///
    /// // Activate the keys for use (they are created as no access).
    /// keypair.activate_sk();
    /// keypair.activate_pk();
    ///
    /// // Validate.
    /// assert!(keypair.sk_bytes().len() == box_::SECRETKEYBYTES);
    /// assert!(keypair.sk_bytes() != [0; box_::SECRETKEYBYTES]);
    /// assert!(keypair.pk_bytes().len() == box_::PUBLICKEYBYTES);
    /// assert!(keypair.pk_bytes() != [0; box_::PUBLICKEYBYTES]);
    /// ```
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

    /// In addition, *derivepk()* can be used to compute the public key given a
    /// secret key previously generated by *KeyPair::new()* or
    /// *KeyPair::seed()*.
    pub fn derivepk(sk: &[u8],
                    sk_size: usize,
                    pk_size: usize) -> Result<KeyPair, SSError> {
        let mut nsk = utils::malloc(sk_size);
        let mut pk = utils::malloc(pk_size);

        // Copy the old secret into this KeyPair to avoid any drop issues.
        for (i,b) in (0..).zip(sk.iter()) {
            nsk[i] = *b;
        }

        let res: i32;

        unsafe {
            res = crypto_scalarmult_base(pk.as_mut_ptr(), nsk.as_ptr());
        }

        if res == 0 {
            utils::mprotect_noaccess(nsk);
            utils::mprotect_noaccess(pk);

            Ok(KeyPair {
                s_key_ptr: nsk.as_mut_ptr(),
                s_size: sk_size,
                p_key_ptr: pk.as_mut_ptr(),
                p_size: pk_size,
            })
        } else {
            Err(KEYGEN("Unable to derive public key"))
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

    /// Applications that send several messages to the same receiver or receive
    /// several messages from the same sender can gain speed by calculating the
    /// shared key only once, and reusing it in subsequent operations.
    ///
    /// The *shared_secret()* function computes a shared secret key given a
    /// public key and returns the shared secret key result.
    pub fn shared_secret<'a>(&self,
                             pk: &[u8]) -> Result<&'a mut [u8], SSError> {
        let mut ssk = utils::malloc(BEFORENMBYTES);

        let res: i32;

        unsafe {
            res = crypto_box_beforenm(ssk.as_mut_ptr(),
                                      pk.as_ptr(),
                                      self.s_key_ptr);
        }

        if res == 0 {
            utils::mprotect_readonly(ssk);
            Ok(ssk)
        } else {
            Err(KEYGEN("Unable to generate shared secret key!"))
        }
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
