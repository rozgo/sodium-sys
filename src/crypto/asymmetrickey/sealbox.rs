//! Sealed boxes are designed to anonymously send messages to a recipient given
//! its public key.
//!
//! Only the recipient can decrypt these messages, using its private key. While
//! the recipient can verify the integrity of the message, it cannot verify the
//! identity of the sender.
//!
//! A message is encrypted using an ephemeral key pair, whose secret part is
//! destroyed right after the encryption process.
//!
//! Without knowing the secret key used for a given message, the sender cannot
//! decrypt its own message later. And without additional data, a message cannot
//! be correlated with the identity of its sender.
use libc::{c_int, c_uchar, c_ulonglong};
use SSError::{self, DECRYPT, ENCRYPT};
use crypto::utils::secmem;

// 32 bytes.
pub const PUBLICKEYBYTES: usize = 32;
// 32 bytes.
pub const SECRETKEYBYTES: usize = 32;
// 32 bytes.
pub const ZEROBYTES: usize = 32;
// 16 bytes.
pub const BOXZEROBYTES: usize = 16;
// 16 bytes.
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES;
// 48 bytes.
pub const SEALBYTES: usize = PUBLICKEYBYTES + MACBYTES;

extern "C" {
    fn crypto_box_seal(out: *mut c_uchar,
                       in_: *const c_uchar,
                       inlen: c_ulonglong,
                       pk: *const c_uchar) -> c_int;
    fn crypto_box_seal_open(out: *mut c_uchar,
                            in_: *const c_uchar,
                            inlen: c_ulonglong,
                            pk: *const c_uchar,
                            sk: *const c_uchar) -> c_int;
}

/// The *seal()* function encrypts a message for a recipients public key. It
/// returns the ciphertext.
///
/// The function creates a new key pair for each message, and attaches the
/// public key to the ciphertext. The secret key is overwritten and is not
/// accessible after this function returns.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::asymmetrickey::{sealbox,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create a keypair and activate for use.
/// let theirkeypair = auth_keypair::KeyPair::new().unwrap();
/// theirkeypair.activate_pk();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = sealbox::seal(b"test",
///                                theirkeypair.pk_bytes()).unwrap();
/// println!("{:?}", ciphertext);
/// ```
pub fn seal<'a>(message: &[u8], pk: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);

    let mut ciphertext = secmem::malloc(SEALBYTES + message.len());

    let res: i32;

    unsafe {
        res = crypto_box_seal(ciphertext.as_mut_ptr(),
                              message.as_ptr(),
                              message.len() as c_ulonglong,
                              pk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(ciphertext);
        Ok(ciphertext)
    } else {
        Err(ENCRYPT("Unable to encrypt message!"))
    }
}

/// The *open()* function decrypts the ciphertext using the key pair (pk, sk),
/// returns the message.
///
/// This function doesn't require passing the public key of the sender, as the
/// ciphertext already includes this information.
///
/// # Examples
///
/// ```
/// use sodium_sys::crypto::utils::init;
/// use sodium_sys::crypto::asymmetrickey::{sealbox,auth_keypair};
///
/// // Initialize sodium_sys
/// init::init();
///
/// // Create another keypair and activate for use.
/// let keypair = auth_keypair::KeyPair::new().unwrap();
/// keypair.activate_pk();
/// keypair.activate_sk();
///
/// // Generate the ciphertext and protect it as readonly.
/// let ciphertext = sealbox::seal(b"test", keypair.pk_bytes()).unwrap();
///
/// // Decrypt the ciphertext.
/// let message = sealbox::open(ciphertext,
///                             keypair.pk_bytes(),
///                             keypair.sk_bytes()).unwrap();
/// assert!(b"test" == message);
/// ```
pub fn open<'a>(ciphertext: &[u8],
                pk: &[u8],
                sk: &[u8]) -> Result<&'a [u8], SSError> {
    assert!(pk.len() == PUBLICKEYBYTES);
    assert!(sk.len() == SECRETKEYBYTES);

    let mut message = secmem::malloc(ciphertext.len() - SEALBYTES);

    let res: i32;

    unsafe {
        res = crypto_box_seal_open(message.as_mut_ptr(),
                                   ciphertext.as_ptr(),
                                   ciphertext.len() as c_ulonglong,
                                   pk.as_ptr(),
                                   sk.as_ptr());
    }

    if res == 0 {
        secmem::mprotect_readonly(message);
        Ok(message)
    } else {
        Err(DECRYPT("Unable to decrypt ciphertext!"))
    }
}
