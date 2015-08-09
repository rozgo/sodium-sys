use sodium_sys::crypto::{nonce,secretbox};

#[test]
fn nonce() {
    ::test_init();
    let nonce = nonce::Nonce::new(secretbox::NONCEBYTES);
    nonce.activate();
    assert!(nonce.bytes().len() == secretbox::NONCEBYTES);
    assert!(nonce.bytes() != [0; secretbox::NONCEBYTES]);
}

#[cfg(feature = "latest")]
#[test]
fn nonce_increment() {
    ::test_init();
    let nonce = nonce::Nonce::new(secretbox::NONCEBYTES);
    nonce.activate();
    assert!(nonce.bytes().len() == secretbox::NONCEBYTES);
    assert!(nonce.bytes() != [0; secretbox::NONCEBYTES]);
    nonce.increment();
    assert!(nonce.bytes().len() == secretbox::NONCEBYTES);
    assert!(nonce.bytes() != [0; secretbox::NONCEBYTES]);
}
