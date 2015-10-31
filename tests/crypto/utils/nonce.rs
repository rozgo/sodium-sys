use sodium_sys::crypto::symmetrickey::authenc;
use sodium_sys::crypto::utils::nonce;

#[test]
fn nonce() {
    ::test_init();
    let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
    nonce.activate();
    assert!(nonce.bytes().len() == authenc::NONCEBYTES);
    assert!(nonce.bytes() != [0; authenc::NONCEBYTES]);
}

#[cfg(feature = "latest")]
#[test]
fn nonce_increment() {
    ::test_init();
    let nonce = nonce::Nonce::new(authenc::NONCEBYTES);
    nonce.activate();
    assert!(nonce.bytes().len() == authenc::NONCEBYTES);
    assert!(nonce.bytes() != [0; authenc::NONCEBYTES]);
    nonce.increment();
    assert!(nonce.bytes().len() == authenc::NONCEBYTES);
    assert!(nonce.bytes() != [0; authenc::NONCEBYTES]);
}
