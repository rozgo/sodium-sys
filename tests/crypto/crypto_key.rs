use sodium_sys::crypto::{key,secretbox};

#[test]
fn key() {
    ::test_init();
    let key = key::Key::new(secretbox::KEYBYTES);
    key.activate();
    assert!(key.bytes().len() == secretbox::KEYBYTES);
    assert!(key.bytes() != [0; secretbox::KEYBYTES]);
}
