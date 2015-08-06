use sodium_sys::crypto::key;
use sodium_sys::crypto::secretbox;

#[test]
fn key() {
    use sodium_sys::core::init;
    init();
    let key = key::Key::new(secretbox::KEYBYTES);
    key.activate();
    assert!(key.bytes().len() == secretbox::KEYBYTES);
    assert!(key.bytes() != [0; secretbox::KEYBYTES]);
}
