use sodium_sys::crypto::symmetrickey::{key,authenc};

#[test]
fn key() {
    ::test_init();
    let key = key::Key::new(authenc::KEYBYTES);
    key.activate();
    assert!(key.bytes().len() == authenc::KEYBYTES);
    assert!(key.bytes() != [0; authenc::KEYBYTES]);
}
