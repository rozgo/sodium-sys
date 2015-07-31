extern "C" {
    pub fn sodium_init() -> ::libc::c_int;
}

#[test]
fn test_sodium_init() {
    assert!(unsafe { sodium_init() } == 0);
}
