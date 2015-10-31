use sodium_sys::crypto::utils::init;

#[test]
fn init() {
    let res = init::init();
    assert!((res.is_positive()) | (res == 0));
}
