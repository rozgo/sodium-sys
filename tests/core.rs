use sodium_sys::core;

#[test]
fn init() {
    let res = core::init();
    assert!((res.is_positive()) | (res == 0));
}
