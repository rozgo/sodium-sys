use sodium_sys::crypto::utils::verify;

#[test]
fn verify_16_bytes() {
    assert!(verify::verify_16_bytes() == verify::crypto_verify_16_BYTES);
}

#[test]
fn verify_32_bytes() {
    assert!(verify::verify_32_bytes() == verify::crypto_verify_32_BYTES);
}

#[test]
fn verify_64_bytes() {
    assert!(verify::verify_64_bytes() == verify::crypto_verify_64_BYTES);
}

#[test]
fn verify_16() {
    let a = [0; 16];
    let b = [0; 16];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(verify::verify_16(&a, &b) == 0);
    assert!(verify::verify_16(&a, &c) == -1);
}

#[test]
fn verify_32() {
    let a = [0; 32];
    let b = [0; 32];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(verify::verify_32(&a, &b) == 0);
    assert!(verify::verify_32(&a, &c) == -1);
}

#[test]
fn verify_64() {
    let a = [0; 64];
    let b = [0; 64];
    let c = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(verify::verify_64(&a, &b) == 0);
    assert!(verify::verify_64(&a, &c) == -1);
}
