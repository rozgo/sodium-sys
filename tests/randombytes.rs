use sodium_sys::randombytes;

#[test]
fn random() {
    let r0 = randombytes::random();
    let r1 = randombytes::random();
    assert!(r0 != r1);
}

#[test]
fn uniform() {
    let r0 = randombytes::uniform(10);
    let r1 = randombytes::uniform(10);
    assert!(r0 < 10);
    assert!(r1 < 10);
}

#[test]
fn random_byte_array() {
    let mut ra0 = [0; 16];
    let mut ra1 = [0; 16];
    randombytes::random_byte_array(&mut ra0);
    randombytes::random_byte_array(&mut ra1);
    assert!(ra0 != [0; 16]);
    assert!(ra1 != [0; 16]);
    assert!(ra0 != ra1);
}
