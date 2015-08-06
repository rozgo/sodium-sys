use sodium_sys::randombytes;
use test::Bencher;

#[bench]
fn bench_random(b: &mut Bencher) {
    b.iter(|| { randombytes::random() })
}

#[bench]
fn bench_uniform(b: &mut Bencher) {
    b.iter(|| { randombytes::uniform(10) })
}

#[bench]
fn bench_random_byte_array(b: &mut Bencher) {
    let mut ra = [0; 16];
    b.iter(|| { randombytes::random_byte_array(&mut ra) });
}
