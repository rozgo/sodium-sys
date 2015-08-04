#![feature(test)]
extern crate sodium_sys;
extern crate test;

use sodium_sys::utils;
use test::Bencher;

#[bench]
fn bench_memcmp_1000(b: &mut Bencher) {
    let v0 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v1 = [0, 1, 2, 3, 4, 5, 6, 7];
    b.iter(|| {
        utils::memcmp(&v0, &v1)
    });
}
