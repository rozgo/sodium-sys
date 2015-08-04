#![feature(test)]
extern crate sodium_sys;
extern crate test;

use sodium_sys::core;
use sodium_sys::utils;

#[test]
fn init() {
    assert!(core::init() == 0);
}

#[test]
fn memzero() {
    let v = [0, 1, 2, 3, 4, 5, 6, 7];
    utils::memzero(&v);
    assert!(v == [0; 8]);
}

#[test]
fn memcmp() {
    let v0 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v1 = [0, 1, 2, 3, 4, 5, 6, 7];
    let v2 = [7, 6, 5, 4, 3, 2, 1, 0];
    assert!(utils::memcmp(&v0,&v1) == 0);
    assert!(utils::memcmp(&v0,&v2) == -1);
    assert!(utils::memcmp(&v1,&v2) == -1);
}
