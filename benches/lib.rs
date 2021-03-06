#![feature(test)]
extern crate sodium_sys;
extern crate test;

use sodium_sys::crypto::utils::init;
use std::sync::{Once,ONCE_INIT};

static START: Once = ONCE_INIT;

fn test_init() {
    START.call_once(|| {
        init::init();
    });
}

mod crypto {
    mod asymmetrickey;
    mod hash;
    mod symmetrickey;
    mod utils;
}
