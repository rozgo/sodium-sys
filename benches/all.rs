#![feature(test)]
extern crate sodium_sys;
extern crate test;

use sodium_sys::core::init;
use std::sync::{Once,ONCE_INIT};

static START: Once = ONCE_INIT;

fn test_init() {
    START.call_once(|| {
        init();
    });
}

mod randombytes;
mod utils;

mod crypto {
    mod crypto_key;
    mod crypto_nonce;
    mod crypto_secretbox;
    mod crypto_verify;
}
