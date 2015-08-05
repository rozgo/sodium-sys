#![feature(test)]
extern crate sodium_sys;
extern crate test;

mod randombytes;
mod utils;

mod crypto {
    mod crypto_secretbox;
    mod crypto_verify;
}
