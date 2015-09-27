extern crate regex;
extern crate sodium_sys;

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
    mod symmetrickey;
    mod utils;
}
