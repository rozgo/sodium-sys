extern crate pkg_config;

use std::env;
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    match pkg_config::find_library("libsodium") {
        Ok(_)  => {},
        Err(_) => {
            let target = env::var("TARGET").unwrap();
            let windows = target.contains("windows");
            let src = PathBuf::from(&env::var_os("CARGO_MANIFEST_DIR").unwrap())
                               .join("libsodium");
            let dst = PathBuf::from(&env::var_os("OUT_DIR").unwrap());
            let _ = fs::create_dir(&dst);

            if !windows || !target.contains("msvc") {
                match File::open(src.join("configure")) {
                    Ok(_)  => {},
                    Err(_) => {
                        run(Command::new("./autogen.sh").current_dir(&src));
                    },
                }
                run(Command::new("./configure").current_dir(&src));
                run(Command::new("make").current_dir(&src));
                let shlib = src.join("src/libsodium/.libs");
                let _ = fs::copy(&shlib.join("libsodium.a"), &dst.join("libsodium.a"));

                println!("cargo:rustc-flags=-l static=sodium");
                println!("cargo:rustc-flags=-L {}", dst.display());
            } else {
                let lib = dst.join("lib");
                let _ = fs::create_dir(&lib);

                run(Command::new("msbuild").current_dir(&src)
                             .arg("/nologo")
                             .arg("/p:Configuration=Release"));

                let mut buildout = src.join("Build");
                buildout.push("Release");

                if target.contains("i686") {
                    buildout.push("Win32");
                } else {
                    buildout.push("x64");
                }

                let _ = fs::copy(&buildout.join("libsodium.lib"), &lib.join("libsodium.lib"));

                println!("cargo:rustc-link-search=native={}/lib", dst.display());
                println!("cargo:rustc-link-lib=libsodium");
                println!("cargo:root={}", dst.display());
                //println!("cargo:include={}/include", dst.display());
            }


        },
    }
}

fn run(cmd: &mut Command) {
    match cmd.status() {
        Ok(status) => assert!(status.success()),
        Err(e)     => panic!("Unable to execute {:?}! {}", cmd, e),
    }
}
