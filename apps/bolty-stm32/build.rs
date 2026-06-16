use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rustc-link-search={}", out.display());

    if env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "arm" {
        fs::copy("memory.x", out.join("memory.x")).unwrap();
    }
}
