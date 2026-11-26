use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/wpe_hook.c");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64")
    {
        return;
    }

    let cc = env::var("CC_aarch64_linux_android")
        .or_else(|_| env::var("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"))
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| "clang".into());
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by Cargo"));
    let out_so = out_dir.join("libskyward_wpe_hook.so");

    let mut cmd = Command::new(&cc);
    if !cc.contains("aarch64") {
        cmd.args(["--target=aarch64-linux-gnu", "-fuse-ld=/usr/bin/aarch64-linux-gnu-ld"]);
    }
    let status = cmd
        .args([
            "-shared",
            "-nostdlib",
            "-fPIC",
            "-O2",
            "-Wl,-z,max-page-size=4096,--allow-shlib-undefined",
            "-s",
            "-o",
        ])
        .arg(&out_so)
        .arg("src/wpe_hook.c")
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke {cc} for wpe_hook.c: {e}"));
    assert!(status.success(), "{cc} failed compiling src/wpe_hook.c");
}
