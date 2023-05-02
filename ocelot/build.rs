fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cbits/transpose.c");
    let cargo_target_arch = std::env::var_os("CARGO_CFG_TARGET_ARCH");
    if let Some(target_arch) = cargo_target_arch {
        if target_arch != "x86_64" {
            return;
        }
    }
    cc::Build::new()
        .file("cbits/transpose.c")
        .flag("-msse4.1")
        .compile("libtranspose.a");
}
