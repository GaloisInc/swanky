extern crate cc;

fn main() {
    let cargo_target_arch = std::env::var_os("CARGO_CFG_TARGET_ARCH");
    if let Some(target_arch) = cargo_target_arch {
        if target_arch == "wasm32" {
            return;
        }
    }

    cc::Build::new()
        .file("cbits/transpose.c")
        .flag("-maes")
        .flag("-msse4.1")
        .compile("libtranspose.a");
}
