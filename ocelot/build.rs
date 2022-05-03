extern crate cc;

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    cc::Build::new()
        .file("cbits/transpose.c")
        .flag("-maes")
        .flag("-msse4.1")
        .compile("libtranspose.a");
}
