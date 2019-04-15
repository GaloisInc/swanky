extern crate cc;

fn main() {
    cc::Build::new()
        .file("cbits/transpose.c")
        .flag("-maes")
        .flag("-msse4.1")
        .compile("libtranspose.a");
}
