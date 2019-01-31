extern crate cc;

fn main() {
    cc::Build::new()
        .file("cbits/transpose.c")
        .compile("libtranspose.a");
    cc::Build::new().file("cbits/aesni.c").compile("libaesni.a");
}
