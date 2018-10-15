extern crate cc;

fn main() {
    cc::Build::new().file("cbits/base_conversion_tables.c").compile("libbaseconversion.a");
}
