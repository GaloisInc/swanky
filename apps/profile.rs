#![feature(test)]

extern crate fancy_garbling;
extern crate test;

use fancy_garbling::high_level::Bundler;
use fancy_garbling::numbers;
use fancy_garbling::garble::garble;

pub fn main() {
    let q = numbers::modulus_with_width(32);

    let mut b = Bundler::new();
    let x = b.input(q);
    let ms = std::iter::repeat(4).take(5).collect::<Vec<_>>();
    let z = b.sgn(x,&ms);
    b.output_ref(z);
    let c = b.finish();

    for _ in 0..16 {
        let (gb, _ev) = garble(&c);
        test::black_box(gb);
    }
}
