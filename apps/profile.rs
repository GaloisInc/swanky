use fancy_garbling::circuit::crt::CrtBundler;
use fancy_garbling::numbers;
use fancy_garbling::garble::garble;

pub fn main() {
    let q = numbers::modulus_with_width(32);

    let mut b = CrtBundler::new();
    let x = b.input(q);
    let ms = std::iter::repeat(4).take(5).collect::<Vec<_>>();
    let z = b.sgn(x,&ms);
    b.output(z);
    let circ = b.finish();

    for _ in 0..16 {
        let _gb = garble(&circ);
    }
}
