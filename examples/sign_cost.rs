use fancy_garbling::informer::Informer;
use fancy_garbling::util::modulus_with_nprimes;
use fancy_garbling::*;

fn exact_sign<F, W>(b: &mut F, q: u128)
where
    F: Fancy<Item = W>,
    W: HasModulus + Clone,
{
    let x = b.garbler_input_bundle_crt(q, None).unwrap();
    let z = b.sign(&x, "100%").unwrap();
    b.output(&z).unwrap();
}

fn main() {
    let nprimes = 10;
    let q = modulus_with_nprimes(nprimes);
    let mut i = Informer::new();
    exact_sign(&mut i, q);
    i.print_info();
}
