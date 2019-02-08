use fancy_garbling::*;
use fancy_garbling::informer::Informer;
use fancy_garbling::util::modulus_with_nprimes;

fn exact_sign<F,W>(b: &F, q: u128)
  where F: Fancy<Item=W>,
        W: HasModulus + Clone,
{
    let x = b.garbler_input_bundle_crt(None, q, None);
    let z = b.sign(None, &x, "100%");
    b.output(None, &z);
}

fn main() {
    let nprimes = 10;
    let q = modulus_with_nprimes(nprimes);
    let i = Informer::new();
    exact_sign(&i,q);
    i.print_info();
}
