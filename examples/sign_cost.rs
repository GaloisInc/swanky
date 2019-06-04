use fancy_garbling::informer::Informer;
use fancy_garbling::util::{factor, modulus_with_nprimes};
use fancy_garbling::*;

fn exact_sign<F: Fancy>(b: &mut F, x: &CrtBundle<F::Item>) {
    let z = b.crt_sign(x, "100%").unwrap();
    b.output(&z).unwrap();
}

fn main() {
    let nprimes = 10;
    let q = modulus_with_nprimes(nprimes);
    let mut i = Informer::new();
    let x = i.crt_receive(q).unwrap();
    exact_sign(&mut i, &x);
    i.print_info();
}
