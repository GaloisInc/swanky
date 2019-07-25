use fancy_garbling::{informer::Informer, util::modulus_with_nprimes, *};

fn exact_sign<F: Fancy>(b: &mut F, x: &CrtBundle<F::Item>) {
    let z = b.crt_sign(x, "100%").unwrap();
    b.output(&z).unwrap();
}

fn main() {
    let nprimes = 10;
    let q = modulus_with_nprimes(nprimes);
    let mut i = Informer::new(dummy::Dummy::new());
    let x = i.crt_encode(2, q).unwrap();
    exact_sign(&mut i, &x);
    println!("{}", i.stats());
}
