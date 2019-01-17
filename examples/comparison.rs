//! Example comparing CRT comparision with boolean comparison.

use fancy_garbling::fancy::{Fancy, BundleGadgets};
use fancy_garbling::informer::Informer;
use fancy_garbling::util::primes_with_width;

fn main() {
    let nbits = 20;

    println!("binary comparison with {} bit inputs", nbits);
    let binary = Informer::new();
    let x = binary.garbler_input_bundle(None, &vec![2;nbits]);
    let y = binary.evaluator_input_bundle(None, &vec![2;nbits]);
    let z = binary.exact_lt(None, &x,&y);
    binary.output(None, &z);
    binary.print_info();
    println!("");

    let ps = primes_with_width(nbits as u32);
    println!("arithmetic comparison with {} primes", ps.len());
    let arith = Informer::new();
    let x = arith.garbler_input_bundle(None, &ps);
    let y = arith.evaluator_input_bundle(None, &ps);
    let z = arith.exact_lt(None, &x,&y);
    arith.output(None, &z);
    arith.print_info();
}
