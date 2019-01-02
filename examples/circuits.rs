//! Example building and exporting circuits using the Fancy interface to CircuitBuilder.

use fancy_garbling::circuit::CircuitBuilder;
use fancy_garbling::fancy::Fancy;
use fancy_garbling::util::RngExt;

fn main() {
    let mut rng = rand::thread_rng();

    // half-gate
    let mut b = CircuitBuilder::new();
    let q = rng.gen_prime();
    let x = b.garbler_input(q);
    let y = b.evaluator_input(q);
    let z = b.mul(&x,&y);
    b.output(&z);
    let c = b.finish();
    c.to_file("half_gate.json").unwrap();

    // and-gate-fan-n
    let mut b = CircuitBuilder::new();
    let mut inps = Vec::new();
    let n = 2 + (rng.gen_usize() % 200);
    for _ in 0..n {
        inps.push(b.garbler_input(2));
    }
    let z = b.and_many(&inps);
    b.output(&z);
    let c = b.finish();
    c.to_file("and_gate_fan_n.json").unwrap()
}
