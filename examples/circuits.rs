//! Example building and exporting circuits using the Fancy interface to CircuitBuilder.

use fancy_garbling::circuit::CircuitBuilder;
use fancy_garbling::fancy::Fancy;
use fancy_garbling::util::RngExt;

fn main() {
    let mut rng = rand::thread_rng();

    // half-gate
    let b = CircuitBuilder::new();
    let q = rng.gen_prime();
    let x = b.garbler_input(None, q);
    let y = b.evaluator_input(None, q);
    let z = b.mul(None, &x,&y);
    b.output(None, &z);
    let c = b.finish();
    c.to_file("half_gate.json").unwrap();

    // and-gate-fan-n
    let b = CircuitBuilder::new();
    let n = 2 + (rng.gen_usize() % 200);
    let inps = b.garbler_inputs(None, 2, n);
    let z = b.and_many(None, &inps);
    b.output(None, &z);
    let c = b.finish();
    c.to_file("and_gate_fan_n.json").unwrap()
}
