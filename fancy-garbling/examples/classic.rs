use fancy_garbling::{circuit::Circuit, classic::garble};
use std::time::SystemTime;

fn main() {
    let circ = Circuit::parse("circuits/adder_32bit.txt").unwrap();

    let start = SystemTime::now();

    let (encoder, garbled) = garble(&circ).unwrap();

    println!("Total: {} ms", start.elapsed().unwrap().as_millis());

    // TODO(interstellar) ???

    // TODO(interstellar) check eval results; or maybe instead in fancy-garbling/examples/semihonest_2pc.rs ?
}
