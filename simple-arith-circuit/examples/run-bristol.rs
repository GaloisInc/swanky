use scuttlebutt::{field::F2, ring::FiniteRing};
use simple_arith_circuit::Circuit;
use std::path::Path;
use std::str::FromStr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("USAGE: run-bristol <path> <num iters> <input bits as 0/1>");
        std::process::exit(1);
    }
    let circuit = Circuit::<F2>::read_bristol_fashion(Path::new(args[1].as_str()), None).unwrap();
    let num_iters = usize::from_str(&args[2]).unwrap();
    let raw_inputs = args[3]
        .chars()
        .map(|ch| match ch {
            '1' => F2::ONE,
            '0' => F2::ZERO,
            _ => panic!("Unexpected char {ch:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(raw_inputs.len(), circuit.noutputs());
    let mut acu = Vec::new();
    for i in 0..circuit.ninputs() {
        acu.push(raw_inputs[i % raw_inputs.len()]);
    }
    let mut wires = Vec::new();
    for _ in 0..num_iters {
        wires.clear();
        let out_slice = circuit.eval(&acu, &mut wires);
        acu.clear();
        for i in 0..circuit.ninputs() {
            acu.push(out_slice[i % out_slice.len()]);
        }
    }
    for bit in &acu[0..circuit.noutputs()] {
        if *bit == F2::ONE {
            print!("1");
        } else {
            print!("0");
        }
    }
    println!();
}
