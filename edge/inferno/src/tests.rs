use crate::Proof;
use proptest::prelude::*;
use simple_arith_circuit::Circuit;
use std::path::PathBuf;
use swanky_field::FiniteField;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F64b};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

// The number of parties in the MPC
const N: usize = 16;
// The compression factor
const K: usize = 8;
// The number of repetitions
const T: usize = 40;

fn test<F: FiniteField>(
    circuit: Circuit<F::PrimeField>,
    witness: Vec<F::PrimeField>,
    rng: &mut SwankyRng,
) {
    let proof = Proof::<F, N>::prove(&circuit, &witness, K, T, rng);
    let res = proof.verify(&circuit, K, T);
    assert!(res.is_ok());
}

fn any_seed() -> impl Strategy<Value = U8x16> {
    any::<u128>().prop_map(U8x16::from)
}

macro_rules! test_circuits {
    ($modname: ident, $field: ty) => {
        mod $modname {
            use super::*;
            use swanky_rng::SwankyRng;
            use rand::SeedableRng;
            use rand::distr::{Distribution, Uniform};

            proptest! {
                #[test]
                fn test_random_circuit(seed in any_seed()) {
                    // SimpleLogger::new().init().unwrap();
                    let mut rng = SwankyRng::from_seed(seed);
                    let input_range = Uniform::try_from(2..100).expect("bounds finite and low < high");
                    let ninputs = input_range.sample(&mut rng);
                    let gate_range = Uniform::try_from(101..200).expect("bounds finite and low < high");
                    let ngates = gate_range.sample(&mut rng);
                    let (circuit, witness) =
                        simple_arith_circuit::circuitgen::random_zero_circuit::<<$field as FiniteField>::PrimeField, _>(ninputs, ngates, &mut rng)
                            ;
                    test::<$field>(circuit, witness, &mut rng);
                }
            }

            proptest! {
                #[test]
                fn test_and_circuit(seed in any_seed()) {
                    // SimpleLogger::new().init().unwrap();
                    let mut rng = SwankyRng::from_seed(seed);
                    let input_range = Uniform::try_from(2..100).expect("bounds finite and low < high");
                    let ninputs = input_range.sample(&mut rng);
                    let gate_range = Uniform::try_from(101..200).expect("bounds finite and low < high");
                    let ngates = gate_range.sample(&mut rng);
                    let (circuit, witness) =
                        simple_arith_circuit::circuitgen::mul_zero_circuit::<<$field as FiniteField>::PrimeField, _>(ninputs, ngates, &mut rng);
                    test::<$field>(circuit, witness, &mut rng);
                }
            }
        }
    };
}

test_circuits!(test_circuits_f64b, F64b);

#[test]
fn test_bristol() {
    let mut rng = SwankyRng::default();
    let base =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../simple-arith-circuit/circuits/bristol");
    for entry in base.read_dir().expect("directory should exist") {
        let circuit = entry.unwrap().path();
        // Skip files that don't look like bristol fashion circuits.
        if let Some(extension) = circuit.extension() {
            if extension != "txt" {
                continue;
            }
        } else {
            continue;
        }
        eprintln!("Circuit = {:?}", circuit);
        let time = std::time::Instant::now();
        let circuit = Circuit::read_bristol_fashion(&circuit, None).unwrap();
        eprintln!("Reading time: {} ms", time.elapsed().as_millis());
        let witness: Vec<F2> = (0..circuit.ninputs())
            .map(|_| <F2 as FiniteRing>::random(&mut rng))
            .collect();
        let mut wires = Vec::with_capacity(circuit.nwires());
        let outputs = circuit.eval(&witness, &mut wires);
        let circuit = simple_arith_circuit::builder::add_binary_equality_check(circuit, outputs);
        eprintln!("# inputs = {}", circuit.ninputs());
        eprintln!("# mults = {}", circuit.nmuls());
        let time = std::time::Instant::now();
        test::<F64b>(circuit, witness, &mut rng);
        eprintln!(
            "Proving / verifying time: {} ms",
            time.elapsed().as_millis()
        );
    }
}
