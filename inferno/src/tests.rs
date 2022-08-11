use crate::Proof;
use proptest::prelude::*;
use scuttlebutt::field::{F61p, F64b, FiniteField, F2};
use scuttlebutt::{AesRng, Block};
use simple_arith_circuit::Circuit;
use std::path::PathBuf;
// use simple_logger::SimpleLogger;

const N: usize = 16;
const K: usize = 8;
const T: usize = 11;

fn test<F: FiniteField>(
    circuit: Circuit<F::PrimeField>,
    witness: Vec<F::PrimeField>,
    rng: &mut AesRng,
) {
    let proof = Proof::<F, N>::prove(&circuit, &witness, K, T, rng);
    let res = proof.verify(&circuit, K, T);
    assert_eq!(res, true);
}

fn any_seed() -> impl Strategy<Value = Block> {
    any::<u128>().prop_map(|seed| Block::from(seed))
}

macro_rules! test_circuits {
    ($modname: ident, $field: ty) => {
        mod $modname {
            use super::*;
            use scuttlebutt::AesRng;
            use rand::SeedableRng;
            use rand::distributions::{Distribution, Uniform};

            proptest! {
                #[test]
                fn test_random_circuit(seed in any_seed()) {
                    // SimpleLogger::new().init().unwrap();
                    let mut rng = AesRng::from_seed(seed);
                    let input_range = Uniform::from(2..100);
                    let ninputs = input_range.sample(&mut rng);
                    let gate_range = Uniform::from(101..200);
                    let ngates = gate_range.sample(&mut rng);
                    let (circuit, witness) =
                        simple_arith_circuit::circuitgen::random_zero_circuit::<<$field as FiniteField>::PrimeField, AesRng>(ninputs, ngates, &mut rng)
                            ;
                    test::<$field>(circuit, witness, &mut rng);
                }
            }

            proptest! {
                #[test]
                fn test_and_circuit(seed in any_seed()) {
                    // SimpleLogger::new().init().unwrap();
                    let mut rng = AesRng::from_seed(seed);
                    let input_range = Uniform::from(2..100);
                    let ninputs = input_range.sample(&mut rng);
                    let gate_range = Uniform::from(101..200);
                    let ngates = gate_range.sample(&mut rng);
                    let (circuit, witness) =
                        simple_arith_circuit::circuitgen::mul_zero_circuit::<<$field as FiniteField>::PrimeField, AesRng>(ninputs, ngates, &mut rng);
                    test::<$field>(circuit, witness, &mut rng);
                }
            }
        }
    };
}

test_circuits!(test_circuits_f61p, F61p);
test_circuits!(test_circuits_f64b, F64b);

#[test]
fn test_bristol() {
    // SimpleLogger::new().init().unwrap();
    let mut rng = AesRng::new();
    let base =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../simple-arith-circuit/circuits/bristol");
    let circuits = [
        "zero_equal.txt",
        "neg64.txt",
        "adder64.txt",
        "sub64.txt",
        "mult64.txt",
        "udivide64.txt",
        "mult2_64.txt",
        "divide64.txt",
        "aes_128.txt",
        "aes_192.txt",
        "aes_256.txt",
        "sha256.txt",
        "Keccak_f.txt",
        "sha512.txt",
    ];
    for circuit in circuits {
        eprintln!("Circuit = {circuit}");
        let time = std::time::Instant::now();
        let circuit = Circuit::read_bristol_fashion(&base.join(circuit), None).unwrap();
        eprintln!("Reading time: {} ms", time.elapsed().as_millis());
        let witness: Vec<F2> = (0..circuit.ninputs())
            .map(|_| F2::random(&mut rng))
            .collect();
        let mut wires = Vec::with_capacity(circuit.nwires());
        let outputs = circuit.eval(&witness, &mut wires);
        let circuit = simple_arith_circuit::builder::add_binary_equality_check(circuit, &outputs);
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
