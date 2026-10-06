// mod aes;
mod example;

use criterion::{Criterion, criterion_group, criterion_main};

use merlin::Transcript;
use rand::rng as thread_rng;
use schmivitz::parameters::{Binary128Bit, Binary256Bit};
use schmivitz::{
    Proof,
    circuit::load_circuit_from_strings_prover,
    circuit_validator::validate_circuit,
    vole::functionality::{VoleProver, VoleVerifier},
};
use std::hint::black_box;

// use crate::aes::AES256;
use crate::example::ExampleCircuit;

macro_rules! make_benches {
    (mod $name:ident { params = $params:ty, prefix = $prefix:literal $(,)? }) => {
        mod $name {
            use super::*;

            #[allow(dead_code)]
            type P = $params;

            // Get a fresh transcript
            fn transcript() -> Transcript {
                Transcript::new(b"basic happy test transcript")
            }

            pub fn benchmark_aes256(c: &mut Criterion) {
                let mini_circuit_bytes = include_str!("../circuits/aes_256_conv.sieve");
                let private_input_bytes = include_str!("../circuits/aes_256_conv_private.sieve");

                c.bench_function(concat!($prefix, "aes256_parse"), |b| {
                    b.iter(|| {
                        let circuit = load_circuit_from_strings_prover(
                            mini_circuit_bytes,
                            private_input_bytes,
                        );
                        std::hint::black_box(circuit.is_ok());
                    })
                });

                let circuit =
                    load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes)
                        .unwrap();
                validate_circuit(&circuit).unwrap();

                c.bench_function(concat!($prefix, "aes256_prove_interp"), |b| {
                    b.iter(|| {
                        let rng = &mut thread_rng();
                        let proof =
                            Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                                &circuit,
                                &mut transcript(),
                                rng,
                            )
                            .unwrap();
                        black_box(proof)
                    })
                });

                let rng = &mut thread_rng();
                let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                    &circuit,
                    &mut transcript(),
                    rng,
                )
                .unwrap();

                c.bench_function(concat!($prefix, "aes256_verify_interp"), |b| {
                    b.iter(|| {
                        let verif = proof.verify_with_circuit(&circuit, &mut transcript());
                        assert!(verif.is_ok());
                        std::hint::black_box(verif.is_ok())
                    })
                });

                // c.bench_function(concat!($prefix, "aes256_prove"), |b| {
                //     b.iter(|| {
                //         let rng = &mut thread_rng();
                //         let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove(
                //             AES256,
                //             &circuit.private_inputs,
                //             circuit.max_wire_id,
                //             &mut transcript(),
                //             rng,
                //         )
                //         .unwrap();
                //         black_box(proof)
                //     })
                // });

                // c.bench_function(concat!($prefix, "aes256_verify"), |b| {
                //     b.iter(|| {
                //         let verif = proof.verify(AES256, &mut transcript());
                //         assert!(verif.is_ok());
                //         black_box(verif.is_ok())
                //     })
                // });
            }

            pub fn benchmark_example_10000(c: &mut Criterion) {
                let mini_circuit_bytes = include_str!("../circuits/example_10000.sieve");
                let private_input_bytes = include_str!("../circuits/example_10000_private.sieve");

                c.bench_function(concat!($prefix, "example_parse"), |b| {
                    b.iter(|| {
                        let circuit = load_circuit_from_strings_prover(
                            mini_circuit_bytes,
                            private_input_bytes,
                        );
                        black_box(circuit.is_ok());
                    })
                });

                let circuit =
                    load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes)
                        .unwrap();

                c.bench_function(concat!($prefix, "example_prove_interp"), |b| {
                    b.iter(|| {
                        let rng = &mut thread_rng();
                        let proof =
                            Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                                &circuit,
                                &mut transcript(),
                                rng,
                            )
                            .unwrap();
                        black_box(proof)
                    })
                });

                let rng = &mut thread_rng();
                let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                    &circuit,
                    &mut transcript(),
                    rng,
                )
                .unwrap();

                c.bench_function(concat!($prefix, "example_verify_interp"), |b| {
                    b.iter(|| {
                        let verif = proof.verify_with_circuit(&circuit, &mut transcript());
                        assert!(verif.is_ok());
                        black_box(verif.is_ok())
                    })
                });

                c.bench_function(concat!($prefix, "example_prove"), |b| {
                    b.iter(|| {
                        let rng = &mut thread_rng();
                        let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove(
                            &ExampleCircuit::<10000>,
                            &circuit.private_inputs,
                            Some(circuit.max_wire_id as usize),
                            &mut transcript(),
                            rng,
                        )
                        .unwrap();
                        black_box(proof)
                    })
                });

                c.bench_function(concat!($prefix, "example_verify"), |b| {
                    b.iter(|| {
                        let verif = proof.verify(&ExampleCircuit::<10000>, &mut transcript());
                        assert!(verif.is_ok());
                        black_box(verif.is_ok())
                    })
                });
            }

            pub fn benchmark_example_100000(c: &mut Criterion) {
                let mini_circuit_bytes = include_str!("../circuits/example_100000.sieve");
                let private_input_bytes = include_str!("../circuits/example_10000_private.sieve");

                c.bench_function(concat!($prefix, "example_100000_parse"), |b| {
                    b.iter(|| {
                        let circuit = load_circuit_from_strings_prover(
                            mini_circuit_bytes,
                            private_input_bytes,
                        );
                        black_box(circuit.is_ok());
                    })
                });

                let circuit =
                    load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes)
                        .unwrap();

                c.bench_function(concat!($prefix, "example_100000_prove_interp"), |b| {
                    b.iter(|| {
                        let rng = &mut thread_rng();
                        let proof =
                            Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                                &circuit,
                                &mut transcript(),
                                rng,
                            )
                            .unwrap();
                        black_box(proof)
                    })
                });

                let rng = &mut thread_rng();
                let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                    &circuit,
                    &mut transcript(),
                    rng,
                )
                .unwrap();

                c.bench_function(concat!($prefix, "example_100000_verify_interp"), |b| {
                    b.iter(|| {
                        let verif = proof.verify_with_circuit(&circuit, &mut transcript());
                        assert!(verif.is_ok());
                        black_box(verif.is_ok())
                    })
                });

                c.bench_function(concat!($prefix, "example_100000_prove"), |b| {
                    b.iter(|| {
                        let rng = &mut thread_rng();
                        let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove(
                            &ExampleCircuit::<100000>,
                            &circuit.private_inputs,
                            Some(circuit.max_wire_id as usize),
                            &mut transcript(),
                            rng,
                        )
                        .unwrap();
                        black_box(proof)
                    })
                });

                let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove(
                    &ExampleCircuit::<100000>,
                    &circuit.private_inputs,
                    Some(circuit.max_wire_id as usize),
                    &mut transcript(),
                    rng,
                )
                .unwrap();

                c.bench_function(concat!($prefix, "example_100000_verify"), |b| {
                    b.iter(|| {
                        let verif = proof.verify(&ExampleCircuit::<100000>, &mut transcript());
                        assert!(verif.is_ok());
                        black_box(verif.is_ok())
                    })
                });
            }

            pub fn benchmark_sha256(c: &mut Criterion) {
                let mini_circuit_bytes = include_str!("../circuits/sha256_conv.sieve");
                let private_input_bytes = include_str!("../circuits/sha256_conv_private.sieve");

                c.bench_function(concat!($prefix, "sha256_parse"), |b| {
                    b.iter(|| {
                        let circuit = load_circuit_from_strings_prover(
                            mini_circuit_bytes,
                            private_input_bytes,
                        );
                        std::hint::black_box(circuit.is_ok());
                    })
                });

                let circuit =
                    load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes)
                        .unwrap();
                validate_circuit(&circuit).unwrap();

                c.bench_function(concat!($prefix, "sha256_prove"), |b| {
                    b.iter(|| {
                        let rng = &mut thread_rng();
                        let proof =
                            Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                                &circuit,
                                &mut transcript(),
                                rng,
                            )
                            .unwrap();
                        black_box(proof)
                    })
                });

                let rng = &mut thread_rng();
                let proof = Proof::<VoleProver<P>, VoleVerifier<P>>::prove_with_circuit::<_>(
                    &circuit,
                    &mut transcript(),
                    rng,
                )
                .unwrap();

                c.bench_function(concat!($prefix, "sha256_verify"), |b| {
                    b.iter(|| {
                        let verif = proof.verify_with_circuit(&circuit, &mut transcript());
                        assert!(verif.is_ok());
                        std::hint::black_box(verif.is_ok())
                    })
                });
            }
        }
    };
}

make_benches! { mod binary_128_bit { params = Binary128Bit, prefix = "binary_128_bit/" } }
make_benches! { mod binary_256_bit { params = Binary256Bit, prefix = "binary_256_bit/" } }

criterion_group!(
    benches,
    binary_128_bit::benchmark_aes256,
    binary_128_bit::benchmark_sha256,
    binary_128_bit::benchmark_example_10000,
    binary_128_bit::benchmark_example_100000,
    binary_256_bit::benchmark_aes256,
    binary_256_bit::benchmark_sha256,
    binary_256_bit::benchmark_example_10000,
    binary_256_bit::benchmark_example_100000
);
criterion_main!(benches);
