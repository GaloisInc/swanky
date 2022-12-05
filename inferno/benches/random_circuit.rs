use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use inferno::Proof;
use scuttlebutt::field::{F61p, F64b, FiniteField};
use scuttlebutt::AesRng;
use std::time::Duration;

const N: usize = 16;

const MIN: usize = 10;
const MAX: usize = 14;

fn bench_random_circuit<F: FiniteField>(c: &mut Criterion, group: &str) {
    let mut group = c.benchmark_group(group);
    for size in (MIN..=MAX).map(|p| 2usize.pow(p as u32)) {
        let input_size = 256;
        let circuit_size = size + 2;

        for (k, t) in [(8, 40)] {
            let title = format!("Prover [k = {}, t = {}]", k, t);
            group.bench_with_input(BenchmarkId::new(title, size), &size, |b, _| {
                b.iter_batched_ref(
                    || {
                        let mut rng = AesRng::default();

                        let (circuit, witness) =
                            simple_arith_circuit::circuitgen::mul_zero_circuit::<
                                F::PrimeField,
                                AesRng,
                            >(input_size, circuit_size, &mut rng);
                        (rng, circuit, witness)
                    },
                    |(rng, circuit, witness)| {
                        let proof = Proof::<F, N>::prove(&circuit, &witness, k, t, rng);
                        black_box(proof);
                    },
                    BatchSize::SmallInput,
                );
            });
            let title = format!("Verifier [k = {}]", k);
            group.bench_with_input(BenchmarkId::new(title, size), &size, |b, _| {
                b.iter_batched_ref(
                    || {
                        let mut rng = AesRng::default();

                        let (circuit, witness) =
                            simple_arith_circuit::circuitgen::mul_zero_circuit::<
                                F::PrimeField,
                                AesRng,
                            >(input_size, circuit_size, &mut rng);
                        let proof = Proof::<F, N>::prove(&circuit, &witness, k, t, &mut rng);
                        (circuit, proof)
                    },
                    |(circuit, proof)| {
                        let res = proof.verify(&circuit, k, t).unwrap();
                        black_box(res);
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
}

pub fn bench_random_circuit_f2(c: &mut Criterion) {
    bench_random_circuit::<F64b>(c, "Random circuit F64b");
}

pub fn bench_random_circuit_f61p(c: &mut Criterion) {
    bench_random_circuit::<F61p>(c, "Random circuit F61p");
}

criterion_group! {
    name = random_circuit_f2;
    config = Criterion::default().measurement_time(Duration::new(10, 0)).sample_size(30);
    targets = bench_random_circuit_f2
}
criterion_group! {
    name = random_circuit_f61p;
    config = Criterion::default().measurement_time(Duration::new(10, 0)).sample_size(30);
    targets = bench_random_circuit_f61p
}
criterion_main!(random_circuit_f2, random_circuit_f61p);
