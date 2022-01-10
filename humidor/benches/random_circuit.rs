use core::time::Duration;
use criterion::{criterion_group, criterion_main};
use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput};
use rand::SeedableRng;
use scuttlebutt::AesRng;

use humidor::circuit::Circuit;
use humidor::circuitgen::random_ckt_zero;
use humidor::ligero::noninteractive;

type Hash = sha2::Sha256;
type Field = scuttlebutt::field::F2_19x3_26;
type Prover = noninteractive::Prover<Field, Hash>;
type Verifier = noninteractive::Verifier<Field, Hash>;

pub fn bench_random_circuit_by_circuit_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Random circuit by circuit size");
    group.sampling_mode(SamplingMode::Flat);
    for size in (10..=16).map(|p| 2usize.pow(p)) {
        let input_size = 256;
        let shared_size = 128;
        let circuit_size = size - input_size;

        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<Field>()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("Prover", size), &size, |b, _| {
            b.iter_batched_ref(
                || {
                    let mut rng = AesRng::from_entropy();

                    let (ckt, w) = random_ckt_zero(&mut rng, input_size, circuit_size);

                    (
                        rng,
                        Circuit {
                            shared: 0..shared_size,
                            ..ckt
                        },
                        w,
                    )
                },
                |(rng, ckt, w)| {
                    let mut p: Prover = noninteractive::Prover::new(rng, ckt, w);
                    p.make_proof();
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Verifier", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let mut rng = AesRng::from_entropy();

                    let (mut ckt, w) = random_ckt_zero(&mut rng, input_size, circuit_size);
                    ckt.shared = 0..shared_size;

                    let mut p: Prover = Prover::new(&mut rng, &ckt, &w);
                    let proof = p.make_proof();

                    (ckt, proof)
                },
                |(ckt, proof)| {
                    let mut v: Verifier = Verifier::new(&ckt);
                    v.verify(proof);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

pub fn bench_random_circuit_by_shared_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Random circuit by shared size");
    group.sampling_mode(SamplingMode::Flat);
    for size in (14..=14).map(|p| 2usize.pow(p)) {
        let input_size = 1usize << 14;
        let shared_size = 1usize << size;
        let circuit_size = 1usize << 15;

        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<Field>()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("Prover", size), &size, |b, _| {
            b.iter_batched_ref(
                || {
                    let mut rng = AesRng::from_entropy();

                    let (ckt, w) = random_ckt_zero(&mut rng, input_size, circuit_size);

                    (
                        rng,
                        Circuit {
                            shared: 0..shared_size,
                            ..ckt
                        },
                        w,
                    )
                },
                |(rng, ckt, w)| {
                    let mut p: Prover = noninteractive::Prover::new(rng, ckt, w);
                    p.make_proof();
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Verifier", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let mut rng = AesRng::from_entropy();

                    let (mut ckt, w) = random_ckt_zero(&mut rng, input_size, circuit_size);
                    ckt.shared = 0..shared_size;

                    let mut p: Prover = Prover::new(&mut rng, &ckt, &w);
                    let proof = p.make_proof();

                    (ckt, proof)
                },
                |(ckt, proof)| {
                    let mut v: Verifier = Verifier::new(&ckt);
                    v.verify(proof);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = random_circuit_by_circuit_size;
    config = Criterion::default()
        .measurement_time(Duration::new(10,0))
        .sample_size(30);
    targets = bench_random_circuit_by_circuit_size
}
criterion_group! {
    name = random_circuit_by_shared_size;
    config = Criterion::default()
        .measurement_time(Duration::new(10,0))
        .sample_size(30);
    targets = bench_random_circuit_by_shared_size
}
criterion_main!(
    random_circuit_by_circuit_size,
    random_circuit_by_shared_size
);
