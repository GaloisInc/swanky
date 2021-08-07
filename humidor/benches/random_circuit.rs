use core::time::Duration;
use criterion::{Criterion, BenchmarkId, Throughput, BatchSize, SamplingMode};
use criterion::{criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};

use humidor::circuit::random_ckt_zero;
use humidor::ligero::noninteractive;
use humidor::merkle::Sha256;

type Field = scuttlebutt::field::F2_19x3_26;
type Prover = noninteractive::Prover<Field, Sha256>;
type Verifier = noninteractive::Verifier<Field, Sha256>;

pub fn bench_random_circuit(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Random circuit");
    group.sampling_mode(SamplingMode::Flat);
    for size in (10..=16).map(|p| 2usize.pow(p)) {
        let input_size = 256;
        let circuit_size = size - input_size;

        group.throughput(Throughput::Bytes((size * std::mem::size_of::<Field>()) as u64));
        group.bench_with_input(BenchmarkId::new("Prover", size), &size, |b, _| {
            b.iter_batched_ref(
                || random_ckt_zero(&mut rng, input_size, circuit_size),
                |(ckt, w)| {
                    let p: Prover = noninteractive::Prover::new(ckt, w);
                    p.make_proof();
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Verifier", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let (ckt, w) = random_ckt_zero(&mut rng, input_size, circuit_size);
                    let p: Prover = Prover::new(&ckt, &w);
                    let proof = p.make_proof();

                    (ckt, proof)
                },
                |(ckt, proof)| {
                    let v: Verifier = Verifier::new(&ckt);
                    v.verify(proof);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!{
    name = random_circuit;
    config = Criterion::default()
        .measurement_time(Duration::new(10,0))
        .sample_size(30);
    targets = bench_random_circuit
}
criterion_main!(random_circuit);
